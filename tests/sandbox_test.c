/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The self-sandbox proves itself by outcome, not by inspecting its own return
 * value: a child applies a profile and then tries the thing that profile is
 * meant to forbid. A client must not be able to execve, nor to reach a syscall
 * its allowlist leaves out; the operator foreground must not be able to open an
 * INET socket yet must keep AF_UNIX and exec. Each check runs in its own forked
 * child because the confinement is irreversible. Where the kernel offers no
 * seccomp the whole test skips (return 77), so it neither passes vacuously nor
 * fails on an old kernel.
 *
 * Some of the checks are about what a profile must *not* take away, because
 * that is the failure this confinement has actually produced: a rule that
 * silently narrows what the process can see, with no error, no log line and a
 * program that carries on looking healthy.
 *
 * Two more exist because the ones above them are individually true and jointly
 * insufficient. One applies a client profile and asserts every layer this
 * kernel was just shown to have engages in that same call, so a layer that
 * quietly stopped engaging is a failure rather than a skip. The other hands
 * over to sandbox_selftest(), which runs the whole probe battery behind the
 * real filter: the point of a default-deny list is what it still lets through,
 * and nothing else here would notice that changing.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "sandbox.h"

/* Set up by main() before forking: a writable data directory the confinement
 * child is granted, and a readable marker file just outside it that the child
 * must NOT be able to reach. */
static char g_datadir[PATH_MAX];
static char g_marker[PATH_MAX];

/* Exit codes carried back from the forked children. */
#define RC_OK		0
#define RC_SKIP		77	/* ctest SKIP_RETURN_CODE: no seccomp here */
#define RC_EXEC_RAN	42	/* a deliberately-run exec reached this code */
#define RC_TCP_OPEN	43	/* the policy let a TCP connect be attempted */
#define RC_TCP_BLOCKED	44	/* the policy refused it */
#define RC_FAIL		1

/* A client applies its profile, then attempts execve: it must be refused. */
static int child_client_no_exec(void)
{
	struct sandbox_cfg sb;
	int layers;

	memset(&sb, 0, sizeof(sb));
	sb.role = SANDBOX_CLIENT;
	layers = sandbox_apply(&sb);
	if (!(layers & SANDBOX_L_SECCOMP))
		return RC_SKIP;
	/*
	 * Were exec allowed, this child would become `exit 42` and never return.
	 * The two sandboxes refuse it in ways that differ in kind, not only in
	 * errno: the Linux profile is a default-deny allowlist that execve is
	 * simply not in, so the kernel ends the process and nothing comes back at
	 * all, while macOS Seatbelt returns ENOENT (it hides the binary it will
	 * not let this process read). The caller reads the death; this code only
	 * runs on the platforms that return.
	 */
	execl("/bin/sh", "sh", "-c", "exit 42", (char *)NULL);
	return (errno == EPERM || errno == EACCES || errno == ENOENT)
		? RC_OK : RC_FAIL;
}

#ifdef __linux__
/*
 * A syscall the allowlist leaves out. getpriority is chosen for being harmless
 * and for having no business in a session: the assertion is not about that
 * call but about the shape of the profile, that a name nobody listed is
 * refused rather than quietly permitted. It must not return.
 */
static int child_client_unlisted_syscall(void)
{
	struct sandbox_cfg sb;
	int layers;

	memset(&sb, 0, sizeof(sb));
	sb.role = SANDBOX_CLIENT;
	layers = sandbox_apply(&sb);
	if (!(layers & SANDBOX_L_SECCOMP))
		return RC_SKIP;
	(void)syscall(SYS_getpriority, 0, 0);
	return RC_FAIL;
}
#endif

/*
 * Every layer this kernel has, engaging in one application of one profile.
 * Each of the checks around this one skips where its layer is missing, which
 * is right for a probe of that layer alone and useless as a whole: all three
 * could skip for ever and the suite would still pass. g_expect_layers is set
 * by main() from what the individual probes just demonstrated is available,
 * so anything that stops engaging fails here.
 */
static int g_expect_layers;

static int child_client_layers(void)
{
	struct sandbox_cfg sb;
	int layers;

	memset(&sb, 0, sizeof(sb));
	sb.role = SANDBOX_CLIENT;
	sb.data_dir = g_datadir;
	layers = sandbox_apply(&sb);
	return (layers & g_expect_layers) == g_expect_layers ? RC_OK : RC_FAIL;
}

/*
 * The foreground applies its profile, then checks all three of its promises:
 * an INET socket is refused, an AF_UNIX socket still works (it must reach the
 * local tmux), and exec is still permitted (it runs tmux). The exec is the
 * last act; a shell that exits 42 tells the parent exec was allowed to run.
 */
static int child_foreground(void)
{
	struct sandbox_cfg sb;
	int layers, s;

	memset(&sb, 0, sizeof(sb));
	sb.role = SANDBOX_FOREGROUND;
	layers = sandbox_apply(&sb);
	if (!(layers & SANDBOX_L_SECCOMP))
		return RC_SKIP;

	/*
	 * No route to the network -- but the two sandboxes stop it differently:
	 * Linux seccomp refuses to make the INET socket at all, while macOS
	 * Seatbelt makes it but refuses to reach an address. Either is a pass.
	 */
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s >= 0) {
		struct sockaddr_in a;

		memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET;
		a.sin_port = htons(53);
		a.sin_addr.s_addr = inet_addr("1.1.1.1");
		if (connect(s, (struct sockaddr *)&a, sizeof(a)) == 0 ||
		    (errno != EPERM && errno != EACCES)) {
			close(s);
			return RC_FAIL;	/* the network was reachable */
		}
		close(s);
	} else if (errno != EPERM && errno != EACCES) {
		return RC_FAIL;
	}

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0)
		return RC_FAIL;		/* the tmux control path must survive */
	close(s);

	execl("/bin/sh", "sh", "-c", "exit 42", (char *)NULL);
	return RC_FAIL;			/* exec must have been allowed to run */
}

/*
 * What every confined client, however confined, must be true of: the data
 * directory it was granted is still reachable; the resolver machinery it was
 * granted (nsswitch, /etc/hosts, the NSS modules under the library dirs) still
 * works, proven by resolving localhost, which the first such call must dlopen
 * its way to from inside the confinement; and the marker file just outside its
 * grant cannot be opened -- absent from the namespace's root, or refused by
 * Landlock. Returns RC_OK or RC_FAIL.
 */
static int confined_checks(void)
{
	struct addrinfo hints, *ai = NULL;
	int rc, fd;

	if (access(g_datadir, F_OK) != 0)
		return RC_FAIL;		/* the kept data dir must survive */

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	rc = getaddrinfo("localhost", NULL, &hints, &ai);
	if (rc != 0)
		return RC_FAIL;		/* the granted resolver must still work */
	freeaddrinfo(ai);

	fd = open(g_marker, O_RDONLY);
	if (fd >= 0) {
		close(fd);
		return RC_FAIL;		/* a file outside the grant must not open */
	}
	return RC_OK;
}

/*
 * The namespace confinement: its root is a fresh one it cannot leave, so the
 * marker (never bound into it) is simply not there. Skips where the kernel
 * gives no user namespace.
 */
static int child_confined_ns(void)
{
	struct sandbox_cfg sb;
	int layers;

	memset(&sb, 0, sizeof(sb));
	sb.role = SANDBOX_CLIENT;
	sb.data_dir = g_datadir;
	layers = sandbox_apply(&sb);
	if (!(layers & SANDBOX_L_MOUNTNS))
		return RC_SKIP;
	if (access("/proc/version", F_OK) == 0)
		return RC_FAIL;		/* host /proc still visible: not confined */
	return confined_checks();
}

/*
 * The Landlock confinement, forced with COMRADE_SANDBOX_NO_USERNS: the paths
 * stay visible, but the marker's read is refused. Skips where the kernel has no
 * Landlock.
 */
static int child_confined_landlock(void)
{
	struct sandbox_cfg sb;
	int layers;

	setenv("COMRADE_SANDBOX_NO_USERNS", "1", 1);
	memset(&sb, 0, sizeof(sb));
	sb.role = SANDBOX_CLIENT;
	sb.data_dir = g_datadir;
	layers = sandbox_apply(&sb);
	if (!(layers & SANDBOX_L_LANDLOCK))
		return RC_SKIP;
	return confined_checks();
}

/*
 * Every address an ICE gather would offer: the up IPv4 and IPv6 addresses
 * getifaddrs() reports. Returns -1 if the walk itself fails.
 */
static int count_ifaddrs(void)
{
	struct ifaddrs *list = NULL;
	struct ifaddrs *p;
	int n = 0;

	if (getifaddrs(&list) != 0)
		return -1;
	for (p = list; p; p = p->ifa_next) {
		if (!p->ifa_addr)
			continue;
		if (p->ifa_addr->sa_family != AF_INET &&
		    p->ifa_addr->sa_family != AF_INET6)
			continue;
		if (!(p->ifa_flags & IFF_UP))
			continue;
		n++;
	}
	freeifaddrs(list);
	return n;
}

/*
 * A confined client must still see every local address. This is the check the
 * macOS net.route rule needed: written with a trailing dot the profile
 * compiles, applies and logs nothing, and getifaddrs() simply stops reporting
 * -- after which the host gathers one ICE candidate where it should gather
 * three and the punch fails for no visible reason. The count is taken twice in
 * this one child, either side of the confinement and milliseconds apart, so an
 * interface coming or going cannot make the comparison lie.
 */
static int child_ifaddrs_survive(void)
{
	struct sandbox_cfg sb;
	int before, after;

	before = count_ifaddrs();
	if (before < 1)
		return RC_SKIP;		/* nothing to compare against */
	memset(&sb, 0, sizeof(sb));
	sb.role = SANDBOX_CLIENT;
	sb.data_dir = g_datadir;
	if (!sandbox_apply(&sb))
		return RC_SKIP;
	after = count_ifaddrs();
	return after >= before ? RC_OK : RC_FAIL;
}

/*
 * The two halves the network grant separates. The UDP socket is comrade's own
 * transport and every role keeps it, so losing it is a failure whoever is
 * asking. The TCP connect is the part that depends on the role: the answer is
 * reported rather than judged here, because what it should be is the caller's
 * business.
 */
static int probe_udp_and_tcp(void)
{
	struct sockaddr_in a;
	int s, rc, err;

	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_port = 0;
	a.sin_addr.s_addr = inet_addr("127.0.0.1");
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return RC_FAIL;
	if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
		close(s);
		return RC_FAIL;		/* the transport itself is gone */
	}
	close(s);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return RC_TCP_BLOCKED;	/* refused before it had an address */
	a.sin_port = htons(9);		/* discard: nothing is listening */
	rc = connect(s, (struct sockaddr *)&a, sizeof(a));
	err = errno;			/* before close(), which may set it */
	close(s);
	/*
	 * Unconfined this ends in ECONNREFUSED, which is the connection being
	 * declined rather than the attempt: only EPERM/EACCES is the policy.
	 */
	if (rc != 0 && (err == EPERM || err == EACCES))
		return RC_TCP_BLOCKED;
	return RC_TCP_OPEN;
}

/* A client that was asked for no forwards: it should have lost TCP. */
static int child_forwards_nothing(void)
{
	struct sandbox_cfg sb;

	memset(&sb, 0, sizeof(sb));
	sb.role = SANDBOX_CLIENT;
	sb.data_dir = g_datadir;
	if (!sandbox_apply(&sb))
		return RC_SKIP;
	return probe_udp_and_tcp();
}

/*
 * A forwarding-only host: no exec, no terminal, and TCP it cannot name the
 * ports of. The tightest role of the three in every other respect, and the one
 * that must keep TCP.
 */
static int child_forward_only_host(void)
{
	struct sandbox_cfg sb;

	memset(&sb, 0, sizeof(sb));
	sb.role = SANDBOX_SERVICE;
	sb.data_dir = g_datadir;
	sb.state_dir = g_datadir;
	sb.no_exec = 1;
	sb.no_pty = 1;
	sb.tcp_any = 1;
	if (!sandbox_apply(&sb))
		return RC_SKIP;
	return probe_udp_and_tcp();
}

/* Run one child helper to completion; return its raw wait status. */
static int run_child_status(int (*fn)(void))
{
	pid_t pid = fork();
	int status;

	if (pid == 0)
		_exit(fn());
	assert(pid > 0);
	assert(waitpid(pid, &status, 0) == pid);
	return status;
}

/* The same, for the children that are expected to come back. */
static int run_child(int (*fn)(void))
{
	int status = run_child_status(fn);

	assert(WIFEXITED(status));
	return WEXITSTATUS(status);
}

/*
 * A child that the profile is expected to end: killed outright by the filter's
 * default action, or -- under COMRADE_SANDBOX=warn -- reported by the SIGSYS
 * handler and exited with 159. Returns 1 if it was stopped either way.
 */
static int was_refused(int status)
{
	return (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) ||
	       (WIFEXITED(status) && WEXITSTATUS(status) == 159);
}

/* A client cannot exec. */
static int the_client_cannot_exec(void)
{
	int st = run_child_status(child_client_no_exec);

	if (was_refused(st))
		return RC_OK;
	assert(WIFEXITED(st));
	if (WEXITSTATUS(st) == RC_SKIP)
		return RC_SKIP;
	assert(WEXITSTATUS(st) == RC_OK);
	return RC_OK;
}

/* A client cannot reach a syscall its allowlist omits. */
static int the_client_cannot_reach_an_unlisted_syscall(void)
{
#ifdef __linux__
	int st = run_child_status(child_client_unlisted_syscall);

	if (was_refused(st))
		return RC_OK;
	assert(WIFEXITED(st));
	if (WEXITSTATUS(st) == RC_SKIP)
		return RC_SKIP;
	assert(!"a syscall outside the allowlist was permitted");
#endif
	return RC_SKIP;
}

/* Every layer this kernel has engages, and in the same call. */
static int the_layers_engage_together(void)
{
	int r;

	if (!g_expect_layers)
		return RC_SKIP;
	r = run_child(child_client_layers);
	assert(r == RC_OK);
	return RC_OK;
}

/*
 * The confinement's own probe battery: the filter installed for real, and then
 * the things a session does. It reports 77 where there is no filter to test,
 * and 1 the moment this libc reaches for something the list does not carry.
 */
static int the_selftest_agrees(void)
{
	int r = sandbox_selftest();

	if (r == 77)
		return RC_SKIP;
	assert(r == 0);
	return RC_OK;
}

/* The foreground has no network but keeps its terminal and tmux. */
static int the_foreground_has_no_network_but_keeps_exec(void)
{
	int r = run_child(child_foreground);

	if (r == RC_SKIP)
		return RC_SKIP;
	assert(r == RC_EXEC_RAN);
	return RC_OK;
}

/* A namespace-confined client cannot see the filesystem it was not granted. */
static int the_namespace_confines_the_filesystem(void)
{
	int r = run_child(child_confined_ns);

	if (r == RC_SKIP)
		return RC_SKIP;
	assert(r == RC_OK);
	return RC_OK;
}

/* A Landlock-confined client is refused the files it was not granted. */
static int the_landlock_fallback_confines_the_filesystem(void)
{
	int r = run_child(child_confined_landlock);

	if (r == RC_SKIP)
		return RC_SKIP;
	assert(r == RC_OK);
	return RC_OK;
}

/* A confined client still sees every address a candidate could be gathered
 * from. */
static int the_confinement_keeps_every_local_address(void)
{
	int r = run_child(child_ifaddrs_survive);

	if (r == RC_SKIP)
		return RC_SKIP;
	assert(r == RC_OK);
	return RC_OK;
}

/*
 * TCP follows the forwarding, and it follows it the right way round. The two
 * roles are run against each other rather than against a fixed expectation, so
 * a platform with no TCP restriction at all skips instead of passing
 * vacuously -- but a forwarding role that lost its TCP fails on every
 * platform, because that is the mistake worth catching: it is the pairing
 * whose intuition points the wrong way, and getting it backwards breaks the
 * one service built to forward while the suite otherwise stays green.
 */
static int the_tcp_grant_follows_the_forwards(void)
{
	int denied = run_child(child_forwards_nothing);
	int granted = run_child(child_forward_only_host);

	if (denied == RC_SKIP || granted == RC_SKIP)
		return RC_SKIP;
	assert(denied != RC_FAIL && granted != RC_FAIL);
	assert(granted == RC_TCP_OPEN);
	if (denied == RC_TCP_OPEN)
		return RC_SKIP;		/* this platform restricts no TCP */
	assert(denied == RC_TCP_BLOCKED);
	return RC_OK;
}

/* Create the granted data dir and the ungranted marker, both under one temp
 * base; returns 0 on success. */
static int make_fixture(char *base)
{
	int fd;

	if (!mkdtemp(base))
		return -1;
	if ((size_t)snprintf(g_datadir, sizeof(g_datadir), "%s/data", base) >=
	    sizeof(g_datadir))
		return -1;
	if ((size_t)snprintf(g_marker, sizeof(g_marker), "%s/secret", base) >=
	    sizeof(g_marker))
		return -1;
	if (mkdir(g_datadir, 0700) != 0)
		return -1;
	fd = open(g_marker, O_WRONLY | O_CREAT, 0644);
	if (fd < 0)
		return -1;
	if (write(fd, "x\n", 2) != 2) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static void drop_fixture(const char *base)
{
	rmdir(g_datadir);	/* the .ns mount, if any, is long gone */
	unlink(g_marker);
	rmdir(base);
}

int main(void)
{
	char base[] = "/tmp/comrade-sbtest-XXXXXX";
	int have_fixture = (make_fixture(base) == 0);
	int seccomp_skipped, ns_skipped, ll_skipped, addr_skipped, tcp_skipped;
	int self_skipped;

	seccomp_skipped = (the_client_cannot_exec() == RC_SKIP) ||
		(the_foreground_has_no_network_but_keeps_exec() == RC_SKIP) ||
		(the_client_cannot_reach_an_unlisted_syscall() == RC_SKIP);
	ns_skipped = !have_fixture ||
		(the_namespace_confines_the_filesystem() == RC_SKIP);
	ll_skipped = !have_fixture ||
		(the_landlock_fallback_confines_the_filesystem() == RC_SKIP);
	addr_skipped = !have_fixture ||
		(the_confinement_keeps_every_local_address() == RC_SKIP);
	tcp_skipped = !have_fixture ||
		(the_tcp_grant_follows_the_forwards() == RC_SKIP);

	/*
	 * Only now is it known which layers this kernel actually has, so only now
	 * can one application of one profile be held to all of them at once.
	 * RLIMIT joins them because it is the one layer no kernel can refuse, and
	 * its absence would mean the call never ran.
	 */
	g_expect_layers = SANDBOX_L_RLIMIT;
	if (!seccomp_skipped)
		g_expect_layers |= SANDBOX_L_SECCOMP;
	if (!ns_skipped)
		g_expect_layers |= SANDBOX_L_USERNS | SANDBOX_L_MOUNTNS;
	if (!ll_skipped)
		g_expect_layers |= SANDBOX_L_LANDLOCK;
	if (have_fixture)
		the_layers_engage_together();

	if (have_fixture)
		drop_fixture(base);

	self_skipped = (the_selftest_agrees() == RC_SKIP);

	if (seccomp_skipped && ns_skipped && ll_skipped && addr_skipped &&
	    tcp_skipped && self_skipped) {
		fprintf(stderr, "sandbox_test: this kernel offers no seccomp, "
			"user namespace or Landlock, skipping\n");
		return 77;
	}
	printf("sandbox_test: ok%s%s%s%s%s%s\n",
	       seccomp_skipped ? " (seccomp skipped)" : "",
	       ns_skipped ? " (namespace skipped)" : "",
	       ll_skipped ? " (landlock skipped)" : "",
	       addr_skipped ? " (addresses skipped)" : "",
	       tcp_skipped ? " (tcp skipped)" : "",
	       self_skipped ? " (selftest skipped)" : "");
	return 0;
}
