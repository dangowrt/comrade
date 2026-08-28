/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The self-sandbox proves itself by outcome, not by inspecting its own return
 * value: a child applies a profile and then tries the thing that profile is
 * meant to forbid. A client must not be able to execve; the operator
 * foreground must not be able to open an INET socket yet must keep AF_UNIX and
 * exec. Each check runs in its own forked child because the confinement is
 * irreversible. Where the kernel offers no seccomp the whole test skips
 * (return 77), so it neither passes vacuously nor fails on an old kernel.
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

#include <sys/socket.h>
#include <sys/stat.h>
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
	execl("/bin/true", "true", (char *)NULL);
	/* Reached only because exec was denied. */
	return errno == EPERM ? RC_OK : RC_FAIL;
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

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s >= 0) {
		close(s);
		return RC_FAIL;		/* INET should have been denied */
	}
	if (errno != EPERM && errno != EACCES)
		return RC_FAIL;

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
	int rc;

	if (access(g_datadir, F_OK) != 0)
		return RC_FAIL;		/* the kept data dir must survive */

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	rc = getaddrinfo("localhost", NULL, &hints, &ai);
	if (rc != 0)
		return RC_FAIL;		/* the granted resolver must still work */
	freeaddrinfo(ai);

	if (open(g_marker, O_RDONLY) >= 0)
		return RC_FAIL;		/* a file outside the grant must not open */
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

/* Run one child helper to completion; return its exit status. */
static int run_child(int (*fn)(void))
{
	pid_t pid = fork();
	int status;

	if (pid == 0)
		_exit(fn());
	assert(pid > 0);
	assert(waitpid(pid, &status, 0) == pid);
	assert(WIFEXITED(status));
	return WEXITSTATUS(status);
}

/* A client cannot exec. */
static int the_client_cannot_exec(void)
{
	int r = run_child(child_client_no_exec);

	if (r == RC_SKIP)
		return RC_SKIP;
	assert(r == RC_OK);
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
	int seccomp_skipped, ns_skipped, ll_skipped;

	seccomp_skipped = (the_client_cannot_exec() == RC_SKIP) ||
		(the_foreground_has_no_network_but_keeps_exec() == RC_SKIP);
	ns_skipped = !have_fixture ||
		(the_namespace_confines_the_filesystem() == RC_SKIP);
	ll_skipped = !have_fixture ||
		(the_landlock_fallback_confines_the_filesystem() == RC_SKIP);

	if (have_fixture)
		drop_fixture(base);

	if (seccomp_skipped && ns_skipped && ll_skipped) {
		fprintf(stderr, "sandbox_test: this kernel offers no seccomp, "
			"user namespace or Landlock, skipping\n");
		return 77;
	}
	printf("sandbox_test: ok%s%s%s\n",
	       seccomp_skipped ? " (seccomp skipped)" : "",
	       ns_skipped ? " (namespace skipped)" : "",
	       ll_skipped ? " (landlock skipped)" : "");
	return 0;
}
