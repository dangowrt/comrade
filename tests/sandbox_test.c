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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "sandbox.h"

/* A writable directory for the confinement child to build its root around,
 * created by main() before forking. */
static char g_datadir[PATH_MAX];

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
 * A confined client's root is a fresh one built in a private mount namespace;
 * the confinement is proven by what is NOT there. /proc is never mounted into
 * it (nothing comrade needs it), so its absence is a portable witness that the
 * pivot happened -- while the data directory the profile was told to keep must
 * still be reachable. Skips where the kernel gives no user namespace.
 */
static int child_client_confined(void)
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
	if (access(g_datadir, F_OK) != 0)
		return RC_FAIL;		/* the kept data dir must survive the pivot */
	return RC_OK;
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

/* A confined client cannot see the host filesystem it was not granted. */
static int the_client_filesystem_is_confined(void)
{
	int r = run_child(child_client_confined);

	if (r == RC_SKIP)
		return RC_SKIP;
	assert(r == RC_OK);
	return RC_OK;
}

int main(void)
{
	char tmpl[] = "/tmp/comrade-sbtest-XXXXXX";
	char *dir = mkdtemp(tmpl);
	int seccomp_skipped, confine_skipped;

	if (dir)
		snprintf(g_datadir, sizeof(g_datadir), "%s", dir);

	seccomp_skipped = (the_client_cannot_exec() == RC_SKIP) ||
		(the_foreground_has_no_network_but_keeps_exec() == RC_SKIP);
	confine_skipped = !dir ||
		(the_client_filesystem_is_confined() == RC_SKIP);

	if (dir)
		rmdir(dir);		/* best effort; the .ns mount is long gone */

	if (seccomp_skipped && confine_skipped) {
		fprintf(stderr, "sandbox_test: this kernel offers neither "
			"seccomp nor a user namespace, skipping\n");
		return 77;
	}
	printf("sandbox_test: ok%s%s\n",
	       seccomp_skipped ? " (seccomp skipped)" : "",
	       confine_skipped ? " (confinement skipped)" : "");
	return 0;
}
