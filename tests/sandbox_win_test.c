/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The Windows self-sandbox proves itself by outcome, not by reading back its
 * own return value: a process applies a profile and then tries both the things
 * that profile forbids and the things it must leave alone. Windows has no fork,
 * and every layer here is irreversible for the life of the process, so each
 * profile is exercised in a fresh copy of this binary re-run with a marker
 * argument -- the same shape sandbox_test.c gets from fork().
 *
 * The parent lays out a directory pair under the temporary directory: one the
 * client is granted (and which the confinement labels low so it stays
 * writable), and a sibling it is not. The child then asserts, in order:
 *
 *   - every privilege but SeChangeNotifyPrivilege is gone from the token;
 *   - a UDP socket still opens, because a joining client is a network program;
 *   - a file inside the granted directory can still be written;
 *   - a file outside it cannot;
 *   - CreateProcess is refused.
 *
 * The last two depend on a layer that a Windows may decline, so each is asked
 * only when the layer it rests on actually engaged. That is the difference
 * between an assertion and a vacuous pass, and it is why the child reports the
 * layer mask alongside each result.
 *
 * The foreground child is the counterweight: the same privilege removal, but
 * CreateProcess must still work, because that role's whole job is to run the
 * operator's tmux.
 */

#include "wsock.h"

#include <aclapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sandbox.h"

/* Room for a temporary directory plus the names this test hangs off it. */
#define PATHBUF		(MAX_PATH + 128)

/* Exit codes carried back from the re-run children. */
#define RC_OK		0
#define RC_FAIL		1
#define RC_SKIP		77	/* ctest SKIP_RETURN_CODE: sandbox disabled */

/* How many privileges the token still holds. -1 if it cannot be read. */
static int privilege_count(void)
{
	unsigned char buf[4096];
	TOKEN_PRIVILEGES *tp;
	HANDLE tok;
	DWORD len = 0;
	int n = -1;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
		return -1;
	if (GetTokenInformation(tok, TokenPrivileges, buf, sizeof(buf), &len)) {
		tp = (TOKEN_PRIVILEGES *)buf;
		n = (int)tp->PrivilegeCount;
	}
	CloseHandle(tok);
	return n;
}

/* Can this process create a file called "probe.dat" in dir? */
static int can_write_in(const char *dir)
{
	char path[PATHBUF];
	HANDLE h;

	if ((size_t)snprintf(path, sizeof(path), "%s\\probe.dat", dir) >=
	    sizeof(path))
		return 0;
	h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return 0;
	CloseHandle(h);
	return 1;
}

/* COMRADE_SANDBOX=0 is the one reason a role may engage nothing. */
static int sandbox_off(void)
{
	const char *e = getenv("COMRADE_SANDBOX");

	return e && !strcmp(e, "0");
}

/* Whether a low mandatory label is on dir; -1 if that cannot be read. */
static int has_low_label(const char *dir)
{
	PSECURITY_DESCRIPTOR sd = NULL;
	PACL sacl = NULL;
	ACE_HEADER *ace;
	int found = 0;
	DWORD i;

	if (GetNamedSecurityInfoA(dir, SE_FILE_OBJECT,
				  LABEL_SECURITY_INFORMATION, NULL, NULL, NULL,
				  &sacl, &sd) != ERROR_SUCCESS)
		return -1;
	for (i = 0; sacl && i < sacl->AceCount; i++) {
		if (GetAce(sacl, i, (void **)&ace) &&
		    ace->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
			found = 1;
	}
	LocalFree(sd);
	return found;
}

/* Can this process start one that runs? The command exits 7 at once: -1 where
 * it could not be created, 0 where it was and did not get that far, 1 where
 * it ran. */
static int spawn_probe(void)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	DWORD code = (DWORD)-1;
	char cmd[64];

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	memset(&pi, 0, sizeof(pi));
	snprintf(cmd, sizeof(cmd), "cmd.exe /c exit 7");
	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
			    NULL, NULL, &si, &pi))
		return -1;
	if (WaitForSingleObject(pi.hProcess, 10000) != WAIT_OBJECT_0)
		TerminateProcess(pi.hProcess, 1);
	GetExitCodeProcess(pi.hProcess, &code);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return code == 7 ? 1 : 0;
}

static int udp_opens(void)
{
	WSADATA wd;
	SOCKET s;

	if (WSAStartup(MAKEWORD(2, 2), &wd))
		return 0;
	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
		return 0;
	closesocket(s);
	return 1;
}

/* The job's UI limits let the clipboard open and refuse the read, with
 * ERROR_ACCESS_DENIED where an empty clipboard says ERROR_NOT_FOUND. */
static int clipboard_read_refused(void)
{
	HANDLE h;
	DWORD err;

	if (!OpenClipboard(NULL))
		return GetLastError() == ERROR_ACCESS_DENIED;
	h = GetClipboardData(CF_TEXT);
	err = GetLastError();
	CloseClipboard();
	return h == NULL && err == ERROR_ACCESS_DENIED;
}

/*
 * The confined client. grant is the directory it is given, denied a sibling it
 * is not.
 */
static int child_client(const char *grant, const char *denied)
{
	struct sandbox_cfg sb;
	int layers, priv, bad = 0;

	memset(&sb, 0, sizeof(sb));
	sb.role = SANDBOX_CLIENT;
	sb.data_dir = grant;
	layers = sandbox_apply(&sb);
	printf("client: layers=0x%04x\n", layers);
	if (sandbox_off())
		return RC_SKIP;
	/* The mitigation policies engage on every Windows this builds for, so
	 * a mask without them is a confinement that stopped engaging. */
	if (!(layers & SANDBOX_L_MITIGATION)) {
		printf("client: FAIL the mitigation policies did not engage\n");
		bad = 1;
	}

	priv = privilege_count();
	printf("client: privileges=%d\n", priv);
	if (priv < 0) {
		printf("client: FAIL the token could not be read\n");
		bad = 1;
	} else if (!(layers & SANDBOX_L_CAPS)) {
		printf("client: (privileges not removed -- not asserted)\n");
	} else if (priv > 1) {
		printf("client: FAIL privileges still held\n");
		bad = 1;
	}

	if (!udp_opens()) {
		printf("client: FAIL a UDP socket would not open\n");
		bad = 1;
	}
	if (!can_write_in(grant)) {
		printf("client: FAIL its own data directory is not writable\n");
		bad = 1;
	}

	/*
	 * Reaching outside the grant is the integrity level's boundary, not the
	 * job's or a policy's, so without that layer there is nothing to assert
	 * -- Windows leaves a medium-integrity process the run of the user's
	 * own files, and it is meant to. What there is to assert without it is
	 * that the directory carries no low label a refused drop left behind.
	 */
	if (!(layers & SANDBOX_L_INTEGRITY)) {
		printf("client: (still at its old integrity level -- the "
		       "outside write is not asserted)\n");
		if (has_low_label(grant) != 0) {
			printf("client: FAIL the data directory is labelled "
			       "low with no drop to show for it\n");
			bad = 1;
		}
	} else if (can_write_in(denied)) {
		printf("client: FAIL wrote outside the granted directory\n");
		bad = 1;
	}

	/*
	 * The job object's one-process limit refuses the spawn at creation, and
	 * its UI restrictions refuse a clipboard read; the bit says both took.
	 */
	if (!(layers & SANDBOX_L_JOB)) {
		printf("client: (no job object -- the spawn is not asserted)\n");
	} else {
		if (spawn_probe() != -1) {
			printf("client: FAIL started a child process\n");
			bad = 1;
		}
		if (!clipboard_read_refused()) {
			printf("client: FAIL read the clipboard\n");
			bad = 1;
		}
	}
	return bad ? RC_FAIL : RC_OK;
}

/*
 * The operator's foreground: hardened, but it drives the local tmux, so the one
 * thing it must not lose is the ability to start one.
 */
static int child_foreground(void)
{
	struct sandbox_cfg sb;
	int layers, priv, bad = 0;

	memset(&sb, 0, sizeof(sb));
	sb.role = SANDBOX_FOREGROUND;
	layers = sandbox_apply(&sb);
	printf("foreground: layers=0x%04x\n", layers);
	if (sandbox_off())
		return RC_SKIP;
	if (!(layers & SANDBOX_L_MITIGATION)) {
		printf("foreground: FAIL the mitigation policies did not "
		       "engage\n");
		bad = 1;
	}
	if (layers & (SANDBOX_L_JOB | SANDBOX_L_INTEGRITY)) {
		printf("foreground: FAIL took a layer tmux would inherit\n");
		bad = 1;
	}
	priv = privilege_count();
	printf("foreground: privileges=%d\n", priv);
	if (priv < 0) {
		printf("foreground: FAIL the token could not be read\n");
		bad = 1;
	} else if ((layers & SANDBOX_L_CAPS) && priv > 1) {
		printf("foreground: FAIL privileges still held\n");
		bad = 1;
	}
	if (spawn_probe() != 1) {
		printf("foreground: FAIL cannot run the tmux it exists to "
		       "drive\n");
		bad = 1;
	}
	return bad ? RC_FAIL : RC_OK;
}

/*
 * The service. On Windows it runs tmux itself (sandbox_needs_spawner() is 0),
 * so like the foreground it must keep CreateProcess.
 */
static int child_service(const char *grant)
{
	struct sandbox_cfg sb;
	int layers, priv, bad = 0;

	memset(&sb, 0, sizeof(sb));
	sb.role = SANDBOX_SERVICE;
	sb.data_dir = grant;
	layers = sandbox_apply(&sb);
	printf("service: layers=0x%04x\n", layers);
	if (sandbox_off())
		return RC_SKIP;
	if (!(layers & SANDBOX_L_MITIGATION)) {
		printf("service: FAIL the mitigation policies did not engage\n");
		bad = 1;
	}
	if (layers & (SANDBOX_L_JOB | SANDBOX_L_INTEGRITY)) {
		printf("service: FAIL took a layer its tmux would inherit\n");
		bad = 1;
	}
	priv = privilege_count();
	printf("service: privileges=%d\n", priv);
	if (priv < 0) {
		printf("service: FAIL the token could not be read\n");
		bad = 1;
	} else if ((layers & SANDBOX_L_CAPS) && priv > 1) {
		printf("service: FAIL privileges still held\n");
		bad = 1;
	}
	if (spawn_probe() != 1) {
		printf("service: FAIL cannot run the tmux it serves\n");
		bad = 1;
	}
	return bad ? RC_FAIL : RC_OK;
}

/* Re-run this binary with a marker and return its exit code, or -1. */
static int rerun(const char *self, const char *marker, const char *grant,
		 const char *denied)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	char cmd[2048];
	DWORD code = (DWORD)-1;

	if ((size_t)snprintf(cmd, sizeof(cmd), "\"%s\" %s \"%s\" \"%s\"", self,
			     marker, grant, denied) >= sizeof(cmd))
		return -1;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	memset(&pi, 0, sizeof(pi));
	if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si,
			    &pi))
		return -1;
	if (WaitForSingleObject(pi.hProcess, 60000) != WAIT_OBJECT_0)
		TerminateProcess(pi.hProcess, 1);
	GetExitCodeProcess(pi.hProcess, &code);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return (int)code;
}

/* Remove probe.dat and the directory, best effort: a low-integrity child may
 * have left a file the parent can still delete, and an empty directory the
 * parent made is the parent's to take away. */
static void sweep(const char *dir)
{
	char path[PATHBUF];

	if ((size_t)snprintf(path, sizeof(path), "%s\\probe.dat", dir) <
	    sizeof(path))
		DeleteFileA(path);
	RemoveDirectoryA(dir);
}

int main(int argc, char **argv)
{
	char root[PATHBUF], grant[PATHBUF], denied[PATHBUF];
	char self[MAX_PATH];
	char tmp[MAX_PATH];
	int rc, bad = 0, skipped = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc >= 4 && !strcmp(argv[1], "client"))
		return child_client(argv[2], argv[3]);
	if (argc >= 4 && !strcmp(argv[1], "service"))
		return child_service(argv[2]);
	if (argc >= 2 && !strcmp(argv[1], "foreground"))
		return child_foreground();

	if (!GetModuleFileNameA(NULL, self, sizeof(self))) {
		fprintf(stderr, "cannot find my own path\n");
		return RC_FAIL;
	}
	if (!GetTempPathA(sizeof(tmp), tmp)) {
		fprintf(stderr, "no temporary directory\n");
		return RC_FAIL;
	}
	if ((size_t)snprintf(root, sizeof(root), "%scomrade-sbx-%lu", tmp,
			     (unsigned long)GetCurrentProcessId()) >=
		    sizeof(root) ||
	    (size_t)snprintf(grant, sizeof(grant), "%s\\data", root) >=
		    sizeof(grant) ||
	    (size_t)snprintf(denied, sizeof(denied), "%s\\elsewhere", root) >=
		    sizeof(denied)) {
		fprintf(stderr, "temporary path too long\n");
		return RC_FAIL;
	}
	if (!CreateDirectoryA(root, NULL) ||
	    !CreateDirectoryA(grant, NULL) ||
	    !CreateDirectoryA(denied, NULL)) {
		fprintf(stderr, "cannot lay out %s (%lu)\n", root,
			(unsigned long)GetLastError());
		return RC_FAIL;
	}

	rc = rerun(self, "client", grant, denied);
	printf("client child: %d\n", rc);
	if (rc == RC_SKIP)
		skipped++;
	else if (rc != RC_OK)
		bad = 1;

	rc = rerun(self, "service", grant, denied);
	printf("service child: %d\n", rc);
	if (rc == RC_SKIP)
		skipped++;
	else if (rc != RC_OK)
		bad = 1;

	rc = rerun(self, "foreground", grant, denied);
	printf("foreground child: %d\n", rc);
	if (rc == RC_SKIP)
		skipped++;
	else if (rc != RC_OK)
		bad = 1;

	sweep(grant);
	sweep(denied);
	RemoveDirectoryA(root);

	if (bad)
		return RC_FAIL;
	if (skipped == 3)
		return RC_SKIP;
	printf("sandbox_win_test: ok\n");
	return RC_OK;
}
