/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "sandbox.h"

#ifdef _WIN32

#include "wsock.h"			/* windows.h with _WIN32_WINNT = 0x0A00 */

#include <aclapi.h>
#include <sddl.h>

#include <stdlib.h>
#include <string.h>

#include "dbg.h"

/*
 * The Windows self-sandbox. Windows cannot narrow an already-running process's
 * view of the filesystem the way a mount namespace does, so this side works on
 * the four things a running process can still take away from itself: the
 * privileges held in its token, the runtime process-mitigation policies, an
 * unnamed job object, and its own integrity level.
 *
 * The integrity drop is the one that carries the weight, and it is the client's
 * alone. A low-integrity process cannot write anywhere the mandatory policy
 * does not label low, and cannot open a process or a window at any higher
 * level, so a compromised client can neither reach the operator's other
 * programs nor leave anything behind in the user's profile. It keeps reading,
 * and it keeps the whole network stack, which is all a joining client ever
 * needed. Its own data directory is labelled low first, so the one thing it
 * does write stays writable.
 *
 * The connection service that serves shells, and the operator's foreground,
 * both keep launching tmux and the per-client shells. A job object's limits
 * apply to every process in the job and children inherit membership, so neither
 * takes the job or the child-process ban -- those would land on tmux and on
 * every guest's shell. They take the privilege removal and the mitigation
 * policies, which are per-process and inherited by nothing.
 */

/* Every policy is best-effort: a Windows that refuses one leaves the rest. */
static int mit_set(PROCESS_MITIGATION_POLICY which, void *buf, size_t len,
		   const char *name)
{
	if (SetProcessMitigationPolicy(which, buf, (SIZE_T)len))
		return 1;
	dbg_logf("sandbox: %s refused (%lu)", name,
		 (unsigned long)GetLastError());
	return 0;
}

/*
 * Whether this role may take the child-process ban. The policy is irrevocable
 * and costs two things at once -- CreateProcess and CreatePseudoConsole -- so
 * only a role that wants neither can have it. A forwarding-only host says so
 * itself: it serves no shell, so it execs nothing and reaches no terminal.
 *
 * A client is named by role rather than by those two facts. It keeps its
 * terminal, and on the POSIX side the grants a terminal costs, so it does not
 * set no_pty; but it renders into the console it was started in and never makes
 * a pseudoconsole, and it spawns nothing at all. Both costs are therefore zero
 * for it, which the fields alone do not say.
 *
 * A service that still runs tmux itself satisfies neither, and on Windows
 * sandbox_needs_spawner() is 0, so that is every service there is today. Asking
 * the facts rather than the role keeps this correct if a Windows broker ever
 * lands.
 */
static int bans_children(const struct sandbox_cfg *cfg)
{
	return cfg->role == SANDBOX_CLIENT || (cfg->no_exec && cfg->no_pty);
}

/* The mitigation policies a process may turn on for itself. */
static int win_mitigations(const struct sandbox_cfg *cfg)
{
	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dc;
	PROCESS_MITIGATION_IMAGE_LOAD_POLICY il;
	PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ep;
	PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY sh;
	PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY sc;
	PROCESS_MITIGATION_CHILD_PROCESS_POLICY cp;
	int took = 0;

	memset(&dc, 0, sizeof(dc));
	dc.ProhibitDynamicCode = 1;
	took |= mit_set(ProcessDynamicCodePolicy, &dc, sizeof(dc),
			"dynamic-code");

	memset(&il, 0, sizeof(il));
	il.NoRemoteImages = 1;
	il.NoLowMandatoryLabelImages = 1;
	il.PreferSystem32Images = 1;
	took |= mit_set(ProcessImageLoadPolicy, &il, sizeof(il), "image-load");

	memset(&ep, 0, sizeof(ep));
	ep.DisableExtensionPoints = 1;
	took |= mit_set(ProcessExtensionPointDisablePolicy, &ep, sizeof(ep),
			"extension-points");

	memset(&sh, 0, sizeof(sh));
	sh.RaiseExceptionOnInvalidHandleReference = 1;
	sh.HandleExceptionsPermanentlyEnabled = 1;
	took |= mit_set(ProcessStrictHandleCheckPolicy, &sh, sizeof(sh),
			"strict-handles");

	memset(&sc, 0, sizeof(sc));
	sc.SpeculativeStoreBypassDisable = 1;
	took |= mit_set(ProcessSideChannelIsolationPolicy, &sc, sizeof(sc),
			"speculative-store-bypass");

	if (bans_children(cfg)) {
		memset(&cp, 0, sizeof(cp));
		cp.NoChildProcessCreation = 1;
		took |= mit_set(ProcessChildProcessPolicy, &cp, sizeof(cp),
				"child-process");
	}

	/* Resolve DLLs only from System32, and make heap corruption fatal.
	 * Neither reports a policy the way the five above do, so neither
	 * decides whether the layer is claimed. */
	SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
	HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);
	return took ? SANDBOX_L_MITIGATION : 0;
}

/*
 * Take every privilege out of the token but the one every process on the system
 * holds: SeChangeNotifyPrivilege, whose absence turns each path lookup into a
 * walk that checks every directory on the way. Removal is irreversible for the
 * life of the token, unlike disabling, so nothing this process later loads can
 * enable one again.
 */
static int win_privileges(void)
{
	unsigned char buf[4096];
	TOKEN_PRIVILEGES *tp;
	TOKEN_PRIVILEGES one;
	LUID keep;
	HANDLE tok;
	DWORD len = 0;
	DWORD i;
	int gone = 0;

	memset(&keep, 0, sizeof(keep));
	LookupPrivilegeValueA(NULL, "SeChangeNotifyPrivilege", &keep);
	if (!OpenProcessToken(GetCurrentProcess(),
			      TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &tok))
		return 0;
	if (!GetTokenInformation(tok, TokenPrivileges, buf, sizeof(buf), &len)) {
		CloseHandle(tok);
		return 0;
	}
	tp = (TOKEN_PRIVILEGES *)buf;
	for (i = 0; i < tp->PrivilegeCount; i++) {
		if (tp->Privileges[i].Luid.LowPart == keep.LowPart &&
		    tp->Privileges[i].Luid.HighPart == keep.HighPart)
			continue;
		one.PrivilegeCount = 1;
		one.Privileges[0].Luid = tp->Privileges[i].Luid;
		one.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
		if (AdjustTokenPrivileges(tok, FALSE, &one, 0, NULL, NULL))
			gone++;
	}
	CloseHandle(tok);
	dbg_logf("sandbox: %d privileges removed", gone);
	return gone ? SANDBOX_L_CAPS : 0;
}

/*
 * An unnamed job object limited to one active process, with the desktop, the
 * clipboard, the global atom table and every window handle outside the job put
 * out of reach. Assign this process to it, then close the only handle so the
 * limits can never be raised again. With the process itself counting as that
 * one, any later CreateProcess fails during association with
 * ERROR_NOT_ENOUGH_QUOTA. Never KILL_ON_JOB_CLOSE: closing our own handle would
 * otherwise kill us.
 */
static int win_job(void)
{
	HANDLE job;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli;
	JOBOBJECT_BASIC_UI_RESTRICTIONS ui;

	job = CreateJobObjectW(NULL, NULL);
	if (!job)
		return 0;
	memset(&ui, 0, sizeof(ui));
	ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_ALL;
	if (!SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui,
				     sizeof(ui)))
		dbg_logf("sandbox: job UI restrictions refused (%lu)",
			 (unsigned long)GetLastError());
	memset(&eli, 0, sizeof(eli));
	eli.BasicLimitInformation.LimitFlags =
		JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
		JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
	eli.BasicLimitInformation.ActiveProcessLimit = 1;
	if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
				     &eli, sizeof(eli)) ||
	    !AssignProcessToJobObject(job, GetCurrentProcess())) {
		dbg_logf("sandbox: job object refused (%lu)",
			 (unsigned long)GetLastError());
		CloseHandle(job);
		return 0;
	}
	CloseHandle(job);
	return SANDBOX_L_JOB;
}

/*
 * Put a low mandatory label on the data directory. The ACE is inheritable and
 * SetNamedSecurityInfo propagates it into what is already there, so a cache
 * written by an earlier run stays replaceable.
 */
static int label_low(const char *dir)
{
	PSECURITY_DESCRIPTOR sd = NULL;
	PACL sacl = NULL;
	BOOL present = FALSE;
	BOOL defaulted = FALSE;
	DWORD rc;

	if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
		    "S:(ML;OICI;NW;;;LW)", SDDL_REVISION_1, &sd, NULL))
		return 0;
	if (!GetSecurityDescriptorSacl(sd, &present, &sacl, &defaulted)) {
		LocalFree(sd);
		return 0;
	}
	rc = SetNamedSecurityInfoA((char *)dir, SE_FILE_OBJECT,
				   LABEL_SECURITY_INFORMATION, NULL, NULL, NULL,
				   sacl);
	LocalFree(sd);
	if (rc != ERROR_SUCCESS) {
		dbg_logf("sandbox: data dir would not take a low label (%lu)",
			 (unsigned long)rc);
		return 0;
	}
	return 1;
}

/*
 * Drop to low integrity, but only once the one directory this process writes
 * will accept a low writer -- a client that cannot save its node cache is a
 * client that re-bootstraps the DHT on every join, so a label that will not
 * take means no drop rather than a broken client. A token's level can be
 * lowered and never raised, and lowering it costs the process the right to
 * lower it again, so this runs last of everything here.
 *
 * The debug log is the other thing the process writes, and its home is the
 * temporary directory, which nothing can label low without labelling every
 * other program's scratch space with it. So a run asked for diagnostics keeps
 * its integrity level and says so, rather than logging nothing and looking
 * like a clean run.
 */
static int win_low_integrity(const char *data_dir)
{
	TOKEN_MANDATORY_LABEL ml;
	const char *dbg;
	PSID low = NULL;
	HANDLE tok;
	int ok = 0;

	dbg = getenv("COMRADE_DEBUG");
	if (dbg && dbg[0]) {
		dbg_logf("sandbox: integrity drop skipped -- it would make "
			 "this log unwritable");
		return 0;
	}
	if (!data_dir || !*data_dir || !label_low(data_dir))
		return 0;
	if (!ConvertStringSidToSidA("S-1-16-4096", &low))
		return 0;
	if (OpenProcessToken(GetCurrentProcess(),
			     TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &tok)) {
		memset(&ml, 0, sizeof(ml));
		ml.Label.Attributes = SE_GROUP_INTEGRITY;
		ml.Label.Sid = low;
		ok = SetTokenInformation(tok, TokenIntegrityLevel, &ml,
					 (DWORD)(sizeof(ml) +
						 GetLengthSid(low))) ? 1 : 0;
		if (!ok)
			dbg_logf("sandbox: integrity drop refused (%lu)",
				 (unsigned long)GetLastError());
		CloseHandle(tok);
	}
	LocalFree(low);
	return ok ? SANDBOX_L_INTEGRITY : 0;
}

int sandbox_apply(const struct sandbox_cfg *cfg)
{
	const char *e;
	int layers = 0;

	if (!cfg)
		return 0;
	e = getenv("COMRADE_SANDBOX");
	if (e && e[0] == '0' && e[1] == '\0') {
		dbg_logf("sandbox: disabled");
		return 0;
	}
	layers |= win_privileges();
	layers |= win_mitigations(cfg);
	if (cfg->role == SANDBOX_CLIENT) {
		layers |= win_job();
		/* Last: the drop costs this process the right to adjust its own
		 * token again, so nothing above may follow it. */
		layers |= win_low_integrity(cfg->data_dir);
	}
	dbg_logf("sandbox: role=%d layers=0x%x", cfg->role, layers);
	return layers;
}

/* Windows cannot deny an already-running process CreateProcess without also
 * denying it the pseudoconsole, so a service that serves shells drives tmux
 * directly and needs no spawner. */
int sandbox_needs_spawner(void)
{
	return 0;
}

/* No syscall filter on this platform: the mitigations are policies, not a
 * program with a length. */
int sandbox_filter_insns(void)
{
	return 0;
}

#endif /* _WIN32 */
