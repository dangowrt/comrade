/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "sandbox.h"

#ifdef _WIN32

#include "wsock.h"			/* windows.h with _WIN32_WINNT = 0x0A00 */

#include <stdlib.h>
#include <string.h>

#include "dbg.h"

/*
 * The Windows self-sandbox. Windows cannot narrow an already-running process's
 * filesystem without a broker or a re-exec under a restricted token, so this
 * side does what a running process can apply to itself: an unnamed job object
 * with a one-process limit -- the irrevocable child-process ban, for the client
 * that spawns nothing -- and the runtime process-mitigation policies that block
 * dynamically generated code, remote and low-integrity image loads, extension-
 * point DLL injection, and loose handle use. The connection service must keep
 * launching tmux.exe (it is not sandboxed against exec, so it needs no spawner),
 * so it takes the mitigations without the job.
 */

/*
 * An unnamed job object limited to one active process: assign this process to
 * it, then close the only handle so the limit can never be raised again. With
 * the process itself counting as that one, any later CreateProcess spins the
 * child up and then fails it during association with ERROR_NOT_ENOUGH_QUOTA.
 * Never KILL_ON_JOB_CLOSE: closing our own handle would otherwise kill us.
 */
static int win_job(void)
{
	HANDLE job;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli;

	job = CreateJobObjectW(NULL, NULL);
	if (!job)
		return 0;
	memset(&eli, 0, sizeof(eli));
	eli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
	eli.BasicLimitInformation.ActiveProcessLimit = 1;
	if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
				     &eli, sizeof(eli)) ||
	    !AssignProcessToJobObject(job, GetCurrentProcess())) {
		CloseHandle(job);
		return 0;
	}
	CloseHandle(job);
	return SANDBOX_L_JOB;
}

/* The process-mitigation policies a process may turn on for itself. Each is
 * best-effort; an older Windows that rejects one leaves the rest in place. */
static int win_mitigations(void)
{
	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dc;
	PROCESS_MITIGATION_IMAGE_LOAD_POLICY il;
	PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ep;
	PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY sh;

	memset(&dc, 0, sizeof(dc));
	dc.ProhibitDynamicCode = 1;
	SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dc, sizeof(dc));

	memset(&il, 0, sizeof(il));
	il.NoRemoteImages = 1;
	il.NoLowMandatoryLabelImages = 1;
	il.PreferSystem32Images = 1;
	SetProcessMitigationPolicy(ProcessImageLoadPolicy, &il, sizeof(il));

	memset(&ep, 0, sizeof(ep));
	ep.DisableExtensionPoints = 1;
	SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &ep,
				   sizeof(ep));

	memset(&sh, 0, sizeof(sh));
	sh.RaiseExceptionOnInvalidHandleReference = 1;
	sh.HandleExceptionsPermanentlyEnabled = 1;
	SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &sh,
				   sizeof(sh));

	/* Resolve DLLs only from System32, and make heap corruption fatal. */
	SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
	HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);
	return SANDBOX_L_MITIGATION;
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
	layers |= win_mitigations();
	if (cfg->role == SANDBOX_CLIENT)
		layers |= win_job();
	dbg_logf("sandbox: role=%d layers=0x%x", cfg->role, layers);
	return layers;
}

/* Windows cannot deny an already-running process CreateProcess, so its service
 * drives tmux directly and needs no spawner. */
int sandbox_needs_spawner(void)
{
	return 0;
}

#endif /* _WIN32 */
