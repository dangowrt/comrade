/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/* unshare(), the CLONE_NEW* flags and the mount constants are GNU extensions. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#ifndef _WIN32

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>

#include "dbg.h"

/*
 * The POSIX self-sandbox. Linux and macOS are genuinely different mechanisms
 * -- raw capset/seccomp/namespaces versus a Seatbelt profile string -- so this
 * file is a thin dispatcher over two per-OS bodies plus a resource-limit
 * fallback that any Unix honours. Every helper is best-effort: it returns the
 * layer bit it managed to set, or 0, and a kernel that refuses one is not an
 * error (see sandbox.h). No designated initialisers or compound literals here
 * (house style is C89); the kernel structs are filled member by member.
 */

/* COMRADE_SANDBOX=0 turns the whole thing off. */
static int sandbox_disabled(void)
{
	const char *e = getenv("COMRADE_SANDBOX");

	return e && e[0] == '0' && e[1] == '\0';
}

/*
 * RLIMIT_CORE = 0 keeps a crash from spilling the token, session keys and
 * terminal scrollback into a core file. Honoured on every Unix, so it is the
 * one thing the generic fallback still does.
 */
static int limit_core(void)
{
	struct rlimit rl;

	rl.rlim_cur = 0;
	rl.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &rl) == 0)
		return SANDBOX_L_RLIMIT;
	return 0;
}

#if defined(__APPLE__)

/*
 * macOS: a Seatbelt profile applied with sandbox_init_with_parameters(). The
 * function is deprecated in name only -- current browsers ship on it -- and is
 * absent from the public header, so its prototype is declared here as they do.
 * The profile is (deny default) with the narrow allowances the running role
 * needs; it covers every thread of the process and cannot be tightened or
 * lifted afterwards.
 */

#include <limits.h>
#include <sys/ptrace.h>

extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
					const char *const parameters[],
					char **errorbuf);
extern void sandbox_free_error(char *errorbuf);

/*
 * The confining profile (client and service): deny everything, then allow the
 * narrow set the work needs -- the system and Homebrew library trees to map and
 * read, the resolver's pieces, the process's own data (and state) directory to
 * read and write, and the network. process-exec and process-fork are left
 * denied by the default, so a compromised process cannot run anything; the host
 * service does its spawning from a separate process forked before this applies.
 * DATA_DIR and STATE_DIR are passed as parameters so the one profile serves any
 * path.
 */
static const char sb_profile_confine[] =
"(version 1)\n"
"(deny default)\n"
"(allow file-read-metadata)\n"
"(allow process-info* (target self))\n"
"(allow signal (target self))\n"
"(allow sysctl-read)\n"
"(allow mach-per-user-lookup)\n"
"(allow file-read* file-map-executable\n"
"  (subpath \"/usr/lib\") (subpath \"/usr/share\") (subpath \"/System\")\n"
"  (subpath \"/private/etc\") (subpath \"/opt/homebrew\")\n"
"  (subpath \"/usr/local\") (subpath \"/Library/Preferences/Logging\")\n"
"  (subpath \"/System/Cryptexes\")\n"
"  (subpath \"/System/Volumes/Preboot/Cryptexes\"))\n"
"(allow file-read*\n"
"  (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/random\")\n"
"  (literal \"/dev/urandom\") (literal \"/dev/dtracehelper\"))\n"
"(allow file-write-data (literal \"/dev/null\"))\n"
"(allow file-ioctl (subpath \"/dev\"))\n"
"(allow file-read* file-write* file-ioctl (subpath (param \"DATA_DIR\")))\n"
"(allow file-read* file-write* file-ioctl (subpath (param \"STATE_DIR\")))\n"
"(allow mach-lookup\n"
"  (global-name \"com.apple.dnssd.service\")\n"
"  (global-name \"com.apple.SystemConfiguration.configd\")\n"
"  (global-name \"com.apple.SystemConfiguration.DNSConfiguration\")\n"
"  (global-name \"com.apple.system.notification_center\")\n"
"  (global-name \"com.apple.system.opendirectoryd.libinfo\")\n"
"  (global-name \"com.apple.system.logger\"))\n"
"(allow ipc-posix-shm-read-data\n"
"  (ipc-posix-name \"apple.shm.notification_center\"))\n"
"(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n"
"(allow network*)\n"
"(allow system-socket)\n";

/*
 * The foreground profile: it runs the operator's local tmux, so it keeps
 * everything a program normally does -- exec, files, a pty, local (unix)
 * sockets -- and loses only the network, denied to any IP peer. UNIX-domain
 * sockets are path-based, not (remote ip), so the tmux connection is untouched.
 */
static const char sb_profile_nonet[] =
"(version 1)\n"
"(allow default)\n"
"(deny network-inbound (remote ip \"*:*\"))\n"
"(deny network-outbound (remote ip \"*:*\"))\n";

/* Apply an SBPL profile; returns 1 on success, 0 (logged) on failure. */
static int seatbelt(const char *profile, const char *const *params)
{
	char *err = NULL;

	if (sandbox_init_with_parameters(profile, 0, params, &err) == 0)
		return 1;
	dbg_logf("sandbox: seatbelt failed: %s", err ? err : "?");
	if (err)
		sandbox_free_error(err);
	return 0;
}

static int apply_macos(const struct sandbox_cfg *cfg)
{
	int layers = 0;
	char dd[PATH_MAX];
	char sd[PATH_MAX];
	const char *params[5];
	struct rlimit rl;

	layers |= limit_core();
	if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == 0)	/* refuse a debugger */
		layers |= SANDBOX_L_NODUMP;

	if (cfg->role == SANDBOX_FOREGROUND) {
		if (seatbelt(sb_profile_nonet, (const char *const *)0))
			layers |= SANDBOX_L_SECCOMP;
		return layers;
	}

	/* Block fork (the spawner is already made); macOS threads are not
	 * processes, so this does not touch pthread_create. */
	rl.rlim_cur = 0;
	rl.rlim_max = 0;
	if (setrlimit(RLIMIT_NPROC, &rl) == 0)
		layers |= SANDBOX_L_RLIMIT;

	if (!cfg->data_dir || !realpath(cfg->data_dir, dd))
		snprintf(dd, sizeof(dd), "/nonexistent");
	if (!cfg->state_dir || !realpath(cfg->state_dir, sd))
		snprintf(sd, sizeof(sd), "%s", dd);
	params[0] = "DATA_DIR";
	params[1] = dd;
	params[2] = "STATE_DIR";
	params[3] = sd;
	params[4] = (const char *)0;
	if (seatbelt(sb_profile_confine, params))
		layers |= SANDBOX_L_SECCOMP | SANDBOX_L_LANDLOCK;
	return layers;
}

#elif defined(__linux__)

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>

#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/seccomp.h>

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_GET_SECCOMP
#define PR_GET_SECCOMP 21
#endif
#ifndef PR_SET_MDWE
#define PR_SET_MDWE 65
#endif
#ifndef PR_MDWE_REFUSE_EXEC_GAIN
#define PR_MDWE_REFUSE_EXEC_GAIN 1
#endif
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

/*
 * The bounding-set number the kernel actually stops at is read with
 * PR_CAPBSET_READ (no file, unprivileged), so the drop loop never guesses.
 */
#ifndef PR_CAPBSET_READ
#define PR_CAPBSET_READ 23
#endif
#ifndef PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif

/* The three capset pieces, so libcap need not be linked. */
#ifndef _LINUX_CAPABILITY_VERSION_3
#define _LINUX_CAPABILITY_VERSION_3 0x20080522
#endif

struct cap_header {
	unsigned int version;
	int pid;
};

struct cap_data {
	unsigned int effective;
	unsigned int permitted;
	unsigned int inheritable;
};

/* Refuse core dumps and same-uid ptrace attach. */
static int no_dumpable(void)
{
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0)
		return SANDBOX_L_NODUMP;
	return 0;
}

/* Write^execute: no page may become executable after having been writable.
 * dlopen still works (it maps executable directly); only a JIT would care, and
 * nothing comrade links has one. Irreversible; harmless where unsupported. */
static int mdwe(void)
{
	if (prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) == 0)
		return SANDBOX_L_MDWE;
	return 0;
}

/*
 * Drop the ambient set, shrink the bounding set as far as this process may
 * (an unprivileged one without CAP_SETPCAP cannot, and the EPERM there is
 * expected and fine -- no_new_privs plus exec denial make the bounding set
 * moot, since it only matters at execve of a file with file capabilities), and
 * clear the effective/permitted/inheritable sets outright.
 */
static int drop_caps(void)
{
	struct cap_header h;
	struct cap_data d[2];
	int i, last;

	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);

	last = 0;
	while (prctl(PR_CAPBSET_READ, last, 0, 0, 0) >= 0)
		last++;			/* last is now one past the top cap */
	for (i = 0; i < last; i++) {
		if (prctl(PR_CAPBSET_DROP, i, 0, 0, 0) != 0)
			break;		/* EPERM without CAP_SETPCAP: stop */
	}

	memset(&h, 0, sizeof(h));
	memset(d, 0, sizeof(d));
	h.version = _LINUX_CAPABILITY_VERSION_3;
	h.pid = 0;
	/* All three sets to zero for this thread. The sandbox point is
	 * single-threaded, so no other thread carries capabilities. */
	if (syscall(SYS_capset, &h, d) == 0)
		return SANDBOX_L_CAPS;
	return 0;
}

/* Mandatory before an unprivileged seccomp filter or Landlock ruleset, and a
 * hardening in its own right: no execve may grant privileges ever again. */
static int no_new_privs(void)
{
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0)
		return SANDBOX_L_NONEWPRIVS;
	return 0;
}

/*
 * The audit arch constant for the seccomp filter. Only arches whose syscall
 * ABI this filter is written for are named; anywhere else the seccomp layer is
 * skipped rather than risking a wrong-arch filter.
 */
#if defined(__x86_64__)
#define SB_AUDIT_ARCH AUDIT_ARCH_X86_64
#define SB_X32_GUARD 1
#elif defined(__aarch64__)
#define SB_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__arm__)
#define SB_AUDIT_ARCH AUDIT_ARCH_ARM
#elif defined(__i386__)
#define SB_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__riscv) && __riscv_xlen == 64
#define SB_AUDIT_ARCH AUDIT_ARCH_RISCV64
#endif

#ifdef SYS_seccomp
#ifdef SB_AUDIT_ARCH

/* seccomp_data field offsets, for the BPF that reads them. */
#define SB_OFF_NR	(offsetof(struct seccomp_data, nr))
#define SB_OFF_ARCH	(offsetof(struct seccomp_data, arch))
#define SB_OFF_ARG0_LO	(offsetof(struct seccomp_data, args[0]))

/*
 * Deny one syscall number, returning EPERM, as a self-contained two-word
 * block: if nr matches, fall through to the RET; otherwise jump past it. Used
 * only while the accumulator holds nr.
 */
#define SB_DENY(nr) \
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (nr), 0, 1), \
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO + (EPERM & SECCOMP_RET_DATA))

static int install_filter(struct sock_filter *f, unsigned short n)
{
	struct sock_fprog prog;

	prog.len = n;
	prog.filter = f;
	/* TSYNC is harmless here (we are single-threaded) but correct if that
	 * ever changes. The filter is a denylist returning errno, never a
	 * kill, except on a wrong-arch syscall. */
	if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
		    SECCOMP_FILTER_FLAG_TSYNC, &prog) == 0)
		return SANDBOX_L_SECCOMP;
	return 0;
}

/*
 * The exec-denying filter (client, and the host service once its spawner does
 * all the real spawning): forbid the program from executing anything or from
 * prying into another process's memory, while leaving fork/clone alone -- a
 * fork with no exec only clones this same confined process, and the thread
 * creation the DHT/ICE/SSH stacks do all through the run must keep working.
 */
static int seccomp_noexec(void)
{
	static struct sock_filter filt[] = {
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, SB_OFF_ARCH),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SB_AUDIT_ARCH, 1, 0),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, SB_OFF_NR),
#ifdef SB_X32_GUARD
		BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, 0x40000000, 0, 1),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
		SB_DENY(__NR_execve),
#ifdef __NR_execveat
		SB_DENY(__NR_execveat),
#endif
#ifdef __NR_ptrace
		SB_DENY(__NR_ptrace),
#endif
#ifdef __NR_process_vm_readv
		SB_DENY(__NR_process_vm_readv),
#endif
#ifdef __NR_process_vm_writev
		SB_DENY(__NR_process_vm_writev),
#endif
#ifdef __NR_io_uring_setup
		SB_DENY(__NR_io_uring_setup),
#endif
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
	};

	return install_filter(filt, sizeof(filt) / sizeof(filt[0]));
}

/*
 * The no-network filter (host operator foreground): it drives a local tmux and
 * must keep exec and the AF_UNIX connect to the tmux socket, but never touches
 * the network, so deny only the creation of INET/INET6 sockets. socket(2)'s
 * domain is args[0] on every arch this filter is enabled for.
 */
static int seccomp_nonet(void)
{
	static struct sock_filter filt[] = {
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, SB_OFF_ARCH),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SB_AUDIT_ARCH, 1, 0),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, SB_OFF_NR),
#ifdef __NR_io_uring_setup
		SB_DENY(__NR_io_uring_setup),
#endif
#ifdef __NR_socket
		/* if nr != socket, skip the family test (jump to ALLOW) */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_socket, 0, 5),
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, SB_OFF_ARG0_LO),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AF_INET, 1, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AF_INET6, 0, 1),
		BPF_STMT(BPF_RET + BPF_K,
			 SECCOMP_RET_ERRNO + (EPERM & SECCOMP_RET_DATA)),
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, SB_OFF_NR),
#endif
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
	};

	return install_filter(filt, sizeof(filt) / sizeof(filt[0]));
}

#endif /* SB_AUDIT_ARCH */
#endif /* SYS_seccomp */

/*
 * Whether a filter can actually be installed here: the syscall exists, this
 * build names an audit arch for the architecture it is running on, and the
 * kernel has seccomp compiled in. All three are needed, and the second is the
 * one that is easy to forget -- a kernel can have seccomp while this file has
 * no constant for the architecture, which is most of what OpenWrt ships. The
 * exec denial is what buys the host its spawner, so the same question decides
 * both, and adding an architecture below turns the spawner on there by itself.
 */
static int seccomp_available(void)
{
#if defined(SYS_seccomp) && defined(SB_AUDIT_ARCH)
	return prctl(PR_GET_SECCOMP) >= 0;
#else
	return 0;
#endif
}

static int seccomp_apply(int role, int confine)
{
#if defined(SYS_seccomp) && defined(SB_AUDIT_ARCH)
	if (!seccomp_available())
		return 0;
	if (role == SANDBOX_FOREGROUND)
		return seccomp_nonet();
	if (confine)
		return seccomp_noexec();
	return 0;
#else
	(void)role;
	(void)confine;
	return 0;
#endif
}

/*
 * Confine the visible filesystem to what the role needs -- writable only its
 * own data (and, for the service, the host state dir), read-only the resolver
 * config and the shared objects the C library and TLS stack keep reading -- by
 * building a fresh root in a private mount namespace and pivoting into it. This
 * is the primitive that works on OpenWrt, where Landlock does not exist: an
 * unprivileged user namespace grants the mount privilege, and nothing here
 * needs a helper binary or a pre-staged root. Every step is best-effort; the
 * one operation that could strand the program in a broken world -- pivot_root
 * -- runs last, only after the whole tree is built, and a failure before it
 * detaches the half-built tree and leaves the process in its normal view.
 *
 * The Landlock ruleset (the desktop filesystem path, for kernels that refuse an
 * unprivileged user namespace) is a later addition; where the namespace is
 * unavailable this returns 0 and the rest of the sandbox still applies.
 */

/* Write a value to a one-shot /proc file (the id maps, setgroups). */
static int write_once(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	ssize_t n;
	size_t len = strlen(val);

	if (fd < 0)
		return -1;
	n = write(fd, val, len);
	close(fd);
	return (n == (ssize_t)len) ? 0 : -1;
}

/*
 * Map this process's own uid and gid to themselves in the new user namespace,
 * so files it owns stay writable. setgroups must be denied before the gid map
 * when unprivileged. Best-effort: an unmapped namespace still confines, it just
 * sees its own files as nobody.
 */
static void map_ids(uid_t uid, gid_t gid)
{
	char buf[64];

	write_once("/proc/self/setgroups", "deny");
	snprintf(buf, sizeof(buf), "%lu %lu 1", (unsigned long)gid,
		 (unsigned long)gid);
	write_once("/proc/self/gid_map", buf);
	snprintf(buf, sizeof(buf), "%lu %lu 1", (unsigned long)uid,
		 (unsigned long)uid);
	write_once("/proc/self/uid_map", buf);
}

/* Create path and every missing parent, like mkdir -p, mode 0755. */
static void mkdir_p(const char *path)
{
	char buf[PATH_MAX];
	size_t i, n;

	n = strlen(path);
	if (n == 0 || n >= sizeof(buf))
		return;
	memcpy(buf, path, n + 1);
	for (i = 1; i < n; i++) {
		if (buf[i] != '/')
			continue;
		buf[i] = '\0';
		mkdir(buf, 0755);
		buf[i] = '/';
	}
	mkdir(buf, 0755);
}

#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY 0x00000001
#endif
#ifndef MOUNT_ATTR_NODEV
#define MOUNT_ATTR_NODEV 0x00000004
#endif
#ifndef MOUNT_ATTR_NOEXEC
#define MOUNT_ATTR_NOEXEC 0x00000008
#endif
#ifndef MOUNT_ATTR_NOSUID
#define MOUNT_ATTR_NOSUID 0x00000002
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

/* The mount_attr the kernel expects; declared here so no UAPI header is
 * assumed. Only the first two fields are set. */
struct sb_mount_attr {
	uint64_t attr_set;
	uint64_t attr_clr;
	uint64_t propagation;
	uint64_t userns_fd;
};

/*
 * Turn a mount (and, where the kernel supports it, its whole subtree) read-only
 * and nosuid. mount_setattr with AT_RECURSIVE does the whole tree and preserves
 * the flags a user namespace forbids changing; the older bind-remount reaches
 * only the top mount but is enough on the flat binds used here. Best-effort.
 */
static void remount_ro(const char *path)
{
#ifdef SYS_mount_setattr
	struct sb_mount_attr a;

	memset(&a, 0, sizeof(a));
	a.attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV;
	if (syscall(SYS_mount_setattr, -1, path, AT_RECURSIVE, &a,
		    sizeof(a)) == 0)
		return;
#endif
	/* The remount only takes read-only in a second call, and must not try to
	 * relax a flag the namespace locked; adding rdonly/nosuid/nodev never is
	 * relaxing, and no atime flag is touched. A failure here is not fatal but
	 * does leave the mount writable -- weaker than intended -- so it is worth
	 * a word in the log. */
	if (mount(NULL, path, NULL,
		  MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV,
		  NULL) != 0)
		dbg_logf("sandbox: %s left writable (read-only remount failed: "
			 "%d)", path, errno);
}

/*
 * The same for a mount that has to stay writable: no execution, no set-id, no
 * device nodes. comrade runs nothing out of its data or state directory, and
 * without this a process that can write there can map what it wrote as code.
 * PR_SET_MDWE does not cover that -- it refuses a write-to-execute transition,
 * not a fresh executable mapping of a file, which is how every dlopen works.
 */
static void remount_noexec(const char *path)
{
#ifdef SYS_mount_setattr
	struct sb_mount_attr a;

	memset(&a, 0, sizeof(a));
	a.attr_set = MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV;
	if (syscall(SYS_mount_setattr, -1, path, AT_RECURSIVE, &a,
		    sizeof(a)) == 0)
		return;
#endif
	if (mount(NULL, path, NULL,
		  MS_REMOUNT | MS_BIND | MS_NOEXEC | MS_NOSUID | MS_NODEV,
		  NULL) != 0)
		dbg_logf("sandbox: %s left executable (remount failed: %d)",
			 path, errno);
}

/*
 * The exact surface the confined process is allowed to see. Both the mount
 * namespace and the Landlock ruleset are built from these two lists, so the two
 * backends grant the same thing. Neither list contains a whole system
 * directory: read-only access to all of /etc or /usr would still let a
 * compromised process read /etc/shadow, an OpenWrt device's wireless keys, or
 * another user's files -- exactly the extraction surface the sandbox is meant
 * to remove. The client never executes anything, so no /bin or /sbin is here
 * at all.
 */

/* Directories holding the shared objects the loader maps and later dlopen()s
 * (the NSS and TLS-provider modules); read-only, but execution preserved. */
static const char *const sb_lib_dirs[] = {
	"/lib", "/lib64", "/usr/lib", "/usr/lib64",
	"/usr/local/lib", "/usr/local/lib64", "/nix/store", "/gnu/store"
};

/* The individual loader, resolver and TLS files the C library reads at runtime.
 * resolv.conf is handled apart (it is usually a symlink to a volatile file). */
static const char *const sb_etc_files[] = {
	"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
	"/etc/ld-musl-x86_64.path", "/etc/ld-musl-aarch64.path",
	"/etc/nsswitch.conf", "/etc/hosts", "/etc/host.conf", "/etc/gai.conf",
	"/etc/services", "/etc/protocols", "/etc/passwd", "/etc/group",
	"/etc/ssl/openssl.cnf", "/etc/ssl/certs", "/etc/pki",
	"/etc/crypto-policies", "/etc/localtime"
};

/* Bind src (a file or a directory) onto <root><at>, creating the mount point of
 * the right kind. recursive carries submounts; ro turns the result read-only.
 * Returns 0 on the bind succeeding, -1 otherwise. */
static int bind_at(const char *root, const char *src, const char *at,
		   int recursive, int ro)
{
	struct stat st;
	char dst[PATH_MAX];
	char *slash;
	unsigned long fl = MS_BIND | (recursive ? (unsigned long)MS_REC : 0UL);
	int fd;

	if (stat(src, &st) != 0) {
		dbg_logf("sandbox: bind source %s is missing (%d)", src, errno);
		return -1;
	}
	if ((size_t)snprintf(dst, sizeof(dst), "%s%s", root, at) >= sizeof(dst))
		return -1;
	if (S_ISDIR(st.st_mode)) {
		mkdir_p(dst);
	} else {
		slash = strrchr(dst, '/');
		if (slash && slash != dst) {
			*slash = '\0';
			mkdir_p(dst);
			*slash = '/';
		}
		fd = open(dst, O_WRONLY | O_CREAT, 0600);
		if (fd >= 0)
			close(fd);
	}
	if (mount(src, dst, NULL, fl, NULL) != 0) {
		dbg_logf("sandbox: could not bind %s (%d)", at, errno);
		return -1;
	}
	if (ro)
		remount_ro(dst);
	else
		remount_noexec(dst);
	return 0;
}

/*
 * Stage one allowed path into the new root read-only: recreate it as a symlink
 * if that is what the host has (so a /lib -> usr/lib layout survives; a symlink
 * whose own target is not staged, like a zoneinfo file, simply dangles, which
 * is cosmetic), otherwise bind the file or directory. Absent paths are skipped.
 */
static int stage_ro(const char *root, const char *path)
{
	struct stat st;
	char dst[PATH_MAX];
	char target[PATH_MAX];
	char *slash;
	ssize_t n;

	if (lstat(path, &st) != 0)
		return 0;			/* absent: nothing to stage */
	if (S_ISLNK(st.st_mode)) {
		n = readlink(path, target, sizeof(target) - 1);
		if (n <= 0)
			return 0;
		target[n] = '\0';
		if ((size_t)snprintf(dst, sizeof(dst), "%s%s", root, path) >=
		    sizeof(dst))
			return 0;
		slash = strrchr(dst, '/');
		if (slash && slash != dst) {
			*slash = '\0';
			mkdir_p(dst);
			*slash = '/';
		}
		if (symlink(target, dst) != 0)
			dbg_logf("sandbox: could not recreate %s -> %s (%d)",
				 path, target, errno);
		return 0;
	}
	return bind_at(root, path, path, 1, 1);
}

/*
 * The directory the live resolv.conf sits in, following symlinks to its real
 * target (which is also returned when `target` is given). It is the DIRECTORY,
 * not the file, that must be bound or granted: a roam installs a new resolver
 * config by writing a fresh file and renaming it into place, so a bind or an
 * open of the old file is left pointing at the unlinked inode and reads stale,
 * while the directory sees the replacement. Returns 0 on success.
 */
static int resolv_dir(char *dir, size_t dn, char *target, size_t tn)
{
	char t[PATH_MAX];
	char *slash;

	if (!realpath("/etc/resolv.conf", t))
		return -1;
	if (target && tn)
		snprintf(target, tn, "%s", t);
	slash = strrchr(t, '/');
	if (!slash || slash == t)
		return -1;
	*slash = '\0';
	if ((size_t)snprintf(dir, dn, "%s", t) >= dn)
		return -1;
	return 0;
}

/*
 * Stage the resolver, loader and TLS files. Where resolv.conf is a symlink out
 * of /etc (systemd-resolved's /run, OpenWrt's /tmp) only its own directory is
 * bound, keeping the rest of /etc out of view. Where it is a plain file managed
 * inside /etc, /etc is bound whole -- catching a rename within a directory
 * needs that directory bound and no narrower mount would, and this case arises
 * only on a desktop, where comrade is a normal user and /etc's secrets stay
 * behind their own permissions.
 */
static int stage_etc(const char *root)
{
	char rdir[PATH_MAX];
	char target[PATH_MAX];
	char dst[PATH_MAX];
	char etc[PATH_MAX];
	int have_resolv;
	int fail = 0;
	size_t i;

	have_resolv = (resolv_dir(rdir, sizeof(rdir), target,
				  sizeof(target)) == 0);
	if (have_resolv && strcmp(rdir, "/etc") == 0)
		return stage_ro(root, "/etc");
	for (i = 0; i < sizeof(sb_etc_files) / sizeof(sb_etc_files[0]); i++)
		if (stage_ro(root, sb_etc_files[i]) < 0)
			fail = 1;
	if (!have_resolv) {
		/* No resolv.conf to follow; its absence is not fatal (the C
		 * library resolver falls back), so this bind is best-effort. */
		bind_at(root, "/etc/resolv.conf", "/etc/resolv.conf", 0, 1);
		return fail ? -1 : 0;
	}
	if (stage_ro(root, rdir) < 0)
		fail = 1;
	if ((size_t)snprintf(etc, sizeof(etc), "%s/etc", root) < sizeof(etc))
		mkdir_p(etc);
	if ((size_t)snprintf(dst, sizeof(dst), "%s/etc/resolv.conf", root) <
	    sizeof(dst) && symlink(target, dst) != 0)
		dbg_logf("sandbox: could not link /etc/resolv.conf -> %s (%d)",
			 target, errno);
	return fail ? -1 : 0;
}

/* Bind a single host device node into the new root's /dev, left writable --
 * /dev/null is written and /dev/urandom is read, and a musl TLS backend reads
 * /dev/urandom throughout the run. */
static int bind_dev(const char *root, const char *node)
{
	char dst[PATH_MAX];
	char *slash;
	int fd;

	if ((size_t)snprintf(dst, sizeof(dst), "%s%s", root, node) >=
	    sizeof(dst))
		return -1;
	/* Create the /dev directory in the new root before the mount point:
	 * without it the mount target does not exist and the bind fails ENOENT. */
	slash = strrchr(dst, '/');
	if (slash && slash != dst) {
		*slash = '\0';
		mkdir_p(dst);
		*slash = '/';
	}
	fd = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd >= 0)
		close(fd);
	if (mount(node, dst, NULL, MS_BIND, NULL) != 0) {
		dbg_logf("sandbox: could not bind %s (%d)", node, errno);
		return -1;
	}
	return 0;
}

/* Bind the writable directories -- the data dir (non-recursively, so the tmpfs
 * staged on its own .ns does not nest into the bind), a host state dir, and the
 * debug log's directory. Shared by the namespace builder below. */
static int bind_writable(const char *root, const struct sandbox_cfg *cfg)
{
	const char *dbg;
	int fail = 0;

	if (bind_at(root, cfg->data_dir, cfg->data_dir, 0, 0) < 0)
		fail = 1;		/* without it the program cannot persist */
	if (cfg->state_dir && cfg->state_dir[0] &&
	    bind_at(root, cfg->state_dir, cfg->state_dir, 0, 0) < 0)
		fail = 1;
	dbg = getenv("COMRADE_DEBUG");
	if (dbg && dbg[0] == '/') {
		char dir[PATH_MAX];
		char *slash;

		/* The debug log's directory is convenient, not essential -- its
		 * bind failing (bind_at logs it) does not fail the confinement. */
		if ((size_t)snprintf(dir, sizeof(dir), "%s", dbg) < sizeof(dir)) {
			slash = strrchr(dir, '/');
			if (slash && slash != dir) {
				*slash = '\0';
				bind_at(root, dir, dir, 0, 0);
			}
		}
	}
	return fail ? -1 : 0;
}

/*
 * Build the confined root in a private mount namespace and pivot into it. An
 * unprivileged user namespace grants the mount privilege; a root process for
 * which even that is unavailable (a tiny-flash OpenWrt build) falls back to a
 * bare mount namespace carried by its real CAP_SYS_ADMIN. Every bind is
 * best-effort; only pivot_root, which runs last over the finished tree, could
 * strand the program, and a failure there detaches the half-built tree and
 * leaves the normal view.
 */
static int fs_confine_ns(const struct sandbox_cfg *cfg)
{
	char root[PATH_MAX];
	uid_t uid;
	gid_t gid;
	int fail;
	size_t i;

	uid = getuid();
	gid = getgid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0) {
		map_ids(uid, gid);
	} else if (geteuid() == 0 && unshare(CLONE_NEWNS) == 0) {
		/* Root without a user namespace: the real CAP_SYS_ADMIN carries
		 * the mounts and no id map is needed. */
	} else {
		dbg_logf("sandbox: no mount namespace (%d); trying Landlock",
			 errno);
		return 0;
	}

	if (mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL) != 0) {
		dbg_logf("sandbox: could not privatise mounts (%d)", errno);
		return 0;
	}
	if ((size_t)snprintf(root, sizeof(root), "%s/.ns", cfg->data_dir) >=
	    sizeof(root))
		return 0;
	mkdir(root, 0700);
	if (mount("tmpfs", root, "tmpfs", MS_NOSUID | MS_NODEV,
		  "mode=0755,size=1M") != 0) {
		dbg_logf("sandbox: could not mount the confined root (%d)",
			 errno);
		return 0;
	}

	fail = 0;
	for (i = 0; i < sizeof(sb_lib_dirs) / sizeof(sb_lib_dirs[0]); i++)
		if (stage_ro(root, sb_lib_dirs[i]) < 0)
			fail = 1;
	if (stage_etc(root) < 0)
		fail = 1;
	if (bind_dev(root, "/dev/null") < 0)
		fail = 1;
	if (bind_dev(root, "/dev/urandom") < 0)
		fail = 1;
	if (bind_writable(root, cfg) < 0)
		fail = 1;

	/*
	 * If a piece the program needs could not be staged, do not pivot into a
	 * root that would break it: detach the half-built tree and run
	 * unconfined but working. The sandbox is defence in depth, so a broken
	 * confinement is worse than none -- and each failure was already logged.
	 */
	if (fail) {
		dbg_logf("sandbox: confined root incomplete; leaving the "
			 "filesystem open");
		umount2(root, MNT_DETACH);
		return 0;
	}

	if (chdir(root) != 0 || syscall(SYS_pivot_root, ".", ".") != 0) {
		dbg_logf("sandbox: pivot_root failed (%d); filesystem left open",
			 errno);
		if (chdir("/") != 0)
			dbg_logf("sandbox: chdir / failed (%d)", errno);
		umount2(root, MNT_DETACH);
		return 0;
	}
	umount2(".", MNT_DETACH);
	if (chdir("/") != 0)
		dbg_logf("sandbox: chdir / after pivot failed (%d)", errno);
	return SANDBOX_L_USERNS | SANDBOX_L_MOUNTNS;
}

/*
 * The desktop filesystem path: a Landlock ruleset, for kernels that refuse an
 * unprivileged user namespace (a hardened desktop, a locked-down container). It
 * confines by access, not by visibility -- the paths stay listable but only the
 * ones granted here can be read, and only the data dir written -- so it is a
 * weaker boundary than the namespace, yet still keeps the program out of every
 * file it was not handed. Landlock does not exist on OpenWrt, so this is purely
 * the fallback for where the namespace could not be built. Raw syscalls, since
 * the UAPI header cannot be assumed; best-effort and ABI-aware.
 */

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif
#define SB_LANDLOCK_VERSION_QUERY 1U
#define SB_LANDLOCK_RULE_PATH_BENEATH 1

#define SB_FS_EXECUTE		(1ULL << 0)
#define SB_FS_WRITE_FILE	(1ULL << 1)
#define SB_FS_READ_FILE		(1ULL << 2)
#define SB_FS_READ_DIR		(1ULL << 3)
#define SB_FS_REMOVE_DIR	(1ULL << 4)
#define SB_FS_REMOVE_FILE	(1ULL << 5)
#define SB_FS_MAKE_CHAR		(1ULL << 6)
#define SB_FS_MAKE_DIR		(1ULL << 7)
#define SB_FS_MAKE_REG		(1ULL << 8)
#define SB_FS_MAKE_SOCK		(1ULL << 9)
#define SB_FS_MAKE_FIFO		(1ULL << 10)
#define SB_FS_MAKE_BLOCK	(1ULL << 11)
#define SB_FS_MAKE_SYM		(1ULL << 12)
#define SB_FS_TRUNCATE		(1ULL << 14)
#define SB_FS_IOCTL_DEV		(1ULL << 15)

struct sb_ruleset_attr {
	uint64_t handled_access_fs;
};

struct sb_path_beneath {
	uint64_t allowed_access;
	int32_t parent_fd;
} __attribute__((packed));

/* The rights that apply to a regular file; the rest are directory-only and the
 * kernel rejects a rule that grants them on a file. */
#define SB_FS_FILE (SB_FS_EXECUTE | SB_FS_WRITE_FILE | SB_FS_READ_FILE | \
		    SB_FS_TRUNCATE)

/* Grant `access` beneath `path`; a path that is not present is skipped, and a
 * file keeps only the file-applicable rights so the rule is not rejected. */
static void ll_allow(int rs, const char *path, uint64_t access)
{
	struct sb_path_beneath pb;
	struct stat st;
	int fd;

	if (access == 0)
		return;
	fd = open(path, O_PATH | O_CLOEXEC);
	if (fd < 0)
		return;
	if (fstat(fd, &st) == 0 && !S_ISDIR(st.st_mode))
		access &= SB_FS_FILE;
	if (access == 0) {
		close(fd);
		return;
	}
	memset(&pb, 0, sizeof(pb));
	pb.allowed_access = access;
	pb.parent_fd = fd;
	if (syscall(__NR_landlock_add_rule, rs, SB_LANDLOCK_RULE_PATH_BENEATH,
		    &pb, 0U) != 0)
		dbg_logf("sandbox: landlock rule for %s failed (%d)", path,
			 errno);
	close(fd);
}

static int fs_confine_landlock(const struct sandbox_cfg *cfg)
{
	struct sb_ruleset_attr attr;
	char resolv[PATH_MAX];
	char dir[PATH_MAX];
	const char *dbg;
	char *slash;
	uint64_t handled, ro, rwx, rw;
	long abi;
	int rs;
	int have_resolv;
	size_t i;

	abi = syscall(__NR_landlock_create_ruleset, (void *)0, (size_t)0,
		      SB_LANDLOCK_VERSION_QUERY);
	if (abi < 1)
		return 0;		/* no Landlock on this kernel */

	/*
	 * An access left out of this mask is one Landlock never checks, so the
	 * node-creating rights belong here even though nothing grants them: a
	 * confined comrade makes no symlink, socket, fifo or device node
	 * anywhere, and leaving them unhandled is what would let it plant one
	 * wherever the ordinary permissions allow.
	 */
	handled = SB_FS_EXECUTE | SB_FS_WRITE_FILE | SB_FS_READ_FILE |
		  SB_FS_READ_DIR | SB_FS_REMOVE_DIR | SB_FS_REMOVE_FILE |
		  SB_FS_MAKE_DIR | SB_FS_MAKE_REG | SB_FS_MAKE_CHAR |
		  SB_FS_MAKE_SOCK | SB_FS_MAKE_FIFO | SB_FS_MAKE_BLOCK |
		  SB_FS_MAKE_SYM;
	if (abi >= 3)
		handled |= SB_FS_TRUNCATE;
	/*
	 * Only devices opened after this point are affected, and the terminal
	 * comrade drives was opened long before it, so this costs the roles
	 * nothing and forbids driver ioctls on anything opened later.
	 */
	if (abi >= 5)
		handled |= SB_FS_IOCTL_DEV;

	memset(&attr, 0, sizeof(attr));
	attr.handled_access_fs = handled;
	rs = (int)syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0U);
	if (rs < 0)
		return 0;

	ro = (SB_FS_READ_FILE | SB_FS_READ_DIR) & handled;
	rwx = (SB_FS_READ_FILE | SB_FS_READ_DIR | SB_FS_EXECUTE) & handled;
	rw = (SB_FS_READ_FILE | SB_FS_WRITE_FILE | SB_FS_READ_DIR |
	      SB_FS_REMOVE_FILE | SB_FS_MAKE_REG | SB_FS_MAKE_DIR |
	      SB_FS_REMOVE_DIR | SB_FS_TRUNCATE) & handled;

	for (i = 0; i < sizeof(sb_lib_dirs) / sizeof(sb_lib_dirs[0]); i++)
		ll_allow(rs, sb_lib_dirs[i], rwx);
	/* Grant the resolver's directory, not its file, so a roam's rename is
	 * followed; /etc whole only where resolv.conf is a plain /etc file. */
	have_resolv = (resolv_dir(resolv, sizeof(resolv), (char *)0, 0) == 0);
	if (have_resolv && strcmp(resolv, "/etc") == 0) {
		ll_allow(rs, "/etc", ro);
	} else {
		for (i = 0; i < sizeof(sb_etc_files) / sizeof(sb_etc_files[0]);
		     i++)
			ll_allow(rs, sb_etc_files[i], ro);
		if (have_resolv)
			ll_allow(rs, resolv, ro);
	}
	ll_allow(rs, "/dev/urandom", SB_FS_READ_FILE & handled);
	ll_allow(rs, "/dev/null", (SB_FS_READ_FILE | SB_FS_WRITE_FILE) & handled);
	ll_allow(rs, cfg->data_dir, rw);
	if (cfg->state_dir && cfg->state_dir[0])
		ll_allow(rs, cfg->state_dir, rw);
	dbg = getenv("COMRADE_DEBUG");
	if (dbg && dbg[0] == '/' &&
	    (size_t)snprintf(dir, sizeof(dir), "%s", dbg) < sizeof(dir)) {
		slash = strrchr(dir, '/');
		if (slash && slash != dir) {
			*slash = '\0';
			ll_allow(rs, dir, rw);
		}
	}

	/* Landlock enforcement requires no_new_privs; setting it here is
	 * harmless -- apply_linux sets it again for the other layers. */
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (syscall(__NR_landlock_restrict_self, rs, 0U) != 0) {
		close(rs);
		return 0;
	}
	close(rs);
	return SANDBOX_L_LANDLOCK;
}

/*
 * Confine the visible filesystem with both boundaries, because they fail in
 * different places. The mount namespace decides what exists, and it has to
 * bind in whichever directory resolv.conf lives in -- which is /etc on a host
 * with a static one and the whole of /tmp on OpenWrt, where /etc/resolv.conf
 * points into it. Landlock decides what may be reached, so it takes back what
 * the namespace was obliged to make visible; and unlike a read-only bind it
 * covers connecting to a unix socket, which is how the interesting things in
 * those directories are spoken to.
 *
 * Either may be absent and the other still applies. COMRADE_SANDBOX_NO_USERNS
 * forces the Landlock path alone -- for exercising it, and for a host where a
 * mount namespace is unwanted.
 */
static int fs_confine(const struct sandbox_cfg *cfg)
{
	const char *nons;
	int r = 0;

	if (!cfg->data_dir || !cfg->data_dir[0])
		return 0;		/* no writable home to build around */

	nons = getenv("COMRADE_SANDBOX_NO_USERNS");
	if (!(nons && nons[0] && nons[0] != '0'))
		r = fs_confine_ns(cfg);
	return r | fs_confine_landlock(cfg);
}

static int apply_linux(const struct sandbox_cfg *cfg)
{
	int layers = 0;
	/*
	 * Confine the filesystem and deny exec only for a process that will not
	 * exec: the client, and the service when a spawner does its spawning.
	 * A service without a spawner forks tmux itself, so those layers would
	 * be inherited by the shells and must not apply; the rest still do.
	 */
	int confine = (cfg->role == SANDBOX_CLIENT) ||
		(cfg->role == SANDBOX_SERVICE && cfg->have_spawner);

	/*
	 * Order matters. The filesystem confinement enters a user namespace and
	 * mounts a new root, which needs the capabilities that namespace grants
	 * and a still-dumpable /proc/self to write its id maps -- so it runs
	 * before the capability drop and before dumpability is turned off. The
	 * capability drop, no_new_privs and the seccomp filter follow, seccomp
	 * last so nothing this function does is itself filtered (and so the
	 * filter can forbid further mounts). The foreground keeps exec and a
	 * full filesystem because it runs tmux, so it takes neither the
	 * confinement nor the exec-denying filter -- only the no-network one.
	 */
	layers |= limit_core();
	if (cfg->role == SANDBOX_CLIENT) {
		/* The client holds only its standard descriptors here; shut the
		 * door on any other inherited fd. The host children keep their
		 * control and status descriptors, so they are left alone. */
#ifdef __NR_close_range
		syscall(__NR_close_range, 3, ~0U, 0);	/* best effort */
#endif
	}
	layers |= mdwe();
	if (confine)
		layers |= fs_confine(cfg);
	layers |= no_dumpable();
	layers |= drop_caps();
	layers |= no_new_privs();
	layers |= seccomp_apply(cfg->role, confine);
	return layers;
}

#else /* a Unix that is neither macOS nor Linux */

static int apply_generic(const struct sandbox_cfg *cfg)
{
	(void)cfg;
	return limit_core();
}

#endif

int sandbox_apply(const struct sandbox_cfg *cfg)
{
	int layers;

	if (!cfg || sandbox_disabled()) {
		dbg_logf("sandbox: disabled");
		return 0;
	}
#if defined(__APPLE__)
	layers = apply_macos(cfg);
#elif defined(__linux__)
	layers = apply_linux(cfg);
#else
	layers = apply_generic(cfg);
#endif
	dbg_logf("sandbox: role=%d layers=0x%x", cfg->role, layers);
	return layers;
}

int sandbox_needs_spawner(void)
{
	if (sandbox_disabled())
		return 0;
#if defined(__APPLE__)
	return 1;			/* the Seatbelt profile denies exec */
#elif defined(__linux__)
	return seccomp_available();
#else
	return 0;
#endif
}

#endif /* !_WIN32 */
