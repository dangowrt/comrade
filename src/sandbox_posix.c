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

extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
					const char *const parameters[],
					char **errorbuf);

/* Filled in a later commit: compose the per-role SBPL and apply it, plus the
 * fork-blocking RLIMIT_NPROC=0 (macOS threads are not processes, so unlike
 * Linux it does not strangle pthread_create). Kept a stub so the file builds
 * and links on macOS from the first commit. */
static int apply_macos(const struct sandbox_cfg *cfg)
{
	int layers = 0;

	(void)cfg;
	layers |= limit_core();
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

static int seccomp_apply(int role)
{
#if defined(SYS_seccomp) && defined(SB_AUDIT_ARCH)
	if (role == SANDBOX_FOREGROUND)
		return seccomp_nonet();
	return seccomp_noexec();
#else
	(void)role;
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
	a.attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID;
	if (syscall(SYS_mount_setattr, -1, path, AT_RECURSIVE, &a,
		    sizeof(a)) == 0)
		return;
#endif
	/* The remount only takes read-only in a second call, and must not try to
	 * relax a flag the namespace locked; adding rdonly/nosuid/nodev never is
	 * relaxing, and no atime flag is touched. */
	mount(NULL, path, NULL,
	      MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL);
}

/* Bind src onto <root><at>, creating the mount point. recursive carries
 * submounts; ro turns the result read-only. Returns 0 on the bind succeeding. */
static int bind_at(const char *root, const char *src, const char *at,
		   int recursive, int ro)
{
	char dst[PATH_MAX];
	unsigned long fl = MS_BIND | (recursive ? (unsigned long)MS_REC : 0UL);

	if ((size_t)snprintf(dst, sizeof(dst), "%s%s", root, at) >= sizeof(dst))
		return -1;
	mkdir_p(dst);
	if (mount(src, dst, NULL, fl, NULL) != 0)
		return -1;
	if (ro)
		remount_ro(dst);
	return 0;
}

/*
 * Stage one top-level system directory into the new root: recreate it as a
 * symlink if that is what the host has (so /bin -> usr/bin layouts survive),
 * otherwise bind it read-only. Absent directories are skipped.
 */
static void stage_sysdir(const char *root, const char *name)
{
	struct stat st;
	char dst[PATH_MAX];
	char target[PATH_MAX];
	ssize_t n;

	if (lstat(name, &st) != 0)
		return;
	if (S_ISLNK(st.st_mode)) {
		n = readlink(name, target, sizeof(target) - 1);
		if (n <= 0)
			return;
		target[n] = '\0';
		if ((size_t)snprintf(dst, sizeof(dst), "%s%s", root, name) >=
		    sizeof(dst))
			return;
		symlink(target, dst);
		return;
	}
	bind_at(root, name, name, 1, 1);
}

/* Bind a single host device node (character device) into the new root's /dev,
 * left writable -- /dev/null is written and /dev/urandom is read, and some TLS
 * backends on musl read /dev/urandom throughout the run. */
static void bind_dev(const char *root, const char *node)
{
	char dst[PATH_MAX];
	int fd;

	if ((size_t)snprintf(dst, sizeof(dst), "%s%s", root, node) >=
	    sizeof(dst))
		return;
	fd = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd >= 0)
		close(fd);
	mount(node, dst, NULL, MS_BIND, NULL);
}

static int fs_confine(const struct sandbox_cfg *cfg)
{
	static const char *sysdirs[] = {
		"/usr", "/etc", "/bin", "/sbin", "/lib", "/lib64",
		"/lib32", "/opt", "/run", "/var", "/nix", "/gnu"
	};
	char root[PATH_MAX];
	char resolv[PATH_MAX];
	const char *dbg;
	uid_t uid;
	gid_t gid;
	size_t i;

	if (!cfg->data_dir || !cfg->data_dir[0])
		return 0;		/* no writable home to build around */

	uid = getuid();
	gid = getgid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
		dbg_logf("sandbox: no user namespace (%d); filesystem left open",
			 errno);
		return 0;
	}
	map_ids(uid, gid);

	/* Keep every mount from here private to this process. */
	if (mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL) != 0) {
		dbg_logf("sandbox: could not privatise mounts (%d)", errno);
		return 0;
	}

	/* The new root is a small tmpfs under the data dir, not /tmp, which on
	 * OpenWrt holds the resolver config we still need to bind from. */
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

	for (i = 0; i < sizeof(sysdirs) / sizeof(sysdirs[0]); i++)
		stage_sysdir(root, sysdirs[i]);

	/* If resolv.conf resolves outside /etc (systemd-resolved, or OpenWrt's
	 * /tmp), bind that directory read-only so the C library can keep reading
	 * it -- and never the file itself, whose inode a rename would leave
	 * stale. */
	if (realpath("/etc/resolv.conf", resolv) &&
	    strncmp(resolv, "/etc/", 5) != 0) {
		char *slash = strrchr(resolv, '/');

		if (slash && slash != resolv) {
			*slash = '\0';
			bind_at(root, resolv, resolv, 1, 1);
		}
	}

	bind_dev(root, "/dev/null");
	bind_dev(root, "/dev/urandom");

	/* Writable: the data dir (bound non-recursively so the tmpfs staged on
	 * its own .ns does not nest into the bind), the host state dir for a
	 * service, and the debug log's directory when one is set. */
	bind_at(root, cfg->data_dir, cfg->data_dir, 0, 0);
	if (cfg->state_dir && cfg->state_dir[0])
		bind_at(root, cfg->state_dir, cfg->state_dir, 0, 0);
	dbg = getenv("COMRADE_DEBUG");
	if (dbg && dbg[0] == '/') {
		char dir[PATH_MAX];
		char *slash;

		if ((size_t)snprintf(dir, sizeof(dir), "%s", dbg) < sizeof(dir)) {
			slash = strrchr(dir, '/');
			if (slash && slash != dir) {
				*slash = '\0';
				bind_at(root, dir, dir, 0, 0);
			}
		}
	}

	/* Pivot into the new root and drop the old one. From here the process
	 * cannot see anything outside what was bound above. */
	if (chdir(root) != 0 ||
	    syscall(SYS_pivot_root, ".", ".") != 0) {
		dbg_logf("sandbox: pivot_root failed (%d); filesystem left open",
			 errno);
		(void)chdir("/");	/* best effort */
		umount2(root, MNT_DETACH);
		return 0;
	}
	umount2(".", MNT_DETACH);
	(void)chdir("/");		/* best effort */

	return SANDBOX_L_USERNS | SANDBOX_L_MOUNTNS;
}

static int apply_linux(const struct sandbox_cfg *cfg)
{
	int layers = 0;

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
	if (cfg->role != SANDBOX_FOREGROUND)
		layers |= fs_confine(cfg);
	layers |= no_dumpable();
	layers |= drop_caps();
	layers |= no_new_privs();
	layers |= seccomp_apply(cfg->role);
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

#endif /* !_WIN32 */
