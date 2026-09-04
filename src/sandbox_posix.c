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

/*
 * The installed filter's length, for sandbox_filter_insns(). Set where a
 * filter is actually accepted by the kernel, so it stays 0 on a platform that
 * compiles none and on a kernel that refused the one it was given.
 */
static int sb_filter_insns;

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

/*
 * Weakly imported, so the day Apple finally removes the SPI it has been
 * deprecating since 10.8 the binary loses a layer instead of refusing to
 * launch. An ordinary extern here is resolved by dyld at load time, which
 * would make its absence fatal.
 */
extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
					const char *const parameters[],
					char **errorbuf) __attribute__((weak_import));
extern void sandbox_free_error(char *errorbuf) __attribute__((weak_import));

/*
 * The confining profile (client and service): deny everything, then allow the
 * narrow set the work needs -- the library directories to map and read, the
 * resolver's pieces, the process's own data and state directories to read and
 * write, and UDP. Exec and fork are covered by the default and denied again by
 * name, because a policy should state its own guarantee rather than leave a
 * reader to derive it; a compromised process cannot run anything, and the host
 * service does its spawning either from a broker forked before this applies or
 * not at all. DATA_DIR and STATE_DIR are passed as parameters so the one
 * profile serves any path.
 *
 * The peer is named by protocol rather than allowed with network*, which would
 * also carry every UNIX-domain socket on the machine -- an address there is a
 * path, so ssh-agent, a container daemon and any other program's control
 * socket come with it. UDP is all comrade's own transport ever speaks: the
 * DHT, the multicast rendezvous, STUN, ICE and the KCP the session rides. TCP
 * is not part of this profile at all; sb_profile_tcp below is appended for the
 * roles that forward ports, which is the only place it is used.
 *
 * sysctl-read is granted by name rather than wholesale: net.route is what
 * getifaddrs() walks, hw.memsize is read directly (bep44.c sizes its store
 * from it), and the three remaining hw names are what sysconf() reaches for
 * underneath a threaded library. Nothing here needs the machine's identity,
 * hostname or uptime, so those names are not granted -- and granting them
 * would not have made uname() work either, since that also wants kern.version
 * and hw.machine.
 *
 * Two things about SBPL that this profile depends on, both of which fail
 * silently when they are got wrong:
 *
 *  1. Path checks canonicalise, so (subpath "/etc") matches nothing -- /etc is
 *     a symlink and /private/etc is what a rule must name. Following that
 *     symlink is itself a metadata read of the link, which is why the three
 *     literals below are granted: /etc, /tmp and /var. state_dir() hands back
 *     an unresolved /tmp/... path while the grant is the realpath of it, and
 *     $TMPDIR lives under /var/folders.
 *  2. (sysctl-name-prefix "net.route.") -- with the trailing dot -- compiles,
 *     runs, and denies getifaddrs() for the whole process. libjuice is only
 *     where the symptom shows: the host gathers one ICE candidate instead of
 *     three and the punch fails, with no error and no violation logged. The
 *     name carries no trailing dot.
 */
static const char sb_profile_confine[] =
"(version 1)\n"
"(deny default)\n"
"(deny process-exec* process-fork)\n"
"(allow file-read-metadata\n"
"  (literal \"/etc\") (literal \"/tmp\") (literal \"/var\"))\n"
"(allow file-read* file-map-executable\n"
"  (subpath \"/usr/lib\") (subpath \"/System/Library\")\n"
"  (subpath \"/System/Cryptexes\")\n"
"  (subpath \"/System/Volumes/Preboot/Cryptexes\")\n"
"  (subpath \"/usr/local/lib\") (subpath \"/usr/local/opt\")\n"
"  (subpath \"/usr/local/Cellar\")\n"
"  (subpath \"/opt/homebrew/lib\") (subpath \"/opt/homebrew/opt\")\n"
"  (subpath \"/opt/homebrew/Cellar\"))\n"
"(allow file-read*\n"
"  (subpath \"/private/etc\")\n"
"  (literal \"/private/var/run/resolv.conf\")\n"
"  (literal \"/dev/null\")\n"
"  (literal \"/dev/random\") (literal \"/dev/urandom\"))\n"
"(allow file-write-data (literal \"/dev/null\"))\n"
"(allow file-read* file-write*\n"
"  (subpath (param \"DATA_DIR\")) (subpath (param \"STATE_DIR\")))\n"
"(allow signal (target self))\n"
"(allow sysctl-read\n"
"  (sysctl-name \"hw.memsize\") (sysctl-name \"hw.ncpu\")\n"
"  (sysctl-name \"hw.activecpu\") (sysctl-name \"hw.pagesize\")\n"
"  (sysctl-name-prefix \"net.route\"))\n"
"(allow mach-lookup\n"
"  (global-name \"com.apple.dnssd.service\")\n"
"  (global-name \"com.apple.SystemConfiguration.configd\")\n"
"  (global-name \"com.apple.SystemConfiguration.DNSConfiguration\")\n"
"  (global-name \"com.apple.system.notification_center\")\n"
"  (global-name \"com.apple.system.opendirectoryd.libinfo\")\n"
"  (global-name \"com.apple.system.logger\"))\n"
"(allow ipc-posix-shm-read-data\n"
"  (ipc-posix-name \"apple.shm.notification_center\"))\n"
"(allow network-bind (local udp \"*:*\"))\n"
"(allow network-inbound (local udp \"*:*\"))\n"
"(allow network-outbound (remote udp \"*:*\"))\n"
"(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n";

/*
 * Appended to the profile above for a role that drives a terminal, and left off
 * the one that cannot. A forwarding-only host serves no shell -- sshd sends it
 * straight to the pump, so the shell request that is the only route to
 * cpty_spawn never runs -- which makes it the tightest of the profiles rather
 * than the loosest, the right way round for the only service that runs nothing
 * at all.
 *
 * What the grant buys is the terminal-altering ioctls: putting one in raw mode
 * or changing its settings. Asking a terminal about itself, its window size
 * included, is permitted without it. And being appended, the rule sits at the
 * end of the composed profile rather than beside the other file rules; SBPL
 * takes the last match and nothing after it names a terminal, so the set of
 * permissions is the same as when it was written in place.
 */
static const char sb_profile_tty[] =
"(allow file-ioctl (literal \"/dev/tty\") (regex #\"^/dev/ttys[0-9]+$\"))\n";

/*
 * Appended for a role that forwards ports, and left off every other one. A
 * -L or -R is the only TCP comrade ever opens, so a client asked for no
 * forwards and a host started --no-fwd both run with TCP denied outright,
 * while the transport they exist for is untouched.
 *
 * All three operations are granted together because which of them a forward
 * needs depends on the side and the direction: a -L has the client listening
 * and the host connecting out, a -R is the mirror of that, and the host learns
 * its port from the client long after it is confined.
 *
 * The pairing is the opposite way round from the terminal rule above: a
 * forwarding-only host serves no shell but exists to forward, so it is the one
 * service that must have this.
 */
static const char sb_profile_tcp[] =
"(allow network-bind (local tcp \"*:*\"))\n"
"(allow network-inbound (local tcp \"*:*\"))\n"
"(allow network-outbound (remote tcp \"*:*\"))\n";

/*
 * The foreground profile: it runs the operator's local tmux, so it keeps
 * everything a program normally does -- exec, files, a pty, local (unix)
 * sockets -- and loses the network. Each denial names an IP peer rather than
 * being written as a blanket (deny network*), which is the mirror of the
 * argument in the confining profile above: a UNIX-domain address is a path, so
 * denying the whole operation would take the connection to the tmux socket with
 * it and the attach would stop working.
 *
 * This profile is hygiene, not containment: the role can drive an unconfined
 * tmux session, so anything denied here is reachable by typing into a shell.
 */
static const char sb_profile_nonet[] =
"(version 1)\n"
"(allow default)\n"
"(deny network-bind (local ip \"*:*\"))\n"
"(deny network-inbound)\n"
"(deny network-outbound (remote ip \"*:*\"))\n"
"(deny system-socket)\n"
"(deny sysctl-write)\n"
"(deny nvram*)\n"
"(deny job-creation)\n"
"(deny authorization-right-obtain)\n";

/* Apply an SBPL profile; returns 1 on success, 0 (logged) on failure. */
static int seatbelt(const char *profile, const char *const *params)
{
	char *err = NULL;

	if (!sandbox_init_with_parameters) {
		dbg_logf("sandbox: no seatbelt on this system");
		return 0;
	}
	if (sandbox_init_with_parameters(profile, 0, params, &err) == 0)
		return 1;
	dbg_logf("sandbox: seatbelt failed: %s", err ? err : "?");
	if (err && sandbox_free_error)
		sandbox_free_error(err);
	return 0;
}

/*
 * Whether this role will open a TCP socket at all. A client knows its forwards
 * from its own -L and -R arguments; a host cannot know the ports in advance,
 * so it says only whether it will forward at all. Neither is true for a role
 * that forwards nothing, and that role gets no TCP.
 */
static int wants_tcp(const struct sandbox_cfg *cfg)
{
	return cfg->tcp_any || cfg->n_tcp_bind > 0 || cfg->n_tcp_connect > 0;
}

static int apply_macos(const struct sandbox_cfg *cfg)
{
	int layers = 0;
	char dd[PATH_MAX];
	char sd[PATH_MAX];
	char prof[sizeof(sb_profile_confine) + sizeof(sb_profile_tty) +
		  sizeof(sb_profile_tcp)];
	const char *params[5];
	struct rlimit rl;
	int confine;

	layers |= limit_core();
	if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == 0)	/* refuse a debugger */
		layers |= SANDBOX_L_NODUMP;

	if (cfg->role == SANDBOX_FOREGROUND) {
		if (seatbelt(sb_profile_nonet, (const char *const *)0))
			layers |= SANDBOX_L_SECCOMP;
		return layers;
	}

	/*
	 * The same gate apply_linux() uses, and for the same reason: the fork
	 * and exec denials below are only correct for a service whose spawning
	 * is already done elsewhere. A service without a broker runs tmux
	 * itself, and denying it both would leave every client attach failing
	 * with nothing to explain it.
	 */
	confine = cfg->role == SANDBOX_CLIENT ||
		  (cfg->role == SANDBOX_SERVICE && cfg->no_exec);
	if (!confine)
		return layers;

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
	snprintf(prof, sizeof(prof), "%s%s%s", sb_profile_confine,
		 cfg->no_pty ? "" : sb_profile_tty,
		 wants_tcp(cfg) ? sb_profile_tcp : "");
	if (seatbelt(prof, params))
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
/*
 * Before <sys/ioctl.h>, and on purpose: TCGETS2 and TCSETS2 are _IOR/_IOW
 * macros over struct termios2, which asm/ioctls.h names but does not define,
 * so the ioctl argument rule cannot use them without this. It is the only
 * header that declares that struct, and unlike <linux/termios.h> it redefines
 * nothing the C library owns -- no struct winsize, no ioctl numbers -- as long
 * as <termios.h> stays out of this file.
 */
#include <asm/termbits.h>

#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/time.h>

#include <signal.h>		/* the SIGSYS handler of COMRADE_SANDBOX=warn */
#include <linux/sockios.h>	/* SIOCGIFINDEX/SIOCGIFNAME for the ioctl rule */

/* --sandbox-selftest does the things the program does, behind the filter. */
#include <dirent.h>
#include <netdb.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <netinet/in.h>

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

/*
 * The securebits, spelled out here so no libcap header is needed. Each is a
 * pair: the bit itself, and the lock that stops it being cleared again.
 */
#ifndef PR_SET_SECUREBITS
#define PR_SET_SECUREBITS 28
#endif
#define SB_SECBIT_NOROOT			(1 << 0)
#define SB_SECBIT_NOROOT_LOCKED			(1 << 1)
#define SB_SECBIT_NO_SETUID_FIXUP		(1 << 2)
#define SB_SECBIT_NO_SETUID_FIXUP_LOCKED	(1 << 3)
#define SB_SECBIT_KEEP_CAPS_LOCKED		(1 << 5)
#define SB_SECBIT_NO_CAP_AMBIENT_RAISE		(1 << 6)
#define SB_SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED	(1 << 7)
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

/*
 * Write^execute: no page may become executable after having been writable.
 * dlopen still works (it maps executable directly); only a JIT would care, and
 * nothing comrade links has one. Irreversible; harmless where unsupported.
 *
 * A debug build leaves it off, and that is what makes the program runnable
 * under valgrind at all: memcheck maps its own shadow memory executable, so
 * the first mapping it needs after this dies with "out of memory: Permission
 * denied" and takes the whole run with it. Gating on the build type means a
 * release ships hardened while the tool that has to rewrite the program's
 * memory can still see every other layer -- the namespaces, the filesystem
 * confinement, the capability drop and the syscall filter -- rather than
 * having to be handed a process with no confinement at all.
 */
static int mdwe(void)
{
#ifdef NDEBUG
	if (prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) == 0)
		return SANDBOX_L_MDWE;
#endif
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

	/*
	 * Clearing the sets is not enough for a process that starts as root,
	 * which on a router is the normal case: uid 0 has its capabilities
	 * recomputed at execve, and an empty permitted set fills straight back
	 * up. These bits refuse that, refuse the recompute on a uid change, and
	 * lock both decisions so nothing later can undo them. Needs CAP_SETPCAP,
	 * so it runs before the sets are dropped and is skipped, like every
	 * other layer, where the kernel refuses it.
	 */
	prctl(PR_SET_SECUREBITS,
	      SB_SECBIT_NOROOT | SB_SECBIT_NOROOT_LOCKED |
	      SB_SECBIT_NO_SETUID_FIXUP | SB_SECBIT_NO_SETUID_FIXUP_LOCKED |
	      SB_SECBIT_KEEP_CAPS_LOCKED | SB_SECBIT_NO_CAP_AMBIENT_RAISE |
	      SB_SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED, 0, 0, 0);

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
 * The audit arch constant the kernel stamps into every seccomp_data, chosen
 * from the target this build is for. It has to be exactly right: a filter
 * whose preamble compares the wrong constant kills the process on its first
 * syscall, so an architecture that cannot be named here is left without a
 * filter rather than guessed at.
 *
 * Three of the answers below are not what the target triple suggests, and all
 * three come from the kernel's own syscall_get_arch():
 *
 *   - arm returns AUDIT_ARCH_ARM whatever the endianness, so a big-endian arm
 *     process reports the little-endian-flagged constant. AUDIT_ARCH_ARMEB
 *     exists but the kernel never reports it, so it must never be selected.
 *   - 32-bit powerpc likewise returns AUDIT_ARCH_PPC in both endiannesses,
 *     including for a 32-bit task on a ppc64le kernel.
 *   - mips is the only family that folds endianness in, and it folds the ABI
 *     in as well: three number bases (o32 4000, n64 5000, n32 6000) times two
 *     endiannesses gives six constants.
 *
 * riscv32 is deliberately absent. The kernel returns AUDIT_ARCH_RISCV64
 * whenever CONFIG_64BIT, so the same rv32 binary reports one constant on an
 * rv32 kernel and another on an rv64 one, and nothing available at build time
 * can tell which it will meet.
 *
 * SB_COMPAT_* names a second ABI the same kernel may report, for the one role
 * that still execs: a filter survives execve and is inherited by every
 * descendant, so a preamble that kills on any other constant kills a
 * foreign-ABI child. The roles that deny exec cannot reach that case, and
 * there the kill stays as a tripwire.
 */

/* Constants a build host's headers may predate. */
#ifndef EM_RISCV
#define EM_RISCV 243
#endif
#ifndef EM_LOONGARCH
#define EM_LOONGARCH 258
#endif
#ifndef AUDIT_ARCH_RISCV64
#define AUDIT_ARCH_RISCV64 (EM_RISCV | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#endif
#ifndef AUDIT_ARCH_PPC64LE
#define AUDIT_ARCH_PPC64LE (EM_PPC64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#endif
#ifndef AUDIT_ARCH_LOONGARCH64
#define AUDIT_ARCH_LOONGARCH64 \
	(EM_LOONGARCH | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#endif

#if defined(__x86_64__)
# if defined(__ILP32__)
/* x32: the kernel reports AUDIT_ARCH_X86_64 and sets bit 30 in nr, so the
 * numbers in the tables below already carry it and no guard is wanted. */
#  define SB_AUDIT_ARCH AUDIT_ARCH_X86_64
#  define SB_ARCH_NAME "AUDIT_ARCH_X86_64 (x32)"
# else
#  define SB_AUDIT_ARCH AUDIT_ARCH_X86_64
#  define SB_ARCH_NAME "AUDIT_ARCH_X86_64"
#  define SB_X32_GUARD 1
#  define SB_COMPAT_AUDIT_ARCH AUDIT_ARCH_I386
#  define SB_COMPAT_NR_SOCKET 359
#  define SB_COMPAT_NR_SOCKETCALL 102
# endif
#elif defined(__i386__)
# define SB_AUDIT_ARCH AUDIT_ARCH_I386
# define SB_ARCH_NAME "AUDIT_ARCH_I386"
#elif defined(__aarch64__)
/* arm64 reports AUDIT_ARCH_AARCH64 for both endiannesses; an AArch32 task on
 * the same kernel reports AUDIT_ARCH_ARM. */
# define SB_AUDIT_ARCH AUDIT_ARCH_AARCH64
# define SB_ARCH_NAME "AUDIT_ARCH_AARCH64"
# define SB_COMPAT_AUDIT_ARCH AUDIT_ARCH_ARM
# define SB_COMPAT_NR_SOCKET 281
# define SB_COMPAT_NR_SOCKETCALL 102
#elif defined(__arm__)
/* Never AUDIT_ARCH_ARMEB: see the block comment. */
# define SB_AUDIT_ARCH AUDIT_ARCH_ARM
# define SB_ARCH_NAME "AUDIT_ARCH_ARM"
#elif defined(__mips__)
# if _MIPS_SIM == _ABIO32
#  ifdef __MIPSEL__
#   define SB_AUDIT_ARCH AUDIT_ARCH_MIPSEL
#   define SB_ARCH_NAME "AUDIT_ARCH_MIPSEL"
#  else
#   define SB_AUDIT_ARCH AUDIT_ARCH_MIPS
#   define SB_ARCH_NAME "AUDIT_ARCH_MIPS"
#  endif
# elif _MIPS_SIM == _ABI64
#  ifdef __MIPSEL__
#   define SB_AUDIT_ARCH AUDIT_ARCH_MIPSEL64
#   define SB_ARCH_NAME "AUDIT_ARCH_MIPSEL64"
#   define SB_COMPAT_AUDIT_ARCH AUDIT_ARCH_MIPSEL
#   define SB_COMPAT2_AUDIT_ARCH AUDIT_ARCH_MIPSEL64N32
#  else
#   define SB_AUDIT_ARCH AUDIT_ARCH_MIPS64
#   define SB_ARCH_NAME "AUDIT_ARCH_MIPS64"
#   define SB_COMPAT_AUDIT_ARCH AUDIT_ARCH_MIPS
#   define SB_COMPAT2_AUDIT_ARCH AUDIT_ARCH_MIPS64N32
#  endif
/* o32 and n32 respectively; the n32 table has no socketcall at all. */
#  define SB_COMPAT_NR_SOCKET 4183
#  define SB_COMPAT_NR_SOCKETCALL 4102
#  define SB_COMPAT2_NR_SOCKET 6040
# elif _MIPS_SIM == _ABIN32
#  ifdef __MIPSEL__
#   define SB_AUDIT_ARCH AUDIT_ARCH_MIPSEL64N32
#   define SB_ARCH_NAME "AUDIT_ARCH_MIPSEL64N32"
#   define SB_COMPAT_AUDIT_ARCH AUDIT_ARCH_MIPSEL
#  else
#   define SB_AUDIT_ARCH AUDIT_ARCH_MIPS64N32
#   define SB_ARCH_NAME "AUDIT_ARCH_MIPS64N32"
#   define SB_COMPAT_AUDIT_ARCH AUDIT_ARCH_MIPS
#  endif
#  define SB_COMPAT_NR_SOCKET 4183
#  define SB_COMPAT_NR_SOCKETCALL 4102
# endif
#elif defined(__powerpc64__)
# if defined(__LITTLE_ENDIAN__)
#  define SB_AUDIT_ARCH AUDIT_ARCH_PPC64LE
#  define SB_ARCH_NAME "AUDIT_ARCH_PPC64LE"
# else
#  define SB_AUDIT_ARCH AUDIT_ARCH_PPC64
#  define SB_ARCH_NAME "AUDIT_ARCH_PPC64"
# endif
/* AUDIT_ARCH_PPC either way, on an LE kernel too: see the block comment. */
# define SB_COMPAT_AUDIT_ARCH AUDIT_ARCH_PPC
# define SB_COMPAT_NR_SOCKET 326
# define SB_COMPAT_NR_SOCKETCALL 102
#elif defined(__powerpc__)
# define SB_AUDIT_ARCH AUDIT_ARCH_PPC
# define SB_ARCH_NAME "AUDIT_ARCH_PPC"
#elif defined(__riscv) && __riscv_xlen == 64
# define SB_AUDIT_ARCH AUDIT_ARCH_RISCV64
# define SB_ARCH_NAME "AUDIT_ARCH_RISCV64"
#elif defined(__loongarch64)
# define SB_AUDIT_ARCH AUDIT_ARCH_LOONGARCH64
# define SB_ARCH_NAME "AUDIT_ARCH_LOONGARCH64"
#endif

#ifdef SYS_seccomp
#ifdef SB_AUDIT_ARCH

/*
 * Every syscall family the allowlist needs a name from, asserted here rather
 * than left to the #ifdef around each entry. A name that vanishes behind its
 * guard would drop silently out of the filter and take the process with it on
 * the first call; this turns that into a build failure instead.
 *
 * The trap this exists for: 32-bit musl does not define __NR_clock_gettime at
 * all. It defines __NR_clock_gettime32 and __NR_clock_gettime64, and nine
 * other legacy time syscalls are renamed the same way.
 */
#if !defined(__NR_read) || !defined(__NR_write) || !defined(__NR_close) || \
    !defined(__NR_ioctl) || !defined(__NR_prctl) || !defined(__NR_exit_group)
#error "seccomp allowlist: this ABI lacks a syscall nothing can run without"
#endif
#if !defined(__NR_open) && !defined(__NR_openat)
#error "seccomp allowlist: no open or openat on this ABI"
#endif
#if !defined(__NR_stat) && !defined(__NR_stat64) && \
    !defined(__NR_newfstatat) && !defined(__NR_fstatat64) && \
    !defined(__NR_statx)
#error "seccomp allowlist: no way to stat a path on this ABI"
#endif
#if !defined(__NR_fstat) && !defined(__NR_fstat64) && !defined(__NR_statx)
#error "seccomp allowlist: no way to stat a descriptor on this ABI"
#endif
#if !defined(__NR_poll) && !defined(__NR_ppoll) && \
    !defined(__NR_ppoll_time64) && !defined(__NR_ppoll_time32)
#error "seccomp allowlist: no poll family on this ABI"
#endif
#if !defined(__NR_dup) || (!defined(__NR_dup2) && !defined(__NR_dup3))
#error "seccomp allowlist: no dup family on this ABI"
#endif
#if !defined(__NR_pipe) && !defined(__NR_pipe2)
#error "seccomp allowlist: no pipe family on this ABI"
#endif
#if !defined(__NR_clock_gettime) && !defined(__NR_clock_gettime64) && \
    !defined(__NR_clock_gettime32)
#error "seccomp allowlist: no clock_gettime here (32-bit musl renames it)"
#endif
#if !defined(__NR_clock_getres) && !defined(__NR_clock_getres_time64) && \
    !defined(__NR_clock_getres_time32)
#error "seccomp allowlist: no clock_getres on this ABI"
#endif
#if !defined(__NR_clock_nanosleep) && \
    !defined(__NR_clock_nanosleep_time64) && \
    !defined(__NR_clock_nanosleep_time32) && !defined(__NR_nanosleep)
#error "seccomp allowlist: no way to sleep on this ABI"
#endif
#if !defined(__NR_futex) && !defined(__NR_futex_time64)
#error "seccomp allowlist: no futex on this ABI"
#endif
#if !defined(__NR_socket)
#error "seccomp allowlist: this ABI has no socket(2), only socketcall(2)"
#endif
#if !defined(__NR_mmap) && !defined(__NR_mmap2)
#error "seccomp allowlist: no mmap family on this ABI"
#endif
#if !defined(__NR_clone)
#error "seccomp allowlist: no clone(2) to fall back to when clone3 is denied"
#endif
#if !defined(__NR_rt_sigreturn) && !defined(__NR_sigreturn)
#error "seccomp allowlist: no sigreturn -- every signal handler would trap"
#endif
#if !defined(__NR_rename) && !defined(__NR_renameat) && \
    !defined(__NR_renameat2)
#error "seccomp allowlist: no rename family on this ABI"
#endif
#if !defined(__NR_mkdir) && !defined(__NR_mkdirat)
#error "seccomp allowlist: no mkdir family on this ABI"
#endif
#if !defined(__NR_unlink) && !defined(__NR_unlinkat)
#error "seccomp allowlist: no unlink family on this ABI"
#endif
#if !defined(__NR_readlink) && !defined(__NR_readlinkat)
#error "seccomp allowlist: no readlink family on this ABI"
#endif
#if !defined(__NR_lseek) && !defined(__NR__llseek)
#error "seccomp allowlist: no lseek family on this ABI"
#endif
#if !defined(__NR_fcntl) && !defined(__NR_fcntl64)
#error "seccomp allowlist: no fcntl family on this ABI"
#endif
#if !defined(__NR_ftruncate) && !defined(__NR_ftruncate64)
#error "seccomp allowlist: no ftruncate family on this ABI"
#endif
#if !defined(__NR_statfs) && !defined(__NR_statfs64)
#error "seccomp allowlist: no statfs family on this ABI"
#endif
#if !defined(__NR_getdents64) && !defined(__NR_getdents)
#error "seccomp allowlist: no getdents family on this ABI"
#endif

/*
 * The ioctl commands the argument rule names, guarded the same way and for the
 * same reason. The terminal pair is per-libc (glibc TCGETS2, musl TCGETS) so
 * either will do; the rest have no alternative spelling.
 */
#if !defined(FIONBIO) || !defined(FIONREAD) || !defined(TIOCGWINSZ)
#error "seccomp allowlist: <sys/ioctl.h> named none of FIONBIO/FIONREAD/TIOCGWINSZ"
#endif
#if !defined(SIOCGIFINDEX) || !defined(SIOCGIFNAME)
#error "seccomp allowlist: no SIOCGIFINDEX/SIOCGIFNAME; if_nametoindex needs them"
#endif
#if !defined(TCGETS) && !defined(TCGETS2)
#error "seccomp allowlist: no terminal ioctls; tcgetattr would be killed"
#endif

/* seccomp_data field offsets, for the BPF that reads them. */
#define SB_OFF_NR	(offsetof(struct seccomp_data, nr))
#define SB_OFF_ARCH	(offsetof(struct seccomp_data, arch))

/*
 * BPF loads 32 bits at a time and seccomp_data::args is an array of 64-bit
 * words, so the half holding a 32-bit argument sits at the front of its word
 * on a little-endian target and at the back on a big-endian one. Getting this
 * wrong does not fail loudly: the comparison simply never matches, so an
 * argument rule silently permits everything -- which is what a plain
 * offsetof() does on the big-endian members of the mips and ppc families.
 */
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__)
# if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define SB_ARG_LO(n)	(offsetof(struct seccomp_data, args[n]) + 4)
# else
#  define SB_ARG_LO(n)	(offsetof(struct seccomp_data, args[n]))
# endif
#else
#error "seccomp: the compiler does not say which endianness this target is"
#endif

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SECCOMP_RET_TRAP
#define SECCOMP_RET_TRAP 0x00030000U
#endif

#define SB_RET_ALLOW	((unsigned int)SECCOMP_RET_ALLOW)
#define SB_RET_ERRNO(e)	((unsigned int)SECCOMP_RET_ERRNO | \
			 ((unsigned int)(e) & SECCOMP_RET_DATA))

/*
 * The filter is assembled at run time rather than written out as a table of
 * hand-counted jump offsets. Two things make the emitter worth its lines: the
 * allowlist runs to a few hundred instructions, so a single jump over it would
 * not fit the one-byte jt/jf field a hand-written preamble has to use; and the
 * same list is built twice, once killing and once trapping, for the
 * COMRADE_SANDBOX=warn diagnostic.
 *
 * Every block emitted here is self-contained: it is entered with nr in the
 * accumulator and left only by returning or by being jumped over whole, so no
 * block depends on what another left in the accumulator.
 */
struct sb_prog {
	struct sock_filter *f;
	unsigned short n;
	unsigned short max;
	int overflow;			/* set once; checked before install */
};

static void sb_emit(struct sb_prog *p, unsigned short code, unsigned char jt,
		    unsigned char jf, unsigned int k)
{
	if (p->n >= p->max) {
		p->overflow = 1;
		return;
	}
	p->f[p->n].code = code;
	p->f[p->n].jt = jt;
	p->f[p->n].jf = jf;
	p->f[p->n].k = k;
	p->n++;
}

static void sb_ld_nr(struct sb_prog *p)
{
	sb_emit(p, BPF_LD + BPF_W + BPF_ABS, 0, 0, SB_OFF_NR);
}

static void sb_ld_arch(struct sb_prog *p)
{
	sb_emit(p, BPF_LD + BPF_W + BPF_ABS, 0, 0, SB_OFF_ARCH);
}

static void sb_ld_arg(struct sb_prog *p, unsigned int off)
{
	sb_emit(p, BPF_LD + BPF_W + BPF_ABS, 0, 0, off);
}

static void sb_ret(struct sb_prog *p, unsigned int action)
{
	sb_emit(p, BPF_RET + BPF_K, 0, 0, action);
}

/* If the accumulator equals k, return action; otherwise carry on. */
static void sb_eq_ret(struct sb_prog *p, unsigned int k, unsigned int action)
{
	sb_emit(p, BPF_JMP + BPF_JEQ + BPF_K, 0, 1, k);
	sb_ret(p, action);
}

/*
 * Emit an equality test whose branches are filled in later, and return its
 * index for sb_land_jt()/sb_land_jf(). A block reached by falling through such
 * a test must never fall out of its end, so that the code the other branch
 * lands on still has the same word in the accumulator.
 */
static unsigned short sb_test(struct sb_prog *p, unsigned int k)
{
	sb_emit(p, BPF_JMP + BPF_JEQ + BPF_K, 0, 0, k);
	return (unsigned short)(p->n - 1);
}

static void sb_land(struct sb_prog *p, unsigned short at, int on_true)
{
	unsigned int d;

	if (at >= p->n)
		return;
	d = (unsigned int)(p->n - at - 1);
	if (d > 255) {
		p->overflow = 1;	/* jt/jf are one byte: never wrap it */
		return;
	}
	if (on_true)
		p->f[at].jt = (unsigned char)d;
	else
		p->f[at].jf = (unsigned char)d;
}

static void sb_land_jt(struct sb_prog *p, unsigned short at)
{
	sb_land(p, at, 1);
}

static void sb_land_jf(struct sb_prog *p, unsigned short at)
{
	sb_land(p, at, 0);
}

/* Emit an "allow every entry in this table" run, two words per entry. */
static void sb_allow_table(struct sb_prog *p, const int *nrs, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++)
		sb_eq_ret(p, (unsigned int)nrs[i], SB_RET_ALLOW);
}

static void sb_errno_table(struct sb_prog *p, const int *nrs, unsigned n,
			   int err)
{
	unsigned i;

	for (i = 0; i < n; i++)
		sb_eq_ret(p, (unsigned int)nrs[i], SB_RET_ERRNO(err));
}

/*
 * Each table ends in a 0 that is never emitted: it only keeps the array
 * non-empty on an ABI where every other entry is compiled out.
 */
#define SB_N(t)   ((unsigned)(sizeof(t) / sizeof((t)[0])))
#define SB_TBL(t) (t), (SB_N(t) - 1u)

/*
 * The list. Measured from 18 traced runs of the real program -- 6 client, 7
 * service and 3 foreground processes -- and then widened by hand with the
 * entries a trace can never show and the partners another architecture or libc
 * reaches for instead. Client and service share one list: their measured sets
 * differ by six names, which is not worth two filters.
 *
 * The hot table comes first because the chain is walked in order and these are
 * nearly all of the traffic: poll 84,910 calls, read 57,402, recvfrom 9,162,
 * sendto 8,386, write 6,463, futex 4,694, against a few hundred for everything
 * else. On a target with the BPF JIT the whole chain costs some fifteen
 * nanoseconds; on a router without one it is interpreted and this order is
 * what keeps it cheap.
 */
static const int sb_nr_hot[] = {
#ifdef __NR_poll
	__NR_poll,
#endif
#ifdef __NR_read
	__NR_read,
#endif
#ifdef __NR_recvfrom
	__NR_recvfrom,
#endif
#ifdef __NR_sendto
	__NR_sendto,
#endif
#ifdef __NR_write
	__NR_write,
#endif
#ifdef __NR_futex
	__NR_futex,
#endif
#ifdef __NR_futex_time64
	__NR_futex_time64,
#endif
#ifdef __NR_ppoll
	__NR_ppoll,		/* the whole of it where there is no poll(2) */
#endif
#ifdef __NR_ppoll_time64
	__NR_ppoll_time64,
#endif
#ifdef __NR_ppoll_time32
	__NR_ppoll_time32,
#endif
	0
};

/* Descriptors: the transport, the terminal and every file comrade keeps. */
static const int sb_nr_io[] = {
#ifdef __NR_readv
	__NR_readv,
#endif
#ifdef __NR_writev
	__NR_writev,
#endif
#ifdef __NR_pread64
	__NR_pread64,
#endif
#ifdef __NR_pwrite64
	__NR_pwrite64,
#endif
#ifdef __NR_close
	__NR_close,
#endif
#ifdef __NR_close_range
	__NR_close_range,
#endif
#ifdef __NR_lseek
	__NR_lseek,
#endif
#ifdef __NR__llseek
	__NR__llseek,		/* 32-bit: what lseek(2) is called there */
#endif
#ifdef __NR_dup
	__NR_dup,
#endif
#ifdef __NR_dup2
	__NR_dup2,
#endif
#ifdef __NR_dup3
	__NR_dup3,
#endif
#ifdef __NR_fcntl
	__NR_fcntl,
#endif
#ifdef __NR_fcntl64
	__NR_fcntl64,
#endif
#ifdef __NR_ftruncate
	__NR_ftruncate,
#endif
#ifdef __NR_ftruncate64
	__NR_ftruncate64,
#endif
#ifdef __NR_fsync
	__NR_fsync,
#endif
#ifdef __NR_fdatasync
	__NR_fdatasync,
#endif
#ifdef __NR_pipe
	__NR_pipe,
#endif
#ifdef __NR_pipe2
	__NR_pipe2,
#endif
#ifdef __NR_eventfd2
	__NR_eventfd2,
#endif
	0
};

/*
 * Paths and metadata. The write side is what the state and data directories
 * need -- the status, token and pid files are written, chmod-ed and renamed
 * into place -- and the read side is the resolver configuration and the shared
 * objects the C library and TLS stack keep opening. statx, and socket(AF_UNIX)
 * below, move with the libc: glibc from 2.28 answers stat() with statx, and
 * NSS reaches for a unix socket.
 */
static const int sb_nr_path[] = {
#ifdef __NR_open
	__NR_open,
#endif
#ifdef __NR_openat
	__NR_openat,
#endif
#ifdef __NR_access
	__NR_access,
#endif
#ifdef __NR_faccessat
	__NR_faccessat,
#endif
#ifdef __NR_stat
	__NR_stat,
#endif
#ifdef __NR_stat64
	__NR_stat64,
#endif
#ifdef __NR_lstat
	__NR_lstat,
#endif
#ifdef __NR_lstat64
	__NR_lstat64,
#endif
#ifdef __NR_fstat
	__NR_fstat,
#endif
#ifdef __NR_fstat64
	__NR_fstat64,
#endif
#ifdef __NR_fstatat64
	__NR_fstatat64,
#endif
#ifdef __NR_newfstatat
	__NR_newfstatat,
#endif
#ifdef __NR_statx
	__NR_statx,
#endif
#ifdef __NR_statfs
	__NR_statfs,
#endif
#ifdef __NR_statfs64
	__NR_statfs64,
#endif
#ifdef __NR_fstatfs
	__NR_fstatfs,
#endif
#ifdef __NR_fstatfs64
	__NR_fstatfs64,
#endif
#ifdef __NR_readlink
	__NR_readlink,
#endif
#ifdef __NR_readlinkat
	__NR_readlinkat,
#endif
#ifdef __NR_getdents64
	__NR_getdents64,
#endif
#ifdef __NR_getdents
	__NR_getdents,
#endif
#ifdef __NR_rename
	__NR_rename,
#endif
#ifdef __NR_renameat
	__NR_renameat,
#endif
#ifdef __NR_renameat2
	__NR_renameat2,
#endif
#ifdef __NR_mkdir
	__NR_mkdir,
#endif
#ifdef __NR_mkdirat
	__NR_mkdirat,
#endif
#ifdef __NR_rmdir
	__NR_rmdir,
#endif
#ifdef __NR_unlink
	__NR_unlink,
#endif
#ifdef __NR_unlinkat
	__NR_unlinkat,
#endif
#ifdef __NR_chmod
	__NR_chmod,
#endif
#ifdef __NR_fchmod
	__NR_fchmod,
#endif
#ifdef __NR_fchmodat
	__NR_fchmodat,
#endif
	0
};

/*
 * Memory. There is deliberately no PROT_EXEC rule: new executable mappings are
 * banned at the mount level instead, where the private root is MS_NOEXEC,
 * which leaves dlopen working for the life of the session. comrade re-resolves
 * names throughout a run -- roaming and connectivity changes are the point of
 * the program -- and a filter rule whose failure mode is glibc silently
 * degrading to another resolution path is the wrong trade for a protection a
 * mount flag already gives.
 */
static const int sb_nr_mem[] = {
#ifdef __NR_brk
	__NR_brk,
#endif
#ifdef __NR_mmap
	__NR_mmap,
#endif
#ifdef __NR_mmap2
	__NR_mmap2,		/* 32-bit: what mmap(2) is called there */
#endif
#ifdef __NR_munmap
	__NR_munmap,
#endif
#ifdef __NR_mprotect
	__NR_mprotect,
#endif
#ifdef __NR_mremap
	__NR_mremap,
#endif
#ifdef __NR_madvise
	__NR_madvise,		/* MADV_GUARD_INSTALL from glibc 2.42 */
#endif
	0
};

/*
 * Time. The three clock reads are served by the vDSO on the box these traces
 * came from, so no trace will ever show them -- but the vDSO is not there on
 * every architecture, nor for every clocksource where it is, and then they are
 * real syscalls and their absence is fatal. Both the time64 and the legacy
 * names are listed because 32-bit musl defines only the renamed pair.
 */
static const int sb_nr_time[] = {
#ifdef __NR_clock_gettime
	__NR_clock_gettime,
#endif
#ifdef __NR_clock_gettime64
	__NR_clock_gettime64,
#endif
#ifdef __NR_clock_gettime32
	__NR_clock_gettime32,
#endif
#ifdef __NR_clock_getres
	__NR_clock_getres,
#endif
#ifdef __NR_clock_getres_time64
	__NR_clock_getres_time64,
#endif
#ifdef __NR_clock_getres_time32
	__NR_clock_getres_time32,
#endif
#ifdef __NR_clock_nanosleep
	__NR_clock_nanosleep,
#endif
#ifdef __NR_clock_nanosleep_time64
	__NR_clock_nanosleep_time64,
#endif
#ifdef __NR_clock_nanosleep_time32
	__NR_clock_nanosleep_time32,
#endif
#ifdef __NR_gettimeofday
	__NR_gettimeofday,
#endif
#ifdef __NR_gettimeofday_time32
	__NR_gettimeofday_time32,
#endif
#ifdef __NR_nanosleep
	__NR_nanosleep,
#endif
#ifdef __NR_time
	__NR_time,
#endif
	0
};

/* Waiting on descriptors, beyond the poll already in the hot table. */
static const int sb_nr_wait[] = {
#ifdef __NR_select
	__NR_select,
#endif
#ifdef __NR__newselect
	__NR__newselect,
#endif
#ifdef __NR_pselect6
	__NR_pselect6,
#endif
#ifdef __NR_pselect6_time64
	__NR_pselect6_time64,
#endif
#ifdef __NR_pselect6_time32
	__NR_pselect6_time32,
#endif
#ifdef __NR_epoll_create1
	__NR_epoll_create1,
#endif
#ifdef __NR_epoll_ctl
	__NR_epoll_ctl,
#endif
#ifdef __NR_epoll_wait
	__NR_epoll_wait,
#endif
#ifdef __NR_epoll_pwait
	__NR_epoll_pwait,
#endif
	0
};

/*
 * Threads. clone is not here: it takes an argument rule of its own below, so
 * that CLONE_THREAD can be required and fork(2) leaves the confined roles
 * altogether. wait4 stays because the service reaps the spawner, which was
 * forked before any of this was applied.
 */
static const int sb_nr_task[] = {
#ifdef __NR_set_tid_address
	__NR_set_tid_address,
#endif
#ifdef __NR_set_robust_list
	__NR_set_robust_list,
#endif
#ifdef __NR_set_thread_area
	__NR_set_thread_area,	/* i386 and mips put TLS setup here */
#endif
#ifdef __NR_rseq
	__NR_rseq,
#endif
#ifdef __NR_gettid
	__NR_gettid,
#endif
#ifdef __NR_getpid
	__NR_getpid,
#endif
#ifdef __NR_getppid
	__NR_getppid,
#endif
#ifdef __NR_sched_yield
	__NR_sched_yield,
#endif
#ifdef __NR_sched_getaffinity
	__NR_sched_getaffinity,
#endif
#ifdef __NR_membarrier
	__NR_membarrier,
#endif
#ifdef __NR_getcpu
	__NR_getcpu,
#endif
#ifdef __NR_exit
	__NR_exit,
#endif
#ifdef __NR_exit_group
	__NR_exit_group,
#endif
#ifdef __NR_wait4
	__NR_wait4,
#endif
#ifdef __NR_waitid
	__NR_waitid,
#endif
	0
};

/*
 * Signals. Three of these no trace can ever show and none may be missing:
 * rt_sigreturn and sigreturn are how a handler returns at all, and
 * restart_syscall is what the kernel puts in the process's mouth after a stop
 * -- Ctrl-Z on the client's terminal is enough to reach it.
 *
 * kill is here although neither confined role has a reachable call to it,
 * because a liveness probe that turns into a killed process is a worse failure
 * than the reach it grants, and LANDLOCK_SCOPE_SIGNAL already bounds that
 * reach to this process's own domain wherever the kernel has it.
 */
static const int sb_nr_signal[] = {
#ifdef __NR_rt_sigaction
	__NR_rt_sigaction,
#endif
#ifdef __NR_rt_sigprocmask
	__NR_rt_sigprocmask,
#endif
#ifdef __NR_rt_sigreturn
	__NR_rt_sigreturn,
#endif
#ifdef __NR_sigreturn
	__NR_sigreturn,
#endif
#ifdef __NR_rt_sigsuspend
	__NR_rt_sigsuspend,
#endif
#ifdef __NR_rt_sigtimedwait
	__NR_rt_sigtimedwait,
#endif
#ifdef __NR_rt_sigtimedwait_time64
	__NR_rt_sigtimedwait_time64,
#endif
#ifdef __NR_sigaltstack
	__NR_sigaltstack,
#endif
#ifdef __NR_restart_syscall
	__NR_restart_syscall,
#endif
#ifdef __NR_tgkill
	__NR_tgkill,		/* raise(), abort(), pthread_kill() */
#endif
#ifdef __NR_tkill
	__NR_tkill,
#endif
#ifdef __NR_kill
	__NR_kill,
#endif
	0
};

/*
 * Sockets. socket(2) itself takes an argument rule below; everything here
 * operates on a descriptor that rule has already vouched for. Four entries
 * move with a dependency rather than with comrade: sendmmsg and the netlink
 * socket are the glibc resolver's, and FIONBIO, FIONREAD and IP_RECVERR are
 * libssh's and libjuice's.
 */
static const int sb_nr_net[] = {
#ifdef __NR_socketpair
	__NR_socketpair,
#endif
#ifdef __NR_bind
	__NR_bind,
#endif
#ifdef __NR_listen
	__NR_listen,
#endif
#ifdef __NR_accept
	__NR_accept,
#endif
#ifdef __NR_accept4
	__NR_accept4,
#endif
#ifdef __NR_connect
	__NR_connect,
#endif
#ifdef __NR_getsockname
	__NR_getsockname,
#endif
#ifdef __NR_getpeername
	__NR_getpeername,
#endif
#ifdef __NR_getsockopt
	__NR_getsockopt,
#endif
#ifdef __NR_setsockopt
	__NR_setsockopt,
#endif
#ifdef __NR_sendmsg
	__NR_sendmsg,
#endif
#ifdef __NR_sendmmsg
	__NR_sendmmsg,
#endif
#ifdef __NR_recvmsg
	__NR_recvmsg,
#endif
#ifdef __NR_recvmmsg
	__NR_recvmmsg,
#endif
#ifdef __NR_recvmmsg_time64
	__NR_recvmmsg_time64,
#endif
#ifdef __NR_shutdown
	__NR_shutdown,
#endif
	0
};

/*
 * What the process asks about itself and the machine. sysinfo is how musl
 * answers sysconf(_SC_PHYS_PAGES), which is what bep44.c sizes its store from.
 */
static const int sb_nr_self[] = {
#ifdef __NR_uname
	__NR_uname,
#endif
#ifdef __NR_sysinfo
	__NR_sysinfo,
#endif
#ifdef __NR_getrandom
	__NR_getrandom,
#endif
#ifdef __NR_getuid
	__NR_getuid,
#endif
#ifdef __NR_getuid32
	__NR_getuid32,
#endif
#ifdef __NR_geteuid
	__NR_geteuid,
#endif
#ifdef __NR_geteuid32
	__NR_geteuid32,
#endif
#ifdef __NR_getgid
	__NR_getgid,
#endif
#ifdef __NR_getgid32
	__NR_getgid32,
#endif
#ifdef __NR_getegid
	__NR_getegid,
#endif
#ifdef __NR_getegid32
	__NR_getegid32,
#endif
#ifdef __NR_getrlimit
	__NR_getrlimit,
#endif
#ifdef __NR_ugetrlimit
	__NR_ugetrlimit,
#endif
#ifdef __NR_prlimit64
	__NR_prlimit64,
#endif
	0
};

#ifdef __arm__
/*
 * arm's private range, which lives outside the __NR_ namespace entirely and so
 * has to go in as raw numbers. musl's src/thread/arm/__set_thread_area.c ends
 * in an unconditional __syscall(0xf0005, p), and AUDIT_ARCH_ARM is enabled
 * above, so a list without these bricks 32-bit arm at thread creation.
 */
static const int sb_nr_arm_private[] = {
	0x0f0001,		/* breakpoint */
	0x0f0002,		/* cacheflush */
	0x0f0003,		/* usr26 */
	0x0f0004,		/* usr32 */
	0x0f0005,		/* set_tls */
	0x0f0006,		/* get_tls */
	0
};
#define SB_ARM_PRIVATE_N SB_N(sb_nr_arm_private)
#else
#define SB_ARM_PRIVATE_N 0u
#endif

/*
 * Denied with ENOSYS rather than killed, because each is something a library
 * probes for and then does without. Denying clone3 with EPERM breaks
 * pthread_create; with ENOSYS glibc marks it unsupported and falls back to
 * clone, which is the whole point -- clone3 takes its arguments in a userspace
 * struct no BPF can read, so a filter that allows it cannot tell a thread from
 * a fork.
 *
 * ENOSYS has to be the symbol and never the number 38: it is 89 on all three
 * MIPS ABIs.
 */
static const int sb_nr_enosys[] = {
#ifdef __NR_clone3
	__NR_clone3,		/* glibc >= 2.34 asks for it first */
#endif
#ifdef __NR_openat2
	__NR_openat2,
#endif
#ifdef __NR_faccessat2
	__NR_faccessat2,
#endif
#ifdef __NR_futex_waitv
	__NR_futex_waitv,
#endif
#ifdef __NR_epoll_pwait2
	__NR_epoll_pwait2,
#endif
#ifdef __NR_io_uring_setup
	__NR_io_uring_setup,
#endif
#ifdef __NR_io_uring_enter
	__NR_io_uring_enter,
#endif
#ifdef __NR_io_uring_register
	__NR_io_uring_register,
#endif
	0
};

/*
 * Denied with EPERM: the honest answer for a thing the kernel has and this
 * process may not do. ptrace is the memory-disclosure route the threat model
 * is about; the mount family is what the confinement itself used on the way
 * in, and a retry of it should be refused rather than fatal.
 */
static const int sb_nr_eperm[] = {
#ifdef __NR_ptrace
	__NR_ptrace,
#endif
#ifdef __NR_mount
	__NR_mount,
#endif
#ifdef __NR_umount2
	__NR_umount2,
#endif
#ifdef __NR_mount_setattr
	__NR_mount_setattr,
#endif
#ifdef __NR_move_mount
	__NR_move_mount,
#endif
#ifdef __NR_open_tree
	__NR_open_tree,
#endif
#ifdef __NR_fsopen
	__NR_fsopen,
#endif
#ifdef __NR_fsconfig
	__NR_fsconfig,
#endif
#ifdef __NR_fsmount
	__NR_fsmount,
#endif
#ifdef __NR_fspick
	__NR_fspick,
#endif
#ifdef __NR_pivot_root
	__NR_pivot_root,
#endif
#ifdef __NR_chroot
	__NR_chroot,
#endif
#ifdef __NR_unshare
	__NR_unshare,
#endif
	0
};

/*
 * The argument rules. Each is a block entered only when nr matches and left
 * only by returning, so the chain after it still has nr in the accumulator. A
 * value the rule does not name gets the filter's default action, which is the
 * point of them: they are allowlists inside the allowlist.
 */
static void sb_rule_prctl(struct sb_prog *p, unsigned int deflt)
{
	unsigned short at = sb_test(p, __NR_prctl);

	sb_ld_arg(p, SB_ARG_LO(0));
	sb_eq_ret(p, PR_SET_NAME, SB_RET_ALLOW);
	sb_eq_ret(p, PR_GET_NAME, SB_RET_ALLOW);
	sb_ret(p, deflt);
	sb_land_jf(p, at);
}

static void sb_rule_socket(struct sb_prog *p, unsigned int deflt)
{
	unsigned short at = sb_test(p, __NR_socket);

	sb_ld_arg(p, SB_ARG_LO(0));
	sb_eq_ret(p, AF_INET, SB_RET_ALLOW);
	sb_eq_ret(p, AF_INET6, SB_RET_ALLOW);
	sb_eq_ret(p, AF_UNIX, SB_RET_ALLOW);	/* NSS, and the tmux socket */
	sb_eq_ret(p, AF_NETLINK, SB_RET_ALLOW);	/* getifaddrs */
	sb_ret(p, deflt);
	sb_land_jf(p, at);
}

/*
 * ioctl's command, in args[1]. Naming the handful the program actually issues
 * also denies TIOCSTI, which pushes bytes into a terminal's input queue and is
 * worth more here than in most programs.
 *
 * The terminal attribute commands come in pairs because the two C libraries
 * differ: glibc issues TCGETS2/TCSETS2 where musl issues TCGETS/TCSETS, and a
 * list carrying only one pair kills the other libc's client at its first
 * tcgetattr(). A role that drives no terminal -- a forwarding-only host --
 * gets neither pair.
 *
 * TIOCGWINSZ stays for every role, that one included. musl's __stdout_write
 * issues it on the first write to stdout whatever the descriptor is, to decide
 * line buffering (checked in the mips musl libc.a: ioctl with 0x40087468), so
 * taking it away would kill a forwarding-only host on OpenWrt the first time
 * it printed anything. Reading a window size is not what the rest of this
 * grant is guarding against.
 */
static void sb_rule_ioctl(struct sb_prog *p, unsigned int deflt, int no_pty)
{
	unsigned short at = sb_test(p, __NR_ioctl);

	sb_ld_arg(p, SB_ARG_LO(1));
	sb_eq_ret(p, FIONBIO, SB_RET_ALLOW);
	sb_eq_ret(p, FIONREAD, SB_RET_ALLOW);
	sb_eq_ret(p, SIOCGIFINDEX, SB_RET_ALLOW);
	sb_eq_ret(p, SIOCGIFNAME, SB_RET_ALLOW);
	sb_eq_ret(p, TIOCGWINSZ, SB_RET_ALLOW);
	if (!no_pty) {
#ifdef TCGETS
		sb_eq_ret(p, TCGETS, SB_RET_ALLOW);
		sb_eq_ret(p, TCSETS, SB_RET_ALLOW);
#endif
#ifdef TCGETS2
		sb_eq_ret(p, TCGETS2, SB_RET_ALLOW);
		sb_eq_ret(p, TCSETS2, SB_RET_ALLOW);
#endif
	}
	sb_ret(p, deflt);
	sb_land_jf(p, at);
}

/*
 * clone must carry CLONE_THREAD. With clone3 answered ENOSYS above, every
 * thread creation comes back through here with its flags in args[0] where BPF
 * can see them, so requiring the bit takes fork(2) away from the confined
 * roles outright -- which the denylist this replaces could not do.
 */
static void sb_rule_clone(struct sb_prog *p, unsigned int deflt)
{
	unsigned short at = sb_test(p, __NR_clone);

	sb_ld_arg(p, SB_ARG_LO(0));
	sb_emit(p, BPF_ALU + BPF_AND + BPF_K, 0, 0, CLONE_THREAD);
	sb_eq_ret(p, CLONE_THREAD, SB_RET_ALLOW);
	sb_ret(p, deflt);
	sb_land_jf(p, at);
}

/*
 * The arch preamble for the roles that deny exec. A syscall arriving under any
 * ABI but the one these numbers belong to is killed; nothing they can do
 * reaches that case, so it stands as a tripwire. seccomp_nonet() gives the
 * exec-permitting foreground a compat branch instead.
 */
static void sb_arch_preamble(struct sb_prog *p)
{
	sb_ld_arch(p);
	sb_emit(p, BPF_JMP + BPF_JEQ + BPF_K, 1, 0, SB_AUDIT_ARCH);
	sb_ret(p, SECCOMP_RET_KILL_PROCESS);
	sb_ld_nr(p);
#ifdef SB_X32_GUARD
	/* x32 numbers, which a native x86-64 filter must never judge. */
	sb_emit(p, BPF_JMP + BPF_JGE + BPF_K, 0, 1, 0x40000000U);
	sb_ret(p, SECCOMP_RET_KILL_PROCESS);
#endif
}

static void sb_build_allowlist(struct sb_prog *p, unsigned int deflt,
			       int no_pty)
{
	sb_arch_preamble(p);
	sb_allow_table(p, SB_TBL(sb_nr_hot));
	sb_rule_socket(p, deflt);
	sb_rule_ioctl(p, deflt, no_pty);
	sb_allow_table(p, SB_TBL(sb_nr_net));
	sb_allow_table(p, SB_TBL(sb_nr_io));
	sb_allow_table(p, SB_TBL(sb_nr_path));
	sb_allow_table(p, SB_TBL(sb_nr_mem));
	sb_allow_table(p, SB_TBL(sb_nr_time));
	sb_allow_table(p, SB_TBL(sb_nr_wait));
	sb_allow_table(p, SB_TBL(sb_nr_task));
	sb_allow_table(p, SB_TBL(sb_nr_signal));
	sb_allow_table(p, SB_TBL(sb_nr_self));
#ifdef __arm__
	sb_allow_table(p, SB_TBL(sb_nr_arm_private));
#endif
	sb_rule_prctl(p, deflt);
	sb_rule_clone(p, deflt);
	sb_errno_table(p, SB_TBL(sb_nr_enosys), ENOSYS);
	sb_errno_table(p, SB_TBL(sb_nr_eperm), EPERM);
	sb_ret(p, deflt);
}

static int install_filter(struct sock_filter *f, unsigned short n)
{
	struct sock_fprog prog;

	prog.len = n;
	prog.filter = f;
	/* TSYNC is harmless here (we are single-threaded) but correct if that
	 * ever changes. */
	if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
		    SECCOMP_FILTER_FLAG_TSYNC, &prog) == 0) {
		sb_filter_insns = n;
		return SANDBOX_L_SECCOMP;
	}
	return 0;
}

/*
 * COMRADE_SANDBOX=warn: the same filter, but a syscall the list omits traps
 * instead of killing and a handler names it. This exists because
 * SECCOMP_RET_KILL_PROCESS leaves no record whatsoever on a stock OpenWrt
 * kernel, where CONFIG_AUDIT is off -- no audit event, no dmesg line, nothing
 * but a process that is suddenly gone.
 *
 * One case reports itself as a kill even here, and it is not a fault: a trap
 * raised where the C library has every signal blocked -- inside fork(), which
 * is exactly one of the things this filter refuses -- is forced to the default
 * action by the kernel, because a blocked synchronous signal has nowhere to
 * go. Observed under strace: the clone traps, SIGSYS is forced, and the
 * process dies unnamed. The verdict is the same, only the line is missing.
 */
static int sb_warn_mode(void)
{
	const char *e = getenv("COMRADE_SANDBOX");

	return e && !strcmp(e, "warn");
}

/*
 * Read by the SIGSYS handler, so neither is a plain int. Both are set before
 * the filter that can raise it goes on -- the descriptor especially, since a
 * log opened after the confinement is unreachable from inside the pivoted root
 * and the run would look clean.
 */
static volatile sig_atomic_t sb_warn_fd = -1;
static volatile sig_atomic_t sb_warn_role = -1;

/* Append an unsigned value in base 10 or 16; returns the new length. */
static size_t sb_putnum(char *buf, size_t len, unsigned long v, int hex)
{
	char tmp[24];
	size_t n = 0;
	unsigned long base = hex ? 16UL : 10UL;

	do {
		unsigned d = (unsigned)(v % base);

		tmp[n++] = (char)(d < 10 ? '0' + d : 'a' + (d - 10));
		v /= base;
	} while (v && n < sizeof(tmp));
	while (n)
		buf[len++] = tmp[--n];
	return len;
}

static size_t sb_putstr(char *buf, size_t len, const char *s)
{
	while (*s)
		buf[len++] = *s++;
	return len;
}

/*
 * The SIGSYS handler. Everything it does is async-signal-safe on purpose: it
 * formats into a stack buffer and write(2)s it, because dbg_logf() opens its
 * file on every call and that file is not reachable from inside a pivoted root
 * -- a log opened after the confinement fails silently and reports a clean
 * run. The descriptor written to here was opened before.
 *
 * The syscall is named by number, not by name: the only table that could give
 * a name is the allowlist itself, and by construction the number that trapped
 * is not in it.
 *
 * rt_sigreturn is in the list above. Without it this handler's own return
 * traps and the process live-locks in a SIGSYS storm instead of reporting.
 */
static void sb_sigsys(int sig, siginfo_t *si, void *uctx)
{
	char buf[256];
	size_t n = 0;
	ssize_t w;

	(void)sig;
	(void)uctx;
	n = sb_putstr(buf, n, "comrade: sandbox: SIGSYS role=");
	n = sb_putnum(buf, n, (unsigned long)sb_warn_role, 0);
	n = sb_putstr(buf, n, " arch=0x");
	n = sb_putnum(buf, n, (unsigned long)(unsigned int)SB_AUDIT_ARCH, 1);
	n = sb_putstr(buf, n, " (" SB_ARCH_NAME ") syscall=");
	n = sb_putnum(buf, n, (unsigned long)si->si_syscall, 0);
	n = sb_putstr(buf, n, ": not in the allowlist. Resolve the number with"
			      " scmp_sys_resolver or ausyscall.\n");
	w = write(2, buf, n);
	if (sb_warn_fd >= 0)
		w = write((int)sb_warn_fd, buf, n);
	(void)w;			/* nothing left to report a failure to */
	_exit(159);			/* 128 + SIGSYS, the shell's numbering */
}

/*
 * Arm the handler and open the log, both before the filter goes on. After it,
 * rt_sigaction would still be permitted but the open would no longer reach the
 * file, and the run would look clean.
 */
static void sb_warn_arm(int role)
{
	struct sigaction sa;
	const char *path = getenv("COMRADE_DEBUG");

	sb_warn_role = role;
	if (path && path[0]) {
		if (!strcmp(path, "1"))
			path = "/tmp/comrade-debug.log";
		sb_warn_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
	}
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = sb_sigsys;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGSYS, &sa, (struct sigaction *)0);
}

/*
 * The filter for the client and the host service: a default-deny allowlist.
 * execve, execveat, fork, ptrace and everything else unnamed above are refused
 * by simply not being there, which is a stronger statement than the denylist
 * this replaces could make -- that one had to enumerate what to forbid, and a
 * syscall nobody had thought of was allowed.
 */
/*
 * The buffer is sized from the tables themselves rather than guessed at, so a
 * name added to one of them can never overflow it. That matters more than the
 * few hundred bytes it costs: an overflow is caught and reported, but the only
 * thing seccomp_allowlist() can do about it is install nothing, and a role
 * that expected a default-deny filter and silently got none is the worst
 * outcome this file has. Two instructions per entry, plus room for the
 * argument rules, the preamble and the arch dispatch.
 */
#define SB_MAX_FILTER (2 * (SB_N(sb_nr_hot) + SB_N(sb_nr_io) + \
			    SB_N(sb_nr_path) + SB_N(sb_nr_mem) + \
			    SB_N(sb_nr_time) + SB_N(sb_nr_wait) + \
			    SB_N(sb_nr_task) + SB_N(sb_nr_signal) + \
			    SB_N(sb_nr_net) + SB_N(sb_nr_self) + \
			    SB_N(sb_nr_enosys) + SB_N(sb_nr_eperm) + \
			    SB_ARM_PRIVATE_N) + 128)

static int seccomp_allowlist(int role, int no_pty)
{
	static struct sock_filter filt[SB_MAX_FILTER];
	struct sb_prog p;
	unsigned int deflt = SECCOMP_RET_KILL_PROCESS;

	if (sb_warn_mode()) {
		sb_warn_arm(role);
		deflt = SECCOMP_RET_TRAP;
	}
	p.f = filt;
	p.n = 0;
	p.max = SB_MAX_FILTER;
	p.overflow = 0;
	sb_build_allowlist(&p, deflt, no_pty);
	if (p.overflow) {
		dbg_logf("sandbox: the filter did not fit in %d instructions",
			 SB_MAX_FILTER);
		return 0;
	}
	dbg_logf("sandbox: allowlist %u instructions, arch %s%s",
		 (unsigned)p.n, SB_ARCH_NAME,
		 deflt == SECCOMP_RET_TRAP ? ", warn mode" : "");
	return install_filter(filt, p.n);
}

/*
 * The body of the no-network filter, for one ABI: refuse to create an INET or
 * INET6 socket, permit every other syscall. Entered with nr in the
 * accumulator, and never falls out of its end.
 */
static void sb_nonet_body(struct sb_prog *p, unsigned int nr_socket)
{
	unsigned short at = sb_test(p, nr_socket);

	sb_ld_arg(p, SB_ARG_LO(0));
	sb_eq_ret(p, AF_INET, SB_RET_ERRNO(EPERM));
	sb_eq_ret(p, AF_INET6, SB_RET_ERRNO(EPERM));
	sb_ret(p, SB_RET_ALLOW);
	sb_land_jf(p, at);
	sb_ret(p, SB_RET_ALLOW);
}

/*
 * The no-network filter for the host operator's foreground. This one stays a
 * denylist, deliberately: the role drives an unconfined tmux, so anything
 * denied to it directly is reachable by typing into the shell that tmux opens,
 * and an allowlist would have to become a superset of the tmux client's own
 * syscall set -- third-party, and moving with tmux versions -- for nothing.
 *
 * socketcall goes wherever the ABI has one (i686, mips o32, ppc, ppc64).
 * Measured on i386 against the filter this replaces: socket(AF_INET) was
 * refused while socketcall(SYS_SOCKET, AF_INET) succeeded. Its argument array
 * lives in userspace, where no BPF can read it, so the whole call has to go.
 *
 * The compat branches are what makes the role's exec safe. A filter survives
 * execve, so without them a foreign-ABI child -- an i386 tmux under an x86-64
 * comrade, say -- would meet the wrong-arch kill on its first syscall. They
 * come first in the program so that the single jump over them to the native
 * body stays inside the one byte a jt field has.
 */
static int seccomp_nonet(void)
{
	static struct sock_filter filt[64];
	struct sb_prog p;
	unsigned short to_native;
#if defined(SB_COMPAT_AUDIT_ARCH) || defined(SB_COMPAT2_AUDIT_ARCH)
	unsigned short skip;
#endif

	p.f = filt;
	p.n = 0;
	p.max = (unsigned short)(sizeof(filt) / sizeof(filt[0]));
	p.overflow = 0;

	sb_ld_arch(&p);
	to_native = sb_test(&p, SB_AUDIT_ARCH);
#ifdef SB_COMPAT_AUDIT_ARCH
	skip = sb_test(&p, SB_COMPAT_AUDIT_ARCH);
	sb_ld_nr(&p);
#ifdef SB_COMPAT_NR_SOCKETCALL
	sb_eq_ret(&p, SB_COMPAT_NR_SOCKETCALL, SB_RET_ERRNO(EPERM));
#endif
	sb_nonet_body(&p, SB_COMPAT_NR_SOCKET);
	sb_land_jf(&p, skip);
#endif
#ifdef SB_COMPAT2_AUDIT_ARCH
	skip = sb_test(&p, SB_COMPAT2_AUDIT_ARCH);
	sb_ld_nr(&p);
	sb_nonet_body(&p, SB_COMPAT2_NR_SOCKET);
	sb_land_jf(&p, skip);
#endif
	sb_ret(&p, SECCOMP_RET_KILL_PROCESS);

	sb_land_jt(&p, to_native);
	sb_ld_nr(&p);
#ifdef __NR_socketcall
	sb_eq_ret(&p, __NR_socketcall, SB_RET_ERRNO(EPERM));
#endif
#ifdef __NR_io_uring_setup
	sb_eq_ret(&p, __NR_io_uring_setup, SB_RET_ERRNO(EPERM));
#endif
	sb_nonet_body(&p, __NR_socket);
	if (p.overflow) {
		dbg_logf("sandbox: the no-network filter did not fit");
		return 0;
	}
	return install_filter(filt, p.n);
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

static int seccomp_apply(const struct sandbox_cfg *cfg, int confine)
{
#if defined(SYS_seccomp) && defined(SB_AUDIT_ARCH)
	if (!seccomp_available())
		return 0;
	if (cfg->role == SANDBOX_FOREGROUND)
		return seccomp_nonet();
	if (confine)
		return seccomp_allowlist(cfg->role, cfg->no_pty);
	return 0;
#else
	(void)cfg;
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
/*
 * Directories that hold far more than a resolver. /etc/resolv.conf can
 * resolve straight into one of these: on OpenWrt dnsmasq, whenever it serves
 * as the box's own resolver, replaces the /tmp/resolv.conf.d symlink with a
 * file it writes directly in /tmp, which is also where /var, and with it
 * every session token, lives. For these the resolver's file is staged and
 * the directory around it is not.
 */
static const char *const sb_shared_dirs[] = {
	"/tmp", "/var", "/var/tmp", "/run", "/var/run", "/dev/shm"
};

static int dir_is_shared(const char *dir)
{
	size_t i;

	for (i = 0; i < sizeof(sb_shared_dirs) / sizeof(sb_shared_dirs[0]); i++)
		if (strcmp(dir, sb_shared_dirs[i]) == 0)
			return 1;
	return 0;
}

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
	if (dir_is_shared(rdir)) {
		if (bind_at(root, target, target, 0, 1) < 0)
			fail = 1;
	} else if (stage_ro(root, rdir) < 0) {
		fail = 1;
	}
	if ((size_t)snprintf(etc, sizeof(etc), "%s/etc", root) < sizeof(etc))
		mkdir_p(etc);
	if ((size_t)snprintf(dst, sizeof(dst), "%s/etc/resolv.conf", root) <
	    sizeof(dst) && symlink(target, dst) != 0)
		dbg_logf("sandbox: could not link /etc/resolv.conf -> %s (%d)",
			 target, errno);
	return fail ? -1 : 0;
}

/*
 * Bind a single host device node into the new root's /dev. /dev/null is
 * written and stays writable; /dev/urandom is only ever read, and a musl TLS
 * backend reads it throughout the run, so it is bound read-only.
 *
 * The read-only remount here cannot be remount_ro(): that adds MS_NODEV, which
 * would make the node it just bound unusable. Mount flags are per-mount, which
 * is also why these binds keep their device permission inside a root mounted
 * nodev.
 */
static int bind_dev(const char *root, const char *node, int ro)
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
	if (ro && mount(NULL, dst, NULL,
			MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID |
			MS_NOEXEC, NULL) != 0)
		dbg_logf("sandbox: %s left writable (%d)", node, errno);
	return 0;
}

/*
 * What to grant a debug log: its own file where the directory holding it is
 * one of the shared roots above, and the directory otherwise. A log in /tmp
 * would otherwise widen the grant to everything else in /tmp, writably. The
 * file has to exist before it can be bound, and creating it is what the first
 * log line would do anyway. NULL where there is nothing to grant.
 */
static const char *dbg_grant(char *dir, size_t dn, const char *dbg)
{
	char *slash;
	int fd;

	if (!dbg || dbg[0] != '/')
		return NULL;
	if ((size_t)snprintf(dir, dn, "%s", dbg) >= dn)
		return NULL;
	slash = strrchr(dir, '/');
	if (!slash || slash == dir)
		return NULL;
	*slash = '\0';
	if (!dir_is_shared(dir))
		return dir;
	fd = open(dbg, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd < 0)
		return NULL;
	close(fd);
	return dbg;
}

/* Bind the writable directories -- the data dir (non-recursively, so the tmpfs
 * staged on its own .ns does not nest into the bind), a host state dir, and the
 * debug log's directory. Shared by the namespace builder below. */
static int bind_writable(const char *root, const struct sandbox_cfg *cfg)
{
	char dir[PATH_MAX];
	const char *dbg;
	int fail = 0;

	if (bind_at(root, cfg->data_dir, cfg->data_dir, 0, 0) < 0)
		fail = 1;		/* without it the program cannot persist */
	if (cfg->state_dir && cfg->state_dir[0] &&
	    bind_at(root, cfg->state_dir, cfg->state_dir, 0, 0) < 0)
		fail = 1;
	/* The debug log is convenient, not essential -- its bind failing
	 * (bind_at logs it) does not fail the confinement. */
	dbg = dbg_grant(dir, sizeof(dir), getenv("COMRADE_DEBUG"));
	if (dbg)
		bind_at(root, dbg, dbg, 0, 0);
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

	/*
	 * IPC and UTS come along for free once a user namespace is being
	 * created anyway, and they take away the System V and POSIX message
	 * queues, semaphores and shared memory of every other process; comrade
	 * uses none of them, and neither does anything it links. They are asked
	 * for separately from the two that matter, because a kernel that
	 * refuses the extra flags must still get its mount namespace -- losing
	 * that to gain these would be a worse sandbox, not a better one.
	 */
	if (unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWIPC |
		    CLONE_NEWUTS) == 0) {
		map_ids(uid, gid);
	} else if (unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0) {
		map_ids(uid, gid);
	} else if (geteuid() == 0 &&
		   unshare(CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS) == 0) {
		/* Root without a user namespace: the real CAP_SYS_ADMIN carries
		 * the mounts and no id map is needed. */
	} else if (geteuid() == 0 && unshare(CLONE_NEWNS) == 0) {
		/* As above, on a kernel that refused the extra namespaces. */
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
	/*
	 * noexec on the root itself, not only on the writable binds staged into
	 * it: the tmpfs is writable, so without this it is somewhere a process
	 * that has been taken over can write a shared object and map it as
	 * code. PR_SET_MDWE does not cover that, since it refuses a
	 * write-to-execute transition and not a fresh executable mapping of a
	 * file. Mount flags are per-mount, so the library directories bound
	 * over this root keep their own exec bit and dlopen is unaffected;
	 * nothing is executed from the tmpfs itself, whose contents are mount
	 * points and recreated symlinks, and a symlink's execute permission
	 * comes from its target's mount rather than its own.
	 */
	if (mount("tmpfs", root, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
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
	if (bind_dev(root, "/dev/null", 0) < 0)
		fail = 1;
	if (bind_dev(root, "/dev/urandom", 1) < 0)
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
#define SB_FS_RESOLVE_UNIX	(1ULL << 16)

/*
 * The kernel takes the size of this and refuses a field it does not know only
 * when that field is set, so one struct serves every ABI: the network member
 * stays zero below version 4 and the call is accepted exactly as before.
 */
struct sb_ruleset_attr {
	uint64_t handled_access_fs;
	uint64_t handled_access_net;
	uint64_t scoped;
};

#define SB_SCOPE_ABSTRACT_UNIX_SOCKET	(1ULL << 0)
#define SB_SCOPE_SIGNAL			(1ULL << 1)

#define SB_LANDLOCK_RULE_NET_PORT 2

#define SB_NET_BIND_TCP		(1ULL << 0)
#define SB_NET_CONNECT_TCP	(1ULL << 1)

struct sb_net_port {
	uint64_t allowed_access;
	uint64_t port;
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
/* One TCP port the process may bind or connect to. */
static void ll_allow_port(int rs, uint16_t port, uint64_t access)
{
	struct sb_net_port np;

	memset(&np, 0, sizeof(np));
	np.allowed_access = access;
	np.port = port;
	if (syscall(__NR_landlock_add_rule, rs, SB_LANDLOCK_RULE_NET_PORT,
		    &np, 0U) != 0)
		dbg_logf("sandbox: landlock rule for tcp/%u failed (%d)",
			 (unsigned)port, errno);
}

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
	uint64_t handled, ro, rwx, rw, net, scoped;
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
	/*
	 * Reaching a unix socket by its pathname is a filesystem right from
	 * version 9, and it is the one the mount namespace already refuses by
	 * simply not having those paths -- ssh-agent, a session bus, a
	 * container daemon, a router's control socket. Handling it here brings
	 * the two backends back into agreement, which is what the two lists
	 * above exist for.
	 */
	if (abi >= 9)
		handled |= SB_FS_RESOLVE_UNIX;

	/*
	 * Network rules arrive at version 4, and only a role that knows its
	 * ports can use them. Handling the access with no rule for a port is
	 * what refuses it, so a role with no forwarding gets no TCP at all --
	 * which is every ordinary client, comrade's own transport being UDP
	 * from the DHT through to the session.
	 */
	net = 0;
	if (abi >= 4 && !cfg->tcp_any)
		net = SB_NET_BIND_TCP | SB_NET_CONNECT_TCP;

	/*
	 * Version 6 adds scopes, which reach two things a path cannot name. A
	 * confined comrade signals nothing outside itself -- the client signals
	 * nobody at all, and a service ends its broker by closing the socket
	 * pair and waiting, never by signal -- and it speaks to no abstract
	 * unix socket, which is where a display server and a session bus
	 * listen. Both are refused for everything outside this process's own
	 * domain; its own threads and children are unaffected.
	 */
	scoped = 0;
	if (abi >= 6)
		scoped = SB_SCOPE_ABSTRACT_UNIX_SOCKET | SB_SCOPE_SIGNAL;

	memset(&attr, 0, sizeof(attr));
	attr.handled_access_fs = handled;
	attr.handled_access_net = net;
	attr.scoped = scoped;
	rs = (int)syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0U);
	if (rs < 0)
		return 0;

	if (net) {
		int i;

		for (i = 0; i < cfg->n_tcp_bind; i++)
			ll_allow_port(rs, cfg->tcp_bind[i], SB_NET_BIND_TCP);
		for (i = 0; i < cfg->n_tcp_connect; i++)
			ll_allow_port(rs, cfg->tcp_connect[i],
				      SB_NET_CONNECT_TCP);
		/*
		 * The resolver falls back to TCP for an answer that will not
		 * fit in a datagram, and comrade resolves names for as long as
		 * a session lasts rather than once at the start, so refusing
		 * this would break name resolution only occasionally and only
		 * for the unlucky.
		 */
		ll_allow_port(rs, 53, SB_NET_CONNECT_TCP);
	}

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
	dbg = dbg_grant(dir, sizeof(dir), getenv("COMRADE_DEBUG"));
	if (dbg)
		ll_allow(rs, dbg, rw);

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
		(cfg->role == SANDBOX_SERVICE && cfg->no_exec);

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
	layers |= seccomp_apply(cfg, confine);
	return layers;
}

/*
 * --sandbox-selftest. The allowlist is measured from one libc on one
 * architecture, and the thing that will quietly break it is a different libc
 * -- or a newer one -- reaching for a syscall nobody listed. Nothing in the
 * ordinary test suite would notice: the filter installs, the layers report,
 * and the process dies later under load on somebody's router.
 *
 * So this installs the real filter, default action and all, and then does the
 * things the program does. Each probe runs in its own forked child, because a
 * syscall the list omits kills the process outright and one death must not
 * hide the rest; the parent reads the exit or the signal and says which probe
 * it was. The negative probes are the other half: a thing that must be refused
 * and is not is just as much a failure.
 *
 * It needs no privilege, no network and no kernel feature beyond seccomp, so
 * it is the one confinement check a cross-build's CI can run under qemu-user
 * -- with the caveat that qemu-user does not emulate seccomp at all, so there
 * it collects the syscalls a build issues and proves nothing about the filter.
 * Only a real kernel makes it a test of the confinement.
 */

#define SB_PROBE_OK	0
#define SB_PROBE_FAIL	1
#define SB_PROBE_SKIP	77
#define SB_PROBE_TRAPPED 159	/* what the warn-mode handler exits with */

static int sbp_basics(void)
{
	struct utsname u;

	if (getpid() <= 0 || uname(&u) != 0)
		return SB_PROBE_FAIL;
	(void)getuid();
	(void)geteuid();
	(void)getgid();
	/* sysconf(_SC_PHYS_PAGES) is sysinfo(2) on musl: bep44.c sizes its
	 * store from exactly this call. */
	if (sysconf(_SC_PHYS_PAGES) == 0)
		return SB_PROBE_FAIL;
	(void)sysconf(_SC_NPROCESSORS_ONLN);
	return SB_PROBE_OK;
}

static int sbp_time(void)
{
	struct timespec ts;
	struct timeval tv;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return SB_PROBE_FAIL;
	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return SB_PROBE_FAIL;
	if (clock_getres(CLOCK_MONOTONIC, &ts) != 0)
		return SB_PROBE_FAIL;
	if (gettimeofday(&tv, (struct timezone *)0) != 0)
		return SB_PROBE_FAIL;
	ts.tv_sec = 0;
	ts.tv_nsec = 1000000;
	(void)nanosleep(&ts, (struct timespec *)0);
	return SB_PROBE_OK;
}

static int sbp_memory(void)
{
	void *big = malloc(4u << 20);
	void *m;

	if (!big)
		return SB_PROBE_FAIL;
	memset(big, 0, 4u << 20);
	free(big);
	m = mmap((void *)0, 65536, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (m == MAP_FAILED)
		return SB_PROBE_FAIL;
	if (mprotect(m, 65536, PROT_READ) != 0)
		return SB_PROBE_FAIL;
	(void)madvise(m, 65536, MADV_DONTNEED);
	if (munmap(m, 65536) != 0)
		return SB_PROBE_FAIL;
	return SB_PROBE_OK;
}

static int sbp_files(void)
{
	char path[64], other[68];
	struct stat st;
	char buf[16];
	DIR *d;
	int fd, rc = SB_PROBE_FAIL;

	snprintf(path, sizeof(path), "/tmp/comrade-sbx-%ld", (long)getpid());
	snprintf(other, sizeof(other), "%s.2", path);
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return SB_PROBE_FAIL;
	do {
		if (write(fd, "hello\n", 6) != 6)
			break;
		if (lseek(fd, 0, SEEK_SET) != 0)
			break;
		if (read(fd, buf, sizeof(buf)) != 6)
			break;
		if (fstat(fd, &st) != 0 || fsync(fd) != 0)
			break;
		if (ftruncate(fd, 3) != 0)
			break;
		if (fchmod(fd, 0600) != 0)
			break;
		if (fcntl(fd, F_GETFL) < 0)
			break;
		if (stat(path, &st) != 0 || access(path, R_OK) != 0)
			break;
		if (rename(path, other) != 0)
			break;
		if (unlink(other) != 0)
			break;
		d = opendir("/tmp");
		if (!d)
			break;
		(void)readdir(d);
		closedir(d);
		rc = SB_PROBE_OK;
	} while (0);
	close(fd);
	unlink(path);
	unlink(other);
	return rc;
}

static int sbp_sockets(void)
{
	struct sockaddr_in a;
	socklen_t alen = sizeof(a);
	struct pollfd pfd;
	char buf[8];
	int s, s6, u, sp[2], on = 1, n;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return SB_PROBE_FAIL;
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0 ||
	    bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 ||
	    getsockname(s, (struct sockaddr *)&a, &alen) != 0) {
		close(s);
		return SB_PROBE_FAIL;
	}
	if (ioctl(s, FIONBIO, &on) != 0 || ioctl(s, FIONREAD, &n) != 0) {
		close(s);
		return SB_PROBE_FAIL;
	}
	if (sendto(s, "x", 1, 0, (struct sockaddr *)&a, alen) != 1) {
		close(s);
		return SB_PROBE_FAIL;
	}
	pfd.fd = s;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd, 1, 500) < 0) {
		close(s);
		return SB_PROBE_FAIL;
	}
	(void)recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)0,
		       (socklen_t *)0);
	close(s);

	s6 = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s6 >= 0)
		close(s6);		/* a kernel without IPv6 is not a fault */
	u = socket(AF_UNIX, SOCK_STREAM, 0);
	if (u < 0)
		return SB_PROBE_FAIL;	/* NSS and the tmux socket need it */
	close(u);
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0)
		return SB_PROBE_FAIL;
	close(sp[0]);
	close(sp[1]);
	return SB_PROBE_OK;
}

static void *sbp_thread_body(void *arg)
{
	(void)arg;
	sched_yield();
	return (void *)0;
}

/*
 * The clone3-denied-with-ENOSYS path, end to end: glibc asks for clone3 first,
 * takes the ENOSYS as "this kernel is too old", and comes back through clone
 * with CLONE_THREAD where the argument rule can see it.
 */
static int sbp_threads(void)
{
	pthread_t th[4];
	int i;

	for (i = 0; i < 4; i++) {
		if (pthread_create(&th[i], (pthread_attr_t *)0,
				   sbp_thread_body, (void *)0) != 0)
			return SB_PROBE_FAIL;
	}
	for (i = 0; i < 4; i++) {
		if (pthread_join(th[i], (void **)0) != 0)
			return SB_PROBE_FAIL;
	}
	return SB_PROBE_OK;
}

/*
 * Name resolution, which is the deepest the confined process reaches into the
 * C library: NSS modules are dlopen-ed, and on glibc the lookup itself opens a
 * netlink socket and may use sendmmsg.
 */
static int sbp_resolver(void)
{
	struct addrinfo hints, *ai = (struct addrinfo *)0;
	int nl;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo("localhost", (const char *)0, &hints, &ai) != 0)
		return SB_PROBE_FAIL;
	freeaddrinfo(ai);
	if (if_nametoindex("lo") == 0)
		return SB_PROBE_FAIL;	/* SIOCGIFINDEX through the ioctl rule */
	nl = socket(AF_NETLINK, SOCK_RAW, 0);
	if (nl < 0)
		return SB_PROBE_FAIL;	/* getifaddrs is built on it */
	close(nl);
	return SB_PROBE_OK;
}

static volatile sig_atomic_t sbp_caught;

static void sbp_handler(int sig)
{
	(void)sig;
	sbp_caught = 1;
}

/*
 * A signal delivered and returned from. The return is the point: rt_sigreturn
 * never appears in a trace, and without it the handler's own return traps.
 */
static int sbp_signals(void)
{
	struct sigaction sa, old;
	sigset_t set;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sbp_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGUSR1, &sa, &old) != 0)
		return SB_PROBE_FAIL;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR2);
	if (sigprocmask(SIG_BLOCK, &set, (sigset_t *)0) != 0)
		return SB_PROBE_FAIL;
	if (raise(SIGUSR1) != 0)
		return SB_PROBE_FAIL;
	if (!sbp_caught)
		return SB_PROBE_FAIL;
	(void)sigprocmask(SIG_UNBLOCK, &set, (sigset_t *)0);
	(void)sigaction(SIGUSR1, &old, (struct sigaction *)0);
	return SB_PROBE_OK;
}

static int sbp_prctl(void)
{
	char name[24];

	if (prctl(PR_SET_NAME, "comrade-sbx", 0, 0, 0) != 0)
		return SB_PROBE_FAIL;
	memset(name, 0, sizeof(name));
	if (prctl(PR_GET_NAME, name, 0, 0, 0) != 0)
		return SB_PROBE_FAIL;
	return SB_PROBE_OK;
}

/* Denied with an errno, not a death: the probe-and-fall-back carve-outs. */
static int sbp_carveouts(void)
{
#ifdef __NR_clone3
	errno = 0;
	if (syscall(__NR_clone3, (void *)0, (size_t)0) != -1 ||
	    errno != ENOSYS)
		return SB_PROBE_FAIL;
#endif
	errno = 0;
	if (syscall(SYS_ptrace, (long)PTRACE_TRACEME, 0, 0, 0) != -1 ||
	    errno != EPERM)
		return SB_PROBE_FAIL;
	errno = 0;
	if (mount("none", "/", "tmpfs", 0, (void *)0) != -1 || errno != EPERM)
		return SB_PROBE_FAIL;
	return SB_PROBE_OK;
}

/* The negative probes. Each must not come back. */
static int sbp_exec(void)
{
	execl("/bin/sh", "sh", "-c", "exit 0", (char *)0);
	return SB_PROBE_FAIL;
}

static int sbp_fork(void)
{
	pid_t pid = fork();

	if (pid == 0)
		_exit(SB_PROBE_FAIL);	/* the fork was allowed: a failure */
	return SB_PROBE_FAIL;
}

static int sbp_packet_socket(void)
{
	int s = socket(AF_PACKET, SOCK_RAW, 0);

	if (s >= 0)
		close(s);
	return SB_PROBE_FAIL;
}

static int sbp_tiocsti(void)
{
	int sp[2];
	char c = 'x';

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0)
		return SB_PROBE_FAIL;
	(void)ioctl(sp[0], TIOCSTI, &c);
	close(sp[0]);
	close(sp[1]);
	return SB_PROBE_FAIL;
}

static int sbp_unlisted_prctl(void)
{
	(void)prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
	return SB_PROBE_FAIL;
}

struct sb_probe {
	const char *name;
	int (*fn)(void);
	int must_be_refused;
};

static const struct sb_probe sb_probes[] = {
	{ "basics", sbp_basics, 0 },
	{ "time", sbp_time, 0 },
	{ "memory", sbp_memory, 0 },
	{ "files", sbp_files, 0 },
	{ "sockets", sbp_sockets, 0 },
	{ "threads", sbp_threads, 0 },
	{ "resolver", sbp_resolver, 0 },
	{ "signals", sbp_signals, 0 },
	{ "prctl", sbp_prctl, 0 },
	{ "carve-outs", sbp_carveouts, 0 },
	{ "execve", sbp_exec, 1 },
	{ "fork", sbp_fork, 1 },
	{ "socket(AF_PACKET)", sbp_packet_socket, 1 },
	{ "ioctl(TIOCSTI)", sbp_tiocsti, 1 },
	{ "prctl(PR_SET_DUMPABLE)", sbp_unlisted_prctl, 1 }
};

/*
 * Run one probe behind the real filter. The child installs it itself, so the
 * parent stays unconfined and can report on however many probes die.
 */
static int sb_run_probe(const struct sb_probe *pr)
{
	pid_t pid;
	int st = 0, refused;

	/* Whatever is still sitting in the buffer would be inherited and, on
	 * the paths where the child's exit does flush, printed a second time
	 * per probe. Empty it before there are two of us. */
	fflush(stdout);
	pid = fork();
	if (pid < 0)
		return SB_PROBE_FAIL;
	if (pid == 0) {
		prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
#if defined(SYS_seccomp) && defined(SB_AUDIT_ARCH)
		if (!(seccomp_allowlist(SANDBOX_CLIENT, 0) & SANDBOX_L_SECCOMP))
			_exit(SB_PROBE_SKIP);
#else
		_exit(SB_PROBE_SKIP);
#endif
		_exit(pr->fn());
	}
	if (waitpid(pid, &st, 0) != pid)
		return SB_PROBE_FAIL;
	/*
	 * Refused means killed by the default action -- or, under
	 * COMRADE_SANDBOX=warn, trapped and reported by the handler, which is
	 * the same verdict reached the other way.
	 */
	refused = (WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS) ||
		  (WIFEXITED(st) && WEXITSTATUS(st) == SB_PROBE_TRAPPED);
	if (refused)
		return pr->must_be_refused ? SB_PROBE_OK : SB_PROBE_FAIL;
	if (WIFSIGNALED(st))
		return SB_PROBE_FAIL;
	if (WEXITSTATUS(st) == SB_PROBE_SKIP)
		return SB_PROBE_SKIP;
	if (pr->must_be_refused)
		return SB_PROBE_FAIL;	/* it came back: nothing stopped it */
	return WEXITSTATUS(st) == 0 ? SB_PROBE_OK : SB_PROBE_FAIL;
}

/*
 * Under a sanitizer the runtime is a second program sharing this process, with
 * a syscall set of its own that the allowlist was never measured against; a
 * failure there would say nothing about comrade. The instrumented builds run
 * the rest of the suite, and this probe skips.
 */
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define SB_INSTRUMENTED 1
#endif
#if defined(__has_feature)
# if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) || \
     __has_feature(memory_sanitizer)
#  undef SB_INSTRUMENTED
#  define SB_INSTRUMENTED 1
# endif
#endif

static int selftest_linux(void)
{
	unsigned i;
	int bad = 0, skipped = 0;

#ifdef SB_INSTRUMENTED
	printf("sandbox selftest: skipped, this build is instrumented\n");
	return SB_PROBE_SKIP;
#endif
#if defined(SYS_seccomp) && defined(SB_AUDIT_ARCH)
	printf("sandbox selftest: %s, seccomp %s\n", SB_ARCH_NAME,
	       seccomp_available() ? "available" : "absent");
#else
	printf("sandbox selftest: this build names no audit arch\n");
	return SB_PROBE_SKIP;
#endif
	for (i = 0; i < sizeof(sb_probes) / sizeof(sb_probes[0]); i++) {
		int r = sb_run_probe(&sb_probes[i]);

		printf("  %-24s %s\n", sb_probes[i].name,
		       r == SB_PROBE_OK ? "ok" :
		       r == SB_PROBE_SKIP ? "skipped" : "FAILED");
		if (r == SB_PROBE_FAIL)
			bad++;
		else if (r == SB_PROBE_SKIP)
			skipped++;
	}
	if (skipped == (int)(sizeof(sb_probes) / sizeof(sb_probes[0]))) {
		printf("sandbox selftest: no seccomp on this kernel\n");
		return SB_PROBE_SKIP;
	}
	printf("sandbox selftest: %s\n", bad ? "FAILED" : "ok");
	return bad ? 1 : 0;
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

int sandbox_filter_insns(void)
{
	return sb_filter_insns;
}

/*
 * The probe battery of --sandbox-selftest. Linux only in substance: the macOS
 * confinement is a Seatbelt profile rather than a syscall filter, and there is
 * nothing here that would test it. 0 means every probe passed, 1 that one did
 * not, and 77 that this build or kernel has no filter to test.
 */
int sandbox_selftest(void)
{
	if (sandbox_disabled()) {
		printf("sandbox selftest: COMRADE_SANDBOX=0, nothing applied\n");
		return 77;
	}
#if defined(__linux__)
	return selftest_linux();
#else
	printf("sandbox selftest: no syscall filter on this platform\n");
	return 77;
#endif
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
