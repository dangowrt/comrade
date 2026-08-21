/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_WSOCK_H
#define COMRADE_WSOCK_H

/*
 * The one socket header. Everything in comrade that touches a socket includes
 * this instead of <sys/socket.h>/<netinet/in.h>/<arpa/inet.h>/<netdb.h>/
 * <poll.h>, so the Windows substitutions live in exactly one place rather than
 * scattered as #ifdefs through the modules.
 *
 * Three things it fixes for Win64, in decreasing order of how quietly they
 * would otherwise break:
 *
 *  1. `sock_t`. A Windows SOCKET is a UINT_PTR -- 64-bit on Win64 -- so storing
 *     one in an `int` truncates it. The truncation is silent and the resulting
 *     handle is usually still valid for small values, which is exactly the kind
 *     of bug that survives testing and fails in the field. Every fd that is a
 *     socket is `sock_t`, and the "no socket" sentinel is INVALID_SOCK, not -1
 *     (SOCKET is unsigned; `s < 0` is always false).
 *  2. `sock_poll()`. WSAPoll takes only SOCKETs -- never a pipe or a HANDLE --
 *     which is why the bridge, the control channel and the liveness fd all have
 *     to be sockets (see sock_pair below). Measured caveat on Win11: WSAPoll
 *     raises POLLHUP *without* POLLRDNORM, so a loop that only reacts to a
 *     readable bit spins forever on a closed peer. Every dispatch site here
 *     treats POLLHUP|POLLERR as drain-and-close.
 *  3. errno. Winsock reports through WSAGetLastError(), not errno, so
 *     `errno == EAGAIN` after a short send is meaningless. Use sock_errno() and
 *     the sock_err_* predicates.
 *
 * On POSIX every one of these is the obvious one-liner and the generated code
 * is what it always was.
 */

#ifdef _WIN32

/* Win10: WSAPoll and struct pollfd need >= 0x0600, inet_ntop/pton >= 0x0600. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stddef.h>
#include <stdint.h>

typedef SOCKET sock_t;
#define INVALID_SOCK INVALID_SOCKET

/* winsock2.h supplies struct pollfd and the POLL* bits, but not nfds_t. */
#ifndef COMRADE_HAVE_NFDS_T
#define COMRADE_HAVE_NFDS_T
typedef unsigned long nfds_t;
#endif

/* mingw-w64 supplies ssize_t and socklen_t (crtdefs.h / ws2tcpip.h). */

/* Winsock has no MSG_NOSIGNAL because Windows never raises SIGPIPE. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif
#ifndef SHUT_RD
#define SHUT_RD SD_RECEIVE
#endif
#ifndef SHUT_WR
#define SHUT_WR SD_SEND
#endif

#else /* !_WIN32 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

typedef int sock_t;
#define INVALID_SOCK (-1)

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#endif /* _WIN32 */

/* SOCKET is unsigned, so "is this a socket" is never a sign test. */
#define sock_valid(s) ((s) != INVALID_SOCK)

/*
 * Optional socket fields (sshd_opts.end_fd, .ctl_fd, ...) are left zero by the
 * memset that clears their struct, and zero means "none". `fd > 0` used to say
 * that; on Windows SOCKET is unsigned, so it says almost nothing. This does.
 */
#define sock_isset(s) ((s) != 0 && sock_valid(s))

/*
 * Winsock needs an explicit per-process start; the count is kept internally so
 * every entry point can call this without coordinating. No-op on POSIX.
 */
int wsock_init(void);
void wsock_fini(void);

int sock_close(sock_t s);
int sock_shutdown(sock_t s, int how);

/* ioctlsocket(FIONBIO) / fcntl(O_NONBLOCK). Returns 0 on success. */
int sock_set_nonblock(sock_t s);

/* WSAGetLastError() / errno, and the three tests worth naming. */
int sock_errno(void);
int sock_err_would_block(int e);
int sock_err_in_progress(int e);
int sock_err_intr(int e);

/*
 * socketpair(AF_UNIX, SOCK_STREAM). Windows has no AF_UNIX socketpair (its
 * AF_UNIX has no socketpair() at all), so this is emulated over a loopback TCP
 * connection: bind 127.0.0.1:0, listen, connect, accept, drop the listener.
 * Both ends stay sockets, which is what keeps the unified WSAPoll loop possible
 * -- see the header comment. Nagle is disabled (the bridge is latency
 * sensitive) and both ends come back non-blocking on Windows, matching how
 * every caller uses them.
 */
int sock_pair(sock_t sv[2]);

/* poll() / WSAPoll(). */
int sock_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms);

/*
 * read()/write() on a socket. Windows CRT read()/write() take an int fd from
 * the CRT's own table and cannot see a SOCKET at all, so these are recv()/
 * send() there and the plain calls on POSIX.
 */
ssize_t sock_read(sock_t s, void *buf, size_t len);
ssize_t sock_write(sock_t s, const void *buf, size_t len);

#endif
