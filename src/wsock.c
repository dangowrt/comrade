/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "wsock.h"

#ifdef _WIN32

#include <mstcpip.h>

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET (IOC_IN | IOC_VENDOR | 12)
#endif

static LONG wsock_refs;

int wsock_init(void)
{
	WSADATA wsa;

	if (InterlockedIncrement(&wsock_refs) != 1)
		return 0;
	if (WSAStartup(MAKEWORD(2, 2), &wsa)) {
		InterlockedDecrement(&wsock_refs);
		return -1;
	}
	return 0;
}

void wsock_fini(void)
{
	if (InterlockedDecrement(&wsock_refs) == 0)
		WSACleanup();
}

int sock_close(sock_t s)
{
	return closesocket(s);
}

int sock_shutdown(sock_t s, int how)
{
	return shutdown(s, how);
}

int sock_set_nonblock(sock_t s)
{
	u_long one = 1;

	return ioctlsocket(s, FIONBIO, &one) == 0 ? 0 : -1;
}

int sock_udp_disable_connreset(sock_t s)
{
	BOOL off = FALSE;
	DWORD bytes;

	return WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof(off), NULL, 0,
			&bytes, NULL, NULL) == 0 ? 0 : -1;
}

int sock_errno(void)
{
	return WSAGetLastError();
}

int sock_err_would_block(int e)
{
	return e == WSAEWOULDBLOCK;
}

int sock_err_in_progress(int e)
{
	/* A non-blocking connect() reports WSAEWOULDBLOCK, not WSAEINPROGRESS
	 * (which on Winsock means "a blocking call is already running"). */
	return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS;
}

int sock_err_intr(int e)
{
	return e == WSAEINTR;
}

/* Lifted from the Phase 0 harness (winport/poc/poc.c), which measured this
 * against WSAPoll teardown before any comrade source was touched. */
int sock_pair(sock_t sv[2])
{
	sock_t listener = INVALID_SOCK, a = INVALID_SOCK, b = INVALID_SOCK;
	struct sockaddr_in addr;
	int addrlen = (int)sizeof(addr);
	int one = 1;

	sv[0] = sv[1] = INVALID_SOCK;
	if (wsock_init())
		return -1;

	listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listener == INVALID_SOCK)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;

	if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)))
		goto err;
	if (listen(listener, 1))
		goto err;
	if (getsockname(listener, (struct sockaddr *)&addr, &addrlen))
		goto err;

	a = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (a == INVALID_SOCK)
		goto err;
	/* Blocking connect: the backlog takes it without accept() running. */
	if (connect(a, (struct sockaddr *)&addr, sizeof(addr)))
		goto err;

	b = accept(listener, NULL, NULL);
	if (b == INVALID_SOCK)
		goto err;

	closesocket(listener);
	listener = INVALID_SOCK;

	/* The SSH<->KCP bridge is latency-sensitive; Nagle would coalesce. */
	setsockopt(a, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
	setsockopt(b, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));

	sv[0] = a;
	sv[1] = b;
	return 0;

err:
	if (listener != INVALID_SOCK)
		closesocket(listener);
	if (a != INVALID_SOCK)
		closesocket(a);
	if (b != INVALID_SOCK)
		closesocket(b);
	return -1;
}

int sock_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms)
{
	if (!nfds) {
		/* WSAPoll rejects nfds == 0 (WSAEINVAL) where poll() just
		 * sleeps; the signalling loop hits this before any socket is
		 * up. */
		if (timeout_ms > 0)
			Sleep((DWORD)timeout_ms);
		return 0;
	}
	return WSAPoll(fds, (ULONG)nfds, timeout_ms);
}

ssize_t sock_read(sock_t s, void *buf, size_t len)
{
	int n = recv(s, (char *)buf, (int)len, 0);

	return n;
}

ssize_t sock_write(sock_t s, const void *buf, size_t len)
{
	int n = send(s, (const char *)buf, (int)len, 0);

	return n;
}

#else /* !_WIN32 */

#include <errno.h>
#include <sys/socket.h>

int wsock_init(void)
{
	return 0;
}

void wsock_fini(void)
{
}

int sock_close(sock_t s)
{
	return close(s);
}

int sock_shutdown(sock_t s, int how)
{
	return shutdown(s, how);
}

int sock_set_nonblock(sock_t s)
{
	int f = fcntl(s, F_GETFL, 0);

	if (f < 0)
		return -1;
	return fcntl(s, F_SETFL, f | O_NONBLOCK) < 0 ? -1 : 0;
}

int sock_udp_disable_connreset(sock_t s)
{
	(void)s;
	return 0;
}

int sock_errno(void)
{
	return errno;
}

int sock_err_would_block(int e)
{
	return e == EAGAIN || e == EWOULDBLOCK;
}

int sock_err_in_progress(int e)
{
	return e == EINPROGRESS;
}

int sock_err_intr(int e)
{
	return e == EINTR;
}

int sock_pair(sock_t sv[2])
{
	return socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
}

int sock_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms)
{
	return poll(fds, nfds, timeout_ms);
}

ssize_t sock_read(sock_t s, void *buf, size_t len)
{
	return read(s, buf, len);
}

ssize_t sock_write(sock_t s, const void *buf, size_t len)
{
	return write(s, buf, len);
}

#endif /* _WIN32 */
