/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#ifndef COMRADE_TTY_H
#define COMRADE_TTY_H

#include <stddef.h>

#include "wsock.h"

/*
 * The local terminal, as the two modules that touch one (ui.c's dashboard and
 * sshc.c's interactive bridge) need it. POSIX gets termios/ioctl/SIGWINCH;
 * Windows gets the console API. Keeping it here rather than #ifdefing the
 * callers means the client's terminal handling reads the same on both.
 *
 * The Windows half also solves a problem that is not about terminals at all:
 * libssh's ssh_event loop polls with select()/WSAPoll, which on Windows accept
 * only SOCKETs. The console handles 0/1/2 are not sockets, so handing
 * STDIN_FILENO to ssh_event_add_fd() there fails the whole poll set. tty_sock_*
 * therefore return real sockets, pumped to and from the console by a thread
 * each -- the same "make every pollable fd a socket" move the SSH<->KCP bridge
 * needs (see wsock.h). On POSIX they are just the standard descriptors.
 */

struct tty_saved {
#ifdef _WIN32
	unsigned long in_mode;
	unsigned long out_mode;
#else
	unsigned char opaque[64];	/* struct termios, without the include */
#endif
	int valid;
};

/*
 * Raw mode. full != 0 is cfmakeraw (the SSH client hands every byte through);
 * full == 0 clears only echo and line buffering and keeps signal generation,
 * which is what the host dashboard wants so Ctrl-C still works.
 */
int tty_raw_on(struct tty_saved *s, int full);
void tty_raw_off(struct tty_saved *s);

/* Terminal size in character cells; 0 on success, leaves *rows/*cols alone
 * otherwise. */
int tty_size(int *rows, int *cols);

int tty_isatty_in(void);
int tty_isatty_out(void);

/* Unbuffered write to the real stdout (status bar, escape sequences). */
int tty_write(const void *buf, size_t len);

/*
 * Resize notification. POSIX installs a SIGWINCH handler; Windows has no such
 * signal and no way to get resize events out of a console read that is in VT
 * mode, so it compares the size on each poll. Callers already ask only a few
 * times a second, from the status tick.
 */
void tty_resize_watch(int on);
int tty_resized(void);

/*
 * Pollable console I/O, for the libssh event loop. Each returns INVALID_SOCK
 * if the console cannot be bridged. tty_sock_release() stops the pump threads
 * and closes the sockets; it is a no-op on POSIX.
 */
sock_t tty_sock_in(void);
sock_t tty_sock_out(void);
sock_t tty_sock_err(void);
void tty_sock_release(void);

#endif
