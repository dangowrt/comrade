/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <string.h>

#include "tty.h"

#ifdef _WIN32

#include <io.h>
#include <pthread.h>

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
#endif
#ifndef DISABLE_NEWLINE_AUTO_RETURN
#define DISABLE_NEWLINE_AUTO_RETURN 0x0008
#endif

int tty_raw_on(struct tty_saved *s, int full)
{
	HANDLE hin = GetStdHandle(STD_INPUT_HANDLE);
	HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD in_mode = 0, out_mode = 0, want_in, want_out;

	s->valid = 0;
	if (!GetConsoleMode(hin, &in_mode) || !GetConsoleMode(hout, &out_mode))
		return -1;
	s->in_mode = in_mode;
	s->out_mode = out_mode;

	/*
	 * VT in both directions is the whole point: the remote end speaks ANSI
	 * and expects ANSI back, so the console must stop cooking input and
	 * start interpreting output escapes rather than the legacy console API.
	 */
	want_in = in_mode & ~(DWORD)(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT |
				     ENABLE_MOUSE_INPUT | ENABLE_WINDOW_INPUT);
	want_in |= ENABLE_VIRTUAL_TERMINAL_INPUT;
	if (full)
		want_in &= ~(DWORD)ENABLE_PROCESSED_INPUT;	/* Ctrl-C is data */
	else
		want_in |= ENABLE_PROCESSED_INPUT;		/* keep Ctrl-C */
	want_out = out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING |
		   DISABLE_NEWLINE_AUTO_RETURN;

	if (!SetConsoleMode(hin, want_in))
		return -1;
	SetConsoleMode(hout, want_out);		/* best effort: pre-Win10 lacks VT */
	s->valid = 1;
	return 0;
}

void tty_raw_off(struct tty_saved *s)
{
	if (!s->valid)
		return;
	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), (DWORD)s->in_mode);
	SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), (DWORD)s->out_mode);
	s->valid = 0;
}

int tty_size(int *rows, int *cols)
{
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	if (!GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi))
		return -1;
	/* The window, not the (often much taller) screen buffer. */
	*rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
	*cols = csbi.srWindow.Right - csbi.srWindow.Left + 1;
	if (*rows < 1 || *cols < 1)
		return -1;
	return 0;
}

int tty_isatty_in(void)
{
	DWORD m;

	return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &m) ? 1 : 0;
}

int tty_isatty_out(void)
{
	DWORD m;

	return GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &m) ? 1 : 0;
}

int tty_write(const void *buf, size_t len)
{
	return (int)_write(1, buf, (unsigned)len);
}

static int watch_rows, watch_cols, watch_on;

void tty_resize_watch(int on)
{
	watch_on = on;
	if (on)
		tty_size(&watch_rows, &watch_cols);
}

int tty_resized(void)
{
	int r = 0, c = 0;

	if (!watch_on || tty_size(&r, &c))
		return 0;
	if (r == watch_rows && c == watch_cols)
		return 0;
	watch_rows = r;
	watch_cols = c;
	return 1;
}

/* ---- console <-> socket pumps (see the header) ---- */

struct pump {
	sock_t app;		/* the end handed to libssh's event loop */
	sock_t pump;		/* the end this module's thread owns */
	int fd;			/* console descriptor being bridged */
	pthread_t th;
	int running;
	volatile int stop;
};

static struct pump p_in, p_out, p_err;

/* console -> socket */
static void *pump_in_fn(void *arg)
{
	struct pump *p = arg;
	char buf[4096];

	while (!p->stop) {
		int n = (int)_read(p->fd, buf, sizeof(buf));
		int off = 0;

		if (n <= 0)
			break;
		while (off < n) {
			int w = send(p->pump, buf + off, n - off, 0);

			if (w <= 0)
				goto done;
			off += w;
		}
	}
done:
	shutdown(p->pump, SD_SEND);
	return NULL;
}

/* socket -> console */
static void *pump_out_fn(void *arg)
{
	struct pump *p = arg;
	char buf[4096];

	while (!p->stop) {
		int n = recv(p->pump, buf, sizeof(buf), 0);
		int off = 0;

		if (n <= 0)
			break;
		while (off < n) {
			int w = (int)_write(p->fd, buf + off, (unsigned)(n - off));

			if (w <= 0)
				goto done;
			off += w;
		}
	}
done:
	return NULL;
}

static sock_t pump_start(struct pump *p, int fd, void *(*fn)(void *))
{
	sock_t sv[2];

	if (p->running)
		return p->app;
	if (sock_pair(sv))
		return INVALID_SOCK;
	p->app = sv[0];
	p->pump = sv[1];
	p->fd = fd;
	p->stop = 0;
	if (pthread_create(&p->th, NULL, fn, p)) {
		sock_close(sv[0]);
		sock_close(sv[1]);
		p->app = p->pump = INVALID_SOCK;
		return INVALID_SOCK;
	}
	p->running = 1;
	/* The app end is polled by libssh, so it must not block. */
	sock_set_nonblock(p->app);
	return p->app;
}

sock_t tty_sock_in(void)
{
	return pump_start(&p_in, 0, pump_in_fn);
}

sock_t tty_sock_out(void)
{
	return pump_start(&p_out, 1, pump_out_fn);
}

sock_t tty_sock_err(void)
{
	return pump_start(&p_err, 2, pump_out_fn);
}

/*
 * Stops and releases an output pump (p_out/p_err). p_in is never stopped
 * here: it is parked in a blocking console read that nothing can interrupt,
 * so once started it is a process-lifetime singleton, reused as-is across
 * repeated tty_sock_in() calls (a host that returns to its dashboard after a
 * detach calls it again) -- tearing it down and starting a second reader on
 * the same console would race the first for every keystroke.
 */
static void pump_stop(struct pump *p)
{
	if (!p->running)
		return;
	p->stop = 1;
	/* shutdown() does not reliably wake a blocking recv() on another
	 * thread here; closesocket() does. */
	sock_close(p->pump);
	pthread_join(p->th, NULL);
	sock_close(p->app);
	p->app = p->pump = INVALID_SOCK;
	p->running = 0;
}

void tty_sock_release(void)
{
	pump_stop(&p_out);
	pump_stop(&p_err);
}

#else /* !_WIN32 */

#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>

int tty_raw_on(struct tty_saved *s, int full)
{
	struct termios orig, t;

	s->valid = 0;
	if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &orig))
		return -1;
	t = orig;
	if (full)
		cfmakeraw(&t);
	else
		t.c_lflag &= ~(unsigned)(ICANON | ECHO);  /* keep ISIG for Ctrl-C */
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSANOW, &t))
		return -1;
	memcpy(s->opaque, &orig, sizeof(orig));
	s->valid = 1;
	return 0;
}

void tty_raw_off(struct tty_saved *s)
{
	struct termios orig;

	if (!s->valid)
		return;
	memcpy(&orig, s->opaque, sizeof(orig));
	tcsetattr(STDIN_FILENO, TCSANOW, &orig);
	s->valid = 0;
}

int tty_size(int *rows, int *cols)
{
	struct winsize ws;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) || !ws.ws_row || !ws.ws_col)
		return -1;
	*rows = ws.ws_row;
	*cols = ws.ws_col;
	return 0;
}

int tty_isatty_in(void)
{
	return isatty(STDIN_FILENO);
}

int tty_isatty_out(void)
{
	return isatty(STDOUT_FILENO);
}

int tty_write(const void *buf, size_t len)
{
	return (int)write(STDOUT_FILENO, buf, len);
}

static volatile sig_atomic_t winch;
static struct sigaction old_winch;
static int watching;

static void on_winch(int sig)
{
	(void)sig;
	winch = 1;
}

void tty_resize_watch(int on)
{
	struct sigaction sa;

	if (on == watching)
		return;
	if (on) {
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = on_winch;
		sigaction(SIGWINCH, &sa, &old_winch);
	} else {
		sigaction(SIGWINCH, &old_winch, NULL);
	}
	watching = on;
	winch = 0;
}

int tty_resized(void)
{
	if (!winch)
		return 0;
	winch = 0;
	return 1;
}

sock_t tty_sock_in(void)
{
	return STDIN_FILENO;
}

sock_t tty_sock_out(void)
{
	return STDOUT_FILENO;
}

sock_t tty_sock_err(void)
{
	return STDERR_FILENO;
}

void tty_sock_release(void)
{
}

#endif /* _WIN32 */
