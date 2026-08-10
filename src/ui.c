/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

/*
 * The view (see ui.h). The controller hands it semantic events; it owns every
 * byte written to the terminal. Two renderings share one model: an animated
 * phosphor dashboard on a real tty, and plain timestamped log lines otherwise
 * (--verbose, or a pipe). The host's split-process bridge -- wire framing on
 * the service side, the render loop on the foreground side -- is also here, so
 * nothing outside this file formats output.
 */

#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "ui.h"

/* Set by SIGINT/SIGTERM while the host foreground waits, so it aborts cleanly
 * (terminal restored, service torn down) instead of dying mid-raw-mode. */
static volatile sig_atomic_t ui_abort_flag;
static void ui_on_signal(int n) { (void)n; ui_abort_flag = 1; }

#define RST "\033[0m"
#define GRN "\033[32m"
#define BGR "\033[92m"
#define CYN "\033[36m"
#define YEL "\033[33m"
#define BYE "\033[93m"
#define RED "\033[31m"
#define WHT "\033[97m"
#define DIM "\033[90m"

struct netrow { int family; int scope; int via; char addr[80]; };
struct linkrow { char name[32]; int has4, has6; };
struct rdvrow { int family; int ready; char addr[80]; };
struct peerrow { int state; char addr[80]; };

struct ui {
	int role;
	int anim;			/* 1 = dashboard, 0 = log lines */
	int rows, cols;
	uint64_t start;
	uint64_t last_paint;
	uint64_t last_spin;
	int spin;
	int dirty;
	int cursor_hidden;

	struct netrow net[12];
	int nnet;
	struct linkrow link[8];
	int nlink;
	struct rdvrow rdv[2];
	int nrdv;
	char token[256];
	int have_token;
	struct peerrow peer[8];
	int npeer;
	char escalate[160];
	int have_escalate;
	int established;

	struct termios saved;
	int raw;
};

struct ui_emit { int fd; };

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ---- log-line rendering (verbose / non-tty) ---- */

static void vlog(struct ui *u, const char *fmt, ...)
{
	va_list ap;
	double el = (double)(now_ms() - u->start) / 1000.0;

	printf(DIM "%6.1f  " RST, el);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
	fflush(stdout);
}

/* ---- animated dashboard ---- */

static void hide_cursor(struct ui *u)
{
	if (!u->cursor_hidden) {
		fputs("\033[?25l", stdout);
		u->cursor_hidden = 1;
	}
}

static void show_cursor(struct ui *u)
{
	if (u->cursor_hidden) {
		fputs("\033[?25h", stdout);
		u->cursor_hidden = 0;
	}
}

static void winsize(struct ui *u)
{
	struct winsize ws;

	u->rows = 24;
	u->cols = 80;
	if (!ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) && ws.ws_row && ws.ws_col) {
		u->rows = ws.ws_row;
		u->cols = ws.ws_col;
	}
}

/* One dashboard line: body text, cleared to end of line, then down. */
static void line(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	fputs("\033[K\n", stdout);
}

static const char *tag(int ready)
{
	return ready ? BGR "[ ready ]" RST : YEL "[  ..  ]" RST;
}

/*
 * Colour + text for a path's classification. A srflx global address means NAT
 * only when the family has no direct global path; when it does (fam_open, e.g.
 * a v6 host with a stable address plus a STUN-seen privacy address) the srflx
 * is that reflexive/privacy source, not NAT.
 */
static void net_label(int scope, int via, int fam_open, const char **color,
		      const char **text)
{
	if (scope == NET_SCOPE_LAN) {
		*color = DIM;
		*text = "LAN";
	} else if (scope == NET_SCOPE_CGNAT) {
		*color = YEL;
		*text = via == NET_VIA_STUN ? "CGNAT (NAT)" : "CGNAT";
	} else if (via == NET_VIA_DIRECT) {
		*color = BGR;
		*text = "GLOBAL (open)";
	} else if (fam_open) {
		*color = CYN;
		*text = "GLOBAL (via STUN)";
	} else {
		*color = BYE;
		*text = "GLOBAL (NAT)";
	}
}

static void draw(struct ui *u)
{
	static const char spc[] = "|/-\\";
	unsigned el = (unsigned)((now_ms() - u->start) / 1000);
	char sp = spc[u->spin & 3];
	int i;

	hide_cursor(u);
	fputs("\033[H", stdout);

	if (u->role == UI_ROLE_HOST)
		line(BGR "comrade" RST DIM
		     "  shared terminals over a punched p2p link"
		     RST "        %02u:%02u %c", el / 60, el % 60, sp);
	else {
		char sh[64];

		sh[0] = '\0';
		if (u->have_token && strlen(u->token) > 18)
			snprintf(sh, sizeof(sh), "%.12s" DIM ".." RST CYN "%.3s",
				 u->token, u->token + strlen(u->token) - 3);
		else
			snprintf(sh, sizeof(sh), "%.40s", u->token);
		line(BGR "comrade" RST DIM "  joining  " RST CYN "%s" RST
		     "        %02u:%02u %c", sh, el / 60, el % 60, sp);
	}
	line("");

	line(CYN "NETWORK" RST);
	if (!u->nnet && !u->nlink)
		line(DIM "  probing ..." RST);
	{
		int open4 = 0, open6 = 0, j;	/* a direct global path per family */

		for (j = 0; j < u->nnet; j++)
			if (u->net[j].via == NET_VIA_DIRECT &&
			    u->net[j].scope == NET_SCOPE_GLOBAL) {
				if (u->net[j].family == 6)
					open6 = 1;
				else
					open4 = 1;
			}
		for (i = 0; i < u->nnet; i++) {
			struct netrow *n = &u->net[i];
			const char *col, *txt;

			net_label(n->scope, n->via, n->family == 6 ? open6 : open4,
				  &col, &txt);
			line("  " DIM "%s" RST "  " CYN "%-40s" RST "%s%s" RST,
			     n->family == 6 ? "IPv6" : "IPv4", n->addr, col, txt);
		}
	}
	for (i = 0; i < u->nlink; i++) {
		struct linkrow *l = &u->link[i];

		line("  " DIM "LINK" RST "  " CYN "%-40s" RST DIM "multicast  "
		     RST "%s%s", l->name,
		     l->has4 ? BGR "v4 " RST : DIM "-- " RST,
		     l->has6 ? BGR "v6" RST : DIM "--" RST);
	}
	line("");

	line(CYN "RENDEZVOUS" RST);
	if (!u->nrdv)
		line(DIM "  locating a close node ..." RST);
	for (i = 0; i < u->nrdv; i++) {
		struct rdvrow *r = &u->rdv[i];

		if (u->role == UI_ROLE_HOST)
			line("  " DIM "v%d" RST "  %s  " CYN "%s" RST,
			     r->family, tag(r->ready), r->addr);
		else
			line("  " DIM "v%d" RST "  %s " DIM "%s" RST,
			     r->family, r->ready ? BGR "[ ready ]" RST :
			     YEL "contacting" RST, r->addr);
	}
	if (u->have_escalate)
		line("  " RED "! %s" RST, u->escalate);
	line("");

	if (u->role == UI_ROLE_HOST) {
		int r4 = 0, r6 = 0, j;

		for (j = 0; j < u->nrdv; j++)
			if (u->rdv[j].ready) {
				if (u->rdv[j].family == 4)
					r4 = 1;
				else
					r6 = 1;
			}
		line(CYN "INVITE" RST);
		if (u->have_token) {
			line("  " WHT "$ comrade %s" RST, u->token);
			if (r4 && r6)
				line("  " BGR "reachable over IPv4 and IPv6" RST);
			else if (r4)
				line("  " YEL "IPv4 only" RST DIM
				     " -- IPv6-only peers cannot reach" RST);
			else if (r6)
				line("  " RED "! IPv6 only" RST DIM
				     " -- IPv4-only peers cannot connect" RST);
		} else {
			line(DIM "  minting once a rendezvous node is ready ..." RST);
		}
		line("");

		line(CYN "PEERS" RST);
		if (!u->npeer)
			line(DIM "  none yet -- you can enter and wait" RST);
		for (i = 0; i < u->npeer; i++) {
			struct peerrow *p = &u->peer[i];
			const char *st = p->state == SESSION_PEER_LIVE ?
					 BGR "live    " RST :
					 p->state == SESSION_PEER_PUNCHING ?
					 YEL "punching" RST : CYN "seen    " RST;

			line("  " BGR "#%d" RST " %s  " CYN "%s" RST,
			     i + 1, st, p->addr[0] && p->addr[0] != '-' ?
			     p->addr : "");
		}
		line("");
		line(DIM "[ " BYE "ENTER" DIM " / " BYE "SPACE" DIM
		     " to enter the shared session ]" RST);
	} else {
		if (u->established)
			line(BGR "  link up -- entering ..." RST);
		else
			line(DIM "  connecting ..." RST);
	}

	fputs("\033[J", stdout);
	fflush(stdout);
	u->last_paint = now_ms();
	u->dirty = 0;
}

static void repaint(struct ui *u)
{
	if (u->anim)
		draw(u);
}

/* ---- the power-on zap: character rows bloom from centre, flare, cut black --- */

static void msleep(int ms)
{
	struct timespec ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (long)(ms % 1000) * 1000000L;
	nanosleep(&ts, NULL);
}

static void bar(int row, int cols, const char *sgr)
{
	printf("\033[%d;1H%s%*s" RST, row + 1, sgr, cols, "");
}

static void zap(struct ui *u, int snow)
{
	int cen, r, y, f;

	if (!u->anim)
		return;
	winsize(u);
	cen = u->rows / 2;
	hide_cursor(u);

	if (snow) {
		static const char ch[] = "@#%&$*+=-:.|/\\<>()[]{} ";
		int c;

		for (f = 0; f < 6; f++) {
			fputs("\033[H", stdout);
			for (y = 0; y < u->rows; y++) {
				printf("\033[%d;1H" DIM, y + 1);
				for (c = 0; c < u->cols; c++)
					putchar(ch[rand() % (int)(sizeof(ch) - 1)]);
				fputs(RST, stdout);
			}
			fflush(stdout);
			msleep(28);
		}
	}

	for (r = 0; r <= cen; r++) {
		for (y = 0; y < u->rows; y++) {
			if (y >= cen - r && y <= cen + r)
				bar(y, u->cols, "\033[42m");
			else
				printf("\033[%d;1H\033[K", y + 1);
		}
		fflush(stdout);
		msleep(20);
	}
	for (y = 0; y < u->rows; y++)		/* flare */
		bar(y, u->cols, "\033[107m");
	fflush(stdout);
	msleep(70);
	fputs(RST "\033[2J\033[H", stdout);	/* cut to black */
	fflush(stdout);
	msleep(130);
}

/* ---- model updates (shared by the inline client and the host foreground) --- */

static const char *scope_word(int scope, int via)
{
	if (scope == NET_SCOPE_LAN)
		return "lan";
	if (scope == NET_SCOPE_CGNAT)
		return via == NET_VIA_STUN ? "cgnat-nat" : "cgnat";
	return via == NET_VIA_STUN ? "global-nat" : "global-open";
}

static void um_net(struct ui *u, int family, int scope, int via, const char *addr)
{
	int i;

	if (!u->anim) {
		vlog(u, "net    %s %-40s %s", family == 6 ? "ipv6" : "ipv4",
		     addr, scope_word(scope, via));
		return;
	}
	for (i = 0; i < u->nnet; i++)		/* de-dup trickled candidates */
		if (u->net[i].family == family && u->net[i].via == via &&
		    !strcmp(u->net[i].addr, addr))
			return;
	if (u->nnet < 12) {
		u->net[u->nnet].family = family;
		u->net[u->nnet].scope = scope;
		u->net[u->nnet].via = via;
		snprintf(u->net[u->nnet].addr, sizeof(u->net[0].addr), "%s", addr);
		u->nnet++;
		u->dirty = 1;
	}
}

static void um_link(struct ui *u, const char *name, int has4, int has6)
{
	int i;

	if (!u->anim) {
		vlog(u, "link   %s %s%s%s", name, has4 ? "v4" : "",
		     has4 && has6 ? "+" : "", has6 ? "v6" : "");
		return;
	}
	for (i = 0; i < u->nlink; i++)
		if (!strcmp(u->link[i].name, name))
			return;
	if (u->nlink < 8) {
		snprintf(u->link[u->nlink].name, sizeof(u->link[0].name), "%s",
			 name);
		u->link[u->nlink].has4 = has4;
		u->link[u->nlink].has6 = has6;
		u->nlink++;
		u->dirty = 1;
	}
}

static void um_rdv(struct ui *u, int family, int ready, const char *addr)
{
	int i;

	if (!u->anim) {
		vlog(u, "rdv    v%d %s %s", family, addr,
		     ready ? "validated, pinned" : "contacting");
		return;
	}
	for (i = 0; i < u->nrdv; i++)
		if (u->rdv[i].family == family) {
			u->rdv[i].ready = ready;
			snprintf(u->rdv[i].addr, sizeof(u->rdv[0].addr), "%s", addr);
			u->dirty = 1;
			return;
		}
	if (u->nrdv < 2) {
		u->rdv[u->nrdv].family = family;
		u->rdv[u->nrdv].ready = ready;
		snprintf(u->rdv[u->nrdv].addr, sizeof(u->rdv[0].addr), "%s", addr);
		u->nrdv++;
		u->dirty = 1;
	}
}

static void um_token(struct ui *u, const char *tok)
{
	snprintf(u->token, sizeof(u->token), "%s", tok);
	u->have_token = 1;
	if (!u->anim)
		vlog(u, "token  %s", tok);
	else
		u->dirty = 1;
}

static void um_peer(struct ui *u, int state, const char *addr)
{
	struct peerrow *p;

	if (!u->anim) {
		vlog(u, "peer   %s %s", state == SESSION_PEER_LIVE ? "live" :
		     state == SESSION_PEER_PUNCHING ? "punching" : "seen",
		     addr && addr[0] && addr[0] != '-' ? addr : "");
		return;
	}
	if (state == SESSION_PEER_SEEN || !u->npeer) {
		if (u->npeer >= 8)
			return;
		p = &u->peer[u->npeer++];
		p->state = state;
		snprintf(p->addr, sizeof(p->addr), "%s", addr ? addr : "");
	} else {
		p = &u->peer[u->npeer - 1];
		p->state = state;
		if (addr && addr[0] && addr[0] != '-')
			snprintf(p->addr, sizeof(p->addr), "%s", addr);
	}
	u->dirty = 1;
}

static void um_escalate(struct ui *u, const char *why)
{
	if (!u->anim) {
		vlog(u, "rdv    ! %s", why);
		return;
	}
	snprintf(u->escalate, sizeof(u->escalate), "%s", why);
	u->have_escalate = 1;
	u->dirty = 1;
}

static void um_live(struct ui *u)
{
	u->established = 1;
	if (!u->anim)
		vlog(u, "local  link up");
	else
		u->dirty = 1;
}

/* ---- observer callbacks (client inline; also reused by the foreground) ---- */

static void cb_net(void *a, int f, int sc, int v, const char *ad)
{
	um_net(a, f, sc, v, ad);
}
static void cb_link(void *a, const char *n, int h4, int h6) { um_link(a, n, h4, h6); }
static void cb_rdv(void *a, int f, const char *ad, int rd) { um_rdv(a, f, rd, ad); }
static void cb_token(void *a, const char *t) { um_token(a, t); }
static void cb_peer(void *a, int s, const char *ad) { um_peer(a, s, ad); }
static void cb_esc(void *a, const char *w) { um_escalate(a, w); }
static void cb_tick(void *a)
{
	struct ui *u = a;
	uint64_t t = now_ms();

	if (!u->anim)
		return;
	if (t - u->last_spin > 120) {
		u->spin++;
		u->last_spin = t;
		u->dirty = 1;
	}
	if (u->dirty || t - u->last_paint > 400)
		draw(u);
}

static void cb_established(void *a)
{
	struct ui *u = a;

	um_live(u);
	if (u->role == UI_ROLE_CLIENT) {
		repaint(u);
		zap(u, 1);
	}
}

void ui_bind(struct ui *u, struct session_obs *obs)
{
	memset(obs, 0, sizeof(*obs));
	obs->arg = u;
	obs->net = cb_net;
	obs->link = cb_link;
	obs->rendezvous = cb_rdv;
	obs->token = cb_token;
	obs->peer = cb_peer;
	obs->escalate = cb_esc;
	obs->established = cb_established;
	obs->tick = cb_tick;
}

/* ---- host service side: serialise events to the foreground pipe ---- */

static void em_net(void *a, int f, int sc, int v, const char *ad)
{
	dprintf(((struct ui_emit *)a)->fd, "N %d %d %d %s\n", f, sc, v, ad);
}
static void em_link(void *a, const char *n, int h4, int h6)
{
	dprintf(((struct ui_emit *)a)->fd, "I %d %d %s\n", h4, h6, n);
}
static void em_rdv(void *a, int f, const char *ad, int rd)
{
	dprintf(((struct ui_emit *)a)->fd, "R %d %d %s\n", f, rd, ad);
}
static void em_token(void *a, const char *t)
{
	dprintf(((struct ui_emit *)a)->fd, "T %s\n", t);
}
static void em_peer(void *a, int s, const char *ad)
{
	dprintf(((struct ui_emit *)a)->fd, "P %d %s\n", s,
		ad && ad[0] ? ad : "-");
}
static void em_esc(void *a, const char *w)
{
	dprintf(((struct ui_emit *)a)->fd, "E %s\n", w);
}
static void em_live(void *a)
{
	dprintf(((struct ui_emit *)a)->fd, "L\n");
}

void ui_emitter(struct session_obs *obs, int fd)
{
	struct ui_emit *e = malloc(sizeof(*e));	/* lives until the service exits */

	memset(obs, 0, sizeof(*obs));
	if (!e)
		return;
	e->fd = fd;
	obs->arg = e;
	obs->net = em_net;
	obs->link = em_link;
	obs->rendezvous = em_rdv;
	obs->token = em_token;
	obs->peer = em_peer;
	obs->escalate = em_esc;
	obs->established = em_live;
	/* tick is local to the view; the foreground animates on its own clock */
}

void ui_emitter_token(const struct session_obs *obs, const char *token_str)
{
	if (obs && obs->token)
		obs->token(obs->arg, token_str);
}

/* ---- host foreground side: render pipe events, wait for the operator ---- */

static void feed(struct ui *u, char *ln)
{
	int a, b, c;
	char s[160];

	switch (ln[0]) {
	case 'N':
		if (sscanf(ln + 1, "%d %d %d %79[^\n]", &a, &b, &c, s) == 4)
			um_net(u, a, b, c, s);
		break;
	case 'I':
		if (sscanf(ln + 1, "%d %d %31[^\n]", &a, &b, s) == 3)
			um_link(u, s, a, b);
		break;
	case 'R':
		if (sscanf(ln + 1, "%d %d %79[^\n]", &a, &b, s) == 3)
			um_rdv(u, a, b, s);
		break;
	case 'T':
		if (sscanf(ln + 1, " %255s", u->token) == 1) {
			u->have_token = 1;
			if (!u->anim)
				vlog(u, "token  %s", u->token);
			else
				u->dirty = 1;
		}
		break;
	case 'P':
		s[0] = '\0';
		if (sscanf(ln + 1, "%d %79[^\n]", &a, s) >= 1)
			um_peer(u, a, s);
		break;
	case 'E':
		if (sscanf(ln + 1, " %159[^\n]", s) == 1)
			um_escalate(u, s);
		break;
	case 'L':
		um_live(u);
		break;
	default:
		break;
	}
}

static void raw_on(struct ui *u)
{
	struct termios t;

	if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &u->saved))
		return;
	t = u->saved;
	t.c_lflag &= ~(unsigned)(ICANON | ECHO);	/* keep ISIG for Ctrl-C */
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 0;
	if (!tcsetattr(STDIN_FILENO, TCSANOW, &t))
		u->raw = 1;
}

static void raw_off(struct ui *u)
{
	if (u->raw) {
		tcsetattr(STDIN_FILENO, TCSANOW, &u->saved);
		u->raw = 0;
	}
}

int ui_host_wait(struct ui *u, int fd)
{
	char buf[1024];
	int len = 0, result = 0, eof = 0, stdin_ok = 1;
	struct sigaction sa, oint, oterm;

	ui_abort_flag = 0;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = ui_on_signal;		/* no SA_RESTART: poll gets EINTR */
	sigaction(SIGINT, &sa, &oint);
	sigaction(SIGTERM, &sa, &oterm);

	raw_on(u);
	repaint(u);
	while (!eof) {
		struct pollfd fds[2];

		fds[0].fd = fd;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		fds[1].fd = stdin_ok ? STDIN_FILENO : -1;
		fds[1].events = POLLIN;
		fds[1].revents = 0;
		poll(fds, 2, 100);

		if (ui_abort_flag) {		/* Ctrl-C / SIGTERM */
			result = -1;
			break;
		}
		/* POLLHUP without POLLIN signals the service closed the pipe. */
		if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
			int got = (int)read(fd, buf + len, sizeof(buf) - 1 - len);

			if (got <= 0)
				eof = 1;
			else {
				char *nl;

				len += got;
				buf[len] = '\0';
				while ((nl = memchr(buf, '\n', len)) != NULL) {
					*nl = '\0';
					feed(u, buf);
					len -= (int)(nl + 1 - buf);
					memmove(buf, nl + 1, len + 1);
				}
			}
		}
		if (fds[1].revents & POLLIN) {
			char c;
			int got = (int)read(STDIN_FILENO, &c, 1);

			if (got == 0) {
				stdin_ok = 0;		/* EOF: stop watching it */
			} else if (got == 1 && c == 27) {	/* ESC */
				result = -1;
				break;
			} else if (got == 1 &&
				   (c == '\r' || c == '\n' || c == ' ')) {
				result = 1;
				break;
			}
		}
		if (u->anim) {
			uint64_t t = now_ms();

			if (t - u->last_spin > 120) {
				u->spin++;
				u->last_spin = t;
				u->dirty = 1;
			}
			if (u->dirty || t - u->last_paint > 400)
				draw(u);
		}
	}
	raw_off(u);
	sigaction(SIGINT, &oint, NULL);
	sigaction(SIGTERM, &oterm, NULL);
	if (result == 1) {
		zap(u, 0);
	} else if (u->anim) {
		fputs(RST "\033[2J\033[H", stdout);	/* clean screen on abort */
		fflush(stdout);
	}
	return result;
}

/* ---- lifecycle ---- */

struct ui *ui_create(int role, int mode)
{
	struct ui *u = calloc(1, sizeof(*u));

	if (!u)
		return NULL;
	u->role = role;
	u->anim = (mode != UI_VERBOSE) && isatty(STDOUT_FILENO);
	u->start = now_ms();
	u->last_spin = u->start;
	srand((unsigned)u->start);
	winsize(u);
	if (u->anim) {
		fputs("\033[2J", stdout);
		hide_cursor(u);
		fflush(stdout);
	}
	return u;
}

void ui_destroy(struct ui *u)
{
	if (!u)
		return;
	if (u->anim) {
		show_cursor(u);
		fputs(RST, stdout);
		fflush(stdout);
	}
	free(u);
}
