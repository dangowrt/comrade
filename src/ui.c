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

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base64.h"
#include "dbg.h"
#include "oscompat.h"
#include "qr.h"
#include "token.h"
#include "tty.h"
#include "ui.h"
#include "wsock.h"

#include <signal.h>
#ifndef _WIN32
#include <unistd.h>
#endif

/*
 * Set by SIGINT/SIGTERM while the host foreground waits, so it aborts cleanly
 * (terminal restored, service torn down) instead of dying mid-raw-mode.
 * Windows has SIGINT too -- the CRT raises it from the console control handler,
 * on its own thread -- and the wait loop is a 100 ms poll that notices the flag
 * on its next turn, so one flag serves both. SIGTERM does not exist there.
 */
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
struct peerrow { int id; int state; int read_only; char addr[80]; };

/* What the host foreground shows: the dashboard, or one token full-screen
 * as a QR code. Q cycles, ESC returns. */
enum ui_view { UI_VIEW_DASH, UI_VIEW_QR_RW, UI_VIEW_QR_RO };

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
	struct rdvrow rdv[2];		/* fixed slots: [0] v4, [1] v6 */
	int stage4, stage6;		/* per-family rendezvous stage, -1 unknown */
	char token[256];
	int have_token;
	int tok_st4, tok_st6;		/* TOKEN_STATE_* decoded from token */
	char token_ro[256];
	int have_token_ro;
	struct peerrow peer[8];
	int npeer;
	char escalate[160];
	int have_escalate;
	int established;
	int view;			/* enum ui_view */
	char notice[96];		/* transient footer note (copy feedback) */
	uint64_t notice_until;

	struct tty_saved saved;
	int raw;
};

/*
 * One queued dashboard event. line is over-allocated to len bytes; the trailing
 * [1] is the C89 spelling of what a flexible array member says in C99.
 */
struct ui_event {
	struct ui_event *next;
	size_t len;
	size_t off;
	char line[1];
};

struct ui_emit {
	sock_t fd;
	pthread_mutex_t lock;
	pthread_cond_t ready;
	pthread_t writer;
	struct ui_event *head;
	struct ui_event *tail;
	int closed;
};

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* Colour on unless --plain or NO_COLOR asked otherwise (set at create). */
static int ui_color = 1;

/* Body text as-is, or with the SGR sequences stripped: only the styling
 * goes, cursor and erase controls stay functional. */
static void emit_body(const char *s)
{
	if (ui_color) {
		fputs(s, stdout);
		return;
	}
	while (*s) {
		if (s[0] == '\033' && s[1] == '[') {
			const char *p = s + 2;

			while (*p && !((*p >= 'A' && *p <= 'Z') ||
				       (*p >= 'a' && *p <= 'z')))
				p++;
			if (*p == 'm') {
				s = p + 1;
				continue;
			}
		}
		putchar(*s++);
	}
}

/* ---- log-line rendering (verbose / non-tty) ---- */

static void vlog(struct ui *u, const char *fmt, ...)
{
	char buf[640];
	va_list ap;
	double el = (double)(now_ms() - u->start) / 1000.0;

	printf(ui_color ? DIM "%6.1f  " RST : "%6.1f  ", el);
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	emit_body(buf);
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
	int rows, cols;

	u->rows = 24;
	u->cols = 80;
	if (!tty_size(&rows, &cols)) {
		u->rows = rows;
		u->cols = cols;
	}
}

/* One dashboard line: body text, cleared to end of line, then down. */
static void line(const char *fmt, ...)
{
	char buf[640];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	emit_body(buf);
	fputs("\033[K\n", stdout);
}

/*
 * Colour + text for a path's classification. A direct global address is
 * routable but not proven reachable from a stranger -- a stateful firewall can
 * still drop inbound -- so it reads "GLOBAL", not "open". A srflx global is
 * behind NAT. Confirming reachability (open vs firewalled) needs an active
 * probe from a second vantage (RFC 5780), still to come.
 */
static void net_label(int scope, int via, const char **color, const char **text)
{
	if (scope == NET_SCOPE_LAN) {
		*color = DIM;
		*text = "LAN";
	} else if (scope == NET_SCOPE_CGNAT) {
		*color = YEL;
		*text = via == NET_VIA_STUN ? "CGNAT (NAT)" : "CGNAT";
	} else if (via == NET_VIA_STUN) {
		*color = BYE;
		*text = "GLOBAL (NAT)";
	} else {
		*color = CYN;
		*text = "GLOBAL";
	}
}

/*
 * Animated spinners. All keep moving -- the DHT stays alive and pumping even
 * once ready -- so the STYLE, not the motion, conveys the stage. The rendezvous
 * spinner has nine styles for the interleaved v4+v6 progress (each family walks
 * cold -> warmup -> store -> get -> ready, and the pair advances one family at a
 * time): 0 both cold, 1 one warming, 2 both, 3 one storing, ... 8 both ready.
 */
static const char rdv_flavor[9][4] = {
	{ '.', '\'', '.', ',' },	/* 0 both cold */
	{ '.', 'o', '.', 'o' },		/* 1 one warming */
	{ 'o', 'O', 'o', 'O' },		/* 2 both warming */
	{ '|', '/', '-', '\\' },		/* 3 one storing */
	{ '-', '\\', '|', '/' },		/* 4 both storing */
	{ '<', '^', '>', 'v' },		/* 5 one getting */
	{ '^', '>', 'v', '<' },		/* 6 both getting */
	{ '+', 'x', '+', 'x' },		/* 7 one ready */
	{ '*', '+', '*', '+' },		/* 8 both ready */
};
static const char net_flavor[3][4] = {
	{ '|', '/', '-', '\\' },		/* 0 probing */
	{ 'o', 'O', 'o', 'O' },		/* 1 paths found */
	{ '*', '+', '*', '+' },		/* 2 NAT resolved */
};

/* Merge the two families' stages (0..4, or -1 if that family is not expected)
 * into the 0..8 rendezvous-spinner index. */
static int rdv_combined(int s4, int s6)
{
	int lo, hi, c;

	if (s4 < 0 && s6 < 0)
		return 0;
	if (s4 < 0)
		s4 = s6;			/* single family: even steps only */
	if (s6 < 0)
		s6 = s4;
	lo = s4 < s6 ? s4 : s6;
	hi = s4 < s6 ? s6 : s4;
	c = lo * 2 + (hi > lo ? 1 : 0);
	return c > 8 ? 8 : c;
}

/* Hand `text` to the terminal's clipboard (OSC 52): works locally and
 * through SSH, and spares anyone -- a screen-reader user above all --
 * selecting a 130-character token off a raw screen by hand. */
static void osc52_copy(const char *text)
{
	char b64[512];

	if (!base64_encode((const uint8_t *)text, strlen(text), b64,
			   sizeof(b64)))
		return;
	printf("\033]52;c;%s\a", b64);
	fflush(stdout);
}

static void notice_set(struct ui *u, const char *msg)
{
	snprintf(u->notice, sizeof(u->notice), "%s", msg);
	u->notice_until = now_ms() + 4000;
	if (u->anim)
		u->dirty = 1;
	else
		vlog(u, "local  %s", msg);
}

static int notice_live(struct ui *u)
{
	return u->notice[0] && now_ms() < u->notice_until;
}

/* The token's reachability classification, one dashboard line after
 * whatever `pre` puts in front of it. */
static void token_class_line(struct ui *u, const char *pre)
{
	int r4 = u->tok_st4 == TOKEN_STATE_RENDEZVOUS ||
		 u->tok_st4 == TOKEN_STATE_DIRECT;
	int r6 = u->tok_st6 == TOKEN_STATE_RENDEZVOUS ||
		 u->tok_st6 == TOKEN_STATE_DIRECT;

	if (r4 && r6)
		line("%s" BGR "reachable over IPv4 and IPv6" RST, pre);
	else if (r4 && u->tok_st6 == TOKEN_STATE_PENDING)
		line("%s" BGR "IPv4 ready" RST DIM
		     " -- locating IPv6 ..." RST, pre);
	else if (r6 && u->tok_st4 == TOKEN_STATE_PENDING)
		line("%s" BGR "IPv6 ready" RST DIM
		     " -- locating IPv4 ..." RST, pre);
	else if (r4)
		line("%s" YEL "IPv4 only" RST, pre);
	else if (r6)
		line("%s" RED "! IPv6 only" RST DIM
		     " -- IPv4-only peers cannot connect" RST, pre);
	else if (u->tok_st4 == TOKEN_STATE_PENDING ||
		 u->tok_st6 == TOKEN_STATE_PENDING)
		line("%s" YEL "locating rendezvous nodes ..." RST
		     DIM " -- joining works now, via a full DHT "
		     "warm-up" RST, pre);
	else
		line("%s" YEL "! no rendezvous nodes" RST DIM
		     " -- joining needs a full DHT warm-up "
		     "(slower, less reliable)" RST, pre);
}

/*
 * One token full-screen as a QR code, the geometry picked to fit the
 * terminal, largest first: double spaces in reverse video (a whole 2x1
 * cell per module, the easiest scan) on roomy terminals, half blocks
 * (square pixels) wherever they fit, sextants only where nothing else
 * does -- their pixels are ~4:3 tall on a 1:2 cell, which the pickiest
 * scanners refuse, so the page runs lean (no header, type and
 * classification share a line) to keep half blocks viable down to a
 * ~27-row terminal. The blank rows above and below and the centring
 * margin are the quiet zone the art itself no longer carries.
 */
static void draw_qr(struct ui *u)
{
	const char *tok = u->view == UI_VIEW_QR_RO ? u->token_ro : u->token;
	const char *kind = u->view == UI_VIEW_QR_RO ? "read-only" : "read-write";
	const char *nxt = u->view == UI_VIEW_QR_RW && u->have_token_ro ?
			  "read-only QR" : "dashboard";
	char enc[280], pre[224];
	struct qr_art art;
	int i, pad;

	hide_cursor(u);
	winsize(u);			/* re-pick the geometry on resize */
	fputs("\033[H", stdout);
	line("");
	snprintf(enc, sizeof(enc), "comrade:%s", tok);
	if (qr_render_fit(enc, u->rows - 4, u->cols - 4, &art)) {
		line(YEL "  the terminal is too small for a scannable QR "
		     "code" RST);
	} else {
		pad = (u->cols - art.cols) / 2;
		if (pad < 0)
			pad = 0;
		for (i = 0; i < art.rows; i++)
			line("%*s%s", pad, "", art.row[i]);
	}
	line("");
	snprintf(pre, sizeof(pre),
		 CYN "INVITE" RST "  " WHT "%s" RST DIM " -- " RST, kind);
	token_class_line(u, pre);
	/* The footer may sit on the last row: no newline, or it scrolls. */
	if (notice_live(u)) {
		snprintf(pre, sizeof(pre), BGR "[ %s ]" RST "\033[K",
			 u->notice);
		emit_body(pre);
	} else {
		snprintf(pre, sizeof(pre),
			 DIM "[ " BYE "Q" DIM " %s / " BYE "C" DIM " copy / "
			 BYE "ESC" DIM " dashboard / " BYE "ENTER" DIM
			 " enter ]" RST "\033[K", nxt);
		emit_body(pre);
	}
	fputs("\033[J", stdout);
	fflush(stdout);
	u->last_paint = now_ms();
	u->dirty = 0;
}

static void draw(struct ui *u)
{
	int i, f = u->spin & 3, ns = 0, rc;

	if (u->view == UI_VIEW_QR_RO && !u->have_token_ro)
		u->view = UI_VIEW_QR_RW;
	if (u->role == UI_ROLE_HOST && u->view != UI_VIEW_DASH &&
	    u->have_token) {
		draw_qr(u);
		return;
	}
	hide_cursor(u);
	fputs("\033[H", stdout);

	if (u->role == UI_ROLE_HOST)
		line(BGR "comrade" RST DIM
		     "  shared terminals over a punched p2p link" RST);
	else {
		char sh[64];

		sh[0] = '\0';
		if (u->have_token && strlen(u->token) > 18)
			snprintf(sh, sizeof(sh), "%.12s" DIM ".." RST CYN "%.3s",
				 u->token, u->token + strlen(u->token) - 3);
		else
			snprintf(sh, sizeof(sh), "%.40s", u->token);
		line(BGR "comrade" RST DIM "  joining  " RST CYN "%s" RST, sh);
	}
	line("");

	if (u->nnet)
		ns = 1;
	for (i = 0; i < u->nnet; i++)
		if (u->net[i].via == NET_VIA_STUN)
			ns = 2;
	line(CYN "NETWORK" RST "  " YEL "%c" RST, net_flavor[ns][f]);
	if (!u->nnet && !u->nlink)
		line(DIM "  probing ..." RST);
	for (i = 0; i < u->nnet; i++) {
		struct netrow *n = &u->net[i];
		const char *col, *txt;

		net_label(n->scope, n->via, &col, &txt);
		line("  " DIM "%s" RST "  " CYN "%-40s" RST "%s%s" RST,
		     n->family == 6 ? "IPv6" : "IPv4", n->addr, col, txt);
	}
	for (i = 0; i < u->nlink; i++) {
		struct linkrow *l = &u->link[i];

		line("  " DIM "LINK" RST "  " CYN "%-44s" RST "%s%s", l->name,
		     l->has4 ? BGR "v4 " RST : DIM "-- " RST,
		     l->has6 ? BGR "v6" RST : DIM "--" RST);
	}
	line("");

	rc = u->role == UI_ROLE_HOST ? rdv_combined(u->stage4, u->stage6) : -1;
	line(CYN "RENDEZVOUS" RST "  " YEL "%c" RST,
	     rc < 0 ? net_flavor[0][f] : rdv_flavor[rc][f]);
	if (!u->rdv[0].family && !u->rdv[1].family)
		line(DIM "  locating a close node ..." RST);
	for (i = 0; i < 2; i++) {
		struct rdvrow *r = &u->rdv[i];

		if (!r->family)			/* empty slot */
			continue;
		if (r->addr[0])			/* known address == located */
			line("  " DIM "v%d" RST "  " CYN "%s" RST,
			     r->family, r->addr);
		else
			line("  " DIM "v%d" RST DIM
			     "  locating a close node ..." RST, r->family);
	}
	if (u->have_escalate)
		line("  " RED "! %s" RST, u->escalate);
	line("");

	if (u->role == UI_ROLE_HOST) {
		line(CYN "INVITE" RST);
		if (u->have_token) {
			line("  " WHT "$ comrade %s" RST DIM "   (read-write)" RST,
			     u->token);
			if (u->have_token_ro)
				line("  " WHT "$ comrade %s" RST DIM
				     "   (read-only)" RST, u->token_ro);
			token_class_line(u, "  ");
		} else {
			line(DIM "  locating a rendezvous node ..." RST);
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

			line("  " BGR "#%d" RST " %s  " CYN "%s" RST "%s",
			     i + 1, st, p->addr[0] && p->addr[0] != '-' ?
			     p->addr : "",
			     p->read_only ? "  " YEL "view-only" RST : "");
		}
		line("");
		if (notice_live(u))
			line(BGR "[ %s ]" RST, u->notice);
		else if (u->have_token)
			line(DIM "[ " BYE "ENTER" DIM " / " BYE "SPACE" DIM
			     " to enter the shared session / " BYE "Q" DIM
			     " invite QR / " BYE "C" DIM " copy token ]" RST);
		else
			line(DIM "[ " BYE "ENTER" DIM " / " BYE "SPACE" DIM
			     " to enter the shared session ]" RST);
	} else {
		const char *pa = u->npeer && u->peer[0].addr[0] &&
				 u->peer[0].addr[0] != '-' ? u->peer[0].addr : NULL;

		if (u->established && pa)
			line(BGR "  link up via " RST CYN "%s" RST BGR
			     " -- entering ..." RST, pa);
		else if (u->established)
			line(BGR "  link up -- entering ..." RST);
		else if (pa)
			line(DIM "  connecting to " RST CYN "%s" RST DIM
			     " ..." RST, pa);
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

static void bar(int row, int cols, const char *sgr)
{
	printf("\033[%d;1H%s%*s" RST, row + 1, sgr, cols, "");
}

static void zap(struct ui *u, int snow)
{
	int cen, r, y, f;
	uint64_t t0;

	if (!u->anim)
		return;
	winsize(u);
	cen = u->rows / 2;
	hide_cursor(u);
	t0 = os_mono_ms();

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
			os_msleep(28);
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
		os_msleep(20);
	}
	for (y = 0; y < u->rows; y++)		/* flare */
		bar(y, u->cols, "\033[107m");
	fflush(stdout);
	os_msleep(70);
	fputs(RST "\033[2J\033[H", stdout);	/* cut to black */
	fflush(stdout);
	os_msleep(130);
	dbg_logf("zap: done total=%ums", (unsigned)(os_mono_ms() - t0));
}

/* ---- model updates (shared by the inline client and the host foreground) --- */

static const char *scope_word(int scope, int via)
{
	if (scope == NET_SCOPE_LAN)
		return "lan";
	if (scope == NET_SCOPE_CGNAT)
		return via == NET_VIA_STUN ? "cgnat-nat" : "cgnat";
	return via == NET_VIA_STUN ? "global-nat" : "global";
}

static void um_net(struct ui *u, int family, int scope, int via, const char *addr)
{
	int i;

	for (i = 0; i < u->nnet; i++)		/* de-dup trickled candidates */
		if (u->net[i].family == family && u->net[i].via == via &&
		    !strcmp(u->net[i].addr, addr))
			return;
	if (u->nnet >= 12)
		return;
	u->net[u->nnet].family = family;
	u->net[u->nnet].scope = scope;
	u->net[u->nnet].via = via;
	snprintf(u->net[u->nnet].addr, sizeof(u->net[0].addr), "%s", addr);
	u->nnet++;
	if (u->anim)
		u->dirty = 1;
	else
		vlog(u, "net    %s %-40s %s", family == 6 ? "ipv6" : "ipv4",
		     addr, scope_word(scope, via));
}

static void um_link(struct ui *u, const char *name, int has4, int has6)
{
	int i;

	for (i = 0; i < u->nlink; i++)
		if (!strcmp(u->link[i].name, name))
			return;
	if (u->nlink >= 8)
		return;
	snprintf(u->link[u->nlink].name, sizeof(u->link[0].name), "%s", name);
	u->link[u->nlink].has4 = has4;
	u->link[u->nlink].has6 = has6;
	u->nlink++;
	if (u->anim)
		u->dirty = 1;
	else
		vlog(u, "link   %s %s%s%s", name, has4 ? "v4" : "",
		     has4 && has6 ? "+" : "", has6 ? "v6" : "");
}

static void um_rdv(struct ui *u, int family, int ready, const char *addr)
{
	/* Fixed slots -- v4 above v6 -- so host and client render the two
	 * rendezvous nodes in the same order regardless of which located first. */
	int slot = family == 4 ? 0 : 1;
	int changed = u->rdv[slot].family != family ||
		      u->rdv[slot].ready != ready ||
		      strcmp(u->rdv[slot].addr, addr) != 0;

	u->rdv[slot].family = family;
	u->rdv[slot].ready = ready;
	snprintf(u->rdv[slot].addr, sizeof(u->rdv[slot].addr), "%.*s",
		 (int)(sizeof(u->rdv[slot].addr) - 1), addr);
	if (!changed)
		return;
	if (u->anim)
		u->dirty = 1;
	else
		vlog(u, "rdv    v%d %s %s", family, addr,
		     ready ? "validated, pinned" : "contacting");
}

static void um_rdv_stage(struct ui *u, int family, int stage)
{
	int *cur = family == 6 ? &u->stage6 : &u->stage4;

	if (*cur == stage)
		return;
	*cur = stage;
	if (u->anim) {
		u->dirty = 1;
	} else {
		static const char *nm[] = { "cold", "warmup", "store", "get",
					    "ready" };

		if (stage >= 0 && stage <= 4)
			vlog(u, "rdv    v%d %s", family, nm[stage]);
	}
}

/* The invite classification is read out of the token itself -- the states are
 * in the string the view is already handed, so decoding it here keeps the
 * lines consistent with what the token actually says. */
static void um_token(struct ui *u, const char *tok)
{
	struct token t;

	snprintf(u->token, sizeof(u->token), "%s", tok);
	u->have_token = 1;
	if (!token_decode(&t, u->token)) {
		u->tok_st4 = token_family_state(&t, 4);
		u->tok_st6 = token_family_state(&t, 6);
	}
	if (!u->anim)
		vlog(u, "token  %s", tok);
	else
		u->dirty = 1;
}

static void um_token_ro(struct ui *u, const char *tok)
{
	snprintf(u->token_ro, sizeof(u->token_ro), "%s", tok);
	u->have_token_ro = 1;
	if (!u->anim)
		vlog(u, "token  %s (read-only)", tok);
	else
		u->dirty = 1;
}

static void um_peer(struct ui *u, int id, int state, const char *addr)
{
	int have_addr = addr && addr[0] && addr[0] != '-';
	int i, at = -1;

	if (!u->anim) {
		vlog(u, "peer   %s %s", state == SESSION_PEER_LIVE ? "live" :
		     state == SESSION_PEER_PUNCHING ? "punching" :
		     state == SESSION_PEER_GONE ? "gone" : "seen",
		     have_addr ? addr : "");
		return;
	}
	/* Rows are keyed by the connection's id, so each attached client owns one
	 * row that its own updates (address, state) and GONE address, independent
	 * of the others; the single-connection client uses id 0. */
	for (i = 0; i < u->npeer; i++)
		if (u->peer[i].id == id) {
			at = i;
			break;
		}
	if (state == SESSION_PEER_GONE) {
		if (at >= 0) {
			memmove(&u->peer[at], &u->peer[at + 1],
				(u->npeer - at - 1) * sizeof(u->peer[0]));
			u->npeer--;
			u->dirty = 1;
		}
		return;
	}
	if (at < 0) {
		if (u->npeer >= 8)
			return;
		at = u->npeer++;
		u->peer[at].id = id;
		u->peer[at].addr[0] = '\0';
		u->peer[at].read_only = 0;
	}
	u->peer[at].state = state;
	if (have_addr)
		snprintf(u->peer[at].addr, sizeof(u->peer[at].addr), "%s", addr);
	u->dirty = 1;
}

/* Mark an existing peer row as a view-only guest (host dashboard). */
static void um_peer_ro(struct ui *u, int id)
{
	int i;

	if (!u->anim) {
		vlog(u, "peer   %d read-only", id);
		return;
	}
	for (i = 0; i < u->npeer; i++)
		if (u->peer[i].id == id) {
			u->peer[i].read_only = 1;
			u->dirty = 1;
			return;
		}
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

static void um_escalate_clear(struct ui *u)
{
	if (!u->anim) {
		vlog(u, "rdv    warning cleared");
		return;
	}
	if (!u->have_escalate)
		return;
	u->have_escalate = 0;
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

/* A roam/reconnect tore the path down: drop the stale local candidates, the
 * dead peer and the "link up", so the dashboard shows the fresh attempt and not
 * the addresses of the network that just vanished. */
static void um_reset(struct ui *u)
{
	u->nnet = 0;
	u->npeer = 0;
	u->established = 0;
	if (u->anim)
		u->dirty = 1;
	else
		vlog(u, "local  reconnecting -- candidates flushed");
}

static void um_net_reset(struct ui *u)
{
	u->nnet = 0;
	if (u->anim)
		u->dirty = 1;
	else
		vlog(u, "local  network changed -- candidates flushed");
}

/* ---- observer callbacks (client inline; also reused by the foreground) ---- */

static void cb_net(void *a, int f, int sc, int v, const char *ad)
{
	um_net(a, f, sc, v, ad);
}
static void cb_link(void *a, const char *n, int h4, int h6) { um_link(a, n, h4, h6); }
static void cb_rdv(void *a, int f, const char *ad, int rd) { um_rdv(a, f, rd, ad); }
static void cb_rdv_stage(void *a, int f, int st) { um_rdv_stage(a, f, st); }
static void cb_token(void *a, const char *t) { um_token(a, t); }
static void cb_token_ro(void *a, const char *t) { um_token_ro(a, t); }
static void cb_peer(void *a, int id, int s, const char *ad) { um_peer(a, id, s, ad); }
static void cb_peer_ro(void *a, int id) { um_peer_ro(a, id); }
static void cb_reset(void *a) { um_reset(a); }
static void cb_net_reset(void *a) { um_net_reset(a); }
static void cb_esc(void *a, const char *w) { um_escalate(a, w); }
static void cb_esc_clear(void *a) { um_escalate_clear(a); }
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
	obs->rdv_stage = cb_rdv_stage;
	obs->token = cb_token;
	obs->token_ro = cb_token_ro;
	obs->peer = cb_peer;
	obs->peer_ro = cb_peer_ro;
	obs->reset = cb_reset;
	obs->net_reset = cb_net_reset;
	obs->escalate = cb_esc;
	obs->escalate_clear = cb_esc_clear;
	obs->established = cb_established;
	obs->tick = cb_tick;
}

/* ---- host service side: serialise events to the foreground channel ---- */

/*
 * One line per event, written to the socket the foreground reads. This was
 * dprintf() on a pipe; the channel is a socket now (the service is a separate
 * *process* on Windows, not a fork, and the only handle both ends can poll is
 * a socket), and Windows has no dprintf and no write() that can see a SOCKET.
 * Same wire format, same one-line-per-event framing.
 */
static void *emit_writer(void *arg)
{
	struct ui_emit *e = arg;

	for (;;) {
		struct ui_event *ev;
		ssize_t n;

		pthread_mutex_lock(&e->lock);
		while (!e->closed && !e->head)
			pthread_cond_wait(&e->ready, &e->lock);
		if (e->closed) {
			pthread_mutex_unlock(&e->lock);
			return NULL;
		}
		ev = e->head;
		pthread_mutex_unlock(&e->lock);

		n = sock_write(e->fd, ev->line + ev->off, ev->len - ev->off);
		if (n > 0) {
			pthread_mutex_lock(&e->lock);
			ev->off += (size_t)n;
			if (ev->off == ev->len) {
				e->head = ev->next;
				if (!e->head)
					e->tail = NULL;
				free(ev);
			}
			pthread_mutex_unlock(&e->lock);
		} else if (n < 0 && sock_err_intr(sock_errno())) {
			continue;
		} else {
			pthread_mutex_lock(&e->lock);
			e->closed = 1;
			while ((ev = e->head) != NULL) {
				e->head = ev->next;
				free(ev);
			}
			e->tail = NULL;
			pthread_mutex_unlock(&e->lock);
			return NULL;
		}
	}
}

static void emitf(void *a, const char *fmt, ...)
{
	struct ui_emit *e = a;
	struct ui_event *ev;
	char line[512];
	va_list ap;
	int n;
	size_t len;

	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	if (n <= 0)
		return;
	len = (size_t)(n < (int)sizeof(line) ? n : (int)sizeof(line) - 1);
	ev = malloc(sizeof(*ev) + len);
	if (!ev) {
		dbg_logf("ui: unable to queue foreground event");
		return;
	}
	ev->next = NULL;
	ev->len = len;
	ev->off = 0;
	memcpy(ev->line, line, len);

	pthread_mutex_lock(&e->lock);
	if (!e->closed) {
		if (e->tail)
			e->tail->next = ev;
		else
			e->head = ev;
		e->tail = ev;
		pthread_cond_signal(&e->ready);
		ev = NULL;
	}
	pthread_mutex_unlock(&e->lock);
	free(ev);
}

static void em_net(void *a, int f, int sc, int v, const char *ad)
{
	emitf(a, "N %d %d %d %s\n", f, sc, v, ad);
}
static void em_link(void *a, const char *n, int h4, int h6)
{
	emitf(a, "I %d %d %s\n", h4, h6, n);
}
static void em_rdv(void *a, int f, const char *ad, int rd)
{
	emitf(a, "R %d %d %s\n", f, rd, ad);
}
static void em_rdv_stage(void *a, int f, int st)
{
	emitf(a, "G %d %d\n", f, st);
}
static void em_token(void *a, const char *t)
{
	emitf(a, "T %s\n", t);
}
static void em_token_ro(void *a, const char *t)
{
	emitf(a, "U %s\n", t);
}
static void em_peer(void *a, int id, int s, const char *ad)
{
	emitf(a, "P %d %d %s\n", id, s, ad && ad[0] ? ad : "-");
}
static void em_peer_ro(void *a, int id)
{
	emitf(a, "O %d\n", id);
}
static void em_reset(void *a)
{
	emitf(a, "X\n");
}
static void em_net_reset(void *a)
{
	emitf(a, "Y\n");
}
static void em_esc(void *a, const char *w)
{
	emitf(a, "E %s\n", w);
}
static void em_esc_clear(void *a)
{
	emitf(a, "C\n");
}
static void em_live(void *a)
{
	emitf(a, "L\n");
}

void ui_emitter(struct session_obs *obs, sock_t fd)
{
	struct ui_emit *e = calloc(1, sizeof(*e)); /* lives until the service exits */

	memset(obs, 0, sizeof(*obs));
	if (!e)
		return;
	if (pthread_mutex_init(&e->lock, NULL)) {
		free(e);
		return;
	}
	if (pthread_cond_init(&e->ready, NULL)) {
		pthread_mutex_destroy(&e->lock);
		free(e);
		return;
	}
	if (pthread_create(&e->writer, NULL, emit_writer, e)) {
		pthread_cond_destroy(&e->ready);
		pthread_mutex_destroy(&e->lock);
		free(e);
		return;
	}
	pthread_detach(e->writer);
	e->fd = fd;
	obs->arg = e;
	obs->net = em_net;
	obs->link = em_link;
	obs->rendezvous = em_rdv;
	obs->rdv_stage = em_rdv_stage;
	obs->token = em_token;
	obs->token_ro = em_token_ro;
	obs->peer = em_peer;
	obs->peer_ro = em_peer_ro;
	obs->reset = em_reset;
	obs->net_reset = em_net_reset;
	obs->escalate = em_esc;
	obs->escalate_clear = em_esc_clear;
	obs->established = em_live;
	/* tick is local to the view; the foreground animates on its own clock */
}

void ui_emitter_token(const struct session_obs *obs, const char *token_str)
{
	if (obs && obs->token)
		obs->token(obs->arg, token_str);
}

void ui_emitter_token_ro(const struct session_obs *obs, const char *token_str)
{
	if (obs && obs->token_ro)
		obs->token_ro(obs->arg, token_str);
}

/* ---- host foreground side: render service events, wait for the operator ---- */

static void feed(struct ui *u, char *ln)
{
	int a, b, c;
	char s[160];
	char tok[256];

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
	case 'G':
		if (sscanf(ln + 1, "%d %d", &a, &b) == 2)
			um_rdv_stage(u, a, b);
		break;
	case 'T':
		if (sscanf(ln + 1, " %255s", tok) == 1)
			um_token(u, tok);
		break;
	case 'U':
		if (sscanf(ln + 1, " %255s", tok) == 1)
			um_token_ro(u, tok);
		break;
	case 'P':
		s[0] = '\0';
		if (sscanf(ln + 1, "%d %d %79[^\n]", &a, &b, s) >= 2)
			um_peer(u, a, b, s);
		break;
	case 'O':
		if (sscanf(ln + 1, "%d", &a) == 1)
			um_peer_ro(u, a);
		break;
	case 'E':
		if (sscanf(ln + 1, " %159[^\n]", s) == 1)
			um_escalate(u, s);
		break;
	case 'C':
		um_escalate_clear(u);
		break;
	case 'L':
		um_live(u);
		break;
	case 'X':
		um_reset(u);
		break;
	case 'Y':
		um_net_reset(u);
		break;
	default:
		break;
	}
}

static void raw_on(struct ui *u)
{
	/* Not full raw: the host dashboard keeps signal generation so Ctrl-C
	 * still aborts (see tty_raw_on). */
	if (!tty_raw_on(&u->saved, 0))
		u->raw = 1;
	/*
	 * Whatever mouse reporting or bracketed paste a mouse-aware terminal, or
	 * a prior program that never cleaned up after itself, left enabled means
	 * nothing to the dashboard -- it reads no mouse events and takes no
	 * paste -- and every report or paste starts with the same byte as a
	 * standalone Escape keypress. Force both off before reading a single
	 * keystroke, rather than trying to tell the two apart from the bytes
	 * alone.
	 */
	if (u->raw) {
		fputs("\033[?1000l\033[?1002l\033[?1003l\033[?1006l\033[?1015l"
		      "\033[?2004l", stdout);
		fflush(stdout);
	}
}

static void raw_off(struct ui *u)
{
	if (u->raw) {
		tty_raw_off(&u->saved);
		u->raw = 0;
	}
}

int ui_host_wait(struct ui *u, sock_t fd)
{
	char buf[1024];
	int len = 0, result = 0, eof = 0, stdin_ok = 1;
	void (*oint)(int);
#ifdef SIGTERM
	void (*oterm)(int);
#endif
	/* The local keyboard, as something poll can see: a real descriptor on
	 * POSIX, a socket fed by the console pump thread on Windows (tty.h). */
	sock_t kbd = tty_sock_in();
	int esc_pending = 0;
	uint64_t esc_deadline = 0;

	ui_abort_flag = 0;
	oint = signal(SIGINT, ui_on_signal);
#ifdef SIGTERM
	oterm = signal(SIGTERM, ui_on_signal);
#endif

	raw_on(u);
	repaint(u);
	while (!eof) {
		struct pollfd fds[2];
		nfds_t nfds = 1;

		if (esc_pending && now_ms() > esc_deadline) {
			esc_pending = 0;
			if (u->view != UI_VIEW_DASH) {
				u->view = UI_VIEW_DASH;
				u->dirty = 1;
			} else {
				result = -1;
				break;
			}
		}
		fds[0].fd = fd;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		fds[1].fd = kbd;
		fds[1].events = POLLIN;
		fds[1].revents = 0;
		if (stdin_ok && sock_valid(kbd))
			nfds = 2;
		sock_poll(fds, nfds, 100);

		if (ui_abort_flag) { 		/* Ctrl-C / SIGTERM */
			result = -1;
			break;
		}
		/* POLLHUP without POLLIN signals the service closed the pipe. */
		if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
			int got;

			/*
			 * Emitters cap their records well below this buffer, so a
			 * full one with no newline in it is malformed. Drop it:
			 * leaving it would size the next read at zero bytes, which
			 * reads back as EOF and retires a live service.
			 */
			if (len == (int)sizeof(buf) - 1)
				len = 0;
			got = (int)sock_read(fd, buf + len,
					     sizeof(buf) - 1 - len);

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
		if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
			char buf[16];
			int got = (int)sock_read(kbd, buf, sizeof(buf));
			int i;

			if (got == 0) {
				stdin_ok = 0;		/* EOF: stop watching it */
			} else if (got > 0) {
				for (i = 0; i < got; i++) {
					unsigned char c = (unsigned char)buf[i];

					if (esc_pending) {
						/* A terminal focus-change or other CSI sequence
						 * starts with Escape; ignore it and only treat a
						 * truly lone Escape as a quit request. */
						if (c == 27) {
							esc_deadline = now_ms() + 80;
							continue;
						}
						esc_pending = 0;
						continue;
					}
					if (c == 27) {
						esc_pending = 1;
						esc_deadline = now_ms() + 80;
						continue;
					}
					if (c == '\r' || c == '\n' || c == ' ') {
						result = 1;
						break;
					}
					/* Q pages through the invite QR codes;
					 * ESC (above) leads back. */
					if ((c == 'q' || c == 'Q') &&
					    u->role == UI_ROLE_HOST &&
					    u->have_token) {
						if (u->view == UI_VIEW_DASH)
							u->view = UI_VIEW_QR_RW;
						else if (u->view == UI_VIEW_QR_RW &&
							 u->have_token_ro)
							u->view = UI_VIEW_QR_RO;
						else
							u->view = UI_VIEW_DASH;
						u->dirty = 1;
					}
					/* c copies the token in view, C the
					 * read-only one, via the terminal. */
					if ((c == 'c' || c == 'C') &&
					    u->role == UI_ROLE_HOST) {
						const char *t = NULL, *w = NULL;

						if (c == 'C' ||
						    u->view == UI_VIEW_QR_RO) {
							if (u->have_token_ro) {
								t = u->token_ro;
								w = "read-only "
								    "token copied "
								    "to the "
								    "clipboard";
							}
						} else if (u->have_token) {
							t = u->token;
							w = "read-write token "
							    "copied to the "
							    "clipboard";
						}
						if (t) {
							osc52_copy(t);
							notice_set(u, w);
						} else {
							notice_set(u, "no such "
								   "token yet");
						}
					}
				}
				if (result)
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
	signal(SIGINT, oint);
#ifdef SIGTERM
	signal(SIGTERM, oterm);
#endif
	if (result == 1) {
		zap(u, 1);			/* same TX-noise entry as the client */
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
	u->stage4 = u->stage6 = -1;
	u->anim = (mode != UI_VERBOSE) && tty_isatty_out();
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
