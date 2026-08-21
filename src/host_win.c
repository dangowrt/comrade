/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host.h"

#ifdef _WIN32

#include <libssh/libssh.h>

#include "conn.h"
#include "cpty.h"
#include "dbg.h"
#include "keys.h"
#include "oscompat.h"
#include "session.h"
#include "sig.h"
#include "sshd.h"
#include "statusbar.h"
#include "termfilter.h"
#include "tmuxpath.h"
#include "token.h"
#include "tty.h"
#include "ui.h"
#include "win_proc.h"

/*
 * The Windows host: the same tmate-like design as the POSIX host.c next to
 * this file -- a private, randomly-named tmux server, a detached service that
 * serves it over the punched link while the operator is away, and a foreground
 * dashboard that waits for the operator to enter -- rebuilt on the three
 * primitives Windows has instead of the three it does not.
 *
 *   fork() + execvp()  ->  CreateProcess                       (win_proc.c)
 *   forkpty() + termios ->  CreatePseudoConsole + STARTUPINFOEX (cpty_win.c)
 *   setsid()           ->  DETACHED_PROCESS | CREATE_NO_WINDOW (win_proc.c)
 *
 * Only one of those substitutions changes the *shape* of the program, and it
 * is the third. setsid() detaches a process that already exists, because it
 * was forked; Windows can only detach a process it is about to create, and a
 * created process starts from main() with none of its parent's memory. So the
 * operator/service split, which on POSIX is "fork and keep going", is here
 * "re-run comrade.exe with --win-service and hand it the state". The state is
 * the session token, the paths, and the ephemeral SSH host key, passed down an
 * inherited socketpair -- the same socketpair the service then emits its
 * dashboard events back on. Nothing touches the disk that did not already, and
 * the host key never does.
 *
 * The other consequence of having no fork is that the service must not be a
 * child that dies with its console. DETACHED_PROCESS gives it no console at
 * all, which is what keeps the session alive after the operator detaches --
 * and is why cpty_win.c has to be explicit about std handles (see the comment
 * there; a console-less parent is exactly the case that breaks silently).
 */

#define ID_LEN 12			/* hex chars of the per-session id */

#define SVC_MAGIC "COMRADESVC1"

struct svc {
	struct token tok;
	char sock[512];
	char tokfile[512];
	char statusfile[512];
	int no_fwd;
	int no_mcast;
	int no_dht;
	struct session_obs obs;		/* view-event emitter to the foreground */
};

/* ---- paths ---- */

/*
 * Per-user runtime directory. The POSIX host puts this on tmpfs
 * ($XDG_RUNTIME_DIR, else /tmp/comrade-$uid) because the status file is
 * rewritten several times a second. %TEMP% is the Windows equivalent and is
 * already per-user and ACL'd to that user, which is the property that matters:
 * the tmux socket and the token file live here.
 */
static const char *state_dir(void)
{
	static char dir[512];

	if (!dir[0]) {
		snprintf(dir, sizeof(dir), "%s\\comrade", os_tmpdir());
		CreateDirectoryA(dir, NULL);
	}
	return dir;
}

static void sock_path(char *out, size_t n, const char *id)
{
	snprintf(out, n, "%s\\%s.sock", state_dir(), id);
}

static void tok_path(char *out, size_t n, const char *id)
{
	snprintf(out, n, "%s\\%s.tok", state_dir(), id);
}

static void status_path(char *out, size_t n, const char *id)
{
	snprintf(out, n, "%s\\%s.status", state_dir(), id);
}

static int gen_id(char *out)
{
	static const char hx[] = "0123456789abcdef";
	uint8_t rb[ID_LEN / 2];
	int i;

	if (random_bytes(rb, sizeof(rb)))
		return -1;
	for (i = 0; i < ID_LEN / 2; i++) {
		out[i * 2] = hx[rb[i] >> 4];
		out[i * 2 + 1] = hx[rb[i] & 0xf];
	}
	out[ID_LEN] = '\0';
	return 0;
}

/* ---- talking to tmux ---- */

static int tmux_alive(const char *sock)
{
	char *argv[] = { NULL, "-S", NULL, "has-session", "-t", "comrade",
			 NULL };

	argv[0] = (char *)tmux_path();
	argv[2] = (char *)sock;
	if (!argv[0])
		return 0;
	/* win_run puts the child's stderr on NUL, so a "no server" complaint
	 * stays as quiet as the POSIX side's /dev/null redirection. */
	return win_run(argv) == 0;
}

/*
 * The end-of-session monitor, unchanged in intent from the POSIX host:
 * `tmux wait-for <channel>` blocks until the server dies, because comrade
 * never signals that channel. On POSIX its exit is seen as EOF on a pipe; here
 * it is seen as a process HANDLE going signalled, which win_proc_exit_sock
 * turns into the same readable-then-EOF socket. Returns INVALID_SOCK if the
 * monitor could not be started, which only costs a slower end-of-session.
 */
static sock_t spawn_end_monitor(const char *sock)
{
	char *argv[] = { NULL, "-S", NULL, "wait-for", "comrade-session",
			 NULL };
	HANDLE h;

	argv[0] = (char *)tmux_path();
	argv[2] = (char *)sock;
	if (!argv[0])
		return INVALID_SOCK;
	h = win_spawn_detached(argv, NULL, 0);
	if (!h)
		return INVALID_SOCK;
	return win_proc_exit_sock(h);
}

/* The command the service serves, and the one the operator attaches with. */
static void attach_cmd(char *out, size_t n, const char *sock)
{
	snprintf(out, n, "tmux -S \"%s\" attach -t comrade", sock);
}

/* The read-only variant, served to a client that presents the read-only
 * secret: tmux's -r puts that client in view-only mode. */
static void attach_cmd_ro(char *out, size_t n, const char *sock)
{
	snprintf(out, n, "tmux -S \"%s\" attach -r -t comrade", sock);
}

/* ---- scanning the state directory ---- */

/*
 * Walk <state_dir>\*.sock, handing each session id to `fn`. opendir/readdir
 * with a fixed name shape, spelled FindFirstFile.
 */
static void each_session(void (*fn)(const char *id, void *arg), void *arg)
{
	WIN32_FIND_DATAA fd;
	HANDLE h;
	char pat[520];

	snprintf(pat, sizeof(pat), "%s\\*.sock", state_dir());
	h = FindFirstFileA(pat, &fd);
	if (h == INVALID_HANDLE_VALUE)
		return;
	do {
		char id[ID_LEN + 1];

		if (strlen(fd.cFileName) != ID_LEN + 5)
			continue;
		memcpy(id, fd.cFileName, ID_LEN);
		id[ID_LEN] = '\0';
		fn(id, arg);
	} while (FindNextFileA(h, &fd));
	FindClose(h);
}

static void sweep_one(const char *id, void *arg)
{
	char sock[512], other[512];

	(void)arg;
	sock_path(sock, sizeof(sock), id);
	if (tmux_alive(sock))
		return;				/* a live session: leave it */
	DeleteFileA(sock);
	tok_path(other, sizeof(other), id);
	DeleteFileA(other);
	status_path(other, sizeof(other), id);
	DeleteFileA(other);
}

/* Remove socket/token files whose tmux server is gone, so stale state from an
 * earlier run cannot linger or confuse a fresh start. */
static void sweep_stale(void)
{
	each_session(sweep_one, NULL);
}

struct live_scan {
	char id[ID_LEN + 1];
	ULONGLONG best;
	int found;
};

static void live_one(const char *id, void *arg)
{
	struct live_scan *s = arg;
	WIN32_FILE_ATTRIBUTE_DATA st;
	ULONGLONG t;
	char sock[512];

	sock_path(sock, sizeof(sock), id);
	if (!tmux_alive(sock))
		return;
	if (!GetFileAttributesExA(sock, GetFileExInfoStandard, &st))
		return;
	t = ((ULONGLONG)st.ftLastWriteTime.dwHighDateTime << 32) |
	    st.ftLastWriteTime.dwLowDateTime;
	if (t >= s->best) {
		s->best = t;
		memcpy(s->id, id, ID_LEN + 1);
		s->found = 1;
	}
}

/* Newest live session id into id[ID_LEN+1]; returns 1 if one was found. */
static int find_live(char *id)
{
	struct live_scan s;

	memset(&s, 0, sizeof(s));
	each_session(live_one, &s);
	if (s.found)
		memcpy(id, s.id, ID_LEN + 1);
	return s.found;
}

/* ---- the operator's local attach ---- */

/* Confine the terminal scroll region to the rows above the reserved status row
 * so nothing scrolling in the tmux area can push into it; on == 0 restores the
 * full-screen region. */
static void scroll_guard(int rows, int reserve, int on)
{
	char b[32];
	int n;

	if (!reserve)
		return;
	if (on)
		n = snprintf(b, sizeof(b), "\033[1;%dr", rows - 1);
	else
		n = snprintf(b, sizeof(b), "\033[r");
	if (n > 0)
		tty_write(b, (size_t)n);
}

/* No usable terminal to reserve a row on: just run tmux, inheriting our stdio,
 * and hand back its status. The POSIX host execs here; there is nothing to
 * exec into on Windows, so it waits instead -- same effect for the operator. */
static int run_tmux_plain(const char *sock)
{
	char *argv[] = { NULL, "-S", NULL, "attach", "-t", "comrade", NULL };

	argv[0] = (char *)tmux_path();
	argv[2] = (char *)sock;
	if (!argv[0]) {
		tmux_missing_help();
		return 1;
	}
	return os_spawn_wait(argv) == 0 ? 0 : 1;
}

/*
 * Attach the operator to the shared tmux, reserving the bottom terminal row
 * for comrade's own status line: run tmux on a pseudoconsole one row shorter
 * and paint the status (read from the service's file) on the freed row here,
 * so it stays live even while the link is down. Identical to the POSIX attach
 * except that the pty is a ConPTY, SIGWINCH is a polled size comparison, and
 * the console is bridged to a socket so one poll covers both directions.
 */
static int attach(const char *id)
{
	char sock[512], statuspath[512], cmd[600];
	struct cpty *child;
	struct tty_saved saved;
	struct termfilter tf;
	struct conn_status cur, prev;
	uint64_t last_paint = 0;
	sock_t kbd, out;
	int rows = 0, cols = 0, alive = 1;

	sock_path(sock, sizeof(sock), id);
	status_path(statuspath, sizeof(statuspath), id);
	attach_cmd(cmd, sizeof(cmd), sock);

	if (!tty_isatty_in() || !tty_isatty_out() || tty_size(&rows, &cols) ||
	    rows < 2)
		return run_tmux_plain(sock);

	/* Raw first: the console must be in VT mode before tmux paints, and the
	 * keyboard pump must not be handing us cooked lines. */
	if (tty_raw_on(&saved, 1))
		return run_tmux_plain(sock);

	dbg_logf("host attach: terminal rows=%d cols=%d -> tmux gets %d rows",
		 rows, cols, rows - 1);
	child = cpty_spawn(cmd, 1, rows - 1, cols, "xterm-256color");
	if (!child) {
		tty_raw_off(&saved);
		fprintf(stderr, "comrade: could not run tmux\n");
		return 1;
	}

	kbd = tty_sock_in();
	out = cpty_out(child);
	scroll_guard(rows, 1, 1);
	termfilter_init(&tf, 1);	/* keep tmux one row shorter than the tty */
	tty_resize_watch(1);
	memset(&prev, 0, sizeof(prev));

	while (alive) {
		struct pollfd fds[2];
		char buf[4096];
		nfds_t nfds = 1;
		uint64_t now;
		int n;

		fds[0].fd = out;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		fds[1].fd = kbd;
		fds[1].events = POLLIN;
		fds[1].revents = 0;
		if (sock_valid(kbd))
			nfds = 2;
		sock_poll(fds, nfds, 200);

		if (tty_resized() && !tty_size(&rows, &cols) && rows >= 2) {
			cpty_resize(child, rows - 1, cols);
			scroll_guard(rows, 1, 1);
			dbg_logf("host resize: rows=%d cols=%d -> tmux %d rows",
				 rows, cols, rows - 1);
			memset(&prev, 0, sizeof(prev));
		}
		if (nfds > 1 && (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
			n = (int)sock_read(kbd, buf, sizeof(buf));
			if (n > 0) {
				char fb[sizeof(buf) + sizeof(tf.pend)];
				size_t fn = termfilter_run(&tf, buf, (size_t)n,
							   fb);

				sock_write(cpty_in(child), fb, fn);
			}
		}
		if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
			n = (int)sock_read(out, buf, sizeof(buf));
			if (n > 0)
				tty_write(buf, (size_t)n);
			else if (n == 0 || !sock_err_would_block(sock_errno()))
				alive = 0;	/* tmux exited */
		}
		if (cpty_exited(child) && !(fds[0].revents & POLLIN))
			alive = 0;

		now = os_mono_ms();
		memset(&cur, 0, sizeof(cur));
		conn_read(statuspath, &cur);	/* zeroed = "connecting" if absent */
		if (memcmp(&cur, &prev, sizeof(cur)) || now - last_paint > 2000) {
			statusbar_render(rows, cols, &cur);
			prev = cur;
			last_paint = now;
		}
	}

	scroll_guard(rows, 1, 0);
	tty_resize_watch(0);
	cpty_close(child);
	tty_sock_release();
	tty_raw_off(&saved);
	return tmux_alive(sock) ? 2 : 0;
}

/* ---- the detached service ---- */

/* Encode the current token (and its read-only twin), write both to the token
 * file so the foreground can print them and `comrade show` can read them, and
 * emit them to the foreground view. Shared by the rendezvous and endpoint mints. */
static void svc_emit_token(struct svc *v)
{
	char tokbuf[TOKEN_STR_LEN + 1];
	char tokbuf_ro[TOKEN_STR_LEN + 1];
	struct token ro;
	FILE *f;

	if (token_encode(&v->tok, tokbuf, sizeof(tokbuf)))
		return;
	ro = v->tok;
	ro.flags |= TOKEN_FLAG_RO;
	keys_derive_ro_auth(ro.auth, v->tok.auth);
	if (token_encode(&ro, tokbuf_ro, sizeof(tokbuf_ro)))
		return;
	f = fopen(v->tokfile, "wb");
	if (f) {
		fprintf(f, "%s\n%s\n", tokbuf, tokbuf_ro);
		fclose(f);
	}
	ui_emitter_token(&v->obs, tokbuf);	/* show it in the foreground */
	ui_emitter_token_ro(&v->obs, tokbuf_ro);
}

/* Called (in the service) once the rendezvous is ready; embed the located DHT
 * node for the family (EPx_RDV set) and write the token. */
static void on_rendezvous(void *arg, const struct sockaddr *sa, socklen_t len)
{
	struct svc *v = arg;

	(void)len;
	if (sa && sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;

		memcpy(v->tok.ep6_addr, &a->sin6_addr, TOKEN_EP6_LEN);
		v->tok.ep6_port = ntohs(a->sin6_port);
		v->tok.flags |= TOKEN_FLAG_EP6_RDV;
	} else if (sa && sa->sa_family == AF_INET) {
		const struct sockaddr_in *a = (const struct sockaddr_in *)sa;

		memcpy(v->tok.ep4_addr, &a->sin_addr, TOKEN_EP4_LEN);
		v->tok.ep4_port = ntohs(a->sin_port);
		v->tok.flags |= TOKEN_FLAG_EP4_RDV;
	}
	svc_emit_token(v);
}

/* The isolated-LAN sibling of on_rendezvous: embed our own direct endpoint for
 * the family (EPx_RDV clear), which the client reaches over the LAN while it
 * keeps looking for the same host on the DHT. */
static void on_endpoint(void *arg, const struct sockaddr *sa, socklen_t len)
{
	struct svc *v = arg;

	(void)len;
	if (sa && sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;

		memcpy(v->tok.ep6_addr, &a->sin6_addr, TOKEN_EP6_LEN);
		v->tok.ep6_port = ntohs(a->sin6_port);
		v->tok.flags &= ~TOKEN_FLAG_EP6_RDV;
	} else if (sa && sa->sa_family == AF_INET) {
		const struct sockaddr_in *a = (const struct sockaddr_in *)sa;

		memcpy(v->tok.ep4_addr, &a->sin_addr, TOKEN_EP4_LEN);
		v->tok.ep4_port = ntohs(a->sin_port);
		v->tok.flags &= ~TOKEN_FLAG_EP4_RDV;
	}
	svc_emit_token(v);
}

/* Serve the shared tmux over the punched link, again after each client, until
 * the tmux server is gone. Runs in the detached process; never returns. */
static void run_service(struct svc *v, void *hostkey, sock_t wfd)
{
	char cmd[600];
	char cmd_ro[600];
	struct session_cfg cfg;
	sock_t end_fd;

	attach_cmd(cmd, sizeof(cmd), v->sock);
	attach_cmd_ro(cmd_ro, sizeof(cmd_ro), v->sock);
	end_fd = spawn_end_monitor(v->sock);

	ui_emitter(&v->obs, wfd);	/* progress -> the foreground view */

	memset(&cfg, 0, sizeof(cfg));
	cfg.is_host = 1;
	cfg.tok = v->tok;
	cfg.sig_flags = (v->no_dht ? 0 : SIG_DHT) | (v->no_mcast ? 0 : SIG_MCAST);
	cfg.stun_port = 3478;
	cfg.stun_auto = 1;
	cfg.log_level = -1;
	cfg.connect_timeout_s = 60;
	cfg.hostkey = hostkey;
	cfg.ssh_command = cmd;
	cfg.ssh_command_ro = cmd_ro;
	cfg.use_pty = 1;
	cfg.ssh_end_fd = sock_isset(end_fd) ? end_fd : 0;
	cfg.no_fwd = v->no_fwd;
	cfg.status_path = v->statusfile;
	cfg.on_rendezvous = on_rendezvous;
	cfg.on_endpoint = on_endpoint;
	cfg.arg = v;
	cfg.obs = &v->obs;

	while (tmux_alive(v->sock)) {
		cfg.tok = v->tok;	/* carry the located anchor forward, so the
					 * next idle attempt reinforces it rather
					 * than locating (and churning) a new one */
		session_run(&cfg);
	}
	if (sock_isset(end_fd))
		sock_close(end_fd);
	DeleteFileA(v->tokfile);
	DeleteFileA(v->statusfile);
	exit(0);
}

/* ---- the operator -> service handover ---- */

static const char hexd[] = "0123456789abcdef";

static void hex_encode(const void *in, size_t len, char *out)
{
	const unsigned char *p = in;
	size_t i;

	for (i = 0; i < len; i++) {
		out[i * 2] = hexd[p[i] >> 4];
		out[i * 2 + 1] = hexd[p[i] & 0xf];
	}
	out[len * 2] = '\0';
}

static int hex_decode(const char *in, void *out, size_t len)
{
	unsigned char *p = out;
	size_t i;

	for (i = 0; i < len; i++) {
		const char *h = strchr(hexd, in[i * 2]);
		const char *l = in[i * 2] ? strchr(hexd, in[i * 2 + 1]) : NULL;

		if (!h || !l)
			return -1;
		p[i] = (unsigned char)(((h - hexd) << 4) | (l - hexd));
	}
	return 0;
}

/*
 * The handover blob: plain text, one key per line, so a hexdump of the socket
 * during debugging is readable and the parser is a strcmp. Everything secret
 * in it (the token's R and A, the SSH private key) exists only in the two
 * processes' memory and in the kernel's loopback buffer -- never on disk,
 * which is the property the POSIX fork gives for free.
 */
static int send_state(sock_t s, const struct svc *v, void *hostkey)
{
	char *b64 = NULL;
	char *blob;
	size_t cap;
	int n, rc = -1;

	if (ssh_pki_export_privkey_base64((ssh_key)hostkey, NULL, NULL, NULL,
					  &b64) != SSH_OK || !b64)
		return -1;
	cap = strlen(b64) * 2 + sizeof(struct token) * 2 + 2048;
	blob = malloc(cap);
	if (!blob)
		goto out;
	n = snprintf(blob, cap, "%s\nsock %s\ntok %s\nstatus %s\n"
		     "nofwd %d\nnomcast %d\nnodht %d\ntoken ", SVC_MAGIC,
		     v->sock, v->tokfile, v->statusfile, v->no_fwd,
		     v->no_mcast, v->no_dht);
	if (n < 0 || (size_t)n >= cap)
		goto out;
	hex_encode(&v->tok, sizeof(v->tok), blob + n);
	n += (int)sizeof(v->tok) * 2;
	blob[n++] = '\n';
	n += snprintf(blob + n, cap - (size_t)n, "key ");
	hex_encode(b64, strlen(b64), blob + n);
	n += (int)strlen(b64) * 2;
	n += snprintf(blob + n, cap - (size_t)n, "\nend\n");

	{
		int off = 0;

		while (off < n) {
			ssize_t w = sock_write(s, blob + off, (size_t)(n - off));

			if (w <= 0)
				goto out;
			off += (int)w;
		}
	}
	rc = 0;
out:
	free(blob);
	ssh_string_free_char(b64);
	return rc;
}

/* Read the blob back in the service. Returns the host key, or NULL. */
static void *recv_state(sock_t s, struct svc *v)
{
	char *blob, *line, *next;
	size_t cap = 65536, got = 0;
	ssh_key key = NULL;
	char *keyhex = NULL;

	blob = malloc(cap);
	if (!blob)
		return NULL;
	for (;;) {
		ssize_t n = sock_read(s, blob + got, cap - 1 - got);

		if (n <= 0)
			goto out;
		got += (size_t)n;
		blob[got] = '\0';
		if (strstr(blob, "\nend\n"))
			break;
		if (got >= cap - 1)
			goto out;
	}
	if (strncmp(blob, SVC_MAGIC "\n", strlen(SVC_MAGIC) + 1))
		goto out;

	for (line = blob; line && *line; line = next) {
		next = strchr(line, '\n');
		if (next)
			*next++ = '\0';
		if (!strncmp(line, "sock ", 5))
			snprintf(v->sock, sizeof(v->sock), "%s", line + 5);
		else if (!strncmp(line, "tok ", 4))
			snprintf(v->tokfile, sizeof(v->tokfile), "%s", line + 4);
		else if (!strncmp(line, "status ", 7))
			snprintf(v->statusfile, sizeof(v->statusfile), "%s",
				 line + 7);
		else if (!strncmp(line, "nofwd ", 6))
			v->no_fwd = atoi(line + 6);
		else if (!strncmp(line, "nomcast ", 8))
			v->no_mcast = atoi(line + 8);
		else if (!strncmp(line, "nodht ", 6))
			v->no_dht = atoi(line + 6);
		else if (!strncmp(line, "token ", 6)) {
			if (strlen(line + 6) < sizeof(v->tok) * 2 ||
			    hex_decode(line + 6, &v->tok, sizeof(v->tok)))
				goto out;
		} else if (!strncmp(line, "key ", 4))
			keyhex = line + 4;
	}
	if (keyhex) {
		size_t kl = strlen(keyhex) / 2;
		char *pem = malloc(kl + 1);

		if (pem && !hex_decode(keyhex, pem, kl)) {
			pem[kl] = '\0';
			if (ssh_pki_import_privkey_base64(pem, NULL, NULL, NULL,
							  &key) != SSH_OK)
				key = NULL;
		}
		free(pem);
	}
out:
	free(blob);
	return key;
}

/*
 * Service entry point: `comrade --win-service <socket handle>`, spawned
 * detached by the operator's process. The argument is the numeric value of an
 * inherited socket handle -- inherited handles keep their value across
 * CreateProcess, and a socket is usable in the child once WSAStartup has run,
 * which main() does before anything else.
 */
int host_win_service(const char *handle_arg)
{
	struct svc v;
	void *hostkey;
	sock_t ctrl = (sock_t)(UINT_PTR)_strtoui64(handle_arg, NULL, 10);

	memset(&v, 0, sizeof(v));
	if (!sock_isset(ctrl))
		return 1;
	hostkey = recv_state(ctrl, &v);
	if (!hostkey) {
		sock_close(ctrl);
		return 1;
	}
	dbg_logf("host service: serving %s", v.sock);
	run_service(&v, hostkey, ctrl);		/* never returns */
	return 0;
}

/* Abort path: stop the detached service and drop its tmux session and state. */
static void teardown(HANDLE svc, const char *sock, const char *tokfile)
{
	char *k[] = { NULL, "-S", NULL, "kill-server", NULL };

	if (svc) {
		TerminateProcess(svc, 0);
		WaitForSingleObject(svc, 3000);
		CloseHandle(svc);
	}
	k[0] = (char *)tmux_path();
	k[2] = (char *)sock;
	if (k[0])
		win_run(k);
	DeleteFileA(tokfile);
	DeleteFileA(sock);
}

/* Absolute path to this comrade.exe, for re-running it as the service. */
static const char *self_path(void)
{
	static char p[MAX_PATH];

	if (!p[0] && !GetModuleFileNameA(NULL, p, sizeof(p)))
		p[0] = '\0';
	return p;
}

/*
 * Make sure the session leaves a directory entry behind.
 *
 * The native (winget) tmux does not create a socket *file*: it turns
 * `-S <path>` into a named pipe, \\.\pipe\<path>, and never touches the
 * filesystem. Everything that talks to that server still works, because the
 * path is only a name -- but comrade finds its own sessions by listing
 * <state_dir>\*.sock, so with no entry `comrade show` reports no session and a
 * second `comrade` starts a second session instead of re-attaching.
 *
 * So create the entry if tmux did not. It must happen *after* tmux has bound,
 * never before: MSYS2's tmux really does bind an AF_UNIX socket there and a
 * pre-existing regular file would stop it. Sweeping deletes it as before, and
 * its mtime is what find_live() orders sessions by.
 */
static void mark_sock(const char *sock)
{
	HANDLE h;

	if (GetFileAttributesA(sock) != INVALID_FILE_ATTRIBUTES)
		return;			/* a Cygwin tmux made a real one */
	h = CreateFileA(sock, GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h != INVALID_HANDLE_VALUE)
		CloseHandle(h);
}

static int start_tmux(const struct svc *v)
{
	char *mk[] = { NULL, "-S", NULL, "new-session", "-d", "-s", "comrade",
		       ";", "set", "-g", "status-position", "top",
		       ";", "set", "-g", "window-size", "smallest", NULL };
	char err[256];

	mk[0] = (char *)tmux_path();
	mk[2] = (char *)v->sock;
	if (win_run_capture(mk, err, sizeof(err))) {
		if (err[0])
			fprintf(stderr, "comrade: could not start tmux: %s\n",
				err);
		else
			fprintf(stderr, "comrade: could not start tmux (%s)\n",
				mk[0]);
		return -1;
	}
	mark_sock(v->sock);
	return 0;
}

static int start_new(int ui_mode, int no_mcast, int no_dht, int no_fwd)
{
	struct svc v;
	char id[ID_LEN + 1], hnum[32];
	char *argv[4];
	void *hostkey;
	struct ui *ui;
	HANDLE proc;
	sock_t sv[2];
	int enter, rc = 0;

	if (!tmux_path() && !tmux_offer_install()) {
		tmux_missing_help();
		return 1;
	}

	memset(&v, 0, sizeof(v));
	v.no_fwd = no_fwd;
	v.no_mcast = no_mcast;
	v.no_dht = no_dht;
	if (gen_id(id)) {
		fprintf(stderr, "comrade: random generation failed\n");
		return 1;
	}
	sock_path(v.sock, sizeof(v.sock), id);
	tok_path(v.tokfile, sizeof(v.tokfile), id);
	status_path(v.statusfile, sizeof(v.statusfile), id);

	v.tok.version = TOKEN_VERSION;
	hostkey = sshd_hostkey_new(v.tok.hostpub);
	if (!hostkey) {
		fprintf(stderr, "comrade: host key generation failed\n");
		return 1;
	}
	if (random_bytes(v.tok.rdv, TOKEN_RDV_LEN) ||
	    random_bytes(v.tok.auth, TOKEN_AUTH_LEN)) {
		fprintf(stderr, "comrade: random generation failed\n");
		sshd_hostkey_free(hostkey);
		return 1;
	}

	if (start_tmux(&v)) {
		sshd_hostkey_free(hostkey);
		return 1;
	}

	/*
	 * The operator/service channel. Inherited by exactly this handle (see
	 * win_spawn_detached), so nothing else in the process leaks into a
	 * service that outlives the terminal.
	 */
	if (sock_pair(sv)) {
		fprintf(stderr, "comrade: could not open the service channel\n");
		sshd_hostkey_free(hostkey);
		return 1;
	}
	snprintf(hnum, sizeof(hnum), "%llu", (unsigned long long)sv[1]);
	argv[0] = (char *)self_path();
	argv[1] = "--win-service";
	argv[2] = hnum;
	argv[3] = NULL;
	proc = win_spawn_detached(argv, (HANDLE *)&sv[1], 1);
	if (!proc) {
		fprintf(stderr, "comrade: could not start the session service\n");
		sock_close(sv[0]);
		sock_close(sv[1]);
		sshd_hostkey_free(hostkey);
		return 1;
	}
	sock_close(sv[1]);			/* the service owns its copy */

	if (send_state(sv[0], &v, hostkey)) {
		fprintf(stderr, "comrade: could not hand the session to the "
			"service\n");
		teardown(proc, v.sock, v.tokfile);
		sock_close(sv[0]);
		sshd_hostkey_free(hostkey);
		return 1;
	}
	sshd_hostkey_free(hostkey);		/* the service has its own copy */

	/* The view renders the service's progress and blocks until the operator
	 * enters (1, playing the zap), aborts (-1), or the service exits (0). A
	 * detach (attach() returns 2, session still alive) loops back to the
	 * dashboard instead of leaving it. */
	ui = ui_create(UI_ROLE_HOST, ui_mode);
	for (;;) {
		enter = ui ? ui_host_wait(ui, sv[0]) : 0;
		if (enter != 1)
			break;
		rc = attach(id);
		if (rc != 2)
			break;
	}
	ui_destroy(ui);
	sock_close(sv[0]);

	if (enter == 1) {
		CloseHandle(proc);
		return rc;
	}
	if (enter < 0) {			/* operator aborted */
		teardown(proc, v.sock, v.tokfile);
		fprintf(stderr, "comrade: aborted.\n");
		return 0;
	}
	CloseHandle(proc);
	fprintf(stderr, "comrade: session ended before you entered "
		"(token: `comrade show`)\n");
	return 1;
}

int host_run(int ui_mode, int no_mcast, int no_dht, int no_fwd)
{
	char id[ID_LEN + 1];
	int rc;

	sweep_stale();
	if (find_live(id)) {
		fprintf(stderr, "comrade: re-attaching to your running session"
			" (its token: `comrade show`)\n");
		do {
			rc = attach(id);
		} while (rc == 2);
		return rc;
	}
	return start_new(ui_mode, no_mcast, no_dht, no_fwd);
}

static void show_one(const char *id, void *arg)
{
	int *shown = arg;
	char sock[512], tf[512], tok[TOKEN_STR_LEN + 8];
	FILE *f;
	int ln = 0;

	sock_path(sock, sizeof(sock), id);
	if (!tmux_alive(sock))
		return;
	tok_path(tf, sizeof(tf), id);
	f = fopen(tf, "r");
	if (!f)
		return;
	while (fgets(tok, sizeof(tok), f)) {
		printf("%s%s", ln ? "read-only   " : "read-write  ", tok);
		*shown = 1;
		ln++;
	}
	fclose(f);
}

int host_show(void)
{
	int shown = 0;

	each_session(show_one, &shown);
	if (!shown) {
		fprintf(stderr, "comrade: no running session\n");
		return 1;
	}
	return 0;
}

#endif /* _WIN32 */
