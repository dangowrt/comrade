# Driving comrade from other software

comrade's machine interface: everything a supervisor (an init system, an
rpcd plugin, a web UI) needs to run a host session without a terminal, and
everything a script or an assistive tool needs to get hold of a token
without scraping a screen. The JSON here is a versioned contract: the
`schema` integer is bumped only on an incompatible change, and additive
fields never bump it. All enums are stable ASCII; human-readable text
appears only beside them, never instead of them. Durations are relative
seconds, never wall-clock timestamps.

## Getting tokens (any session)

    comrade show                print both tokens, human-formatted
    comrade show --token        the read-write token, bare, one line
    comrade show --token-ro     the read-only token, bare, one line
    comrade show --json         every live session, machine-readable

The bare-token forms exist for scripts and for accessibility: pipe into
`wl-copy`/`xclip`, or read linearly with a screen reader. They require
exactly one live session (exit 1 otherwise, with a hint on stderr).
`show --json` prints `{"schema":1,"sessions":[...]}` where each element
is a session document (below); with no sessions it prints an empty list
and exits 0.

## Headless hosting

    comrade --headless [--id NAME] [--expire SECONDS] [--max-clients N]
                       [--no-multicast|--no-dht|--no-forwarding]

Runs the host service in the calling process's foreground: no tty, no
dashboard -- what procd and systemd want. On stdout it emits one JSON
event line per state change (see Events); stderr carries diagnostics.
It also maintains the session document as a state file, rewritten via a
temporary name and rename(2) so a reader never sees a partial document.
Supervisors poll that file; no exec is needed on the poll path.

`--id NAME` (a-z A-Z 0-9 `-` `_`, at most 32 chars) makes every path
deterministic. A named session that is already running is refused
(exit 2).

Headless is the one host that is meant to outlive the process that
started it, and it is the exception to comrade's own lifecycle rule: an
interactive `comrade` ends its session the moment the operator leaves
the terminal, so nothing is ever hosting in the background unnoticed.
A headless session is a supervisor's, and is owned by whatever started
it -- it runs until `stop`, `--expire`, or its grant is spent. The two
never collide: a headless session is the one with a pidfile, an
interactive `comrade` never touches one, and both appear in `show`.

`--expire SECONDS` ends the session after that long, whatever happens:
a root-shell grant handed out by QR code should be temporary by
construction. `--max-clients N` bounds the grant: at most N claimants
are ever admitted (a reconnecting admitted client does not count), and
once they are gone the session ends -- with `--max-clients 1`, a leaked
QR code is inert the moment the intended helper has joined. The
configured bounds appear in the state document as `expire_s` and
`max_clients` (static values; the countdown is the supervisor's
arithmetic, and expiry itself shows up as the session ending).

`--forward-only` (with `--headless`) serves no shell at all: no tmux is
started (and none need be installed), the primary SSH channel is an
inert keepalive, and only the control plane and `-L`/`-R` port
forwarding run. This is the "no terminal" host. `comrade capture` and
`comrade attach` report such a session as forwarding-only rather than
showing a pane. A client joins a forward-only host -- or any host, to
forward without a shell -- with `comrade <token> -N -L... -R...`, the
OpenSSH spelling: no shell is requested, only the forwards.

Exit codes: 0 the session ended or was stopped, 1 an internal failure,
2 a bad or already-running `--id`, 3 a startup failure -- the state
file then carries `"state":"error"` and a stable `"error"` enum (today:
`no_tmux`), so a UI can say what is wrong. On clean exit the state file
is removed: a stopped session is an absent document.

An error document persists so the failure stays explainable: the next
`--headless` with the same `--id` overwrites it, and any comrade
invocation that sweeps stale state collects it. Since the pidfile is
only written once startup has succeeded, an error document with no
`NAME.pid` beside it reads as "failed, not running now" rather than
"failing".

    comrade stop [--id NAME]

Ends any session, interactive or headless, completely: the tmux server
is killed first, which closes every attached client's channel through
the end monitor, and `stop` then waits for the service to finish going
-- a headless one on SIGTERM (~3 s), an interactive one on its own,
watched by its token file disappearing (~6 s). When `stop` returns,
access has ended and the state file is gone. A client still holding the
token is told so rather than left waiting: the service replaces the
mailbox offer with a tombstone on its way out (PROTOCOL.md §4.1), so a
join attempt fails with an error in a few seconds. Idempotent: exit 0
when nothing was running. Without `--id` it acts on the single live
session and refuses (exit 1) when there are several.

    comrade capture [--id NAME] [--ansi]

Prints the shared terminal's current contents (tmux capture-pane) to
stdout; `--ansi` keeps the colour escapes. For read-only surfaces such
as a web page's session preview, polled alongside the state file. A
forward-only session has no terminal, so this reports it as such.

    comrade attach [--id NAME] [-r]

Execs `tmux attach` for the session, taking over the process: a web
front end spawns this on a PTY and wires its websocket to it, without
hard-coding the tmux socket path or session name. `-r` attaches
read-only. Fails on a forward-only session (no terminal).

## The state directory

`$COMRADE_STATE_DIR` overrides everything. Otherwise **root is pinned to
`/var/run/comrade`** regardless of `$XDG_RUNTIME_DIR`, and a non-root user
gets `$XDG_RUNTIME_DIR/comrade`, else `/tmp/comrade-$UID`. The directory
is 0700, files 0600 -- state files carry tokens, and a read-write token
is a shell credential.

The root pin is deliberate and load-bearing: comrade has exactly two
entry points -- an operator at a console and a supervisor such as
luci-app-remoteassist -- and they must resolve to the same directory
with no configuration, or a grant made through one is invisible (and so
un-stoppable) through the other. The console is exactly where an
operator goes to end a stranger's shell when the web UI is unreachable,
so that must never depend on which door the session came in by. A fixed
path is also the only thing an ACL can name literally, so an ACL points
at `/var/run/comrade/<id>.json` directly. Do not set `COMRADE_STATE_DIR`
for root; let both entry points take the default. (`/var` is a symlink
to `/tmp` on OpenWrt and `/run` elsewhere, so the path is tmpfs either
way -- correct for session state, which must not survive a reboot.)

comrade ships no init script and is never a system service: a session
is started by an operator or by a supervisor's transient procd instance,
so nothing lives in `/etc` and no grant survives a reboot.

For `--id NAME` the paths are exactly:

    $DIR/NAME.json      the session document (the poll target)
    $DIR/NAME.pid       the service pid
    $DIR/NAME.sock      the shared tmux server's socket
    $DIR/NAME.tok       both tokens, read-write then read-only, one per line
    $DIR/NAME.status    connection status for comrade's own status row

An interactive session has no `.json` and no `.pid` -- it belongs to an
operator, not a supervisor -- and carries `NAME.svc` instead, naming its
connection service while that runs. The two files answer different
questions and are not interchangeable: `.pid` says a session is a
supervisor's, `.svc` says the service behind a shared tmux is still
alive, which is what tells a session somebody is hosting from a tmux
server left standing by a service that was killed outright.

## The session document (schema 1)

    {
      "schema": 1,
      "id": "remoteassist",
      "pid": 1234,
      "state": "serving",
      "doc_uptime_s": 4821.7,
      "expire_s": 1800,
      "expires_in_s": 1523,
      "sandbox": {"mask": 315,
                  "layers": ["userns", "mountns", "seccomp", "caps",
                             "nonewprivs", "nodump"],
                  "filter_insns": 74},
      "token": "112F...",
      "token_ro": "112F...",
      "reach": {
        "v4": {"state": "ready", "kind": "rendezvous",
               "addr": "192.0.2.7", "port": 6881},
        "v6": {"state": "none"}
      },
      "tmux": {"socket": "/var/run/comrade/remoteassist.sock",
               "session": "comrade"},
      "peers": [
        {"id": 1, "state": "connected", "grade": "rw",
         "addr": "198.51.100.4:41641"}
      ],
      "warning": "..."
    }

- `doc_uptime_s`: seconds since boot (`/proc/uptime`'s clock) at the
  moment the document was written. Every relative duration in the
  document ages from that instant: a stateless reader computes
  `remaining = expires_in_s - (uptime_now - doc_uptime_s)` with its own
  `/proc/uptime`, immune to stepped wall clocks and its own restarts.
- `expire_s` / `expires_in_s`: with `--expire` only -- the configured
  bound, and the remainder as of `doc_uptime_s`.
- `state`: `starting` | `rendezvous` (locating nodes; joining already
  works via a full DHT warm-up) | `ready` (a rendezvous is in the token)
  | `serving` (at least one connected peer) | `error`.
- `error`: present with `state=error`; stable enum, today `no_tmux`.
- `sandbox`: what comrade's self-confinement engaged in this service
  process. `mask` is the layer bitmask (`src/sandbox.h`), `layers` the
  same set by stable name -- `userns`, `mountns`, `landlock`, `seccomp`,
  `caps`, `nonewprivs`, `mdwe`, `rlimit`, `nodump`, `job`, `mitigation`,
  in that bit order, with a bit this comrade has no name for appearing as
  `bitN` -- and `filter_insns` the length of the syscall filter that
  installed, in BPF instructions, present only where the platform compiles
  one and the kernel took it. `"mask": 0` with an empty `layers` is the
  answer that matters most: nothing was applied, because
  `COMRADE_SANDBOX=0` is set or because the kernel offers none of it.
  Every layer is best-effort by design, so a short list is a fact about
  the machine rather than an error. Absent until the confinement has been
  applied (a document written before that, an error document from a
  failed start, and the reduced document an interactive session gets).
- `token_ro` is omitted entirely when the session mints none, never an
  empty string.
- `reach.*.state`: `ready` | `pending` | `none`; `kind` (`rendezvous` |
  `direct`) with `addr`/`port` accompany `ready`.
- `peers[].state`: `seen` | `punching` | `connected` (gone peers leave
  the list); `grade`: `rw` | `ro` -- which token the peer presented.
- `peers[].forward_refused`: `true` once a peer's `-L`/`-R` attempt was
  declined (the host runs `--no-forwarding`, or the peer is read-only --
  a read-only grade never gets a tunnel, since a tunnel into the host's
  LAN is more capability than the shell it withholds). Absent otherwise.
- `warning`: the current operator-facing warning, cleared when the
  condition passes. Advisory prose beside the machine state, never the
  only carrier of one.

`comrade show --json` embeds headless sessions' documents verbatim in
`sessions[]`; interactive sessions get a reduced document derived from
the token (no `pid`, `state`, `peers`).

## Events (headless stdout)

One JSON object per line. Every event carries the resulting `"state"`.

    {"event":"started","state":"starting"}
    {"event":"sandbox","sandbox":{"mask":315,"layers":["..."],
     "filter_insns":74},"state":"starting"}
    {"event":"token","token":"...","token_ro":"...","state":"rendezvous"}
    {"event":"peer","peer":{"id":1,"peer_state":"connected","grade":"rw",
     "addr":"..."},"state":"serving"}
    {"event":"forward_refused","peer":{"id":1,"peer_state":"connected",
     "grade":"ro","forward_refused":true},"state":"serving"}
    {"event":"warning","warning":"...","state":"ready"}
    {"event":"warning_cleared","state":"ready"}
    {"event":"error","state":"error"}
    {"event":"stopped","state":"..."}

Under procd, point stdout at logd and the system log becomes a session
audit trail.

## Accessibility at the terminal

- `--plain`: log lines with no colour, no spinner, every fact a complete
  sentence -- the screen-reader mode. `NO_COLOR` (any non-empty value)
  strips colour from every mode without changing layout.
- On the host dashboard, `c` copies the read-write token (in the QR
  views, the token shown) and `C` the read-only token to the system
  clipboard via OSC 52, which works across SSH; the footer confirms it.
- `comrade show --token` is the zero-interaction path to the same thing.

## What a QR code carries

Every comrade QR -- the terminal's and any UI's -- encodes exactly
`comrade:<token>`. That is a URL: a URI in the `comrade` scheme, which a
device acts on through a registered handler rather than by fetching it
over the network. This is contractual: an `http`/`https` join URL is a
different scheme and is not planned (it would need comrade compiled to
WebAssembly and protocol changes of the BitTorrent-vs-WebTorrent kind),
so nothing should mint one.
