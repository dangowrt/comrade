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
(exit 2). Sessions with a pidfile (every headless session) are never
adopted by an interactive `comrade`, so a supervisor's session and an
operator's shell session cannot collide; both appear in `show`.

`--expire SECONDS` ends the session after that long, whatever happens:
a root-shell grant handed out by QR code should be temporary by
construction. `--max-clients N` bounds the grant: at most N claimants
are ever admitted (a reconnecting admitted client does not count), and
once they are gone the session ends -- with `--max-clients 1`, a leaked
QR code is inert the moment the intended helper has joined. The
configured bounds appear in the state document as `expire_s` and
`max_clients` (static values; the countdown is the supervisor's
arithmetic, and expiry itself shows up as the session ending).

Exit codes: 0 the session ended or was stopped, 1 an internal failure,
2 a bad or already-running `--id`, 3 a startup failure -- the state
file then carries `"state":"error"` and a stable `"error"` enum (today:
`no_tmux`), so a UI can say what is wrong. On clean exit the state file
is removed: a stopped session is an absent document.

    comrade stop [--id NAME]

Ends a session, completely: the tmux server is killed first, which
closes every attached client's channel through the end monitor, then
the service gets SIGTERM and `stop` waits (up to ~3 s) for it to exit
before returning -- when it returns, access has ended and the state
file is gone. A client still holding the token has nothing left to
join: the mailbox offer it might read has no live host behind it.
Idempotent: exit 0 when nothing was running. Without `--id` it acts on
the single live session and refuses (exit 1) when there are several.

    comrade capture [--id NAME] [--ansi]

Prints the shared terminal's current contents (tmux capture-pane) to
stdout; `--ansi` keeps the colour escapes. For read-only surfaces such
as a web page's session preview, polled alongside the state file.

## The state directory

`$COMRADE_STATE_DIR` when set, else `$XDG_RUNTIME_DIR/comrade`, else
`/tmp/comrade-$UID`. The directory is 0700, files 0600 -- state files
carry tokens, and a read-write token is a shell credential. On OpenWrt
set `COMRADE_STATE_DIR=/var/run/comrade` in the init script.

For `--id NAME` the paths are exactly:

    $DIR/NAME.json      the session document (the poll target)
    $DIR/NAME.pid       the service pid
    $DIR/NAME.sock      the shared tmux server's socket
    $DIR/NAME.tok       both tokens, read-write then read-only, one per line
    $DIR/NAME.status    connection status for comrade's own status row

## The session document (schema 1)

    {
      "schema": 1,
      "id": "remoteassist",
      "pid": 1234,
      "state": "serving",
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

- `state`: `starting` | `rendezvous` (locating nodes; joining already
  works via a full DHT warm-up) | `ready` (a rendezvous is in the token)
  | `serving` (at least one connected peer) | `error`.
- `error`: present with `state=error`; stable enum, today `no_tmux`.
- `token_ro` is omitted entirely when the session mints none, never an
  empty string.
- `reach.*.state`: `ready` | `pending` | `none`; `kind` (`rendezvous` |
  `direct`) with `addr`/`port` accompany `ready`.
- `peers[].state`: `seen` | `punching` | `connected` (gone peers leave
  the list); `grade`: `rw` | `ro` -- which token the peer presented.
- `warning`: the current operator-facing warning, cleared when the
  condition passes. Advisory prose beside the machine state, never the
  only carrier of one.

`comrade show --json` embeds headless sessions' documents verbatim in
`sessions[]`; interactive sessions get a reduced document derived from
the token (no `pid`, `state`, `peers`).

## Events (headless stdout)

One JSON object per line. Every event carries the resulting `"state"`.

    {"event":"started","state":"starting"}
    {"event":"token","token":"...","token_ro":"...","state":"rendezvous"}
    {"event":"peer","peer":{"id":1,"peer_state":"connected","grade":"rw",
     "addr":"..."},"state":"serving"}
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
