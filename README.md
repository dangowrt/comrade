```
 ______ _______ _______ ______ _______ _____  _______
|      |       |   |   |   __ \   _   |     \|    ___|
|   ---|   -   |       |      <       |  --  |    ___|
|______|_______|__|_|__|___|__|___|___|_____/|_______|

                 no server. no relay.
                    just peers.
```

# comrade

**Peer-to-peer terminal sharing without a relay.**

Share a tmux session with another machine using a short-lived token. No
account, no central comrade service, and no relay carrying the session:
peers rendezvous, establish a direct connection when possible, and talk
SSH.

IPv6 is preferred; IPv4 uses NAT traversal. On an isolated LAN with no
internet, peers discover each other over link-local multicast, the host
mints a token, and the session runs over a direct link-local transport,
on Linux, macOS and Windows. The host keeps the session, clients join
it, and SSH port forwarding is available on the same connection.

Think of comrade as tmate without the relay. The host shares a tmux
session, but the peers establish their own connection rather than
sending the terminal through a tmate service.

## why

- **no account.** Give someone a session token instead of provisioning
  an account.
- **no relay.** The terminal session is carried directly between peers
  when connectivity allows it.
- **no server to operate.** Rendezvous rides public infrastructure;
  there is no comrade server to run, authenticate with, or trust with
  your terminal traffic.
- **ssh underneath.** The session is an authenticated SSH connection
  around an ordinary tmux session.
- **temporary by default.** Every session mints a fresh token, useless
  once the session has ended.
- **small enough for routers.** Plain C and OpenWrt support suit
  machines where a large runtime or service stack is unwelcome.

Sometimes you just want to connect two machines. Give someone the token
and let the machines find each other.

## quick start

Host a session:

    comrade

A dashboard shows the session tokens -- a read-write one and a read-only
twin -- to hand to your peers over any channel you trust, and the peers
as they arrive. ENTER drops you into the shared tmux session, and
detaching that tmux brings the dashboard back, so you can step in and
out for as long as the session lasts. `comrade show` prints the tokens
of a running session from another terminal.

ESC leaves the dashboard, and leaving the dashboard ends the session.
comrade never keeps hosting in the background: when the shell you
started it from gets its prompt back, there is nothing left running and
no way back into that session -- so a machine is never quietly still
being shared. That holds however you leave, including closing the
terminal or killing comrade outright, and `comrade stop` ends a session
from elsewhere. The session also ends when the last shell in it exits,
on whichever side; a client detaching or dropping never ends it.

Join one from anywhere, in the same tmux session:

    comrade <token>

The read-write token joins read-write; the read-only token joins the
same session view-only, unable to type into it. Which one you were handed
decides it; there is no extra flag.

Joining is the other way round from hosting: detaching there behaves
like detaching from a local tmux -- you drop back to your own shell, the
shared session carries on without you, and comrade prints the command to
rejoin. If the host's session has ended instead, comrade says so and
offers no way back. A guest who was in it is told over its own
connection; anyone presenting the token afterwards is told by the note
the host leaves on the DHT rendezvous, so a spent token fails in a few
seconds rather than hanging on a host that will never answer. On an
isolated LAN there is nowhere to leave that note -- discovery there only
exists while somebody is talking -- so a token whose host has gone
simply finds nobody, exactly as one whose host has not started yet
does.

`-v` swaps the dashboard for plain log lines on either side.
`--no-multicast` skips link-local discovery to force the DHT/STUN path,
and `--no-dht` declines the DHT so peers meet over link-local discovery
alone. Both work on either side, and each is that operator's own choice:
a token never switches a transport off for the other end. Giving both at
once is refused, since it would leave nothing to meet on. They are
properties of the session being started, and a session lasts exactly as
long as the terminal that started it, so there is never a running one to
give them to a second time.

A host on an isolated LAN reaches no DHT, so its mailbox is published
nowhere and its token carries no rendezvous node. Joining such a host
with `--no-multicast` cannot connect: the client searches a DHT the host
never reached, and sends none of the sealed multicast announcements the
host needs to authenticate it and spawn its worker. On a LAN with no
internet, `--no-dht` at both ends skips that fruitless search.

Already connected? Ordinary SSH `-L` and `-R` tunnel TCP services
through the same authenticated session, and can be repeated:

    comrade -L 8080:127.0.0.1:80 -R 2222:127.0.0.1:22 <token>

`-L [bind:]port:host:hostport` listens here and connects from the host;
`-R [bind:]port:host:hostport` listens on the host and connects from
here. The bind address defaults to loopback, `*` binds every interface,
and port 0 asks for any free port. The tunnels are plain SSH channels on
the session you are already in, so they need no extra credential and no
second connection. A host that would rather not carry that traffic
starts with `comrade --no-forwarding` and refuses every request.

## security

The token is a capability to join one session, and the session is SSH.

- The token is session-specific and useless once the session has ended.
- The host identity is pinned in the token, so a joining client knows it
  reached the right host.
- The terminal traffic travels the direct peer-to-peer link, not the DHT
  rendezvous infrastructure.
- Port forwards ride the same authenticated session as ordinary SSH
  channels, so they inherit the pinned host key and token auth and add
  nothing to the pre-auth surface; a host can decline them all with
  `--no-forwarding`.

One invitation can be handed to several people, and a read-only link is
the one you hand to a room, so what one holder can do to another matters
as much as what an outsider can do:

- **A holder cannot read another's claim.** The rendezvous mailbox is
  readable by everyone holding the invitation, so a claim -- which names
  the addresses a peer can be reached at -- is sealed to the host, whose
  key nobody else has. A read-only link given to twenty people does not
  publish each attendee's address to the other nineteen.
- **A holder cannot reach another's session.** Once two ends are talking
  they agree a key of their own inside the SSH session and everything on
  the direct link is keyed to that pair, so the invitation buys the right
  to start a session and nothing over one already running.
- **A holder can still take a turn.** Joining is a queue, and occupancy
  cannot be hidden from the people entitled to queue: a holder can claim
  repeatedly and delay others. It needs a valid invitation, it delays
  rather than discloses, and it shows up as a rendezvous that will not
  settle.

> Treat the session token like a credential: anyone who has it can use it
> to attempt to join the session.

The wire protocol and the reasoning behind these properties are in
PROTOCOL.md.

### sandboxing

comrade shrinks its own privileges to what it needs, using only what the running
kernel already offers and never a helper binary. It does so right after
launching tmux and before opening any network socket, so the shared tmux session
and the shells it runs keep the caller's full privileges while comrade's own
network-facing process does not. Every layer is best-effort -- one the platform
lacks is skipped, never fatal -- and `COMRADE_SANDBOX=0` turns it all off.

|         | joining client | host service | operator foreground |
|---------|----------------|--------------|---------------------|
| Linux   | drop capabilities, `no_new_privs`, W^X, a seccomp filter denying `execve`, and a mount-namespace (or Landlock) filesystem confinement | the same, with tmux launched through a small unsandboxed broker | a seccomp filter denying the network |
| macOS   | a Seatbelt `deny default` profile, `fork` blocked, `ptrace` refused | the same, through the broker | a Seatbelt profile denying the network |
| Windows | a one-process job object (no child processes) plus process-mitigation policies | the mitigation policies (it launches tmux directly) | the mitigation policies |

## what works

comrade works end to end and is usable today. The core peer discovery,
NAT traversal, SSH session, multi-user tmux sharing, reconnect and
forwarding paths are implemented and tested on real networks. The
remaining work is primarily hardening, additional packaging, and a
handful of protocol and platform improvements.

- **Connection establishment** across every covered path: rendezvous on
  a single shared BEP 44 mailbox, with a one-time host-side DHT
  convergence captured in the token so a client joins in about two
  seconds; ICE hole punching; and a direct UDP transport (lanlink) that
  carries same-segment link-local peers, including under the multi-user
  turnstile. Validated between local processes, on two real boxes on
  different ISPs across IPv6-direct, IPv6/IPv4 via STUN and nested NAT,
  and on a real macOS peer for same-host multicast and the link-local
  transport; the Windows multicast and lanlink path is built and
  CI-smoke-tested, with end-to-end runtime validation pending.
- **The end-user CLI.** `comrade` hosts a private per-session tmux
  server, a connection service that keeps serving while the operator is
  inside the shared terminal, and a dashboard showing the tokens and the
  live peer list. The session lives exactly as long as the operator has
  it on screen, and ends -- leaving a tombstone for anyone still holding
  the token -- the moment they leave. `comrade <token>` joins
  interactively; `comrade show` prints a running session's tokens and
  `comrade stop` ends one. Both ends paint a live status row: connection
  health, RTT, the in-use path, and the rendezvous state.
- **Multi-user.** One host serves up to `HOST_MAX_WORKERS` (16)
  concurrent clients on the single shared tmux session. DHT/ICE joins
  pass through a turnstile on the rendezvous mailbox with single-use
  per-offer ICE credentials, releasing the offer on pickup so a stuck
  punch never head-of-line-blocks the next joiner; same-segment clients
  are admitted concurrently over the direct link-local transport
  alongside the DHT/ICE ones. A worker serves each connected client, and
  vanished clients are reaped by heartbeat.
- **Read-only tokens.** Each session mints a read-only token beside the
  read-write one, derived one way from it so a guest can never walk it
  back. A peer joining with the read-only token gets a view-only tmux
  attach (`attach -r`) and cannot type into the session. `comrade show`
  and the dashboard print both.
- **Keep-alive, roaming and reconnect.** A liveness heartbeat and a warm
  rendezvous node per address family ride a control channel inside the
  SSH session, so either end can re-signal after a network change. A
  client that loses its link rejoins as a fresh join, with a grace
  window so a transient blip resumes without a re-punch.
- **TCP port forwarding** with OpenSSH `-L`/`-R` semantics, riding the
  authenticated session as ordinary SSH channels, and refused wholesale
  with `--no-forwarding`.

## use cases

- **pair debugging.** Temporarily let someone interact with the terminal
  on your machine.
- **remote assistance.** Hand over a session token without exposing an
  SSH port.
- **machines behind NAT.** Connect where ordinary inbound SSH would need
  port forwarding.
- **routers and embedded systems.** The same workflow on an OpenWrt
  machine.
- **temporary collaboration.** Share one live tmux session without a
  permanent network or account.

## how it works

The rendezvous infrastructure helps peers find each other; the terminal
session itself is carried over the direct connection.

```
                  rendezvous
              +----------------+
              |  mainline DHT  |
              | / LAN multicast|
              +-------+--------+
                      |
                 find each other
                      |
          +-----------+-----------+
          |                       |
     +----+----+             +----+----+
     |  host   |<----------->| client  |
     |  tmux   |  direct p2p |  ssh    |
     |  ssh    |             |         |
     +---------+             +---------+
```

Rendezvous happens on the BitTorrent mainline DHT (BEP 44), or on
link-local multicast when the peers share an isolated LAN. From there
ICE hole punching opens a direct path (IPv6 preferred, IPv4 supported
throughout), and the session runs end-to-end SSH wrapping stock tmux.
The DHT sees the introduction, not the conversation. PROTOCOL.md carries the full design.

## Installation

Packaged for the systems below; to build from source instead, see
Building. Every channel tracks the tagged releases, so an ordinary
`apt upgrade` or `brew upgrade` moves to the newest version. Hosting a
session needs tmux; joining one never does, so tmux is a recommendation
you can leave out on a join-only machine.

### Debian and Ubuntu

A signed apt repository serves every current Debian stable and testing
release architecture. Add the key and the source once, then install and
update through apt like any other package:

    sudo install -d -m 0755 /etc/apt/keyrings
    sudo curl -fsSL https://comrade.makrotopia.org/comrade-archive-keyring.asc \
        -o /etc/apt/keyrings/comrade.asc
    echo "deb [signed-by=/etc/apt/keyrings/comrade.asc] https://comrade.makrotopia.org stable main" \
        | sudo tee /etc/apt/sources.list.d/comrade.list
    sudo apt update
    sudo apt install comrade

On a Debian testing system use `testing` in place of `stable`.

### macOS

From the Homebrew tap. `brew install` fetches prebuilt bottles for comrade
and its three dependency formulae alike, so nothing is compiled on your
machine and no build toolchain is required; `brew upgrade` moves to the
next release:

    brew tap dangowrt/comrade
    brew trust dangowrt/comrade   # Homebrew 4.3+ requires trusting a third-party tap
    brew install comrade

### OpenWrt

comrade is small enough to run on OpenWrt routers, and its plain-C
footprint keeps it that way. `net/comrade` and its `libjuice`/`kcp`
dependencies (see Dependencies) are in openwrt/packages master, so
`apk add comrade` works on a snapshot build:

    apk update
    apk add comrade   # hosting a session also needs tmux: apk add tmux

Neither comrade nor libjuice/kcp have been backported to a stable
release branch (23.05, 24.10, 25.12) yet -- only libdht has -- so on
those, build it from source against the dependencies below instead.

### Arch Linux

Not in the official repositories; build from the in-tree PKGBUILDs. Every
dependency but kcp is in the official repositories, so build that one
first:

    git clone https://github.com/dangowrt/comrade
    cd comrade/packaging/arch
    (cd kcp && makepkg -si)
    (cd comrade && makepkg -si)

### Nix

The flake builds comrade together with the dependencies nixpkgs does not
carry. Fetch it with submodules (the `github:` fetcher omits them, and the
build needs the STUN pool submodule). Run it without installing, or add it
to a profile:

    nix run 'git+https://github.com/dangowrt/comrade?submodules=1'
    nix profile install 'git+https://github.com/dangowrt/comrade?submodules=1'

### Windows (EXPERIMENTAL!)

A single portable `comrade.exe` (x64 or arm64), no installer. Download
`comrade-x64.exe` or `comrade-arm64.exe` from the [latest
release](https://github.com/dangowrt/comrade/releases/latest) and put it on
`PATH` -- or, once the manifest is accepted into winget-pkgs:

    winget install dangowrt.comrade

Joining a session needs nothing else. Hosting a session also needs tmux, a
native ConPTY build from winget:

    winget install arndawg.tmux-windows

## Limitations and plans

Standing:

- **Everything is UDP, and there is no relay.** comrade needs a path that
  carries UDP between the two ends. A network permitting outbound UDP
  nowhere -- some hotel, campus and corporate networks -- stops it, and no
  amount of obfuscation changes that. Having no relay is deliberate: there
  is nothing to run, fund or trust, and nothing that sees the timing and
  volume of every session. A TCP fallback straight to a reachable host
  would cover the common half of the problem without a third party, and is
  the shape any future answer would take; see SECURITY-ARCHITECTURE.md.
- **An invitation is shared by everyone holding it.** One token is one
  rendezvous, which is what lets a link be handed to whoever you like and
  simply work. A holder can therefore take a turn in the queue and delay
  others, though not read what they exchange. The trade is described in
  SECURITY-ARCHITECTURE.md.

Planned:

- The deliberate good-DHT-citizen pass: both ends already keep their DHT
  node running and answering for the whole session, but the audit has not
  been done.
- NAT-PMP/PCP port mapping on both ends, opening a path through a
  cooperating router to shorten or avoid the punch.
- The hardening pass: privilege separation, sandboxing, fuzzing.
- Further packaging.

Copying files needs no new feature: forward the port of any server with
`-L`/`-R` and use stock tooling (an HTTP server, rsync, SMB). A dedicated
SSH endpoint was considered and dropped: forwarding already covers it, and
comrade's own SSH credentials are neither operator-accessible nor
configurable, so exposing that server buys little.

## Comparison

A survey of the FOSS landscape (August 2026) turned up no project with
the same combination of properties, though several are close in one
dimension or another. The closest neighbours, by user-visible
behaviour; every row is free software except share terminal, whose
MIT client fronts a proprietary service:

| Project | Shares | Relay in the data path | Control plane you must trust | NAT traversal |
|---------|--------|------------------------|------------------------------|---------------|
| comrade | tmux session | no; direct punch | none; token only | ICE/STUN, no TURN |
| tmate | tmux session | yes | the relay | none |
| upterm | terminal | yes (self-hostable) | the relay | none |
| sshx | browser terminal | yes; always relayed | author's hosted service | none |
| share terminal | browser terminal | whatever TURN the operator sets | its proprietary backend, plus a Google account | ICE/STUN, TURN if configured |
| shwim | terminal | fallback only | wormhole mailbox server | direct, relay fallback |
| tunshell | one-off shell | fallback only | own relay server | punch, relay fallback |
| dhtnet | netcat, shell | TURN by default | OpenDHT + bootstrap | ICE, TURN default |
| iroh-ssh | SSH tunnel | fallback only | n0-run DNS and relays | punch, relay fallback |

Overlay VPNs (Tailscale, ZeroTier, n2n and kin) and stable-addressing
overlays (Yggdrasil, cjdns) are an adjacent category, deliberately
different in kind: they need a coordination layer someone runs, or
reachable peers, rather than a one-shot punched session. comrade combines
a set of properties that is unusual among existing FOSS tools: direct
hole-punched terminal sharing, no central service, SSH with the host key
pinned in the token, dual-stack IPv4+IPv6, and a plain-C footprint that
fits an OpenWrt router.

## Prior art and related work

The nearest neighbours, and what each one teaches:

- dhtnet (`dnc`/`dsh`/`dvpn`; Savoir-faire Linux, C++, GPL-3.0,
  extracted from Jami): the same use-case, shells and TCP streams over
  DHT rendezvous plus ICE, and the closest living relative. It rides
  OpenDHT with `bootstrap.sfl.io` as default
  bootstrap and `turn.sfl.io` as default TURN relay, X.509 certificate
  identity, and pjproject/GnuTLS-class dependencies. It validates the
  architecture, and demonstrates how "distributed" quietly decays into
  operated bootstrap-plus-relay defaults, which the mainline-DHT
  choice and the no-TURN stance avoid.
- Holepunch/Pear family (hypershell, hyperssh, hypertele, holesail;
  Node.js): key-addressed servers on their own HyperDHT, hole punching
  built in, DHT nodes doubling as signalling relays; hyperssh layers
  real SSH on top, the same transport/auth split as comrade. Bootstrap
  is run by Holepunch (Tether-funded), the runtime is Node, and the
  DHT is IPv4-only (issue open since 2018), so dual-stack is a real
  differentiator against this, the closest UX family.
- bitbang-cli (`bitbang serve`/`share`/`connect`; Go, MIT): the same
  audience and much of the same UX, a single static binary that opens
  a P2P terminal, file transfer and web-app proxy to a machine behind
  NAT, shares a running tmux session with separate control and view
  URLs (comrade's read-only tokens by another name), and forwards
  ports with `-L`. It rides WebRTC/DTLS with ICE punching and a TURN
  fallback, signalled through a dedicated hosted rendezvous server
  (`bitba.ng`, self-hostable) rather than the mainline DHT, and pins
  device identity as an RSA-keypair UID confirmed out of band by a
  read-aloud short authentication string. Several touches are worth
  stealing: named device memory (`bitbang connect nas1`), QR, URL and
  six-digit invitations, the access code kept in the URL fragment so
  the signalling server never sees it, and one URL that serves both a
  browser and the CLI. It leans on an operated signalling server and a
  relay fallback where comrade takes the mainline DHT and the no-relay
  stance, and ships a Go binary with a browser client where comrade is
  plain C with the host key pinned in the token.
- share terminal (`npx share-terminal start`; MIT client, proprietary
  service, <https://www.shareterminal.cloud/>): a PTY punched to a
  browser viewer over a WebRTC DataChannel, ICE by libdatachannel and
  so libjuice underneath. It ranks first for this kind of search and
  reads as open source, but the MIT covers the client alone: pairing,
  Google OAuth, the signaller and the per-session ICE list sit behind
  an unpublished backend on a $5-a-month subscription, so identity is a
  Google account rather than a pinned host key, and a relay in the path
  is the operator's call. The advertised 140 KB also wants 77 MB of
  `node_modules` under a 60 MB runtime.
- tuntox over c-toxcore (C, GPL-3.0): plain-C tunnels over the Tox DHT
  with volunteer bootstrap; the nearest language-and-footprint cousin.
  Tox TCP relays carry traffic as a routine fallback, the address is a
  76-hex-char Tox ID, auth is an optional PSK, and releases have been
  stale since 2021.
- iroh with iroh-ssh and dumbpipe (Rust): ticket-string UX like our
  token, hole punch with relay fallback; but the n0-operated relays
  are also the default candidate-exchange channel, default discovery
  is an n0-run DNS server, and mainline-DHT publication (via pkarr) is
  opt-in. iroh-ssh pointedly does not pin a host key in its ticket
  (anyone holding the endpoint ID reaches sshd), which is the design
  our hostpub-in-token pinning corrects.
- Mainline-DHT precedents: bluntly (dead 2020) punched from BEP 5
  announces, pre-BEP 44; emilbayes/rendezvous-point (2018, a dozen
  commits) prototyped the same DH-derived shared BEP 44 mailbox idea;
  cipherpost (Rust, alive) delivers secrets through a BEP 44 encrypted
  mailbox but carries no live session; pkarr/pkdns (Rust, production)
  publishes signed DNS records via BEP 44 and confirms at 10M-node
  scale the 1000-byte ceiling and the constant-republish obligation
  the design already assumes.
- gsocket/gs-netcat (C, THC): shared-secret rendezvous and SRP E2E in
  a 200 KB OpenWrt package, but zero hole punching: every byte
  transits THC's GSRN relay network. The footprint proof and the
  anti-model in one package.
- wush (Go, Coder): the token-carries-everything UX (key, UDP
  endpoints and DERP region in one string, no accounts), with
  signalling and fallback riding Tailscale's DERP relays.
- gonc (Go): the strongest open punching reference: TCP and UDP
  punching, IPv6-first preference, NAT classification, and a
  birthday-paradox 600-port spray for symmetric NATs, signalled over
  public STUN and public MQTT brokers. Worth mining as the later
  NAT-traversal stages are built.
- shwim (Python) and the magic-wormhole family: the PAKE short-code
  handoff precedent for the token UX; mailbox and transit-relay
  servers still required, and no host-key pinning.
- yggdrasil-jumper (Rust): bolts STUN discovery plus punching onto
  Yggdrasil, using the overlay itself as the signalling channel: the
  comrade pattern on a different substrate.
- Server-based terminal sharers (tmate, upterm, tty-share, sshx,
  termpair, tunshell, teleconsole and kin): UX prior art only. Each
  needs an operated or self-hostable relay; several see plaintext
  (tmate's relay reconstitutes the tmux session and must be fully
  trusted, its issue #22; tty-share lists E2E as a TODO). The hosted
  tmate.io service has been failing since mid-2025 with no maintainer
  response (tmate issue #322), which sharpens the case for a design
  with no service to lose.

Measured findings folded into the design:

- DHT latency is a product risk: pcp (archived libp2p copy tool) died
  in part, by its author's own post-mortem, because cold IPFS-DHT
  lookups took minutes. This confirms the propagation measurements
  and the token-carried DIRECT/RENDEZVOUS hints as the first paths in
  the connection race.
- Punching at scale: the libp2p DCUtR study (arXiv 2510.27500, 4.4M
  attempts across 85k networks) measured ~70% hole-punch success, TCP
  and QUIC statistically equal, and 97.6% of successes on the first
  attempt. A ~30% tail must be planned for; comrade's answer remains
  retry-and-escalate, never a relay.
- OpenWrt installed-size benchmarks: natmap 61 KB, gsocket 200 KB,
  tinc 450 KB, tmate 625 KB (tmate and tmate-ssh-server are already
  feed packages, easing comrade's path in). The sub-1 MB budget is
  realistic; the Go tools (croc 8.7 MB, netbird 33 MB) confirm the
  language constraint, and the Node ones put it beyond argument: share
  terminal's 140 KB bundle needs 77 MB of `node_modules` and a 60 MB
  runtime under it, on an architecture that runtime was ported to.
- Citable design context: chr15m's essay "BEP44 for decentralized
  applications", and BitTorrent proposal issue #178, a DHT
  hole-punching extension that was never adopted.

## Building

    git submodule update --init   # STUN server list baked into the binary
    cmake -B build
    cmake --build build
    ctest --test-dir build

The submodule is data, not code: the community always-online-stun list.
Without it configure stops rather than silently baking the three-server
fallback (available behind `-DCOMRADE_STUN_FALLBACK=ON` for builds that
truly cannot fetch the list); either way `comrade stun-update` refreshes
the list at runtime.

Dependencies installed outside the system prefix are picked up via
`-DCMAKE_PREFIX_PATH`, and the jech/dht checkout via `-DCOMRADE_DHT_DIR`,
for example:

    cmake -B build -DCMAKE_PREFIX_PATH=/usr/src/local -DCOMRADE_DHT_DIR=/usr/src/dht

## Dependencies

All libraries are system-provided, nothing is vendored. Every one of them
is load-bearing, so a missing one stops configure with a list of what to
install, rather than yielding a binary with the session stack cut out of
it.

| Library | Purpose | Arch Linux | OpenWrt |
|---------|---------|------------|---------|
| libssh | SSH server and client | extra/libssh | libssh (packages feed) |
| libjuice | ICE/STUN hole punching | extra/libjuice | libjuice (packages feed, master only) |
| a crypto library | ed25519, X25519, ChaCha20-Poly1305, BLAKE2b | whichever libssh uses | whichever libssh uses (see below) |
| kcp | reliable stream over UDP | `packaging/arch/kcp` (in-tree PKGBUILD) | libkcp (packages feed, master only) |
| jech/dht | mainline DHT (Kademlia, BEP 32) | extra/dht | libdht (packages feed) |

Runtime dependency: tmux, on the host side only.

kcp is the one dependency Arch has no package for, so `packaging/arch`
carries a PKGBUILD for it. jech/dht comes from `extra/dht`, which builds
it as a static `libdht.a`; the shared `libdht` the OpenWrt, Debian and
Homebrew recipes install serves the same purpose where a repository
package does not exist. The apt repository and the Homebrew tap ship
libjuice, kcp and libdht as their own packages, so installing comrade
there pulls them in.

An installed libdht is found by configure on its own, static or shared
alike; a plain jech/dht checkout works too, via `-DCOMRADE_DHT_DIR=<path>`,
which compiles dht.c straight in. Every route relies on comrade defining
the four symbols dht.c deliberately leaves to the application
(`dht_hash`, `dht_random_bytes`, `dht_blacklisted`, `dht_sendto`),
resolved at link time against the archive and by the dynamic linker
against the shared library.

jech/dht carries no BEP 44 support and needs none: BEP 44 put/get is
implemented in-tree (`src/bep44.c`) beside an unpatched jech/dht
checkout, which settled the old fork-or-patches question.

comrade supports several crypto backends through one in-tree shim
(`src/ccrypto.h`) and keeps the wire format byte-for-byte compatible
across them, so peers built against different ones interoperate. It does
not choose one for you: it follows whatever crypto library **libssh** is
already linked against, so it adds no second one, with a small monocypher
fallback for mbedTLS-based systems.

| libssh built against | comrade uses | why |
|----------------------|--------------|-----|
| OpenSSL | OpenSSL libcrypto | already linked |
| libgcrypt | libgcrypt, 1.10 or newer | already linked |
| mbedTLS | monocypher (~70 KB) | mbedTLS has no BLAKE2b and no Ed25519 |

Configure reads that from the libssh binary itself and prints what it
resolved and why; `-DCOMRADE_CRYPTO=<backend>` overrides it. The libgcrypt
floor is `gcry_ecc_mul_point`, which arrived in 1.10 and is what the
X25519 half is written against; configure checks for it rather than
letting the compiler find out.

## Documentation

- **PROTOCOL.md** -- the wire protocol and rendezvous design, precise
  enough to implement against. Nothing on the wire is stable across
  0.1.x, and it says which parts moved last.
- **SECURITY-ARCHITECTURE.md** -- what two adversarial reviews of the
  transport found, what was done about it, and what is left: the parts
  that are properties of the design rather than bugs in it, each with the
  option that would close it and what that would cost.
- **INTEGRATION.md** -- the machine-readable interface for embedding
  comrade in something else.

## Licence

comrade is free software under the **GNU Affero General Public License,
version 3 or later** (AGPL-3.0-or-later); see the `LICENSE` file for the
full text, and the `SPDX-License-Identifier` header in each source file.

The AGPL's network clause is deliberate: comrade is peer-to-peer, so anyone
running a *modified* comrade that others connect to must offer them its
source. This keeps the tool, and any hosted or relay variant, free.

### OpenSSL / system-crypto linking exception

As an additional permission under section 7 of the AGPL version 3, you
are granted permission to link or combine comrade with the OpenSSL library
(or a modified version of it), and with the system TLS/crypto library
that libssh is built against (for example OpenSSL or mbedTLS), and to
convey the resulting work. The Corresponding Source for such a
combination need not include the source of those libraries where they
are System Libraries in the AGPL's sense. This exception is granted by
the comrade copyright holders and does not apply to third-party code that
carries its own terms.
