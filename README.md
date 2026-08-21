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
as they arrive. ENTER drops you into the shared tmux session; ESC before
entering aborts it. `comrade` again re-attaches to your running session,
and `comrade show` prints them. The session ends when the last shell in
it exits, on whichever side; a client detaching or dropping never ends
it.

Join one from anywhere, in the same tmux session:

    comrade <token>

The read-write token joins read-write; the read-only token joins the
same session view-only, unable to type into it. Which one you were handed
decides it; there is no extra flag.

`-v` swaps the dashboard for plain log lines on either side.
`--no-multicast` skips link-local discovery to force the DHT/STUN path,
and `--no-dht` declines the DHT so peers meet over link-local discovery
alone. Both work on either side, and each is that operator's own choice:
a token never switches a transport off for the other end. Giving both at
once is refused, since it would leave nothing to meet on. They are
properties of the session being started, so `comrade` re-attaching to a
session you already have keeps whatever that service was started with,
and says which of them it is ignoring.

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

> Treat the session token like a credential: anyone who has it can use it
> to attempt to join the session.

The wire protocol and the reasoning behind these properties are in
PROTOCOL.md.

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
  server, a detached connection service that keeps serving while the
  operator is away, and a dashboard showing the tokens and the live peer
  list. `comrade <token>` joins interactively; `comrade show` prints a
  running session's tokens. Both ends paint a live status row: connection
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

From the Homebrew tap. `brew install` fetches a prebuilt bottle for the latest
release, and `brew upgrade` moves to the next one:

    brew tap dangowrt/comrade
    brew trust dangowrt/comrade   # Homebrew 4.3+ requires trusting a third-party tap
    brew install comrade

### OpenWrt

comrade is small enough to run on OpenWrt routers, and its plain-C
footprint keeps it that way. Packaging for the OpenWrt packages feed is
not yet in the tree, though: libjuice and kcp still need feed packages
and the jech/dht dependency is undecided (see Dependencies), so there is
no `apk add comrade` to run yet. Until the feed packages land, build it
from source against the dependencies below.

### Arch Linux

Not in the official repositories; build from the in-tree PKGBUILDs. kcp
and jech/dht are not packaged for Arch either, so build those two first:

    git clone https://github.com/dangowrt/comrade
    cd comrade/packaging/arch
    (cd libdht && makepkg -si)
    (cd kcp && makepkg -si)
    (cd comrade && makepkg -si)

### Nix

The flake builds comrade together with the dependencies nixpkgs does not
carry. Run it without installing, or add it to a profile:

    nix run github:dangowrt/comrade
    nix profile install github:dangowrt/comrade

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
dimension or another. The closest neighbours, by user-visible behaviour:

| Project | Shares | Relay in the data path | Control plane you must trust | NAT traversal |
|---------|--------|------------------------|------------------------------|---------------|
| comrade | tmux session | no; direct punch | none; token only | ICE/STUN, no TURN |
| tmate | tmux session | yes | the relay | none |
| upterm | terminal | yes (self-hostable) | the relay | none |
| sshx | browser terminal | yes; always relayed | author's hosted service | none |
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
  language constraint.
- Citable design context: chr15m's essay "BEP44 for decentralized
  applications", and BitTorrent proposal issue #178, a DHT
  hole-punching extension that was never adopted.

## Building

    git submodule update --init   # STUN server list baked into the binary
    cmake -B build
    cmake --build build
    ctest --test-dir build

The submodule is data, not code: the community always-online-stun list.
Without it configure warns and bakes a minimal fallback; either way
`comrade stun-update` refreshes the list at runtime.

Dependencies installed outside the system prefix are picked up via
`-DCMAKE_PREFIX_PATH`, and the jech/dht checkout via `-DCOMRADE_DHT_DIR`,
for example:

    cmake -B build -DCMAKE_PREFIX_PATH=/usr/src/local -DCOMRADE_DHT_DIR=/usr/src/dht

## Dependencies

All libraries are system-provided, nothing is vendored. Configure prints
a summary; a build with libraries missing still configures, but the
resulting binary lacks the session stack and says so.

| Library | Purpose | Arch Linux | OpenWrt |
|---------|---------|------------|---------|
| libssh | SSH server and client | extra/libssh | libssh (packages feed) |
| libjuice | ICE/STUN hole punching | extra/libjuice | new package needed (plain CMake, no dependencies) |
| a crypto library | ed25519, ChaCha20-Poly1305, BLAKE2b | whichever libssh uses | whichever libssh uses (see below) |
| kcp | reliable stream over UDP | install from upstream: `cmake -B build && cmake --install build` | new package needed |
| jech/dht | mainline DHT (Kademlia, BEP 32) | source checkout, pass `-DCOMRADE_DHT_DIR=<path>` | to be decided |

Runtime dependency: tmux, on the host side only.

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
| libgcrypt | libgcrypt | already linked |
| mbedTLS | monocypher (~70 KB) | mbedTLS has no BLAKE2b and no Ed25519 |

Configure reads that from the libssh binary itself and prints what it
resolved and why; `-DCOMRADE_CRYPTO=<backend>` overrides it.

## Documentation

- **PROTOCOL.md** -- the wire protocol and rendezvous design.

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
