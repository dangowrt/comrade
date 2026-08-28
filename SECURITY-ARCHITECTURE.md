# What the raw-path review found that a patch cannot fix

Two adversarial reviews of the probe parser, path selection and the transport
under them (2026-08-28) turned up sixteen defects with contained fixes, which
are the code commits on this branch, and four findings that reach into the
design rather than sitting in one place in it. Three are written up here with
options and their costs, and none of those three is implemented. The fourth,
section 4, held one contained defect inside a general truth about networks;
that defect is fixed, and the truth is stated.

The threat models were: a holder of the invitation who is not the peer --
including someone handed a view-only link -- and the ISP or hoster, who sees
and can spoof every datagram but holds no key.

---

## 1. One key per invitation, not per peer

`keys_derive` (src/keys.c) takes the token's rendezvous secret and nothing
else, so `sig_key` is the same 32 bytes for the host and for every guest it
ever admits. The read-only credential is a separate *auth* secret over the
same rendezvous secret, so a view-only guest holds the transport key in full.

What follows from that is not fixed by any of the commits here:

- "Sealed" proves a token holder wrote a frame. It never proves *which*, so
  every per-peer rule on this path is really a rule about a claimant ufrag,
  and that ufrag travels under the same key: any guest can read another
  guest's announcement or mailbox slot and learn it.
- The patches on this branch narrow what a frame may then do -- it must be
  new, it must arrive where the session is, it may not evict a warm path, its
  claims about cost are bounded -- but a determined key holder still shares
  the transport plane with every other guest of that host.
- `TOKEN_FLAG_RO` is enforced above the transport, not on it.

**Options.**

*A. Per-connection transport key, exchanged inside SSH.* Once a session is up,
both ends already share an authenticated, confidential channel with a pinned
host key. Derive the probe key from a secret exchanged there (a `CTLM_*`
message), keeping the token-derived key only for the frames that must work
before a session exists -- the punch and the announcement. Cost: two keys and
a switchover point; probes sent between the punch completing and the exchange
finishing must be accepted under either. Benefit: everything after the
handshake becomes genuinely per-peer, and a view-only guest loses the
transport plane entirely. This is the option I would take.

*B. Per-guest tokens.* Give each invitation its own rendezvous secret, with
the host holding a set. Cost: the mailbox is keyed by the rendezvous secret,
so one shared mailbox becomes many, and the whole "one place both ends meet"
property that the rendezvous design rests on has to be reworked. Also ends
the "copy one link to whoever you like" model, which may be the point of the
tool.

*C. Accept it, and say so.* Document that a comrade invitation, view-only or
not, admits its holder to the transport plane of that host, and that guests
are therefore mutually trusted. Cheapest, and honest, but it makes
`--read-only` a much weaker promise than its name suggests.

## 2. Comrade is identifiable, and therefore blockable

Fixed in part on this branch: both wire tags are now derived per session, so
the trivial four-byte rule is gone. What remains is structural.

- Everything is UDP. `nat_create` configures STUN only -- no TURN -- and the
  segment transport is a datagram socket. A policy of "outbound UDP to 53 and
  443 only" stops comrade dead, and such policies are common on the networks
  where this tool is most wanted.
- The shape is still distinctive: fixed-size probes on a fixed cadence, a
  heartbeat at another, a STUN exchange before anything else, and a BEP 44
  mutable put/get pattern in the DHT that looks like nothing else on the wire.
- The DHT traffic precedes the session and identifies the protocol before a
  single session datagram exists.

**Options.** A TCP/443 fallback carrying the same KCP stream would cost a
listener and a fallback path in the transport, and would make comrade look
like TLS to a port-based policy; it does not make it look like TLS to
inspection. A TURN client would let a relay stand in where no direct path
exists, at the cost of trusting a relay. Padding probes to a common length and
jittering the cadence is cheap and buys a little. None of this makes comrade
unblockable by a determined national adversary, and pretending otherwise
would be worse than saying plainly what it does not do.

## 3. The data plane is not authenticated

KCP datagrams are handed to `ikcp_input` as they arrive. On this branch they
must now come from an endpoint the connection holds, and the conversation id
is per session rather than a constant, so blind injection needs the endpoint
and the id. But the bytes themselves are neither sealed nor authenticated:
anyone who can send from the right endpoint can corrupt the stream, and the
24-byte KCP header is in the clear, so segment sizes and sequence numbers are
readable by anyone on the path. SSH inside means this is corruption and
metadata, never disclosure of content.

**Options.** Sealing every datagram under the session key costs
`SEAL_OVERHEAD` (40 bytes, ~3.3% of a 1200-byte MTU) and one AEAD operation
each way per datagram; it closes injection outright and hides the KCP header.
The measurement to take first is what that AEAD costs on the slowest target
(an OpenWrt router), because that is the only real argument against it.

## 4. An outage is indistinguishable from an adversary

Selective dropping is available to the ISP by definition, and the design
responds to loss by moving, re-probing and eventually rejoining. On this
branch the responses are no longer *triggerable* by spoofed traffic, but they
are still driveable by dropping: silence a path and it is left, silence
everything and the session rejoins. For the general case there is no fix and
no defect; it is worth stating in the threat model that comrade's availability
against an on-path adversary is exactly the availability of some path they
have not chosen to block. SSH over TCP is no better off -- a blackholed
connection is equally indistinguishable from a dead network -- and comrade,
holding several paths, can at least tell one dead path from a dead network.

One part of it was a defect, and is fixed rather than proposed. `hb_lost_ms()`
is `HB_SILENT_TRIES * HB_INTERVAL_MS + rtt`, so 2.1 to 3.1 s of silence sets
`lost_since_ms`, and `RESUME_AFTER_MS` added 3 s before `resume_tick` case 0
destroyed the ICE agent and re-punched. Around 6 s of total inbound drop
therefore cost a working agent and its bindings, and an adversary dropping for
6 s at intervals could ask for a re-punch each time, re-running STUN and the
DHT claim on demand.

The replaced agent is now set aside instead: it keeps its path and is probed
like any other, so the ranking decides whether it still carries, and if it does
it takes the current role back while the punch built in its place is let go.
One is held at a time, for `RESUME_ATTEMPT_MS`. Holding two agents required the
receive side to stop crediting a datagram to whichever agent is current --
libjuice reports no source, so the receiving agent is the only thing that says
which path a frame arrived on -- which is threaded from the transport callback
to the path lookup.

What is *not* covered: no test stages an outage that also blocks the
replacement punch, so the parked agent is never the one that recovers in the
suite. `tests/resume.sh` blackholes application data but not ICE, so its
re-punch completes inside the staged outage and parking correctly stands
aside; `--stuck` wedges the *first* punches, not a later one, so it cannot
express "wedge the resume punch". Deciding coverage would need a hook that
does, which is production test machinery nobody asked for. The two-agent
attribution it rests on is unit-tested (`agent_paths_check`, tests/path_test.c)
and both mutants of the rule are killed.

---

## Not proposed

Rotating or revoking an invitation was raised by the review as the obvious
answer to (1). It is deliberately absent from comrade (`--max-clients` and
expiry exist; kick and rotate do not), and adding it is a product decision
rather than a security fix, so it is noted and left alone.
