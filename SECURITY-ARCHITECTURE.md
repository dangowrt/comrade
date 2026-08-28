# What the raw-path review found that a patch cannot fix

Two adversarial reviews of the probe parser, path selection and the transport
under them (2026-08-28) turned up eleven defects with contained fixes, which
are the commits on this branch, and four findings that are properties of the
design rather than bugs in it. Those four are written up here, with options
and their costs, and none of them is implemented.

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

One part of it is a defect, and it is not a small patch. `hb_lost_ms()` is
`HB_SILENT_TRIES * HB_INTERVAL_MS + rtt`, so 2.1 to 3.1 s of silence sets
`lost_since_ms`; `RESUME_AFTER_MS` adds 3 s; then `resume_tick` case 0
(src/session.c) destroys the ICE agent outright and re-punches. Around 6 s of
total inbound drop therefore costs a working agent and its NAT bindings, and
an adversary dropping for 6 s at intervals keeps comrade re-punching, re-running
STUN and the DHT claim each time -- paying cost and emitting fingerprint on
demand.

**Options, and why neither is a one-liner.**

*Park the agent instead of destroying it.* Build the replacement while the old
agent stays alive and receiving, and adopt whichever proves out; a drop that
ends inside the window then costs nothing. libjuice has no ICE restart and
`conn_fresh_pwd` mints new credentials, so the replacement must be a new agent
either way -- parking does not fight that. What it does fight is the receive
path: `conn_recv_path` (src/session.c:1969) resolves an ICE datagram to
`path_table_find_agent(&c->paths, c->nat)`, i.e. to whatever agent is current,
not to the one that received it. With two agents alive the parked agent's
traffic would credit the new agent's path, which is the same
liveness-on-the-wrong-path defect this branch closed elsewhere. Parking is
therefore gated on giving the receive callback an agent identity and keying
the ICE path on it.

*Back off repeated teardowns.* Cheaper to write, but it collides with a stated
contract: `HOST_REAP_MS` is defined as `RESUME_AFTER_MS + RESUME_ATTEMPT_MS +
RESUME_ATTEMPT_MS / 2` precisely so a worker outlives the claimant's second
attempt. Raising the claimant's delay to *N* requires raising the reap to
*N* + 15 s, so a vanished client holds its worker, tmux client and dashboard
row that much longer. The security gain is paid for in reaping latency, which
is a product call rather than a security one.

Of the two, parking is the one worth doing: it removes the reward without
changing any timing contract. It is listed here rather than fixed because the
receive-attribution rework it needs is exactly the code this branch has just
been hardening, and landing both at once would make neither reviewable.

---

## Not proposed

Rotating or revoking an invitation was raised by the review as the obvious
answer to (1). It is deliberately absent from comrade (`--max-clients` and
expiry exist; kick and rotate do not), and adding it is a product decision
rather than a security fix, so it is noted and left alone.
