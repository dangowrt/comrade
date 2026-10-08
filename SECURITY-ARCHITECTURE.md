# What the raw-path review found, and what is left of it

Two adversarial reviews of the probe parser, path selection and the transport
under them (2026-08-28) turned up defects with contained fixes, which are the
code commits on this branch, and four findings that reach into the design
rather than sitting in one place in it.

Three of the four are now closed in code: nothing on the transport or in the
rendezvous can be read by a holder of the invitation who is not a party to it
(1), the stream says who sent it (3), and an outage no longer costs a working
agent (4). What is left here is what those changes do not reach: comrade is
UDP-only with no fallback (2); the KCP header is still readable (3); and an
adversary who drops everything is indistinguishable from a dead network (4).

Finding (1) also had a residual, a holder taking the shared answer slot and
delaying somebody else's exchange, and that one is now closed as well: the
rendezvous is a slot per party rather than one container, so there is no mutex
to take. What survives of it is narrower and recorded in section 1.

The threat models were: a holder of the invitation who is not the peer --
including someone handed a view-only link -- and the ISP or hoster, who sees
and can spoof every datagram but holds no key.

---

## 1. One key per invitation, not per peer

`keys_derive` takes the token's rendezvous secret and nothing else, so the
sealing key was the same 32 bytes for the host and every guest it ever
admitted. "Sealed" proved a token holder wrote a frame and never which one, and
the read-only credential is a separate *auth* secret over the same rendezvous
secret, so a view-only guest held the transport key in full.

**Closed for the steady state.** Both ends now trade a random half over the
control channel -- a stream inside the SSH session, under a pinned host key --
and everything on the raw path is keyed to that pair (keys.h, `keys_conn_key`).
No guest can reach another guest's path plane or stream once a session is up,
whatever the invitation says. The switch is clocked by the peer rather than a
timer, because the halves travel over the stream the key protects.

**Closed for the rendezvous too, and by a cheaper route than the one costed
below.** The rendezvous is no longer one container under the invitation's key.
It is a slot per party, each named by its own BEP 44 salt under the one
keypair, and a claimant's slot is sealed under a key derived from the auth
secret of that claimant's credential class (`keys.c:keys_slot_key`). The two
slots the old shared container held were not alike, which is why reading it
mattered:

- The *offer* slot is the host's own description. Every invited guest needs it
  to reach the host, view-only ones included, so reading it is not a leak -- it
  is the invitation working.
- The *answer* slot is whichever guest is currently claiming, and it carried
  that guest's ICE candidates in the clear to every other holder. Between
  read-write guests that was a small matter, since the host has trusted each
  of them with a shell and they are trusted accordingly by each other. Between
  read-only guests it was the worst case in the design: a read-only link is
  the one handed to a room, and a crowd with no reason to trust each other was
  publishing its addresses to itself.

A claimant now writes its description into a slot of its own, sealed under its
class key. A read-only holder derives that key from the `A_ro` it was given and
cannot reach `A_rw`, because `keys_derive_ro_auth` is one-way, so it cannot
read or write a read-write holder's slot at all. That is the pair the design
cared about: a read-only link is the one handed to a room, and an audience can
no longer touch the operator's own people.

Read-write holders can still reach each other, which is deliberate: the host
has trusted each of them with a shell, so they are trusted accordingly by each
other. Two read-only holders can still reach each other too, since they share
`A_ro` and instance ids travel in the clear through the doorbell. That is an
accepted flaw, recorded in `PROTOCOL.md` section 4.2. Note it is wider than
disclosure: a holder able to derive another's slot key can also overwrite that
slot, so within a class the exposure is interference as well as reading.

It also takes away what the pre-handshake probe interference used to aim with.
The per-connection key binds only once the SSH handshake completes, so until
then a guest can still send probes at another guest's punch -- but the
endpoints it would send them to came out of the mailbox.

**The occupancy argument this section used to make was wrong, and the cost it
quoted was wrong twice.** It held that occupancy is inherent to a mutex, that
closing it needed mailboxes single-use or private per guest, and that the price
would be the property the whole tool rests on: one token is one BEP 44 key, so
a link can be handed to whoever you like and simply works. Both halves were
mistaken. A slot per party costs no second key, because BEP 44 names an item by
keypair *and salt*, so one keypair carries as many private slots as there are
parties. And the mutex was not merely an occupancy risk, it was a liveness
fault in ordinary use: with one answer slot, three claimants resolved 60/0/0,
two of them never getting in at all, which is why a real user connected once
and never again. It was measured, not postulated (`PROTOCOL.md` section 4).

**What survives.** The doorbell is shared and last-writer-wins, so an
authenticated holder can overwrite another's announcement and delay its
harvest. A claimant keeps ringing while it has no live path, so this is delay
rather than denial, and the bound is in messages rather than seconds. Within a
class a holder can read and overwrite a peer's slot, as above. None of this
reaches across the class boundary, and none of it needs a timeout to recover.

**No longer needed: a rendezvous secret per class.** This section used to
propose deriving a read-only rendezvous secret one-way from the read-write one
and putting it in the read-only token's `rdv` field. The per-class *slot* key
achieves the same separation without touching the token or splitting the
rendezvous, so the proposal is withdrawn. Per-class admission limits remain
open, and the grant now refuses a claimant in its own slot rather than leaving
it silent, which is the mechanism such a limit would use.

One property the slot design relies on, worth keeping rather than assuming: a
DHT stores an item on the nodes closest to its key, and salts do not move it,
so every slot of one invitation lives in the same place and a pinned rendezvous
node serves them all. That is what makes a slot per party cost lookups rather
than nodes.

**What is still not worth doing.** Per-invitation keys would separate the crowd
from each other, but a crowd is exactly what one link handed to many people is;
the model that makes an anonymous audience possible is the model that gives
them a shared secret. The per-class slot key gets the protection that matters,
read-only away from read-write, without asking the operator to mint and track a
token per attendee.

## 2. Comrade is identifiable, and therefore blockable

Both wire tags are derived per session, so the four-byte rule that would have
caught every comrade datagram anywhere is gone. What remains is structural, and
it is worth being precise about where it actually sits.

**Identification is not where the risk is.** SSH over TCP announces itself in
cleartext -- `SSH-2.0-...` in the first bytes, on a well-known port -- so on
identifiability alone comrade is now the harder of the two. The ICE and STUN
traffic blends into a very large crowd: the STUN magic cookie is in every
WebRTC call, so a policy that drops it breaks Teams, Meet and WhatsApp calls,
which is expensive for the network operator to do. What does stand out is the
BEP 44 rendezvous: mutable put/get looks like BitTorrent, which ISPs do
throttle and block, and it happens before any session datagram exists.
`TOKEN_FLAG_EP6_RDV` and `TOKEN_FLAG_EP4_RDV` already let a token name a
rendezvous node directly, so the mitigation there is half-built.

**Blocking is where the risk is, and the difference from SSH is fallback, not
fingerprint.** SSH survives a hostile network because 443, ProxyJump and an
installed base that must keep working all exist. Comrade is UDP-only with no
relay: `nat_create` configures STUN and no TURN, and the segment transport is a
datagram socket. "Outbound UDP to 53 and 443 only" stops it dead, costs the
operator nothing, and is common on exactly the networks where a tool for
reaching your own machine is most wanted.

**This is a product stance, not a defect, and it should be stated as one.** A
comrade session needs a path that carries UDP between the two ends, or a relay,
and comrade deliberately has no relay to depend on, run, or trust. Someone on a
UDP-blocked network cannot reach their machine with it, and no amount of
obfuscation changes that.

**Options, if a fallback is ever wanted.** They are not equal:

- *TCP/443 direct to the host*, carrying the same KCP stream. Costs a listener
  and a fallback path in the transport, and no third party at all. It covers
  the case where the host has a reachable port and the guest is on a
  UDP-hostile network -- hotel wifi to a home router with a forward -- which is
  the common half of the problem. To a port-based policy it looks like TLS; to
  inspection it does not.
- *TURN*, which covers the other half (neither end reachable) at the cost of
  trusting somebody's relay with the timing and volume of every session, and of
  there being far fewer community TURN operators than STUN ones, since relaying
  costs real bandwidth.

Padding probes to a common length and jittering the cadence is cheap and buys a
little. None of it makes comrade unblockable by a determined national
adversary, and pretending otherwise would be worse than saying plainly what it
does not do.

## 3. The data plane is not authenticated

KCP datagrams were handed to `ikcp_input` with nothing under them saying where
they came from. SSH inside means that was never a disclosure and never a
forgery of terminal content -- but it was a teardown this design cannot route
around. Dropping is what the path layer survives, by measuring loss and moving;
corruption ends the SSH session above every path at once, so injection was
strictly the stronger move against comrade specifically.

**Closed.** Every stream datagram now carries a counter and a tag over itself
and that counter (`src/dataauth.c`), keyed to the connection like the probes,
with the counter judged once by a replay window. KCP is given 24 bytes less of
the budget, so nothing grew on the wire.

**What remains, and the measurement says the choice was wrong.** The KCP header
is still readable: an observer on the path sees segment sizes and sequence
numbers. The reason for a MAC rather than a seal was that it should be cheaper
on a slow target. It is not. Measured on an MT7621 (MIPS 1004Kc, 880 MHz,
monocypher), per 1200-byte datagram:

| | ns/datagram | throughput |
|---|---|---|
| XChaCha20-Poly1305 seal | 84,285 | 14.2 MB/s |
| XChaCha20-Poly1305 open | 84,612 | 14.2 MB/s |
| keyed BLAKE2b (what is shipped) | 121,931 | 9.8 MB/s |

The MAC is 45% slower than the seal on the target it was chosen for. BLAKE2b
works in 64-bit words, which a 32-bit MIPS core emulates in register pairs,
while ChaCha20 is 32-bit-native. On x86 with OpenSSL the seal is also slightly
ahead (1441 ns against 1545). So the seal is faster on both backends measured,
and would hide the KCP header as well.

What stops it being a straight swap is the demux: a stream datagram is told
from a probe by the conversation id in its first four bytes, and sealing the
datagram puts ciphertext there. The shape that keeps both is a cleartext
framing prefix -- `[conv 4][counter 8][sealed datagram + tag 16]`, 28 bytes
against today's 24 -- with the nonce built from the counter. That needs the
counter never to repeat under one key: true under a connection key, which is
unique to a pair, but not automatically true under the invitation's key, which
every connection of a session shares before it binds. Getting that wrong is
silent and total, so it wants deciding rather than assuming. Both constructions
live behind `dataauth.{c,h}`, so the swap is contained once the nonce rule is
settled.

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
