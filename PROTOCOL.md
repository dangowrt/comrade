# comrade protocol and UX specification

Wire-level specification of comrade as implemented in this tree, precise enough
for an independent implementation to interoperate with the C one. Every constant
is cited to its source (`file:function`/`#define`). All multi-byte integers on
the wire are **big-endian** unless stated otherwise.

Layering, outermost to innermost:

```
  token (base58, out of band)
    -> rendezvous: sealed mailbox on DHT (BEP44) and/or LAN multicast
        -> ICE hole punch (libjuice)  |  direct UDP (lanlink, same segment)
            -> KCP reliable stream
                -> SSH (pinned host key, token auth)
                    -> tmux  +  comrade-ctl in-band control channel
```

Sections and paragraphs marked **PLANNED**, with the release the change is
expected in, specify behaviour this tree does not implement yet; everything
unmarked is implemented as described. Each mark is removed when its change
lands.

**Wire compatibility.** Nothing here is stable across 0.1.x. This revision
changes the probe frame (a sequence number, §9), what a datagram opens with
(both tags derived from the token rather than fixed, §2), the stream datagram
(a counter and tag, §9), the mailbox slots (a key in the offer, a box in the
answer, §4), the multicast announcement (the slot letter bound into the seal,
§6) and the control channel (two new message types and a larger frame bound,
§10). Two peers must be built from the same revision; there is no version
negotiation and none is planned before the format settles.

---

## 1. Crypto primitives (`src/ccrypto.h`)

One choke point, backend-selectable (OpenSSL, libgcrypt or monocypher). Outputs
are **byte-identical across backends** except unkeyed 32-byte BLAKE2b
(process-local only, never on the wire). All wire crypto uses only the primitives
below.

- **Ed25519** (RFC 8032): `sk` is `seed(32) || pk(32)` = 64 bytes.
  `cc_ed25519_{key_pair,sign,check}`.
- **XChaCha20-Poly1305**, 24-byte nonce, **Monocypher `crypto_aead_lock`
  layout**: `cc_aead_lock(ct, mac[16], key[32], nonce[24], ad, ad_len, pt,
  pt_len)`. Critical: the MAC is a **separate 16-byte output**, not appended to
  the ciphertext by the primitive; comrade places it between nonce and
  ciphertext (see §4).
- **Keyed BLAKE2b** (RFC 7693 keyed mode, digest length in the parameter
  block): `cc_blake2b_keyed(out, out_len, key, key_len, msg, msg_len)`. Used as
  the KDF and BEP44 seed. Interop-critical.
- **X25519** (RFC 7748): `cc_x25519_public(pk, sk)` and
  `cc_x25519(out, sk, peer)`. A shared secret of all zeros is refused, since it
  means the peer sent a low-order point. Used only to seal a claim to the host
  (§4). Interop-critical, and pinned to RFC 7748's own vector by
  `tests/box_test.c`, because two peers need not share a backend.
- **SHA-1** (`src/sha1.c`, RFC 3174, standard IVs `0x67452301…`), namespaced
  `cc_sha1_*`. Used only for BEP44 target derivation.

### The seal (`src/keys.c:msg_seal`/`msg_open`, `SEAL_OVERHEAD = 24+16 = 40`)

A sealed blob is:

```
  nonce (24 bytes, random)  ||  mac (16 bytes)  ||  ciphertext (len bytes)
```

`msg_seal`: draw 24 random bytes into `dst[0..24]`; `cc_aead_lock(ct=dst+40,
mac=dst+24, key, nonce=dst, ad=NULL, ad_len=0, pt=plain, plain_len)`. No
associated data. `msg_open` reverses it; a bad tag fails. Total length =
`plain_len + 40`. This layout (nonce, then MAC, then ciphertext) is the single
highest-risk interop detail.

`msg_seal_ad`/`msg_open_ad` are the same with associated data: the AD is
covered by the tag while staying in the clear, for framing outside the seal
that decides what the plaintext means (the multicast slot letter, §6).

### The box (`src/keys.c:box_seal`/`box_open`, `BOX_OVERHEAD = 32+16 = 48`)

Sealed **to a recipient** rather than to a shared secret, so that only the
holder of one secret key can open it:

```
  ephemeral public key (32)  ||  mac (16)  ||  ciphertext (len bytes)
```

`box_seal(pk, plain)`: draw an ephemeral X25519 pair `(esk, epk)`;
`shared = X25519(esk, pk)`;
`key = BLAKE2b_keyed(key=shared, len=32, msg="comrade1 claim box" || epk || pk)`;
then `cc_aead_lock(ct=dst+48, mac=dst+32, key, nonce=24 zero bytes, ad=epk,
ad_len=32, pt=plain)`. The nonce is fixed and costs nothing to carry because
the key is fresh for every box and belongs to exactly one recipient; binding
both public keys into the KDF is what makes that true. `box_open(sk, ...)`
recomputes `pk` from `sk`, agrees against the carried `epk`, and fails on a bad
tag. Used for the answer slot (§4).

---

## 2. Key derivation (`src/keys.c:keys_derive`)

All session keys derive from the token's 16-byte rendezvous secret `R`
(`tok.rdv`, `TOKEN_RDV_LEN = 16`):

```
  sig_key(32)  = BLAKE2b_keyed(key=R, len=32, msg="comrade1 sig key")     # 16 bytes, no NUL
  seed(32)     = BLAKE2b_keyed(key=R, len=32, msg="comrade1 bep44 seed")  # 19 bytes, no NUL
  (bep44_pk, bep44_sk) = Ed25519_keypair_from_seed(seed)
```

The two wire tags come from the same secret, so no datagram opens with a
constant that would identify comrade to anyone without the token:

```
  tags(8)      = BLAKE2b_keyed(key=R, len=8, msg="comrade1 wire tags")  # 18 bytes, no NUL
  probe_magic  = tags[0..4]  as big-endian uint32
  conv         = tags[4..8]  as big-endian uint32
  if probe_magic == conv: conv ^= 0x5f5f5f5f

  pb(2)        = BLAKE2b_keyed(key=R, len=2, msg="comrade1 mcast port") # 19 bytes, no NUL
  mcast_port   = 32768 + ((pb[0]<<8 | pb[1]) & 0x3fff)                  # 32768..49151
```

`mcast_port` is the link-local group's port (§6), above the registered range
and clear of the ephemeral one most systems draw from, so it neither squats on
a service nor collides with what else the machine binds.

`probe_magic` opens a probe (§9) and `conv` is the KCP conversation id, and the
demux that tells one from the other is a single compare of the first four
bytes -- so they are forced apart rather than left to chance.

`sig_key` seals every mailbox/multicast payload (§4, §6). `bep44_pk/sk` are the
BEP44 mutable-item identity (§5). Both peers derive the **same** keys from the
same token, so the mailbox is a shared rendezvous only they can read or write.

### Per-connection key (`src/keys.c:keys_conn_key`)

`sig_key` is derived from the invitation, so every guest of a host holds it and
"sealed" never said *which* guest wrote a frame. Once a session exists, the raw
path leaves it behind. Each end draws 32 random bytes and sends them over the
in-band control channel (`CTLM_KEY`, §10), which is a stream inside the
authenticated SSH session under a pinned host key, and both derive:

```
  lo, hi   = the two halves ordered by memcmp (not by role)
  conn_key = BLAKE2b_keyed(key=sig_key, len=32,
                           msg="comrade1 conn key" || lo || hi)   # 17 bytes, no NUL
```

Ordering by value rather than by role is what lets both ends compute the same
key with neither deciding. `conn_key` then seals the probes (§9) and keys the
stream tag (§9), so no other holder of the invitation can reach or read a
connection it is not part of.

The **read-only auth secret** is a one-way derivation of the read-write one
(`src/keys.c:keys_derive_ro_auth`):

```
  A_ro(16) = BLAKE2b_keyed(key=A_rw, len=32, msg="comrade1 ro token")[0:16]
```

the 32-byte keyed digest truncated to `TOKEN_AUTH_LEN = 16` (gcrypt offers
BLAKE2b only at whole standard digest sizes, so the 16-byte secret is a prefix of
the 32-byte hash, not a 16-byte-digest request). A host holding `A_rw` can mint
and accept `A_ro`; a read-only guest cannot walk `A_ro` back to `A_rw`. The
read-only token carries `A_ro` in its `auth` slot with `TOKEN_FLAG_RO` set (§3),
and SSH auth maps it to a view-only attach (§10).

---

## 3. Token (`src/token.c`, `src/token.h`)

Fixed **90-byte** payload (`TOKEN_RAW_LEN`), packed in order:

| field | bytes | meaning |
|-------|-------|---------|
| version | 1 | `TOKEN_VERSION = 1` |
| flags | 1 | see below |
| rdv `R` | 16 | rendezvous secret (KDF input, §2) |
| auth `A` | 16 | session auth secret (SSH password, §10) |
| hostpub | 32 | **SHA-256 of the host's ed25519 SSH public key** (pin) |
| ep6_addr | 16 | v6 endpoint hint (all-zero = absent) |
| ep6_port | 2 | BE |
| ep4_addr | 4 | v4 endpoint hint (all-zero = absent) |
| ep4_port | 2 | BE |

**Flags** (`token.h`):

| bit | name | meaning |
|-----|------|---------|
| 0 `0x01` | `RO` | read-only credential (§2/§10) |
| 1 `0x02` | `NODHT` | **reserved, never set.** Retired: it told the client to drop `SIG_DHT`, which is exactly the wrong thing to do (§5, §11) |
| 2 `0x04` | `EP6_RDV` | the ep6 slot holds a **rendezvous DHT node** rather than a host endpoint |
| 3 `0x08` | `EP4_RDV` | likewise for ep4 |
| 4 `0x10` | `EP6_SETTLED` | the v6 family's state is determined, not still being worked out |
| 5 `0x20` | `EP4_SETTLED` | likewise for v4 |
| 6-7 | | reserved, must be zero |

**Per-family state**. A family's slot and its two bits encode one of four
states. The families are wholly independent: every mix is legal, and a host that
reaches the DHT over one family only is normal rather than degraded.

| slot | `RDV` | `SETTLED` | state | meaning |
|------|-------|-----------|-------|---------|
| all-zero | -- | 0 | `PENDING` | the host has not finished determining this family |
| all-zero | -- | 1 | `NONE` | this family has no path to the DHT |
| set | 1 | 1 | `RENDEZVOUS` | a DHT node holding the host's mailbox, so the client skips cold convergence (§5) |
| set | 0 | 1 | `DIRECT` | the host's own endpoint, **proven reachable from outside** |

A set slot with `SETTLED` clear does not occur; a decoder treats it as settled.

**The state is advisory.** `R` alone is always sufficient: every address in the
token is a hint that skips work, never a precondition, and a client that finds
nothing useful in the slots converges on the mailbox target from the DHT
bootstrap (§5). That is what makes the token safe to re-mint. The host mints one
at t=0 in `PENDING`/`PENDING` and re-emits on every state change, so an
already-copied string is a snapshot that is never wrong, only sometimes slower.
No token state ever instructs a client to disable a transport.

**`NONE` has two causes**, which the host separates locally for the operator but
does not encode:

- **deliberately isolated**: no default route for the family, so the DHT is
  unreachable by construction and the state settles at once;
- **actually isolated**: a default route exists but does not work -- a broken
  gateway, filtered UDP, an infrastructure outage -- so the state settles only
  once the DHT attempt has run its course.

An operator may also decline the DHT outright with `--no-dht` (§13), which
settles both families to `NONE` as soon as the local addresses are known.

**`DIRECT` requires proof** *(PLANNED, 0.2.0)*. The slot is specified and its
encoding fixed, but nothing in 0.1.x may mint it: a host cannot tell whether one
of its own ports is reachable from a stranger's address without an external
prober, and a UPnP/NAT-PMP/PCP mapping reporting success is not that proof,
because a CGNAT gateway will happily report a mapping on an address nothing can
reach. The intended prover is the RFC 5780 filtering test, which uses the
`OTHER-ADDRESS` attribute (there is no `OTHER-SERVER`). Until it exists every
globally connected family mints `RENDEZVOUS` and no address of the host's own
ever enters a token.

Note what that test can and cannot establish. It shows that *one* third party --
an address and port chosen by the STUN operator, not by us -- can reach the
mapped port unsolicited. That is real evidence, and it is strictly weaker than
"reachable from an arbitrary stranger", which is the claim a `DIRECT` slot makes
to every holder of the token. `DIRECT` must therefore not displace `RENDEZVOUS`
wherever `RENDEZVOUS` also works: the rendezvous is the path that survives a
firewall changing its mind, and the token has only one slot per family to say it
with.

Wire form: payload(90) `||` **CRC-32/IEEE** over the payload (4 bytes, stored as
two BE `put16` halves `sum>>16`, `sum&0xffff`) = `TOKEN_WIRE_LEN = 94`.
`crc32` is the standard reflected `0xedb88320` variant, init `0xffffffff`,
final XOR (`token.c:crc32`); integrity only, not security.

String form: **base58** of the 94-byte wire (`src/base58.c`, Bitcoin alphabet
`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`), then
**left-padded with `'1'`** to a constant `TOKEN_STR_LEN = 94*138/100+1 = 130`
characters. Decode requires exactly 130 chars, base58 back to 94 bytes, a CRC
match, and `version == TOKEN_VERSION` (`token.c:token_decode`). A decoder
**must** make that last check, so that a future revision of the format fails
cleanly on an older build instead of being misparsed as this one.

---

## 4. Rendezvous mailbox (`src/mailbox.c`, `src/sig.c`)

One shared mailbox. The container is a **bencoded dict** with keys in
sorted order (`mailbox.c:mailbox_build`):

```
  d [ 1:a <sealed answer> ] [ 1:o <sealed offer> ] [ 1:x <sealed tombstone> ] e
```

- `o` (offer) is written by the **host**, `a` (answer) by the **client**, `x`
  (tombstone, §4.1) by the host as it goes. `o` and `x` never stand together,
  so the item carries at most two sealed slots at a time.
- Each slot value is a **sealed blob** (§1) under `sig_key`, but the offer and
  the answer do not carry the same thing:

```
  offer  = seal(sig_key,  claim_pk(32) || candpack )
  answer = seal(sig_key,  ulen(1) || ufrag(ulen) || box(claim_pk, candpack) )
```

- `candpack` is the compact ICE description (§7). For the DHT it is packed with
  `for_dht=1` (segment-local addresses dropped).
- `claim_pk` is an X25519 public key the host mints once per signaller and whose
  secret half it alone holds. **A claim is boxed to it** (§1), so the outer seal
  still says a token holder wrote the slot -- which is what the container's
  compare-and-swap rests on -- while only the host can read where a claimant
  is. Every holder of the invitation can read the mailbox, and a read-only link
  is the one handed to a room, so without this a crowd of mutually untrusting
  guests published its addresses to itself.
- The claimant's **ufrag rides in the clear** beside the box. The rule that lets
  a client overwrite its own superseded claim is about which claimant holds the
  slot, not where it is; a client cannot open even its own box, the ephemeral
  secret being gone the moment it is sealed.

Publishing (`sig.c:sig_post` → `sig_stage`): pack the local SDP → `candpack`,
then build the slot value for this role and seal it. A client can only box once
it has seen the host's slot, so the value is built **when it can be** rather
than when it is posted; nothing is lost by waiting, because a write is only ever
decided against a container that has been read
(`mailbox.c:recompute_need_write`). Reading a peer slot: `msg_open(sig_key, …)`
→ `slot_unwrap` (take `claim_pk` as a client, open the box as a host) →
`candpack` → rebuilt SDP handed to libjuice.

What this does **not** hide is occupancy: the slot being non-empty is the
turnstile mutex (§12), so any holder can still see a claim is in progress and
can still take the slot. Closing that would mean single-use or per-guest
mailboxes, and the one-token-one-BEP44-key property is worth more than
protecting against an authenticated holder delaying an exchange it can no
longer read.

The host can release the answer slot on offer rotation
(`mailbox.c`: `clear_peer` drops `a` once, `mailbox_arm_release`).

### 4.1 Tombstone: the session has ended

An invitation says where to meet a host that is still there and, on its own,
can say nothing else -- so a token outliving its session sends every holder
into a wait with no end. The `x` slot is the missing answer.

```
  tombstone = seal(sig_key, version(1) = 1)
```

- The **host** writes it as the session ends (`sig_end`, from
  `session.c:session_entomb_start`), replacing the container: no offer to answer and
  no claim to serve, since a session cannot be both live and over. It is sealed
  like every other slot -- not because that makes it unforgeable among the
  holders of the invitation, but because a passer-by should learn no more from
  the end of a session than from the rest of it.
- It is published from **inside the session**, while the rendezvous node is
  still warm and pinned; a process that had already torn its signalling down
  would have to converge on the DHT from cold to say one word. Both routes are
  used and **both are waited for** (`sig_end_placed`): the direct store reaches
  the node a token names, and the convergent store reaches whoever is closest to
  the key -- which is where a token naming no node leads a client, and where
  this host's own last offer is sitting. Leaving before the second lands leaves
  that offer standing, and a client that finds it punches at nothing. They go
  out **one at a time**: both are read-modify-writes of the same mutable item,
  so two in flight read the same sequence, write the same next one, and every
  node refuses the second on the compare-and-swap it has just lost -- which
  reads back as one route having reached nothing at all.
- A **live host erases** any `x` it reads (`recompute_need_write`), which is
  what makes the slot self-healing. Every holder of the invitation can write
  this container, so a forged tombstone must not outlive the next write of the
  host it lies about -- roughly a second, while one is serving.
- A **client** therefore does not act on first sight. `sig_peer_ended` believes
  the slot once it has stood `SIG_TOMB_SETTLE_MS` (4 s) with no offer seen
  since, timed from when it was **first** seen rather than most recently, so
  the clock runs out rather than restarting on every read. A read with no
  tombstone puts the clock back. The cost of forging one is therefore a joiner's
  pause, not the session.
- It is a **DHT-only** thing, because only the DHT holds anything once the host
  is gone. Link-local discovery is a conversation and not a store: a message
  left there reaches whoever happens to be listening at that instant, which is
  the peers already connected -- and those are told inside their own session,
  where the statement cannot be forged. On an isolated LAN a session that has
  ended is a segment where nobody is offering, which is also what a session that
  never started looks like, and there is nothing truthful to say about the
  difference. So a LAN-only host stops announcing and says nothing more, and
  `sig_end_placed` has nothing to wait for.

The tombstone is the slower of the two ways a client learns this, and the only
one that reaches a client that was never connected. A client that **is**
connected is told over the control channel first (`CTLM_BYE`, §10).

---

## 5. DHT rendezvous / BEP44 (`src/bep44.c`, `src/dhtnode.c`, `src/sig.c`)

Standard BitTorrent mainline DHT (jech/dht for the Kademlia routing) with
**BEP44 mutable items** implemented in-tree (`src/bep44.c`); jech/dht itself
carries no BEP44 support.

- **Salt**: `SIG_SALT = "m"` (`sig.c`), one shared mailbox per token.
- **Target** (`bep44.c:bep44_target`): `SHA1( bep44_pk[32] || salt )` = 20 bytes.
- **Signed buffer** (`bep44.c:bep44_sig_buffer`), exactly:
  `4:salt<len>:<salt> 3:seq i<seq>e 1:v<raw value>` (the `salt` fragment omitted
  when empty; here salt is `"m"` so `4:salt1:m`). `<raw value>` is the mailbox
  container dict from §4, inserted verbatim after the `1:v` marker.
- **Signature**: `Ed25519_sign(bep44_sk, signed_buffer)` = 64 bytes.
- **put** KRPC (`bep44.c:put_send`), `a` dict keys in sorted order:
  `cas` (opt), `id`(20, node id), `k`(32, `bep44_pk`), `salt`(`"m"`),
  `seq`(int), `sig`(64), `token`(write token from the node), `v`(raw container).
- **seq/cas rule** (`bep44.c`): a put with a prior value already observed uses
  `seq = best_seq + 1` and `cas = best_seq` (compare-and-swap against the last
  seen seq); a first put with no prior value uses `seq = 1` and omits `cas`. Both
  roles put and both use CAS -- the host on offer rotation, the client on the
  answer write -- not the client alone.
- **Transaction id** (`bep44.c:tid_bytes`): every KRPC query tags `t` with four
  bytes, `'p' 'm'` then a **16-bit little-endian** per-request counter; a reply is
  matched back to its pending request by that id.
- **get/put targeting**: both peers converge on the k-closest nodes to `target`
  (evict farthest, not refuse newcomers, or the sets diverge and the get
  misses). The chosen rendezvous node(s) can be embedded in the token
  (`EPx_RDV`) so a client skips cold convergence.

Turnstile / mutex (host, `session.c:host_turnstile`, `mailbox.c`): the host
advertises one offer at a time with a fresh ICE identity; a client claims by
writing its sealed answer into slot `a` (CAS). `mailbox_claim_status` →
`FREE`/`HELD`/`BUSY`; `mailbox_client_should_claim` gates the write. The host
rotates the offer and releases `a` **on pickup** (when it adopts the claim), not
after the punch completes; see §12. Workers run concurrently.

Timings (`sig.c`): `SIG_DHT_GET_MS 1000`, `SIG_DHT_PUT_MS 1000`,
`SIG_DHT_RESTORE_MS 8000`, `SIG_DHT_GRACE_MS 2000`, `SIG_DHT_OPEN_MS 1000`.

**Engagement is unconditional**. A session engages the DHT after
`SIG_DHT_GRACE_MS` whatever else has happened, on both roles, and keeps it
running for the session's whole life. A multicast announcement arriving first
does not suppress it. The DHT is the only rendezvous that survives a change of
network, so it has to be running *before* the change rather than started after
it: a host and a client that meet on an isolated LAN and later roam apart depend
on a mailbox published while they were still together, and on the warm
rendezvous nodes they exchanged over `CTLM_RDV` (§10, §11). A LAN-only session
therefore pays a socket and periodic bootstrap traffic that will not succeed;
that is the price of being able to leave the LAN, and the only opt-out is the
operator's explicit `--no-dht` (§13).

---

## 6. Multicast / lanlink (`src/sig_mcast.c`, `src/lanlink.c`)

For isolated LANs, the same sealed candpack is announced over link-local
multicast, plus a direct UDP transport port.

Multicast (`sig_mcast.c`):
- Groups: v6 `MCAST_V6 = ff02::da7a`, v4 `MCAST_V4 = 224.0.0.224`. The **port
  is this session's**, derived from the invitation (§2), not a constant: on a
  fixed port every comrade session sharing a segment lands in one conversation,
  hearing every other's announcements, opening none of them and paying for all
  of them. `MCAST_PORT = 47654` remains only as the fallback for a caller with
  no session to derive from (the `mcast-probe` interface check).
- Packet: `MCAST_MAGIC "pMc1"` (4 bytes) `|| salt_len(1) || salt || payload`.
- **Salt = the sender's own role slot character**: `"o"` (host) or `"a"`
  (client); a receiver listens for the *peer's* slot char (`sig.c` `peer_slot`,
  `ps`).
- `payload` = `seal_ad(sig_key, ad=salt(1), mcast_plain)`. The salt frames the
  value on the wire outside the seal and is what says whether a description is
  an offer or an answer, so it is **bound into the tag**: without that, a frame
  captured from one slot opens in the other and a client can be handed its own
  description as the peer's.
- `mcast_plain` (`sig.c:sig_stage`) = `direct_port(2, BE) || slot value`, where
  the slot value is **exactly what the DHT slot carries** (§4) -- `claim_pk ||
  candpack` from a host, `ulen || ufrag || box(...)` from a client -- built from
  the same packed buffer, not a wider `for_dht=0` one. So a claim announced on
  the segment is sealed to the host just as one in the mailbox is. The peer takes
  the sender address from the packet source and the direct port from the payload.

**Role split on receive** (`sig.c:deliver_peer_mcast`): both roles adopt an
endpoint only from a packet whose seal verifies under `sig_key` **and** whose
source is **LAN-scope** (`addr_is_lan_scope`: link-local, RFC1918
`10/8` / `172.16/12` / `192.168/16` / `169.254/16`, ULA `fc00::/7`, and loopback
`::1` / `127/8` for a same-host peer). The source class is not the trust boundary -- the
seal is; it only decides who gets the ICE-free bypass. A **client** feeds the
candpack to its ICE agent and learns the host's direct endpoint. A **host** that
demultiplexes the shared lanlink socket (`mcast_claims`) does **not** feed the
candpack to its ICE turnstile -- it can serve a same-segment claimant directly
over lanlink, so punching it too would serve the client twice; instead the
claimant's `(source, announced-port)` becomes a direct claim (§12). The v6 zone
id is preserved for a link-local peer.

lanlink (`src/lanlink.c`): a single dual-stack (`IPV6_V6ONLY=0`) UDP socket
carrying KCP directly with no ICE; v4 peers kept v4-mapped. It is no longer
session-global 1:1. The **host binds one shared lanlink socket on one advertised
port** (`sig_set_direct_port` from `lanlink_port`), the single `direct_port` in
every offer. The **peer is a property of the connection, not the socket**: each
`struct conn` holds its own path table (§9), and `transport_send` sends its KCP
over the shared socket to the endpoint of the path in use while a connection
carried by ICE uses its own agent, so the two coexist -- and one connection may
hold both kinds at once. The host demultiplexes inbound datagrams by source on
its main thread (`lanlink_dispatch` uses `recvfrom`; `host_lan_recv` matches the
source against the paths of the connections it serves, `sess.conns[]`, and
delivers into the owning worker's stream under a per-conn lock); a source no
connection holds is offered to adoption (§9). A client accepts on the one
socket whatever the source, since it holds one peer.

The socket is created with the multicast transport (`session.c:sig_setup`), so a
session that declines multicast has no direct transport, and therefore no
`SEGMENT` or `ROUTED` path, at all.

---

## 7. Candidate policy (`src/candpolicy.c`) and candpack (`src/candpack.c`)

Policy defaults (`cand_policy_default`): keep private v4; **drop** ULA
(`fc00::/7`), overlay (`0200::/7` Yggdrasil / cjdns), EUI-64 global v6
(`ff:fe` interface id), link-local, loopback. v6 kept only if global-unicast
(`2000::/3`) and non-EUI-64. (Scope classification for the dashboard lives
separately in `session.c:addr_scope`, which also treats `fe80::/10`,
`fec0::/10` site-local and `fc00::/7` as LAN.)

candpack binary layout (`candpack.c`, `CANDPACK_VERSION = 1`):

```
  version(1)=1 | ufrag_len(1) | ufrag | pwd_len(1) | pwd | ncand(1)
  ncand *   [ type(1) | family(1) | prio(4,BE) | port(2,BE) | addr(4 or 16) ]
```

`type`: `0 host, 1 srflx, 2 prflx, 3 relay`. `family`: `4` or `6`. Only
`component 1`, `UDP` candidates are packed. Decode rebuilds
`a=ice-ufrag:…\na=ice-pwd:…\n` and one `a=candidate:<idx> 1 UDP <prio> <addr>
<port> typ <type>[ raddr 0.0.0.0 rport 0]\n` per candidate (foundation = index).

---

## 8. ICE / NAT (`src/nat.c`, libjuice 1.7.3)

libjuice agent per connection: gather → exchange the bundled SDP as candpack via
the mailbox/multicast → connectivity checks → connected/failed. STUN
server-reflexive candidates gathered from the community STUN pool
(`src/stunlist.c`, baked-in list). Nested NAT handled by publishing the private
v4 (mailbox sealed) + libjuice RFC 8445 peer-reflexive source learning. KCP
output sends via the peer's own agent (`juice_send` targets that agent's
remote).

---

## 9. KCP transport (`src/stream.c`, kcp 2.1.1)

Exact config (`stream_create`), **all must match for interop**:

| parameter | value | call |
|-----------|-------|------|
| conv | `keys.conv`, derived per session (§2) | `ikcp_create(conv,…)` (`stream.c`) |
| MTU | `STREAM_MTU - STREAM_OVERHEAD = 1200 - 24 = 1176` | `ikcp_setmtu` |
| window (snd/rcv) | `STREAM_WND = 1024` / 1024 | `ikcp_wndsize` |
| nodelay | 1 | `ikcp_nodelay(kcp, 1, 10, 2, 0)` |
| interval | 10 ms | ” |
| fast resend | 2 | ” |
| no-congestion (nc) | 0 (**congestion control ON**) | ” |
| stream mode | 1 | `kcp->stream = 1` |
| dead_link | `STREAM_DEAD_LINK = 1000` | `kcp->dead_link` |

`conv` is derived from the token (§2), not a constant, so a datagram's first
four bytes say nothing about which program sent it. `stream=1` means byte-stream
(not message) framing. `stream_update` drives `ikcp_update`/`ikcp_check`; a
finished receiver LINGERS on `ikcp_waitsnd` until its own sent tail is acked.

KCP is given 24 bytes less than the wire budget because the transport puts a
counter and a tag under every datagram, so nothing grew on the wire.

### Stream datagram origin (`src/dataauth.c`)

KCP carries SSH, so its bytes are already unreadable on the path; what they
lacked was any statement of who sent them. That matters more here than
elsewhere: dropping is what the path model survives by moving, while a forged
segment corrupts the byte stream and ends the SSH session above **every** path
at once, so injection is strictly the stronger move against this design.

```
  [kcp datagram][counter(8, BE)][tag(16)]      DATAAUTH_OVERHEAD = 24
  tag = BLAKE2b_keyed(key, len=32, msg = kcp datagram || counter)[0:16]
```

The key is the connection's (§2) once both ends have agreed one, and `sig_key`
before that. The tag goes **last** so a datagram still opens with `conv`, which
is what tells stream data from a probe. The counter is covered by the tag, so a
frame cannot be replayed under a different number, and is judged once by the
same sliding window as the probes (`src/replay.c`, 64 wide). It is seeded from
the clock rather than from one, for the reason given for the probe sequence
below. Comparison of the tag does not say where two differ.

It authenticates and does not encrypt: sealing instead would hide the KCP
header, whose segment sizes and timing are on the wire regardless, and cost 40
bytes rather than 24. On an MT7621 (MIPS 1004Kc, monocypher) the seal is in
fact the *faster* of the two -- 84 us against 122 us per 1200-byte datagram,
BLAKE2b working in 64-bit words that a 32-bit core emulates in pairs -- so if
the trade is ever revisited, overhead is not the argument for the tag.

---

### Path model and transport probe (`src/path.c`, `src/session.c`)

A **path** is a pair (local transport instance, remote endpoint) over which
sealed datagrams for one connection can be sent. Three kinds exist:

| kind | local transport | remote endpoint |
|---|---|---|
| `SEGMENT` | the shared lanlink socket (§6) | a peer endpoint on the link, learnt from a sealed multicast announcement |
| `ROUTED` | the shared lanlink socket | any other peer endpoint, learnt from a probe that arrived from it |
| `ICE` | a libjuice agent (§8) | its nominated pair |

A connection can hold **two** ICE agents at once: a resume replaces the agent,
and the one being replaced is not known to be dead -- it stopped answering,
which is also what a drop lasting a moment looks like. It is set aside with its
path rather than destroyed, for one claim's worth of time, so the ranking can
find it still alive and keep carrying on it; libjuice reports no source with a
datagram, so the agent that received one is the only thing that says which path
it arrived on, and that identity is carried from the transport callback through
to the path lookup (`session.c`, `struct ice_ctx`).

The kind is a description, not a rank: it names how a path was come by and
nothing else, and plays no part in choosing between paths. A connection tracks up
to `PATH_TABLE_MAX` of them and carries KCP over exactly one at a time.

Path management is **symmetric and role-free**. comrade's application model has a
host and a client -- one owns the tmux, one claims the turnstile (§12) -- but
that asymmetry ends at admission. Both ends run identical path code: both probe,
both measure, both rank, and both arrive at the same choice without either
deciding for the other.

**Invariants.**

1. A path carries the session only once a probe has round-tripped on it. Nothing
   else qualifies a path: a transport reporting a pair says that packets move,
   not that the far end is serving *us* (§12). This governs **adoption**, which
   is every send after the first exchange.
2. Every end accepts stream data on **every** path it holds, not only the one it
   sends on. Selection is therefore never a negotiation, and a transient
   disagreement costs nothing but a moment of asymmetric routing.
3. All obtainable paths are kept **warm**, not merely the one in use, so a switch
   is an immediate reordering rather than a rediscovery.
4. A host **speaks first**, on its best path whatever its qualification state.
   This is the single exemption to invariant 1 and is bounded to it: the opening
   send is not the session being carried, it is the stimulus that creates the
   round trip, and the client's proof of the path is that banner arriving.
   Qualification reorders paths; it never gates the first send.
5. **Ordering is total, so both ends always agree**, even before any measurement
   exists: qualified paths before unqualified, then by cost, then by the lowest
   `id(P)`. At t=0 nothing is qualified and no cost is known, so the order falls
   through to the id -- deterministic, role-free and identical on both ends.
   "Purely by measurement" governs from the first measurement onward.

#### Probe frame

```
  [4 magic][seal(key, plain)]                  magic = keys.probe_magic (§2)

  plain = [1 type][8 nonce][8 seq][1 ulen][ulen claimant ufrag]   head, 18+ulen
          [16 addr][2 port BE][2 srtt_ms BE][2 loss_ppt BE]       tail, optional
  type: 1 = PING, 2 = PONG (echoes the nonce), 3 = FRESH
```

`deliver_stream_from()` splits probes off ahead of `stream_input()`: every KCP
datagram opens with `conv` and the magic is forced to differ from it (§2), so a
datagram opening with the magic is unambiguously not stream data. Neither value
is a constant, so neither identifies comrade to anyone without the token.

The 22-byte tail is present when the plaintext runs past `18 + ulen`; a peer
that omits it merely shares no measurements, which costs accuracy and never
correctness. A `FRESH` carries a tail it never reads, so that the one datagram
which ends a session is not also the only short one on the wire.

**`seq` counts this sender's frames on this connection.** The seal says a frame
was written by a key holder; it never said *when*, so a copy taken off the wire
could be opened again whenever its holder chose. The receiver keeps a 64-wide
sliding window (`src/replay.c`) and acts on each sequence once. The counter is
seeded from the clock, not from one: a host that reaps a worker serves the
returning client from a new connection while the client keeps its window, so a
counter starting over is exactly what a replayed frame looks like.

**Which key seals it.** Before the two ends have agreed a connection key it is
`sig_key`, which every holder of the invitation has. After (§2) it is
`conn_key`, and the invitation's key then opens only two things: any frame in
the moment before the far end has switched too, and a `FRESH`, which by
construction comes from a worker the host started after reaping the one we had
and so shares no key with us. A `FRESH` is still refused unless it arrives on a
path this connection is actually carried on. The switch is clocked by the peer
rather than by a timer -- see `CTLM_KEYOK` (§10) -- because the halves that
derive the key travel over the stream the key protects.

- **addr/port** is the source this path's last inbound datagram was observed
  arriving from, v4 carried v4-mapped, all-zero when nothing has arrived yet. On
  a PONG it is the source of the PING being answered, so a prober learns its own
  reflexive endpoint on that path for free. That echo is also the groundwork the
  RFC 5780 work in §3 builds on. An `ICE` path has no observed source to give:
  libjuice's receive callback carries none, so the remote of the pair it
  nominated stands in (`session.c:conn_ice_ep`), which is right except between a
  re-nomination and the next report -- and a wrong echo costs a tie-break, never
  a delivery.
- **srtt_ms** is the sender's current smoothed round trip for this path, 0 when
  unmeasured; **loss_ppt** its probe loss in parts per thousand.

The seal under `sig_key` was never a defence against another holder of the
invitation, only against a stranger who can guess an endpoint; the connection
key is what makes a frame provably from *this* peer. The **nonce must be
unpredictable**, being what stops a PONG being guessed rather than replayed, and
a PING carrying a nonce this end is itself waiting on is refused -- otherwise
the handler is an oracle that re-signs any nonce shown to it.

The **claimant ufrag** ties a frame to one connection: a host worker answers only
for the claimant it was admitted for, and that single test separates the winner
of a turnstile round from the losers whose checks its agent answered on the way
past (§12). A client fills it with its own ICE ufrag and a host with the
claimant's, so both ends hold the same string and the exchange is symmetric.

#### Path identity

Both ends must name a path identically without either being "first". Each knows
the remote endpoint directly and learns its own reflexive endpoint from the PONG
echo, so both hold the same unordered pair:

```
  E     = addr(16) || port(2)                                 18 bytes each
  id(P) = cc_blake2b_keyed(sig_key, min(Ea,Eb) || max(Ea,Eb))  -> 32 bytes,
          of which the first 8 are the id
```

`min`/`max` are plain byte comparisons, so the value is order-free and no role
appears in it. Keyed BLAKE2b is the primitive from §1; nothing new is
introduced. Take the natural 32-byte digest and truncate -- do **not** ask for an
8-byte digest, which the libgcrypt backend cannot produce.

#### Qualification, warmth and measurement

One probe is outstanding per path, carrying its own nonce and send timestamp, so
a round trip is measured from the probe that was actually answered, and the next
probe on a path waits for the outstanding one to be answered or to pass its loss
deadline.

| state | condition |
|---|---|
| `UNQUALIFIED` | never answered |
| `WARM` | answered within `PATH_WARM_MS` |
| `COLD` | qualified once, silent for longer than `PATH_WARM_MS` |
| `DEAD` | silent for longer than `PATH_DEAD_MS` |

Per path each end keeps a smoothed round trip (EWMA, alpha 1/8), a loss ratio
over the last 16 probe outcomes, and the time of the last PONG. A probe becomes
a **loss** outcome only once it has been outstanding longer than
`max(3 * srtt, 1000 ms)`: scoring a superseded probe as lost the moment the next
one is sent would score 100% loss on any path whose round trip exceeds the probe
period, condemning a working path for being slow. It probes an
unqualified path every `PROBE_EVERY_MS` and a qualified one every `PATH_KEEP_MS`,
the path in use included: the ctl heartbeat (§10) measures the session end to
end, not any individual path.

#### Ranking and symmetric selection

Ranking is **purely by measurement**. Class plays no part: a segment path wins
because it measures lower, and where it does not measure lower the measurement is
right and a class rule would have been wrong.

Because a probe measures a round trip, both ends observe roughly the same value
for the same path, and each publishes its own view in the tail. Each then ranks
over the **pair** of views through a commutative function, so both compute the
same number from the same data:

```
  cost(P)   = max(srtt_local, srtt_peer)
              + PATH_LOSS_PENALTY_MS * max(loss_local, loss_peer) / 1000
  bucket(P) = floor(cost(P) / PATH_COST_QUANTUM_MS)
```

`floor`, so costs within one quantum of each other share a bucket. Rounding up
would put 0ms and 1ms a whole bucket -- the switch margin -- apart, at exactly
the boundary where a LAN's measurement noise lives, and equal paths would
drift.

A path whose local transport cannot carry a datagram at that moment -- an `ICE`
path whose agent has nominated no pair -- is not a candidate at all rather than
a poor one, and an incumbent that becomes one is left immediately, exactly as a
`DEAD` one is. That is a fact about the transport, not a rank, and it is the
only thing besides measurement that keeps a path out of the running.

Selection takes the lowest `bucket` among the paths in the best occupied warmth
tier (`WARM`, else `COLD`), ties broken by the lowest `id(P)`. That is the whole
of the agreement: **consensus by deterministic function over shared observations,
not by handshake.** No leader, no vote, no role. Quantisation and the id
tie-break are what keep measurement noise from splitting the two ends.

Divergence remains possible while a measurement update is in flight, and is
harmless by invariant 2.

**Switching** is immediate when the path in use goes `DEAD`. Otherwise a
candidate must win by `PATH_SWITCH_MARGIN` buckets for `PATH_SWITCH_HOLD`
consecutive evaluations, so near-equal paths cannot flap. Selection is evaluated
once per `PATH_KEEP_MS`, which is what gives `PATH_SWITCH_HOLD` its unit. The
margin-and-hold applies only **between paths in the same warmth tier**: a
demotion of the incumbent is immediate and ungated, so a dying path never holds
the session for extra evaluations at exactly the wrong moment. Both ends apply
the identical rule to the identical numbers and so flip together.

| constant | value | meaning |
|---|---|---|
| `PATH_TABLE_MAX` | 4 | paths tracked per connection |
| `PROBE_EVERY_MS` | 200 | probe period while unqualified |
| `PATH_KEEP_MS` | 1000 | probe period once qualified, every path |
| `PATH_WARM_MS` | 3000 | silence beyond this: `WARM` becomes `COLD` |
| `PATH_DEAD_MS` | 8000 | silence beyond this: `COLD` becomes `DEAD` |
| `PATH_LOSS_PENALTY_MS` | 200 | cost added by total loss |
| `PATH_COST_QUANTUM_MS` | 5 | ranking bucket width |
| `PATH_SWITCH_MARGIN` | 1 | buckets a candidate must win by |
| `PATH_SWITCH_HOLD` | 2 | consecutive evaluations it must hold (one per `PATH_KEEP_MS`) |
| `PATH_ADOPT_RATE` | 8/s, depth 8 | token bucket for unknown-source probes, per listening socket |

#### Adding a path mid-session

A sealed PING naming a connection's claimant ufrag **adds a path** for that
connection, whatever source it arrives from (`session.c:probe_apply`). This is
what lets an end whose address changed keep the session: it simply probes from
the new source, and the peer picks the new path up. The new path's kind follows
the source -- `SEGMENT` for a LAN-scope one, `ROUTED` otherwise -- which names
how it was come by and changes nothing about how it ranks.

The rule is **add, never replace**. A new endpoint enters the path table as one
more candidate and ranking decides whether it carries anything (§9 "Ranking and
symmetric selection"); it never displaces the endpoint in use. A late datagram
from an address that has gone away therefore cannot flap the binding: the stale
path simply cools, and is evicted when the table is full at `PATH_TABLE_MAX`. What
goes then is the worst-ranked path that is not carrying the session, oldest
`DEAD` first and oldest first between equals -- never the path in use, and never
the newcomer, since a probe that arrived is evidence its source works where a
path that has stopped answering is evidence of the opposite.

**Why the ufrag suffices.** It is not a secret between token holders -- it
travels in the mailbox slot every holder of `R` can read and unseal (§4, §12) --
and it does not need to be. Everyone holding a token can reach the machine
anyway, and the read-only grade shares the same `R`, so `sig_key` and every
capability it confers (mailbox reads, sealed announcements, turnstile claims) are
already common to both grades. Disruption between token holders is out of scope;
the boundary the seal defends is the **stranger**, who holds no `R`, can seal
nothing, and cannot attach to anything.

A host has many connections and the source names none of them, so it is the
claimant ufrag inside the seal that says which one the path belongs to: the host
keeps the connections it serves in `sess.conns[]`, registered at admission and
cleared before the connection is freed, and matches the ufrag against them
(`session.c:probe_adopt`). A client has one connection and needs no such lookup.

A host has many connections and, once each has agreed its own key (§2), the
frame is opened against them in turn until one opens: which connection a frame
belongs to is answered by **which key opens it**, and the ufrag inside then has
to agree. A worker that has bound will not open a frame meant for another, which
is the point of binding.

**Bounding the cost.** Only a frame opening with this session's `probe_magic`
is a candidate at all; a frame from an endpoint the connection already holds is
free; and everything else must pass two token buckets before any AEAD work,
consulted **before** the open rather than after (`session.c:probe_gate`):

- `adopt_allow_src` -- a `PATH_ADOPT_RATE` bucket **per source endpoint**, in a
  small ring, so one address flooding spends only its own budget;
- `adopt_allow` -- the session-wide bucket behind it, the ceiling on the whole
  of this work.

The per-source bucket is what the shared one alone could not give: without it a
single spoofing source spends the budget every real peer needs. Both belong to
the listening socket and are touched only by the thread that dispatches it.

The cost of one admitted junk datagram is now **up to one open per live
connection** rather than exactly one, since the connections no longer share a
key. That is the price of a claim being unreachable by other guests, and it is
why the buckets sit in front of it rather than behind.

**What this does and does not recover.** It recovers an address change that
leaves the peer's endpoint reachable: a DHCP renewal, a move between interfaces
on one segment, a multi-homed end bringing a second address up. It does not
recover a move to a network from which the peer's endpoints are unreachable at
all; that still needs fresh signalling, which is what the always-engaged DHT of
§5 and the warm rendezvous nodes of §11 exist to make quick.

Paths are not only discovered by accident, either. Each end advertises its own
local candidate endpoints over comrade-ctl (`CTLM_CAND`, §10) and probes every
endpoint the peer advertises, so both ends explore the full set rather than only
the pair admission happened to produce (`session.c:cand_tell`,
`session.c:conn_offer_path`). A multi-homed end therefore has its alternatives
already `WARM` before anything fails, which is invariant 3 applied to discovery
rather than only to upkeep.

The port an advertised endpoint names is the **shared lanlink socket's**: that
is the one transport able to send to an arbitrary endpoint, so an advertisement
always yields a `SEGMENT` or `ROUTED` path and never an `ICE` one. The addresses
are the local interfaces', less loopback (which names this machine to nobody
else) and IPv6 link-local (which travels without the zone id it cannot be
reached without). A session with no lanlink socket advertises nothing.

An advertisement is a **claim, not evidence**: nothing has been seen to arrive
from the endpoint it names. It is therefore admitted only into a free slot, or
one a `DEAD` path is holding, and is otherwise declined
(`path.c:path_table_offer`) -- where a probe that *arrived* displaces the
worst-ranked path above. A peer with more addresses than `PATH_TABLE_MAX` can then
name them all without churning the paths that are answering, and can never
touch the one in use.

A declined endpoint is not lost, and that is what makes the conservative rule
safe. If it works at all, the peer's own probe reaches this end from the source
that reaches it, and adoption -- which is evidence -- takes the slot the claim
could not. The advertisement is an accelerator: it is how an endpoint gets
warmed *before* it is needed, not the only way one is ever found.

---

## 10. SSH session (`src/sshd.c`, `src/sshc.c`, `src/sshbridge.c`)

libssh server (host) and client (joiner) over the KCP byte stream
(`sshbridge.c` couples a socketpair fd to KCP with buffered backpressure and a
bounded-linger teardown).

- **Host key**: host mints an ephemeral **ed25519** key; the token's `hostpub`
  is `SSH_PUBLICKEY_HASH_SHA256` of that key (`sshd.c:sshd_hostkey_new`,
`sshc.c:pin_hostkey`).
- **Pinning** (`sshc.c:pin_hostkey`): the client compares the server key's
  SHA-256 to `hostpub`; mismatch is a hard failure. No TOFU.
- **Auth** (`sshd.c:do_auth`, `sshc.c`): password auth only; the password is
  `base64url(A[16])` (`src/base64.c`, alphabet `A-Za-z0-9-_`, **no padding**,
  16 bytes → 22 chars), compared **constant-time** (`ct_equal`). The host accepts
  either `base64url(A_rw)` or `base64url(A_ro)` (§2); a match on the read-only
  secret marks the session read-only. Both candidates are the same length, so the
  length gate leaks nothing about which, if either, was presented.
- **Connector** (`sshd.c`): default remote command
  `tmux new-session -A -s comrade`, run via `execl("/bin/sh","sh","-c",cmd)` on
  an allocated pty; a read-only session instead runs
  `tmux -S <sock> attach -r -t comrade` (`host.c`), a view-only attach that
  cannot type into the session; the host also refuses all `-L`/`-R` port
  forwarding for the read-only grade, so a view-only guest cannot make the host
  `connect()` outbound. TERM/rows propagated (the host keeps tmux one row short
  to reserve the client status line). `--no-forwarding` additionally declines
  all `-L`/`-R` for every grade.
- **Port forwarding** (`src/sshfwd.c`, `src/fwdspec.c`): OpenSSH `-L`/`-R`
  semantics as ordinary SSH channels, spec `[bind:]port:host:hostport`.

### comrade-ctl in-band control channel (`src/ctlproto.c`)

A second SSH channel carries heartbeat, roam re-signal and the end of the
session. Framing (no magic, no per-message checksum; the SSH channel provides
integrity):

```
  frame = type(1) | len(1) | payload(len)
```

Message types (`ctlproto.h`): `CTLM_PING 0` payload `timestamp(8, BE)`;
`CTLM_PONG 1` payload echoed timestamp(8); `CTLM_RDV 2` payload
`family(1) | port(2,BE) | addr(16)` = `CTL_RDV_PLEN 19` (a warm rendezvous node
for the peer to reuse on a roam); `CTLM_CAND 3`, the same 19-byte payload shape
and so the same codec, one local endpoint at the sender's lanlink port for the
peer to probe and hold as a path (§9), re-sent every `CAND_TELL_MS 5000` so an
interface brought up mid-session is advertised within one period; `CTLM_REACH 4`
and `CTLM_RDVASK 5` (§11).

`CTLM_BYE 8`, no payload: **the shared session behind this connection has
ended**. The host sends it the moment its end-of-session monitor fires
(`session.c:conn_run`, per connection), which is while the control channel is
still up: sshd sees the same signal and keeps pumping for `SSHD_END_DRAIN_MS`
before it closes the shell channel, a window measured in time precisely so that
this message has one to be written and bridged in. It matters because the two ways a guest's session can finish look identical from
the channel closing: the guest detached, and there is a session to rejoin; or
the shared session ended, and there is not. This is the one statement about the
end that cannot be forged, since it arrives inside the authenticated SSH
session, and it beats the mailbox tombstone (§4.1) by the time a DHT store
takes. A guest that hears it leaves with `SESSION_ENDED` rather than
re-claiming; a peer on a build that does not know the type ignores the frame and
falls back to the tombstone.

`CTLM_KEY 6` payload `half(32)` = `CTL_KEY_PLEN`, and `CTLM_KEYOK 7` with no
payload, carry the per-connection key exchange (§2). Each end sends its half as
soon as the channel is up; on receiving the peer's it can derive the key, says
so with `CTLM_KEYOK`, and only starts **sealing** with the key once the peer has
said the same. That order is not optional: the halves ride this channel, which
rides the stream the key protects, so an end that switched as soon as it could
would seal the very datagram carrying a half with the key that half is needed to
derive, and neither end would ever bind. The invitation's key stays acceptable
for opening until the first frame arrives under the connection's, which is the
peer proving it switched rather than a clock guessing. A new control channel is
a new pair of ends, so the binding does not outlive the session that agreed it.

`CTL_HDR = 2`, `CTL_FRAME_MAX = CTL_HDR + CTL_KEY_PLEN = 34` -- the key half is
the largest message, and the reframer rejects anything claiming more.

---

## 11. Roaming, reconnect, keep-alive (`src/session.c`)

- Heartbeat over comrade-ctl: `HB_INTERVAL_MS 700`, and the link is lost when
  **nothing at all** -- pong or any other datagram from the peer -- has arrived
  for `hb_lost_ms(rtt)` = `HB_SILENT_TRIES(3) * HB_INTERVAL_MS + rtt`, the round
  trip capped at `HB_RTT_CAP_MS 1000`, so 2.1 s on a fast link and up to 3.1 s
  on a slow one. It is a count of missed beats plus the link's own measured
  latency rather than a fixed span, because a fixed one is either too tight for
  a slow link or too slack for a fast one. The pong alone must not carry the
  verdict: it rides the same stream and queues as bulk data, so on a saturated
  slow link it arrives seconds late while the transfer demonstrably moves; the
  pong's own job is the round-trip figure. A vanished host worker is reaped
  after `HOST_REAP_MS`, itself derived from the claimant's own cadence
  (`RESUME_AFTER_MS + RESUME_ATTEMPT_MS + RESUME_ATTEMPT_MS / 2` = 18 s) so a
  worker always outlives the claimant's second attempt, and deferred while a
  resumption punch for it is in flight (§12).
- Network changes are polled (`netmon`, `NETMON_POLL_MS 2000`).
- Each end keeps a **warm rendezvous node per address family** and exchanges it
  over `CTLM_RDV`, so either side can re-signal quickly after a move. This is
  what the unconditional DHT engagement of §5 exists to feed: a node can only be
  exchanged if one was ever located.
- **Roaming is a path switch, not a rejoin**. When the path carrying the session
  dies, the session moves to the best warm path (§9) with the connection, the
  worker, the tmux attach and the KCP stream all intact. The peer needs no
  notice, since it accepts on every path it holds. Nothing signals the switch
  and nothing waits for it: ranking reorders, and the next datagram leaves by
  the new path.
- The heartbeat is **end to end and knows nothing about paths**, so it is not
  what decides a switch and is not suppressed for one either. Depending on where
  in its round the path died it may report the link lost for a moment while the
  switch lands; that is the outage the switch is repairing, and it is far inside
  the rejoin grace below. `HOST_REAP_MS 12000` likewise sits well above
  `PATH_DEAD_MS 8000`, so a host never reaps a client that is mid-switch.
- **Total loss resumes in place; a new join is the last resort.** Where no
  path is warm and nothing has been heard for `RESUME_AFTER_MS 3000`, the
  client re-runs the claim half of the join from inside the live connection
  (`resume_tick`): the signalling is rebuilt if the network moved, a fresh
  agent gathers under the connection's **session-stable ufrag** with a fresh
  password (an unchanged claim would be deduplicated away by the peer's
  redelivery guard), and the claim is posted again. The host recognises the
  claimant and grafts the punch into the worker it already runs (§12), so the
  SSH session, the port forwards and their carried TCP streams ride out the
  outage on KCP retransmission; each attempt runs `RESUME_ATTEMPT_MS 10000`
  before regathering. Only when that keeps failing does the interactive client
  tear down and rejoin as a fresh identity (tmux redraws), after
  `SSHC_REJOIN_GRACE_S 75`: the worker was reaped, the host is gone, or the
  network refuses every punch.
- **Signalling is rebuilt on a move**. A fresh `sig` binds a new DHT socket on
  the new network, where the old one stays stuck on the interface that vanished;
  that is why a manual restart reconnects instantly where a reused socket does
  not. It is re-seeded from the rendezvous nodes learnt over `CTLM_RDV` rather
  than from the token, whose slots may long since be stale. The rebuild never
  gives the session up: a network that is still coming up has no
  multicast-capable interface for the link-local half to bind, so the flag stays
  set and `sig_dispatch` retries the open every `SIG_MCAST_OPEN_MS 1000` while
  the DHT half, which binds the wildcard address, runs meanwhile. The DHT half
  is symmetrical: a node that cannot be created now is retried every
  `SIG_DHT_OPEN_MS 1000` rather than on every pump tick, and is never given up
  either.
- A change of **local address** is survivable without re-signalling wherever the
  peer's endpoints stay reachable, because a sealed probe from the new source
  adds a path; see "Adding a path mid-session" in §9. A move to a network from
  which they are not reachable falls back to the rejoin above.

---

## 12. Multi-user turnstile (`session.c:host_turnstile`)

A host serves up to `HOST_MAX_WORKERS = 16` concurrent clients on one shared
tmux session. `host_is_multiuser = is_host && (sig_flags & (SIG_DHT | SIG_MCAST))
&& !test_single_conn`, so a host that declines the DHT (`--no-dht`, §13) and
serves over multicast alone runs the turnstile too. A worker's `conn_run(conn, drive_sig=0)` does not pump sig; the
turnstile owns rendezvous. Heartbeat reaps vanished clients.

**DHT/ICE path, release-on-pickup.** The host advertises one offer at a time with
**single-use per-offer ICE credentials**; a client claims via the `a` slot (CAS).
On pickup the host sets the claimant's remote description, moves the listening
conn into an in-flight set `punching[]`, and **immediately rotates a fresh offer**
(fresh credentials; one mailbox write clears `a` and installs the new offer),
admitting the next client without waiting for the punch. `punch_scan` then
advances each in-flight punch: a connected one becomes a worker (its dashboard row
opens there); a failed one, or one past `ICE_ATTEMPT_MS = 90000`, is freed. A
stuck punch therefore never head-of-line-blocks the next joiner. A **stale-claim
guard keyed by the claimant's ICE ufrag** (`have_served`/`last_served_ufrag`, plus
`ufrag_admitted` over `punching[]` and `lan_ufrag_claimed` over the direct path)
ignores a lagging DHT re-read of an already-served or in-flight answer, so no
client is punched twice.

**Losing a round.** One offer is readable by every client that reads the mailbox
before the rotate, and its ICE credentials stay valid at the host until that
agent is retired -- so a client that lost the CAS still completes a connectivity
check, against an agent that is punching or serving somebody else. ICE reporting
a pair therefore says nothing about who is being served; only the probe does, and
a loser is never answered because the worker checks the claimant ufrag. A client
that has qualified nothing recovers by re-claiming with a fresh ICE identity
(`session.c:client_regather`), triggered by either of:

- **its claim leaving the answer slot** without a path qualifying within
  `PATH_PROBE_MS`. The slot is the mutex, so a claim still in it is queued
  however long the queue -- which a clock cannot tell apart, and a clock-driven
  re-claim livelocks one case or the other (measured, both directions).
- **the offer rotating past the one its agent is primed against**. Release-on-
  pickup mints a fresh ICE identity every time somebody is served, so a queued
  client would be punched by a listener whose credentials it never had. Acted on
  once per rotation, so a burst of joiners does not re-gather in lockstep.

A client also re-claims when an SSH bring-up fails outright. A host never
re-gathers: the turnstile owns its offer, and it retries its own listener. The
direct LAN path is exempt from all of it -- its admission queue is per claimant
and there is no shared offer to lose.

Because a re-claiming client discards the offer it was given, and the host has no
reason to rewrite an offer nobody has taken, `sig_redeliver()` makes the next
read deliver the current offer again rather than dedupe it away.

**The host does not reject a claim that answers a retired offer.** It punches
with whatever is listening when it reads the claim, which is the point of
release-on-pickup: rejecting stalls exactly the joiners that arrive while a punch
is wedged (measured, and what `turnstile_stuck.sh` exists to catch). A claimant
paired with an agent it never primed against simply never qualifies, and the
rules above recover it.

**A claim naming a claimant the host already serves is a resumption.** The
ufrag is session-stable, so it names the same client across its claims. If the
worker serving it has lost its client, the claim is that client returning, and
its punch ends in a graft rather than a worker: the punched agent's callbacks
are re-pointed at the worker's connection -- packets land in its stream from
that instant -- and the agent is parked for the worker's own thread to adopt
as the sending one, since `c->nat` belongs to that thread. The punch shell is
dissolved with no worker, no dashboard row and no registration of its own, and
the worker's reap is held off while the punch runs. From a *healthy* worker
the same claim is the eventually-consistent DHT re-serving a stale value and
is ignored, as are claims whose punch is already in flight, and resumptions
inside `RESUME_ATTEMPT_MS` of the last -- the window between a graft and its
first probe, where the worker still reads as lost. Anyone holding the token
can claim any ufrag, but a resumption moves packets, not trust: the SSH
session inside the stream authenticates end to end, so a forged resumption
redirects the transport at worst -- a denial no cheaper than the claim spam
the shared-secret model already admits (see the slot limit below).

Concurrent DHT admission is partial beyond two clients: the turnstile is serial
by construction, so N clients cost N rotations and each rotation strands the
others. The LAN path has no such limit -- no shared offer -- and admits N
concurrently.

**LAN direct path, admission queue.** A sealed multicast answer from a LAN-scope
source becomes a direct claim (§6): `on_direct_claim` appends its
`(source, announced-port)` endpoint to a small pending queue, deduped against the
active `lan_conns[]` and the queue itself. The host main thread drains the queue
into fresh **lanlink-only workers** (a `conn` with `nat == NULL`, `have_lan_peer`
set), registered in `lan_conns[]`; `host_lan_recv` then demultiplexes inbound
datagrams to the owning worker's stream by source. All multicast receive,
admission, worker spawn/reap and this demux run on the one host main thread, so N
concurrent claimants are admitted race-free with no CAS and no shared mutable
offer. LAN workers and ICE punches share the `HOST_MAX_WORKERS` budget and are
reaped identically by heartbeat.

**Shared-credential slot limit.** Every guest authenticates with the same sealed
`sig_key` and token, so the `HOST_MAX_WORKERS` budget is first-come across all
endpoints: the host cannot distinguish many endpoints of one legitimate guest
from one guest spamming endpoints, and a single token holder can therefore take
all 16 slots. This is an inherent property of the one-shared-secret model, not an
admission bug; dedup is per `(source, port)` endpoint and heartbeat reaps
vanished claimants to free slots.

---

## 13. UX and CLI (`src/main.c`, `src/ui.c`, `src/statusbar.c`, `src/host.c`)

CLI surface:

| command | effect |
|---------|--------|
| `comrade` | start/attach a shared session; dashboard shows token + live peers; ENTER attaches tmux, ESC aborts |
| `comrade <token>` | join interactively, read-write |
| `comrade show` | print the running session's token(s); exit 1 if none |
| `comrade stun-update` | refresh the baked STUN list into the data dir |
| `-L [bind:]port:host:hostport` / `-R …` | forward a port (repeatable) |
| `--no-multicast` | DHT/STUN only, skip link-local discovery |
| `--no-dht` | decline the DHT entirely: link-local discovery only, and both token families settle to `NONE` (§3, §5); refused with `--no-multicast`, which would leave nothing to meet on |
| `--no-forwarding` | host declines all client forwards |
| `-v`, `--verbose` | log lines instead of the dashboard |

`--no-dht` names the mechanism it declines rather than the medium it assumes. A
future non-IP transport (BLE, LoRaWAN, AX.25) would make a `--lan-only` spelling
meaningless, while "no DHT" still says exactly what it does. These options
configure the session being started: `comrade` re-attaching to a session that is
already running keeps whatever its service was given, and names on stderr which
of them it is ignoring.

MVC seam (`src/session.h:session_obs`): the controller emits semantic events
(`net`, `link`, `rendezvous`, `rdv_stage`, `token`, `peer`, `reset`, `escalate`,
`established`, `tick`); the view owns all formatting. Peer lifecycle states
`SEEN/PUNCHING/LIVE/GONE`, each addressed by a stable `id` so a multi-user host
draws one row per client.

- **Host dashboard** (`ui.c`): the token to share, and the live peer list
  (per-connection rows keyed by connection id, each with its proven path). A
  detached connection **service** keeps serving while the operator is away
  (`host.c`: `run_service` re-serves until the tmux session dies); the operator
  attaches/detaches without ending the session.
- **Status row** (`statusbar.c`): connection health (green live / amber if smoothed
  RTT over `RTT_WARN_MS 250` / down), RTT, the path in use and its warm
  alternatives (§9), and the rendezvous state; address scope shown as LAN / CGNAT / GLOBAL (`session.c:addr_scope`).
- The session ends when the last shell in the tmux exits on either side; a
  client detaching or dropping never ends it.
