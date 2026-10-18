# comrade protocol and UX specification

Wire-level specification of comrade as implemented in this tree, precise enough
for an independent implementation to interoperate with the C one. Every constant
is cited to its source (`file:function`/`#define`). All multi-byte integers on
the wire are **big-endian** unless stated otherwise.

Layering, outermost to innermost:

```
  token (base58, out of band)
    -> rendezvous: one sealed cell on DHT (BEP44) and/or LAN multicast
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
(`TOKEN_VERSION = 6`, §3) returns the rendezvous to **one** BEP 44 target
(§4, §5), whose value holds the host's own statement beside the one turn a
claimant exchange takes, seals a
claimant's statements to its credential class alone (§4.2), and carries the
same addressed envelope in the multicast announcements (§6). Two peers
must be built from the same revision; there is no version negotiation and
none is planned before the format settles.

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
  means the peer sent a low-order point. Used by the box below, which no slot
  of this revision carries. Pinned to RFC 7748's own vector by
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
tag. Kept in the key schedule with its vector; a claimant's statements are sealed
to a key its class derives (§4.2), so nothing on the wire is boxed in this
revision.

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
  draw(n):
    m           = "comrade1 wire tags"                    # 18 bytes, no NUL
    if n > 0: m = m || byte(n)
    tags(32)    = BLAKE2b_keyed(key=R, len=32, msg=m)
    probe_magic = tags[0..4]  as big-endian uint32
    conv        = tags[4..8]  as big-endian uint32

  n = 0, 1, 2, ... until every one of these holds:
    probe_magic != conv
    bswap32(probe_magic) not in 1..4
    conv                 not in 1..4

  pb(32)       = BLAKE2b_keyed(key=R, len=32, msg="comrade1 mcast port") # 19 bytes, no NUL
  mcast_port   = 32768 + ((pb[0]<<8 | pb[1]) & 0x3fff)                   # 32768..49151
```

Both are the first bytes of a 32-byte digest and not a digest of their own
length. BLAKE2b folds the digest length into its parameter block (RFC 7693),
so a short digest is a different hash rather than a prefix of a longer one,
and not every library can be asked for one: taking a prefix of the size they
all have is what makes these the same number on every backend, which is the
whole point of deriving them from a shared secret. §9 states the same rule for
a path's id.

Three properties, and a draw that fails any of them is rejected in favour of
the next rather than nudged into shape, since a nudge has to be re-examined
for what it broke. A draw fails about once in 2^30, so the first is
effectively always the one taken. A conforming implementation must still
iterate, because the invitations where it matters are exactly the ones where
guessing is wrong.

`probe_magic` opens a probe (§9) and `conv` is the KCP conversation id, and
the demux that tells one from the other is a single compare of the first four
bytes -- so they are forced apart rather than left to chance. The 1..4
exclusion is the same rule against a third reader: a WireGuard datagram opens
with a little-endian `uint32` message type of 1 to 4, and wherever comrade and
WireGuard share a port those four bytes are the whole of the demux between
them. The two tags are tested differently because they reach the wire
differently -- a probe writes `probe_magic` big-endian (§9) while KCP writes
`conv` little-endian -- so the same four bytes are a different number in each,
and only one of them is byte-swapped before the test.

Implementations bounding the loop should note that eight consecutive failures
is 2^-240; comrade takes `probe_magic = (probe_magic & 0x7fffffff) | 0x80` and
`conv = conv | 0x80000000` at that point, which satisfies all three by
construction and is unreachable in practice.

`mcast_port` is the link-local group's port (§6), above the registered range
and clear of the ephemeral one most systems draw from, so it neither squats on
a service nor collides with what else the machine binds.

`sig_key` seals the host's own statements in the cell and its announcement (§4,
§6); a claimant's statements and its announcement are sealed to its credential
class's key (§4.2). `bep44_pk/sk` are the BEP44 mutable-item identity
(§5). Both peers derive the **same** keys from the same token, so the
rendezvous is a set of items only they can read or write.

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

the 32-byte keyed digest truncated to `TOKEN_AUTH_LEN = 16`, so the 16-byte
secret is a prefix of the 32-byte hash rather than a 16-byte-digest request.
BLAKE2b folds the digest length into its parameter block (RFC 7693), which
makes a short digest its own hash and not the front of a longer one, and not
every library offers the short ones: asking for the natural size and
truncating is what keeps a derivation available on any backend. A host holding `A_rw` can mint
and accept `A_ro`; a read-only guest cannot walk `A_ro` back to `A_rw`. The
read-only token carries `A_ro` in its `auth` slot with `TOKEN_FLAG_RO` set (§3),
and SSH auth maps it to a view-only attach (§10).

---

## 3. Token (`src/token.c`, `src/token.h`)

Fixed **90-byte** payload (`TOKEN_RAW_LEN`), packed in order:

| field | bytes | meaning |
|-------|-------|---------|
| version | 1 | `TOKEN_VERSION = 6` |
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
| set | 1 | 1 | `RENDEZVOUS` | a DHT node holding the host's slot, so the client skips cold convergence (§5) |
| set | 0 | 1 | `DIRECT` | the host's own endpoint, **proven reachable from outside** |

A set slot with `SETTLED` clear does not occur; a decoder treats it as settled.

**The state is advisory.** `R` alone is always sufficient: every address in the
token is a hint that skips work, never a precondition, and a client that finds
nothing useful in the token converges on the cell's target from the DHT
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

**`DIRECT` requires proof** *(PLANNED, 0.3.0)*. The slot is specified and its
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
cleanly on an older build instead of being misparsed as this one, and must
report it apart from the rest: every other reason a decode fails is a typo,
while this one is an intact string whose other end derives different keys
from it.

`TOKEN_VERSION` numbers the **whole protocol**, not this table. It is the
only field either end reads before it derives a key or sends a packet, and
the only one carried by something a human hands over, so it is the one place
an incompatible peer can be refused with a word to the user rather than a
silence. Every incompatible change anywhere on the wire bumps it, whether or
not the 90 bytes above move: a `CANDPACK_VERSION` bump (§7), a different
seal, a new key schedule, a changed framing. Two peers that disagree below
the token still read the same 90 bytes, so without the bump they meet in the
same rendezvous, exchange offers and then never complete a punch. That is what
happened between versions 2 and 3, which differ only in §7, and it is the
failure a protocol-wide version number exists to turn into one clear line at
the point the token is pasted. Versions 3 and 4 differ in §4, §5, §6 and §12:
a version 3 peer looks for one shared mailbox under a salt a version 4 peer
never writes. Wire compatibility is deliberately unstable across 0.x, so the
bump costs nothing and is never worth skipping.

---

## 4. The rendezvous cell (`src/rdv.c`, `src/sig.c`)

A rendezvous is **one** BEP 44 mutable item under the invitation's key
(`bep44_pk`, §2), at one salt (`keys.c:keys_slot_salt`) and so at one target.
That is the locked shape: the node named in a token (§3) accepted a store for
that key, which makes it one of the key's k-closest and a legitimate holder, so
a direct op to it (`bep44_get_direct`, `bep44_update_direct`) skips only our own
re-lookup. More than one target would void that.

```
  salt = 'r' || hex(BLAKE2b_keyed(key=R, len=32,
                                  msg="comrade1 cell")[0..8])   # 17 chars, no NUL
```

The value is a bencoded dictionary with two places, and **every writer keeps
the place it did not author** (`sig.c:cell_pack`, `cell_part`):

```
  d 1:c <sealed turn statement> 1:h <sealed host statement> e
```

| place | holds | written by | read by | carries |
|---|---|---|---|---|
| `h` | `HOSTINFO`, or `TOMB` | the host | everyone | its instance id and generation, and the rendezvous nodes it is operating; `TOMB` when the session has ended (§4.1) |
| `c` | `OFFER` | one claimant | the host | that claimant's candpack (§7) |
| `c` | `ANSWER` / `REFUSE` | the host | that claimant | the host's candpack for it, or a refusal reason |

The host's own statement is therefore readable whoever holds the turn, which is
what lets the host keep placing it where a converging client will look (§5)
without costing a claimant its turn. One claimant at a time holds `c`: that is
the whole of the admission queue, so establishment is sequential, which is what
`--max-clients` does **not** limit (that counts simultaneously *connected*
clients, §12).

A claimant writes `c` when it is free, and to replace an ask of its own under a
different number; it never writes over what the host put there, and never
restates the ask already standing. An answer written over before it is read
leaves both ends waiting on each other, and a restated ask is a store that
changes nothing and costs a round. The host hands the turn back by writing `h`
while no claimant is engaged (`rdv_host_busy`), which happens as soon as a
punch connects for one and the claimant has been heard from, or when it ends
(`rdv_host_release`); a `TOMB` clears the turn outright.

The host answers **by the route the ask arrived on** (`wide_ask`): a claimant
that joined on a token naming no node is reachable through the key's k-closest
and nowhere else, so an answer stored only on the host's own pinned node would
never reach it.

**The host's statement advertises its own rendezvous nodes**
(`sig.c:host_info_nodes`, read by `host_nodes_seed`), one per family in the
`CTL_RDV_PLEN` shape the in-band advert uses (§10): `family(1) port(2)
addr(16)`. A claimant that reached the cell by converging on the key pins them
and goes direct from its next statement on, which is what a token naming a node
gives a later joiner (§3) and what `CTLM_RDV` gives a connected peer. Without
it a cold claimant pays a lookup for every statement in the exchange.

A claimant that finds the turn free while its ask stood there asks again under
a **new** `seq` (`rdv.c:offer_seq`, driven by `rdv_client_ask_gone`), since
repeating one the host has already read would be refused as a replay and the
claimant would wait for ever. A copy below the newest it has seen says nothing
about the turn now and is ignored. The host's answer to the offer a claimant has just superseded is still
taken (`prev_offer_seq`), or an answer in flight and a fresh ask would pass
each other indefinitely.

`cid` is a party's **instance id**: 8 random bytes minted once per process
(`sig.c:sig_instance_id`), carried inside the sealed envelope and never in the
clear. It is what the host tells a returning claimant by, since an ICE restart
carries fresh credentials and the name has to survive one.

**The envelope** (`rdv.c:rdv_encode`), the plaintext of the cell:

```
  version(1)=3 | kind(1) | gen(4) | from(8) | to(8) | seq(4) | re(4) | len(2) | payload(len)
```

`kind`: `1 HOSTINFO, 2 OFFER, 3 ANSWER, 4 REFUSE, 5 TOMB`. `from` is
the sender's instance id, `to` the recipient's or all-zero for whoever reads.
`gen` is the host's generation (§7, §12) on everything the host writes and,
on an `OFFER`, the host generation the claimant is answering. `seq` is the
sender's statement number; `re` is, on an `ANSWER` or `REFUSE`, the `seq` of
the `OFFER` it answers, and 0 elsewhere; `len <= RDV_MAX_PAYLOAD = 760` in the
turn place and `RDV_HOST_PAYLOAD = 64` in the host's.
`TOMB` carries no payload; `REFUSE` carries one byte,
`1 full` (the grant is spent) or `2 clash` (two claimants under one id).

**Sealing.** The host's statements are `seal(sig_key, envelope)` (§1): every
holder of the invitation reads them. A claimant's are sealed to its class,
§4.2. The two sealed places and the frame around them share
`BEP44_MAX_VALUE = 1000` bytes (`rdv.c`, static assertion): `792 + 40` for the
turn, `96 + 40` for the host's statement, and `RDV_CELL_OVERHEAD = 20` for the
bencoding.

**The exchange** (the claimant offers first):

1. The host writes `HOSTINFO` into `h` when it starts, whenever its generation
   changes, and on its re-store cadence (§5). It is there for a claimant to
   discover the host by whatever the turn holds.
2. A claimant reads the cell, learns the host's id and generation from `h`, and
   writes its `OFFER` into `c` **while the turn is free**. It keeps asking for
   as long as it has **no live path** (`sig_withdraw` stops it, `sig_post`
   re-arms it) and the host has neither answered nor refused, under a new `seq`
   each time the turn has lost its previous ask.
3. The host reads the cell. An `OFFER` with a sequence above the last taken
   from that claimant is handed to the turnstile (§12), which mints an ICE
   agent for that claimant alone and writes its candpack into `c`, or `REFUSE`
   when the grant is spent. One store is in flight at a time
   (`sig.c:slot_inflight`), so the turn is observable between statements.
4. The claimant reads the cell. An `ANSWER` addressed to it, from the host
   instance it offered to, answering the offer it has standing now or the one
   that just superseded it (`re`), with a sequence above the last it took, is
   primed into its agent; a `REFUSE` to that offer ends the join
   (`SESSION_FULL`). Anything older is a no-op: a replica still serving it
   would otherwise prime a punch at an agent the host has since spent.
5. Once that claimant has been heard from on the punch, or its punch ends, the
   host hands the turn back and the next claimant's can begin
   (`rdv_host_release`). A pong is what proves the answer was read: a punch
   connecting proves only the host's half of it, since the host holds the
   claimant's credentials from the ask and the claimant's agent answers checks
   whether or not it ever read the answer. A claimant that never read its
   answer is thereby self-healing: the punch for it ends, the turn frees, and
   it asks afresh.

**The invariant.** No protocol state is derived by comparing a replicated
value against local expectation: a peer advances only on a statement addressed
to it, from the sender it expects, answering what it asked, with a sequence
above the last it took from that sender, so a stale or replayed read is a
no-op and a duplicate delivery is idempotent (`rdv_test.c` drives both state
machines against a store that serves each reader a different revision,
delivers everything twice and partitions a claimant). The four rules that make
one shared cell safe:

- **L1** a claimant asks *while* it has no live path. An ask overwritten by a
  rival before the host read it costs one round; asking once would have
  deadlocked the loser.
- **L2** the host reads on its own cadence whatever its load, and never answers
  with silence: a claimant whose offer it took gets an `ANSWER` or a `REFUSE`.
- **L3** the cell carries the host's instance id and generation, and a claimant
  that sees either change treats its next offer as a new statement
  (`rdv_client_host_slot` resets the offer sequence), so a host that restarted,
  roamed or re-served is asked again by a claimant whose answer it no longer
  knows about.
- **L4** nothing about the *other end* is inferred from absence. A claimant
  that finds the turn free concludes only that its own ask is no longer there,
  and asks again under a new number, which is idempotent either way.

An **unchanged offer keeps its sequence while it still stands**
(`rdv.c:offer_seq`): the host answers a sequence once, so a repeat of one it
has read would be refused as a replay. An ask the cell has lost takes the next
sequence instead (`reask`), and the answer to the offer just superseded is
still taken (`prev_offer_seq`), or an answer in flight and a fresh ask pass
each other indefinitely. Measured in messages, which a bound in seconds could
meet by polling harder: one claimant is answered after 4, three after 25, four
after 40, three across a six-round partition after 25, and one whose host
restarted is answered again after 41 (`rdv_test`). Serialised turns cost more
messages than the four-target shape this replaces; one target is the locked
design (§4) and the cost is accepted.

### 4.2 Who may read whom (`keys.c:keys_slot_key`)

A claimant's statements in the cell, and its multicast announcement (§6), are
sealed under a key derived from the **auth secret of that claimant's
credential class** alone. The host's own statements are sealed under the
session key, which every holder of either class derives, so discovery always
works:

```
  class_key(32) = BLAKE2b_keyed(key=A_class, len=16, msg="comrade1 cell class key")
```

No instance id enters it, which is what lets the host open a statement from a
claimant it has never met: it tries `A_rw`, then `A_ro`, and reads the `cid`
from inside the seal (`sig.c:claimant_open`).

The intended reach follows from `keys_derive_ro_auth` being one-way:

| reader | may read |
|---|---|
| read-write holder | the host, and other read-write holders |
| read-only holder | the host only |

A read-write holder's class key comes from `A_rw`, which a read-only holder
cannot derive from the `A_ro` it was given, so **a read-only guest cannot read a
read-write holder's statement.** The host holds `A_rw` and so derives both
classes, remembers which one opened a claimant's statement, and seals its
answer under the same.

**Accepted flaw, documented rather than fixed:** holders of one class *can*
read each other, since they share that class's key. For read-write holders that
is intended. For read-only holders it means a room handed one read-only link is
a room whose guests can see each other's addresses, though not those of any
read-write holder. Closing it would need a per-claimant secret the host alone
shares with each guest, which a one-way token cannot carry.

What this does **not** hide is presence. A holder that cannot open what the
cell currently holds still learns that some other establishment is in progress,
and when. That is metadata rather than content, and it is wider than the
previous shape, where a read-only holder could not see that a read-write holder
existed at all. Any holder can also take a turn it is not using, which costs
another claimant a retry; the one-token-one-BEP44-target property is worth more
than protecting against an authenticated holder delaying an exchange it cannot
read.

### 4.1 Tombstone: the session has ended

An invitation says where to meet a host that is still there and, on its own,
can say nothing else -- so a token outliving its session sends every holder
into a wait with no end. A `TOMB` in the cell is the missing answer.

- The **host** writes it as the session ends (`sig_end`, from
  `session.c:session_entomb_start`), in place of its `HOSTINFO`: a session
  cannot be both live and over. It is sealed like the host's every other statement -- not
  because that makes it unforgeable among the holders of the invitation, but
  because a passer-by should learn no more from the end of a session than from
  the rest of it.
- It is published from **inside the session**, while the rendezvous node is
  still warm and pinned; a process that had already torn its signalling down
  would have to converge on the DHT from cold to say one word. Both routes are
  used and **both are waited for** (`sig_end_placed`): the direct store reaches
  the node a token names, and the convergent store reaches whoever is closest to
  the key -- which is where a token naming no node leads a client, and where
  this host's own last statement is sitting. They go out one at a time, on the
  tombstone's own cadence (`SIG_DHT_TOMB_MS 300`).
- A **live host re-states the cell** whenever a read shows anything else there
  (`sig.c:host_slot_read`, `h_stale`), which is what makes the rendezvous
  self-healing. Every holder of the invitation can write it, so a forged
  tombstone must not outlive the next write of the host it lies about --
  roughly a second, while one is serving.
- A **client** therefore does not act on first sight. `sig_peer_ended` believes
  the tombstone once it has stood `SIG_TOMB_SETTLE_MS` (4 s) with no `HOSTINFO`
  read since, timed from when it was **first** seen rather than most recently,
  so the clock runs out rather than restarting on every read. A `HOSTINFO` read
  puts the clock back. A copy at a BEP44 sequence below the highest the client
  has seen for the cell moves neither clock, nor the client's idea of
  which instance is serving, when it comes from an instance the client has
  already dealt with (`rdv_client_host_slot`); a lagging replica can therefore
  neither forge an end, hide one, nor pull a claimant back to a host it has
  left. One it has never met counts whatever its sequence, since a host that
  restarted may write below its predecessor. The cost of forging a tombstone is
  therefore a joiner's pause, not the session.
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

- **Salt**: one per slot, `keys_slot_salt` (§4): `h`, `d`, `c` + cid and
  `a` + cid, each 17 bytes.
- **Target** (`bep44.c:bep44_target`): `SHA1( bep44_pk[32] || salt )` = 20 bytes.
- **Signed buffer** (`bep44.c:bep44_sig_buffer`), exactly:
  `4:salt<len>:<salt> 3:seq i<seq>e 1:v<raw value>` (the `salt` fragment omitted
  when empty; here every salt is 17 bytes, so `4:salt17:<salt>`). `<raw value>`
  is the sealed envelope from §4, inserted verbatim after the `1:v` marker.
- **Signature**: `Ed25519_sign(bep44_sk, signed_buffer)` = 64 bytes.
- **put** KRPC (`bep44.c:put_send`), `a` dict keys in sorted order:
  `cas` (opt), `id`(20, node id), `k`(32, `bep44_pk`), `salt`,
  `seq`(int), `sig`(64), `token`(write token from the node), `v`(raw value).
- **seq/cas rule** (`bep44.c:store_seq`, `node_cas`): the value is stored at
  `seq = best_seq + 1`, `best_seq` being the highest sequence the lookup found,
  or at `best_seq` itself when the bytes to store are exactly the ones found (a
  refresh, so the keep-warm re-stores do not walk the sequence up); a first put
  with no prior value uses `seq = 1`. `cas` is decided per node: the sequence
  that node reported holding in the lookup, the lookup's best for a node that
  reported none, and omitted where nothing was found at all. A node whose copy
  fell behind is thereby caught up rather than refusing every later store with
  301, and whatever a peer wrote to it alone is still read from it.
- **Every write keeps the place it did not author** (`sig.c:slot_put`,
  `merge_mine`, `cell_pack`): the lookup earns the write tokens and finds both
  the stored sequence and the value, and what is stored is this end's own
  statement in its own place beside the other place exactly as read. The host's
  statement therefore survives a claimant's turn, and a claimant's turn
  survives the host's re-store. Each place is last-writer-wins, so two
  claimants asking in one round cost the loser a retry on its next tick (L1,
  §4), never a session; who may write the turn is §4's rule. A
  client that relays the host's statement for a
  family the host cannot reach (`sig_relay`, §10) re-stores the host's bytes
  exactly as last read, and stands down where the store already holds a copy
  at a higher sequence than the one it read.
- **Transaction id** (`bep44.c:tid_bytes`): every KRPC query tags `t` with four
  bytes, `'p' 'm'` then a **16-bit little-endian** per-request counter; a reply is
  matched back to its pending request by that id.
- **get/put targeting**: both peers converge on the k-closest nodes to `target`
  (evict farthest, not refuse newcomers, or the sets diverge and the get
  misses). The chosen rendezvous node(s) can be embedded in the token
  (`EPx_RDV`) so a client skips cold convergence.

**Reads** (`sig.c:host_read`, `client_read`), one direct get per
`SIG_DHT_GET_MS` to the pinned and retained nodes. One cell, so one read tells
either end everything there is: what it holds is discovered rather than asked
for, by trying the session key and then the reader's own class key
(`sig.c:on_slot_get`), and a value neither opens is another claimant's turn.
Both also read convergently, every `SIG_DHT_WIDE_GET_MS 4000` until the host
has been seen and every `SIG_DHT_WIDE_IDLE_MS 20000` after, which is how a
token naming no node, or a dead one, still finds the host, and how the nodes
each end holds converge on the ones closest to the cell's key.

**The rendezvous node is the one that served the cell back**
(`sig.c:node_note`): the host captures and pins the first of each family to do
so and the token names it (§3), and either end's `netstate` is told which node
answered a validated read, which is the proof the anchor stays qualified on.

**Writes** (`sig.c:host_pump_puts`, `client_pump_puts`), at most one in flight
at a time (`slot_inflight`), because one cell admits one writer per turn: the
host stores the cell convergently while a reachable family has no anchor yet
(`SIG_DHT_PUT_MS` apart while that family's connectivity is proven,
`SIG_DHT_PUT_SLOW_MS 20000` otherwise), every `SIG_DHT_WIDE_PUT_MS 45000`
after as a refresh, and directly whenever a read shows something else where
its own statement should be; it writes each pending answer or refusal directly
on a `SIG_DHT_PUT_MS` tick. A claimant writes its offer directly every
`SIG_DHT_PUT_MS`, and only on its turn (§4). Nothing a claimant writes goes
out convergently: the nodes it has retained from reading the cell are the
host's own.

Timings (`sig.c`): `SIG_DHT_GET_MS 1000`, `SIG_DHT_PUT_MS 1000`,
`SIG_DHT_RESTORE_MS 8000`, `SIG_DHT_GRACE_MS 2000`, `SIG_DHT_OPEN_MS 1000`.

**Engagement is unconditional**. A session engages the DHT after
`SIG_DHT_GRACE_MS` whatever else has happened, on both roles, and keeps it
running for the session's whole life. A multicast announcement arriving first
does not suppress it. The DHT is the only rendezvous that survives a change of
network, so it has to be running *before* the change rather than started after
it: a host and a client that meet on an isolated LAN and later roam apart depend
on a cell published while they were still together, and on the warm
rendezvous nodes they exchanged over `CTLM_RDV` (§10, §11). A LAN-only session
therefore pays a socket and periodic bootstrap traffic that will not succeed;
that is the price of being able to leave the LAN, and the only opt-out is the
operator's explicit `--no-dht` (§13).

---

## 6. Multicast / lanlink (`src/sig_mcast.c`, `src/lanlink.c`)

For isolated LANs, the host's presence and each claimant's offer are announced
over link-local multicast, each with a direct UDP transport port.

Multicast (`sig_mcast.c`):
- Groups: v6 `MCAST_V6 = ff02::da7a`, v4 `MCAST_V4 = 224.0.0.224`. The **port
  is this session's**, derived from the invitation (§2), not a constant: on a
  fixed port every comrade session sharing a segment lands in one conversation,
  hearing every other's announcements, opening none of them and paying for all
  of them. `MCAST_PORT = 47654` remains only as the fallback for a caller with
  no session to derive from (the `mcast-probe` interface check).
- Packet: `MCAST_MAGIC "pMc1"` (4 bytes) `|| salt_len(1) || salt || payload`.
- **Salt = the sender's role**: `"h"` from a host, `"c"` from a claimant; a
  receiver listens for the *other* role's (`sig.c:on_mcast_recv`), which is
  also how it ignores its own announcements looping back.
- A host's `payload` = `seal_ad(sig_key, ad="h", direct_port(2, BE) ||
  envelope)`, the envelope a `HOSTINFO` exactly as in its DHT slot (§4), so a
  segment hears which instance and generation is serving and where its lanlink
  socket is. It carries no description: a host gathers for a claimant, never
  ahead of one.
- A claimant's `payload` = `cid(8) || seal_ad(slot_key, ad="c", direct_port(2,
  BE) || envelope)`, the envelope its `OFFER` with the candpack packed for the
  DHT (`for_dht=1`), sealed to its class (§4.2) under the key the clear `cid`
  lets the host derive. So an offer announced on the segment is readable by
  exactly who may read it in the DHT.
- The salt frames the value on the wire outside the seal and is **bound into
  the tag** as associated data, so a frame captured under one role does not
  open under the other.

**Role split on receive** (`sig.c:deliver_host_mcast`,
`deliver_claim_mcast`): both roles adopt an endpoint only from a packet whose
seal verifies **and** whose source is **LAN-scope** (`addr_is_lan_scope`:
link-local, RFC1918 `10/8` / `172.16/12` / `192.168/16` / `169.254/16`, ULA
`fc00::/7`, and loopback `::1` / `127/8` for a same-host peer). The source class
is not the trust boundary -- the seal is; it only decides who gets the ICE-free
bypass. A **client** learns the host's direct endpoint and nothing for ICE. A
**host** that demultiplexes the shared lanlink socket (`mcast_claims`) does
**not** feed the offer to ICE -- it can serve a same-segment claimant directly
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

candpack binary layout (`candpack.c`, `CANDPACK_VERSION = 4`):

```
  version(1)=4 | gen(4,BE) | offer_len(1) | offer_ufrag | cid_len(1) | cid
              | ufrag_len(1) | ufrag | pwd_len(1) | pwd | ncand(1)
  ncand *   [ type(1) | family(1) | prio(4,BE) | port(2,BE) | addr(4 or 16) ]
```

`gen` is the offerer's network generation (`session.c: netgen`, 0 where none),
which bumps on every move; a client tells a moved offer, whose candidates are
new, from one that only rotated credentials, and re-claims at once on a move.

`offer_ufrag` (v3) named the offer a claim answered under the shared mailbox;
this revision packs `offer_len = 0` everywhere, the slot a description is read
from saying who it answers. `cid` (v4) is the sender's instance id, the same 8
bytes the envelope's `from` carries (§4), or `cid_len = 0` naming none. ICE
credentials cannot say that two offers came from one client, because a
reconnect is an ICE restart and carries fresh ones; the instance id is what a
host tells a reconnecting client by. Decoding accepts versions 2 through 4,
taking the fields a older packing lacks as absent. A `CANDPACK_VERSION` bump
that older peers cannot decode also bumps `TOKEN_VERSION` (§3), which is where
a mismatch is caught and named.

`type`: `0 host, 1 srflx, 2 prflx, 3 relay`. `family`: `4` or `6`. Only
`component 1`, `UDP` candidates are packed. Decode rebuilds
`a=ice-ufrag:…\na=ice-pwd:…\n` and one `a=candidate:<idx> 1 UDP <prio> <addr>
<port> typ <type>[ raddr 0.0.0.0 rport 0]\n` per candidate (foundation = index).

---

## 8. ICE / NAT (`src/nat.c`, libjuice 1.7.3)

libjuice agent per connection: gather → exchange the bundled SDP as candpack via
the rendezvous cell/multicast → connectivity checks → connected/failed. STUN
server-reflexive candidates gathered from the community STUN pool
(`src/stunlist.c`, baked-in list). Nested NAT handled by publishing the private
v4 (the cell is sealed) + libjuice RFC 8445 peer-reflexive source learning. KCP
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
host and a client -- one owns the tmux, one asks to be admitted (§12) -- but
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
introduced. Take the natural 32-byte digest and truncate rather than asking
for an 8-byte one, for the reason in §2: a short BLAKE2b is a distinct hash,
and not every backend can produce one. Every keyed derivation in comrade asks
for 32 bytes and slices, for that reason and no other.

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
travels in a slot every holder of the claimant's class can read and unseal
(§4, §12) -- and it does not need to be. Everyone holding a token can reach the
machine anyway, and the read-only grade shares the same `R`, so `sig_key` and
every capability it confers (reading the host's statements in the cell, taking
a turn in it, the host's announcement) are already common to both grades. Disruption between
token holders is out of scope;
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
session, and it beats the cell's tombstone (§4.1) by the time a DHT store
takes. A guest that hears it leaves with `SESSION_ENDED` rather than
offering again; a peer on a build that does not know the type ignores the frame
and falls back to the tombstone.

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
  client re-runs the offer half of the join from inside the live connection
  (`resume_tick`): the signalling is rebuilt if the network moved, a fresh
  agent gathers under the connection's **session-stable ufrag** with a fresh
  password (an unchanged offer keeps its sequence and is a refresh the host
  has already answered, §4), and the offer is written again. The host
  recognises the claimant and grafts the punch into the worker it already
  runs (§12), so the
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
  than from the token, whose endpoint hints may long since be stale. The rebuild never
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

**DHT/ICE path: an agent per claimant.** The host keeps **one gathered ICE
agent ready** (`TS_GATHER` → `TS_WAIT_CLAIM`) and publishes nothing of it. A
claimant's `OFFER` arriving in the cell (§4) is queued
(`session.c:offers_push`, replacing an older one from the same claimant) and
decided on the next pass (`host_offer_take`): the ready agent is primed with
the claimant's description, moved into the in-flight set `punching[]` under
the claimant's ufrag and instance id, and its own description is written as
the `ANSWER` addressed to that claimant (`sig_answer`); the host then gathers the
next agent. So every claimant is answered with **credentials minted for it
alone**, nothing is shared between claimants, and nothing is rotated.
`punch_scan` advances each in-flight punch: a connected one becomes a worker
(its dashboard row opens there); a failed one, or one past `HOST_PUNCH_MS`
(`ICE_ATTEMPT_MS` for a resumption of a proven worker), is freed. A stuck punch
never blocks the next joiner, since the next joiner has an agent of its own.
A punch in flight gains the egress addresses the pool learns later by being
answered again with its description fanned across them (`host_reanswer`).

**What the host does with an offer** (`host_offer_take`, in order): an offer
whose claimant is already served over lanlink, already being punched under the
same password, queued for LAN admission, or served by a healthy worker, is
left as it stands (`rdv_host_keep`: the earlier answer holds, and the claimant
is told nothing new); an offer under a **new password** from a claimant
already being punched replaces that punch (`punch_tried_again`); at
`PUNCH_PARALLEL_MAX` punches for one claimant the oldest is reaped; a fresh
claimant past `--max-clients` is **refused in its slot** (`sig_refuse`,
`REFUSE full`), which ends its join with `SESSION_FULL`; everything else is
answered as above once an agent is ready and a punch slot is free, and waits
in the queue meanwhile. An offer is replayed by nothing: the slot's sequence
filters a lagging copy before the turnstile sees it (§4).

**A client that has qualified nothing** within `PATH_PROBE_MS` of priming the
host's answer regathers with a fresh ICE identity
(`session.c:client_regather`), which writes a new offer the host answers with
a new agent; so does one whose host moved (a higher generation in the host
slot, §4 L3) or whose SSH bring-up failed outright. A host never regathers for
a claimant on its own: it answers what it is offered.

**An offer from a claimant the host already serves is a resumption.** The
ufrag is session-stable, so it names the same client across its offers, as the
instance id does across its sessions. If the worker serving it has lost its
client, the offer is that client returning, and its punch ends in a graft
rather than a worker: the punched agent's callbacks are re-pointed at the
worker's connection -- packets land in its stream from that instant -- and the
agent is parked for the worker's own thread to adopt as the sending one, since
`c->nat` belongs to that thread. The punch shell is dissolved with no worker,
no dashboard row and no registration of its own, and the worker's reap is held
off while the punch runs. From a *healthy* worker the same offer is left
standing, as are offers whose punch is already in flight, and resumptions
inside `RESUME_ATTEMPT_MS` of the last -- the window between a graft and its
first probe, where the worker still reads as lost. When a worker is reaped its
claimant is forgotten (`sig_claimant_gone`), keeping only the sequence that
filters a replay of its last offer, so the same instance coming back is
admitted afresh. Anyone holding the token can offer under any ufrag, but a
resumption moves packets, not trust: the SSH session inside the stream
authenticates end to end, so a forged resumption redirects the transport at
worst -- a denial no cheaper than the offer spam the shared-secret model
already admits (see the slot limit below).

N claimants cost N agents and N answers, and no claimant's punch waits on
another's: once answered, every punch runs concurrently and every worker is
served in parallel. What is serialised is the exchange itself, because one
cell admits one statement at a time (§4), so claimants take their turn to
offer and are answered one after another. What bounds the rate is that turn
and the one gathered agent kept ready at a time.

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

## 13. UX and CLI (`src/main.c`, `src/ui.c`, `src/host.c`)

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
configure the session being started, and a session lasts exactly as long as the
terminal that started it, so a second `comrade` never inherits them: it is told
where the running session is rather than adopting it.

MVC seam (`src/session.h:session_obs`): the controller emits semantic events
(`net`, `link`, `rendezvous`, `rdv_stage`, `token`, `peer`, `reset`, `escalate`,
`established`, `tick`); the view owns all formatting. Peer lifecycle states
`SEEN/PUNCHING/LIVE/GONE`, each addressed by a stable `id` so a multi-user host
draws one row per client.

- **Host dashboard** (`ui.c`): the token to share, and the live peer list
  (per-connection rows keyed by connection id, each with its proven path). A
  connection **service** runs beside it, detached from the terminal so it keeps
  serving while the operator is inside the shared tmux (`host.c`: `run_service`
  re-serves until the tmux session dies).
- **Status row** (`ui.c:ui_render_status`): connection health (green live / amber if smoothed
  RTT over `RTT_WARN_MS 250` / down), RTT, the path in use and its warm
  alternatives (§9), and the rendezvous state; address scope shown as LAN / CGNAT / GLOBAL (`session.c:addr_scope`).
- **Session lifecycle** -- a live session is always on screen, as the shared
  tmux or as the dashboard, in the terminal it was started in. Detaching tmux
  comes back to the dashboard; leaving the dashboard (ESC) ends the session, and
  the shell is not given its prompt back until the service has finished doing so
  (`host.c:teardown`, bounded by `TEARDOWN_WAIT_MS`). Nothing survives the
  operator: the service holds the far end of the event pipe and ends the session
  when it closes -- or when the foreground it was forked from is gone, watched
  alongside it since how a broken pipe reports itself differs between kernels
  (`host.c:hangup_watch`). That covers a hangup, a closed window, or a kill -- and a later `comrade` starts a new session rather than
  adopting one, since there is no session left to come back to. A tmux server
  left standing by a service that was killed outright is collected by the next
  `comrade` (`find_live`, against the service's own pidfile).
- The session also ends when the last shell in the tmux exits on either side; a
  client detaching or dropping never ends it. A guest detaching drops back to
  its own shell with the token to rejoin, exactly like detaching from a local
  tmux; a guest whose session **ended** is told so instead (`CTLM_BYE`, §10),
  and anyone presenting the token afterwards is told the same by the tombstone
  (§4.1) rather than left punching.
- `comrade --headless` is the exception to all of that, deliberately: it is a
  supervisor's service with a pidfile (INTEGRATION.md), owned by whatever
  started it, and an interactive `comrade` never touches one. It still leaves a
  tombstone when it ends.
