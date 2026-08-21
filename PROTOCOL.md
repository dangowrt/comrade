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

Sections and paragraphs marked **PLANNED (0.1.x)** or **PLANNED (0.2.0)** specify
behaviour this tree does not implement yet; everything unmarked is implemented as
described. Each mark is removed when its change lands.

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

---

## 2. Key derivation (`src/keys.c:keys_derive`)

All session keys derive from the token's 16-byte rendezvous secret `R`
(`tok.rdv`, `TOKEN_RDV_LEN = 16`):

```
  sig_key(32)  = BLAKE2b_keyed(key=R, len=32, msg="comrade1 sig key")     # 16 bytes, no NUL
  seed(32)     = BLAKE2b_keyed(key=R, len=32, msg="comrade1 bep44 seed")  # 19 bytes, no NUL
  (bep44_pk, bep44_sk) = Ed25519_keypair_from_seed(seed)
```

`sig_key` seals every mailbox/multicast payload (§4, §6). `bep44_pk/sk` are the
BEP44 mutable-item identity (§5). Both peers derive the **same** keys from the
same token, so the mailbox is a shared rendezvous only they can read or write.

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
| 4 `0x10` | `EP6_SETTLED` | the v6 family's state is determined, not still being worked out *(PLANNED, 0.1.x)* |
| 5 `0x20` | `EP4_SETTLED` | likewise for v4 *(PLANNED, 0.1.x)* |
| 6-7 | | reserved, must be zero |

**Per-family state** *(PLANNED, 0.1.x, for the `PENDING`/`NONE` split; the
`RENDEZVOUS` and `DIRECT` encodings are unchanged from 0.1.0)*. A family's slot
and its two bits encode one of four states.
The families are wholly independent: every mix is legal, and a host that reaches
the DHT over one family only is normal rather than degraded.

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
settles both families to `NONE` at t=0.

**`DIRECT` requires proof** *(PLANNED, 0.2.0)*. The slot is specified and its
encoding fixed, but nothing in 0.1.x may mint it: a host cannot tell whether one
of its own ports is reachable from a stranger's address without an external
prober, and a UPnP/NAT-PMP/PCP mapping reporting success is not that proof,
because a CGNAT gateway will happily report a mapping on an address nothing can
reach. The intended prover is an RFC 5780 `OTHER-SERVER` STUN probe. Until it
exists every globally connected family mints `RENDEZVOUS` and no address of the
host's own ever enters a token. When `DIRECT` does become mintable it takes the
family's slot ahead of `RENDEZVOUS`, because it removes the signalling round trip
altogether; the cold DHT lookup remains the fallback should the host's firewall
later change.

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

One shared mailbox, two slots. The container is a **bencoded dict** with keys in
sorted order (`mailbox.c:mailbox_build`):

```
  d [ 1:a <sealed answer> ] [ 1:o <sealed offer> ] e
```

- `o` (offer) is written by the **host**, `a` (answer) by the **client**.
- Each slot value is a **sealed blob** (§1): `seal(sig_key, candpack)`.
- `candpack` is the compact ICE description (§7). For the DHT it is packed with
  `for_dht=1` (segment-local addresses dropped); the seal makes the DHT value
  opaque.

Publishing (`sig.c:sig_post`): pack the local SDP → `candpack` →
`seal(sig_key, candpack)` → set as this side's slot. Reading a peer slot:
`msg_open(sig_key, sealed)` → `candpack` → rebuilt SDP handed to libjuice.

The host can release the answer slot on offer rotation
(`mailbox.c`: `clear_peer` drops `a` once, `mailbox_arm_release`).

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
`SIG_DHT_RESTORE_MS 8000`, `SIG_DHT_GRACE_MS 2000`.

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
- Groups: v6 `MCAST_V6 = ff02::da7a`, v4 `MCAST_V4 = 224.0.0.224`,
  port `MCAST_PORT = 47654`.
- Packet: `MCAST_MAGIC "pMc1"` (4 bytes) `|| salt_len(1) || salt || payload`.
- **Salt = the sender's own role slot character**: `"o"` (host) or `"a"`
  (client); a receiver listens for the *peer's* slot char (`sig.c` `peer_slot`,
  `ps`). `payload` = `seal(sig_key, mcast_plain)`.
- `mcast_plain` (`sig.c:sig_post`) = `direct_port(2, BE) || candpack`, where
  `candpack` is the **same `for_dht=1` routable set as the DHT slot** (`sig_post`
  reuses the identical packed buffer, not a wider `for_dht=0` one). The peer takes
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
`struct conn` holds its own `lan_peer`/`have_lan_peer`, and `transport_send`
sends a lanlink worker's KCP over the shared socket to that conn's `lan_peer`
while an ICE worker uses its own agent, so the two coexist. The host
demultiplexes inbound datagrams by source on its main thread (`lanlink_dispatch`
uses `recvfrom`; `host_lan_recv` matches the source against the active
`lan_conns[]` and delivers into the owning worker's stream under a per-conn
lock). A client keeps its single `lan_peer`.

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
| conv | `SESSION_CONV = 0x70326531` | `#define` (`session.c:28`), `ikcp_create(conv,…)` (`stream.c:44`) |
| MTU | `STREAM_MTU = 1200` | `ikcp_setmtu` |
| window (snd/rcv) | `STREAM_WND = 256` / 256 | `ikcp_wndsize` |
| nodelay | 1 | `ikcp_nodelay(kcp, 1, 10, 2, 0)` |
| interval | 10 ms | ” |
| fast resend | 2 | ” |
| no-congestion (nc) | 0 (**congestion control ON**) | ” |
| stream mode | 1 | `kcp->stream = 1` |
| dead_link | `STREAM_DEAD_LINK = 1000` | `kcp->dead_link` |

`conv` is a fixed constant shared by both ends. `stream=1` means byte-stream
(not message) framing. `stream_update` drives `ikcp_update`/`ikcp_check`; a
finished receiver LINGERS on `ikcp_waitsnd` until its own sent tail is acked.

---

### Path model and transport probe (`session.c`, `PROBE_MAGIC`)

A **path** is a pair (local transport instance, remote endpoint) over which
sealed datagrams for one connection can be sent. Three kinds exist:

| kind | local transport | remote endpoint |
|---|---|---|
| `SEGMENT` | the shared lanlink socket (§6) | a peer endpoint on the link, learnt from a sealed multicast announcement |
| `ROUTED` | the shared lanlink socket | any other peer endpoint, learnt in band or from a probe that arrived from it *(PLANNED, 0.1.x)* |
| `ICE` | a libjuice agent (§8) | its nominated pair |

The kind is a description, not a rank: it names how a path was come by and
nothing else, and plays no part in choosing between paths. A connection tracks up
to `PATH_MAX` of them and carries KCP over exactly one at a time.

Path management is **symmetric and role-free**. comrade's application model has a
host and a client -- one owns the tmux, one claims the turnstile (§12) -- but
that asymmetry ends at admission. Both ends run identical path code: both probe,
both measure, both rank, and both arrive at the same choice without either
deciding for the other.

**Invariants.**

1. A path carries the session only once a probe has round-tripped on it. Nothing
   else qualifies a path: a transport reporting a pair says that packets move,
   not that the far end is serving *us* (§12).
2. Every end accepts stream data on **every** path it holds, not only the one it
   sends on. Selection is therefore never a negotiation, and a transient
   disagreement costs nothing but a moment of asymmetric routing.
3. All obtainable paths are kept **warm**, not merely the one in use, so a switch
   is an immediate reordering rather than a rediscovery.
4. A host **speaks first**, on its lowest-cost path whatever its qualification
   state, because its banner is what supplies the client's proof. Qualification
   reorders paths; it never gates the first send.

*(PLANNED, 0.1.x: everything below beyond invariant 1. 0.1.0 keeps one flag and
one RTT per transport kind, probes only until something qualifies, never probes
from the host, and prefers by a fixed class order.)*

#### Probe frame

```
  PROBE_MAGIC 0x434d5250 ("CMRP")
  [4 magic][seal(sig_key, plain)]

  plain = [1 type][8 nonce][1 ulen][ulen claimant ufrag]      head
          [16 addr][2 port BE][2 srtt_ms BE][2 loss_ppt BE]   tail, optional
  type: 1 = PING, 2 = PONG (echoes the nonce)
```

`deliver_stream()` splits probes off ahead of `stream_input()`: every KCP
datagram opens with the fixed `SESSION_CONV` and `ikcp_input` rejects a mismatch,
so a datagram opening with a different magic is unambiguously not stream data.

The head is unchanged from 0.1.0. The 22-byte tail is present when the plaintext
runs past `10 + ulen`; a peer that omits it merely shares no measurements, which
costs accuracy and never correctness.

- **addr/port** is the source this path's last inbound datagram was observed
  arriving from, v4 carried v4-mapped, all-zero when nothing has arrived yet. On
  a PONG it is the source of the PING being answered, so a prober learns its own
  reflexive endpoint on that path for free. That echo is also the groundwork the
  RFC 5780 work in §3 builds on.
- **srtt_ms** is the sender's current smoothed round trip for this path, 0 when
  unmeasured; **loss_ppt** its probe loss in parts per thousand.

The seal is not defending against the peer, who holds the token and is trusted by
construction (§12); it stops a stranger who can guess an endpoint from forging a
reply. The **nonce must be unpredictable**, being the only thing that stops a
forged PONG. *(PLANNED, 0.1.x: `session.c:probe_pump` derives it from `now_ms()`,
which any token holder can guess; it has to be `random_bytes`.)*

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
  id(P) = cc_blake2b_keyed(sig_key, min(Ea,Eb) || max(Ea,Eb))[0..8]
```

`min`/`max` are plain byte comparisons, so the value is order-free and no role
appears in it. Keyed BLAKE2b is the primitive from §1; nothing new is introduced.

#### Qualification, warmth and measurement

One probe is outstanding per path, carrying its own nonce and send timestamp, so
a round trip is measured from the probe that was actually answered. *(PLANNED,
0.1.x: `probe_start_ms` is set once per attempt today, so a reported RTT includes
every retry that preceded the answer.)*

| state | condition |
|---|---|
| `UNQUALIFIED` | never answered |
| `WARM` | answered within `PATH_WARM_MS` |
| `COLD` | qualified once, silent for longer than `PATH_WARM_MS` |
| `DEAD` | silent for longer than `PATH_DEAD_MS` |

Per path each end keeps a smoothed round trip (EWMA, alpha 1/8), a loss ratio
over the last 16 probe outcomes, and the time of the last PONG. It probes an
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
  bucket(P) = ceil(cost(P) / PATH_COST_QUANTUM_MS)
```

Selection takes the lowest `bucket` among the paths in the best occupied warmth
tier (`WARM`, else `COLD`), ties broken by the lowest `id(P)`. That is the whole
of the agreement: **consensus by deterministic function over shared observations,
not by handshake.** No leader, no vote, no role. Quantisation and the id
tie-break are what keep measurement noise from splitting the two ends.

Divergence remains possible while a measurement update is in flight, and is
harmless by invariant 2.

**Switching** is immediate when the path in use goes `DEAD`. Otherwise a
candidate must win by `PATH_SWITCH_MARGIN` buckets for `PATH_SWITCH_HOLD`
consecutive evaluations, so near-equal paths cannot flap. Both ends apply the
identical rule to the identical numbers and so flip together.

| constant | value | meaning |
|---|---|---|
| `PATH_MAX` | 4 | paths tracked per connection |
| `PROBE_EVERY_MS` | 200 | probe period while unqualified |
| `PATH_KEEP_MS` | 1000 | probe period once qualified, every path |
| `PATH_WARM_MS` | 3000 | silence beyond this: `WARM` becomes `COLD` |
| `PATH_DEAD_MS` | 8000 | silence beyond this: `COLD` becomes `DEAD` |
| `PATH_LOSS_PENALTY_MS` | 200 | cost added by total loss |
| `PATH_COST_QUANTUM_MS` | 5 | ranking bucket width |
| `PATH_SWITCH_MARGIN` | 1 | buckets a candidate must win by |
| `PATH_SWITCH_HOLD` | 2 | consecutive evaluations it must hold |

#### Adding a path mid-session

*(PLANNED, 0.1.x.)* A sealed PING naming a connection's claimant ufrag **adds a
path** for that connection, whatever source it arrives from. This is what lets an
end whose address changed keep the session: it simply probes from the new source,
and the peer picks the new path up.

The rule is **add, never replace**. A new endpoint enters the path table as one
more candidate and ranking decides whether it carries anything (§9 "Ranking and
symmetric selection"); it never displaces the endpoint in use. A late datagram
from an address that has gone away therefore cannot flap the binding: the stale
path simply cools and is evicted, oldest `DEAD` first, when the table is full at
`PATH_MAX`.

**Why the ufrag suffices.** It is not a secret between token holders -- it
travels in the mailbox slot every holder of `R` can read and unseal (§4, §12) --
and it does not need to be. Everyone holding a token can reach the machine
anyway, and the read-only grade shares the same `R`, so `sig_key` and every
capability it confers (mailbox reads, sealed announcements, turnstile claims) are
already common to both grades. Disruption between token holders is out of scope;
the boundary the seal defends is the **stranger**, who holds no `R`, can seal
nothing, and cannot attach to anything.

**Bounding the cost.** A datagram from an unknown source can only be matched to
a connection by trying its seal against each candidate, so an implementation must
bound that work: only a frame opening with `PROBE_MAGIC` is a candidate at all,
and unknown-source attempts are rate-limited (`PATH_ADOPT_RATE`, per second, per
listening socket). Without the bound a stranger who can seal nothing still costs
one AEAD open per live connection per junk datagram.

**What this does and does not recover.** It recovers an address change that
leaves the peer's endpoint reachable: a DHCP renewal, a move between interfaces
on one segment, a multi-homed end bringing a second address up. It does not
recover a move to a network from which the peer's endpoints are unreachable at
all; that still needs fresh signalling, which is what the always-engaged DHT of
§5 and the warm rendezvous nodes of §11 exist to make quick.

Paths are not only discovered by accident, either. Each end advertises its own
local candidate endpoints over comrade-ctl (`CTLM_CAND`, §10) and probes every
endpoint the peer advertises, so both ends explore the full set rather than only
the pair admission happened to produce. A multi-homed end therefore has its
alternatives already `WARM` before anything fails, which is invariant 3 applied
to discovery rather than only to upkeep.

---

## 10. SSH session (`src/sshd.c`, `src/sshc.c`, `src/sshbridge.c`)

libssh server (host) and client (joiner) over the KCP byte stream
(`sshbridge.c` couples a socketpair fd to KCP with buffered backpressure and a
bounded-linger teardown).

- **Host key**: host mints an ephemeral **ed25519** key; the token's `hostpub`
  is `SSH_PUBLICKEY_HASH_SHA256` of that key (`sshd.c`, `sshc.c:make_host_fp`).
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

A second SSH channel carries heartbeat + roam re-signal. Framing (no magic, no
per-message checksum; the SSH channel provides integrity):

```
  frame = type(1) | len(1) | payload(len)
```

Message types (`ctlproto.h`): `CTLM_PING 0` payload `timestamp(8, BE)`;
`CTLM_PONG 1` payload echoed timestamp(8); `CTLM_RDV 2` payload
`family(1) | port(2,BE) | addr(16)` = `CTL_RDV_PLEN 19` (a warm rendezvous node
for the peer to reuse on a roam); `CTLM_CAND 3` *(PLANNED, 0.1.x)*, same 19-byte
payload shape, one local candidate endpoint the peer should probe and hold as a
path (§9). `CTL_HDR = 2`, `CTL_FRAME_MAX = 21`.

---

## 11. Roaming, reconnect, keep-alive (`src/session.c`)

- Heartbeat over comrade-ctl: `HB_INTERVAL_MS 700`, link lost after
  `HB_LOST_MS 2500`, a vanished host worker reaped after `HOST_REAP_MS 12000`.
- Network changes are polled (`netmon`, `NETMON_POLL_MS 2000`).
- Each end keeps a **warm rendezvous node per address family** and exchanges it
  over `CTLM_RDV`, so either side can re-signal quickly after a move. This is
  what the unconditional DHT engagement of §5 exists to feed: a node can only be
  exchanged if one was ever located.
- **Roaming is a path switch, not a rejoin** *(PLANNED, 0.1.x)*. When the path
  carrying the session dies, the session moves to the best warm path (§9) with
  the connection, the worker, the tmux attach and the KCP stream all intact. The
  peer needs no notice, since it accepts on every path it holds.
- **Reconnect == new join** (tmux redraws) is the fallback for when *no* path is
  warm, with a grace window `SSHC_REJOIN_GRACE_S 6` so a transient blip resumes
  without a re-punch.
- **Signalling is rebuilt on a move** *(PLANNED, 0.1.x)*. A fresh `sig` binds a
  new DHT socket on the new network, where the old one stays stuck on the
  interface that vanished; that is why a manual restart reconnects instantly
  where a reused socket does not. It is re-seeded from the rendezvous nodes
  learnt over `CTLM_RDV` rather than from the token, whose slots may long since
  be stale. (`sig_setup` runs exactly once today, at session start.)
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
| `--no-dht` | decline the DHT entirely: link-local discovery only, and both token families settle to `NONE` (§3, §5) |
| `--no-forwarding` | host declines all client forwards |
| `-v`, `--verbose` | log lines instead of the dashboard |

`--no-dht` names the mechanism it declines rather than the medium it assumes. A
future non-IP transport (BLE, LoRaWAN, AX.25) would make a `--lan-only` spelling
meaningless, while "no DHT" still says exactly what it does.

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
