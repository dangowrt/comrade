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

Flags (`token.h`): `RO 0x01` (read-only credential, §2/§10), `NODHT 0x02` (host
is not on the DHT). All four flag bits are live. `NODHT` is set by an
isolated-LAN host (§12) and honoured by the client (`main.c`: a `NODHT` token
drops `SIG_DHT`, leaving multicast only), so the client never queries the DHT and
finds the host over multicast + lanlink. `EP6_RDV 0x04` / `EP4_RDV 0x08` mark the
matching endpoint slot as a **rendezvous DHT node** address rather than a direct
host endpoint; with the bit **clear** the slot is a **direct host endpoint**,
which an isolated-LAN host fills with its own lanlink endpoint and a client
preloads to start KCP toward the host at t=0 (`session.c:client_direct_connect`)
instead of waiting to hear the host's announcement.

Wire form: payload(90) `||` **CRC-32/IEEE** over the payload (4 bytes, stored as
two BE `put16` halves `sum>>16`, `sum&0xffff`) = `TOKEN_WIRE_LEN = 94`.
`crc32` is the standard reflected `0xedb88320` variant, init `0xffffffff`,
final XOR (`token.c:crc32`); integrity only, not security.

String form: **base58** of the 94-byte wire (`src/base58.c`, Bitcoin alphabet
`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`), then
**left-padded with `'1'`** to a constant `TOKEN_STR_LEN = 94*138/100+1 = 130`
characters. Decode requires exactly 130 chars, base58 back to 94 bytes, CRC
match, and `version == 1`.

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

### Transport probe (`session.c`, `PROBE_MAGIC`)

The transport carries one more thing beside the KCP stream, and the two are told
apart for the cost of one compare: every KCP datagram opens with the 4-byte
conversation id and `ikcp_input` rejects a mismatch, and comrade uses the single
fixed `SESSION_CONV`, so a datagram opening with a different magic is
unambiguously not stream data.

```
  PROBE_MAGIC 0x434d5250 ("CMRP")
  [4 magic][seal(sig_key, [1 type][8 nonce][1 ulen][ulen claimant ufrag])]
  type: 1 = PING, 2 = PONG (echoes the nonce)
```

`deliver_stream()` splits probes off ahead of `stream_input()`. The seal is not
defending against the peer, who holds the token and is trusted by construction
(§12); it stops a stranger who can guess an endpoint from forging a reply.

**A path is qualified when a probe round-trips on it**, and nothing else
qualifies a path. That is strictly stronger than a transport reporting a pair: it
proves reachability in both directions, and -- because the probe carries the
**claimant ufrag** and a host worker answers only for the claimant it was
admitted for -- it proves the far end is serving *this* client rather than
somebody who happened to read the same offer (§12). A client sends a probe on
every candidate path every `PROBE_EVERY_MS`; the host answers and never sends.

**Path preference.** Qualification says a path works; class says which working
path to use, lowest first:

| class | recognised by | why |
|---|---|---|
| LAN | a qualified lanlink endpoint | same segment: no NAT binding, no ICE keepalive, no gateway, lowest RTT |
| ICE local | qualified ICE whose remote is LAN-scope | on-segment, but pays ICE overhead |
| ICE reflexive | anything else | leaves the segment; for two peers behind one NAT this is the hairpin case, which is slower and which many routers cannot do |

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
for the peer to reuse on a roam). `CTL_HDR = 2`, `CTL_FRAME_MAX = 21`.

---

## 11. Roaming, reconnect, keep-alive (`src/session.c`)

- Heartbeat over comrade-ctl: `HB_INTERVAL_MS 700`, link lost after
  `HB_LOST_MS 2500`, a vanished host worker reaped after `HOST_REAP_MS 12000`.
- Network changes are polled (`netmon`, `NETMON_POLL_MS 2000`); on a change the
  connection context resets (drop stale local candidates, peer and "link up"),
  re-signals, and re-punches.
- **Reconnect == new join** (tmux redraws), with a grace window
  `SSHC_REJOIN_GRACE_S 6` so a transient blip resumes without a re-punch.
- Each end keeps a **warm rendezvous node per address family** and exchanges it
  over `CTLM_RDV`, so either side can re-signal quickly after a move.

---

## 12. Multi-user turnstile (`session.c:host_turnstile`)

A host serves up to `HOST_MAX_WORKERS = 16` concurrent clients on one shared
tmux session. `host_is_multiuser = is_host && (sig_flags & (SIG_DHT | SIG_MCAST))
&& !test_single_conn`, so an isolated-LAN host (multicast only, no DHT) runs the
turnstile too. A worker's `conn_run(conn, drive_sig=0)` does not pump sig; the
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
| `--no-forwarding` | host declines all client forwards |
| `-v`, `--verbose` | log lines instead of the dashboard |

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
  RTT over `RTT_WARN_MS 250` / down), RTT, the in-use path, and the rendezvous
  state; address scope shown as LAN / CGNAT / GLOBAL (`session.c:addr_scope`).
- The session ends when the last shell in the tmux exits on either side; a
  client detaching or dropping never ends it.
