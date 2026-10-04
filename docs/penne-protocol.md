# Penne frontline protocol specification (minimum supported), v1

Status: implemented-against. Supersedes: nothing. Date: 2026-09-11.
Scope: the persistent notification connection ("frontline") of Penne/NPNS on
Horizon 22.5.0, plus the REST registration surfaces that feed it. This document
is the protocol gate required by `../prds/native-switch-penne-notifications-prd.md`
(NTF-02): no native delivery is claimed beyond what is stated here.

Every statement carries a provenance label:

- **[firmware]** — recovered from the Horizon 22.5.0 NPNS module
  (`010000000000002F`, NSO build ID `942e27bd…`) by static analysis. Working
  files live in the private analysis directory; no firmware content is
  committed. Module-relative RVAs below are +0 relative to the ELF's own
  addresses; the Ghidra projects load at base 0x100000.
- **[wire-spec]** — the public FlatBuffers wire format documentation.
- **[observed]** — captured console traffic from earlier hardware sessions
  (Fix_Experimental trace), as recorded in the repo docs.
- **[hypothesis]** — best-evidence inference, marked, never to be presented as
  interoperability until a runtime capture confirms it.

## 1. Registration REST surfaces [observed]

Hosts and response shapes are observed; the console bootstraps through them in
order and fails loudly (empty replies, wrong keys) when they deviate.

| Host | Route | Response (shape) |
| --- | --- | --- |
| `god.penne.srv.nintendo.net` | `POST /v1/penne_ids` | `{"id": "p…", "password": "…"}` |
| `god.penne.srv.nintendo.net` | `POST /v1/immigrate` | 404 (nothing to migrate) |
| `god.penne.srv.nintendo.net` | `…/notification_tokens` | `{"notification_token": "…"}` |
| `god.penne.srv.nintendo.net` | `…/links` | `{"nsa_id": "…"}` |
| `val.penne.srv.nintendo.net` | `POST /v1/frontlines` | `{current_time, frontline_fqdn, persistent_connection_params_simple}` |
| `val.penne.srv.nintendo.net` | `POST /v1/login_tickets` | `{ticket, issued_at, expires_at, frontline_fqdn, persistent_connection_params_simple}` |

`persistent_connection_params_simple` [observed]:
`awake/sleep: {count, idle, interval}`, `wait_sec`, `ignore_rst`, `retry_count`.
The firmware also requires `wowl_timeout`, `rtt_max`, and a `disable` boolean in
both awake and sleep settings [firmware, follow-up 2026-09-12]. NPNS RVA
`0xBF100` combines all seven child validation flags; `0xB8B50` requires the
result before accepting a login ticket. Omitting these fields fails validation.
The server now includes the defaults recovered from constructor RVA `0xB82E0`:
`wowl_timeout: 410`, `rtt_max: 300`, `awake.disable: false`, and
`sleep.disable: true`. These values are firmware defaults, not measured operating
limits. Hardware progression past login remains a separate verification gate.

This adapter's server-side semantics (beyond the shapes): registrations are
durable and device/account-bound; notification tokens and login tickets inherit
the binding; everything minted under a registration dies with it on revocation;
a supplied id authorizes nothing without its password [implementation, NTF-01].

**Open:** the request-side field names for `notification_tokens`,
`login_tickets` and `links`. Where a request carries no recognizable
credential, the adapter falls back to the device's newest association; this
fallback is provisional and a hardware capture should settle the real shapes.

## 2. Framing

- **Client → server:** the message routine passes a body reader of
  *four-byte little-endian length, then that many bytes of buffer* to the HTTP
  transport [firmware, send path around RVA `0xD4010`].
- **The frontline connection is downlink-only** [firmware + runtime,
  2026-09-12]. The request body's producer object is constructed with an empty
  segment list at connect (`0xd9250` builds the sink on its own stack with
  base, length and index all zero; the producer's copy-out method is `0xb9560`,
  its "finished" predicate `0xb9630`), so the console streams nothing up on
  this request. Production traffic agrees: every frontline POST arrives with no
  Content-Length, no Transfer-Encoding and a zero-byte body. **`frames_in: 0`
  on a live connection is therefore the designed behaviour, not a symptom** —
  the console's own messages must travel as separate requests, and waiting for
  uplink frames on the held-open POST waits forever.
- **Server → client: four-byte little-endian length, then exactly that many
  bytes** [firmware, 2026-09-12 — confirmed, no longer a hypothesis]. The
  decoder is fed one byte at a time at RVA `0x1e8d70`: it collects four bytes,
  reads them as a `uint32` length, rejects a **zero length** (error `0x703`)
  and a length past its buffer (`0x303`), then collects exactly that many bytes
  and marks the message complete. `0x1e8d50` initialises it (header mode on),
  `0x1e8e00` reports completeness. The send direction is the same shape, so the
  framing is symmetric after all. The response is held open and streamed; whether the
  console's parser expects chunked transfer encoding around those frames is
  part of the same open question. The implementation sends
  `Transfer-Encoding: chunked` (hand-written after hijack) so both a
  chunk-aware and a raw reader have a defensible stream. The response side goes
  through libcurl's WRITEFUNCTION (`0xb55b0`, paired with READFUNCTION
  `0xb5530`; the option table sits at `0x16b208`/`0x16b210`), which feeds a
  consumer object hung off the transfer at `+0x28`. **Open (static only):**
  that consumer's class for the frontline transfer, which is what names the
  delimiter; the setter is `0xb6ef0`. The behavioural half is settled
  [runtime, 2026-09-12]: the console consumed our chunked stream — handover,
  sync reply, everything — all the way into the steady state, so the length
  prefix inside the chunks is confirmed end to end.
- Heartbeats: **no content-bearing keepalive is sent.** The newline heartbeat
  this implementation replaced was unvalidated [observed shape, unvalidated
  content], and any stray byte desyncs a length-prefixed decoder. The client's
  own `persistent_connection_params` drive its traffic; TCP keepalive is on.

## 3. Envelope and message slots

The envelope is a FlatBuffers table whose field 0 (first vtable slot) is the
one-byte union discriminator and whose field 1 is the union payload table
[firmware: the send path switches on slot 0 as a byte and dereferences slot 1
as an indirect table]. Table/vtable layout per [wire-spec]. Root fields ≥ 2 are
**not recovered**; nothing may assume them.

The union slot table was recovered from the message-name table at module
RVA `0x168968` [firmware]. Slot value = discriminator. The one slot the earlier
findings had pinned independently (`SubscribeTopic` = `0x17` = 23) matches,
which is what validates the table's interpretation.

| Slot | Name | Slot | Name |
| --- | --- | --- | --- |
| 0x00 | NONE | 0x14 | Idle |
| 0x01 | MessageRequest | 0x15 | PutRequest |
| 0x02 | PublishRequest | 0x16 | DeleteRequest |
| 0x03 | KickRequest | 0x17 | **SubscribeTopic** |
| 0x04 | PutRecord | 0x18 | Nack |
| 0x05 | DeleteRecord | 0x19 | SubscriptionList |
| 0x06 | RootHash | 0x1a | ResendRequest |
| 0x07 | LeafHash | 0x1b | DAPresence |
| 0x08 | SyncComplete | 0x1c | SubscriptionListRequest |
| 0x09 | Ack | 0x1d | MyAccountMessageRequest |
| 0x0a | HandoverRequest | 0x1e | ReloadLink |
| 0x0b | HandoverResponse | 0x1f | SubscriptionUpdated |
| 0x0c | HandoverResult | 0x20 | Hi |
| 0x0d | Reset | 0x21 | Onset |
| 0x0e | PowerState | 0x22 | PresenceNotifyRequest |
| 0x0f | DebugDisconnect | 0x23 | DenySubscribe |
| 0x10 | Ping | 0x24 | TopicRead |
| 0x11 | Pong | 0x25 | CrewNotifyRequest |
| 0x12 | DebugUpdateRecord | 0x13 | DebugDeleteRecord |

Recovered payload shapes (from the send path's per-type logging) — field
positions are vtable slot numbers; **positions, not semantics**, are what the
firmware shows:

- Ping (0x10): three uint64 fields [firmware].
- Pong (0x11): one uint64 [firmware]; echoing Ping's field 0 is [hypothesis].
- Hi (0x20), SyncComplete (0x08), SubscriptionListRequest (0x1c): logged with
  no payload fields [firmware].
- Ack (0x09), ResendRequest (0x1a), ReloadLink (0x1e), DebugDeleteRecord
  (0x13): one field each; scalar vs string not distinguished by the evidence
  [firmware shape, semantics open].
- SubscribeTopic (0x17): the client's builder formats the topic name as
  `%016llx` of a u64 — sixteen lowercase hex characters — when the topic id is
  numeric, plus a second string and boolean flags [firmware, builder at RVA
  `0xEAA10`]. Exact payload vtable slots: **open**. The caller tracks the
  `topic.subscription` operation with a **10-second** confirmation deadline
  [firmware, `0xDD980`], which is the one timeout in this protocol with
  evidence behind it.
- DAPresence (0x1b), Reset (0x0d), PowerState (0x0e), Nack (0x18),
  SubscriptionList (0x19), Onset (0x21), DenySubscribe (0x23), TopicRead
  (0x24), MyAccountMessageRequest (0x1d), SubscriptionUpdated (0x1f): partial
  shapes only [firmware]; see the decoder's field readers in
  `internal/penne`.
- Record-sync machinery (PutRecord/DeleteRecord/RootHash/LeafHash + vectors):
  present with vector-of-table payloads [firmware]. RootHash and PutRecord are
  implemented server-side (`BuildRootHash`, `BuildPutRecord`); DeleteRecord,
  LeafHash and the leaf drill-down are not.

## 4. What the server sends today, and why

| Message | Trigger | Evidence status |
| --- | --- | --- |
| Pong (echoing Ping f0) | inbound Ping | shape [firmware]; echo [hypothesis] |
| SubscriptionUpdated (unix second) | inbound SubscribeTopic | shape [firmware]; meaning of value + whether a reply is required within the 10 s deadline [hypothesis] |
| HandoverResult (0x0c), field 0 = 0, on connect | connection accepted | **[firmware]** — the console reads exactly this message before anything else (§4b) |
| ~~Hi (0x20), no payload~~ | superseded | was a hypothesis; the console rejects it by name
| PutRecord carrying a **kind-1 message** | outbox delivery | shape **[firmware, 2026-09-16]** — the payload is a vector of kind-tagged entries, not `{name, value}`; a notification is a message routed by its `Meta`, not a stored record (`docs/penne-record-shape-2026-09-16.md`, §4d below). The old MessageRequest carrier is **superseded**: the steady state rejects it on arrival. Open half: the receiver token (N5) |

The five native event kinds the dispatcher recognizes [firmware]:
`presence_updated`, `friend_invitation_received`, `friend_request_received`,
`friend_request_authorized`, `friend_deleted`. The server never invents other
kinds, never answers unknown slots, and never substitutes newline/JSON body
bytes for frames.


## 4a. Addressing: events must name a console account

The friends module's dispatcher (`0xA15C0`) matches the five event names and
calls one handler each. Every handler returns immediately unless the 128-bit
account id it was handed is non-zero — `friend_request_authorized` at
`0x1A1BB0`, `friend_deleted` at `0x1A1C60`, both guarded by
`if (*p != 0 || p[1] != 0)` on two 64-bit words copied from the notification
context at `+0x30`/`+0x38` [firmware, 2026-09-12]. The id arrives with the
message from the NPNS layer, not from the JSON body.

That id is the one the console itself puts in `/v1/accounts/%016llx%016llx/...`
[npns `0x120f4b`]. The adapter records it against the registration that
authenticated the call, and against a BAAS account when the same request proved
one (`NoteAccount`); it is never derived from a device certificate, because one
console holds several accounts and guessing which is which loses events.

**Open:** which field of which carrier puts that id on the wire. Until the
console subscribes to a topic — `subscriptions` is still 0 — the likeliest
mechanism is the topic a message is published to rather than a field in the
event frame, since the console's SubscribeTopic builder formats a topic as
`%016llx` of a u64 [firmware `0xEAA10`].

## 4b. The opening handshake: HandoverResult, not silence

The state the console enters once the frontline response opens (RVA `0xd9730`)
reads **exactly one message** with a 70-second deadline (`0xd2100`, timeout
`70000000000` ns) and accepts only two types:

- `HandoverResult` (0x0c) — its payload table's **field 0 is a byte**: zero
  continues to normal operation, non-zero sends the console down the retry path
  at `0xda010`. An absent field reads as zero.
- `Reset` (0x0d) — `0xd9b30`.

Anything else is logged as *"HandoverResult expected, but \"%s\"(%d)
received."* and fails the connection. That is what a console holding a silent
connection for ~65 seconds was doing: waiting out its 70-second deadline for a
handover that never came, then reconnecting.

On a zero result the console proceeds to `0xda1a0`, which **sends** — it builds
a list of up to 100 items (`0xb1c40`) and serialises it through the send path
(`0xd4010`). That is the subscription sync we have never seen arrive: it comes
after the handover, not before it.

## 4c. The rest of the opening sequence, as the firmware runs it

Each state reads one message and accepts only the types it names; everything
else is a logged type error and a failed connection. Addresses are ELF virtual
(Ghidra +0x100000).

| Step | Who | Message | Evidence |
| --- | --- | --- | --- |
| 1 | server | `HandoverResult` (0x0c), field 0 = 0 | state `0xd9730`, §4b |
| 2 | console | a vector of up to 100 entries, each a **string name plus a 20-byte digest**, followed by a two-byte string and two timestamps (`now`, `now + 3600`) | builder `0x1eb310` (entry stride 0x34: 0x20 name + 0x14 hash), source list `0xb1c40`, sent through `0xd4010` from state `0xda1a0` |
| 3 | server | `RootHash` (0x06) **or** `LeafHash` (0x07) — or `Reset` (0x0d) | state `0xda2f0`: *"LeafHash/RootHash expected, but \"%s\"(%d) received."* |
| 4 | both | record reconciliation: the `RootHash` handler (`0x1dab90`) parses a vector of entries carrying string names, then state `0xdba50` merges two sorted sets of **32-byte keys** — the client's records against the server's — which is what `PutRecord` (0x04), `DeleteRecord` (0x05) and `SyncComplete` (0x08) are for. `LeafHash` takes the parallel path (`0x1da490` → `0xdb120`). |
| 5 | server | `PutRecord` (0x04) / `DeleteRecord` (0x05) until the sets agree, then the steady state | `0xdbf20`: *"PutRecord/DeleteRecord expected, but ...received."*; handlers `0x1dc0b0`/`0x1dc290` loop back to it |
| 6 | steady state (`0xdc9e0`) | see §4d | *"Unexpected command \"%s\"(%d) received in steady state."* |

So this is a Merkle-style subscription sync, not a plain "subscribe and push":
the console offers digests of what it holds, and the server answers with hashes
until the two agree. Steps 1–3 are implemented and hardware-proven (§4f):
HandoverResult, the console's opening RootHash, and the empty-vector reply that
lands the connection in the steady state. Step 4's drill-down (LeafHash, a
per-record listing) is not implemented and not needed while the server
truthfully holds nothing. Step 2's payload arrived as the firmware predicted
and its parser is `ParseRootHash` in `internal/penne`. Unknown inbound frames
are logged with their bytes for exactly this reason.

## 4d. The steady state, and what a notification actually is

The steady state (`0xdc9e0`) polls for a message with no wait and accepts
**exactly** these types [firmware]:

| Slot | Name | | Slot | Name |
| --- | --- | --- | --- | --- |
| 0x04 | PutRecord | | 0x14 | Idle |
| 0x05 | DeleteRecord | | 0x18 | Nack |
| 0x09 | Ack | | 0x19 | SubscriptionList |
| 0x0d | Reset | | 0x1f | SubscriptionUpdated |
| 0x10 | Ping | | 0x20 | Hi (accepted, ignored) |
| 0x11 | Pong | | | |

Everything else is *"Unexpected command \"%s\"(%d) received in steady state."*
and the connection fails.

**`MessageRequest` (0x01) and `PublishRequest` (0x02) are not in that set.**
The carrier this adapter uses for an event would therefore be rejected on
arrival — those two slots are things the *client* sends, not things it accepts.

A notification is a **record**. `PutRecord` carries a name and a payload:
`0x1dfbb0` unpacks it, `0x1dc430` stores it into the same record store the sync
uses (`0x1b0040(store, name, nameLen, payload, payloadLen, 1)`) and then calls
`0x1d0840`, which is what wakes the subscriber — the friends module. That is
also where its 128-bit account id comes from: the record namespace, not a field
inside the event body (§4a). Keys are compared as up to 32 bytes, which is the
width of the account id the console writes as `%016llx%016llx`.

So delivery is not "push a frame". It is: complete the sync, then write a
record under the recipient's key and let the console's record store hand it to
the friends module.

**Superseded 2026-09-16.** The paragraph above read `0x1dc430` (the kind-2
handler) as if it were the whole of `PutRecord`. The parser above it
(`0x1dfbb0`) reads the payload as `{0: [Entry], 1: u8 1}`, each entry tagged
with a kind: kind 2 stores a record, kind 1 is a **message** that `0x1dc510`
queues by `deliverAt` and hands to the IPC layer as the struct the friends
module reads. A notification is the message. Full shape, including the `Meta`
that addresses it and the `"NX"` in envelope slot 2:
`docs/penne-record-shape-2026-09-16.md` §2.

Which also settles §4a, though not the way this read at first: the account id
does travel with the message, in `Meta.accountId`, as the 32 hex chars
`0x1e9000` parses. An empty one leaves the uid zero and the friends handlers
drop the event, so the server addresses each delivery from `AccountsFor` —
the accounts the console itself named on its notification-token calls — rather
than relying on the connection being per account.

### Topics, and the one the friends module listens on

A `RootHash` entry names a **namespace**; a record is named for a **topic**,
which is a dotted path under one. Topics seen as literals across the modules:

| Topic | Module |
| --- | --- |
| `c-friends.inv.subsTypes` | friends |
| `c-appearance.main`, `c-appearance.controller` | appearance (NIM reads these as `devices[*].appearance.*.payload`) |
| `c-settings.LanguageCode` | settings |
| `c-storage.summary` | ns (beside `topic.subscription` in npns) |

The friends module makes **exactly one subscription in its entire init** —
`FUN_001eaa30("c-friends.inv.subsTypes", "friend", 6)` at `0x17bd24` — and that
looked like the name a notification had to be written under. It is not: the
call is a proxy write on `npns:s` slot 49, so the console *uploads* that pair
rather than listening for it (`docs/penne-record-shape-2026-09-16.md` §1).
Writing it from the server is a no-op for the friends module. That is
open question N2, answered **no**.

Record values are themselves documents: `ns` reads `$.key.{id,type,ownerNaId,
userNaId}` and `$.data.{naId,applicationId,…}` out of a record, so a record is
`{key: {...}, data: {...}}` for at least some topics.

**Implemented:** deliveries go out as a kind-1 message inside `PutRecord`,
addressed by `Meta.accountId` to the recipient's console account and routed by
`Meta.receivers` (`penne_deliver.go`, `penneMessageFrames`;
`internal/penne.BuildMessage`). The record store is no longer on that path and
nothing writes to it today; it stays because the leaf half of the sync reads
it. A sync answers
with an **empty entry vector** (§4f) — the one reply the console accepts —
because a partial or mismatched RootHash invites a leaf drill-down the server
cannot answer yet, not because we hold nothing we could describe.

## 4e. The sync message, captured from the console

A live console opened the sync with this, one second after the handover
[runtime capture, 2026-09-12, 320-byte frame]:

- **Envelope** — richer than slots 0 and 1, which is all this adapter used to
  write: `{0: u8 type, 1: payload table, 2: u32 count (20 as sent), 3: u32
  issued (unix seconds), 4: u32 expiry (issued + 3600)}`.
- **RootHash payload** — `{0: vector of entries}`, each entry
  `{0: string name, 1: [ubyte] 20-byte digest}`.
- The four names the console holds: **`c-appearance`, `c-friends`,
  `c-settings`, `c-storage`**. `c-friends` is the namespace the friends module
  reads, so a friend notification is a record written there.

**The answer is an empty entry vector** — `RootHash` with the envelope filled
and no entries — and it cost a month to find. The candidate rotation and the
full elimination table are §4f; what matters for the state machine is what the
console does with it: it answers SyncComplete and enters the steady state
(`0xdba50 → 0xdbe50 → 0xda010 → 0xdc9e0`), and only then acts on its own
behalf — subscribing to topics and publishing presence, both observed in §4f.

A mismatched or partial RootHash is what triggers the console's LeafHash
drill-down, and the leaf level is not implemented server-side — which is why
the sync keeps answering empty even now that the record store
(`penne_records.go`) holds digests for the records we do write. Upgrading the
reply from "we hold nothing" to "we hold these records" waits on the console
being proven to accept a pushed record (open question N2).

## 5. Connection lifecycle (implemented)

1. `POST https://<frontline>/` with `Authorization: Bearer <login ticket>`,
   `X-Protocol-Version: 4`, `X-Power-State`, `X-Hug`, `X-System-Version`,
   `X-Network-Type` [firmware header set at `0xD9250`].
2. Server validates the ticket: known, unrevoked, unexpired, device-matched.
   Any failure is a plain 401 before streaming; the console re-registers.
3. Server answers 200 `application/octet-stream`, held open.
4. Frames flow both ways. The server: decodes, counts unknowns, persists topic
   subscriptions, answers what §4 lists, pumps outbox deliveries.
5. On connect the server reconciles: queued, unexpired, unacknowledged
   deliveries are sent before new work; delivered ids are remembered 24 h so a
   reconnect does not re-alert. Delivery is **at-least-once**; deduplication is
   by event id at the recipient.
6. On silence: no invented keepalive bytes; the connection closes on error or
   cancellation, with the chunked terminator written when possible.

## 6. Transport notes (Go server specifics)

- Go's `net/http` server cannot stream a response while the client streams an
  unbounded request body: the first response flush synchronously drains up to
  256 KiB of the request body (`writeHeader` → `body.Close`). The NPNS shape is
  exactly that bidirectional stream, so the frontline handler **hijacks** the
  connection after authentication and carries the HTTP/1.1 chunked exchange by
  hand. [measured against Go 1.26's server, this repo's runtime]
- With TLS, the server's background read holds the `crypto/tls` mutex while
  waiting; a handler flush behind it blocks until the client's first body byte.
  The console speaks first (Hi/SubscribeTopic on connect), so this resolves
  naturally in production — but any proxy in the deployment path must tolerate
  a request body that stays open while the response streams.
- NX_DEBUG's logging wrapper must forward `http.Flusher` and `http.Hijacker`;
  it did neither before this workstream (the audit's reproduced P0).

## 7. Open questions and the next experiment

Closed by the 2026-09-12 capture, findings folded into the sections above:
server→client framing (§2 — symmetric length prefixes inside a chunked stream,
consumed end to end) and the event carrier (§4d — a record written with
`PutRecord`, not a message; the receive-side-parser hunt it motivated is dead
weight and is gone with it).

| # | Question | Blocking | Next reproducible experiment |
| --- | --- | --- | --- |
| 1 | Ack correlation (what the client's Ack field references) | at-least-once → at-most-once tightening | Capture; alternatively server-side experiment: echo candidate ids and observe Acks |
| 2 | SubscribeTopic payload slots; whether SubscriptionUpdated is the expected confirmation inside 10 s | subscription lifecycle | The console subscribes right after SyncComplete [runtime, §4f]; log the next one's bytes and compare against the dispatch's slot heuristic |
| 3 | REST request shapes (§1 open items) | strict authentication of registration | Capture of one clean bootstrap with the current server |
| 4 | Leaf-level record listing (what a LeafHash drill-down asks for) | a truthful sync answer ("we hold these records") once record acceptance is proven | Implement per-namespace listing over `penne_records.go`, answer one drill-down, and watch what the console asks to put or delete |

Failure posture while the table above has open rows: malformed or unknown
inbound frames are counted and never answered with invented schemas; outbound
record writes are well-formed per §4d. A console that rejects them closes the
connection — observable, recoverable, and exactly what the next capture run
needs to see.

## 4f. The sync answer (settled on hardware, 2026-09-12)

**Answer the opening `RootHash` with an empty entry vector.** That is the whole of it, and it
cost a month.

The console opens with a `RootHash` naming four namespaces and their digests
(`c-appearance`, `c-friends`, `c-settings`, `c-storage`). Six candidate answers were armed
behind `NX_PENNE_SYNC_PROBE` and rotated one per connection; a console judged each in turn over
four cycles:

| Answer | What the console did |
| --- | --- |
| `RootHash` mirror (its own digests back) | nothing; reconnected in about a second |
| `RootHash`, two-slot envelope | replied `LeafHash` — a drill-down — then gave up after ~70 s |
| `RootHash`, count+1 | nothing |
| `LeafHash` mirror | nothing |
| **`RootHash`, no entries** | **`SyncComplete`**, then `SubscribeTopic` and `DAPresence` |
| no reply (control) | nothing |

Reproduced on every cycle. It is also the honest answer: mirroring the console's digests claimed
this server held records under those namespaces, and the console will not proceed on a claim the
server cannot then back with a leaf. An empty vector says "nothing here", which is true.

### What the console does once it is past the sync

Two behaviours nothing had ever seen, both unanswered so far:

- **`SubscribeTopic` on `nx_data_<titleId>`** — three in one session
  (`nx_data_0100000000010000`, `nx_data_01006f8002326000`, `nx_data_0100d4f00dd02000`). That is
  the exact name the `bcat` module formats for BCAT data (`nx_data_%016llx`,
  `firmware-22.5.0-followup-2026-09-12.md` §21b), so **BCAT and News pushes ride Penne topics**.
  Note what was *not* subscribed here: `c-friends.inv.subsTypes`. The friends module makes that
  subscription at its own init, so it belongs to a different phase — worth pinning down before
  assuming a friend event can be written to it on this connection.
- **`DAPresence`** — the console publishing its own presence, carrying the extras document this
  server already serves (`{"self":{},"favoriteFriends":{},"friends":{"appField":"{}",
  "appInfo:appId":"...","appInfo:acdIndex":0,"appInfo:presenceGroupId":"..."},"foaf":{},
  "everyone":{}}`) followed by two 16-hex ids. Presence is bidirectional, and this server has
  only ever written it.
