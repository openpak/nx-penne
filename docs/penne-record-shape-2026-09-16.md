# Penne record delivery: what the console actually accepts (2026-09-16)

Static pass over the 22.5.0 `npns` and `friends` modules plus one runtime
capture (the console's own `PutRecord` at 08:34 UTC today). Addresses are
Ghidra (+0x100000). Nothing below is hardware-confirmed as *delivery*; the
shapes are.

## 1. `c-friends.inv.subsTypes` is written BY the console, not read by it

`FUN_001eaa30("c-friends.inv.subsTypes", "friend", 6)` in friends is a proxy
call on `npns:s` vtable slot 49. The server handler (`FUN_0019da00` →
`FUN_001a3b80` → `FUN_001d0740` → `FUN_001d03f0`) writes the pair into the
console's local record store and marks it for upload. That is the record the
console synced up to us at 08:34 (`c-storage.summary` is the same path).
Writing to that name from the server is a no-op for the friends module.
Open question N2 is answered: **no**.

## 2. `PutRecord` framing, from the console's parser (`FUN_001dfbb0`) and its own frame

```
Envelope   {0: u8 type=4, 1: →PutRecord, 2: string "NX", 3: u64 issued, 4: u64 expires}
PutRecord  {0: [Entry] (exactly one element), 1: u8 = 1}
Entry      {0: u8 kind, 1: →Record}          kind 2 = stored record, kind 1 = message
Record(2)  {0: string name (<32), 1: →Meta, 2: u8 = 1, 3: [ubyte] value}
Message(1) {0: string name (≤47), 1: u16 type, 2: →Meta, 4: string body (≤4095), 5: u64 deliverAt}
Meta(1)    {1: string receivers, 2: string accountId, 4: string (≤39)}
```

- Envelope slot 2 is a **string "NX"**, not a count; our `BuildRootHash`/
  `BuildPutRecord` write a u32 there. The console tolerated it on RootHash
  (empty vector) but a verifier-checked PutRecord is not the same bet.
- Our `BuildPutRecord` puts `{name, value}` directly in envelope slot 1. The
  parser reads slot 0 of that table as a vector length and aborts
  (`FUN_001062a0`) when it is not 1. Production log: every record we wrote
  was followed within a second by a fresh frontline connection.
- Kind 2 stores the value and announces the name (`FUN_001dc430` →
  `FUN_001d0840`). Kind 1 is a **message**: `FUN_001dc510` parses it with
  `FUN_001d69f0`, queues it by `deliverAt` (absent ⇒ now), and hands it to the
  IPC layer (`FUN_001a7a40`) as the 0x10a0-byte struct the friends module
  reads: uid at +0x30/+0x38, body length at +6, body at +0xa0. A notification
  is therefore a **kind-1 message**, not a record.
- `Meta.f2` is the 128-bit account id as **32 hex chars** (optional `0x`),
  parsed by `FUN_001e9000`; an empty string leaves the uid zero and the friends
  handlers drop the event. It is the same id the console puts in
  `/v1/accounts/<32hex>/notification_tokens`, which we record (`NoteAccount`).
- `Meta.f1` is a **comma-separated receiver list**: each token is a hex u64
  (`0x…`, 16 digits, `FUN_001af4f0`) or a name (letters/digits/`-`, ≤31,
  `FUN_001af690`). It must be non-empty. A token `penne` makes npns treat the
  body as its own control message (`onset`, `presence:*`); anything else is
  routed to IPC clients whose listen keys match (`FUN_001a09a0`), else to the
  wildcard listeners, else to an undelivered queue.
- The body is JSON; the friends dispatcher parses it into a 1 KiB scratch
  buffer, so keep events under 1 KiB.
- `DeleteRecord` payload is `{0: [string name]}` (`FUN_001e01f0`).

## 3. ANSWERED (2026-09-16, later): the receiver token is `0x010000000000000e`

The earlier pass here concluded the friends module "never calls any Listen
command" and left `Meta.f1` a guess. That was wrong, and wrong for a specific
reason worth recording: friends reaches npns through **two** proxy getters
(`FUN_001eae60`, which requires the newer interface, and `FUN_001eae30`, which
takes any), and only the first was enumerated. The Listen call is on the second.

Friends' init does this, at `0x17bd38` — fourteen bytes after the
`c-friends.inv.subsTypes` record write that anchored the whole earlier reading:

```c
void FUN_001a0d20(void) {            // friends init
  ...
  local_4 = FUN_001eab80(0x10000000000000e);   // npns proxy vtable +0x28, slot 5
  if (local_4 == 0) {
    FUN_00129700(&DAT_0047b110, ...);          // and only then:
    FUN_00129770(&DAT_0047b110, "nn.friends.EventWatcher");
    FUN_00129750(&DAT_0047b110);               // start the event-watcher thread
  }
}
```

It registers its own program id as a listen key and **gates the event-watcher
thread on the registration succeeding**. That thread is what dispatches the five
event kinds. So `Meta.f1` = `0x010000000000000e`, hex u64 form, parsed by
`FUN_001af4f0` into the same `{tag 0, u64}` token the router matches.

### How routing actually works, end to end

- **Registration.** `Listen(u64)` → `FUN_0019b3f0`/`FUN_0019f060`, `Listen(name)`
  → `FUN_0019b410`/`FUN_0019f170` (name truncated to 31 chars), both into
  `FUN_001a03b0` → `FUN_001a03e0`: append a 40-byte `{tag, value|name}` token to
  the session's key set. **Maximum eight keys per session**; a ninth fails with
  `0xa9a`.
- **Matching.** `FUN_001a09a0(hub, token, msg)` walks the circular list of
  sessions and stops at the first whose key set contains the token. The string
  the function builds along the way (`"0x%016llx"` for a u64) is for the log
  line only — matching is on the token struct.
- **Fallback.** `FUN_001a0560` tries the message's own token, then retries with
  a fixed `{tag 0, value 0}` token (`PTR_DAT_0026afe8`). A session that
  registered `0` is a wildcard listener and gets everything unclaimed.
- **Nothing matched is not lost.** The message is parked on the hub's
  undelivered queue, and a *later* `Listen` drains it: `FUN_0019fd40` moves the
  parked messages whose token equals the newly registered one, `FUN_0019fc60`
  (the `{0,0}` case) moves all of them. So a wrong token would have been
  delivered late rather than dropped — which is worth knowing before reading any
  hardware run that shows a delayed refresh.
- **Queue depth is seven.** `FUN_0019f4c0` allocates a `0x10b0` node, copies
  `0x10a0` bytes of the message into it (the struct the friends module reads),
  appends, and **evicts the oldest once the list passes seven**, flagging the
  overflow. Eight probe messages in a row would silently lose the first.

### The working precedent

`bcat` does the same thing by name: `FUN_0019f390` formats `nx_data_%016llx`
into a 32-byte buffer and passes it to slot 26, the name-Listen. That is the
same string the console announces as a wire topic, and BCAT/News demonstrably
work — so receiver tokens and wire topics are spelled alike, and the friends
case is the u64 variant of the identical mechanism.

Static only; no console has seen a kind-1 message from this server yet.

## 4. What to change (in order)

1. `internal/penne`: envelope slot 2 → string "NX"; add `BuildMessage(name,
   receivers, accountID, body)` producing the nesting above; keep
   `BuildPutRecord` only for the kind-2 shape (unused by delivery).
2. `penne_deliver.go`: drop the six-way `NX_PENNE_RECORD_PROBE` rotation; one
   shape. Address with `AccountsFor(userID)` (per-account map), not
   `AssocByID(...).AccountIDs[0]` (first account on the console).
3. Keep `presence_updated`/invitation bodies as recovered in the followup doc
   §15; they ride unchanged inside the message body.
4. Then the two-console run: friend request, accept, remove, presence.
