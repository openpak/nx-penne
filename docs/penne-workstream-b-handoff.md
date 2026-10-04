# Workstream B review handoff: Penne transport and native notifications

Status: code complete on branch `penne-notifications`, base `a-friends-presence`
(07ba967). Date: 2026-09-11. Implements `../prds/native-switch-penne-notifications-prd.md`
(NTF-01..06, notification/recovery portions of J1/J4/J5) against the shared
parent PRD and the coordination plan.

Branch/commits:
- `e9b5152` Penne transport and native notifications (NTF-01..06)
- `4820c65` Rebase onto A's milestone: default presence-alert policy

## Requirement ledger

| Req | Deliverable | Code | Tests | Status |
| --- | --- | --- | --- | --- |
| NTF-01 durable setup | `penne_store.go` (registrations, tokens, tickets, links, push channels — all persisted in `$NX_DATA/penne.json`), REST wiring in `penne.go`, push-channel persistence patch in `main.go`; a supplied id authorizes nothing without its password; revocation kills tokens/tickets; device-scoped revocation on DELETE | `penne_store.go`, `penne.go`, `main.go` (4 narrow patches, labeled) | `TestRegistrationPersistsAcrossRestart`, `TestSuppliedIDAuthorizesNothing`, `TestTicketExpiryRevocationAndWrongDevice`, `TestFrontlineDeniesBadTickets`, `TestPushChannelsAndLinksPersist`, `TestTicketDenialRecordsSurviveSweep` | implemented; request-shape capture pending (provisional fallbacks documented in the spec §1) |
| NTF-02 protocol gate | `docs/penne-protocol.md` v1 with provenance labels; `internal/penne` package: framing codec, FlatBuffers-compatible decoder/builder, the recovered 38-slot union table, envelope codec | `internal/penne/protocol.go`, `docs/penne-protocol.md` | `internal/penne/protocol_test.go` (hand-assembled fixture, byte-corruption fuzz, frame abuse) | spec written; server→client framing + event carrier remain labeled open questions (§7) with a concrete next experiment |
| NTF-03 streaming integrity | recorder forwards `Flusher` **and** `Hijacker`; frontline pre-read exemption in the router; full `ServeHTTP` streaming tests with debug on/off; hijacked bidirectional stream (the net/http drain constraint is documented and engineered around); malformed/oversized frames close without panic; cancellation cleanup | `main.go` (2 patches), `penne_conn.go` | `TestFrontlineStreamsThroughServeHTTPDebugOnAndOff`, `TestFrontlineClosesOnMalformedFrame`, `TestFrameTooLargeIsRejectedWithoutAllocating`, `TestMalformedBuffersDecodeWithoutPanic` | implemented on this deployment's Go 1.26 server; live TLS/proxy path pending hardware |
| NTF-04 event delivery | five firmware kinds (`presence_updated`, `friend_invitation_received`, `friend_request_received`, `friend_request_authorized`, `friend_deleted`); semantic submission API `SubmitNotification`; conversion to wire frames; dispatch-time recipient/policy revalidation; timestamp bumping alone is not delivery | `penne_deliver.go` | `TestAllFiveEventKindsRideThePipeline`, `TestSubmitNotificationValidatesKindAndRecipient`, `TestEventJSONCarriesTypeIDDedup`, `TestOnlineNotificationPreferenceGatesOnlyPresence` | pipeline implemented; the wire envelope is the spec's marked hypothesis — native acceptance pending capture |
| NTF-05 recovery | durable outbox: submit persists before returning (atomic per write), event-id dedup with 24 h delivered-retention, presence coalescing per friend (latest wins), bounded queues (128/user) with a defined overflow policy, retry with 5 s doubling backoff capped at 5 min, expiry drops, reconnect reconciliation before new work, `Ack`/`ResendRequest` best-effort settling | `penne_store.go`, `penne_conn.go` | `TestSubmitIsIdempotentByEventID`, `TestPresenceUpdatesCoalescePerFriend`, `TestQueueOverflowPolicy`, `TestRetryBackoffAndExpiry`, `TestDeliveredRetentionDeduplicatesReplays`, `TestSweepExpiresAndPrunes`, `TestFrontlineReconnectReplaysPendingOnce` | implemented (at-least-once + recipient dedup; protocol ack schema still open) |
| NTF-06 alert behavior | per-friend `isOnlineNotification` gates presence alerts at dispatch only (A's SOC-02 preference; social events ride regardless); policy hook interface for A/C quiet/privacy checks; every event's toast/badge/inbox outcome **not verifiable without hardware** | `penne_deliver.go` (`RegisterPolicy`, default policy) | `TestOnlineNotificationPreferenceGatesOnlyPresence`, `TestPolicyHoldsDeliveryAtDispatch` | implemented (policy layer); toast/badge/state matrix **pending hardware** |

Journey portions: J1 (acceptance notifies via `friend_request_authorized`),
J4 (invitations via `friend_invitation_received`), J5 (J5 is this workstream's
recovery story — reconnect convergence, no duplicate alerts). The REST state
sides belong to A/C; the notification side is here and testable in isolation.

## Integration patches for A (in `main.go`, all labeled "B workstream")

1. `recorder.Flush` / `recorder.Hijack` — the debug wrapper hid `http.Flusher`
   (the audit's reproduced P0) and would have hidden `http.Hijacker`.
2. Router body pre-read skipped for `fro-` hosts only — the frontline POST is
   bidirectional; everything else keeps the buffered path.
3. Push-channel echo now persists through `RecordPushChannel` (NTF-01).
4. `server` struct: `penneState`/`penneHub` fields; `main()` initializes the
   store file + sweeper + default policies.

No edits to A's event poller (`openpak_events.go`), authentication, or the
presence reconciler. No second core poller.

## Contract published (coordination plan, "Semantic notification submission")

`SubmitNotification(PenneDelivery) PenneSubmission` in `penne_deliver.go`:
stable event/dedup identity (caller-supplied or minted, returned in the
outcome), recipient (BAAS user, optional device), firmware kind (five,
validated), payload map, expiry (default 10 min). Outcomes:
`persisted | duplicate | rejected_queue_full | rejected_unknown_recipient |
rejected_expired`. Accepted ⇒ durable before return; callers never retry an
accepted submission. A/C register policy checks by name via
`penneHub.RegisterPolicy`; a policy "hold" retains (not drops) until expiry.
Delivery is at-least-once; recipients dedup by event id.

## Development-only tooling

`POST /internal/notifications/test` (game API, internal-key guarded, labeled
DEVELOPMENT ONLY) injects a synthetic event through the real pipeline. It
permits development, not end-to-end completion.

## Verification performed

- `go vet ./...` — clean.
- `go test -race ./...` — clean (85 tests in the package; includes A's suite,
  which passes on this branch after rebase).
- Protocol fixtures are independently hand-assembled (not builder output);
  decoder survives every single-byte corruption of the fixture plus truncations.

## Pending / hardware gates (explicitly not closed)

- NTF-06 alert matrix: toast/badge/inbox/state per event type on two consoles,
  quiet settings, sleep — requires hardware.
- Server→client framing and event-carrier confirmation (spec §7): requires one
  live capture; the next experiment is written there, including the Ghidra xref
  that could settle it statically.
- Deployment TLS/proxy path (Traefik buffering/timeouts) with a real console.
- Latency/convergence targets (p95 ≤ 5 s delivery, ≤ 30 s reconnect
  convergence): measurable only with real events on hardware; the pipeline
  timestamps exist to measure them (sweep logs `oldest_event_age_s`).

## Deployment / rollback

Deploy: this branch builds the same single binary; the new state file
`$NX_DATA/penne.json` is created on first run; no schema changes elsewhere; no
console-facing behavior changes except the frontline improvements (denials are
new but only reachable with an invalid/absent ticket, which previously got a
connection that did nothing). Rollback: redeploy the previous image and delete
`$NX_DATA/penne.json` (it is additive state; nothing else reads it). The game
API route is internal and key-guarded; remove the two labeled lines to drop it.

## Reproduction commands

```
cd nx-baas-penne
go vet ./...
go test -race ./...            # full suite incl. A's, on this branch
go test -race -run TestFrontline -v .          # transport lifecycle
go test -race ./internal/penne/ -v             # wire protocol fixtures
# pipeline demo without a console:
NX_INTERNAL_KEY=dev go run . & # then, with a user in baas.json:
curl -s -XPOST localhost:20070/internal/notifications/test \
  -H 'X-Internal-Key: dev' -d '{"user_id":"<baas id>","kind":"friend_request_received","payload":{"friendId":"0123456789abcdef"}}'
```

## Known blockers

- The dispatch-side delivery of real social/invitation events still needs A's
  poller → `SubmitNotification` wiring (one call site per event in A's
  `followCoreEvents`) and C's invitation trigger; the contract is published and
  tested, the wiring is intentionally not mine to land (no second poller).
- Hardware slot for the capture + two-console matrix (owner's authorization
  flow, per the coordination plan's test-slot record).
