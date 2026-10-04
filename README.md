# nx-penne

Penne, the Switch's push channel, for OpenPak: split out of [nx-baas](../nx-baas) so a core
release no longer drops every console's persistent connection.

It owns Penne's hostnames and state:

- **god** (`god.hac.lp1.penne.srv.nintendo.net`): registrations (`/v1/penne_ids`), notification
  tokens, NSA links, revocation;
- **val** (`val.hac[.lp1].penne.srv.nintendo.net`): the frontline lookup and login tickets;
- **fro-** (`fro-3.hac.lp1.penne.srv.nintendo.net`): the persistent frontline, one connection
  per console, carrying FlatBuffers frames both ways (hijacked HTTP/1.1, see
  `penne_conn.go`): sync, subscriptions, DAPresence, acks, and the notifications;
- `$NX_DATA/penne.json`: registrations, tickets, subscriptions and the delivery outbox.

The identity core (nx-baas) decides what to tell whom — friend events, presence fan-out,
invitations, news, bans, parental-control pushes — and submits it through the penne API
below; this service persists, delivers, retries and deduplicates it. Protocol and delivery
notes: [`docs/`](docs).

## Who talks to it

The penne API on the internal listener (`X-Internal-Key`, strict), contract in nx-common
`nxapi` and nx-baas `docs/service-split.md`:

| route | caller |
|---|---|
| `GET /internal/penne/registrations/{penne_id}` | nx-shop (pushmo `/p/`) |
| `POST /internal/penne/consoles` | nx-baas (`/1.0.0/login`, NA token refresh) |
| `POST /internal/penne/push-channels` | nx-baas (`/1.0.0/push_channels`) |
| `POST /internal/penne/notifications` | nx-baas (friend events, presence, invitations) |
| `POST /internal/penne/topic-messages` | nx-baas (news push) |
| `POST /internal/penne/token-bindings` | nx-baas (olsc token upload) |
| `POST /internal/penne/users/{id}/close` | nx-baas (a ban) |
| `POST /internal/penne/device-messages` | nx-pctl (setting changed) |

And it asks nx-baas (`ident.go`): an account's lock for the frontline, a viewer's
online-notification preference, and it hands over the presence a console publishes
(DAPresence) and its lease renewals, in order, without making the frontline wait. With the
core away, a frontline still connects (lock unknown) and alerts are allowed.

## Running

| env | default | |
|---|---|---|
| `NX_CORE_URL` | (required) | nx-baas's internal listener, e.g. `http://openpak-nx-baas:20070` |
| `NX_INTERNAL_KEY` | | the shared internal key; the penne API refuses everyone without it |
| `NX_ADDR` | `:21000` | TLS for consoles (Traefik SNI passthrough) |
| `NX_API_ADDR` | `:20070` | plain HTTP: `/internal/penne/*` and the god/val routes nx-baas forwards |
| `NX_DATA` | `/data` | `penne.json` |
| `NX_PENNE_IMPORT` | | first start only: nx-baas's `penne.json` to start from |
| `NX_CA_DIR` | `/data/ca` | `ca.pem`/`ca.key` that sign the listener's certificates |
| `BAAS_SIGNING_KEY` | `/keys/baas_signing_key.pem` | verifies the tokens nx-baas mints |
| `NX_PENNE_RECEIVER`, `NX_PENNE_SYNC_PROBE`, `NX_PENNE_RECONCILE`, `NX_DEBUG` | | as in nx-baas |

A hostname this service does not own is answered 421 and logged. `deploy/` has a sample
quadlet and the Traefik router (the frontline must be routed here; nx-baas cannot forward a
full-duplex stream). Neither is applied anywhere.

## Building

`nx-common` is a sibling module with no remote yet: `go.mod` replaces it with `../nx-common`
and `vendor/` holds the copy the image build uses. After changing nx-common, run
`go mod vendor` here and commit `vendor/`.

    go vet ./... && go test ./...

Releases are tags: `v*.*.*` runs `.github/workflows/release.yml` on the self-hosted podman
runner and publishes `ghcr.io/openpak/nx-penne`.

## Porting a fix from nx-baas

`penne*.go` and `internal/penne/` are nx-baas's at commit `f2cb368`, with the helpers they
call kept under their nx-baas names (`common.go`), so a fix made there applies here as a
patch until nx-baas drops its copy:

    git -C ../nx-baas diff f2cb368 origin/main -- penne.go penne_conn.go penne_deliver.go \
        penne_presence.go penne_records.go penne_store.go internal/penne | git apply -3

The deliberate differences: `penne.go` lost the vermillion gateway (it stays in nx-baas);
the frontline's lock check, the online-notification policy and DAPresence ask the core
(`ident.go`); `SubmitNotification` no longer checks that the recipient is a user (the core
does before it submits); news, parental-control and ban deliveries live in
`internal_api.go`.
