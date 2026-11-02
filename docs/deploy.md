# Deploy: nx-penne

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

`penne*.go` and `internal/penne/` are nx-baas's at commit `f2cb368`, with the helpers they call kept under their nx-baas
names (`common.go`), so a fix made there applies here as a patch until nx-baas drops its copy:

    git -C ../nx-baas diff f2cb368 origin/main -- penne.go penne_conn.go penne_deliver.go \
        penne_presence.go penne_records.go penne_store.go internal/penne | git apply -3

The deliberate differences: `penne.go` lost the vermillion gateway (it stays in nx-baas);
the frontline's lock check, the online-notification policy and DAPresence ask the core
(`ident.go`); `SubmitNotification` no longer checks that the recipient is a user (the core
does before it submits); news, parental-control and ban deliveries live in
`internal_api.go`.

The split itself (internal API, cut-over and rollback runbook) is in nx-baas `docs/service-split.md`.
