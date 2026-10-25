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
