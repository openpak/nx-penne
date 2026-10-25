# Switch Push Server

OpenPak's Switch Push Server.

| | |
| --- | --- |
| Network | Switch |
| Role | Penne push channel: registrations, the persistent frontline, and delivery of notifications submitted by the identity core |
| Depends on | [`nx-baas`](https://github.com/openpak/nx-baas) (internal listener, `NX_CORE_URL`), `nx-common` (sibling Go module) |
| Used by | [`nx-baas`](https://github.com/openpak/nx-baas), [`nx-shop`](https://github.com/openpak/nx-shop), [`nx-pctl`](https://github.com/openpak/nx-pctl) |
| Image | `ghcr.io/openpak/nx-penne` |
| Licence | AGPL-3.0-only |

## What it serves

| Endpoint | What |
| --- | --- |
| `fro-3.hac.lp1.penne.srv.nintendo.net` | Persistent frontline: one connection per Switch console, carrying sync, subscriptions, presence, acks and notifications |
| `god.hac.lp1.penne.srv.nintendo.net`, `val.hac[.lp1].penne.srv.nintendo.net` | Registrations, notification tokens, NSA links, frontline lookup and login tickets |
| Penne API on the internal listener (`X-Internal-Key`) | Submissions from nx-baas, nx-shop and nx-pctl |

## Run

```sh
NX_CORE_URL=http://openpak-nx-baas:20070 NX_INTERNAL_KEY=<key> go run .
```

`NX_CORE_URL` is required. The container image is the normal deployment; the full
environment table and the quadlet/Traefik layout are in [deploy.md](docs/deploy.md).

## Docs

- [Protocol](docs/protocol.md)
- [Evidence](docs/evidence.md)
- [Deploy](docs/deploy.md)
- [Notes](docs/notes.md)
- [Penne frontline](docs/penne-frontline.md)
- [Penne message delivery (2026-09-20)](docs/penne-message-delivery-2026-09-20.md)
- [Penne protocol](docs/penne-protocol.md)
- [Penne record shape (2026-09-16)](docs/penne-record-shape-2026-09-16.md)
- [Penne workstream B handoff](docs/penne-workstream-b-handoff.md)

## Licence

AGPL-3.0-only. See [LICENSE](LICENSE).
