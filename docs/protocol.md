# Protocol: nx-penne

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
notes: [`docs/`](.).

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
