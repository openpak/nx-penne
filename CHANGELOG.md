# Changelog: nx-penne

## 0.2.0 - 2026-11-03

- The Penne state (registrations, tokens, login tickets, subscriptions, push channels, delivery outbox, delivered ids) now lives in Postgres (table `penne_state`, small pool of 2) instead of `$NX_DATA/penne.json`. `NX_PENNE_DATABASE_URL` is required; the service refuses to start without it and there is no memory fallback.
- On the first start against an empty database the old `penne.json` is imported once (counts are logged); the file is left in place.
- Removed the `NX_PENNE_IMPORT` nx-baas file import and its mount.
