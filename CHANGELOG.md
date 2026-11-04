# Changelog: nx-penne

## 0.3.0 - 2026-11-04

- Account erasure (card #120): `DELETE /internal/accounts/{account_id}/data` with `Authorization: Bearer $ACCOUNT_ERASE_KEY` on the internal listener (`NX_API_ADDR`, default `:20070`, container network; console hosts never reach it). Unset key = 503, bad key = 401, non-UUID = 400. Reply `{"service":"nx-penne","rows":N}`, one `account erased` log line.
- The OpenPak account is mapped to its BAAS user id through nx-baas's identity API (read-only, `NX_CORE_URL`). Erased from `penne_state`: push registrations (and their device/user/console/profile mappings), notification tokens, frontline tickets, topic subscriptions, push channels, the delivery outbox, the delivered-event window and the in-memory record store. The document is written on a copy and swapped in only after the write succeeded; a failed write deletes nothing.
- Kept: nothing of that account. Console device ids are not account data and only lose their pointer to the erased registration.

## 0.2.1 - 2026-11-03

- Every HTTP request now writes one access line to stderr: `http <method> <host> <path> -> <status> <ms>ms ua=...` (shared `nx-common/httplog`, vendored; ids in the path are tagged). The query string, headers and bodies are never logged. `/healthz` is skipped. The vendored copy now matches `vendor/modules.txt`.

## 0.2.0 - 2026-11-03

- The Penne state (registrations, tokens, login tickets, subscriptions, push channels, delivery outbox, delivered ids) now lives in Postgres (table `penne_state`, small pool of 2) instead of `$NX_DATA/penne.json`. `NX_PENNE_DATABASE_URL` is required; the service refuses to start without it and there is no memory fallback.
- On the first start against an empty database the old `penne.json` is imported once (counts are logged); the file is left in place.
- Removed the `NX_PENNE_IMPORT` nx-baas file import and its mount.
