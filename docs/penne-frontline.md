# The Penne frontline connection is held open

A `POST` to `fro-N.hac.lp1.penne.srv.nintendo.net` fell through to the penne default and answered
`404`. The client holds this "frontline" connection open for room-code registration and push, and
closing it immediately is an error to the client. This is the last of the four pre-gRPC bootstrap
defects (after device id, `vphyms`, and `config`).

We already hand the client this host: `val. /v1/frontlines` and `/v1/login_tickets` both return
`frontline_fqdn: fro-3.hac.lp1.penne.srv.nintendo.net` with the persistent-connection params. The
console then dials it — and until now got a 404.

## The fact

The connection must be **held open as a chunked stream with a heartbeat**, not answered and closed.
Closing it immediately errors the client; the Splatoon 2 form of that failure is `2307-2103`.

Source: `servers/splatoon-3/docs/provenance.md`, "The pre-gRPC REST chain":
`POST` to `fro-N...` — "the connection must be **held open** as a bidirectional stream (chunked,
heartbeat) for room-code registration. Closing it immediately errors the client." Recorded as observed behaviour under `docs/clean-room-policy.md`; no code,
structure or wording carried across.

## What is and is not known

The **shape** is the recorded fact: 200, chunked, held open, with a periodic heartbeat, closing
only when the console disconnects. That is what `frontline` (in `penne.go`) now does — one goroutine
per console, a keepalive chunk every `frontlineHeartbeat`, and a return on `r.Context().Done()`.

The **content** of the heartbeat and of any pushed frame is *not* captured. A benign newline stands
in as the keepalive, and nothing is pushed yet — no room codes are delivered over it. Swapping in a
real frame is a one-line change to the write payload once a capture exists; the connection lifecycle
does not change. This is marked with a `ponytail:` note in the code, and it is the specific thing a
hardware run should measure.

One assumption worth stating: `nx-baas`'s `ServeHTTP` reads the request body up front
(`io.ReadAll` of a 1 MB `LimitReader`) before dispatch, so this handler assumes the client sends a
finite request body and then reads the long-lived response. If the frontline instead streams an
unbounded request body, that up-front read would block and this needs revisiting — a hardware run
would show it as the connection never being accepted.

## Effect on the console link

New behaviour on a host the link never reaches for gameplay. The link uses `god.`/`val.`/`beach.`
and the account/dauth surface; `fro-` is the NPLN title frontline and no linking capture touches it.
The change is additive — a `fro-` prefix case ahead of the penne default — so every other penne,
gw. and beach. request answers exactly as before. Lowest risk of the three console-facing responses
this round, but still console-facing: confirm the link on hardware first.
