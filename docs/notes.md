# Notes: nx-penne

Penne, the Switch's push channel, for OpenPak: split out of [nx-baas](../../nx-baas) so a core
release no longer drops every console's persistent connection.

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
