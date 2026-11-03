// nx-penne: Penne, the Switch's push channel, split out of nx-baas so a core release no
// longer drops every console's persistent connection (nx-baas docs/service-split.md).
//
// It owns Penne's hostnames -- god (registrations, notification tokens, NSA links), val
// (frontline lookup, login tickets) and the fro- frontlines, where each console holds one
// connection open -- and the push state in $NX_DATA/penne.json: registrations, tickets,
// subscriptions and the delivery outbox. The core (nx-baas) decides what to tell whom and
// submits it through the penne API; this process persists, delivers and retries it.
//
// Two listeners:
//
//	NX_ADDR      TLS for consoles (Traefik passes the SNIs through), certificates from the
//	             OpenPak CA in NX_CA_DIR, exactly as nx-baas terminates them (nx-common/nxtls)
//	NX_API_ADDR  plain HTTP on the openpak network: the penne API (/internal/penne), and the
//	             god/val routes again for what nx-baas forwards here
package main

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/openpak/nx-common/httplog"
	"github.com/openpak/nx-common/nxapi"
	"github.com/openpak/nx-common/nxjwt"
	"github.com/openpak/nx-common/nxtls"

	"nx-penne/redact"
)

type server struct {
	// key is the BAAS signing key: it verifies the tokens nx-baas mints, which consoles
	// present on god and val.
	key *rsa.PrivateKey
	// core is the identity core (nx-baas): locks, preferences, and where presence goes.
	core identity
	// presence carries DAPresence reports and renewals to the core, in order (ident.go).
	presence chan presenceJob
	// Penne notification channel: durable push-channel state (registrations, tokens,
	// tickets, subscriptions, delivery outbox) and the live frontline session registry.
	// notifStore() lazily creates in-memory versions when unset, so direct handler tests
	// keep working.
	penneState *penneStore
	penneHub   *penneHub
	// Penne record store: what this server has written to each account's records, and its
	// digests (penne_records.go).
	recordStore *penneRecordStore
	recordsOnce sync.Once
}

// fixedNames were on nx-baas's fixed certificate and stay fixed here: the console
// authenticates some names strictly and refused an on-demand certificate on those.
var fixedNames = []string{
	"god.hac.lp1.penne.srv.nintendo.net", "val.hac.penne.srv.nintendo.net", "val.hac.lp1.penne.srv.nintendo.net",
	"fro-3.hac.lp1.penne.srv.nintendo.net",
}

var debug = os.Getenv("NX_DEBUG") != ""

// ServeHTTP answers Penne's hosts; any other host is misrouted and says so with a 421.
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	httplog.Wrap(logPrefix, httplog.Options{Path: redact.Path, UserAgent: redact.IDs}, http.HandlerFunc(s.serve)).ServeHTTP(w, r)
}

// serve is ServeHTTP's body; ServeHTTP adds the access line (status, duration, never the query).
func (s *server) serve(w http.ResponseWriter, r *http.Request) {
	host := hostOf(r)
	if r.URL.Path == "/healthz" {
		writeJSON(w, 200, map[string]any{"status": "ok", "service": "nx-penne"})
		return
	}
	if !strings.Contains(host, "penne.") {
		misrouted(w, r)
		return
	}
	// The frontline POST is bidirectional -- the request body carries the client's frames,
	// so it must reach the handler unread. Everything else is read and buffered.
	var body []byte
	if !isPenneFrontline(host) {
		body, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
	}
	if debug {
		dump(r, body, "DBG >>>")
		rec := &recorder{ResponseWriter: w, status: 200}
		w = rec
		defer func() {
			if !redact.Bodies {
				log.Printf("%s DBG <<< %d %s %s%s body(%d)", logPrefix, rec.status, r.Method, host, redact.Path(r.URL.Path), rec.buf.Len())
				return
			}
			log.Printf("%s DBG <<< %d %s %s%s body(%d)=%s", logPrefix, rec.status, r.Method, host, r.URL.Path, rec.buf.Len(), rec.buf.Bytes())
		}()
	}
	s.penne(w, r, body)
}

func main() {
	key, err := nxjwt.LoadRSAKey(getenv("BAAS_SIGNING_KEY", "/keys/baas_signing_key.pem"))
	if err != nil {
		log.Fatalf("%s signing key: %v", logPrefix, redact.Err(err))
	}
	coreURL := os.Getenv("NX_CORE_URL")
	if coreURL == "" {
		log.Fatalf("%s NX_CORE_URL is required (nx-baas's internal listener, e.g. http://openpak-nx-baas:20070)", logPrefix)
	}
	data := getenv("NX_DATA", "/data")
	s := &server{key: key, core: nxapi.New(coreURL), presence: make(chan presenceJob, 4096)}
	s.penneState = openPenneStore(os.Getenv("NX_PENNE_DATABASE_URL"), data+"/penne.json")
	s.penneHub = newPenneHub()
	s.registerDefaultPennePolicies()
	go s.presenceWorker()
	// The sweeper drives delivery retries, expiry and retention (NTF-05).
	go s.penneSweep()
	go func() {
		addr := getenv("NX_API_ADDR", ":20070")
		log.Printf("%s internal API listening %s (penne API, forwarded god/val)", logPrefix, addr)
		log.Fatal((&http.Server{Addr: addr, Handler: s.internalAPI(), ErrorLog: redact.ErrorLog()}).ListenAndServe())
	}()
	srv := &http.Server{
		Addr: getenv("NX_ADDR", ":21000"), Handler: s,
		TLSConfig: tlsConfig(), ErrorLog: redact.ErrorLog(),
	}
	log.Printf("%s listening %s; state in Postgres; core %s", logPrefix, srv.Addr, coreURL)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// tlsConfig is the listener's TLS config. The ClientHello trace nxtls offers under debug
// names the client's address, so it is done here with the address tagged.
func tlsConfig() *tls.Config {
	conf := nxtls.ServerConfig(logPrefix, fixedNames, getenv("NX_CA_DIR", "/data/ca"), false)
	if debug {
		conf.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			log.Printf("%s TLS hello sni=%s from=%s alpn=%v", logPrefix, h.ServerName, redact.Addr(h.Conn.RemoteAddr()), h.SupportedProtos)
			return nil, nil
		}
	}
	return conf
}

// ---------- debug recorder (nx-baas main.go) ----------

type recorder struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (rec *recorder) WriteHeader(c int) { rec.status = c; rec.ResponseWriter.WriteHeader(c) }
func (rec *recorder) Write(b []byte) (int, error) {
	if rec.buf.Len() < 8192 {
		rec.buf.Write(b)
	}
	return rec.ResponseWriter.Write(b)
}

// Flush forwards to the wrapped writer when it can stream: the frontline's held-open
// response needs http.Flusher.
func (rec *recorder) Flush() {
	if f, ok := rec.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards likewise: the frontline takes the raw connection for its bidirectional
// frame stream.
func (rec *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rec.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("recorder: wrapped writer is not a Hijacker")
}
