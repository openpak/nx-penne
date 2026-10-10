package main

// The helpers the Penne files were written against in nx-baas, under the same names, so a
// fix made to one of those files there applies here as a patch (README.md). The bodies live
// in nx-common.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/openpak/nx-common/nxhttp"
	"github.com/openpak/nx-common/nxjwt"

	"nx-penne/redact"
)

const logPrefix = "[nx-penne]"

func getenv(k, d string) string                          { return nxhttp.Getenv(k, d) }
func writeJSON(w http.ResponseWriter, status int, v any) { nxhttp.WriteJSON(w, status, v) }
func hostOf(r *http.Request) string                      { return nxhttp.HostOf(r) }
func str(m map[string]any, k string) string              { return nxjwt.Str(m, k) }
func randHex(n int) string                               { return nxjwt.RandHex(n) }
func randB64(n int) string                               { return nxjwt.RandB64(n) }
func uuid4() string                                      { return nxjwt.UUID4() }

var (
	parseJWT = nxjwt.Parse
	signJWT  = nxjwt.Sign
)

func apiErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

// bearer returns the claims of a token nx-baas signed on the request, or nil.
func (s *server) bearer(r *http.Request) map[string]any {
	a := r.Header.Get("Authorization")
	if !strings.HasPrefix(a, "Bearer ") {
		return nil
	}
	c, err := parseJWT(strings.TrimPrefix(a, "Bearer "), &s.key.PublicKey)
	if err != nil {
		return nil
	}
	return c
}

// deviceIDFromUA pulls the console's own device id out of the SDK's User-Agent,
// which is where the SDK puts it: "NintendoSDK Firmware/<ver> (platform:NX; did:<hex>; eid:lp1)".
func deviceIDFromUA(ua string) string {
	i := strings.Index(ua, "did:")
	if i < 0 {
		return ""
	}
	rest := ua[i+len("did:"):]
	if j := strings.IndexAny(rest, "; )"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// dump logs a request the server does not (fully) understand. By default it names the
// route, the header names and the body's size: header values, query values and bodies carry
// tokens, ids and names. NX_PENNE_TRACE_BODIES=1 (never in production) adds the full headers
// and body.
func dump(r *http.Request, body []byte, tag string) {
	if !redact.Bodies {
		names := make([]string, 0, len(r.Header))
		for k := range r.Header {
			names = append(names, k)
		}
		sort.Strings(names)
		log.Printf("%s %s %s %s%s hdr{%s} body(%d) ct=%q", logPrefix, tag, r.Method, hostOf(r), redact.URL(r.URL),
			strings.Join(names, ","), len(body), r.Header.Get("Content-Type"))
		return
	}
	var hdr strings.Builder
	for k, v := range r.Header {
		if k == "Authorization" && len(v) > 0 && len(v[0]) > 40 {
			fmt.Fprintf(&hdr, " %s: %s...;", k, v[0][:40])
			continue
		}
		fmt.Fprintf(&hdr, " %s: %s;", k, strings.Join(v, ","))
	}
	log.Printf("%s %s %s %s%s?%s hdr{%s} body(%d)=%q", logPrefix, tag, r.Method, hostOf(r), r.URL.Path, r.URL.RawQuery, hdr.String(), len(body), body)
	if len(body) > 0 && !json.Valid(body) && !strings.Contains(r.Header.Get("Content-Type"), "form") {
		log.Printf("%s %s body hex: %s", logPrefix, tag, hex.EncodeToString(body))
	}
}

// misrouted answers a request for a hostname this service does not own with a 421, logged.
func misrouted(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s !! MISROUTED %s %s%s: this service does not own that hostname", logPrefix, r.Method, hostOf(r), redact.Path(r.URL.Path))
	writeJSON(w, http.StatusMisdirectedRequest, map[string]any{"status": 421, "title": "misdirected request"})
}
