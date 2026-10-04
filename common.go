package main

// The helpers the Penne files were written against in nx-baas, under the same names, so a
// fix made to one of those files there applies here as a patch (README.md). The bodies live
// in nx-common.

import (
	"net/http"
	"strings"

	"github.com/openpak/nx-common/nxhttp"
	"github.com/openpak/nx-common/nxjwt"
)

const logPrefix = "[nx-penne]"

func getenv(k, d string) string                          { return nxhttp.Getenv(k, d) }
func writeJSON(w http.ResponseWriter, status int, v any) { nxhttp.WriteJSON(w, status, v) }
func hostOf(r *http.Request) string                      { return nxhttp.HostOf(r) }
func dump(r *http.Request, body []byte, tag string)      { nxhttp.Dump(logPrefix, r, body, tag) }
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
