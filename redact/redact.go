// Package redact keeps personal data out of logs. A log line never carries an
// account id, pid, NSA id, device id, name, email, token, code or address;
// where two lines have to be matched up it carries a Tag instead.
package redact

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// key is random per process: tags correlate lines within one run and cannot be
// reversed or compared across restarts.
var key = func() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}()

// Bodies is true only when NX_PENNE_TRACE_BODIES=1. Request and response body
// dumps, header values and query strings are logged only then; never set it in
// production.
var Bodies = os.Getenv("NX_PENNE_TRACE_BODIES") == "1"

// Tag returns a short stable per-process tag for v ("~" and six hex digits).
func Tag(v any) string {
	m := hmac.New(sha256.New, key)
	fmt.Fprint(m, v)
	return "~" + hex.EncodeToString(m.Sum(nil)[:3])
}

// Err returns err's text without the addresses and URLs that net and url
// errors spell out ("read tcp 10.0.0.1:443->203.0.113.7:5000: ...").
func Err(err error) string {
	if err == nil {
		return "<nil>"
	}
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return Err(ue.Err)
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Op + ": " + oe.Err.Error()
	}
	return IDs(err.Error())
}

var (
	uuidRe  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	ipv4Re  = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$`)
	tokenRe = regexp.MustCompile(`[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}` +
		`|[^\s/@;,()<>"'=&?~]+@[^\s/;,()<>"'=&?]+` +
		`|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?` +
		`|~?[0-9A-Za-z]+`)
	// A title id is not personal and is what makes a shop or news line useful:
	// an application or its patch (…000, …800) or a system title (010000000000xxxx).
	titleRe = regexp.MustCompile(`^(?:01[0-9a-f]{11}[08]00|010000000000[0-9a-f]{4})$`)
)

// IDs replaces anything in s that looks like an identifier with its Tag: UUIDs,
// emails, IPv4 addresses, long hex runs (user, NSA, device ids), decimal runs of
// five digits or more (pids) and any 24+ character alphanumeric run (tokens).
// Title ids are kept, and so are tags already in s. Use it on text a client
// chose, such as a User-Agent, which carries the console's device id.
func IDs(s string) string {
	return tokenRe.ReplaceAllStringFunc(s, func(m string) string {
		low := strings.ToLower(m)
		switch {
		case strings.HasPrefix(m, "~"):
			if len(m) == 7 && isHex(m[1:]) {
				return m // already a tag
			}
			return "~" + IDs(m[1:])
		case uuidRe.MatchString(low), strings.Contains(m, "@"), ipv4Re.MatchString(m):
			return Tag(low)
		case titleRe.MatchString(low):
			return m
		case len(m) >= 24:
			return Tag(m)
		case len(m) >= 12 && isHex(low) && strings.ContainsAny(low, "0123456789"):
			return Tag(low)
		case len(m) >= 5 && isDigits(m):
			return Tag(m)
		}
		return m
	})
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Path is a request path with every id-shaped segment tagged
// ("/2.0.0/users/~1a2b3c/friends").
func Path(p string) string {
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if strings.Contains(seg, "@") {
			segs[i] = Tag(seg)
			continue
		}
		segs[i] = IDs(seg)
	}
	return strings.Join(segs, "/")
}

// Query keeps only a query string's parameter names ("?filter.x&p"): values are
// codes, tokens and ids. Empty when there is no query.
func Query(raw string) string {
	if raw == "" {
		return ""
	}
	if Bodies {
		return "?" + raw
	}
	var names []string
	for _, kv := range strings.Split(raw, "&") {
		k, _, _ := strings.Cut(kv, "=")
		if k, err := url.QueryUnescape(k); err == nil && k != "" {
			names = append(names, IDs(k))
		}
	}
	return "?" + strings.Join(names, "&")
}

// URL is Path plus Query: safe to log for any request.
func URL(u *url.URL) string {
	if u == nil {
		return ""
	}
	return Path(u.Path) + Query(u.RawQuery)
}

// Addr tags a client address (ip:port).
func Addr(a any) string {
	if a == nil {
		return "-"
	}
	return Tag(fmt.Sprint(a))
}

// Text stands in for free text a person typed (names, nicknames, messages):
// its length and tag.
func Text(s string) string {
	return fmt.Sprintf("%s(%d)", Tag(s), len([]rune(s)))
}

// Link is a URL string (a redirect target, say) reduced to its scheme, host,
// tagged path and the names of its query and fragment parameters: a fragment
// can carry an id_token.
func Link(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return Tag(raw)
	}
	out := Path(u.Path) + Query(u.RawQuery)
	if u.Host != "" {
		out = u.Scheme + "://" + u.Host + out
	} else if u.Scheme != "" {
		out = u.Scheme + ":" + out
	}
	if u.Fragment != "" {
		out += "#" + strings.TrimPrefix(Query(u.EscapedFragment()), "?")
	}
	return out
}

var addrRe = regexp.MustCompile(`\[[0-9a-fA-F:.%a-z]+\](:\d+)?|\b\d{1,3}(\.\d{1,3}){3}(:\d+)?`)

// Scrub replaces every IP address (with its port) in s with "~addr".
func Scrub(s string) string { return addrRe.ReplaceAllString(s, "~addr") }

type scrubWriter struct{}

func (scrubWriter) Write(p []byte) (int, error) {
	log.Print(Scrub(strings.TrimRight(string(p), "\n")))
	return len(p), nil
}

// ErrorLog is for http.Server.ErrorLog, whose own messages ("http: TLS handshake
// error from 203.0.113.7:5000") name the client. It writes to the standard logger
// with addresses scrubbed.
func ErrorLog() *log.Logger { return log.New(scrubWriter{}, "", 0) }
