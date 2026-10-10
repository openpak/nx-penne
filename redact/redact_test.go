package redact

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
)

func TestTagHidesTheValue(t *testing.T) {
	for _, v := range []any{uint64(1234567890), "Some Nickname", "tok-abc123secret"} {
		line := fmt.Sprintf("session %s", Tag(v))
		if strings.Contains(line, fmt.Sprint(v)) {
			t.Fatalf("%v leaked into %q", v, line)
		}
		if Tag(v) != Tag(v) {
			t.Fatalf("tag for %v is not stable", v)
		}
	}
	if Tag(1) == Tag(2) {
		t.Fatal("two values share a tag")
	}
	if Tag(uint64(1234567890)) != Tag("1234567890") {
		t.Fatal("a pid and its decimal spelling should share a tag")
	}
}

func TestErrDropsAddressesAndURLs(t *testing.T) {
	op := &net.OpError{Op: "read", Net: "tcp", Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 5000}, Err: errors.New("i/o timeout")}
	ue := &url.Error{Op: "Get", URL: "https://example.test/?token=secret-token", Err: op}
	for _, err := range []error{op, ue} {
		got := Err(err)
		if strings.Contains(got, "203.0.113.7") || strings.Contains(got, "secret-token") || !strings.Contains(got, "i/o timeout") {
			t.Fatalf("Err = %q", got)
		}
	}
}

func TestPathTagsIdsAndKeepsTitles(t *testing.T) {
	const user, pid, title = "8a2b3c4d5e6f7081", "73400125", "0100abcdef123000"
	got := Path("/2.0.0/users/" + user + "/friends/" + pid + "/apps/" + title + "/x@example.com")
	for _, secret := range []string{user, pid, "x@example.com"} {
		if strings.Contains(got, secret) {
			t.Fatalf("%q leaked into %q", secret, got)
		}
	}
	if !strings.Contains(got, title) || !strings.Contains(got, "/2.0.0/users/~") || !strings.Contains(got, "/friends/~") {
		t.Fatalf("Path = %q", got)
	}
	if strings.Contains(Path(got), user) || Path(got) != got {
		t.Fatalf("Path is not idempotent: %q -> %q", got, Path(got))
	}
}

func TestQueryKeepsNamesOnly(t *testing.T) {
	if Bodies {
		t.Skip("NX_PENNE_TRACE_BODIES=1")
	}
	got := Query("filter.links.pairingCode.code.$eq=123456&account_id=8a2b3c4d5e6f7081")
	if got != "?filter.links.pairingCode.code.$eq&account_id" {
		t.Fatalf("Query = %q", got)
	}
}

func TestIDsInUserAgent(t *testing.T) {
	ua := "NintendoSDK Firmware/23.0.1-1.0 (platform:NX; did:6b1f2e3d4c5a6978; eid:lp1) 789f928b-138e-4b2f-afeb-1acae821d897 203.0.113.9"
	got := IDs(ua)
	for _, secret := range []string{"6b1f2e3d4c5a6978", "789f928b", "203.0.113.9"} {
		if strings.Contains(got, secret) {
			t.Fatalf("%q leaked into %q", secret, got)
		}
	}
	if !strings.Contains(got, "Firmware/23.0.1-1.0") || !strings.Contains(got, "eid:lp1") {
		t.Fatalf("IDs lost the readable part: %q", got)
	}
}
