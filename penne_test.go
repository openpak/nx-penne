package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// The Penne frontline POST must be held open, not 404-ed, and only for a real
// login ticket: the console re-registers on a denial, so a denial must be fast
// and honest. These tests drive s.penne (the routed entry point) the way the
// console drives it after registration.
// NPNS 22.5.0 requires the nested parameter descriptors to all report success
// before its login routine returns success (RVA 0xbf100 and 0xb8b50). Values
// below come from its constructor at RVA 0xb82e0, not from our renderer.
func TestPenneBootstrapIncludesRequiredNativeConnectionParameters(t *testing.T) {
	for _, path := range []string{"/v1/frontlines", "/v1/login_tickets"} {
		t.Run(path, func(t *testing.T) {
			s := &server{}
			id, pw := s.notifStore().Register("console", "user", "", time.Now())
			body, _ := json.Marshal(map[string]string{"id": id, "password": pw})
			req := httptest.NewRequest(http.MethodPost, "https://val.hac.lp1.penne.srv.nintendo.net"+path, strings.NewReader(string(body)))
			rr := httptest.NewRecorder()
			s.penne(rr, req, body)
			if rr.Code != http.StatusOK {
				t.Fatalf("status: %d", rr.Code)
			}
			var reply map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			params, ok := reply["persistent_connection_params_simple"].(map[string]any)
			if !ok {
				t.Fatal("missing connection parameters")
			}
			for key, want := range map[string]any{
				"ignore_rst": true, "retry_count": float64(2), "wait_sec": float64(3600),
				"wowl_timeout": float64(410), "rtt_max": float64(300),
			} {
				if got := params[key]; got != want {
					t.Errorf("%s = %v, want native default %v", key, got, want)
				}
			}
			for name, disabled := range map[string]bool{"awake": false, "sleep": true} {
				mode, ok := params[name].(map[string]any)
				if !ok {
					t.Fatalf("missing %s parameters", name)
				}
				count := float64(2)
				if name == "sleep" {
					count = 1440
				}
				for key, want := range map[string]any{"idle": float64(60), "interval": float64(10), "count": count, "disable": disabled} {
					if got := mode[key]; got != want {
						t.Errorf("%s.%s = %v, want native default %v", name, key, got, want)
					}
				}
			}
		})
	}
}

func frontlineServer(t *testing.T, deviceID string) (*server, string) {
	t.Helper()
	s := &server{}
	id, pw := s.notifStore().Register(deviceID, "u_"+deviceID, "", time.Now())
	_, ticket, err := s.notifStore().IssueTicket(id, pw, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	return s, ticket
}

func frontlineRequest(ticket, deviceID string) *http.Request {
	return frontlineRequestCtx(context.Background(), ticket, deviceID)
}

func frontlineRequestCtx(ctx context.Context, ticket, deviceID string) *http.Request {
	r := httptest.NewRequest("POST", "/", nil).WithContext(ctx)
	r.Host = "fro-3.hac.lp1.penne.srv.nintendo.net"
	if ticket != "" {
		r.Header.Set("Authorization", "Bearer "+ticket)
	}
	if deviceID != "" {
		r.Header.Set("User-Agent", "NintendoSDK Firmware/22.5.0 (platform:NX; did:"+deviceID+"; eid:lp1)")
	}
	return r
}

func TestFrontlineHoldsOpenWithATicket(t *testing.T) {
	const device = "0123456789abcdef"
	s, ticket := frontlineServer(t, device)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.penne(w, frontlineRequestCtx(ctx, ticket, device), nil); close(done) }()

	select { // held open: it must not return on its own
	case <-done:
		t.Fatal("frontline returned without the client disconnecting")
	case <-time.After(50 * time.Millisecond):
	}
	cancel() // console hung up
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("frontline did not return after the client disconnected")
	}
	// Only after the handler returned may the recorder be read.
	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("content type = %q, want octet-stream", ct)
	}
}

func TestFrontlineDeniesBadTickets(t *testing.T) {
	const device = "0123456789abcdef"
	s, ticket := frontlineServer(t, device)
	id, pw := s.notifStore().Register(device, "u2", "", time.Now())

	_, revoked, err := s.notifStore().IssueTicket(id, pw, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("issue revoked ticket: %v", err)
	}
	_, expired, err := s.notifStore().IssueTicket(id, pw, time.Now().Add(-2*time.Hour), time.Hour)
	if err != nil {
		t.Fatalf("issue expired ticket: %v", err)
	}
	s.notifStore().Revoke(id, time.Now())

	cases := map[string]struct {
		ticket, device string
	}{
		"no ticket":      {"", ""},
		"unknown ticket": {strings.Repeat("ab", 32), device},
		"revoked":        {revoked, device},
		"expired":        {expired, device},
		"wrong device":   {ticket, "ffffffffffffffff"},
	}
	for name, tc := range cases {
		w := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { s.penne(w, frontlineRequest(tc.ticket, tc.device), nil); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s: frontline stayed open on a denial", name)
		}
		if w.Code != 401 {
			t.Errorf("%s: status = %d, want 401", name, w.Code)
		}
	}
}

var errNoPayload = errors.New(`reply has no string "payload" field`)

// The console reports its previous frontline attempt on every Penne request.
// An all-zero result is "nothing to report" and stays quiet; anything else is
// the console telling us why it dropped the last connection, and it must reach
// the log rather than be discarded.
func TestConsoleReportedFrontlineResultIsLogged(t *testing.T) {
	s := &server{}
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	call := func(fro string) {
		r := httptest.NewRequest("GET", "https://val.hac.lp1.penne.srv.nintendo.net/v1/frontlines", nil)
		r.Host = "val.hac.lp1.penne.srv.nintendo.net"
		if fro != "" {
			r.Header.Set("X-Fro-Result", fro)
			r.Header.Set("X-Login-Try", "2")
		}
		s.penne(httptest.NewRecorder(), r, nil)
	}

	call("000-0000")
	if strings.Contains(logged.String(), "console reports") {
		t.Errorf("an all-zero result was logged as a failure: %s", logged.String())
	}
	call("2-ABCDE")
	if !strings.Contains(logged.String(), "console reports last frontline result 2-ABCDE") {
		t.Errorf("a reported failure did not reach the log: %s", logged.String())
	}
}

// A console keeps its Penne registration in its own save data and presents it
// forever. One that registered against a different server arrives with an id
// this store never minted; answering 403 leaves it holding credentials we
// reject with no way to get ones we accept, so it never opens a frontline again
// and every notification for it is undeliverable for the life of the console.
// That is what a real console looked like on 2026-09-12: active on BAAS all
// evening, no Penne registration at all, no frontline connection ever.
func TestUnknownPenneIdIsRegisteredNotRefused(t *testing.T) {
	s, _ := liveServer(t)
	store := s.notifStore()

	body := `{"id":"pneverminted0000000000000000000","password":"whatever"}`
	r := httptest.NewRequest("POST", "https://god.hac.lp1.penne.srv.nintendo.net/v1/penne_ids",
		strings.NewReader(body))
	r.Host = "god.hac.lp1.penne.srv.nintendo.net"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.penne(w, r, []byte(body))

	if w.Code != 200 {
		t.Fatalf("status %d: a console with a foreign id must be able to register, not be locked out", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	id, _ := got["id"].(string)
	if id == "" || id == "pneverminted0000000000000000000" {
		t.Fatalf("id = %q, want a freshly minted one", id)
	}
	if pw, _ := got["password"].(string); pw == "" {
		t.Fatal("no password: the console cannot use the registration it was just given")
	}
	if !store.KnowsAssoc(id) {
		t.Fatal("the minted id is not in the store")
	}
}

// The other half: a known id with a wrong password is still a denial. Minting
// on an unverifiable id must not become a way to take over one that exists.
func TestKnownPenneIdWithABadPasswordIsStillRefused(t *testing.T) {
	s, _ := liveServer(t)
	store := s.notifStore()
	id, _ := store.Register("dev-1", "user-1", "", time.Now())

	body := `{"id":"` + id + `","password":"wrong"}`
	r := httptest.NewRequest("POST", "https://god.hac.lp1.penne.srv.nintendo.net/v1/penne_ids",
		strings.NewReader(body))
	r.Host = "god.hac.lp1.penne.srv.nintendo.net"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.penne(w, r, []byte(body))

	if w.Code != 403 {
		t.Fatalf("status %d, want 403", w.Code)
	}
}

// The console names its registration without a password when it asks for a
// notification token, and the request is authenticated by its bearer instead.
// Refusing it 401'd a console presenting its own live penne_id on every
// attempt, so the console account id in the path -- the address the friends
// module requires every event to carry -- was never recorded.
// Captured from hardware 2026-09-12:
//
//	POST /v1/accounts/1000000000a100010000000000000001/notification_tokens
//	{"penne_id":"pzxi…","application_id":"0x010000000000003e"}
func TestNotificationTokenAcceptsAPasswordlessPenneId(t *testing.T) {
	s, _ := liveServer(t)
	store := s.notifStore()
	id, _ := store.Register("", "user-1", "", time.Now())

	const account = "1000000000a100010000000000000001"
	body := `{"penne_id":"` + id + `","application_id":"0x010000000000003e"}`
	r := httptest.NewRequest("POST",
		"https://god.hac.lp1.penne.srv.nintendo.net/v1/accounts/"+account+"/notification_tokens",
		strings.NewReader(body))
	r.Host = "god.hac.lp1.penne.srv.nintendo.net"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.penne(w, r, []byte(body))

	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if tok, _ := got["notification_token"].(string); tok == "" {
		t.Fatal("no notification_token in the reply")
	}
	// The point of the route: the console account id must now be on record
	// against this registration. It is the address the friends module requires
	// every event to carry, and the only place the console ever shows it to us.
	a := store.AssocByID(id)
	if a == nil || len(a.AccountIDs) == 0 || a.AccountIDs[0] != account {
		t.Fatalf("registration records %v, want the console account from the path", a)
	}
}

// A revoked registration is still refused, password or not.
func TestPasswordlessPenneIdIsRefusedOnceRevoked(t *testing.T) {
	s, _ := liveServer(t)
	store := s.notifStore()
	id, _ := store.Register("", "user-1", "", time.Now())
	store.Revoke(id, time.Now())

	body := `{"penne_id":"` + id + `"}`
	r := httptest.NewRequest("POST",
		"https://god.hac.lp1.penne.srv.nintendo.net/v1/accounts/1000000000a100010000000000000001/notification_tokens",
		strings.NewReader(body))
	r.Host = "god.hac.lp1.penne.srv.nintendo.net"
	w := httptest.NewRecorder()
	s.penne(w, r, []byte(body))

	if w.Code != 401 {
		t.Fatalf("status %d, want 401 for a revoked registration", w.Code)
	}
}
