package main

// What is new in Penne as its own service: only its own hostnames, the penne API the core,
// the shop and parental controls call, the one-time import of nx-baas's state, and the
// identity core reached over HTTP.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openpak/nx-common/nxapi"

	"nx-penne/internal/penne"
)

func TestForeignHostsAreMisrouted(t *testing.T) {
	s := &server{core: mustStore(t)}
	for _, host := range []string{"gw.hac.lp1.vermillion.srv.nintendo.net", "m-lp1.baas.nintendo.com", "hac.lp1.savanna.srv.nintendo.net"} {
		r := httptest.NewRequest("GET", "https://"+host+"/v1/accounts/config", nil)
		r.Host = host
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusMisdirectedRequest {
			t.Errorf("%s = %d, want 421", host, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "https://val.hac.lp1.penne.srv.nintendo.net/v1/frontlines", strings.NewReader(`{}`))
	r.Host = "val.hac.lp1.penne.srv.nintendo.net"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "fro-3.hac.lp1.penne.srv.nintendo.net") {
		t.Fatalf("val frontlines = %d %s", w.Code, w.Body)
	}
}

// A banned account gets no notification channel; the lock comes from the core.
func TestBannedAccountGetsNoNotificationChannel(t *testing.T) {
	s := &server{core: mustStore(t)}
	u, _ := testCore(s).NewUser()
	id, pw := s.notifStore().Register("dev1", u.ID, "", time.Now())
	_, ticket, err := s.notifStore().IssueTicket(id, pw, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	testCore(s).lock(u.ID, "banned")
	w := httptest.NewRecorder()
	s.frontline(w, frontlineRequest(ticket, "dev1"))
	if w.Code != 403 {
		t.Fatalf("frontline for a banned account = %d %s", w.Code, w.Body)
	}
}

// The core being away must not cost a console its push channel: the lock is unknown and
// the connection is let in (the core closes a banned user's connections itself).
func TestFrontlineConnectsWhileTheCoreIsDown(t *testing.T) {
	s := &server{core: mustStore(t)}
	u, _ := testCore(s).NewUser()
	id, pw := s.notifStore().Register("dev1", u.ID, "", time.Now())
	_, ticket, _ := s.notifStore().IssueTicket(id, pw, time.Now(), time.Hour)
	testCore(s).down = true
	ctx, cancel := context.WithCancel(context.Background())
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.frontline(w, frontlineRequestCtx(ctx, ticket, "dev1")); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if w.Code != 200 {
		t.Fatalf("frontline with the core down = %d %s", w.Code, w.Body)
	}
}

// A console's own presence frame reaches the core, decoded, and its lease is renewed there
// while the console stays connected.
func TestDAPresenceAndRenewalsReachTheCore(t *testing.T) {
	s := &server{core: mustStore(t)}
	withPresenceWorker(s)
	c := testCore(s)
	c.users["aaaaaaaaaaaa0001"] = &nxapi.User{ID: "aaaaaaaaaaaa0001"}
	frame, _ := hex.DecodeString(capturedDAPresence)
	env, err := penne.DecodeEnvelope(frame)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := env.Payload()
	if !s.penneNotePresence(p) {
		t.Fatal("captured frame not read")
	}
	eventually(t, "presence at the core", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.presence) == 1
	})
	got := c.presence[0]
	if got.UserID != "aaaaaaaaaaaa0001" || got.Device != "cccccccccccc0001" || got.State != "INACTIVE" || got.AppID != "" || got.ACDIndex != -1 {
		t.Fatalf("presence reached the core as %+v", got)
	}

	sess := &penneSession{user: "aaaaaaaaaaaa0001", penneID: "reg-1"}
	sess.published.Store("aaaaaaaaaaaa0001", "cccccccccccc0001")
	s.penneRenewPresence(sess)
	eventually(t, "renewal at the core", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		pair, user := false, false
		for _, r := range c.renewals {
			pair = pair || r.Device == "cccccccccccc0001"
			user = user || (r.UserID == "aaaaaaaaaaaa0001" && r.Device == "")
		}
		return pair && user
	})
}

// A console that reconnected has published nothing on the new connection, yet the claim it made
// on the last one must not lapse: the session's user is renewed with no device named.
func TestReconnectedSessionStillRenewsItsUser(t *testing.T) {
	s := &server{core: mustStore(t)}
	withPresenceWorker(s)
	c := testCore(s)
	sess := &penneSession{user: "aaaaaaaaaaaa0001", penneID: "reg-2"}
	s.penneRenewPresence(sess)
	eventually(t, "user-level renewal", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.renewals) == 1 && c.renewals[0].UserID == "aaaaaaaaaaaa0001" && c.renewals[0].Device == ""
	})
}

func penneAPIDo(t *testing.T, s *server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://openpak-nx-penne:20070"+path, strings.NewReader(body))
	r.Header.Set("X-Internal-Key", "k")
	w := httptest.NewRecorder()
	s.internalAPI().ServeHTTP(w, r)
	return w
}

// The penne API answers what nx-baas answered in-process (nx-baas internal_penne.go).
func TestPenneAPI(t *testing.T) {
	t.Setenv("NX_INTERNAL_KEY", "k")
	s := &server{core: mustStore(t)}
	u, _ := testCore(s).NewUser()

	if w := penneAPIDo(t, s, "POST", "/internal/penne/consoles", `{"device_id":"cert-1","user_id":"`+u.ID+`"}`); w.Code != 204 {
		t.Fatalf("consoles = %d", w.Code)
	}
	if got := s.notifStore().ResolveUser("cert-1"); got != u.ID {
		t.Fatalf("console binding = %q", got)
	}
	id, _ := s.notifStore().Register("dev1", u.ID, "", time.Now())
	w := penneAPIDo(t, s, "GET", "/internal/penne/registrations/"+id, "")
	var reg nxapi.Registration
	json.Unmarshal(w.Body.Bytes(), &reg)
	if w.Code != 200 || !reg.Live || reg.UserID != u.ID {
		t.Fatalf("registration = %d %s", w.Code, w.Body)
	}

	sess := &penneSession{user: u.ID, device: "dev1", penneID: id, ctx: context.Background(),
		send: make(chan penneOutbound, 8), cancel: func() {}}
	s.notifHub().attach(sess)

	w = penneAPIDo(t, s, "POST", "/internal/penne/notifications", `{"id":"n1","user_id":"`+u.ID+`","kind":"friend_deleted","payload":{"friendId":"x"}}`)
	var sub nxapi.Submission
	json.Unmarshal(w.Body.Bytes(), &sub)
	if w.Code != 200 || !sub.Accepted || sub.ID != "n1" {
		t.Fatalf("notification = %d %s", w.Code, w.Body)
	}

	s.notifStore().AddSubscription(u.ID, "dev1", "openpak_news", time.Now())
	w = penneAPIDo(t, s, "POST", "/internal/penne/topic-messages", `{"topic":"OpenPak_News","name":"news","receivers":"0x010000000000000c","body":"{}"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"delivered":1`) {
		t.Fatalf("topic message = %d %s", w.Code, w.Body)
	}

	// Parental controls name the console by the certificate its registration was made under.
	cid, _ := s.notifStore().Register("dev2", "cert-2", "", time.Now())
	csess := &penneSession{user: "cert-2", device: "dev2", penneID: cid, ctx: context.Background(), send: make(chan penneOutbound, 8)}
	s.notifHub().attach(csess)
	w = penneAPIDo(t, s, "POST", "/internal/penne/device-messages", `{"dauth_user":"cert-2","name":"DID_CHANGE_PARENTAL_CONTROL_SETTING","receivers":"pctl","body":"{}"}`)
	var dm nxapi.DeviceResult
	json.Unmarshal(w.Body.Bytes(), &dm)
	if w.Code != 200 || dm.PenneID != cid || dm.Connections != 1 {
		t.Fatalf("device message = %d %s", w.Code, w.Body)
	}

	if w = penneAPIDo(t, s, "POST", "/internal/penne/broadcasts", `{"name":"versionlist2","receivers":"versionlist2","body":"{}"}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"connections":`) || strings.Contains(w.Body.String(), `"connections":0`) {
		t.Fatalf("broadcast = %d %s", w.Code, w.Body)
	}

	if w := penneAPIDo(t, s, "POST", "/internal/penne/token-bindings", `{"notification_token":"unknown","user_id":"`+u.ID+`"}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"bound":false`) {
		t.Fatalf("token binding = %d %s", w.Code, w.Body)
	}
	if w := penneAPIDo(t, s, "POST", "/internal/penne/push-channels", `{"user_id":"`+u.ID+`","device_account_id":"d","service":"npns","device_token":"t"}`); w.Code != 204 {
		t.Fatalf("push channel = %d", w.Code)
	}
	if w := penneAPIDo(t, s, "POST", "/internal/penne/users/"+u.ID+"/close", `{}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"closed":1`) {
		t.Fatalf("close = %d %s", w.Code, w.Body)
	}

	t.Setenv("NX_INTERNAL_KEY", "other")
	if w := penneAPIDo(t, s, "GET", "/internal/penne/registrations/"+id, ""); w.Code != 401 {
		t.Fatalf("wrong key = %d", w.Code)
	}
}

// The first start takes nx-baas's penne.json as it stood; later starts keep their own; and a
// second cut-over after a rollback -- nx-baas's file moved on meanwhile -- takes it again
// instead of resuming from our stale copy.
func TestImportFollowsNxBaasAcrossARollback(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "baas-penne.json")
	old := newPenneStore(src)
	id, pw := old.Register("dev1", "user1", "", time.Now())

	mine := filepath.Join(dir, "penne.json")
	ps := loadPenneState(mine, src)
	if _, err := ps.CheckAssoc(id, pw, time.Now()); err != nil {
		t.Fatalf("imported registration does not verify: %v", err)
	}
	ps.Register("dev2", "user2", "", time.Now())
	again := loadPenneState(mine, src)
	if again.AssocForDevice("dev2") == nil || again.AssocForDevice("dev1") == nil {
		t.Fatal("a restart re-imported nx-baas's file over our own")
	}

	// Rollback: nx-baas serves Penne again and its file changes.
	back := newPenneStore(src)
	back.Register("dev3", "user3", "", time.Now())
	recut := loadPenneState(mine, src)
	if recut.AssocForDevice("dev3") == nil {
		t.Fatal("the second cut-over resumed from our stale state instead of nx-baas's")
	}
	if kept, _ := filepath.Glob(mine + ".before-import-*"); len(kept) != 1 {
		t.Fatalf("our replaced state was not kept aside: %v", kept)
	}
}

// A console host on the internal listener never reaches the penne API.
func TestConsoleHostNeverReachesThePenneAPI(t *testing.T) {
	t.Setenv("NX_INTERNAL_KEY", "k")
	s := &server{core: mustStore(t)}
	r := httptest.NewRequest("POST", "http://openpak-nx-penne:20070/internal/penne/users/u1/close", strings.NewReader(`{}`))
	r.Host = "god.hac.lp1.penne.srv.nintendo.net"
	r.Header.Set("X-Internal-Key", "k")
	w := httptest.NewRecorder()
	s.internalAPI().ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "closed") {
		t.Fatalf("console host reached the penne API: %d %s", w.Code, w.Body)
	}
}

// The real client against a stand-in for nx-baas's identity routes.
func TestPenneTalksToTheCoreOverHTTP(t *testing.T) {
	t.Setenv("NX_INTERNAL_KEY", "k")
	got := make(chan string, 8)
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Key") != "k" {
			w.WriteHeader(401)
			return
		}
		got <- r.Method + " " + r.URL.Path
		switch r.URL.Path {
		case "/internal/identity/users/u1":
			w.Write([]byte(`{"id":"u1","na_id":"n","pid":7,"nickname":"","lock":"banned"}`))
		case "/internal/identity/users/u1/friends/f1/preference":
			w.Write([]byte(`{"online_notification":false}`))
		case "/internal/identity/presence":
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer core.Close()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := &server{key: key, core: nxapi.New(core.URL)}
	withPresenceWorker(s)
	if lock := s.userLock(context.Background(), "u1"); lock != "banned" {
		t.Fatalf("lock = %q", lock)
	}
	if s.onlineNotification("u1", "f1") {
		t.Fatal("preference off read as on")
	}
	if !s.onlineNotification("nobody", "f1") {
		t.Fatal("an unknown viewer must allow")
	}
	s.reportPresence(presenceJob{p: nxapi.Presence{UserID: "u1", Device: "d", State: "ONLINE", ACDIndex: -1}})
	deadline := time.After(2 * time.Second)
	for {
		select {
		case call := <-got:
			if call == "POST /internal/identity/presence" {
				return
			}
		case <-deadline:
			t.Fatal("presence never reached the core")
		}
	}
}
