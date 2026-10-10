package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"nx-penne/internal/penne"
)

// Everything this service logs about a request, a delivery and a presence frame must leave
// the ids, the token, the user agent's device id and the client address out: they are tagged
// or reduced to a length, and header values and bodies are never logged (debug on, trace off).
func TestLogsCarryNoPersonalData(t *testing.T) {
	if os.Getenv("NX_PENNE_TRACE_BODIES") == "1" {
		t.Skip("NX_PENNE_TRACE_BODIES=1 logs bodies and values on purpose")
	}
	const (
		userID   = "8a2b3c4d5e6f7081"
		viewerID = "1f2e3d4c5b6a7988"
		pid      = "73400125"
		code     = "483920"
		token    = "tok-9f8e7d6c5b4a39281706"
		device   = "6b1f2e3d4c5a6978"
		addr     = "203.0.113.77"
	)
	var logged bytes.Buffer
	log.SetOutput(&logged)
	oldDebug := debug
	debug = true
	t.Cleanup(func() { log.SetOutput(os.Stderr); debug = oldDebug })

	// (a) A request with ids in the path and query, a bearer token, a device id in the
	// user agent and a client address.
	s := &server{}
	r := httptest.NewRequest("POST", "https://god.hac.lp1.penne.srv.nintendo.net/v1/users/"+userID+"/devices/"+pid+
		"?pairingCode="+code, strings.NewReader(`{"deviceId":"`+device+`"}`))
	r.RemoteAddr = addr + ":44312"
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("User-Agent", "NintendoSDK Firmware/23.0.1-1.0 (platform:NX; did:"+device+"; eid:lp1)")
	s.ServeHTTP(httptest.NewRecorder(), r)

	// A frontline request with a ticket, which the store refuses.
	fr := frontlineRequest(token, device)
	fr.RemoteAddr = addr + ":44313"
	s.frontline(httptest.NewRecorder(), fr)

	// (b) The notification path: a presence delivery whose id carries both users, for a
	// recipient no console account is known for (the "unaddressed" line).
	id := "presence:" + userID + ":" + viewerID + ":1760000000:ONLINE|0100152000022000|{}"
	sess := &penneSession{
		user: userID, device: device,
		ctx:  context.Background(),
		send: make(chan penneOutbound, 4),
	}
	s.notifHub().attach(sess)
	if res := s.SubmitNotification(PenneDelivery{ID: id, UserID: userID, Kind: EventPresenceUpdated}); !res.Accepted {
		t.Fatalf("submit: %+v", res)
	}
	s.penneWake(userID)
	s.penneMessageFrames(&penneOutRec{ID: id, UserID: userID, Kind: EventPresenceUpdated})

	// (c) A presence frame naming a device and a user.
	frame, err := hex.DecodeString(capturedDAPresence)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	env, err := penne.DecodeEnvelope(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	p, _ := env.Payload()
	if !s.penneNotePresence(p) {
		t.Fatal("presence frame not read")
	}

	got := logged.String()
	if !strings.Contains(got, "[nx-penne]") || !strings.Contains(got, "~") {
		t.Fatalf("no tagged line in the log:\n%s", got)
	}
	for _, line := range []string{"unaddressed", "DBG >>>", "presence user="} {
		if !strings.Contains(got, line) {
			t.Errorf("expected a %q line in the log:\n%s", line, got)
		}
	}
	for _, secret := range []string{
		userID, viewerID, pid, code, token, device, addr, "44312", "44313",
		"cccccccccccc0001", "aaaaaaaaaaaa0001", // the captured frame's device account and user
	} {
		if strings.Contains(got, secret) {
			t.Errorf("log contains %q:\n%s", secret, got)
		}
	}
}
