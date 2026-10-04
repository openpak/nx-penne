package main

// penne_router_test.go: full-path transport tests (NTF-03). They drive the real
// ServeHTTP -- through the debug wrapper on and off -- over a live HTTP server,
// because the streaming defects the audit found only exist on that path: a
// recorder can hide a missing http.Flusher, a socket cannot.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nx-penne/internal/penne"
)

const frontlineDevice = "0123456789abcdef"

// liveServer is a server with one registered user, one device registration and
// a valid login ticket, like a console just past Penne setup.
func liveServer(t *testing.T) (*server, string) {
	t.Helper()
	s := &server{core: mustStore(t)}
	u, _ := testCore(s).NewUser()
	id, pw := s.notifStore().Register(frontlineDevice, u.ID, "", time.Now())
	_, ticket, err := s.notifStore().IssueTicket(id, pw, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	return s, ticket
}

// frontlineDial opens a bidirectional frontline connection the way the console
// does: POST with a ticket, frames written on the request body while the
// response streams back.
func frontlineDial(t *testing.T, ts *httptest.Server, ticket string, hello []byte) (*http.Response, io.WriteCloser, *penne.FrameReader) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, pr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "fro-3.hac.lp1.penne.srv.nintendo.net"
	req.Header.Set("Authorization", "Bearer "+ticket)
	req.Header.Set("User-Agent", "NintendoSDK Firmware/22.5.0 (platform:NX; did:"+frontlineDevice+"; eid:lp1)")
	// Speak first, like the console: its frontline frames go out on the request
	// body as soon as the connection is up.
	if hello != nil {
		go pw.Write(hello) //nolint:errcheck -- test: reader side fails loudly
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res, pw, penne.NewFrameReader(res.Body, penne.MaxFrameSize)
}

// expectGreeting consumes the frame the server sends as soon as the connection
// is accepted: the console's state machine reads exactly one message with a
// 70-second deadline and accepts only HandoverResult or Reset, so every
// frontline test starts by reading that handover.
func expectGreeting(t *testing.T, fr *penne.FrameReader) {
	t.Helper()
	frame, err := fr.Next()
	if err != nil {
		t.Fatalf("greeting: %v", err)
	}
	env, err := penne.DecodeEnvelope(frame)
	if err != nil {
		t.Fatalf("greeting malformed: %v", err)
	}
	if env.Type() != penne.TypeHandoverResult {
		t.Fatalf("first frame = %s, want HandoverResult", env.TypeName())
	}
	// Field 0 is the byte the console tests: zero continues, non-zero retries.
	payload, ok := env.Payload()
	if !ok {
		t.Fatal("handover has no payload table")
	}
	if v, ok := payload.U8(0); !ok || v != 0 {
		t.Fatalf("handover result = %d (present=%v), want 0", v, ok)
	}
}

// The full ServeHTTP path must stream with the debug wrapper on AND off: the
// audit reproduced the failure class (frontline answered non-streaming under
// NX_DEBUG because the wrapper dropped http.Flusher). Both directions must
// carry real frames.
func TestFrontlineStreamsThroughServeHTTPDebugOnAndOff(t *testing.T) {
	for _, debugOn := range []bool{false, true} {
		t.Run(fmt.Sprintf("debug=%v", debugOn), func(t *testing.T) {
			old := debug
			debug = debugOn
			t.Cleanup(func() { debug = old })

			s, ticket := liveServer(t)
			ts := httptest.NewTLSServer(s)
			defer ts.Close()
			userID := ""
			for id := range testCore(s).users {
				userID = id
			}

			// Hello first (the console sends Hi/SubscribeTopic on connect):
			// a Ping, whose Pong must come back.
			res, _, fr := frontlineDial(t, ts, ticket, penne.AppendFrame(nil, penne.BuildPing(0xdeadbeef, 0, 0)))
			expectGreeting(t, fr)
			if res.StatusCode != 200 {
				t.Fatalf("status = %d, want 200", res.StatusCode)
			}
			if ct := res.Header.Get("Content-Type"); ct != "application/octet-stream" {
				t.Fatalf("content type = %q, want octet-stream", ct)
			}

			// Server->client: a submitted event reaches the live connection.
			if res := s.SubmitNotification(PenneDelivery{
				UserID: userID, Kind: EventFriendRequestReceived,
				Payload: map[string]any{"friendId": "aaaabbbbccccdddd"},
			}); !res.Accepted {
				t.Fatalf("submit: %+v", res)
			}

			// Both directions are in flight; classify the two frames as they
			// arrive (order is the session's send queue's choice).
			gotPong, gotEvent := false, false
			for i := 0; i < 2; i++ {
				frame, err := fr.Next()
				if err != nil {
					t.Fatalf("frame %d: %v", i, err)
				}
				env, err := penne.DecodeEnvelope(frame)
				if err != nil {
					t.Fatalf("frame %d malformed: %v", i, err)
				}
				switch env.Type() {
				case penne.TypePong:
					pong, _ := env.Payload()
					if v, _ := pong.U64(0); v != 0xdeadbeef {
						t.Fatalf("pong echo = %#x, want %#x", v, uint64(0xdeadbeef))
					}
					gotPong = true
				case penne.TypeMessageRequest:
					payload, _ := env.Payload()
					body, _ := payload.String(0)
					var event map[string]any
					if err := json.Unmarshal([]byte(body), &event); err != nil {
						t.Fatalf("event body is not JSON: %v (%q)", err, body)
					}
					if event["type"] != EventFriendRequestReceived {
						t.Fatalf("event type = %v, want %s", event["type"], EventFriendRequestReceived)
					}
					if event["id"] == "" {
						t.Fatal("event body carries no dedup id")
					}
					gotEvent = true
				default:
					t.Fatalf("unexpected frame %s", env.TypeName())
				}
			}
			if !gotPong || !gotEvent {
				t.Fatalf("bidirectional frames incomplete: pong=%v event=%v", gotPong, gotEvent)
			}
		})
	}
}

// A malformed frame must terminate the session without a panic and without
// reading the next frames (robustness: bounded, fail-closed).
func TestFrontlineClosesOnMalformedFrame(t *testing.T) {
	s, ticket := liveServer(t)
	ts := httptest.NewTLSServer(s)
	defer ts.Close()
	// The hello IS the malformed frame: a length prefix beyond any bound with
	// no body behind it.
	res, _, fr := frontlineDial(t, ts, ticket, []byte{0xff, 0xff, 0xff, 0xff, 0x01})
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	done := make(chan struct{})
	go func() { // the session must end; the reader errors instead of hanging
		for {
			if _, err := fr.Next(); err != nil {
				break
			}
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("connection survived a malformed frame for 3s")
	}
}

// Reconnect reconciliation (NTF-05): an event submitted while nobody is
// connected is delivered on the next connection; a duplicate submission is not
// delivered twice; presence converges to the latest payload.
func TestFiniteFrontlineReplaysOfflineFriendChange(t *testing.T) {
	s, ticket := liveServer(t)
	ts := httptest.NewTLSServer(s)
	defer ts.Close()
	var userID string
	for id := range testCore(s).users {
		userID = id
	}
	if res := s.SubmitNotification(PenneDelivery{
		ID: "offline-removal", UserID: userID, Kind: EventFriendDeleted,
		Payload: map[string]any{"friendId": "1111"},
	}); !res.Accepted {
		t.Fatalf("submit: %+v", res)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "fro-3.hac.lp1.penne.srv.nintendo.net"
	req.Header.Set("Authorization", "Bearer "+ticket)
	req.Header.Set("User-Agent", "NintendoSDK Firmware/22.5.0 (platform:NX; did:"+frontlineDevice+"; eid:lp1)")
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", res.StatusCode)
	}
	fr := penne.NewFrameReader(res.Body, penne.MaxFrameSize)
	expectGreeting(t, fr)
	frame, err := fr.Next()
	if err != nil {
		t.Fatalf("offline change was not replayed: %v", err)
	}
	env, err := penne.DecodeEnvelope(frame)
	if err != nil {
		t.Fatal(err)
	}
	if env.Type() != penne.TypeMessageRequest {
		t.Fatalf("unexpected frame: %s", env.TypeName())
	}
	payload, ok := env.Payload()
	if !ok {
		t.Fatal("missing event payload")
	}
	body, _ := payload.String(0)
	if !strings.Contains(body, `"type":"friend_deleted"`) || !strings.Contains(body, `"id":"offline-removal"`) {
		t.Fatalf("wrong replayed event: %s", body)
	}
}

func TestFrontlineReconnectReplaysPendingOnce(t *testing.T) {
	s, ticket := liveServer(t)
	ts := httptest.NewTLSServer(s)
	defer ts.Close()
	userID := ""
	for id := range testCore(s).users {
		userID = id
	}

	// Offline: two submissions, one a duplicate of the other.
	r1 := s.SubmitNotification(PenneDelivery{
		ID: "ev-fixed", UserID: userID, Kind: EventFriendRequestAuthorized,
		Payload: map[string]any{"friendId": "1111"},
	})
	if !r1.Accepted {
		t.Fatalf("submit 1: %+v", r1)
	}
	r2 := s.SubmitNotification(PenneDelivery{
		ID: "ev-fixed", UserID: userID, Kind: EventFriendRequestAuthorized,
		Payload: map[string]any{"friendId": "1111"},
	})
	if !r2.Duplicate {
		t.Fatalf("submit 2 (same id): %+v, want duplicate", r2)
	}

	// Connect: the queued event is reconciled on connect (the hello Ping is
	// answered with a Pong, so skip that frame first).
	res, _, fr := frontlineDial(t, ts, ticket, penne.AppendFrame(nil, penne.BuildPing(1, 0, 0)))
	expectGreeting(t, fr)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	// The hello Ping is answered with a Pong; read past whatever comes first
	// until the replayed event shows up (bounded: at most a few frames).
	sawReplay, body := false, ""
	for i := 0; i < 5; i++ {
		frame, err := fr.Next()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		env, err := penne.DecodeEnvelope(frame)
		if err != nil {
			t.Fatalf("frame %d malformed: %v", i, err)
		}
		if env.Type() == penne.TypeMessageRequest {
			payload, _ := env.Payload()
			body, _ = payload.String(0)
			sawReplay = true
			break
		}
		if env.Type() != penne.TypePong {
			t.Fatalf("unexpected frame %s while waiting for replay", env.TypeName())
		}
	}
	if !sawReplay {
		t.Fatal("the queued event was never replayed on connect")
	}
	if !strings.Contains(body, `"type":"friend_request_authorized"`) {
		t.Fatalf("replayed body = %s", body)
	}

	// The same id must not be replayed again on the next connection.
	res2, _, fr2 := frontlineDial(t, ts, ticket, penne.AppendFrame(nil, penne.BuildPing(1, 0, 0)))
	expectGreeting(t, fr2)
	if res2.StatusCode != 200 {
		t.Fatalf("reconnect status = %d", res2.StatusCode)
	}
	// Wake with nothing new: only the hello's Pong may arrive. The keepalive
	// flush writes nothing, so a quiet window past the Pong means no replay.
	var replayed bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			frame, err := fr2.Next()
			if err != nil {
				return
			}
			if env, err := penne.DecodeEnvelope(frame); err != nil || env.Type() != penne.TypePong {
				replayed = true
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
	}
	if replayed {
		t.Fatal("delivered event was replayed after reconnect")
	}
}

// The sync answer, and the single fact the whole notification path rests on:
// the console proceeds only when the entry vector is EMPTY. Mirroring its own
// digests back claims this server holds records under those namespaces, and it
// then asks for a leaf we cannot produce and reconnects forever. An empty
// vector says "nothing here", which is true, and the console answers
// SyncComplete and moves to the steady state
// [runtime capture, 2026-09-12: four cycles, six candidates each, only this one
// ever produced SyncComplete].
func TestSyncIsAnsweredWithAnEmptyEntryVector(t *testing.T) {
	s, ticket := liveServer(t)
	ts := httptest.NewTLSServer(s)
	defer ts.Close()

	entries := []penne.RootEntry{
		{Name: "c-appearance", Digest: bytes.Repeat([]byte{0x11}, 20)},
		{Name: "c-friends", Digest: bytes.Repeat([]byte{0x22}, 20)},
	}
	hello := penne.AppendFrame(nil, penne.BuildRootHash(entries, 20, 1789204471, 1789208071))
	res, _, fr := frontlineDial(t, ts, ticket, hello)
	defer res.Body.Close()
	expectGreeting(t, fr)

	frame, err := fr.Next()
	if err != nil {
		t.Fatalf("no answer to RootHash: %v", err)
	}
	env, err := penne.DecodeEnvelope(frame)
	if err != nil {
		t.Fatalf("answer malformed: %v", err)
	}
	if env.Type() != penne.TypeRootHash {
		t.Fatalf("answer = %s, want RootHash", env.TypeName())
	}
	payload, ok := env.Payload()
	if !ok {
		t.Fatal("answer has no payload")
	}
	if got := penne.ParseRootHash(payload); len(got) != 0 {
		t.Fatalf("answered with %d entries (%q…), want none -- mirroring the "+
			"console's digests is what kept it in the reconnect loop", len(got), got[0].Name)
	}
}

// A notification goes out as a kind-1 message inside a PutRecord, addressed by
// its Meta to the recipient's console account
// (docs/penne-record-shape-2026-09-16.md).
func TestEventIsDeliveredAsAKindOneMessage(t *testing.T) {
	old := penneSendEvents
	penneSendEvents = false
	t.Cleanup(func() { penneSendEvents = old })

	s, ticket := liveServer(t)
	ts := httptest.NewTLSServer(s)
	defer ts.Close()
	var userID string
	for id := range testCore(s).users {
		userID = id
	}
	if res := s.SubmitNotification(PenneDelivery{
		ID: "record-1", UserID: userID, Kind: EventFriendRequestAuthorized,
		Payload: map[string]any{"friendId": "aaaaaaaaaaaa0002"},
	}); !res.Accepted {
		t.Fatalf("submit: %+v", res)
	}

	res, _, fr := frontlineDial(t, ts, ticket, nil)
	defer res.Body.Close()
	expectGreeting(t, fr)

	frame, err := fr.Next()
	if err != nil {
		t.Fatalf("no delivery: %v", err)
	}
	env, err := penne.DecodeEnvelope(frame)
	if err != nil {
		t.Fatalf("delivery malformed: %v", err)
	}
	if env.Type() != penne.TypePutRecord {
		t.Fatalf("delivery = %s, want PutRecord", env.TypeName())
	}
	payload, ok := env.Payload()
	if !ok {
		t.Fatal("delivery has no payload")
	}
	// Exactly one entry: the parser reads slot 0 as a vector length and aborts
	// on anything else, which is what our old {name, value} payload did.
	if n, ok := payload.VectorLen(0); !ok || n != 1 {
		t.Fatalf("entry vector = %d (ok=%v), want one", n, ok)
	}
	m, ok := penne.ParseMessage(payload)
	if !ok {
		t.Fatal("the entry is not a kind-1 message")
	}
	if !strings.Contains(m.Body, `"type":"friend_request_authorized"`) {
		t.Errorf("message body = %s", m.Body)
	}
	if m.Receivers == "" {
		t.Error("empty receiver list; npns has nothing to route by")
	}
}
