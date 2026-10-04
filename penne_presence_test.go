package main

// The console's own presence frame, byte-for-byte as a live Switch sent it.
// Nothing about presence for a real console works unless this parses: a Switch
// never PATCHes the REST presence route, so this frame is the only presence it
// ever offers.

import (
	"encoding/hex"
	"testing"

	"nx-penne/internal/penne"
)

// Captured 2026-09-12 from a console signed in as two profiles, idle on Home.
const capturedDAPresence = "180000000000000000000e002400070008000c00100018000e0000000000001b3000000018000000" +
	"b6ada56a00000000c6bba56a0000000000000000020000004e58000000000a001200040008000c00" +
	"0a000000fc000000e00000001000000000000a000c000400080006000a0000000100010004000000" +
	"b90000007b2273656c66223a7b7d2c226661766f72697465467269656e6473223a7b7d2c22667269" +
	"656e6473223a7b226170704669656c64223a227b7d222c22617070496e666f3a6170704964223a22" +
	"30303030303030303030303030303030222c22617070496e666f3a616364496e646578223a302c22" +
	"617070496e666f3a70726573656e636547726f75704964223a223030303030303030303030303030" +
	"3030227d2c22666f6166223a7b7d2c2265766572796f6e65223a7b7d7d0000001000000061616161" +
	"61616161616161613030303100000000100000006363636363636363636363633030303100000000"

func TestCapturedDAPresenceParses(t *testing.T) {
	frame, err := hex.DecodeString(capturedDAPresence)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	env, err := penne.DecodeEnvelope(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Type() != penne.TypeDAPresence {
		t.Fatalf("type %s, want DAPresence", env.TypeName())
	}
	p, ok := env.Payload()
	if !ok {
		t.Fatal("no payload")
	}
	if got, _ := p.String(0); got != "cccccccccccc0001" {
		t.Errorf("device account = %q", got)
	}
	if got, _ := p.String(1); got != "aaaaaaaaaaaa0001" {
		t.Errorf("user = %q", got)
	}
	inner, ok := p.Table(2)
	if !ok {
		t.Fatal("no presence table")
	}
	if live, _ := inner.U8(0); live != 1 {
		t.Errorf("state byte = %d, want 1", live)
	}
	doc, _ := inner.String(1)
	if doc == "" {
		t.Fatal("no extras document")
	}

	// Idle on Home: online, and deliberately NOT "playing title 0000000000000000".
	state, appID, _, _, acd := presenceFromExtras(doc, 1)
	if state != "INACTIVE" {
		t.Errorf("state = %q, want INACTIVE (signed in, no game)", state)
	}
	if appID != "" {
		t.Errorf("appID = %q; an all-zero title id means no game", appID)
	}
	if acd != -1 {
		t.Errorf("acdIndex = %d, want -1 when no title is published", acd)
	}
}

// The same document with a real title in it: that is what "online, playing X"
// has to come from, because the frame carries no title field of its own.
func TestPresenceFromExtrasReadsTheTitle(t *testing.T) {
	doc := `{"self":{},"friends":{"appField":"AA==","appInfo:appId":"0100e65002bb8000",` +
		`"appInfo:acdIndex":3,"appInfo:presenceGroupId":"0100e65002bb8000"},"everyone":{}}`
	state, appID, appField, group, acd := presenceFromExtras(doc, 3)
	if state != "PLAYING" {
		t.Errorf("state = %q, want PLAYING", state)
	}
	// In the same game with no session open: online, not joinable.
	if st, _, _, _, _ := presenceFromExtras(doc, 2); st != "ONLINE" {
		t.Errorf("state byte 2 = %q, want ONLINE", st)
	}
	if appID != "0100e65002bb8000" || group != "0100e65002bb8000" {
		t.Errorf("appID=%q group=%q", appID, group)
	}
	if appField != "AA==" {
		t.Errorf("appField = %q", appField)
	}
	if acd != 3 {
		t.Errorf("acdIndex = %d, want 3", acd)
	}
}

// A console that has gone offline publishes the same document with the live
// byte clear; it must not read as online.
func TestPresenceFromExtrasHonoursTheLiveByte(t *testing.T) {
	doc := `{"friends":{"appInfo:appId":"0100e65002bb8000"}}`
	if state, _, _, _, _ := presenceFromExtras(doc, 0); state != "OFFLINE" {
		t.Errorf("state = %q, want OFFLINE", state)
	}
}
