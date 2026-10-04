package main

// The leaf half of the sync. The console's LeafHash is an OFFER -- it names a
// namespace and lists the leaves it holds under it, then waits for ours. Left
// unanswered it abandons the connection after about seventy seconds, which is
// what every entries-bearing sync answer did before this existed.

import (
	"encoding/hex"
	"testing"

	"nx-penne/internal/penne"
)

// Captured from a live console, 2026-09-12, in reply to a RootHash that carried
// entries: namespace "c-appearance", zero leaves.
const capturedLeafHash = "180000000000000000000e002400070008000c00100018000e000000000000072c000000180000" +
	"00ba82a56a00000000ca90a56a0000000000000000020000004e58000008000c00040008000800" +
	"00000c00000004000000000000000c000000632d617070656172616e636500000000"

func TestCapturedLeafHashIsAnOfferNotARejection(t *testing.T) {
	frame, err := hex.DecodeString(capturedLeafHash)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	env, err := penne.DecodeEnvelope(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Type() != penne.TypeLeafHash {
		t.Fatalf("type %s, want LeafHash", env.TypeName())
	}
	p, ok := env.Payload()
	if !ok {
		t.Fatal("no payload")
	}
	ns, leaves := penne.ParseLeafHash(p)
	if ns != "c-appearance" {
		t.Fatalf("namespace = %q, want c-appearance", ns)
	}
	if len(leaves) != 0 {
		t.Fatalf("leaves = %d, want 0 -- the console holds none under it", len(leaves))
	}
}

// Our reply has to be the console's own shape: namespace in slot 0, leaves in
// slot 1. RootHash uses a bare vector and getting the two confused sends a
// well-formed frame that answers a different question.
func TestLeafHashReplyRoundTrips(t *testing.T) {
	want := []penne.RootEntry{
		{Name: "c-friends.inv.subsTypes", Digest: make([]byte, 20)},
		{Name: "c-friends.other", Digest: make([]byte, 20)},
	}
	frame := penne.BuildLeafHashReply("c-friends", want, uint32(len(want)), 100, 3700)
	env, err := penne.DecodeEnvelope(frame)
	if err != nil {
		t.Fatalf("our own frame does not decode: %v", err)
	}
	if env.Type() != penne.TypeLeafHash {
		t.Fatalf("type %s", env.TypeName())
	}
	p, ok := env.Payload()
	if !ok {
		t.Fatal("no payload")
	}
	ns, got := penne.ParseLeafHash(p)
	if ns != "c-friends" {
		t.Fatalf("namespace = %q", ns)
	}
	if len(got) != len(want) {
		t.Fatalf("%d leaves, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Name != want[i].Name {
			t.Errorf("leaf %d = %q, want %q", i, got[i].Name, want[i].Name)
		}
	}
}

// A namespace owns the dotted topics beneath it, and a record named for the
// namespace itself is its own leaf. Anything else must not leak into the reply.
func TestLeavesUnderSelectsTheNamespacesRecords(t *testing.T) {
	s := newPenneRecordStore()
	s.Put("u1", "c-friends.inv.subsTypes", []byte(`{"a":1}`))
	s.Put("u1", "c-friends", []byte(`{"b":2}`))
	s.Put("u1", "c-appearance.main", []byte(`{"c":3}`))
	s.Put("u2", "c-friends.someone-else", []byte(`{"d":4}`))

	got := s.LeavesUnder("u1", "c-friends")
	if len(got) != 2 {
		t.Fatalf("got %d leaves: %+v", len(got), got)
	}
	if got[0].Name != "c-friends" || got[1].Name != "c-friends.inv.subsTypes" {
		t.Fatalf("wrong or unsorted: %q %q", got[0].Name, got[1].Name)
	}
	for _, e := range got {
		if len(e.Digest) != 20 {
			t.Errorf("%s digest is %d bytes, want 20", e.Name, len(e.Digest))
		}
	}
	if n := len(s.LeavesUnder("u1", "c-settings")); n != 0 {
		t.Fatalf("a namespace we hold nothing under returned %d leaves", n)
	}
}
