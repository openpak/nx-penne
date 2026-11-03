package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testDSN is a scratch database for the persistence tests (NX_PENNE_TEST_DATABASE_URL); the
// state table is emptied first. Unset skips, unless NX_PENNE_TEST_REQUIRE_DB is set.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("NX_PENNE_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("NX_PENNE_TEST_REQUIRE_DB") != "" {
			t.Fatal("NX_PENNE_TEST_DATABASE_URL is required")
		}
		t.Skip("NX_PENNE_TEST_DATABASE_URL not set")
	}
	s, err := connectPenneStore(context.Background(), dsn, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pg.Exec(context.Background(), `DELETE FROM penne_state`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	return dsn
}

func testPenneStore(t *testing.T, dsn, legacy string) *penneStore {
	t.Helper()
	s, err := connectPenneStore(context.Background(), dsn, legacy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// The old penne.json is imported once, only into an empty database, and left in place.
func TestLegacyFileImportedOnceAndKept(t *testing.T) {
	dsn := testDSN(t)
	legacy := filepath.Join(t.TempDir(), "penne.json")
	id, pw := func() (string, string) {
		old := newPenneStore()
		id, pw := old.Register("dev1", "user1", "", time.Now())
		b, _ := json.Marshal(old.d)
		os.WriteFile(legacy, b, 0o600)
		return id, pw
	}()
	a := testPenneStore(t, dsn, legacy)
	if _, err := a.CheckAssoc(id, pw, time.Now()); err != nil {
		t.Fatalf("imported registration does not verify: %v", err)
	}
	a.Register("dev2", "user2", "", time.Now())
	b := testPenneStore(t, dsn, legacy) // second start: must keep dev2, not re-import
	if b.AssocForDevice("dev2") == nil || b.AssocForDevice("dev1") == nil {
		t.Fatal("a restart lost or re-imported state")
	}
	if len(b.d.Assocs) != 2 {
		t.Fatalf("assocs = %d, want 2", len(b.d.Assocs))
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatal("legacy file was removed")
	}
}
