// The record store the sync answers from.
//
// The console keeps four record namespaces per account — c-appearance,
// c-friends, c-settings, c-storage — and opens every connection by offering a
// SHA-1 digest of each (RootHash). This holds what THIS server has written
// under them, so a LeafHash reply can answer truthfully about records we own
// instead of mirroring the console's digests back at it
// (docs/penne-protocol.md §4d, §4e).
//
// It is no longer the delivery path: a notification turned out to be a kind-1
// message routed by its Meta, not a record write
// (docs/penne-record-shape-2026-09-16.md). Nothing writes here today; the
// store stays because the leaf half of the sync reads it.
package main

import (
	"crypto/sha1"
	"nx-penne/internal/penne"
	"sort"
	"strings"
	"sync"
)

// penneRecordStore holds what this server has written, per account. It is
// deliberately not a mirror of the console's own store: the console is
// authoritative for everything we have never written, and a sync answers with
// the console's own digest for those.
type penneRecordStore struct {
	mu   sync.Mutex
	byID map[string]map[string][]byte // user id -> record name -> value
}

func newPenneRecordStore() *penneRecordStore {
	return &penneRecordStore{byID: map[string]map[string][]byte{}}
}

// Put remembers the value written to one of an account's records.
func (s *penneRecordStore) Put(userID, name string, value []byte) {
	if userID == "" || name == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID[userID] == nil {
		s.byID[userID] = map[string][]byte{}
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	s.byID[userID][name] = cp
}

// Digest is the SHA-1 of a record we have written, and whether we have one.
// The console's RootHash carries twenty bytes per name, which is the width of
// a SHA-1 [runtime capture].
func (s *penneRecordStore) Digest(userID, name string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.byID[userID][name]
	if !ok {
		return nil, false
	}
	sum := sha1.Sum(value)
	return sum[:], true
}

// LeavesUnder lists the records this server holds under a namespace, with their
// digests, in a stable order. A record is named for a topic and a topic is a
// dotted path under a namespace, so "c-friends" owns "c-friends.inv.subsTypes"
// -- and a record whose name IS the namespace counts as its own leaf.
func (s *penneRecordStore) LeavesUnder(userID, namespace string) []penne.RootEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []penne.RootEntry{}
	for name, value := range s.byID[userID] {
		if name != namespace && !strings.HasPrefix(name, namespace+".") {
			continue
		}
		sum := sha1.Sum(value)
		out = append(out, penne.RootEntry{Name: name, Digest: sum[:]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// records is the process-wide store; one per server, created on first use so a
// zero-value server (the tests') works without setup.
func (s *server) records() *penneRecordStore {
	s.recordsOnce.Do(func() { s.recordStore = newPenneRecordStore() })
	return s.recordStore
}
