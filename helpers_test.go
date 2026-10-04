package main

// A stand-in for the identity core (nx-baas /internal/identity). The Penne tests are
// nx-baas's, kept as close to the originals as the seam allows: where they created users in
// baas.json they now create them here, and where they read presence back out of baas.json
// they read what reached the core.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openpak/nx-common/nxapi"
)

type fakeCore struct {
	mu       sync.Mutex
	users    map[string]*nxapi.User
	prefs    map[[2]string]bool
	presence []nxapi.Presence
	renewals []nxapi.PresenceRenewal
	down     bool
}

func mustStore(t *testing.T) *fakeCore {
	t.Helper()
	return &fakeCore{users: map[string]*nxapi.User{}, prefs: map[[2]string]bool{}}
}

func testCore(s *server) *fakeCore { return s.core.(*fakeCore) }

// NewUser mirrors nx-baas's Store.NewUser closely enough for these tests: a fresh id.
func (c *fakeCore) NewUser() (*nxapi.User, struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	u := &nxapi.User{ID: randHex(8)}
	c.users[u.ID] = u
	return u, struct{}{}
}

func (c *fakeCore) setOnlineNotification(viewer, friend string, on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prefs[[2]string{viewer, friend}] = on
}

func (c *fakeCore) lock(userID, lock string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.users[userID].Lock = lock
}

func (c *fakeCore) User(_ context.Context, id string) (*nxapi.User, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down {
		return nil, errCoreDown
	}
	if u := c.users[id]; u != nil {
		cp := *u
		return &cp, nil
	}
	return nil, nxapi.ErrNotFound
}

func (c *fakeCore) FriendPreference(_ context.Context, viewer, friend string) (*nxapi.FriendPreference, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down {
		return nil, errCoreDown
	}
	if c.users[viewer] == nil {
		return nil, nxapi.ErrNotFound
	}
	on, ok := c.prefs[[2]string{viewer, friend}]
	return &nxapi.FriendPreference{OnlineNotification: !ok || on}, nil
}

func (c *fakeCore) Presence(_ context.Context, p nxapi.Presence) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down {
		return errCoreDown
	}
	if c.users[p.UserID] == nil {
		return nxapi.ErrNotFound
	}
	c.presence = append(c.presence, p)
	return nil
}

func (c *fakeCore) RenewPresence(_ context.Context, userID, device string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down {
		return errCoreDown
	}
	c.renewals = append(c.renewals, nxapi.PresenceRenewal{UserID: userID, Device: device})
	return nil
}

type coreDownErr struct{}

func (coreDownErr) Error() string { return "fake core: connection refused" }

var errCoreDown error = coreDownErr{}

// withPresenceWorker gives s the ordered presence queue main() starts.
func withPresenceWorker(s *server) {
	s.presence = make(chan presenceJob, 64)
	go s.presenceWorker()
}

// eventually polls cond for up to two seconds: presence reaches the core asynchronously.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}
