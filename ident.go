package main

// What Penne asks the identity core (nx-baas /internal/identity, nx-common/nxapi).
//
// In nx-baas these were in-process reads of baas.json. Three things cross over:
//
//   - the frontline's ban check: a locked account gets no notification channel;
//   - the online-notification policy: whether a viewer wants an alert when a friend comes
//     online (the core keeps friend preferences);
//   - the presence a console publishes up its connection (DAPresence) and its lease
//     renewal, which belong to the core because presence is part of the friend graph.
//
// The first two degrade open when the core cannot be reached -- a console's push channel
// must not die because the core is restarting; a ban is enforced again on the next connect,
// and the core closes a banned user's connections itself (POST /internal/penne/users/{id}/close).
// Presence reports go through one ordered worker, so a slow core never holds up the
// frontline that decoded them.

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/openpak/nx-common/nxapi"

	"nx-penne/redact"
)

// identity is what Penne asks the core (nxapi.Client implements it; tests use a fake).
type identity interface {
	User(ctx context.Context, id string) (*nxapi.User, error)
	FriendPreference(ctx context.Context, viewer, friend string) (*nxapi.FriendPreference, error)
	Presence(ctx context.Context, p nxapi.Presence) error
	RenewPresence(ctx context.Context, userID, device string) error
}

// userLock is the account's ban state from the core, "" when it may connect or when the
// core cannot say.
func (s *server) userLock(ctx context.Context, userID string) string {
	if s.core == nil || userID == "" {
		return ""
	}
	u, err := s.core.User(ctx, userID)
	if err != nil {
		if !errors.Is(err, nxapi.ErrNotFound) {
			log.Printf("[nx-penne] identity: lock of %s unknown (%v); letting it connect", redact.Tag(userID), redact.Err(err))
		}
		return ""
	}
	return u.Lock
}

// onlineNotification is the viewer's alert preference for a friend; true when unknown,
// which is the core's own default.
func (s *server) onlineNotification(viewer, friend string) bool {
	if s.core == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p, err := s.core.FriendPreference(ctx, viewer, friend)
	if err != nil {
		if !errors.Is(err, nxapi.ErrNotFound) {
			log.Printf("[nx-penne] identity: preference %s/%s unknown (%v); allowing", redact.Tag(viewer), redact.Tag(friend), redact.Err(err))
		}
		return true
	}
	return p.OnlineNotification
}

// presenceJob is one report to the core: a published presence, or a lease renewal.
type presenceJob struct {
	p     nxapi.Presence
	renew bool
}

// reportPresence queues a presence for the core. A full queue means the core has been away
// for a long time; the report is dropped and said so, the console publishes again on change.
func (s *server) reportPresence(job presenceJob) {
	if s.presence == nil {
		return
	}
	select {
	case s.presence <- job:
	default:
		log.Printf("[nx-penne] presence queue full; dropped user=%s device=%s", redact.Tag(job.p.UserID), redact.Tag(job.p.Device))
	}
}

// presenceWorker delivers the queued reports in order.
func (s *server) presenceWorker() {
	for job := range s.presence {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var err error
		if job.renew {
			err = s.core.RenewPresence(ctx, job.p.UserID, job.p.Device)
		} else {
			err = s.core.Presence(ctx, job.p)
		}
		cancel()
		switch {
		case errors.Is(err, nxapi.ErrNotFound):
			log.Printf("[nx-penne] presence for unknown user %s; ignored by the core", redact.Tag(job.p.UserID))
		case err != nil:
			log.Printf("[nx-penne] presence for %s did not reach the core: %v", redact.Tag(job.p.UserID), redact.Err(err))
		}
	}
}

// renewDevicePresence keeps alive what a console has already published (penne_conn.go).
func (s *server) renewDevicePresence(userID, deviceID string) {
	if deviceID == "" {
		return
	}
	s.reportPresence(presenceJob{p: nxapi.Presence{UserID: userID, Device: deviceID}, renew: true})
}
