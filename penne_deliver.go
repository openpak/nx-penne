package main

// penne_deliver.go: the semantic notification submission contract this
// workstream publishes to A and C (coordination plan, "Semantic notification
// submission"). Callers describe WHAT changed and WHO receives it; this file
// owns the conversion to the native wire envelope, the policy revalidation
// before sending, and the persistence/idempotency outcome. It deliberately
// knows nothing about where events come from -- A feeds social/presence
// changes, C feeds invitations, the core poller stays A's.

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"slices"
	"sync"
	"time"

	"nx-penne/internal/penne"
)

// The five event type strings the 22.5.0 friends module's dispatcher
// recognizes (firmware-confirmed). Anything else is not a native event.
const (
	EventPresenceUpdated          = "presence_updated"
	EventFriendInvitationReceived = "friend_invitation_received"
	EventFriendRequestReceived    = "friend_request_received"
	EventFriendRequestAuthorized  = "friend_request_authorized"
	EventFriendDeleted            = "friend_deleted"
)

var eventKinds = map[string]bool{
	EventPresenceUpdated: true, EventFriendInvitationReceived: true,
	EventFriendRequestReceived: true, EventFriendRequestAuthorized: true,
	EventFriendDeleted: true,
}

// PennePolicy decides whether an event may be delivered to its recipient right
// now. A/C register checks (quiet settings, per-friend alert preference,
// privacy); the default is allow. A false return is a final "not now": the
// event stays in the outbox until expiry rather than being dropped, so a
// temporary policy (sleep mode) can still converge.
type PennePolicy func(d PenneDelivery, now time.Time) bool

type pennePolicyReg struct {
	name string
	fn   PennePolicy
}

type penneHub struct {
	mu       sync.Mutex
	policy   []pennePolicyReg
	sessions map[string][]*penneSession // BAAS user id -> live frontline sessions
}

// notifStore returns the durable penne state, creating in-memory versions on
// first use so zero-config runs and direct handler tests keep working. main()
// installs the persistent store before any request can arrive.
var penneWiring sync.Mutex

func (s *server) notifStore() *penneStore {
	penneWiring.Lock()
	defer penneWiring.Unlock()
	if s.penneState == nil {
		s.penneState = newPenneStore("")
	}
	if s.penneHub == nil {
		s.penneHub = newPenneHub()
		s.registerDefaultPennePolicies()
	}
	return s.penneState
}

// notifHub returns the live-session registry (notifStore ensures both exist).
func (s *server) notifHub() *penneHub {
	s.notifStore()
	return s.penneHub
}

// registerDefaultPennePolicies installs the delivery checks this deployment
// can make on its own. A and C add theirs on top; names deduplicate.
func (s *server) registerDefaultPennePolicies() {
	if s.core == nil {
		return
	}
	s.penneHub.RegisterPolicy("online-notification", func(d PenneDelivery, now time.Time) bool {
		// PRE-04: the per-friend online-alert preference gates the presence
		// alert only. A friend with alerts off still becomes current in the
		// list through the REST side; only the toast-worthy push is held.
		if d.Kind != EventPresenceUpdated {
			return true
		}
		friendID, _ := d.Payload["friendId"].(string)
		if friendID == "" {
			return true
		}
		// The preference is the core's (ident.go); an unknown viewer or an unreachable
		// core allows, as an absent preference always did.
		return s.onlineNotification(d.UserID, friendID)
	})
}

func newPenneHub() *penneHub {
	return &penneHub{sessions: map[string][]*penneSession{}}
}

// RegisterPolicy installs a named delivery check. Registered once per name.
func (h *penneHub) RegisterPolicy(name string, fn PennePolicy) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.policy {
		if p.name == name {
			p.fn = fn
			return
		}
	}
	h.policy = append(h.policy, pennePolicyReg{name, fn})
}

// allowed runs the policy chain. Failure is logged once per event (sanitized:
// recipient and kind only), because silent suppression would look identical to
// a dead connection from the outside.
func (h *penneHub) allowed(d PenneDelivery, now time.Time) bool {
	h.mu.Lock()
	chain := make([]pennePolicyReg, len(h.policy))
	copy(chain, h.policy)
	h.mu.Unlock()
	for _, p := range chain {
		if p.fn == nil {
			continue
		}
		if !p.fn(d, now) {
			log.Printf("[nx-baas] penne: policy %q holds %s for %s", p.name, d.Kind, d.UserID)
			return false
		}
	}
	return true
}

// SubmitNotification is the entry point A and C call. It persists durably
// before returning and only then wakes live connections. The returned outcome
// is the contract: Accepted means "persisted or already known"; the caller
// never has to retry a submission that returned Accepted.
func (s *server) SubmitNotification(d PenneDelivery) PenneSubmission {
	now := time.Now()
	if !eventKinds[d.Kind] {
		return PenneSubmission{Outcome: penneRejectUser} // not a native event; refuse loudly via outcome
	}
	// Whether the recipient is a user is the core's question, asked before it submits
	// (nx-baas penne_deliver.go); here a recipient is any non-empty BAAS user id.
	if d.UserID == "" {
		return PenneSubmission{Outcome: penneRejectUser}
	}
	if d.ID == "" {
		d.ID = "ev" + randHex(8)
	}
	res := s.notifStore().Submit(d, now)
	// Say it out loud. "Was this event ever queued?" was unanswerable from the
	// log twice in one evening of hardware testing, and the difference between
	// "never submitted" and "submitted and the console ignored it" is the
	// difference between two completely different bugs.
	log.Printf("[nx-baas] notify: %s for %s -> %s (id=%s)", d.Kind, d.UserID, res.Outcome, d.ID)
	if res.Accepted {
		s.penneWake(d.UserID)
	}
	return res
}

// NOTE (firmware, 2026-09-12): the steady state at RVA 0xdc9e0 accepts only
// PutRecord, DeleteRecord, Ack, Reset, Ping, Pong, Idle, Nack,
// SubscriptionList, SubscriptionUpdated and Hi — a MessageRequest carrier is
// answered with "Unexpected command ... received in steady state" and the
// connection fails. A notification is a kind-1 message carried inside a
// PutRecord (docs/penne-record-shape-2026-09-16.md §2). This body is still the
// right JSON; what carries it is not.
//
// penneEventJSON renders the event body carried inside a wire envelope: the
// firmware-recognized type string plus the semantic payload. The envelope's
// outer shape is the marked hypothesis in internal/penne; this JSON shape is
// what the friends module's event parser is known to read a "type" field from.
func penneEventJSON(d PenneDelivery) string {
	body := map[string]any{
		"type": d.Kind,
		"id":   d.ID,
	}
	for k, v := range d.Payload {
		if k != "type" && k != "id" {
			body[k] = v
		}
	}
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Sprintf(`{"type":%q,"id":%q}`, d.Kind, d.ID)
	}
	return string(b)
}

// ---------- live-session registry (connection fan-out) ----------

// penneAttach registers a live frontline session for fan-out.
func (h *penneHub) attach(sess *penneSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessions[sess.user] = append(h.sessions[sess.user], sess)
}

// penneDetach removes a closing session.
func (h *penneHub) detach(sess *penneSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	live := h.sessions[sess.user][:0]
	for _, x := range h.sessions[sess.user] {
		if x != sess {
			live = append(live, x)
		}
	}
	if len(live) == 0 {
		delete(h.sessions, sess.user)
	} else {
		h.sessions[sess.user] = live
	}
}

// penneWake pushes due deliveries for a user to their live connections; with
// no connection live, the outbox holds the work for reconciliation on connect.
func (s *server) penneWake(userID string) {
	now := time.Now()
	due := s.notifStore().ClaimDue(userID, "", now, 64)
	if len(due) == 0 {
		return
	}
	regs := s.notifStore().RegistrationsFor(userID)
	h := s.notifHub()
	h.mu.Lock()
	// The user's own connections, and every connection of a console that
	// holds one of the user's profiles: one console, one connection, filed
	// under the user it was registered for.
	sessions := append([]*penneSession(nil), h.sessions[userID]...)
	for u, list := range h.sessions {
		if u == userID {
			continue
		}
		for _, sess := range list {
			if slices.Contains(regs, sess.penneID) {
				sessions = append(sessions, sess)
			}
		}
	}
	if len(sessions) == 0 {
		// The commonest reason nothing arrives, and it used to be invisible:
		// the work is claimed and there is nobody to hand it to. It stays
		// queued for the next connection.
		log.Printf("[nx-baas] notify: %d delivery(ies) for %s have no live connection; still queued", len(due), userID)
	}
	h.mu.Unlock()
	for _, sess := range sessions {
		for _, e := range due {
			if e.DeviceID != "" && e.DeviceID != sess.device {
				continue
			}
			// Recipient revalidation happens here, at dispatch: policy checks
			// (quiet settings, per-friend alert preference, privacy) run
			// against the delivery as it is about to go out, not only when it
			// was submitted. A held event stays queued until expiry.
			if !h.allowed(PenneDelivery{ID: e.ID, UserID: e.UserID, Kind: e.Kind, Payload: e.Payload}, now) {
				continue
			}
			if penneSendEvents {
				// The pipeline's own tests drive the old MessageRequest
				// carrier; a console never sees it (penneSendEvents).
				sess.offer(e.ID, penneEventFrame(e))
				continue
			}
			// A notification is a kind-1 message inside a PutRecord, routed
			// by its Meta to the recipient's console account
			// (docs/penne-record-shape-2026-09-16.md).
			log.Printf("[nx-baas] notify: writing %s to the wire for %s (id=%s, device=%q)", e.Kind, e.UserID, e.ID, sess.device)
			for _, frame := range s.penneMessageFrames(e) {
				sess.offer(e.ID, frame)
			}
		}
	}
}

// penneSendEvents gates delivery on the old MessageRequest carrier. It is off
// everywhere but the pipeline's own tests: a console in the steady state drops
// the connection when it receives a type it does not accept, and MessageRequest
// is one of those. It goes away when deliveries become records.
var penneSendEvents = false

// penneMessageFrames renders one queued delivery as the frames to put on the
// wire: a kind-1 message inside a PutRecord, one per console account the
// recipient is known by (docs/penne-record-shape-2026-09-16.md).
//
// The record write we used to send here was the wrong shape twice over. Our
// PutRecord payload was {name, value} where the parser reads a vector of
// entries -- it aborted on slot 0 and the console opened a fresh connection
// after every write -- and `c-friends.inv.subsTypes` is a record the console
// *writes*, not one it listens to, so even a well-formed store would have
// changed nothing. A notification is a message, routed by Meta.
func (s *server) penneMessageFrames(e *penneOutRec) [][]byte {
	body := penneEventJSON(PenneDelivery{
		ID: e.ID, UserID: e.UserID, Kind: e.Kind, Payload: e.Payload,
	})
	accounts := s.notifStore().AccountsFor(e.UserID)
	if len(accounts) == 0 {
		// Addressed to nobody: the friends module drops an event whose uid is
		// zero, so this will not land. It still goes out, because a frame on
		// the wire is visible in a capture and a silent drop is not.
		log.Printf("[nx-baas] notify: no console account id known for %s; sending %s unaddressed", e.UserID, e.Kind)
		accounts = []string{""}
	}
	now := uint64(time.Now().Unix())
	frames := make([][]byte, 0, len(accounts))
	for _, account := range accounts {
		m := penne.Message{
			Name:      e.Kind,
			Type:      1,
			Receivers: penneReceiverToken,
			AccountID: account,
			Body:      body,
		}
		if m.TooLong() {
			log.Printf("[nx-baas] notify: %s for %s exceeds the parser's bounds; dropped", e.Kind, e.UserID)
			continue
		}
		frames = append(frames, penne.BuildMessage(m, now, now+penneSyncTTL))
	}
	return frames
}

// penneReceiverToken is Meta.f1, the routing token npns matches against its IPC
// clients' listen keys. The friends module registers its own program id as that
// key -- its init calls the u64 Listen with 0x010000000000000e and starts the
// nn.friends.EventWatcher thread only if the call succeeds [firmware,
// FUN_001a0d20 at 0x17bd38] -- so this is the address, not a guess
// (docs/penne-record-shape-2026-09-16.md §3, open question N5).
//
// NX_PENNE_RECEIVER overrides it without a rebuild, which is worth keeping for
// the reachability question the static read cannot settle: whether npns routes
// our message to that key at all. Note if you use it to probe: unmatched
// messages park on a seven-deep queue and the oldest is evicted, so probe in
// batches under seven.
var penneReceiverToken = func() string {
	if v := os.Getenv("NX_PENNE_RECEIVER"); v != "" {
		return v
	}
	return "0x010000000000000e"
}()

// penneEventFrame converts a queued delivery into its wire frame. The carrier
// slot and payload field are the marked hypotheses (docs/penne-protocol.md);
// the frame is well-formed either way, and a runtime capture is what upgrades
// this from best evidence to confirmed interop.
func penneEventFrame(e *penneOutRec) []byte {
	return penne.BuildEvent(penneEventJSON(PenneDelivery{
		ID: e.ID, UserID: e.UserID, Kind: e.Kind, Payload: e.Payload,
	}))
}
