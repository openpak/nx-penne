package main

// penne_store.go: durable state for the Penne notification channel (NTF-01,
// NTF-05). Everything the push channel used to answer from thin air -- penne
// ids, notification tokens, login tickets, account/device links, subscriptions
// and the delivery outbox -- lives in one JSON file next to the BAAS store so a
// backend restart keeps the associations a console still holds credentials for.
//
// File-per-mutation persistence with a mutex, matching the repo's Store style:
// writes are rare (registration, linking, events), reads are hot.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"nx-penne/redact"
)

// ---------- records ----------

// penneAssoc is a console's push identity: the penne id + password a Penne
// registration minted, bound to the BAAS user and device it was created for.
// A supplied id never authorizes anything by itself; the password (and the
// device/account binding) do.
type penneAssoc struct {
	AccountIDs   []string `json:"account_ids,omitempty"` // console account ids seen for this registration
	ID           string   `json:"id"`
	PasswordHash string   `json:"password_hash"` // sha256 hex of the minted password
	UserID       string   `json:"user_id"`       // BAAS user id ("" until linked)
	DeviceID     string   `json:"device_id"`     // console device id from its own report
	NsaID        string   `json:"nsa_id"`        // Nintendo Account id, when the link carried one
	CreatedAt    int64    `json:"created_at"`
	RevokedAt    int64    `json:"revoked_at,omitempty"`
}

// penneTokenRec is a notification token handed out against a registration.
type penneTokenRec struct {
	Token    string `json:"token"`
	PenneID  string `json:"penne_id"`
	UserID   string `json:"user_id"`
	DeviceID string `json:"device_id"`
	// AccountID is the console profile (nn::account::Uid) the token was
	// minted for: /v1/accounts/<uid>/notification_tokens.
	AccountID string `json:"account_id,omitempty"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	RevokedAt int64  `json:"revoked_at,omitempty"`
}

// penneTicketRec is a frontline login ticket: what the persistent connection
// authenticates with. Bound to account, device and penne id; expiry and
// revocation are enforced on every connection attempt.
type penneTicketRec struct {
	TicketHash string `json:"ticket_hash"` // sha256 hex: the file must not carry live credentials
	PenneID    string `json:"penne_id"`
	UserID     string `json:"user_id"`
	DeviceID   string `json:"device_id"`
	IssuedAt   int64  `json:"issued_at"`
	ExpiresAt  int64  `json:"expires_at"`
	RevokedAt  int64  `json:"revoked_at,omitempty"`
}

// penneSubRec is a topic subscription a console made over the frontline
// connection. The topic is the 16-hex id the SubscribeTopic builder formats
// from a u64; for this deployment the account's own topic is its BAAS user id.
type penneSubRec struct {
	Topic     string `json:"topic"`
	DeviceID  string `json:"device_id"`
	CreatedAt int64  `json:"created_at"`
}

// pennePushChan is the push-channel registration BAAS used to echo and forget.
// It is the association the audit flagged as lost: user + device account +
// service + device token.
type pennePushChan struct {
	UserID     string `json:"user_id"`
	DeviceAcct string `json:"device_account_id"`
	Service    string `json:"service"`
	DeviceTok  string `json:"device_token"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
}

// penneOutRec is one delivery waiting for (or already through) a connection.
type penneOutRec struct {
	ID        string         `json:"id"` // stable dedup identity
	UserID    string         `json:"user_id"`
	DeviceID  string         `json:"device_id,omitempty"` // "" = every device of the account
	Kind      string         `json:"kind"`                // firmware event type string
	Payload   map[string]any `json:"payload"`
	CreatedAt int64          `json:"created_at"`
	ExpiresAt int64          `json:"expires_at"`
	Attempts  int            `json:"attempts"`
	NextAt    int64          `json:"next_attempt_at"`
	LastError string         `json:"last_error,omitempty"`
}

// Outcomes of a submission, in the semantic-delivery contract.
type penneOutcome string

const (
	pennePersisted    penneOutcome = "persisted"
	penneDuplicate    penneOutcome = "duplicate"
	penneRejectFull   penneOutcome = "rejected_queue_full"
	penneRejectUser   penneOutcome = "rejected_unknown_recipient"
	penneRejectExpiry penneOutcome = "rejected_expired"
)

// ---------- store ----------

type penneData struct {
	Assocs       map[string]*penneAssoc `json:"associations"`  // penne id -> assoc
	ByDevice     map[string]string      `json:"by_device"`     // device id -> newest penne id
	ByUser       map[string]string      `json:"by_user"`       // BAAS user id -> newest penne id
	ConsoleUsers map[string]string      `json:"console_users"` // device certificate -> BAAS user id
	AccountUsers map[string]string      `json:"account_users"` // console account id (128-bit) -> BAAS user id
	// AccountProven marks the mappings a request proved, as opposed to the
	// device-token guess: an event goes only to a proven profile when one
	// exists, because a frame addressed to the wrong profile is dropped by
	// the console and costs one of its seven undelivered slots.
	AccountProven map[string]bool `json:"account_proven,omitempty"`
	// SyncProbe counts the sync answers tried while NX_PENNE_SYNC_PROBE is
	// set. It is durable because the rotation is worthless if a deploy sends
	// it back to the first candidate every time.
	SyncProbe    uint64                      `json:"sync_probe,omitempty"`
	Tokens       map[string]*penneTokenRec   `json:"tokens"`        // token -> record
	Tickets      map[string]*penneTicketRec  `json:"tickets"`       // ticket hash -> record
	Subs         map[string][]*penneSubRec   `json:"subscriptions"` // user id -> subs
	PushChannels map[string]*pennePushChan   `json:"push_channels"` // user/service -> record
	Outbox       map[string][]*penneOutRec   `json:"outbox"`        // user id -> queue
	Delivered    map[string]map[string]int64 `json:"delivered"`     // user id -> event id -> time (retention window)
}

// penneStore is the durable Penne state. path == "" keeps everything in memory
// (tests and direct-handler use); main() supplies the deployment path.
type penneStore struct {
	mu   sync.Mutex
	path string
	d    *penneData

	// Sanitized counters for the ops surface (PRD §6); never payloads.
	// Atomic: bumped on request paths, read by Snapshot, all lock-free.
	framesIn, framesOut    atomic.Uint64
	malformed, unknownType atomic.Uint64
	delivered, retried     atomic.Uint64
	dropped                atomic.Uint64
}

func newPenneStore(path string) *penneStore {
	s := &penneStore{path: path, d: &penneData{
		Assocs: map[string]*penneAssoc{}, ByDevice: map[string]string{}, ByUser: map[string]string{},
		ConsoleUsers: map[string]string{}, AccountUsers: map[string]string{},
		AccountProven: map[string]bool{},
		Tokens:        map[string]*penneTokenRec{}, Tickets: map[string]*penneTicketRec{},
		Subs: map[string][]*penneSubRec{}, PushChannels: map[string]*pennePushChan{},
		Outbox: map[string][]*penneOutRec{}, Delivered: map[string]map[string]int64{},
	}}
	if path == "" {
		return s
	}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, s.d); err != nil {
			log.Printf("[nx-penne] penne store %s unreadable (%v); starting empty", path, redact.Err(err))
			return s
		}
		// Records predating a schema change can lack the maps.
		if s.d.Assocs == nil {
			s.d.Assocs = map[string]*penneAssoc{}
		}
		if s.d.ByDevice == nil {
			s.d.ByDevice = map[string]string{}
		}
		if s.d.ConsoleUsers == nil {
			s.d.ConsoleUsers = map[string]string{}
		}
		if s.d.AccountUsers == nil {
			s.d.AccountUsers = map[string]string{}
		}
		if s.d.AccountProven == nil {
			s.d.AccountProven = map[string]bool{}
		}
		if s.d.ByUser == nil {
			s.d.ByUser = map[string]string{}
		}
		if s.d.Tokens == nil {
			s.d.Tokens = map[string]*penneTokenRec{}
		}
		if s.d.Tickets == nil {
			s.d.Tickets = map[string]*penneTicketRec{}
		}
		if s.d.Subs == nil {
			s.d.Subs = map[string][]*penneSubRec{}
		}
		if s.d.PushChannels == nil {
			s.d.PushChannels = map[string]*pennePushChan{}
		}
		if s.d.Outbox == nil {
			s.d.Outbox = map[string][]*penneOutRec{}
		}
		if s.d.Delivered == nil {
			s.d.Delivered = map[string]map[string]int64{}
		}
	}
	return s
}

func (s *penneStore) saveLocked() {
	if s.path == "" {
		return
	}
	b, err := json.Marshal(s.d)
	if err != nil {
		log.Printf("[nx-penne] penne store: marshal: %v", redact.Err(err))
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("[nx-penne] penne store: write: %v", redact.Err(err))
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		log.Printf("[nx-penne] penne store: rename: %v", redact.Err(err))
	}
}

func hashCred(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// ---------- registration (NTF-01) ----------

// Register mints a fresh penne id + password bound to a device (and account,
// once linked). A client-supplied id is never adopted: possession of an id
// authorizes nothing, only a minted pair does. Re-registration of the same
// device leaves the old pair alone (consoles re-bootstrap with fresh ids; the
// old one stays valid until revoked or expired).
func (s *penneStore) Register(deviceID, userID, nsaID string, now time.Time) (id, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = "p" + randHex(16)
	password = randHex(16)
	s.d.Assocs[id] = &penneAssoc{
		ID: id, PasswordHash: hashCred(password),
		UserID: userID, DeviceID: deviceID, NsaID: nsaID,
		CreatedAt: now.Unix(),
	}
	if deviceID != "" {
		s.d.ByDevice[deviceID] = id
	}
	if userID != "" {
		s.d.ByUser[userID] = id
	}
	s.saveLocked()
	return id, password
}

// NoteAccount records a console account id the console itself put in a Penne
// path, against the registration it authenticated with — and against a BAAS
// account when the same request proved one. The friends module drops any event
// that does not arrive addressed to one of these ids [firmware: the dispatched
// handlers return unless the 128-bit id is non-zero], so this is the address
// deliveries need, and it is recorded rather than derived: several accounts
// share one console, and guessing which is which loses events.
func (s *penneStore) NoteAccount(assocID, accountID, userID string) {
	if assocID == "" || accountID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.d.Assocs[assocID]
	if a == nil {
		return
	}
	changed := false
	if !slices.Contains(a.AccountIDs, accountID) {
		a.AccountIDs = append(a.AccountIDs, accountID)
		changed = true
	}
	// Only a first guess: the device token here names the console, not the
	// profile, so this is whoever signed in last. BindAccount corrects it.
	if userID != "" && s.d.AccountUsers[accountID] == "" {
		s.d.AccountUsers[accountID] = userID
		changed = true
	}
	if changed {
		s.saveLocked()
	}
}

// BindAccount records which BAAS user a console profile belongs to, from a
// request that proves it: the olsc upload of the profile's notification token
// carries that user's own token, and /links carries its id token. Two profiles
// on one console were both mapped to whoever signed in last, so one of them
// never received a notification (2026-09-19,
// docs/switch/friends-notifications-firmware-2026-09-19.md §1).
func (s *penneStore) BindAccount(accountID, userID string) bool {
	if accountID == "" || userID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	was, proven := s.d.AccountUsers[accountID], s.d.AccountProven[accountID]
	s.d.AccountUsers[accountID] = userID
	s.d.AccountProven[accountID] = true
	s.saveLocked()
	return was != userID || !proven
}

// TokenAccount is the console profile a notification token was minted for.
func (s *penneStore) TokenAccount(tok string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.d.Tokens[tok]; t != nil {
		return t.AccountID
	}
	return ""
}

// RegistrationsFor lists the console registrations holding a profile that
// belongs to this user. One console connection carries every profile on it,
// and the connection is filed under whoever it was registered for.
func (s *penneStore) RegistrationsFor(userID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for id, a := range s.d.Assocs {
		for _, acct := range a.AccountIDs {
			if s.d.AccountUsers[acct] == userID {
				out = append(out, id)
				break
			}
		}
	}
	return out
}

// UsersOn lists the users whose profiles sit on this registration.
func (s *penneStore) UsersOn(penneID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.d.Assocs[penneID]
	if a == nil {
		return nil
	}
	var out []string
	for _, acct := range a.AccountIDs {
		if u := s.d.AccountUsers[acct]; u != "" && !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	return out
}

// AccountsFor lists the console account ids an event for this BAAS account can
// be addressed to. Empty means we have not been shown one yet.
func (s *penneStore) AccountsFor(userID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out, guesses := []string{}, []string{}
	for account, user := range s.d.AccountUsers {
		if user != userID {
			continue
		}
		if s.d.AccountProven[account] {
			out = append(out, account)
		} else {
			guesses = append(guesses, account)
		}
	}
	if len(out) > 0 {
		return out
	}
	return guesses
}

// NextSyncProbe returns the next probe attempt number and remembers it.
func (s *penneStore) NextSyncProbe() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.SyncProbe++
	s.saveLocked()
	return s.d.SyncProbe
}

// BindConsole records which account signed in on a console, keyed by the
// device certificate. Penne only ever sees the console's device token — its
// subject is the certificate, never the account — so without this the
// registration is bound to something the outbox is not keyed by, and a
// connected console is told there is nothing for it while its events expire.
// Registrations and tickets minted before the account was known are healed.
// Account addresses recorded under the certificate are healed too — including
// on a login where the console was already bound, which is the ordinary case
// for a console that has been signed in for days.
func (s *penneStore) BindConsole(certID, userID string) {
	if certID == "" || userID == "" || certID == userID {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	if s.d.ConsoleUsers[certID] != userID {
		s.d.ConsoleUsers[certID] = userID
		changed = true
		for _, a := range s.d.Assocs {
			if a.UserID == certID {
				a.UserID = userID
				s.d.ByUser[userID] = a.ID
			}
		}
		for _, t := range s.d.Tickets {
			if t.UserID == certID {
				t.UserID = userID
			}
		}
	}
	for account, u := range s.d.AccountUsers {
		if u == certID {
			s.d.AccountUsers[account] = userID
			changed = true
		}
	}
	if changed {
		s.saveLocked()
	}
}

// ConsoleAssoc is the penne id of the console a device certificate names: registrations
// are keyed by the user they were made for, which is the certificate itself until a profile
// binds it, then the BAAS user it resolved to.
func (s *penneStore) ConsoleAssoc(cert string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range []string{cert, s.d.ConsoleUsers[cert]} {
		if id := s.d.ByUser[k]; k != "" && id != "" {
			return id
		}
	}
	return s.d.ByDevice[cert]
}

// ResolveUser maps a device certificate onto the account signed in on it, and
// leaves a real account id alone.
func (s *penneStore) ResolveUser(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.d.ConsoleUsers[id]; u != "" {
		return u
	}
	return id
}

// Adopt takes a credential pair the console already holds and makes it real,
// but only when the id is unknown here and the caller proved an account with a
// BAAS token: the id names the registration, the token authorizes it. Consoles
// registered against the permissive build carry ids this store never minted,
// and without this they retry a 401 forever instead of re-registering.
func (s *penneStore) Adopt(id, password, deviceID, userID string, now time.Time) (*penneAssoc, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" || password == "" || userID == "" || s.d.Assocs[id] != nil {
		return nil, false
	}
	a := &penneAssoc{
		ID: id, PasswordHash: hashCred(password),
		UserID: userID, DeviceID: deviceID,
		CreatedAt: now.Unix(),
	}
	s.d.Assocs[id] = a
	if deviceID != "" {
		s.d.ByDevice[deviceID] = id
	}
	s.d.ByUser[userID] = id
	s.saveLocked()
	cp := *a
	return &cp, true
}

// KnowsAssoc says whether this store ever minted an id, without saying
// anything about its password. Registration needs the distinction that
// CheckAssoc deliberately hides: an id we never minted is not an attacker, it
// is a console carrying credentials from somewhere else, and answering it with
// a denial locks it out of notifications for good.
func (s *penneStore) KnowsAssoc(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.Assocs[id] != nil
}

// AssocIfLive returns a registration by id when it exists and has not been
// revoked, for the routes where the console names its registration without a
// password. It says nothing about credentials — the caller must already have
// authenticated the request some other way.
func (s *penneStore) AssocIfLive(id string) *penneAssoc {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.d.Assocs[id]
	if a == nil || a.RevokedAt != 0 {
		return nil
	}
	cp := *a
	return &cp
}

// CheckAssoc verifies a penne id + password pair. A wrong password, unknown id
// or revoked registration is an error naming nothing an attacker can use.
func (s *penneStore) CheckAssoc(id, password string, now time.Time) (*penneAssoc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkAssocLocked(id, password, now)
}

func (s *penneStore) checkAssocLocked(id, password string, now time.Time) (*penneAssoc, error) {
	a := s.d.Assocs[id]
	if a == nil || subtle.ConstantTimeCompare([]byte(a.PasswordHash), []byte(hashCred(password))) != 1 {
		return nil, errors.New("unknown penne credentials")
	}
	if a.RevokedAt != 0 {
		return nil, errors.New("penne registration revoked")
	}
	return a, nil
}

// Revoke kills a registration and everything minted under it: tokens and
// tickets stop working on the next check, and live connections refuse their
// next dispatch (expiry/revocation, NTF-01).
func (s *penneStore) Revoke(id string, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.d.Assocs[id]
	if a == nil {
		return 0
	}
	a.RevokedAt = now.Unix()
	n := 0
	for _, t := range s.d.Tokens {
		if t.PenneID == id && t.RevokedAt == 0 {
			t.RevokedAt = now.Unix()
			n++
		}
	}
	for _, tk := range s.d.Tickets {
		if tk.PenneID == id && tk.RevokedAt == 0 {
			tk.RevokedAt = now.Unix()
			n++
		}
	}
	s.saveLocked()
	return n
}

// RevokeDevice revokes on logout/device unlink: everything minted for a device
// dies with it.
func (s *penneStore) RevokeDevice(deviceID string, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, t := range s.d.Tokens {
		if t.DeviceID == deviceID && t.RevokedAt == 0 {
			t.RevokedAt = now.Unix()
			n++
		}
	}
	for _, tk := range s.d.Tickets {
		if tk.DeviceID == deviceID && tk.RevokedAt == 0 {
			tk.RevokedAt = now.Unix()
			n++
		}
	}
	s.saveLocked()
	return n
}

// NotificationToken mints a token for an authenticated registration. The
// registration's own id+password authorize the mint; the token inherits the
// binding so a leaked token cannot outlive its registration.
func (s *penneStore) NotificationToken(id, password, userID, deviceID string, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.checkAssocLocked(id, password, now); err != nil {
		return "", err
	}
	tok := randHex(18)
	s.d.Tokens[tok] = &penneTokenRec{
		Token: tok, PenneID: id, UserID: userID, DeviceID: deviceID,
		CreatedAt: now.Unix(), ExpiresAt: now.Add(90 * 24 * time.Hour).Unix(),
	}
	s.saveLocked()
	return tok, nil
}

// NotificationTokenFor mints a token for an association already authenticated
// by binding (bearer account or device), not by password.
func (s *penneStore) NotificationTokenFor(a *penneAssoc, accountID string, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.Assocs[a.ID] == nil || s.d.Assocs[a.ID].RevokedAt != 0 {
		return "", errors.New("penne registration revoked")
	}
	tok := randHex(18)
	s.d.Tokens[tok] = &penneTokenRec{
		Token: tok, PenneID: a.ID, UserID: a.UserID, DeviceID: a.DeviceID, AccountID: accountID,
		CreatedAt: now.Unix(), ExpiresAt: now.Add(90 * 24 * time.Hour).Unix(),
	}
	s.saveLocked()
	return tok, nil
}

// IssueTicketFor mints a frontline ticket for an association already
// authenticated by binding; see IssueTicket for the credential path.
func (s *penneStore) IssueTicketFor(a *penneAssoc, now time.Time, ttl time.Duration) (*penneTicketRec, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.Assocs[a.ID] == nil || s.d.Assocs[a.ID].RevokedAt != 0 {
		return nil, "", errors.New("penne registration revoked")
	}
	ticket := randHex(32)
	rec := &penneTicketRec{
		TicketHash: hashCred(ticket), PenneID: a.ID,
		UserID: a.UserID, DeviceID: a.DeviceID,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(),
	}
	s.d.Tickets[rec.TicketHash] = rec
	s.saveLocked()
	return rec, ticket, nil
}

// IssueTicket mints a frontline login ticket for an authenticated registration.
// The ticket is bound to the registration's account and device: presenting it
// from another device is a denial, not a warning.
func (s *penneStore) IssueTicket(id, password string, now time.Time, ttl time.Duration) (*penneTicketRec, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.checkAssocLocked(id, password, now)
	if err != nil {
		return nil, "", err
	}
	ticket := randHex(32)
	rec := &penneTicketRec{
		TicketHash: hashCred(ticket), PenneID: id,
		UserID: a.UserID, DeviceID: a.DeviceID,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(),
	}
	s.d.Tickets[rec.TicketHash] = rec
	s.saveLocked()
	return rec, ticket, nil
}

var (
	errTicketUnknown = errors.New("penne ticket unknown")
	errTicketExpired = errors.New("penne ticket expired")
	errTicketRevoked = errors.New("penne ticket revoked")
	errTicketDevice  = errors.New("penne ticket bound to another device")
	errTicketNoUser  = errors.New("penne ticket is not linked to an account")
)

// ValidateTicket checks a presented frontline ticket. deviceID may be "" when
// the request carries no device identity; a non-empty mismatch is a denial.
func (s *penneStore) ValidateTicket(ticket, deviceID string, now time.Time) (*penneTicketRec, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.d.Tickets[hashCred(ticket)]
	if rec == nil {
		return nil, errTicketUnknown
	}
	if rec.RevokedAt != 0 {
		return nil, errTicketRevoked
	}
	if now.Unix() >= rec.ExpiresAt {
		return nil, errTicketExpired
	}
	if deviceID != "" && rec.DeviceID != "" && deviceID != rec.DeviceID {
		return nil, errTicketDevice
	}
	if rec.UserID == "" {
		return nil, errTicketNoUser
	}
	return rec, nil
}

// AssocByID returns a registration record by penne id (no credential check).
func (s *penneStore) AssocByID(id string) *penneAssoc {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.d.Assocs[id]; a != nil {
		cp := *a
		return &cp
	}
	return nil
}

// AssocIDForUser names the newest registration bound to an account.
func (s *penneStore) AssocIDForUser(userID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.ByUser[userID]
}

// AssocForDevice answers "which registration did this console mint" for
// surfaces that authenticate by device (delete-account cleanup, tests).
func (s *penneStore) AssocForDevice(deviceID string) *penneAssoc {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id := s.d.ByDevice[deviceID]; id != "" {
		return s.d.Assocs[id]
	}
	return nil
}

// RecordPushChannel persists what /1.0.0/push_channels used to echo and forget.
func (s *penneStore) RecordPushChannel(userID, deviceAcct, service, deviceToken string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := userID + "/" + service
	prev := s.d.PushChannels[key]
	rec := &pennePushChan{
		UserID: userID, DeviceAcct: deviceAcct, Service: service, DeviceTok: deviceToken,
		CreatedAt: now.Unix(), UpdatedAt: now.Unix(),
	}
	if prev != nil {
		rec.CreatedAt = prev.CreatedAt
	}
	s.d.PushChannels[key] = rec
	s.saveLocked()
}

// LinkNSA records the Nintendo Account binding a /links call carried, on the
// registration it authenticated.
func (s *penneStore) LinkNSA(id, nsaID string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.d.Assocs[id]; a != nil {
		a.NsaID = nsaID
		s.saveLocked()
	}
}

// ---------- subscriptions ----------

// AddSubscription records one SubscribeTopic: the console subscribes topics one frame
// at a time, so each adds to what the device already holds for the account instead of
// replacing it (a replace kept only the last topic a device subscribed).
func (s *penneStore) AddSubscription(userID, deviceID, topic string, now time.Time) {
	if topic == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sub := range s.d.Subs[userID] {
		if sub.DeviceID == deviceID && sub.Topic == topic {
			return
		}
	}
	s.d.Subs[userID] = append(s.d.Subs[userID], &penneSubRec{Topic: topic, DeviceID: deviceID, CreatedAt: now.Unix()})
	s.saveLocked()
}

// topicSubscriber is one (account, device) holding a topic.
type topicSubscriber struct {
	UserID, DeviceID string
}

// TopicSubscribers lists who subscribed a topic, by its raw string.
func (s *penneStore) TopicSubscribers(topic string) []topicSubscriber {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []topicSubscriber
	for user, subs := range s.d.Subs {
		for _, sub := range subs {
			if sub.Topic == topic {
				out = append(out, topicSubscriber{UserID: user, DeviceID: sub.DeviceID})
			}
		}
	}
	return out
}

func (s *penneStore) Subscriptions(userID string) []penneSubRec {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]penneSubRec, 0, len(s.d.Subs[userID]))
	for _, sub := range s.d.Subs[userID] {
		out = append(out, *sub)
	}
	return out
}

// ---------- delivery outbox (NTF-05) ----------

const (
	// maxPendingPerUser bounds a recipient's queue: a dead console must not
	// grow the backend without limit (queue-overflow policy below).
	maxPendingPerUser = 128
	// deliveredRetention is how long an event id stays remembered as seen, so
	// redelivery after reconnect can be deduplicated.
	deliveredRetention = 24 * time.Hour
	// retryBase/retryCap define the retry backoff curve: 5s doubling, capped.
	retryBase = 5 * time.Second
	retryCap  = 5 * time.Minute
)

// PenneDelivery is the semantic submission contract (coordination plan): a
// stable event identity, a recipient, a firmware event kind, the payload and an
// expiry. Submit persists before returning; callers may treat Accepted as
// "will be delivered or visibly dropped".
type PenneDelivery struct {
	ID        string // stable dedup identity; minted when empty
	UserID    string // recipient BAAS user id
	DeviceID  string // optional target device
	Kind      string // firmware event type string
	Payload   map[string]any
	ExpiresAt time.Time // zero: default TTL
}

type PenneSubmission struct {
	Accepted  bool
	Duplicate bool
	Outcome   penneOutcome
	ID        string
}

// Submit validates, deduplicates and persists a delivery atomically. Presence
// updates coalesce per (friend) subject so a sleeping console converges to
// current state instead of replaying stale toasts.
func (s *penneStore) Submit(d PenneDelivery, now time.Time) PenneSubmission {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.UserID == "" {
		return PenneSubmission{Outcome: penneRejectUser}
	}
	if d.ID == "" {
		d.ID = randHex(8) // stable from here on: the identity the whole pipeline dedups on
	}
	if seen := s.d.Delivered[d.UserID]; seen != nil {
		if t, dup := seen[d.ID]; dup && now.Unix()-t < int64(deliveredRetention/time.Second) {
			return PenneSubmission{Duplicate: true, Outcome: penneDuplicate, ID: d.ID}
		}
	}
	queue := s.d.Outbox[d.UserID]
	for _, e := range queue {
		if e.ID == d.ID {
			return PenneSubmission{Duplicate: true, Outcome: penneDuplicate, ID: d.ID}
		}
	}
	exp := d.ExpiresAt
	if exp.IsZero() {
		exp = now.Add(10 * time.Minute)
	}
	if !exp.After(now) {
		return PenneSubmission{Outcome: penneRejectExpiry, ID: d.ID}
	}
	rec := &penneOutRec{
		ID: d.ID, UserID: d.UserID, DeviceID: d.DeviceID, Kind: d.Kind,
		Payload: d.Payload, CreatedAt: now.Unix(), ExpiresAt: exp.Unix(), NextAt: now.Unix(),
	}
	// Coalesce: a presence update for a subject already pending is replaced in
	// place (latest wins), so offline convergence shows current state.
	if d.Kind == "presence_updated" {
		subj := fmt.Sprint(d.Payload["friendId"])
		for _, e := range queue {
			if e.Kind == d.Kind && fmt.Sprint(e.Payload["friendId"]) == subj {
				e.Payload, e.CreatedAt, e.ExpiresAt = rec.Payload, rec.CreatedAt, rec.ExpiresAt
				s.saveLocked()
				return PenneSubmission{Accepted: true, Outcome: pennePersisted, ID: d.ID}
			}
		}
	}
	// Overflow policy: expire what is already stale, then shed the oldest
	// coalescable presence, and only then refuse the new event.
	if len(queue) >= maxPendingPerUser {
		kept := queue[:0]
		for _, e := range queue {
			if e.ExpiresAt <= now.Unix() {
				s.dropped.Add(1)
				continue
			}
			kept = append(kept, e)
		}
		queue = kept
	}
	if len(queue) >= maxPendingPerUser {
		for i, e := range queue {
			if e.Kind == "presence_updated" {
				s.dropped.Add(1)
				queue = append(queue[:i], queue[i+1:]...)
				break
			}
		}
	}
	if len(queue) >= maxPendingPerUser {
		return PenneSubmission{Outcome: penneRejectFull, ID: d.ID}
	}
	s.d.Outbox[d.UserID] = append(queue, rec)
	s.saveLocked()
	return PenneSubmission{Accepted: true, Outcome: pennePersisted, ID: d.ID}
}

// ClaimDue returns the recipient's due, unexpired deliveries, oldest first.
// Nothing is mutated: the caller marks the outcome.
func (s *penneStore) ClaimDue(userID, deviceID string, now time.Time, limit int) []*penneOutRec {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*penneOutRec
	for _, e := range s.d.Outbox[userID] {
		if e.DeviceID != "" && deviceID != "" && e.DeviceID != deviceID {
			continue
		}
		if e.NextAt > now.Unix() {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out
}

// MarkDelivered records the write (protocol acks are not yet confirmed, so
// delivery means "written to the connection"); the id is remembered for the
// retention window so reconnect replay deduplicates.
func (s *penneStore) MarkDelivered(userID, eventID string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	queue := s.d.Outbox[userID]
	for i, e := range queue {
		if e.ID == eventID {
			queue = append(queue[:i], queue[i+1:]...)
			break
		}
	}
	s.d.Outbox[userID] = queue
	seen := s.d.Delivered[userID]
	if seen == nil {
		seen = map[string]int64{}
		s.d.Delivered[userID] = seen
	}
	seen[eventID] = now.Unix()
	s.delivered.Add(1)
	s.saveLocked()
}

// MarkFailed schedules the retry with doubling backoff, or drops the event as
// expired once its expiry has passed.
func (s *penneStore) MarkFailed(userID, eventID, errMsg string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.d.Outbox[userID] {
		if e.ID != eventID {
			continue
		}
		e.Attempts++
		e.LastError = errMsg
		if e.ExpiresAt <= now.Unix() {
			queue := s.d.Outbox[userID]
			for i, x := range queue {
				if x.ID == eventID {
					s.d.Outbox[userID] = append(queue[:i], queue[i+1:]...)
					break
				}
			}
			s.dropped.Add(1)
		} else {
			backoff := retryBase << min(e.Attempts-1, 6)
			if backoff > retryCap {
				backoff = retryCap
			}
			e.NextAt = now.Add(backoff).Unix()
			s.retried.Add(1)
		}
		break
	}
	s.saveLocked()
}

// AckDelivery settles a delivery by id: true when it was still pending (and is
// now marked delivered), false when nothing was waiting. Only real removals are
// remembered as seen, so junk ack ids cannot pollute the dedup window.
func (s *penneStore) AckDelivery(userID, eventID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	queue := s.d.Outbox[userID]
	for i, e := range queue {
		if e.ID == eventID {
			s.d.Outbox[userID] = append(queue[:i], queue[i+1:]...)
			seen := s.d.Delivered[userID]
			if seen == nil {
				seen = map[string]int64{}
				s.d.Delivered[userID] = seen
			}
			seen[eventID] = now.Unix()
			s.delivered.Add(1)
			s.saveLocked()
			return true
		}
	}
	return false
}

// SeenRecently reports whether an event id was delivered inside the retention
// window (reconnect dedup).
func (s *penneStore) SeenRecently(userID, eventID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.d.Delivered[userID][eventID]
	return ok && now.Unix()-t < int64(deliveredRetention/time.Second)
}

// Sweep expires stale work and prunes retention. It also returns users with
// due work so failed or deferred deliveries retry without another submission.
func (s *penneStore) Sweep(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var kicked []string
	unix := now.Unix()
	for uid, queue := range s.d.Outbox {
		kept := queue[:0]
		changed := false
		due := false
		for _, e := range queue {
			if e.ExpiresAt <= unix {
				s.dropped.Add(1)
				changed = true
				continue
			}
			kept = append(kept, e)
			if e.NextAt <= unix {
				due = true
			}
		}
		if changed {
			s.d.Outbox[uid] = kept
		}
		if changed || due {
			kicked = append(kicked, uid)
		}
	}
	for uid, seen := range s.d.Delivered {
		for id, t := range seen {
			if unix-t >= int64(deliveredRetention/time.Second) {
				delete(seen, id)
			}
		}
		if len(seen) == 0 {
			delete(s.d.Delivered, uid)
		}
	}
	for h, tk := range s.d.Tickets {
		if tk.ExpiresAt <= unix-int64(7*24*time.Hour/time.Second) { // keep expired tickets a week for denial audits
			delete(s.d.Tickets, h)
		}
	}
	for h, t := range s.d.Tokens {
		if t.ExpiresAt <= unix {
			delete(s.d.Tokens, h)
		}
	}
	s.saveLocked()
	return kicked
}

// Snapshot is the sanitized ops surface: counters and queue shapes, never
// payloads or credentials.
func (s *penneStore) Snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := 0
	oldest := int64(0)
	now := time.Now().Unix()
	for _, queue := range s.d.Outbox {
		pending += len(queue)
		for _, e := range queue {
			if oldest == 0 || e.CreatedAt < oldest {
				oldest = e.CreatedAt
			}
		}
	}
	out := map[string]any{
		"registrations": len(s.d.Assocs), "tokens": len(s.d.Tokens), "tickets": len(s.d.Tickets),
		"subscriptions": len(s.d.Subs), "outbox_pending": pending,
		"frames_in": s.framesIn.Load(), "frames_out": s.framesOut.Load(),
		"malformed": s.malformed.Load(), "unknown_type": s.unknownType.Load(),
		"delivered": s.delivered.Load(), "retried": s.retried.Load(), "dropped": s.dropped.Load(),
	}
	if oldest != 0 {
		out["oldest_event_age_s"] = now - oldest
	}
	return out
}
