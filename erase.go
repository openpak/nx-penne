package main

// Account erasure (card #120): the Penne store keeps, per BAAS user, the push registrations,
// notification tokens, frontline tickets, topic subscriptions, push channels, the delivery
// outbox and the delivered-event window, plus the console-profile -> user mappings. The OpenPak
// account id is mapped to the BAAS user id through nx-baas's identity API (account -> Nintendo
// Account id -> BAAS user), which still knows the account while the website finaliser runs.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/openpak/nx-common/nxapi"

	"nx-penne/redact"
)

var eraseUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// accountResolver is the part of the identity API erasure needs (nxapi.Client implements it).
type accountResolver interface {
	Account(ctx context.Context, accountID string) (*nxapi.Account, error)
	NA(ctx context.Context, naID string) (*nxapi.NA, error)
}

// eraseAccount removes everything the Penne store holds for the OpenPak account and returns how
// many records went. Idempotent. The document is rewritten on a copy and swapped in only after the
// write succeeded, so a failed write leaves the store as it was and the finaliser retries.
func (s *server) eraseAccount(ctx context.Context, accountID string) (int, error) {
	res, ok := s.core.(accountResolver)
	if !ok {
		return 0, errors.New("identity core cannot resolve accounts")
	}
	acct, err := res.Account(ctx, accountID)
	if errors.Is(err, nxapi.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	na, err := res.NA(ctx, acct.NaID)
	if err != nil {
		return 0, err
	}
	n, err := s.notifStore().eraseUser(na.BaasUserID, acct.NaID)
	if err != nil {
		return 0, err
	}
	if na.BaasUserID != "" {
		n += s.records().eraseUser(na.BaasUserID)
	}
	log.Printf("account erased account=%s rows=%d service=nx-penne", strings.ToLower(accountID), n)
	return n, nil
}

func (s *penneStore) eraseUser(userID, naID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := json.Marshal(s.d)
	if err != nil {
		return 0, err
	}
	d := &penneData{}
	if err := json.Unmarshal(raw, d); err != nil {
		return 0, err
	}
	d.fill()
	n := 0
	gone := map[string]bool{} // penne ids of the registrations that go
	for id, a := range d.Assocs {
		if a.UserID == userID || (naID != "" && a.NsaID == naID) {
			gone[id] = true
			delete(d.Assocs, id)
			n++
		}
	}
	for k, v := range d.ByDevice {
		if gone[v] {
			delete(d.ByDevice, k)
			n++
		}
	}
	for k, v := range d.ByUser {
		if k == userID || gone[v] {
			delete(d.ByUser, k)
			n++
		}
	}
	for k, v := range d.ConsoleUsers {
		if v == userID {
			delete(d.ConsoleUsers, k)
			n++
		}
	}
	for k, v := range d.AccountUsers {
		if v == userID {
			delete(d.AccountUsers, k)
			delete(d.AccountProven, k)
			n++
		}
	}
	for k, t := range d.Tokens {
		if t.UserID == userID || gone[t.PenneID] {
			delete(d.Tokens, k)
			n++
		}
	}
	for k, t := range d.Tickets {
		if t.UserID == userID || gone[t.PenneID] {
			delete(d.Tickets, k)
			n++
		}
	}
	n += len(d.Subs[userID])
	delete(d.Subs, userID)
	for k, c := range d.PushChannels {
		if c.UserID == userID {
			delete(d.PushChannels, k)
			n++
		}
	}
	n += len(d.Outbox[userID]) + len(d.Delivered[userID])
	delete(d.Outbox, userID)
	delete(d.Delivered, userID)
	if n == 0 {
		return 0, nil
	}
	if s.pg != nil {
		if err := s.persistData(d); err != nil {
			return 0, err
		}
	}
	s.d = d
	return n, nil
}

func (s *penneRecordStore) eraseUser(userID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.byID[userID])
	delete(s.byID, userID)
	return n
}

// eraseHandler serves DELETE /internal/accounts/{account_id}/data on the internal listener.
func (s *server) eraseHandler(w http.ResponseWriter, r *http.Request) {
	key := os.Getenv("ACCOUNT_ERASE_KEY")
	if key == "" {
		writeJSON(w, 503, map[string]any{"error": "erase disabled"})
		return
	}
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(h, "Bearer ")), []byte(key)) != 1 {
		writeJSON(w, 401, map[string]any{"error": "unauthorized"})
		return
	}
	id := r.PathValue("account_id")
	if !eraseUUID.MatchString(id) {
		writeJSON(w, 400, map[string]any{"error": "bad account id"})
		return
	}
	n, err := s.eraseAccount(r.Context(), strings.ToLower(id))
	if err != nil {
		log.Printf("%s erase failed: %v", logPrefix, redact.Err(err))
		writeJSON(w, 502, map[string]any{"error": "erase failed"})
		return
	}
	writeJSON(w, 200, map[string]any{"service": "nx-penne", "rows": n})
}
