package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openpak/nx-common/nxapi"
)

const (
	eraseA = "11111111-1111-4111-8111-111111111111"
	eraseB = "22222222-2222-4222-8222-222222222222"
)

// eraseCore adds the account and Nintendo Account lookups nx-baas answers.
type eraseCore struct {
	*fakeCore
	accts map[string]string // core account -> NA id
	baas  map[string]string // NA id -> BAAS user id
}

func (c *eraseCore) Account(_ context.Context, id string) (*nxapi.Account, error) {
	if na := c.accts[id]; na != "" {
		return &nxapi.Account{AccountID: id, NaID: na}, nil
	}
	return nil, nxapi.ErrNotFound
}

func (c *eraseCore) NA(_ context.Context, na string) (*nxapi.NA, error) {
	return &nxapi.NA{NaID: na, BaasUserID: c.baas[na]}, nil
}

func eraseHTTP(s *server, key, path string) int {
	req := httptest.NewRequest("DELETE", path, nil)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	w := httptest.NewRecorder()
	s.internalAPI().ServeHTTP(w, req)
	return w.Code
}

func TestEraseAccountPenne(t *testing.T) {
	t.Setenv("ACCOUNT_ERASE_KEY", "erase-key-0123456789")
	now := time.Now()
	ps := newPenneStore()
	s := &server{penneState: ps, core: &eraseCore{fakeCore: mustStore(t),
		accts: map[string]string{eraseA: "na-a", eraseB: "na-b"}, baas: map[string]string{"na-a": "ua", "na-b": "ub"}}}
	idA, pwA := ps.Register("devA", "ua", "na-a", now)
	idB, pwB := ps.Register("devB", "ub", "na-b", now)
	ps.NoteAccount(idA, "acctuidA", "ua")
	ps.NoteAccount(idB, "acctuidB", "ub")
	ps.BindConsole("certA", "ua")
	ps.BindConsole("certB", "ub")
	for _, u := range []string{"ua", "ub"} {
		if _, err := ps.NotificationToken(map[string]string{"ua": idA, "ub": idB}[u], map[string]string{"ua": pwA, "ub": pwB}[u], u, "dev"+u, now); err != nil {
			t.Fatal(err)
		}
		ps.AddSubscription(u, "dev", "topic"+u, now)
		ps.RecordPushChannel(u, "acct", "svc", "tok", now)
		ps.Submit(PenneDelivery{ID: "e-" + u, UserID: u, Kind: EventFriendDeleted}, now)
	}
	if _, _, err := ps.IssueTicket(idA, pwA, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	s.records().Put("ua", "c-friends", []byte("x"))
	s.records().Put("ub", "c-friends", []byte("y"))

	p := "/internal/accounts/" + eraseA + "/data"
	if c := eraseHTTP(s, "", p); c != http.StatusUnauthorized {
		t.Fatalf("no key: %d", c)
	}
	if c := eraseHTTP(s, "nope", p); c != http.StatusUnauthorized {
		t.Fatalf("wrong key: %d", c)
	}
	if c := eraseHTTP(s, "erase-key-0123456789", "/internal/accounts/zzz/data"); c != 400 {
		t.Fatalf("bad id: %d", c)
	}
	if c := eraseHTTP(s, "erase-key-0123456789", p); c != 200 {
		t.Fatalf("erase: %d", c)
	}
	d := ps.d
	has := func(user string) int {
		n := 0
		for _, a := range d.Assocs {
			if a.UserID == user {
				n++
			}
		}
		for _, t := range d.Tokens {
			if t.UserID == user {
				n++
			}
		}
		for _, t := range d.Tickets {
			if t.UserID == user {
				n++
			}
		}
		for _, v := range d.AccountUsers {
			if v == user {
				n++
			}
		}
		for _, v := range d.ConsoleUsers {
			if v == user {
				n++
			}
		}
		for _, v := range d.ByUser {
			if v == idA && user == "ua" {
				n++
			}
		}
		n += len(d.Subs[user]) + len(d.Outbox[user])
		for _, c := range d.PushChannels {
			if c.UserID == user {
				n++
			}
		}
		return n
	}
	if n := has("ua"); n != 0 {
		t.Fatalf("account A left %d records", n)
	}
	if has("ub") < 7 {
		t.Fatalf("account B lost records: %d", has("ub"))
	}
	if _, err := ps.CheckAssoc(idA, pwA, now); err == nil {
		t.Fatal("erased registration still authenticates")
	}
	if _, err := ps.CheckAssoc(idB, pwB, now); err != nil {
		t.Fatalf("B's registration broke: %v", err)
	}
	if _, ok := s.records().Digest("ua", "c-friends"); ok {
		t.Fatal("record store kept A")
	}
	if _, ok := s.records().Digest("ub", "c-friends"); !ok {
		t.Fatal("record store lost B")
	}
	if n, err := s.eraseAccount(context.Background(), eraseA); err != nil || n != 0 {
		t.Fatalf("second run: %d %v", n, err)
	}
	if n, err := s.eraseAccount(context.Background(), "33333333-3333-4333-8333-333333333333"); err != nil || n != 0 {
		t.Fatalf("unknown: %d %v", n, err)
	}
	t.Setenv("ACCOUNT_ERASE_KEY", "")
	if c := eraseHTTP(s, "x", p); c != 503 {
		t.Fatalf("no env key: %d", c)
	}
}
