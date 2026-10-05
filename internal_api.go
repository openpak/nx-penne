package main

// The penne API (nx-common/nxapi): what the core, the shop and parental controls ask of the
// push side. nx-baas served these same routes from its own state until the cut-over
// (nx-baas internal_penne.go, penne_link.go); the bodies of the deliveries below are its
// code, moved here unchanged.
//
// Keyed and strict: no NX_INTERNAL_KEY configured, no caller.

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/openpak/nx-common/internalkey"
	"github.com/openpak/nx-common/nxhttp"

	"nx-penne/internal/penne"
)

// internalAPI is the plain-HTTP listener: the god/val requests nx-baas forwards with the
// console's Host kept, and -- for every other Host -- the penne API and a health check. A
// console host never reaches the penne API (nxhttp.SplitListener).
func (s *server) internalAPI() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/internal/penne/", internalkey.Guard(http.HandlerFunc(s.penneAPI)))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "ok", "service": "nx-penne"})
	})
	return nxhttp.SplitListener(s, mux)
}

func (s *server) penneAPI(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/internal/penne")
	if id, ok := strings.CutPrefix(p, "/registrations/"); ok && r.Method == http.MethodGet && id != "" && !strings.Contains(id, "/") {
		ps := s.notifStore()
		out := map[string]any{"penne_id": id, "live": false, "user_id": "", "users": []string{}}
		if a := ps.AssocIfLive(id); a != nil {
			out["live"], out["user_id"] = true, a.UserID
			if users := ps.UsersOn(id); users != nil {
				out["users"] = users
			}
		}
		writeJSON(w, 200, out)
		return
	}
	if r.Method != http.MethodPost {
		apiErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var in struct {
		DeviceID          string         `json:"device_id"`
		UserID            string         `json:"user_id"`
		DeviceAccountID   string         `json:"device_account_id"`
		Service           string         `json:"service"`
		DeviceToken       string         `json:"device_token"`
		ID                string         `json:"id"`
		Kind              string         `json:"kind"`
		Payload           map[string]any `json:"payload"`
		Topic             string         `json:"topic"`
		Name              string         `json:"name"`
		Receivers         string         `json:"receivers"`
		Body              string         `json:"body"`
		NotificationToken string         `json:"notification_token"`
		PenneID           string         `json:"penne_id"`
		DauthUser         string         `json:"dauth_user"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "body is not JSON")
		return
	}
	switch {
	case p == "/consoles" && in.DeviceID != "" && in.UserID != "":
		// The core's /1.0.0/login (and NA token refresh): which account is on this console.
		s.notifStore().BindConsole(in.DeviceID, in.UserID)
		w.WriteHeader(http.StatusNoContent)
	case p == "/push-channels" && in.UserID != "":
		s.notifStore().RecordPushChannel(in.UserID, in.DeviceAccountID, in.Service, in.DeviceToken, time.Now())
		w.WriteHeader(http.StatusNoContent)
	case p == "/notifications" && in.UserID != "" && in.Kind != "":
		res := s.SubmitNotification(PenneDelivery{ID: in.ID, UserID: in.UserID, Kind: in.Kind, Payload: in.Payload})
		writeJSON(w, 200, map[string]any{"accepted": res.Accepted, "duplicate": res.Duplicate, "outcome": string(res.Outcome), "id": res.ID})
	case p == "/topic-messages" && in.Topic != "" && in.Name != "":
		subs, n := s.topicMessage(strings.ToLower(in.Topic), in.Name, in.Receivers, in.Body)
		log.Printf("[nx-penne] topic message %s -> topic %q: %d subscriber(s), %d connection(s)", in.Name, in.Topic, subs, n)
		writeJSON(w, 200, map[string]any{"subscribers": subs, "delivered": n})
	case p == "/token-bindings" && in.NotificationToken != "" && in.UserID != "":
		writeJSON(w, 200, map[string]any{"bound": s.bindToken(in.NotificationToken, in.UserID)})
	case p == "/device-messages" && (in.PenneID != "" || in.DauthUser != "") && in.Name != "":
		id, n := s.deviceMessage(in.PenneID, in.DauthUser, in.Name, in.Receivers, in.Body)
		writeJSON(w, 200, map[string]any{"penne_id": id, "connections": n})
	case strings.HasPrefix(p, "/users/") && strings.HasSuffix(p, "/close"):
		user := strings.TrimSuffix(strings.TrimPrefix(p, "/users/"), "/close")
		n := s.notifHub().closeUser(user)
		if n > 0 {
			log.Printf("[nx-penne] closed %d notification connection(s) of user %s (ban)", n, user)
		}
		writeJSON(w, 200, map[string]any{"closed": n})
	default:
		apiErr(w, http.StatusNotFound, "no such penne route, or a required field is missing")
	}
}

// closeUser cancels a BAAS user's live frontline sessions and reports how many.
func (h *penneHub) closeUser(user string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, sess := range h.sessions[user] {
		sess.cancel()
	}
	return len(h.sessions[user])
}

// pushFrame is a kind-1 message addressed to a receiver token: what news and parental
// controls send a console.
func pushFrame(name, receivers, body string, now uint64) []byte {
	return penne.BuildMessage(penne.Message{Name: name, Type: 1, Receivers: receivers, Body: body}, now, now+penneSyncTTL)
}

// topicMessage writes one message to every live connection of every account that
// subscribed the topic on that connection's device (nx-baas news.go).
func (s *server) topicMessage(topic, name, receivers, body string) (subscribers, delivered int) {
	subs := s.notifStore().TopicSubscribers(topic)
	subscribers = len(subs)
	if subscribers == 0 {
		return 0, 0
	}
	frame := pushFrame(name, receivers, body, uint64(time.Now().Unix()))
	h := s.notifHub()
	h.mu.Lock()
	var targets []*penneSession
	for _, list := range h.sessions {
		for _, sess := range list {
			for _, sub := range subs {
				if (sub.DeviceID != "" && sub.DeviceID == sess.device) || (sub.DeviceID == "" && sub.UserID == sess.user) {
					targets = append(targets, sess)
					break
				}
			}
		}
	}
	h.mu.Unlock()
	for _, sess := range targets {
		sess.offer("", frame)
	}
	return subscribers, len(targets)
}

// bindToken learns which user a console profile belongs to: olsc uploads the profile's
// notification token with the user's own token, token -> profile (recorded at mint) -> user
// (nx-baas services.go, which checked the user before asking).
func (s *server) bindToken(tok, userID string) bool {
	store := s.notifStore()
	if acct := store.TokenAccount(tok); acct != "" && store.BindAccount(acct, userID) {
		log.Printf("[nx-penne] console account %s is %s (olsc token upload)", acct, userID)
		return true
	}
	return false
}

// deviceMessage writes one message to every live connection of one registration: the penne
// id the caller kept, else the registration made under a device certificate (nx-baas moon.go
// pctlPush, for consoles paired before their token was kept).
func (s *server) deviceMessage(penneID, dauthUser, name, receivers, body string) (string, int) {
	if penneID == "" && dauthUser != "" {
		penneID = s.notifStore().AssocIDForUser(dauthUser)
	}
	if penneID == "" {
		return "", 0
	}
	frame := pushFrame(name, receivers, body, uint64(time.Now().Unix()))
	h := s.notifHub()
	h.mu.Lock()
	var live []*penneSession
	for _, list := range h.sessions {
		for _, sess := range list {
			if sess.penneID == penneID {
				live = append(live, sess)
			}
		}
	}
	h.mu.Unlock()
	for _, sess := range live {
		sess.offer("", frame)
	}
	return penneID, len(live)
}
