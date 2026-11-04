package main

// penne_pg.go: Postgres is the store of the Penne state (owner rule 2026-11-03: player and
// account state lives in Postgres, not in files on a volume). The state is one document, saved
// whole under the store's mutex exactly where the JSON file used to be written, so a restart
// (or a second instance on the same database) sees every registration, token, ticket,
// subscription and outbox record.

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"nx-penne/redact"
)

const penneSchema = `
CREATE TABLE IF NOT EXISTS penne_state (
	id         int PRIMARY KEY CHECK (id = 1),
	doc        jsonb NOT NULL,
	updated_at timestamptz NOT NULL DEFAULT now()
)`

// openPenneStore connects (small pool), creates the table and loads the document. When the
// database holds none yet, legacyFile (the old penne.json, if it exists) is imported once; the
// file is left in place. A failure is fatal: there is no memory fallback.
func openPenneStore(dsn, legacyFile string) *penneStore {
	if dsn == "" {
		log.Fatalf("%s NX_PENNE_DATABASE_URL is required (Postgres is the Penne store)", logPrefix)
	}
	s, err := connectPenneStore(context.Background(), dsn, legacyFile)
	if err != nil {
		log.Fatalf("%s postgres: %v", logPrefix, redact.Err(err))
	}
	d := s.d
	log.Printf("%s penne state in Postgres: %d associations, %d console users, %d tokens, %d tickets, %d subscription users, %d outbox users",
		logPrefix, len(d.Assocs), len(d.ConsoleUsers), len(d.Tokens), len(d.Tickets), len(d.Subs), len(d.Outbox))
	return s
}

func connectPenneStore(ctx context.Context, dsn, legacyFile string) (*penneStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, penneSchema); err != nil {
		pool.Close()
		return nil, err
	}
	s := newPenneStore()
	s.pg = pool
	var raw []byte
	err = pool.QueryRow(ctx, `SELECT doc FROM penne_state WHERE id = 1`).Scan(&raw)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, s.d); err != nil {
			pool.Close()
			return nil, err
		}
		s.d.fill()
	default:
		// No row (pgx.ErrNoRows): first start on this database. Import the old file once.
		if b, rerr := os.ReadFile(legacyFile); legacyFile != "" && rerr == nil {
			if err := json.Unmarshal(b, s.d); err != nil {
				pool.Close()
				return nil, err
			}
			s.d.fill()
			log.Printf("%s imported %s (%d bytes) into Postgres; the file is kept", logPrefix, legacyFile, len(b))
		}
		s.mu.Lock()
		perr := s.persist()
		s.mu.Unlock()
		if perr != nil {
			pool.Close()
			return nil, perr
		}
	}
	return s, nil
}

// fill makes every map non-nil (records predating a schema change can lack them).
func (d *penneData) fill() {
	if d.Assocs == nil {
		d.Assocs = map[string]*penneAssoc{}
	}
	if d.ByDevice == nil {
		d.ByDevice = map[string]string{}
	}
	if d.ByUser == nil {
		d.ByUser = map[string]string{}
	}
	if d.ConsoleUsers == nil {
		d.ConsoleUsers = map[string]string{}
	}
	if d.AccountUsers == nil {
		d.AccountUsers = map[string]string{}
	}
	if d.AccountProven == nil {
		d.AccountProven = map[string]bool{}
	}
	if d.Tokens == nil {
		d.Tokens = map[string]*penneTokenRec{}
	}
	if d.Tickets == nil {
		d.Tickets = map[string]*penneTicketRec{}
	}
	if d.Subs == nil {
		d.Subs = map[string][]*penneSubRec{}
	}
	if d.PushChannels == nil {
		d.PushChannels = map[string]*pennePushChan{}
	}
	if d.Outbox == nil {
		d.Outbox = map[string][]*penneOutRec{}
	}
	if d.Delivered == nil {
		d.Delivered = map[string]map[string]int64{}
	}
}

// persist upserts the document; mu is held.
func (s *penneStore) persist() error { return s.persistData(s.d) }

func (s *penneStore) persistData(d *penneData) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = s.pg.Exec(ctx, `INSERT INTO penne_state (id, doc) VALUES (1, $1)
		ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()`, b)
	return err
}

// Close releases the pool.
func (s *penneStore) Close() {
	if s.pg != nil {
		s.pg.Close()
	}
}
