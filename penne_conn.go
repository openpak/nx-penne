package main

// penne_conn.go: the Penne "frontline" persistent connection (NTF-02, NTF-03).
//
// Lifecycle the 22.5.0 client drives, per the recovered protocol specification
// (docs/penne-protocol.md): a POST to https://<frontline>/ with a bearer login
// ticket, X-Protocol-Version 4 and friends; the connection is held open and
// carries length-prefixed FlatBuffers envelopes in both directions. The
// client's outgoing framing is firmware-confirmed (u32 LE length + buffer);
// server-to-client framing is treated as symmetric pending a capture.
//
// What changed versus the old handler: authentication (the ticket is real and
// revocable), frames instead of a newline heartbeat (a newline byte would
// desync any length-prefixed decoder -- the keepalive below flushes without
// writing content), subscriptions that persist, and a delivery pump with
// reconnect reconciliation (NTF-05).

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"nx-penne/internal/penne"
	"nx-penne/redact"
)

// frontlineKeepalive is how often the held-open connection is flushed. A Flush
// with nothing written keeps intermediaries from timing the connection out
// without inventing frame content the protocol has not shown us.
var frontlineKeepalive = 30 * time.Second

// penneSyncTTL is the expiry the console puts on its own sync messages: it
// sends issued and issued+3600 [runtime capture].
const penneSyncTTL = 3600

// isPenneFrontline names the hosts the persistent connection lands on
// (fro-N.hac.lp1.penne.srv.nintendo.net).
func isPenneFrontline(host string) bool { return strings.HasPrefix(host, "fro-") }

// frontline answers the Penne persistent POST. Two shapes exist:
//
//   - A streaming request body (chunked, no length): the NPNS shape -- the
//     client keeps writing frames while it reads pushes. Go's net/http server
//     cannot serve this: its first response flush drains up to 256 KiB of the
//     request body into io.discard (server.go writeHeader -> body.Close),
//     destroying the frame stream. The connection is hijacked instead and the
//     HTTP/1.1 chunked exchange is carried by hand.
//   - A finite request body: the older frontline shape (register a room, hold
//     the response open). The ordinary held-open response below serves it.
func (s *server) frontline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"status": 405, "title": "method not allowed"})
		return
	}
	now := time.Now()
	ticket := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	ticket = strings.TrimSpace(ticket)
	if ticket == "" {
		writeJSON(w, 401, map[string]any{"status": 401, "errorCode": "credentials_required",
			"title": "Credentials required", "detail": "The frontline connection requires a login ticket",
			"type": "https://penne.nintendo.net/errors/1.0.0/401/credentials_required"})
		return
	}
	rec, err := s.notifStore().ValidateTicket(ticket, deviceIDFromUA(r.UserAgent()), now)
	if err != nil {
		// Expired, revoked, unknown or wrong-device: a denial is a denial, and
		// the console re-registers rather than retrying forever.
		log.Printf("[nx-penne] penne frontline: denied (%v)", redact.Err(err))
		writeJSON(w, 401, map[string]any{"status": 401, "errorCode": "invalid_credentials",
			"title": "Invalid credentials", "detail": "The login ticket is not usable",
			"type": "https://penne.nintendo.net/errors/1.0.0/401/invalid_credentials"})
		return
	}
	if !isPenneFrontline(hostOf(r)) {
		writeJSON(w, 404, map[string]any{})
		return
	}
	// A banned account gets no notification channel (bans.go); a ban that lands while the
	// connection is open closes it (closeUser, from the core's account_banned event).
	{
		if lock := s.userLock(r.Context(), s.sessionUser(rec)); lock != "" {
			log.Printf("[nx-penne] penne frontline: account %s is %s; refusing", redact.Tag(rec.UserID), lock)
			writeJSON(w, 403, map[string]any{"status": 403, "errorCode": "forbidden",
				"title": "Forbidden", "detail": "This account cannot use the OpenPak network",
				"type": "https://penne.nintendo.net/errors/1.0.0/403/forbidden"})
			return
		}
	}
	if len(r.TransferEncoding) > 0 && r.TransferEncoding[0] == "chunked" {
		s.frontlineStream(w, r, rec)
		return
	}
	s.frontlineHeldOpen(w, r, rec)
}

// frontlineHeldOpen serves the finite-body shape: 200, chunked, held open,
// flushing the writer so the client sees acceptance, delivering frames as they
// are submitted. A keepalive ticker flushes the writer without content: the
// newline heartbeat this replaces was unvalidated and would desync any
// length-prefixed decoder; a zero-byte flush desyncs nothing.
func (s *server) frontlineHeldOpen(w http.ResponseWriter, r *http.Request, rec *penneTicketRec) {
	fl, ok := w.(http.Flusher)
	if !ok {
		// Without Flusher there is no streaming; answering and closing is the
		// documented failure class, so refuse loudly instead.
		writeJSON(w, 500, map[string]any{"status": "no-stream"})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(200)
	fl.Flush() // let the client see the connection accepted before anything else

	ctx, cancel := context.WithCancel(r.Context())
	sess := &penneSession{
		user: s.sessionUser(rec), device: rec.DeviceID, penneID: rec.PenneID,
		ctx: ctx, cancel: cancel, send: make(chan penneOutbound, penneSendQueue), prio: make(chan []byte, 1),
		done: make(chan struct{}),
	}
	s.penneHub.attach(sess)
	defer s.penneHub.detach(sess)
	defer cancel()
	log.Printf("[nx-penne] penne frontline: open user=%s device=%s proto=%s te=%v len=%d",
		redact.Tag(sess.user), redact.Tag(rec.DeviceID), r.Proto, r.TransferEncoding, r.ContentLength)

	// The console reads exactly one message here, with a 70-second deadline,
	// and accepts only HandoverResult or Reset (RVA 0xd9730): everything else
	// is "HandoverResult expected, but ...received" and the connection fails.
	// A zero result continues to normal operation, where it sends its
	// subscription list. This is why a connection held open in silence closed
	// itself after ~65 seconds having sent nothing [firmware, 2026-09-12].
	if err := penne.WriteFrame(w, penne.BuildHandoverResult(0)); err != nil {
		return
	}
	fl.Flush()
	s.notifStore().framesOut.Add(1)

	// Reader: the request body carries the client's frames.
	go s.penneRead(sess, r.Body)

	// Finite-body connections need the same offline replay as stream connections.
	s.penneWakeConsole(sess)

	ticker := time.NewTicker(frontlineKeepalive)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done(): // console hung up
			close(sess.done)
			return
		case frame := <-sess.prio:
			s.notifStore().framesOut.Add(1)
			if err := penne.WriteFrame(w, frame); err != nil {
				cancel()
				continue
			}
			fl.Flush()
		case out := <-sess.send:
			// An answer queued behind this one would arrive late, so take it
			// first if it is already waiting.
			select {
			case frame := <-sess.prio:
				s.notifStore().framesOut.Add(1)
				if err := penne.WriteFrame(w, frame); err != nil {
					cancel()
					continue
				}
				fl.Flush()
			default:
			}
			s.notifStore().framesOut.Add(1)
			if err := penne.WriteFrame(w, out.frame); err != nil {
				if out.id != "" {
					s.penneMarkFailed(sess, out.id, err)
				}
				cancel()
				continue
			}
			if out.id != "" {
				s.penneMarkDelivered(sess, out.id)
			}
			fl.Flush()
		case <-ticker.C:
			// Keepalive: flush without content. The newline heartbeat this
			// replaces was unvalidated and would desync a length-prefixed
			// decoder; a zero-byte flush desyncs nothing.
			s.penneRenewPresence(sess)
			fl.Flush()
		}
	}
}

// frontlineStream serves the NPNS bidirectional shape over a hijacked
// connection: HTTP/1.1 chunked frames in both directions, carried by hand.
func (s *server) frontlineStream(w http.ResponseWriter, r *http.Request, rec *penneTicketRec) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[nx-penne] penne frontline: no hijacker available; refusing")
		writeJSON(w, 500, map[string]any{"status": "no-stream"})
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		log.Printf("[nx-penne] penne frontline: hijack: %v", redact.Err(err))
		return
	}
	defer conn.Close()
	if k, ok := conn.(interface{ NetConn() net.Conn }); ok { // *tls.Conn: keepalive on the TCP beneath
		if tc, ok := k.NetConn().(*net.TCPConn); ok {
			tc.SetKeepAlive(true) // no HTTP-level keepalive exists in this shape
		}
	}
	// The response head, written directly: chunked octet-stream, held open.
	if _, err := brw.Writer.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n"); err != nil {
		return
	}
	if err := brw.Writer.Flush(); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	sess := &penneSession{
		user: s.sessionUser(rec), device: rec.DeviceID, penneID: rec.PenneID,
		ctx: ctx, cancel: cancel, send: make(chan penneOutbound, penneSendQueue), prio: make(chan []byte, 1),
		done: make(chan struct{}),
	}
	s.penneHub.attach(sess)
	defer s.penneHub.detach(sess)
	log.Printf("[nx-penne] penne frontline: open (stream) user=%s device=%s proto=%s te=%v",
		redact.Tag(sess.user), redact.Tag(rec.DeviceID), r.Proto, r.TransferEncoding)

	// Reader: the client's frames arrive as chunked request-body bytes.
	body := newChunkReader(brw.Reader)
	go s.penneRead(sess, body)

	// Reconciliation first: anything the outbox owes this account goes out
	// before new work (NTF-05 reconnect behavior).
	s.penneWakeConsole(sess)

	writeChunk := func(frame []byte) error {
		if _, err := fmt.Fprintf(brw.Writer, "%x\r\n", len(frame)); err != nil {
			return err
		}
		if _, err := brw.Writer.Write(frame); err != nil {
			return err
		}
		_, err := brw.Writer.WriteString("\r\n")
		if err != nil {
			return err
		}
		return brw.Writer.Flush()
	}
	// Same handover as the finite-body path.
	if err := writeChunk(penne.AppendFrame(nil, penne.BuildHandoverResult(0))); err != nil {
		return
	}
	s.notifStore().framesOut.Add(1)

	for {
		select {
		case <-ctx.Done():
			close(sess.done)
			// Terminate the chunked response so a well-behaved client sees EOF.
			brw.Writer.WriteString("0\r\n\r\n") //nolint:errcheck // closing anyway
			brw.Writer.Flush()
			return
		case frame := <-sess.prio:
			s.notifStore().framesOut.Add(1)
			if err := writeChunk(penne.AppendFrame(nil, frame)); err != nil {
				cancel()
				continue
			}
		case out := <-sess.send:
			select {
			case frame := <-sess.prio:
				s.notifStore().framesOut.Add(1)
				if err := writeChunk(penne.AppendFrame(nil, frame)); err != nil {
					cancel()
					continue
				}
			default:
			}
			s.notifStore().framesOut.Add(1)
			// The chunk carries a framed message: the protocol's own
			// length prefix rides inside the HTTP chunk, as in the
			// held-open path.
			if err := writeChunk(penne.AppendFrame(nil, out.frame)); err != nil {
				if out.id != "" {
					s.penneMarkFailed(sess, out.id, err)
				}
				cancel()
				continue
			}
			if out.id != "" {
				s.penneMarkDelivered(sess, out.id)
			}
		}
	}
}

// chunkReader de-chunks a request body we took over with Hijack (the server's
// own decoder belongs to the r.Body we may no longer touch). Chunk-size lines
// are bounded by the bufio buffer: one longer than that is a protocol error,
// not an allocation opportunity.
type chunkReader struct {
	br   *bufio.Reader
	n    int  // bytes left in the current chunk
	done bool // terminating chunk seen
}

func newChunkReader(br *bufio.Reader) *chunkReader { return &chunkReader{br: br} }

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.done {
		return 0, io.EOF
	}
	if c.n == 0 {
		line, err := c.br.ReadString('\n')
		if err != nil {
			return 0, err
		}
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, ';'); i >= 0 { // chunk extensions
			line = line[:i]
		}
		n, err := strconv.ParseInt(line, 16, 64)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("bad chunk size %q", line)
		}
		if n == 0 {
			c.done = true
			return 0, io.EOF
		}
		if n > penne.MaxFrameSize*4 {
			return 0, penne.ErrFrameTooLarge
		}
		c.n = int(n)
	}
	if len(p) == 0 {
		return 0, nil
	}
	want := c.n
	if want > len(p) {
		want = len(p)
	}
	r, err := io.ReadFull(c.br, p[:want])
	c.n -= r
	if c.n == 0 && err == nil {
		if _, err := c.br.Discard(2); err != nil { // the CRLF after each chunk
			return r, err
		}
	}
	return r, err
}

// penneSendQueue bounds a session's outbound queue. When full, the work stays
// in the persistent outbox (bounded there too) instead of growing here.
const penneSendQueue = 64

// penneOutbound is one queued write: the encoded frame plus the delivery id it
// settles on success ("" for control frames like Pong, which settle nothing).
type penneOutbound struct {
	id    string
	frame []byte
}

// penneSession is one live frontline connection.
type penneSession struct {
	user    string
	device  string
	penneID string
	// published is every (user, device) whose presence arrived on this
	// connection, so the keepalive can renew what the console has already
	// said rather than let it lapse between changes.
	published sync.Map
	// prio carries answers the console is blocking on. They must go out
	// before anything queued, and a late one is fatal, so the channel holds
	// exactly one and a reply that cannot leave at once is dropped.
	prio   chan []byte
	ctx    context.Context
	cancel context.CancelFunc
	send   chan penneOutbound
	done   chan struct{}
}

// ack answers the request the console just sent, on the priority path.
//
// The console keeps one request outstanding, with the string it expects in a
// buffer that is never cleared, only overwritten by its next request. So an
// Ack that arrives late does not miss its window: it is compared against the
// NEXT request's string and aborts npns, taking the friends module's listener
// with it for the rest of the boot (2026-09-20, two crash reports). A reply
// that cannot go out immediately is therefore dropped -- that costs one
// reconnect, where a late one costs a crash
// (docs/penne-message-delivery-2026-09-20.md §7).
func (sess *penneSession) ack(name string) {
	if name == "" {
		return
	}
	select {
	case sess.prio <- penne.BuildAck(name):
	default: // an answer is already waiting: this one would be late
	}
}

// offer queues a frame without ever blocking the caller; if this connection is
// slow, the persistent outbox keeps the work.
func (sess *penneSession) offer(id string, frame []byte) {
	select {
	case sess.send <- penneOutbound{id: id, frame: frame}:
	default:
	}
}

// sessionUser is the account a live connection delivers for. A ticket minted
// before its console signed in to BAAS carries the device certificate as its
// subject, and the outbox is keyed by accounts — so the certificate is resolved
// through what the login recorded. Without this a console reconnecting on an
// old ticket is told there is nothing for it while its events expire.
func (s *server) sessionUser(rec *penneTicketRec) string {
	if rec == nil {
		return ""
	}
	if u := s.notifStore().ResolveUser(rec.UserID); u != "" && u != rec.UserID {
		log.Printf("[nx-penne] penne frontline: ticket names console %s; delivering for account %s", redact.Tag(rec.UserID), redact.Tag(u))
		return u
	}
	return rec.UserID
}

// penneSyncProbe rotates the answer to the console's RootHash through the
// candidate shapes when NX_PENNE_SYNC_PROBE is set. It did its job on
// 2026-09-12: four wake cycles, six candidates each, and exactly one of them
// got the console past the sync every single time. It stays for the next
// question of this shape.
var penneSyncProbe = os.Getenv("NX_PENNE_SYNC_PROBE") != ""

// penneReconcile turns on the leaf half of the sync: answering the console's
// LeafHash, and (step two, once this is proven on hardware) advertising the
// namespaces we hold records under in the RootHash answer so the console asks
// for them. Off means production keeps the empty-vector answer, which is the
// only one the console accepts today.
var penneReconcile = os.Getenv("NX_PENNE_RECONCILE") != ""

// penneSyncReply picks the answer and names it for the log.
//
// **An empty entry vector is the answer.** The console opens with a RootHash
// naming four namespaces and their digests; answering with an empty vector --
// this server holds no records under any of them -- makes it send SyncComplete
// and move to the steady state, where it subscribes to its topics and publishes
// its own presence. Every other shape tried leaves it in the reconnect loop
// that blocked delivery for a month:
//
//	mirror (the console's own digests back)  -> nothing, reconnect in ~1s
//	two-slot envelope                        -> LeafHash, a drill-down we
//	                                            cannot answer; gives up in ~70s
//	count+1                                  -> nothing
//	LeafHash mirror                          -> nothing
//	empty vector                             -> SyncComplete, then SubscribeTopic
//	                                            and DAPresence
//	no reply                                 -> nothing
//
// Reproduced on four consecutive cycles [runtime capture, 2026-09-12 16:50-16:53].
// It reads as the honest answer too: mirroring the console's digests claimed we
// held records we could not describe, and the console would not proceed on a
// claim the server could not back with a leaf.
func (s *server) penneSyncReply(entries []penne.RootEntry, count uint32, now uint64) ([]byte, string) {
	empty := func() ([]byte, string) {
		return penne.BuildRootHash(nil, count, now, now+penneSyncTTL), "RootHash, no entries"
	}
	if !penneSyncProbe {
		return empty()
	}
	switch s.notifStore().NextSyncProbe() % 6 {
	case 1:
		return penne.BuildRootHash(entries, count, now, now+penneSyncTTL), "RootHash mirror"
	case 2:
		return penne.BuildRootHashMinimal(entries), "RootHash, two-slot envelope"
	case 3:
		return penne.BuildRootHash(entries, count+1, now, now+penneSyncTTL), "RootHash, count+1"
	case 4:
		return penne.BuildLeafHash(entries, count, now, now+penneSyncTTL), "LeafHash mirror"
	case 5:
		return empty()
	default:
		// The control: if the console still drops the connection in about a
		// second with nothing sent, the loop is not our reply's fault.
		return nil, "no reply (control)"
	}
}

// frameHex renders a bounded hex dump for the protocol log. The payload shapes
// of the client's own messages are what the spec still marks open, so the first
// ones to arrive are worth keeping verbatim.
func frameHex(frame []byte) string {
	if !redact.Bodies {
		return fmt.Sprintf(" len=%d", len(frame))
	}
	const max = 4096
	if len(frame) <= max {
		return fmt.Sprintf(" len=%d hex=%x", len(frame), frame)
	}
	return fmt.Sprintf(" len=%d hex=%x…(truncated)", len(frame), frame[:max])
}

// penneRead decodes the client's frames until the connection ends. A malformed
// or oversized stream terminates the session: never a panic, never unbounded
// allocation.
func (s *server) penneRead(sess *penneSession, body io.Reader) {
	fr := penne.NewFrameReader(body, penne.MaxFrameSize)
	read := 0
	for {
		frame, err := fr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Worth saying out loud: an immediate EOF means the request
				// carried no readable body, so nothing the console sends on
				// this connection can ever reach us.
				log.Printf("[nx-penne] penne frontline: uplink ended after %d frame(s) (EOF)", read)
				return
			}
			if sess.ctx.Err() == nil {
				s.notifStore().malformed.Add(1)
				log.Printf("[nx-penne] penne frontline: read ended (%v); closing", redact.Err(err))
				sess.cancel()
			}
			return
		}
		read++
		s.notifStore().framesIn.Add(1)
		s.penneDispatch(sess, frame)
	}
}

// penneDispatch handles one inbound envelope. Only firmware-identified
// messages get firmware-identified answers; everything else is counted and
// logged for the protocol capture, never answered with invented schemas.
func (s *server) penneDispatch(sess *penneSession, frame []byte) {
	env, err := penne.DecodeEnvelope(frame)
	if err != nil {
		s.notifStore().malformed.Add(1)
		log.Printf("[nx-penne] penne frontline: malformed frame (%v); closing", redact.Err(err))
		sess.cancel()
		return
	}
	store := s.notifStore()
	switch env.Type() {
	case penne.TypeRootHash: // 0x06 — the sync the console opens with
		payload, ok := env.Payload()
		if !ok {
			store.unknownType.Add(1)
			log.Printf("[nx-penne] penne: RootHash without a payload; counted")
			return
		}
		entries := penne.ParseRootHash(payload)
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, fmt.Sprintf("%s=%x", e.Name, e.Digest))
		}
		// The console offers a digest per record namespace (c-appearance,
		// c-friends, c-settings, c-storage) and waits for RootHash or
		// LeafHash. The answer it accepts is an empty entry vector — "the
		// server holds no records" — after which it sends SyncComplete and
		// enters the steady state, where records are delivered and stored
		// (RVA 0xdba50 -> 0xdbe50 -> 0xda010 -> 0xdc9e0).
		//
		// Hardware-proven on four consecutive wake cycles [runtime,
		// 2026-09-12]; every mirror shape was refused. The elimination
		// table is docs/penne-protocol.md §4f; the candidate rotation is
		// penneSyncReply below.
		count, _ := env.Root().U32(2)
		now := uint64(time.Now().Unix())
		// A RootHash entry is a namespace digest, aggregated over the records
		// below it by a function this server cannot reproduce — so even for a
		// namespace we have written into, the console's own digest is the only
		// value we can state honestly. What we write is recorded per topic
		// (penne_records.go); what we claim here is what the console claims.
		reply, shape := s.penneSyncReply(entries, count, now)
		if reply == nil {
			log.Printf("[nx-penne] penne: RootHash from user=%s [%s]; answering with silence (%s)", redact.Tag(sess.user), redact.IDs(strings.Join(names, " ")), shape)
			return
		}
		select {
		case sess.send <- penneOutbound{frame: reply}:
			log.Printf("[nx-penne] penne: RootHash from user=%s [%s]; answered %s", redact.Tag(sess.user), redact.IDs(strings.Join(names, " ")), shape)
		default:
			log.Printf("[nx-penne] penne: RootHash from user=%s dropped, send queue full", redact.Tag(sess.user))
		}

	case penne.TypeSubscribeTopic: // 0x17, firmware-confirmed
		payload, hasPayload := env.Payload()
		var topic string
		var flags [2]bool
		var have [2]bool
		if hasPayload {
			flags[0], have[0] = payload.Bool(0)
			flags[1], have[1] = payload.Bool(4)
			// The recovered builder formats the topic as %016llx of a u64
			// (16 lowercase hex); field 3 is the best-evidence topic slot.
			for _, f := range []int{3, 2, 1} {
				if v, ok := payload.String(f); ok && v != "" {
					topic = v
					break
				}
			}
		}
		if topic == "" {
			store.unknownType.Add(1)
			log.Printf("[nx-penne] penne: SubscribeTopic without a readable topic (flags %v/%v); counted, not guessed", have[0], have[1])
			return
		}
		store.AddSubscription(sess.user, sess.device, strings.ToLower(topic), time.Now())
		// Every topic is logged by name: which string a followed News channel is
		// subscribed under is still unrecovered, and this line is how hardware
		// answers it (news.go).
		log.Printf("[nx-penne] penne: subscribed user=%s device=%s topic=%s", redact.Tag(sess.user), redact.Tag(sess.device), redact.IDs(topic))
		// Confirmation: SubscriptionUpdated carries one u64 (recovered shape);
		// the value's meaning is not recovered -- we send the unix second as
		// the least-surprising candidate, flagged in the protocol spec.
		// SubscriptionUpdated does not clear the console's pending request;
		// only an Ack naming the subscription does.
		sess.ack("topic.subscription")
	case penne.TypePing: // 16: three u64s recovered; echo field 0
		var ping uint64
		if payload, ok := env.Payload(); ok {
			ping, _ = payload.U64(0)
		}
		sess.offer("", penne.BuildPong(ping))
	case penne.TypeAck: // 9: one string — the name it read out of our frame
		if payload, ok := env.Payload(); ok {
			if id, ok := payload.String(0); ok {
				log.Printf("[nx-penne] penne: ack=%q user=%s", redact.IDs(id), redact.Tag(sess.user))
				// Best-effort replay ack: a message id naming one of our
				// queued events settles that delivery.
				if !store.AckDelivery(sess.user, id, time.Now()) {
					for _, u := range store.UsersOn(sess.penneID) {
						store.AckDelivery(u, id, time.Now())
					}
				}
			} else if v, ok := payload.U64(0); ok {
				log.Printf("[nx-penne] penne: ack=%d user=%s", v, redact.Tag(sess.user))
			}
		}
	case penne.TypeResendRequest: // 26: one string field; treat it as replay-by-id
		if payload, ok := env.Payload(); ok {
			if id, ok := payload.String(0); ok {
				log.Printf("[nx-penne] penne: resend requested for %s", redact.IDs(id))
				s.penneWakeConsole(sess)
			}
		}
	case penne.TypePutRecord, penne.TypeDeleteRecord:
		// The console uploading (or deleting) one of its own records. It waits
		// for an Ack naming that record.
		payload, ok := env.Payload()
		if !ok {
			store.unknownType.Add(1)
			log.Printf("[nx-penne] penne: %s without a payload%s", env.TypeName(), frameHex(frame))
			return
		}
		name, ok := penne.EntryName(payload)
		if !ok || name == "" {
			store.unknownType.Add(1)
			log.Printf("[nx-penne] penne: %s without a record name%s", env.TypeName(), frameHex(frame))
			return
		}
		log.Printf("[nx-penne] penne: %s %s from user=%s", env.TypeName(), redact.IDs(name), redact.Tag(sess.user))
		sess.ack(name)

	case penne.TypePowerState: // 0x0e: one string, "Awake" or "Asleep"
		state := ""
		if payload, ok := env.Payload(); ok {
			state, _ = payload.String(0)
		}
		if state == "" {
			store.unknownType.Add(1)
			log.Printf("[nx-penne] penne: PowerState without a state%s", frameHex(frame))
			return
		}
		// The console sends "Awake" or "Sleep" and waits for that same word.
		log.Printf("[nx-penne] penne: power state %s user=%s", state, redact.Tag(sess.user))
		sess.ack(state)

	case penne.TypeHi, penne.TypeIdle, penne.TypeSubscriptionListRequest:
		// Recovered empty/near-empty client messages: noted, no answer defined
		// by evidence. Logged by name because the first one the console ever
		// sends is what settles the opening handshake.
		log.Printf("[nx-penne] penne: %s from user=%s device=%s%s", env.TypeName(), redact.Tag(sess.user), redact.Tag(sess.device), frameHex(frame))
	case penne.TypeLeafHash:
		// The other half of the sync, and the frame this server has always
		// dropped. The console is not rejecting anything here: it names a
		// namespace and lists the leaves IT holds under it, and waits for ours
		// back. Unanswered it gives up after about seventy seconds, which is
		// what every entries-bearing sync answer did [runtime capture,
		// 2026-09-12]. Dark until NX_PENNE_RECONCILE, because advertising in
		// the RootHash without this reply is the loop we already measured.
		if !penneReconcile {
			store.unknownType.Add(1)
			log.Printf("[nx-penne] penne: frame type LeafHash counted, reconciliation is off%s", frameHex(frame))
			return
		}
		p, ok := env.Payload()
		if !ok {
			store.unknownType.Add(1)
			log.Printf("[nx-penne] penne: LeafHash without a payload; counted")
			return
		}
		ns, theirs := penne.ParseLeafHash(p)
		ours := s.records().LeavesUnder(sess.user, ns)
		now := uint64(time.Now().Unix())
		reply := penne.BuildLeafHashReply(ns, ours, uint32(len(ours)), now, now+penneSyncTTL)
		log.Printf("[nx-penne] penne: LeafHash for %s from user=%s (theirs=%d, ours=%d); answering",
			redact.IDs(ns), redact.Tag(sess.user), len(theirs), len(ours))
		select {
		case sess.send <- penneOutbound{frame: reply}:
		default:
			log.Printf("[nx-penne] penne: LeafHash reply for %s dropped, send queue full", redact.IDs(ns))
		}

	case penne.TypeDAPresence:
		// The console publishing its own presence, for any account signed in on
		// it — not only the one this connection is bound to (penne_presence.go).
		//
		// Answered first, and whether or not the user is one we know: a
		// presence frame is a request like any other, and until it is answered
		// the console publishes nothing else and is torn down ten seconds
		// later. That is why only one profile's presence ever reached us
		// (docs/switch/presence-publish-gate-2026-09-20.md).
		p, ok := env.Payload()
		if !ok {
			store.unknownType.Add(1)
			log.Printf("[nx-penne] penne: DAPresence without a payload%s", frameHex(frame))
			return
		}
		// Echoed the other way round from the wire: the console builds the
		// string it waits for as <nsa>/<device account>.
		device, _ := p.String(0)
		user, _ := p.String(1)
		if device != "" && user != "" {
			sess.ack(user + "/" + device)
			sess.published.Store(user, device)
		}
		if s.penneNotePresence(p) {
			return
		}
		store.unknownType.Add(1)
		log.Printf("[nx-penne] penne: DAPresence could not be read%s", frameHex(frame))
	default:
		store.unknownType.Add(1)
		// With the bytes: the console's own messages are the only source for
		// the payload shapes the spec still marks open, and they are cheap to
		// keep once — bounded, and a frame carries no credential.
		log.Printf("[nx-penne] penne: frame type %s counted, no evidence-backed answer%s", env.TypeName(), frameHex(frame))
	}
}

// penneSweep retries due deliveries, expires stale work and prunes retention.
// Started once from main(); every tick logs the sanitized snapshot.
func (s *server) penneSweep() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	var lastLog int64
	for now := range t.C {
		for _, uid := range s.notifStore().Sweep(now) {
			s.penneWake(uid)
		}
		if now.Unix()-lastLog >= 600 {
			lastLog = now.Unix()
			snap := s.notifStore().Snapshot()
			if snap["outbox_pending"] != 0 || snap["malformed"] != uint64(0) {
				log.Printf("[nx-penne] penne: %v", snap)
			}
		}
	}
}

// penneRenewPresence keeps alive what this console has already published. The
// console publishes on change only, so between changes its people would fall
// out of their lease and read as offline.
func (s *server) penneRenewPresence(sess *penneSession) {
	sess.published.Range(func(user, device any) bool {
		s.renewDevicePresence(user.(string), device.(string))
		return true
	})
	// A console that reconnected has published nothing on this connection, so the pairs above
	// are empty and its claim from the previous one would lapse two minutes later (2026-10-15:
	// leia read offline to everyone, no renew reached the core in 45 minutes). The user the
	// session belongs to is enough: the core renews every claim a console made for them.
	if sess.user != "" {
		s.renewDevicePresence(sess.user, "")
	}
}

// penneWakeConsole replays what is owed to every profile on this console, not
// only the user the connection was registered for.
func (s *server) penneWakeConsole(sess *penneSession) {
	s.penneWake(sess.user)
	for _, u := range s.notifStore().UsersOn(sess.penneID) {
		if u != sess.user {
			s.penneWake(u)
		}
	}
}

// penneMarkDelivered settles a written delivery against whichever profile on
// this console owns it. A connection is filed under the profile that
// registered it, so a notification for the other profile on the same console
// was never found here and was re-sent on every wake (2026-09-20: the same
// presence_updated written once a second).
func (s *server) penneMarkDelivered(sess *penneSession, id string) {
	store := s.notifStore()
	now := time.Now()
	store.MarkDelivered(sess.user, id, now)
	for _, u := range store.UsersOn(sess.penneID) {
		if u != sess.user {
			store.MarkDelivered(u, id, now)
		}
	}
}

// penneMarkFailed schedules the retry against whichever profile owns it.
func (s *server) penneMarkFailed(sess *penneSession, id string, err error) {
	store := s.notifStore()
	now := time.Now()
	store.MarkFailed(sess.user, id, err.Error(), now)
	for _, u := range store.UsersOn(sess.penneID) {
		if u != sess.user {
			store.MarkFailed(u, id, err.Error(), now)
		}
	}
}
