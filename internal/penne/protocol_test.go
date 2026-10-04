package penne

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// ---------- hand-assembled fixtures ----------
//
// The fixture below is assembled byte by byte from the wire format and the
// recovered constants, NOT from this package's builder, so the decoder is
// checked against independent construction rather than its own encoder's
// output. Derivation for the Pong fixture (48 bytes, all numbers little-endian):
//
//	[ 0, 4)  root uoffset = 12            -> root table at 12
//	[ 4, 6)  root vtable vsize = 8        (4 + 2 fields)
//	[ 6, 8)  root tsize = 12              (soffset 4 + u8 @4 pad + u32 @8)
//	[ 8,10)  root f0 offset = 4           (type byte at table+4)
//	[10,12)  root f1 offset = 8           (payload uoffset at table+8)
//	[12,16)  root soffset = 8             -> root vtable at 12-8 = 4
//	[16,17)  type = 0x11 (Pong)
//	[20,24)  payload uoffset = 16         -> payload table at 20+16 = 36
//	[28,30)  payload vtable vsize = 6     (4 + 1 field)
//	[30,32)  payload tsize = 12           (soffset 4 + u64 @4)
//	[32,34)  payload f0 offset = 4
//	[36,40)  payload soffset = 8          -> payload vtable at 36-8 = 28
//	[40,48)  Pong field 0 u64

// handPongFixture builds the documented 48-byte fixture with explicit writes so
// the derivation above stays auditable line by line.
func handPongFixture(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 48)
	putU32 := func(off int, v uint32) {
		buf[off] = byte(v)
		buf[off+1] = byte(v >> 8)
		buf[off+2] = byte(v >> 16)
		buf[off+3] = byte(v >> 24)
	}
	putU16 := func(off int, v uint16) {
		buf[off] = byte(v)
		buf[off+1] = byte(v >> 8)
	}
	putU32(0, 12)      // root table at 12
	putU16(4, 8)       // root vtable size
	putU16(6, 12)      // root table size
	putU16(8, 4)       // f0 offset
	putU16(10, 8)      // f1 offset
	putU32(12, 8)      // root soffset: 12 - 4
	buf[16] = TypePong // union type
	putU32(20, 16)     // payload uoffset: 36 - 20
	putU16(28, 6)      // payload vtable size
	putU16(30, 12)     // payload table size
	putU16(32, 4)      // payload f0 offset
	putU32(36, 8)      // payload soffset: 36 - 28
	var v uint64 = 0x1122334455667788
	for i := 0; i < 8; i++ { // Pong field 0
		buf[40+i] = byte(v >> (8 * i))
	}
	return buf
}

func TestDecodeHandAssembledPong(t *testing.T) {
	buf := handPongFixture(t)
	env, err := DecodeEnvelope(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Type() != TypePong {
		t.Fatalf("type = %#x (%s), want Pong", env.Type(), env.TypeName())
	}
	p, ok := env.Payload()
	if !ok {
		t.Fatal("payload missing")
	}
	v, ok := p.U64(0)
	if !ok {
		t.Fatal("payload field 0 missing")
	}
	if v != 0x1122334455667788 {
		t.Fatalf("field 0 = %#x, want 0x1122334455667788", v)
	}
}

func TestBuilderRoundTripsAgainstFixtureSemantics(t *testing.T) {
	// Same message as the hand fixture, built with this package's builder: the
	// decoded semantics must agree even though the byte layout may differ.
	env, err := DecodeEnvelope(BuildPong(0x1122334455667788))
	if err != nil {
		t.Fatalf("decode built buffer: %v", err)
	}
	if env.Type() != TypePong || env.TypeName() != "Pong" {
		t.Fatalf("type = %s, want Pong", env.TypeName())
	}
	p, _ := env.Payload()
	v, ok := p.U64(0)
	if !ok || v != 0x1122334455667788 {
		t.Fatalf("field 0 = %#x (ok=%v), want the echoed value", v, ok)
	}
}

func TestEnvelopeWithoutPayload(t *testing.T) {
	t.Run("absent field", func(t *testing.T) {
		b := NewBuilder(32)
		// Root with the type field only: slot 1 never written -> absent.
		b.StartTable(1)
		b.PrependU8Slot(0, TypeSyncComplete)
		root := b.EndTable()
		b.prep(b.minalign, 4)
		b.placeU32(uint32(b.Offset() + 4 - root))
		env, err := DecodeEnvelope(b.Bytes())
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if env.Type() != TypeSyncComplete {
			t.Fatalf("type = %s, want SyncComplete", env.TypeName())
		}
		if _, ok := env.Payload(); ok {
			t.Fatal("absent payload field decoded as present")
		}
	})
	t.Run("empty payload table", func(t *testing.T) {
		// A table with a vtable but no entries (e.g. Hi, SyncComplete,
		// SubscriptionListRequest, which the module logs with no fields) is
		// present but fieldless.
		b := NewBuilder(32)
		payload := b.EmptyPayload()
		buf := b.FinishEnvelope(TypeSyncComplete, payload)
		env, err := DecodeEnvelope(buf)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		p, ok := env.Payload()
		if !ok {
			t.Fatal("empty payload table decoded as absent")
		}
		if _, ok := p.U64(0); ok {
			t.Fatal("fieldless payload produced a field")
		}
	})
}

func TestSubscribeTopicSlotIs23(t *testing.T) {
	// The one slot the firmware findings pinned independently: the client's
	// SubscribeTopic builder is invoked with discriminator 0x17. If this
	// constant drifts from the recovered table, everything built on it drifts.
	if TypeSubscribeTopic != 0x17 {
		t.Fatalf("SubscribeTopic = %#x, want 0x17", TypeSubscribeTopic)
	}
}

func TestSlotTableCoversRecoveredNames(t *testing.T) {
	for slot, want := range map[byte]string{
		TypeAck:                     "Ack",
		TypePing:                    "Ping",
		TypeNack:                    "Nack",
		TypeDAPresence:              "DAPresence",
		TypeResendRequest:           "ResendRequest",
		TypeSubscriptionList:        "SubscriptionList",
		TypeSubscriptionUpdated:     "SubscriptionUpdated",
		TypePresenceNotifyRequest:   "PresenceNotifyRequest",
		TypeSubscriptionListRequest: "SubscriptionListRequest",
		TypeHi:                      "Hi",
		TypeDenySubscribe:           "DenySubscribe",
		TypeReset:                   "Reset",
		TypePowerState:              "PowerState",
	} {
		if got := TypeName(slot); got != want {
			t.Errorf("TypeName(%#x) = %q, want %q", slot, got, want)
		}
	}
	if got := TypeName(200); !strings.HasPrefix(got, "Unknown") {
		t.Errorf("TypeName(200) = %q, want an Unknown name", got)
	}
}

func TestEventEnvelopeCarriesJSONString(t *testing.T) {
	body := `{"type":"friend_request_received","id":"abc","from":"0123456789abcdef"}`
	env, err := DecodeEnvelope(BuildEvent(body))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Type() != TypeMessageRequest {
		t.Fatalf("carrier = %s, want MessageRequest (the marked hypothesis)", env.TypeName())
	}
	p, ok := env.Payload()
	if !ok {
		t.Fatal("payload missing")
	}
	got, ok := p.String(0)
	if !ok || got != body {
		t.Fatalf("payload string = %q (ok=%v), want the event JSON", got, ok)
	}
}

// ---------- framing ----------

func TestFrameRoundTrip(t *testing.T) {
	payloads := [][]byte{nil, {}, []byte("x"), bytes.Repeat([]byte{0x1f}, 4096)}
	var wire []byte
	for _, p := range payloads {
		wire = AppendFrame(wire, p)
	}
	fr := NewFrameReader(bytes.NewReader(wire), 0)
	for i, want := range payloads {
		got, err := fr.Next()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d = %d bytes, want %d", i, len(got), len(want))
		}
	}
	if _, err := fr.Next(); err != io.EOF {
		t.Fatalf("final read = %v, want io.EOF", err)
	}
}

func TestFrameTooLargeIsRejectedWithoutAllocating(t *testing.T) {
	wire := AppendFrame(nil, []byte("irrelevant"))
	// Claim a length above the bound; the reader must refuse before touching
	// the body, so the two bytes that follow are never read.
	wire[0], wire[1], wire[2] = 0xff, 0xff, 0xff // 0x00ffffff > 1 MiB
	fr := NewFrameReader(bytes.NewReader(append(wire, 1, 2)), MaxFrameSize)
	if _, err := fr.Next(); err != ErrFrameTooLarge {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
}

func TestPartialFramesFailNotHang(t *testing.T) {
	t.Run("truncated length prefix", func(t *testing.T) {
		fr := NewFrameReader(bytes.NewReader([]byte{4, 0}), 0)
		if _, err := fr.Next(); err == nil {
			t.Fatal("truncated length prefix read as success")
		}
	})
	t.Run("truncated body", func(t *testing.T) {
		wire := AppendFrame(nil, []byte("0123456789"))
		fr := NewFrameReader(bytes.NewReader(wire[:7]), 0)
		_, err := fr.Next()
		if err == nil {
			t.Fatal("truncated body read as success")
		}
	})
	t.Run("zero-length frame then clean EOF", func(t *testing.T) {
		fr := NewFrameReader(bytes.NewReader(AppendFrame(nil, nil)), 0)
		got, err := fr.Next()
		if err != nil || len(got) != 0 {
			t.Fatalf("got %d bytes, %v", len(got), err)
		}
		if _, err := fr.Next(); err != io.EOF {
			t.Fatalf("second read = %v, want io.EOF", err)
		}
	})
}

// ---------- malformed envelopes must never panic ----------

func TestMalformedBuffersDecodeWithoutPanic(t *testing.T) {
	good := handPongFixture(t)
	var inputs [][]byte
	for n := 0; n <= len(good); n++ {
		inputs = append(inputs, good[:n]) // every truncation
	}
	flipped := append([]byte(nil), good...)
	flipped[0] = 0x7f // root offset beyond the buffer
	inputs = append(inputs, flipped, nil, []byte{0}, []byte{0xff, 0xff, 0xff, 0xff, 0xff})
	// Corrupt every single byte position, too: bounds checks must hold under
	// any vtable/offset content.
	for i := range good {
		bad := append([]byte(nil), good...)
		bad[i] ^= 0xff
		inputs = append(inputs, bad)
	}
	for i, in := range inputs {
		env, err := DecodeEnvelope(in)
		if err != nil {
			continue
		}
		// Whatever decodes must survive a full field walk.
		env.Type()
		if p, ok := env.Payload(); ok {
			for f := 0; f < 8; f++ {
				p.U8(f)
				p.U16(f)
				p.U32(f)
				p.U64(f)
				p.Bool(f)
				p.String(f)
				p.VectorLen(f)
				p.VectorTable(f, 0)
				p.VectorTable(f, 3)
				if st, ok := p.Table(f); ok {
					st.String(0)
					st.Table(0)
				}
			}
		}
		_ = i
	}
}

func TestAbsentFieldsReadAsAbsent(t *testing.T) {
	b := NewBuilder(32)
	b.StartTable(1)
	b.PrependU64Slot(0, 42)
	payload := b.EndTable()
	buf := b.FinishEnvelope(TypePing, payload)
	env, err := DecodeEnvelope(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	p, ok := env.Payload()
	if !ok {
		t.Fatal("payload missing")
	}
	if _, ok := p.U64(5); ok {
		t.Error("absent slot 5 read as present")
	}
	if _, ok := p.String(0); ok {
		t.Error("u64 slot 0 read as a string")
	}
	// Ping's recovered shape is three u64 fields at slots 0..2; slot 2 absent
	// here must not be confused with slot 0's value.
	if v, ok := p.U64(0); !ok || v != 42 {
		t.Errorf("slot 0 = %d (ok=%v), want 42", v, ok)
	}
}

// Meta carries four slots. The console reads slot 4 for every message whose
// type is not 2, without checking the vtable is long enough, so a three-slot
// Meta was read past its end and the message dropped after being acked
// (docs/penne-message-delivery-2026-09-20.md §1.4).
func TestMessageMetaCarriesTheSlotTheConsoleAlwaysReads(t *testing.T) {
	frame := BuildMessage(Message{
		Name: "friend_deleted", Type: 1, Receivers: "0x010000000000000e",
		AccountID: "1000000000a100010000000000000001", Body: `{"type":"friend_deleted"}`,
	}, 100, 3700)
	env, err := DecodeEnvelope(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	payload, ok := env.Payload()
	if !ok {
		t.Fatal("no payload")
	}
	m, ok := ParseMessage(payload)
	if !ok {
		t.Fatal("not a kind-1 message")
	}
	entry, _ := payload.VectorTable(0, 0)
	msg, _ := entry.Table(1)
	meta, _ := msg.Table(2)
	if _, present := meta.String(4); !present {
		t.Fatal("Meta slot 4 is absent; the console drops the message")
	}
	if len(m.Tag) > 39 {
		t.Fatalf("tag is %d chars, the console's limit is 39", len(m.Tag))
	}
	if m.AccountID != "1000000000a100010000000000000001" || m.Receivers != "0x010000000000000e" {
		t.Fatalf("meta round-trip: %+v", m)
	}
}

// The Ack is one string: the name the console read out of our frame, and the
// exact string it expects back after a request of its own.
func TestAckCarriesTheNameAsAString(t *testing.T) {
	env, err := DecodeEnvelope(BuildAck("topic.subscription"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Type() != TypeAck {
		t.Fatalf("type %s", env.TypeName())
	}
	payload, _ := env.Payload()
	if got, ok := payload.String(0); !ok || got != "topic.subscription" {
		t.Fatalf("ack string = %q (ok=%v)", got, ok)
	}
}
