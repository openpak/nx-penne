package penne

import "testing"

// The nesting is the whole point: our old BuildPutRecord put {name, value}
// straight into envelope slot 1, and the console's parser reads slot 0 of that
// table as a vector length and aborts. This walks the frame back down the
// recovered path -- envelope → PutRecord → entry vector → kind-1 message →
// meta -- so a regression in any layer fails here instead of on hardware.
func TestBuildMessageNestsAsTheParserReads(t *testing.T) {
	want := Message{
		Name:      "friend_request_authorized",
		Type:      1,
		Receivers: "0x010000000000000e",
		AccountID: "e1c0f4a2b3d4e5f60718293a4b5c6d7e",
		Body:      `{"type":"friend_request_authorized","id":"ev1"}`,
		DeliverAt: 1789208071,
	}
	env, err := DecodeEnvelope(BuildMessage(want, 1789204471, 1789208071))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Type() != TypePutRecord {
		t.Fatalf("envelope = %s, want PutRecord", env.TypeName())
	}
	if tag, ok := env.Root().String(2); !ok || tag != "NX" {
		t.Errorf("envelope slot 2 = %q (ok=%v), want the string NX", tag, ok)
	}
	payload, ok := env.Payload()
	if !ok {
		t.Fatal("no payload")
	}
	if n, ok := payload.VectorLen(0); !ok || n != 1 {
		t.Fatalf("entry vector = %d (ok=%v), want exactly one -- the parser aborts otherwise", n, ok)
	}
	if v, ok := payload.U8(1); !ok || v != 1 {
		t.Errorf("PutRecord slot 1 = %d (ok=%v), want 1", v, ok)
	}
	got, ok := ParseMessage(payload)
	if !ok {
		t.Fatal("entry is not a kind-1 message")
	}
	if got != want {
		t.Errorf("round trip:\n got %+v\nwant %+v", got, want)
	}
}

// deliverAt absent means "now"; a zero written as a field would be a delivery
// scheduled at the epoch.
func TestBuildMessageOmitsAZeroDeliverAt(t *testing.T) {
	env, _ := DecodeEnvelope(BuildMessage(Message{
		Name: "presence_updated", Receivers: "penne", AccountID: "00", Body: "{}",
	}, 1, 2))
	payload, _ := env.Payload()
	entry, _ := payload.VectorTable(0, 0)
	msg, _ := entry.Table(1)
	if _, ok := msg.U64(5); ok {
		t.Error("deliverAt written for a zero value; absent is what means now")
	}
}

func TestMessageTooLong(t *testing.T) {
	long := make([]byte, 4096)
	if !(Message{Body: string(long)}).TooLong() {
		t.Error("a 4096-byte body is over the parser's bound")
	}
	if (Message{Name: "c-friends.inv.subsTypes", Body: "{}"}).TooLong() {
		t.Error("an ordinary message is not too long")
	}
}
