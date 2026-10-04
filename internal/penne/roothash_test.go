package penne

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// Round-trip against the shape the console actually sent.
func TestRootHashRoundTrip(t *testing.T) {
	in := []RootEntry{
		{Name: "c-appearance", Digest: bytes.Repeat([]byte{0xa1}, 20)},
		{Name: "c-friends", Digest: bytes.Repeat([]byte{0xb2}, 20)},
	}
	frame := BuildRootHash(in, 20, 1789204471, 1789208071)
	env, err := DecodeEnvelope(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Type() != TypeRootHash {
		t.Fatalf("type = %s", env.TypeName())
	}
	pay, ok := env.Payload()
	if !ok {
		t.Fatal("no payload")
	}
	got := ParseRootHash(pay)
	if len(got) != len(in) {
		t.Fatalf("entries = %d, want %d", len(got), len(in))
	}
	for i := range in {
		if got[i].Name != in[i].Name || !bytes.Equal(got[i].Digest, in[i].Digest) {
			t.Errorf("entry %d = %q/%x", i, got[i].Name, got[i].Digest)
		}
	}
}

// The captured frame is the specification: a RootHash we build must have the
// console's own table layout — vtable before the table, a +14 soffset, five
// slots at 7/8/12/16/24 and a 32-byte table. The timestamps are 64-bit, which
// is what puts slot 4 at 24 rather than 20.
func TestRootHashMatchesTheConsolesTableLayout(t *testing.T) {
	frame := BuildRootHash([]RootEntry{{Name: "c-friends", Digest: make([]byte, 20)}}, 20, 1789204471, 1789208071)
	root := int(binary.LittleEndian.Uint32(frame))
	soffset := int(int32(binary.LittleEndian.Uint32(frame[root:])))
	if soffset <= 0 {
		t.Fatalf("soffset = %d; the vtable must sit before the table it describes", soffset)
	}
	vt := root - soffset
	vsize := int(binary.LittleEndian.Uint16(frame[vt:]))
	tsize := int(binary.LittleEndian.Uint16(frame[vt+2:]))
	slots := map[int]int{}
	for i := 0; i < (vsize-4)/2; i++ {
		slots[i] = int(binary.LittleEndian.Uint16(frame[vt+4+2*i:]))
	}
	want := map[int]int{0: 7, 1: 8, 2: 12, 3: 16, 4: 24}
	if vsize != 14 || tsize != 32 || !reflect.DeepEqual(slots, want) {
		t.Errorf("vsize=%d tsize=%d slots=%v; want 14/32/%v", vsize, tsize, slots, want)
	}
}
