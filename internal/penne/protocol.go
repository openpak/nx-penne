// Package penne implements the Penne (NPNS) frontline wire protocol: the
// length-prefixed binary frames and the FlatBuffers-compatible message
// envelopes the persistent notification connection carries.
//
// Provenance of every recovered constant lives in docs/penne-protocol.md
// (nx-baas). In short: the union slot table and envelope layout were recovered
// from the Horizon 22.5.0 NPNS module (static analysis, private working
// directory), the outbound framing from the same module's send path, and the
// FlatBuffers table layout from the public wire-format specification. Anything
// not yet confirmed is marked hypothesis at its definition and must not be
// presented as interoperable until a runtime capture proves it.
//
// This is an independent implementation: it follows the documented wire format
// and the recovered constants, and carries no third-party code.
package penne

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ---------- framing ----------
//
// A frame is a four-byte little-endian length followed by that many bytes of
// buffer. The 22.5.0 NPNS send path passes exactly this shape (a body reader of
// "four-byte length followed by the binary buffer") to its HTTP transport;
// server-to-client framing is not yet runtime-confirmed and is treated as the
// symmetric case, per docs/penne-protocol.md.

const (
	// LengthPrefixSize is the size of a frame's length prefix.
	LengthPrefixSize = 4
	// MaxFrameSize bounds a single frame. A malformed or hostile stream must
	// fail this bound instead of growing memory without limit.
	MaxFrameSize = 1 << 20
)

// ErrFrameTooLarge is returned for a frame whose declared length exceeds the
// reader's bound.
var ErrFrameTooLarge = errors.New("penne: frame length exceeds the maximum frame size")

// AppendFrame appends one length-prefixed frame to dst.
func AppendFrame(dst, payload []byte) []byte {
	var head [LengthPrefixSize]byte
	binary.LittleEndian.PutUint32(head[:], uint32(len(payload)))
	dst = append(dst, head[:]...)
	return append(dst, payload...)
}

// WriteFrame writes one length-prefixed frame to w.
func WriteFrame(w io.Writer, payload []byte) error {
	var head [LengthPrefixSize]byte
	binary.LittleEndian.PutUint32(head[:], uint32(len(payload)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// FrameReader reads length-prefixed frames off a stream. Frames larger than max
// fail with ErrFrameTooLarge; a stream that ends mid-frame fails with
// io.ErrUnexpectedEOF; a clean end of stream is io.EOF.
type FrameReader struct {
	r    io.Reader
	max  int
	head [LengthPrefixSize]byte
	buf  []byte
}

// NewFrameReader reads frames of at most max bytes (MaxFrameSize when 0).
func NewFrameReader(r io.Reader, max int) *FrameReader {
	if max <= 0 {
		max = MaxFrameSize
	}
	return &FrameReader{r: r, max: max}
}

// Next returns the next frame payload. The returned slice aliases an internal
// buffer and stays valid only until the following call.
func (fr *FrameReader) Next() ([]byte, error) {
	if _, err := io.ReadFull(fr.r, fr.head[:]); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("penne: reading frame length: %w", err)
	}
	n := binary.LittleEndian.Uint32(fr.head[:])
	if int(n) > fr.max {
		return nil, ErrFrameTooLarge
	}
	if cap(fr.buf) < int(n) {
		fr.buf = make([]byte, n)
	}
	buf := fr.buf[:n]
	if _, err := io.ReadFull(fr.r, buf); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("penne: frame truncated after length prefix: %w", io.ErrUnexpectedEOF)
		}
		return nil, fmt.Errorf("penne: reading frame body: %w", err)
	}
	return buf, nil
}

// ---------- message slots ----------
//
// The union discriminator of an envelope names its payload type. Slot numbers
// below were recovered from the 22.5.0 NPNS module's message-name table
// (module-relative RVA 0x168968; slot value == discriminator byte). The slot
// the findings had already pinned independently (SubscribeTopic = 0x17 = 23)
// matches this table, which is what makes the rest of the ordering usable.

const (
	TypeNONE                    = 0x00
	TypeMessageRequest          = 0x01
	TypePublishRequest          = 0x02
	TypeKickRequest             = 0x03
	TypePutRecord               = 0x04
	TypeDeleteRecord            = 0x05
	TypeRootHash                = 0x06
	TypeLeafHash                = 0x07
	TypeSyncComplete            = 0x08
	TypeAck                     = 0x09
	TypeHandoverRequest         = 0x0a
	TypeHandoverResponse        = 0x0b
	TypeHandoverResult          = 0x0c
	TypeReset                   = 0x0d
	TypePowerState              = 0x0e
	TypeDebugDisconnect         = 0x0f
	TypePing                    = 0x10
	TypePong                    = 0x11
	TypeDebugUpdateRecord       = 0x12
	TypeDebugDeleteRecord       = 0x13
	TypeIdle                    = 0x14
	TypePutRequest              = 0x15
	TypeDeleteRequest           = 0x16
	TypeSubscribeTopic          = 0x17
	TypeNack                    = 0x18
	TypeSubscriptionList        = 0x19
	TypeResendRequest           = 0x1a
	TypeDAPresence              = 0x1b
	TypeSubscriptionListRequest = 0x1c
	TypeMyAccountMessageRequest = 0x1d
	TypeReloadLink              = 0x1e
	TypeSubscriptionUpdated     = 0x1f
	TypeHi                      = 0x20
	TypeOnset                   = 0x21
	TypePresenceNotifyRequest   = 0x22
	TypeDenySubscribe           = 0x23
	TypeTopicRead               = 0x24
	TypeCrewNotifyRequest       = 0x25
)

// typeName maps every recovered slot to its recovered name.
var typeName = [38]string{
	"NONE", "MessageRequest", "PublishRequest", "KickRequest",
	"PutRecord", "DeleteRecord", "RootHash", "LeafHash",
	"SyncComplete", "Ack", "HandoverRequest", "HandoverResponse",
	"HandoverResult", "Reset", "PowerState", "DebugDisconnect",
	"Ping", "Pong", "DebugUpdateRecord", "DebugDeleteRecord",
	"Idle", "PutRequest", "DeleteRequest", "SubscribeTopic",
	"Nack", "SubscriptionList", "ResendRequest", "DAPresence",
	"SubscriptionListRequest", "MyAccountMessageRequest", "ReloadLink", "SubscriptionUpdated",
	"Hi", "Onset", "PresenceNotifyRequest", "DenySubscribe",
	"TopicRead", "CrewNotifyRequest",
}

// TypeName names a slot; unknown slots read as "Unknown(n)".
func TypeName(t byte) string {
	if int(t) < len(typeName) {
		return typeName[t]
	}
	return fmt.Sprintf("Unknown(%d)", t)
}

// ---------- envelope reading ----------
//
// The envelope is a FlatBuffers-compatible table with a union pair: field 0 is
// the one-byte discriminator, field 1 the payload table (recovered from the
// 22.5.0 NPNS send path, which switches on vtable slot 0 as a byte and
// dereferences slot 1 as an indirect table). Table/vtable layout follows the
// public wire format. Every read is bounds-checked: a malformed buffer yields
// an error or absent fields, never a panic.

// Buffer is a received wire buffer.
type Buffer []byte

// Table is a table position inside a Buffer.
type Table struct {
	buf Buffer
	pos int
}

// ErrMalformed reports a buffer that does not decode as an envelope.
var ErrMalformed = errors.New("penne: malformed envelope")

// Envelope is a decoded message: a union slot plus its payload table.
type Envelope struct {
	root Table
}

// DecodeEnvelope parses a wire buffer into its envelope.
func DecodeEnvelope(buf Buffer) (Envelope, error) {
	if len(buf) < 4 {
		return Envelope{}, fmt.Errorf("%w: shorter than a root offset", ErrMalformed)
	}
	root := int(binary.LittleEndian.Uint32(buf))
	if root < 0 || root+4 > len(buf) {
		return Envelope{}, fmt.Errorf("%w: root offset %d out of range (len %d)", ErrMalformed, root, len(buf))
	}
	return Envelope{root: Table{buf: buf, pos: root}}, nil
}

// Type is the union discriminator (envelope field 0). Zero (NONE) when absent.
func (e Envelope) Type() byte {
	v, _ := e.root.u8(0)
	return v
}

// TypeName names the envelope's slot.
func (e Envelope) TypeName() string { return TypeName(e.Type()) }

// Payload returns the union payload table; ok is false for NONE or an absent
// field.
func (e Envelope) Payload() (Table, bool) { return e.root.table(1) }

// Table exposes the root table itself for field access beyond the union pair
// (root fields >= 2 are not yet recovered; nothing may assume them).
func (e Envelope) Root() Table { return e.root }

// Type reads the table's field id as a byte (union discriminators are bytes).
func (t Table) Type(id int) (byte, bool) { return t.u8(id) }

// U8 reads field id as a uint8.
func (t Table) U8(id int) (uint8, bool) { return t.u8(id) }

// U16 reads field id as a uint16.
func (t Table) U16(id int) (uint16, bool) { return t.u16(id) }

// U32 reads field id as a uint32.
func (t Table) U32(id int) (uint32, bool) { return t.u32(id) }

// U64 reads field id as a uint64.
func (t Table) U64(id int) (uint64, bool) { return t.u64(id) }

// Bool reads field id as a boolean.
func (t Table) Bool(id int) (bool, bool) {
	v, ok := t.u8(id)
	return v != 0, ok
}

// String reads field id as a string.
func (t Table) String(id int) (string, bool) {
	pos, ok := t.uoffset(id)
	if !ok {
		return "", false
	}
	if pos+4 > len(t.buf) {
		return "", false
	}
	n := int(binary.LittleEndian.Uint32(t.buf[pos:]))
	if n < 0 || pos+4+n > len(t.buf) {
		return "", false
	}
	return string(t.buf[pos+4 : pos+4+n]), true
}

// Table reads field id as an indirect table reference.
func (t Table) Table(id int) (Table, bool) { return t.table(id) }

// VectorLen reads field id as a vector and returns its element count.
// Bytes reads a [ubyte] vector field.
func (t Table) Bytes(id int) ([]byte, bool) {
	pos, ok := t.uoffset(id)
	if !ok || pos+4 > len(t.buf) {
		return nil, false
	}
	n := int(binary.LittleEndian.Uint32(t.buf[pos:]))
	if n < 0 || pos+4+n > len(t.buf) {
		return nil, false
	}
	return t.buf[pos+4 : pos+4+n], true
}

func (t Table) VectorLen(id int) (int, bool) {
	pos, ok := t.uoffset(id)
	if !ok || pos+4 > len(t.buf) {
		return 0, false
	}
	n := int(binary.LittleEndian.Uint32(t.buf[pos:]))
	if n < 0 || pos+4+4*n > len(t.buf) {
		return 0, false
	}
	return n, true
}

// VectorTable reads element i of the vector at field id as a table.
func (t Table) VectorTable(id, i int) (Table, bool) {
	pos, ok := t.uoffset(id)
	if !ok || pos+4 > len(t.buf) {
		return Table{}, false
	}
	n := int(binary.LittleEndian.Uint32(t.buf[pos:]))
	if i < 0 || i >= n {
		return Table{}, false
	}
	elem := pos + 4 + 4*i
	if elem+4 > len(t.buf) {
		return Table{}, false
	}
	next := elem + int(binary.LittleEndian.Uint32(t.buf[elem:]))
	if next < 0 || next+4 > len(t.buf) {
		return Table{}, false
	}
	return Table{buf: t.buf, pos: next}, true
}

// fieldOff returns the field data's offset from the table start.
func (t Table) fieldOff(id int) (int, bool) {
	if t.pos < 0 || t.pos+4 > len(t.buf) {
		return 0, false
	}
	vtRel := int(int32(binary.LittleEndian.Uint32(t.buf[t.pos:])))
	vpos := t.pos - vtRel
	if vpos < 0 || vpos+4 > len(t.buf) {
		return 0, false
	}
	vsize := int(binary.LittleEndian.Uint16(t.buf[vpos:]))
	if vsize < 4 || vpos+vsize > len(t.buf) {
		return 0, false
	}
	foffIdx := 4 + 2*id
	if foffIdx+2 > vsize {
		return 0, false
	}
	off := int(binary.LittleEndian.Uint16(t.buf[vpos+foffIdx:]))
	if off == 0 || t.pos+off >= len(t.buf) {
		return 0, false // absent field (FlatBuffers omits defaults) or out of range
	}
	return off, true
}

func (t Table) u8(id int) (uint8, bool) {
	off, ok := t.fieldOff(id)
	if !ok || t.pos+off >= len(t.buf) {
		return 0, false
	}
	return t.buf[t.pos+off], true
}

func (t Table) u16(id int) (uint16, bool) {
	off, ok := t.fieldOff(id)
	if !ok || t.pos+off+2 > len(t.buf) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(t.buf[t.pos+off:]), true
}

func (t Table) u32(id int) (uint32, bool) {
	off, ok := t.fieldOff(id)
	if !ok || t.pos+off+4 > len(t.buf) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(t.buf[t.pos+off:]), true
}

func (t Table) u64(id int) (uint64, bool) {
	off, ok := t.fieldOff(id)
	if !ok || t.pos+off+8 > len(t.buf) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(t.buf[t.pos+off:]), true
}

func (t Table) uoffset(id int) (int, bool) {
	off, ok := t.fieldOff(id)
	if !ok {
		return 0, false
	}
	fieldPos := t.pos + off
	if fieldPos+4 > len(t.buf) {
		return 0, false
	}
	next := fieldPos + int(binary.LittleEndian.Uint32(t.buf[fieldPos:]))
	if next < 0 || next+4 > len(t.buf) {
		return 0, false
	}
	return next, true
}

func (t Table) table(id int) (Table, bool) {
	pos, ok := t.uoffset(id)
	if !ok {
		return Table{}, false
	}
	return Table{buf: t.buf, pos: pos}, true
}

// ---------- envelope building ----------
//
// A builder for the same wire format, used for the server-to-client direction.
// It writes back to front as the format requires. Vtable deduplication is
// deliberately omitted: it is an optimisation, not a correctness requirement.

// Builder assembles a wire buffer.
type Builder struct {
	buf       []byte
	head      int
	minalign  int
	vtable    []int
	fieldLow  int
	objectEnd int
}

// NewBuilder creates a builder whose initial buffer holds size bytes.
func NewBuilder(size int) *Builder {
	if size < 16 {
		size = 16
	}
	buf := make([]byte, size)
	return &Builder{buf: buf, head: size, minalign: 1}
}

// Offset is the distance from the buffer end to the write head.
func (b *Builder) Offset() int { return len(b.buf) - b.head }

// Bytes returns the finished buffer.
func (b *Builder) Bytes() []byte { return b.buf[b.head:] }

func (b *Builder) grow(need int) {
	if b.head >= need {
		return
	}
	size := len(b.buf) * 2
	for size-b.head < need {
		size *= 2
	}
	base := size - (len(b.buf) - b.head)
	nbuf := make([]byte, size)
	copy(nbuf[base:], b.buf[b.head:])
	b.buf, b.head = nbuf, base
}

func (b *Builder) place(v byte) {
	b.grow(1)
	b.head--
	b.buf[b.head] = v
}

// prep aligns the head so that, after additional more bytes, a field of the
// given size lands size-aligned from the buffer end.
func (b *Builder) prep(size, additional int) {
	if size > b.minalign {
		b.minalign = size
	}
	// align so that, after `additional` further bytes, a field of `size`
	// bytes lands size-aligned from the buffer end. (-v)&(size-1) is v's
	// complement to the next multiple of size; ^v would be off by one.
	align := (-(len(b.buf) - b.head + additional)) & (size - 1)
	for i := 0; i < align; i++ {
		b.place(0)
	}
}

func (b *Builder) placeU16(v uint16) {
	b.grow(2)
	b.head -= 2
	binary.LittleEndian.PutUint16(b.buf[b.head:], v)
}

func (b *Builder) placeU32(v uint32) {
	b.grow(4)
	b.head -= 4
	binary.LittleEndian.PutUint32(b.buf[b.head:], v)
}

func (b *Builder) placeU64(v uint64) {
	b.grow(8)
	b.head -= 8
	binary.LittleEndian.PutUint64(b.buf[b.head:], v)
}

// CreateString writes a string and returns its offset.
func (b *Builder) CreateString(s string) int {
	b.prep(4, len(s)+1)
	b.place(0) // NUL terminator as the format prescribes
	for i := len(s) - 1; i >= 0; i-- {
		b.place(s[i])
	}
	b.placeU32(uint32(len(s)))
	return b.Offset()
}

// CreateByteVector writes a [ubyte] vector and returns its offset.
func (b *Builder) CreateByteVector(v []byte) int {
	b.prep(4, len(v))
	for i := len(v) - 1; i >= 0; i-- {
		b.place(v[i])
	}
	b.placeU32(uint32(len(v)))
	return b.Offset()
}

// CreateOffsetVector writes a vector of offsets (to tables or strings) and
// returns its offset. Elements are written back to front, each as the distance
// from its own position to the target, which is how a reader resolves them.
func (b *Builder) CreateOffsetVector(offs []int) int {
	b.prep(4, 4*len(offs))
	for i := len(offs) - 1; i >= 0; i-- {
		b.prep(4, 0)
		b.placeU32(uint32(b.Offset() + 4 - offs[i]))
	}
	b.placeU32(uint32(len(offs)))
	return b.Offset()
}

// StartTable begins a table; slot ids run 0..fields-1.
func (b *Builder) StartTable(fields int) {
	b.vtable = make([]int, fields)
	b.fieldLow = -1
	b.objectEnd = b.Offset()
}

func (b *Builder) addSlot(slot, size int) {
	if slot < 0 || slot >= len(b.vtable) {
		panic(fmt.Sprintf("penne: builder slot %d outside table of %d fields", slot, len(b.vtable)))
	}
	b.vtable[slot] = b.Offset()
	// Track the lowest field start (in end-distance coordinates) for the
	// table-size computation in EndTable; -1 marks a table with no fields.
	if low := b.Offset() - size; b.fieldLow < 0 || low < b.fieldLow {
		b.fieldLow = low
	}
}

// PrependU8Slot writes a byte field.
func (b *Builder) PrependU8Slot(slot int, v uint8) {
	b.prep(1, 0)
	b.place(v)
	b.addSlot(slot, 1)
}

// PrependU16Slot writes a uint16 field.
func (b *Builder) PrependU16Slot(slot int, v uint16) {
	b.prep(2, 0)
	b.placeU16(v)
	b.addSlot(slot, 2)
}

// PrependU32Slot writes a uint32 field.
func (b *Builder) PrependU32Slot(slot int, v uint32) {
	b.prep(4, 0)
	b.placeU32(v)
	b.addSlot(slot, 4)
}

// PrependU64Slot writes a uint64 field.
func (b *Builder) PrependU64Slot(slot int, v uint64) {
	b.prep(8, 0)
	b.placeU64(v)
	b.addSlot(slot, 8)
}

// PrependBoolSlot writes a boolean field.
func (b *Builder) PrependBoolSlot(slot int, v bool) {
	n := uint8(0)
	if v {
		n = 1
	}
	b.PrependU8Slot(slot, n)
}

// PrependUOffsetSlot writes a forward reference (string, table, vector).
func (b *Builder) PrependUOffsetSlot(slot, off int) {
	b.prep(4, 0)
	b.placeU32(uint32(b.Offset() + 4 - off))
	b.addSlot(slot, 4)
}

// EndTable finishes the table and returns its offset.
//
// The formulas below are derived in end-distance coordinates (doff = bytes
// written from the buffer end; a field recorded at doff F occupies final
// positions [L-F, L-F+size)) and were checked byte-for-byte against the
// hand-assembled fixture in protocol_test.go:
//
//	vtable entry_i = S - F_i        (field offset from the table start)
//	tsize          = S - fieldLow   (table bytes from its soffset on)
//	soffset        = W - S          (table start minus vtable start; negative,
//	                                 because back-to-front building puts the
//	                                 vtable above the table's soffset)
func (b *Builder) EndTable() int {
	// Trim trailing absent slots: the vtable only covers used fields.
	used := len(b.vtable)
	for used > 0 && b.vtable[used-1] == 0 {
		used--
	}
	// Reserve the soffset first, so the vtable written after it lands at a
	// LOWER address and the stored soffset is positive. The console's own
	// frames are built that way (a captured RootHash has root 24 with its
	// vtable at 10), and the reference builder does the same; a vtable sitting
	// above its table is legal arithmetic but not a shape the firmware's
	// verifier is ever handed.
	b.prep(4, 0)
	b.placeU32(0)
	S := b.Offset() // doff of the table start (where the soffset sits)

	for i := used - 1; i >= 0; i-- {
		b.prep(2, 0)
		off := uint16(0)
		if b.vtable[i] != 0 {
			off = uint16(S - b.vtable[i])
		}
		b.placeU16(off)
	}
	b.prep(2, 0)
	tsize := 4
	if b.fieldLow >= 0 {
		tsize = S - b.fieldLow
	}
	b.placeU16(uint16(tsize)) // table size
	b.prep(2, 0)
	b.placeU16(uint16(4 + 2*used)) // vtable size
	vOff := b.Offset()             // doff of the vtable's first byte

	// Patch the reserved soffset: table start minus vtable, positive because
	// the vtable was written later and therefore sits earlier in the buffer.
	binary.LittleEndian.PutUint32(b.buf[len(b.buf)-S:], uint32(int32(vOff-S)))
	b.vtable, b.fieldLow = nil, -1
	return S
}

// FinishEnvelope writes the root envelope table (union slot + payload) and the
// root offset, returning the finished buffer.
func (b *Builder) FinishEnvelope(slot byte, payload int) []byte {
	b.StartTable(2)
	b.PrependUOffsetSlot(1, payload)
	b.PrependU8Slot(0, slot)
	root := b.EndTable()
	b.prep(b.minalign, 4)
	b.placeU32(uint32(b.Offset() + 4 - root))
	return b.Bytes()
}

// EmptyPayload builds the offset of a table with no fields (the payload of
// messages recovered with empty payloads, e.g. Hi, SyncComplete,
// SubscriptionListRequest).
func (b *Builder) EmptyPayload() int {
	b.StartTable(0)
	return b.EndTable()
}

// ---------- recovered payload helpers ----------
//
// Only shapes the 22.5.0 module demonstrably reads or writes are provided.
// Field semantics beyond what the module's own logging showed remain unknown
// and are named for their position, not guessed meanings.

// BuildPong encodes a Pong envelope echoing value back on field 0. The 22.5.0
// module reads Pong as a single uint64 field; echoing the Ping's first field is
// the minimum-behaviour hypothesis (docs/penne-protocol.md).
func BuildPong(echo uint64) []byte {
	b := NewBuilder(64)
	b.StartTable(1)
	b.PrependU64Slot(0, echo)
	payload := b.EndTable()
	return b.FinishEnvelope(TypePong, payload)
}

// BuildAck encodes the Ack the console waits for after every request it
// sends. Its payload is one string, and the console aborts on an Ack with no
// request outstanding or one whose string differs from what it expects, so
// this is only ever a reply (docs/penne-message-delivery-2026-09-20.md §4).
func BuildAck(name string) []byte {
	b := NewBuilder(64 + len(name))
	s := b.CreateString(name)
	b.StartTable(1)
	b.PrependUOffsetSlot(0, s)
	payload := b.EndTable()
	return b.FinishEnvelope(TypeAck, payload)
}

// EntryName is slot 0 of the single entry a PutRecord or DeleteRecord carries:
// the record name, which is what its Ack echoes.
func EntryName(payload Table) (string, bool) {
	entry, ok := payload.VectorTable(0, 0)
	if !ok {
		return "", false
	}
	t, ok := entry.Table(1)
	if !ok {
		return "", false
	}
	return t.String(0)
}

// BuildPing encodes a Ping envelope with its three recovered uint64 fields
// (semantics not yet recovered; the caller supplies what it can defend).
func BuildPing(f0, f1, f2 uint64) []byte {
	b := NewBuilder(64)
	b.StartTable(3)
	b.PrependU64Slot(2, f2)
	b.PrependU64Slot(1, f1)
	b.PrependU64Slot(0, f0)
	payload := b.EndTable()
	return b.FinishEnvelope(TypePing, payload)
}

// BuildSubscriptionUpdated encodes a SubscriptionUpdated envelope with a single
// uint64 field (the shape the module logs). The meaning of the value is not
// recovered; callers pass what they can defend.
func BuildSubscriptionUpdated(v uint64) []byte {
	b := NewBuilder(64)
	b.StartTable(1)
	b.PrependU64Slot(0, v)
	payload := b.EndTable()
	return b.FinishEnvelope(TypeSubscriptionUpdated, payload)
}

// BuildHandoverResult encodes the message the console waits for as soon as the
// frontline response opens. Its state machine at RVA 0xd9730 reads exactly one
// message with a 70-second deadline and accepts only HandoverResult (0x0c) or
// Reset (0x0d); anything else is logged as
// "HandoverResult expected, but \"%s\"(%d) received." and fails the connection.
// The payload is a table whose field 0 is a byte: zero continues to normal
// operation, non-zero sends the console down the retry path [firmware].
func BuildHandoverResult(result byte) []byte {
	b := NewBuilder(32)
	b.StartTable(1)
	b.PrependU8Slot(0, result)
	payload := b.EndTable()
	return b.FinishEnvelope(TypeHandoverResult, payload)
}

// RootEntry is one namespace digest in a RootHash: the console sends four
// (c-appearance, c-friends, c-settings, c-storage), each with a 20-byte hash of
// everything it holds under that name [runtime capture, 2026-09-12].
type RootEntry struct {
	Name   string
	Digest []byte
}

// ParseRootHash reads the entries out of a RootHash payload table.
func ParseRootHash(payload Table) []RootEntry {
	n, ok := payload.VectorLen(0)
	if !ok {
		return nil
	}
	out := make([]RootEntry, 0, n)
	for i := 0; i < n; i++ {
		e, ok := payload.VectorTable(0, i)
		if !ok {
			continue
		}
		name, _ := e.String(0)
		digest, _ := e.Bytes(1)
		out = append(out, RootEntry{Name: name, Digest: digest})
	}
	return out
}

// BuildRootHash encodes a RootHash the way the console encodes its own:
// {0: u8 type, 1: payload, 2: u32 count, 3: u64 issued, 4: u64 expires}, the
// payload being one vector of {name, 20-byte digest} tables. The widths come
// from the captured frame's own table layout — slot 3 at +16 and slot 4 at +24
// in a 32-byte table leaves eight bytes for each timestamp
// [runtime capture of the console's own message, 2026-09-12].
func BuildRootHash(entries []RootEntry, count uint32, issued, expires uint64) []byte {
	return buildHashMessage(TypeRootHash, entries, count, issued, expires)
}

// buildRootPayload writes the {vector of {name, digest}} payload table.
func buildRootPayload(b *Builder, entries []RootEntry) int {
	offs := make([]int, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		name := b.CreateString(e.Name)
		digest := b.CreateByteVector(e.Digest)
		b.StartTable(2)
		b.PrependUOffsetSlot(1, digest)
		b.PrependUOffsetSlot(0, name)
		offs = append([]int{b.EndTable()}, offs...)
	}
	vec := b.CreateOffsetVector(offs)
	b.StartTable(1)
	b.PrependUOffsetSlot(0, vec)
	return b.EndTable()
}

// ParseLeafHash reads the console's leaf-reconciliation request. Captured from
// a live console [2026-09-12]:
//
//	LeafHash (0x07)
//	  0: string  namespace  "c-appearance"
//	  1: vector  the leaves IT holds under that namespace (empty in the capture)
//
// This is an offer, not a rejection: the console is listing its own leaves and
// waiting for ours back. Left unanswered it gives up after about seventy
// seconds, which is what every sync attempt did before this existed.
func ParseLeafHash(p Table) (namespace string, leaves []RootEntry) {
	namespace, _ = p.String(0)
	n, ok := p.VectorLen(1)
	if !ok {
		return namespace, nil
	}
	for i := 0; i < n; i++ {
		e, ok := p.VectorTable(1, i)
		if !ok {
			continue
		}
		name, _ := e.String(0)
		digest, _ := e.Bytes(1)
		leaves = append(leaves, RootEntry{Name: name, Digest: digest})
	}
	return namespace, leaves
}

// BuildLeafHashReply answers that request in the console's own shape: the
// namespace it asked about, then the leaves THIS server holds under it. Note
// the payload differs from RootHash's — a namespace string in slot 0 and the
// vector in slot 1, rather than the bare vector RootHash uses.
func BuildLeafHashReply(namespace string, leaves []RootEntry, count uint32, issued, expires uint64) []byte {
	b := NewBuilder(128 + 64*len(leaves))

	offs := make([]int, 0, len(leaves))
	for i := len(leaves) - 1; i >= 0; i-- {
		e := leaves[i]
		name := b.CreateString(e.Name)
		digest := b.CreateByteVector(e.Digest)
		b.StartTable(2)
		b.PrependUOffsetSlot(1, digest)
		b.PrependUOffsetSlot(0, name)
		offs = append([]int{b.EndTable()}, offs...)
	}
	vec := b.CreateOffsetVector(offs)
	ns := b.CreateString(namespace)
	b.StartTable(2)
	b.PrependUOffsetSlot(1, vec)
	b.PrependUOffsetSlot(0, ns)
	payload := b.EndTable()

	b.StartTable(5)
	b.PrependU64Slot(4, expires)
	b.PrependU64Slot(3, issued)
	b.PrependU32Slot(2, count)
	b.PrependUOffsetSlot(1, payload)
	b.PrependU8Slot(0, TypeLeafHash)
	root := b.EndTable()
	b.prep(b.minalign, 4)
	b.placeU32(uint32(b.Offset() + 4 - root))
	return b.Bytes()
}

func buildHashMessage(kind byte, entries []RootEntry, count uint32, issued, expires uint64) []byte {
	b := NewBuilder(128 + 64*len(entries))
	payload := buildRootPayload(b, entries)
	b.StartTable(5)
	b.PrependU64Slot(4, expires)
	b.PrependU64Slot(3, issued)
	b.PrependU32Slot(2, count)
	b.PrependUOffsetSlot(1, payload)
	b.PrependU8Slot(0, kind)
	root := b.EndTable()
	b.prep(b.minalign, 4)
	b.placeU32(uint32(b.Offset() + 4 - root))
	return b.Bytes()
}

// BuildRootHashMinimal encodes a RootHash with the two-slot envelope the
// handover uses (type and payload only). The console accepts that envelope for
// HandoverResult, so it is one of the candidates when a five-slot RootHash is
// refused.
func BuildRootHashMinimal(entries []RootEntry) []byte {
	b := NewBuilder(128 + 64*len(entries))
	payload := buildRootPayload(b, entries)
	b.StartTable(2)
	b.PrependUOffsetSlot(1, payload)
	b.PrependU8Slot(0, TypeRootHash)
	root := b.EndTable()
	b.prep(b.minalign, 4)
	b.placeU32(uint32(b.Offset() + 4 - root))
	return b.Bytes()
}

// BuildLeafHash encodes the same entry vector under the LeafHash slot: the
// state that waits for the sync accepts either type.
func BuildLeafHash(entries []RootEntry, count uint32, issued, expires uint64) []byte {
	return buildHashMessage(TypeLeafHash, entries, count, issued, expires)
}

// BuildEmpty encodes an envelope whose payload table has no fields. Hi (0x20),
// SyncComplete (0x08) and SubscriptionListRequest (0x1c) are logged by the
// module with no payload fields, so this is their shape.
func BuildEmpty(kind byte) []byte {
	b := NewBuilder(32)
	b.StartTable(0)
	payload := b.EndTable()
	return b.FinishEnvelope(kind, payload)
}

// BuildEvent encodes a delivered event: carrier slot MessageRequest with a
// single string field holding the event's JSON body. Both the carrier slot and
// the payload field are hypotheses pending a runtime capture -- they are the
// best-evidence candidates, not confirmed interoperability, and everything
// downstream must treat them as such (docs/penne-protocol.md).
func BuildEvent(jsonBody string) []byte {
	b := NewBuilder(64 + len(jsonBody))
	str := b.CreateString(jsonBody)
	b.StartTable(1)
	b.PrependUOffsetSlot(0, str)
	payload := b.EndTable()
	return b.FinishEnvelope(TypeMessageRequest, payload)
}

// ---------- kind-1 messages: the notification carrier ----------
//
// Recovered 2026-09-16 (docs/penne-record-shape-2026-09-16.md) from the
// console's own PutRecord frame and its parser at RVA 0x1dfbb0. A PutRecord
// payload is not {name, value}: it is a vector of entries, each tagged with a
// kind. Kind 2 is a stored record; kind 1 is a *message*, which is what a
// notification is — 0x1dc510 parses it, queues it by deliverAt and hands it to
// the IPC layer as the struct the friends module reads.
//
//	Envelope   {0: u8 type=4, 1: →PutRecord, 2: string "NX", 3: u64 issued, 4: u64 expires}
//	PutRecord  {0: [Entry] (exactly one element), 1: u8 = 1}
//	Entry      {0: u8 kind, 1: →Message}
//	Message(1) {0: string name, 1: u16 type, 2: →Meta, 4: string body, 5: u64 deliverAt}
//	Meta       {1: string receivers, 2: string accountId, 4: string (≤39)}

const (
	// EntryKindMessage tags an entry the console delivers to a module rather
	// than storing; EntryKindRecord is the stored-record half.
	EntryKindMessage = 1
	EntryKindRecord  = 2

	// envelopeTag is what envelope slot 2 carries in the console's own frames:
	// the string "NX", not the u32 the hash builders above write there. The
	// RootHash answer keeps its u32 because that shape is hardware-proven; a
	// verifier-checked message is not the place to re-bet it.
	envelopeTag = "NX"

	// maxMessageName and maxMessageBody are the parser's own bounds; longer
	// values fail verification rather than being truncated on the console.
	maxMessageName = 47
	maxMessageBody = 4095
)

// Message is one kind-1 notification.
//
// Receivers is a comma-separated list of routing tokens, each a hex u64
// ("0x…", 16 digits) or a name; it must be non-empty or npns has nothing to
// route by. AccountID is the recipient's 128-bit console account as 32 hex
// chars — empty leaves the uid zero and the friends handlers drop the event.
// Type is the u16 in slot 1, whose meaning is not recovered.
type Message struct {
	Name      string
	Type      uint16
	Receivers string
	AccountID string
	// Tag is Meta slot 4: at most 39 characters, may be empty, must exist.
	Tag       string
	Body      string
	DeliverAt uint64 // absent (0) means deliver now
}

// BuildMessage encodes one kind-1 message inside a PutRecord envelope.
func BuildMessage(m Message, issued, expires uint64) []byte {
	b := NewBuilder(256 + len(m.Body))

	recv := b.CreateString(m.Receivers)
	acct := b.CreateString(m.AccountID)
	// Slot 4 is read with no vtable-length check for every message whose type
	// is not 2, and its length must be <= 39. A three-slot Meta made the read
	// run off the end of the vtable, the parse fail, and the message be
	// dropped after the console had already acked it
	// (docs/penne-message-delivery-2026-09-20.md §1.4).
	tag := b.CreateString(m.Tag)
	b.StartTable(5)
	b.PrependUOffsetSlot(4, tag)
	b.PrependUOffsetSlot(2, acct)
	b.PrependUOffsetSlot(1, recv)
	meta := b.EndTable()

	name := b.CreateString(m.Name)
	body := b.CreateString(m.Body)
	b.StartTable(6)
	if m.DeliverAt != 0 {
		b.PrependU64Slot(5, m.DeliverAt)
	}
	b.PrependUOffsetSlot(4, body)
	b.PrependUOffsetSlot(2, meta)
	b.PrependU16Slot(1, m.Type)
	b.PrependUOffsetSlot(0, name)
	msg := b.EndTable()

	b.StartTable(2)
	b.PrependUOffsetSlot(1, msg)
	b.PrependU8Slot(0, EntryKindMessage)
	entry := b.EndTable()

	vec := b.CreateOffsetVector([]int{entry})
	b.StartTable(2)
	b.PrependU8Slot(1, 1)
	b.PrependUOffsetSlot(0, vec)
	payload := b.EndTable()

	envTag := b.CreateString(envelopeTag)
	b.StartTable(5)
	b.PrependU64Slot(4, expires)
	b.PrependU64Slot(3, issued)
	b.PrependUOffsetSlot(2, envTag)
	b.PrependUOffsetSlot(1, payload)
	b.PrependU8Slot(0, TypePutRecord)
	root := b.EndTable()
	b.prep(b.minalign, 4)
	b.placeU32(uint32(b.Offset() + 4 - root))
	return b.Bytes()
}

// MessageTooLong reports a message the console's parser would refuse on
// length alone, so a caller finds out here instead of by a dropped connection.
func (m Message) TooLong() bool {
	return len(m.Name) > maxMessageName || len(m.Body) > maxMessageBody
}

// ParseMessage reads the first kind-1 message out of a PutRecord payload.
// ok is false for an empty vector or an entry of another kind.
func ParseMessage(payload Table) (Message, bool) {
	entry, ok := payload.VectorTable(0, 0)
	if !ok {
		return Message{}, false
	}
	if kind, _ := entry.U8(0); kind != EntryKindMessage {
		return Message{}, false
	}
	t, ok := entry.Table(1)
	if !ok {
		return Message{}, false
	}
	var m Message
	m.Name, _ = t.String(0)
	m.Type, _ = t.U16(1)
	m.Body, _ = t.String(4)
	m.DeliverAt, _ = t.U64(5)
	if meta, ok := t.Table(2); ok {
		m.Receivers, _ = meta.String(1)
		m.AccountID, _ = meta.String(2)
		m.Tag, _ = meta.String(4)
	}
	return m, true
}
