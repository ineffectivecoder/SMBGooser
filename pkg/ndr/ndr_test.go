package ndr

import (
	"testing"
)

func TestReaderUint32(t *testing.T) {
	data := []byte{0x78, 0x56, 0x34, 0x12}
	r := NewReader(data)

	v, err := r.ReadUint32()
	if err != nil {
		t.Fatalf("ReadUint32 error: %v", err)
	}
	if v != 0x12345678 {
		t.Errorf("ReadUint32 = 0x%08X, want 0x12345678", v)
	}
}

func TestReaderUint16(t *testing.T) {
	data := []byte{0x34, 0x12}
	r := NewReader(data)

	v, err := r.ReadUint16()
	if err != nil {
		t.Fatalf("ReadUint16 error: %v", err)
	}
	if v != 0x1234 {
		t.Errorf("ReadUint16 = 0x%04X, want 0x1234", v)
	}
}

func TestReaderAlign(t *testing.T) {
	data := []byte{0x01, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00}
	r := NewReader(data)

	// Read 1 byte
	r.ReadUint8()

	// Now at offset 1, align to 4
	r.Align(4)
	if r.offset != 4 {
		t.Errorf("offset after Align(4) = %d, want 4", r.offset)
	}
}

func TestReaderConformantString(t *testing.T) {
	// NDR conformant string: "Hi" in UTF-16LE
	// MaxCount=3, Offset=0, ActualCount=3, "Hi\0"
	data := []byte{
		0x03, 0x00, 0x00, 0x00, // MaxCount = 3
		0x00, 0x00, 0x00, 0x00, // Offset = 0
		0x03, 0x00, 0x00, 0x00, // ActualCount = 3
		'H', 0x00, 'i', 0x00, 0x00, 0x00, // "Hi\0" in UTF-16LE
	}

	r := NewReader(data)
	s, err := r.ReadConformantString()
	if err != nil {
		t.Fatalf("ReadConformantString error: %v", err)
	}
	if s != "Hi" {
		t.Errorf("ReadConformantString = %q, want %q", s, "Hi")
	}
}

func TestReaderSID(t *testing.T) {
	// S-1-5-21-1234-5678-91011-500 (simplified)
	data := []byte{
		0x01,                               // Revision = 1
		0x05,                               // SubAuthorityCount = 5
		0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority = 5
		0x15, 0x00, 0x00, 0x00, // SubAuth[0] = 21
		0xD2, 0x04, 0x00, 0x00, // SubAuth[1] = 1234
		0x2E, 0x16, 0x00, 0x00, // SubAuth[2] = 5678
		0x23, 0x64, 0x01, 0x00, // SubAuth[3] = 91171
		0xF4, 0x01, 0x00, 0x00, // SubAuth[4] = 500
	}

	r := NewReader(data)
	sid, err := r.ReadSID()
	if err != nil {
		t.Fatalf("ReadSID error: %v", err)
	}

	expected := "S-1-5-21-1234-5678-91171-500"
	if sid != expected {
		t.Errorf("ReadSID = %s, want %s", sid, expected)
	}
}

func TestDecodeUTF16LE(t *testing.T) {
	// "Test" in UTF-16LE
	data := []byte{'T', 0, 'e', 0, 's', 0, 't', 0}
	s := DecodeUTF16LE(data)
	if s != "Test" {
		t.Errorf("DecodeUTF16LE = %q, want %q", s, "Test")
	}
}

func TestWriterUint32(t *testing.T) {
	w := NewWriter()
	w.WriteUint32(0x12345678)

	if len(w.Bytes()) != 4 {
		t.Fatalf("wrong length: %d", len(w.Bytes()))
	}

	expected := []byte{0x78, 0x56, 0x34, 0x12}
	for i, b := range w.Bytes() {
		if b != expected[i] {
			t.Errorf("byte %d = 0x%02X, want 0x%02X", i, b, expected[i])
		}
	}
}

func TestWriterConformantString(t *testing.T) {
	w := NewWriter()
	w.WriteConformantString("Hi")

	b := w.Bytes()
	if len(b) < 12 {
		t.Fatalf("too short: %d bytes", len(b))
	}

	// Check MaxCount
	maxCount := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	if maxCount != 3 {
		t.Errorf("MaxCount = %d, want 3", maxCount)
	}
}

func TestReaderPointer(t *testing.T) {
	// Non-null pointer
	data := []byte{0x04, 0x00, 0x02, 0x00}
	r := NewReader(data)

	hasPtr, err := r.ReadPointer()
	if err != nil {
		t.Fatal(err)
	}
	if !hasPtr {
		t.Error("expected non-null pointer")
	}

	// Null pointer
	r = NewReader([]byte{0x00, 0x00, 0x00, 0x00})
	hasPtr, err = r.ReadPointer()
	if err != nil {
		t.Fatal(err)
	}
	if hasPtr {
		t.Error("expected null pointer")
	}
}
