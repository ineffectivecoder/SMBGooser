package srvsvc

import (
	"testing"
)

func TestEncodeNetSessionEnum(t *testing.T) {
	stub := encodeNetSessionEnum("", 10)

	// Should have: null ptr (4) + null ptr (4) + null ptr (4) + level (4) + switch (4) +
	//              container ptr (4) + entries (4) + buffer (4) + prefmax (4) + resume ptr (4) + resume (4)
	if len(stub) < 40 {
		t.Errorf("encodeNetSessionEnum returned %d bytes, want >= 40", len(stub))
	}
}

func TestEncodeNetShareEnum(t *testing.T) {
	stub := encodeNetShareEnum("", 1)

	if len(stub) < 32 {
		t.Errorf("encodeNetShareEnum returned %d bytes, want >= 32", len(stub))
	}
}

func TestAppendUint32(t *testing.T) {
	buf := appendUint32(nil, 0x12345678)

	if len(buf) != 4 {
		t.Fatalf("appendUint32 returned %d bytes, want 4", len(buf))
	}

	// Little endian
	if buf[0] != 0x78 || buf[1] != 0x56 || buf[2] != 0x34 || buf[3] != 0x12 {
		t.Errorf("appendUint32 wrong encoding: %x", buf)
	}
}

func TestParseSessionEnumResponse(t *testing.T) {
	// Empty response
	resp := make([]byte, 20)
	sessions, err := parseSessionEnumResponse(resp)
	if err != nil {
		t.Logf("parseSessionEnumResponse error: %v", err)
	}
	t.Logf("Parsed %d sessions", len(sessions))
}

func TestParseShareEnumResponse(t *testing.T) {
	resp := make([]byte, 20)
	shares, err := parseShareEnumResponse(resp)
	if err != nil {
		t.Logf("parseShareEnumResponse error: %v", err)
	}
	t.Logf("Parsed %d shares", len(shares))
}
