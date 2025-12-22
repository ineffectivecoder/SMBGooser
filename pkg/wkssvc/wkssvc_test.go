package wkssvc

import (
	"testing"
)

func TestEncodeNetrWkstaUserEnum(t *testing.T) {
	stub := encodeNetrWkstaUserEnum("", 1)

	if len(stub) < 32 {
		t.Errorf("encodeNetrWkstaUserEnum returned %d bytes, want >= 32", len(stub))
	}
}

func TestEncodeNetrWkstaGetInfo(t *testing.T) {
	stub := encodeNetrWkstaGetInfo("", 100)

	if len(stub) != 8 {
		t.Errorf("encodeNetrWkstaGetInfo returned %d bytes, want 8", len(stub))
	}
}

func TestParseWkstaUserEnumResponse(t *testing.T) {
	resp := make([]byte, 20)
	users, err := parseWkstaUserEnumResponse(resp)
	if err != nil {
		t.Logf("parseWkstaUserEnumResponse error: %v", err)
	}
	t.Logf("Parsed %d users", len(users))
}

func TestParseWkstaGetInfoResponse(t *testing.T) {
	resp := make([]byte, 12)
	info, err := parseWkstaGetInfoResponse(resp)
	if err != nil {
		t.Errorf("parseWkstaGetInfoResponse error: %v", err)
	}
	if info == nil {
		t.Error("parseWkstaGetInfoResponse returned nil")
	}
}

func TestAppendUint32(t *testing.T) {
	buf := appendUint32(nil, 0xDEADBEEF)

	if len(buf) != 4 {
		t.Fatalf("appendUint32 returned %d bytes, want 4", len(buf))
	}

	if buf[0] != 0xEF || buf[1] != 0xBE || buf[2] != 0xAD || buf[3] != 0xDE {
		t.Errorf("appendUint32 wrong encoding: %x", buf)
	}
}
