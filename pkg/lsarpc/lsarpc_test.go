package lsarpc

import (
	"testing"
)

func TestEncodeLsarOpenPolicy2(t *testing.T) {
	stub := encodeLsarOpenPolicy2("")

	// Should have: null ptr (4) + ObjectAttributes (24) + DesiredAccess (4) = 32
	if len(stub) != 32 {
		t.Errorf("encodeLsarOpenPolicy2 returned %d bytes, want 32", len(stub))
	}
}

func TestEncodeLsarQueryInfoPolicy(t *testing.T) {
	var handle Handle
	stub := encodeLsarQueryInfoPolicy(handle, 12)

	// Handle (20) + InfoClass (2) + Padding (2) = 24
	if len(stub) != 24 {
		t.Errorf("encodeLsarQueryInfoPolicy returned %d bytes, want 24", len(stub))
	}
}

func TestEncodeLsarEnumerateTrustedDomains(t *testing.T) {
	var handle Handle
	stub := encodeLsarEnumerateTrustedDomains(handle)

	// Handle (20) + EnumContext (4) + PrefMax (4) = 28
	if len(stub) != 28 {
		t.Errorf("encodeLsarEnumerateTrustedDomains returned %d bytes, want 28", len(stub))
	}
}

func TestParsePolicyInfo(t *testing.T) {
	resp := make([]byte, 12)
	info, err := parsePolicyInfo(resp)
	if err != nil {
		t.Errorf("parsePolicyInfo error: %v", err)
	}
	if info == nil {
		t.Error("parsePolicyInfo returned nil")
	}
}

func TestParseTrustedDomains(t *testing.T) {
	resp := make([]byte, 12)
	domains, err := parseTrustedDomains(resp)
	if err != nil {
		t.Logf("parseTrustedDomains error: %v", err)
	}
	t.Logf("Parsed %d domains", len(domains))
}

func TestAppendUint32(t *testing.T) {
	buf := appendUint32(nil, 0xCAFEBABE)
	if len(buf) != 4 {
		t.Fatalf("wrong length")
	}
	if buf[0] != 0xBE || buf[3] != 0xCA {
		t.Error("wrong endianness")
	}
}

func TestAppendUint16(t *testing.T) {
	buf := appendUint16(nil, 0x1234)
	if len(buf) != 2 {
		t.Fatalf("wrong length")
	}
	if buf[0] != 0x34 || buf[1] != 0x12 {
		t.Error("wrong endianness")
	}
}
