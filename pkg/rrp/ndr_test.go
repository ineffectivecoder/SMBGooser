package rrp

import (
	"testing"
)

// TestEncodeRpcUnicodeString tests RPC Unicode string encoding
func TestEncodeRpcUnicodeString(t *testing.T) {
	tests := []struct {
		input string
	}{
		{"SOFTWARE"},
		{"Microsoft"},
		{"Windows\\CurrentVersion"},
		{""},
	}

	for _, tt := range tests {
		stub := encodeRpcUnicodeString(tt.input)

		// Should be 4-byte aligned
		if len(stub)%4 != 0 {
			t.Errorf("encodeRpcUnicodeString(%q) not 4-byte aligned: %d bytes", tt.input, len(stub))
		}

		// Minimum size is header (12) + null terminator (2) + padding
		if len(stub) < 16 {
			t.Errorf("encodeRpcUnicodeString(%q) too short: %d bytes", tt.input, len(stub))
		}
	}
}

// TestEncodeOpenKey tests OpenKey encoding
func TestEncodeOpenKey(t *testing.T) {
	var handle Handle
	stub := encodeOpenKey(handle, "SOFTWARE\\Microsoft", 0x20019)

	// Should contain handle (20) + encoded string
	if len(stub) < 40 {
		t.Errorf("encodeOpenKey returned %d bytes, want >= 40", len(stub))
	}
}

// TestEncodeQueryValue tests QueryValue encoding
func TestEncodeQueryValue(t *testing.T) {
	var handle Handle
	stub := encodeQueryValue(handle, "ProductName")

	// Should contain handle + value name + null pointers
	if len(stub) < 40 {
		t.Errorf("encodeQueryValue returned %d bytes, want >= 40", len(stub))
	}
}

// TestEncodeDeleteKey tests DeleteKey encoding
func TestEncodeDeleteKey(t *testing.T) {
	var handle Handle
	stub := encodeDeleteKey(handle, "TestKey")

	// Handle (20) + encoded string
	if len(stub) < 30 {
		t.Errorf("encodeDeleteKey returned %d bytes, want >= 30", len(stub))
	}
}

// TestEncodeSaveKey tests SaveKey encoding
func TestEncodeSaveKey(t *testing.T) {
	var handle Handle
	stub := encodeSaveKey(handle, "C:\\Windows\\Temp\\test.hiv")

	// Handle (20) + encoded path + null security
	if len(stub) < 50 {
		t.Errorf("encodeSaveKey returned %d bytes, want >= 50", len(stub))
	}
}

// TestAppendUint32 tests uint32 encoding
func TestAppendUint32(t *testing.T) {
	buf := make([]byte, 0)
	buf = appendUint32(buf, 0xDEADBEEF)

	if len(buf) != 4 {
		t.Fatalf("appendUint32 returned %d bytes, want 4", len(buf))
	}

	// Little endian
	if buf[0] != 0xEF || buf[1] != 0xBE || buf[2] != 0xAD || buf[3] != 0xDE {
		t.Errorf("appendUint32 wrong encoding: %v", buf)
	}
}

// TestAppendUint16 tests uint16 encoding
func TestAppendUint16(t *testing.T) {
	buf := make([]byte, 0)
	buf = appendUint16(buf, 0xABCD)

	if len(buf) != 2 {
		t.Fatalf("appendUint16 returned %d bytes, want 2", len(buf))
	}

	// Little endian
	if buf[0] != 0xCD || buf[1] != 0xAB {
		t.Errorf("appendUint16 wrong encoding: %v", buf)
	}
}

// BenchmarkEncodeRpcUnicodeString benchmarks string encoding
func BenchmarkEncodeRpcUnicodeString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		encodeRpcUnicodeString("SOFTWARE\\Microsoft\\Windows\\CurrentVersion")
	}
}
