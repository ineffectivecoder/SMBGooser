package svcctl

import (
	"testing"
)

// TestEncodeOpenSCManager tests the OpenSCManager encoding
func TestEncodeOpenSCManager(t *testing.T) {
	// Test with empty machine name
	stub := encodeOpenSCManager("", SCManagerConnect)

	// Should have: null pointer (4) + null pointer (4) + access mask (4) = 12 bytes minimum
	if len(stub) < 12 {
		t.Errorf("encodeOpenSCManager returned %d bytes, want >= 12", len(stub))
	}

	// First 4 bytes should be null pointer
	if stub[0] != 0 || stub[1] != 0 || stub[2] != 0 || stub[3] != 0 {
		t.Error("Expected null pointer for empty machine name")
	}
}

// TestEncodeOpenSCManagerWithName tests with a machine name
func TestEncodeOpenSCManagerWithName(t *testing.T) {
	stub := encodeOpenSCManager("SERVER01", SCManagerConnect)

	// Should be larger with machine name
	if len(stub) < 20 {
		t.Errorf("encodeOpenSCManager with name returned %d bytes, want >= 20", len(stub))
	}

	// First 4 bytes should be non-null pointer
	if stub[0] == 0 && stub[1] == 0 && stub[2] == 0 && stub[3] == 0 {
		t.Error("Expected non-null pointer for machine name")
	}
}

// TestEncodeDeleteService tests delete service encoding
func TestEncodeDeleteService(t *testing.T) {
	var handle Handle
	copy(handle[:], []byte("12345678901234567890"))

	stub := encodeDeleteService(handle)

	if len(stub) != 20 {
		t.Errorf("encodeDeleteService returned %d bytes, want 20", len(stub))
	}

	// Should contain the handle
	for i := 0; i < 20; i++ {
		if stub[i] != handle[i] {
			t.Errorf("Handle byte %d mismatch", i)
		}
	}
}

// TestEncodeStartService tests start service encoding
func TestEncodeStartService(t *testing.T) {
	var handle Handle
	copy(handle[:], []byte("12345678901234567890"))

	stub := encodeStartService(handle)

	// Handle (20) + argc (4) + argv null (4) = 28
	if len(stub) != 28 {
		t.Errorf("encodeStartService returned %d bytes, want 28", len(stub))
	}
}

// TestEncodeNdrString tests NDR string encoding
func TestEncodeNdrString(t *testing.T) {
	tests := []struct {
		input       string
		minExpected int
	}{
		{"A", 14},    // 12 header + 2 bytes char + padding
		{"Test", 20}, // 12 header + 10 bytes (5 chars * 2) + padding
		{"", 14},     // 12 header + 2 bytes (null) + padding
	}

	for _, tt := range tests {
		stub := encodeNdrString(tt.input)
		if len(stub) < tt.minExpected {
			t.Errorf("encodeNdrString(%q) = %d bytes, want >= %d", tt.input, len(stub), tt.minExpected)
		}

		// Should be 4-byte aligned
		if len(stub)%4 != 0 {
			t.Errorf("encodeNdrString(%q) not 4-byte aligned: %d bytes", tt.input, len(stub))
		}
	}
}

// TestAppendUint32 tests uint32 encoding
func TestAppendUint32(t *testing.T) {
	buf := make([]byte, 0)
	buf = appendUint32(buf, 0x12345678)

	if len(buf) != 4 {
		t.Fatalf("appendUint32 returned %d bytes, want 4", len(buf))
	}

	// Little endian
	if buf[0] != 0x78 || buf[1] != 0x56 || buf[2] != 0x34 || buf[3] != 0x12 {
		t.Errorf("appendUint32 wrong encoding: %v", buf)
	}
}

// TestEncodeEnumServicesStatus tests service enumeration encoding
func TestEncodeEnumServicesStatus(t *testing.T) {
	var handle Handle
	stub := encodeEnumServicesStatus(handle, 0x30, 3)

	// Handle (20) + type (4) + state (4) + bufsize (4) + resume (4) = 36
	if len(stub) != 36 {
		t.Errorf("encodeEnumServicesStatus returned %d bytes, want 36", len(stub))
	}
}

// BenchmarkEncodeNdrString benchmarks string encoding
func BenchmarkEncodeNdrString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		encodeNdrString("TestService")
	}
}
