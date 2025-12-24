package samr

import (
	"testing"
)

// TestEncodeConnect tests SamrConnect encoding
func TestEncodeConnect(t *testing.T) {
	stub := encodeConnect()

	// Should have null pointer (4) + access mask (4) + flags (4) = 12 bytes
	if len(stub) != 12 {
		t.Errorf("encodeConnect returned %d bytes, want 12", len(stub))
	}
}

// TestEncodeLookupDomain tests SamrLookupDomainInSamServer encoding
func TestEncodeLookupDomain(t *testing.T) {
	var handle Handle
	stub := encodeLookupDomain(handle, "TESTDOMAIN")

	// Handle (20) + RPC_UNICODE_STRING (variable)
	if len(stub) < 30 {
		t.Errorf("encodeLookupDomain returned %d bytes, want >= 30", len(stub))
	}
}

// TestEncodeOpenDomain tests SamrOpenDomain encoding
func TestEncodeOpenDomain(t *testing.T) {
	var handle Handle
	// Minimal SID
	sid := []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0}
	stub := encodeOpenDomain(handle, sid)

	// Handle (20) + access (4) + SID
	if len(stub) < 48 {
		t.Errorf("encodeOpenDomain returned %d bytes, want >= 48", len(stub))
	}
}

// TestEncodeEnumerateUsers tests SamrEnumerateUsersInDomain encoding
func TestEncodeEnumerateUsers(t *testing.T) {
	var handle Handle
	stub := encodeEnumerateUsers(handle)

	// Handle (20) + context (4) + filter (4) + maxlen (4) = 32
	if len(stub) != 32 {
		t.Errorf("encodeEnumerateUsers returned %d bytes, want 32", len(stub))
	}
}

// TestEncodeEnumerateGroups tests SamrEnumerateGroupsInDomain encoding
func TestEncodeEnumerateGroups(t *testing.T) {
	var handle Handle
	stub := encodeEnumerateGroups(handle)

	// Handle (20) + context (4) + maxlen (4) = 28
	if len(stub) != 28 {
		t.Errorf("encodeEnumerateGroups returned %d bytes, want 28", len(stub))
	}
}

// TestEncodeRpcUnicodeString tests RPC Unicode string encoding
func TestEncodeRpcUnicodeString(t *testing.T) {
	tests := []struct {
		input string
	}{
		{"DOMAIN"},
		{"TEST"},
		{""},
	}

	for _, tt := range tests {
		stub := encodeRpcUnicodeStringInline(tt.input)
		// Should be 4-byte aligned
		if len(stub)%4 != 0 {
			t.Errorf("encodeRpcUnicodeStringInline(%q) not 4-byte aligned: %d bytes", tt.input, len(stub))
		}
	}
}

// TestAppendUint32 tests uint32 encoding
func TestAppendUint32(t *testing.T) {
	buf := make([]byte, 0)
	buf = appendUint32(buf, 0xCAFEBABE)

	if len(buf) != 4 {
		t.Fatalf("appendUint32 returned %d bytes, want 4", len(buf))
	}

	// Little endian
	if buf[0] != 0xBE || buf[1] != 0xBA || buf[2] != 0xFE || buf[3] != 0xCA {
		t.Errorf("appendUint32 wrong encoding: %v", buf)
	}
}

// TestAppendUint16 tests uint16 encoding
func TestAppendUint16(t *testing.T) {
	buf := make([]byte, 0)
	buf = appendUint16(buf, 0xDEAD)

	if len(buf) != 2 {
		t.Fatalf("appendUint16 returned %d bytes, want 2", len(buf))
	}

	if buf[0] != 0xAD || buf[1] != 0xDE {
		t.Errorf("appendUint16 wrong encoding: %v", buf)
	}
}

// TestParseEnumerateUsersResponse tests user enumeration response parsing
func TestParseEnumerateUsersResponse(t *testing.T) {
	// Create minimal response with count
	resp := make([]byte, 20)
	// Put count near end
	resp[12] = 5 // 5 users

	users, err := parseEnumerateUsersResponse(resp)
	if err != nil {
		t.Logf("parseEnumerateUsersResponse error: %v", err)
	}
	t.Logf("Parsed %d users", len(users))
}

// TestPasswordPolicyFormatters tests password policy formatting
func TestPasswordPolicyFormatters(t *testing.T) {
	// Test FormatPasswordAge
	tests := []struct {
		input    int64
		contains string
	}{
		{0, "Never"},
		{-864000000000, "days"}, // ~1 day in 100ns
		{1, "Unlimited"},
	}

	for _, tt := range tests {
		result := FormatPasswordAge(tt.input)
		if result == "" {
			t.Errorf("FormatPasswordAge(%d) returned empty", tt.input)
		}
	}

	// Test DescribePasswordProperties
	props := DescribePasswordProperties(DomainPasswordComplex | DomainLockoutAdmins)
	if len(props) == 0 {
		t.Error("DescribePasswordProperties returned empty")
	}
}

// BenchmarkEncodeRpcUnicodeString benchmarks string encoding
func BenchmarkEncodeRpcUnicodeString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		encodeRpcUnicodeStringInline("TESTDOMAIN")
	}
}
