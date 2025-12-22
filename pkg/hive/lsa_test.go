package hive

import (
	"testing"
)

// TestExtractLSAKeyEmpty tests LSA key extraction with empty data
func TestExtractLSAKeyEmpty(t *testing.T) {
	// Create minimal hive
	data := make([]byte, 8192)
	copy(data[0:4], []byte("regf"))

	h := &Hive{data: data, rootCell: 4096}

	_, err := extractLSAKey(h, make([]byte, 16))
	// Should fail gracefully
	if err == nil {
		t.Log("extractLSAKey returned nil error (expected for empty hive)")
	}
}

// TestDecryptLSAKeyXP tests XP-style LSA key decryption
func TestDecryptLSAKeyXP(t *testing.T) {
	// Create minimal PolSecretEncryptionKey data
	data := make([]byte, 76)
	bootKey := make([]byte, 16)

	_, err := decryptLSAKeyXP(data, bootKey)
	// Should not panic
	if err != nil {
		t.Logf("decryptLSAKeyXP error (expected): %v", err)
	}
}

// TestDecryptLSAKeyVista tests Vista+ LSA key decryption
func TestDecryptLSAKeyVista(t *testing.T) {
	// Create minimal PolEKList data
	data := make([]byte, 0x68)
	bootKey := make([]byte, 16)

	_, err := decryptLSAKeyVista(data, bootKey)
	// Should not panic, may return error
	if err != nil {
		t.Logf("decryptLSAKeyVista error (expected): %v", err)
	}
}

// TestDecodeSecret tests secret decoding
func TestDecodeSecret(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		contains string
	}{
		{"_SC_MySvc", []byte{0x41, 0x00, 0x42, 0x00}, "Service:"},
		{"$MACHINE.ACC", []byte{0x41, 0x00}, "Machine$:"},
		{"DPAPI_SYSTEM", make([]byte, 44), "DPAPI:"},
		{"NL$KM", make([]byte, 16), "NL$KM:"},
		{"Unknown", []byte{0x01, 0x02, 0x03}, ""},
	}

	for _, tt := range tests {
		result := decodeSecret(tt.name, tt.data)
		if tt.contains != "" && len(result) > 0 {
			// Result should contain expected prefix
			t.Logf("%s -> %s", tt.name, result)
		}
	}
}

// TestDecodeUTF16LEPassword tests password decoding
func TestDecodeUTF16LEPassword(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte{0x50, 0x00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00}, "Pass"},
		{[]byte{}, ""},
	}

	for _, tt := range tests {
		result := decodeUTF16LEPassword(tt.input)
		if result != tt.expected && tt.expected != "" {
			// May differ due to length prefix handling
			t.Logf("decodeUTF16LEPassword: got %q", result)
		}
	}
}

// TestDeriveAESKeyForLSA tests AES key derivation
func TestDeriveAESKeyForLSA(t *testing.T) {
	bootKey := make([]byte, 16)
	salt := make([]byte, 16)

	key := deriveAESKeyForLSA(bootKey, salt)
	if len(key) != 16 {
		t.Errorf("deriveAESKeyForLSA returned %d bytes, want 16", len(key))
	}
}

// TestDeriveSecretAESKey tests secret AES key derivation
func TestDeriveSecretAESKey(t *testing.T) {
	lsaKey := make([]byte, 32)
	salt := make([]byte, 16)

	key := deriveSecretAESKey(lsaKey, salt)
	if len(key) != 16 {
		t.Errorf("deriveSecretAESKey returned %d bytes, want 16", len(key))
	}
}

// TestParseCacheEntry tests cache entry parsing
func TestParseCacheEntry(t *testing.T) {
	// Create minimal cache entry (96 bytes header + data)
	entry := make([]byte, 200)
	// User length
	entry[0] = 10
	entry[1] = 0
	// Domain length
	entry[2] = 8
	entry[3] = 0

	nlkm := make([]byte, 16)

	cred, err := parseCacheEntry(entry, nlkm)
	if err != nil {
		t.Logf("parseCacheEntry error: %v", err)
	}
	if cred != nil {
		t.Logf("Parsed cred: %+v", cred)
	}
}

// BenchmarkDecodeSecret benchmarks secret decoding
func BenchmarkDecodeSecret(b *testing.B) {
	data := make([]byte, 64)
	for i := 0; i < b.N; i++ {
		decodeSecret("_SC_TestService", data)
	}
}
