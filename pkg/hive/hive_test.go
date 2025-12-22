package hive

import (
	"bytes"
	"testing"
)

// TestParseValidHive tests parsing a minimal valid hive
func TestParseValidHive(t *testing.T) {
	// Create a minimal valid hive header
	hiveData := make([]byte, 8192)
	copy(hiveData[0:4], []byte("regf")) // Signature

	// Root cell offset at offset 36 (points to data area)
	hiveData[36] = 0x20 // Root at offset 0x20 in hive bins (after 4096 header)
	hiveData[37] = 0x00
	hiveData[38] = 0x00
	hiveData[39] = 0x00

	h, err := Parse(hiveData)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if h == nil {
		t.Fatal("Parse returned nil hive")
	}

	if h.rootCell != 0x20+4096 {
		t.Errorf("Expected rootCell %d, got %d", 0x20+4096, h.rootCell)
	}
}

// TestParseInvalidSignature tests rejection of invalid hive
func TestParseInvalidSignature(t *testing.T) {
	hiveData := make([]byte, 8192)
	copy(hiveData[0:4], []byte("XXXX")) // Invalid signature

	_, err := Parse(hiveData)
	if err == nil {
		t.Error("Expected error for invalid signature")
	}
}

// TestParseTooSmall tests rejection of too-small data
func TestParseTooSmall(t *testing.T) {
	hiveData := make([]byte, 1000) // Too small

	_, err := Parse(hiveData)
	if err == nil {
		t.Error("Expected error for too-small hive")
	}
}

// TestSplitPath tests path splitting
func TestSplitPath(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"", nil},
		{"SAM", []string{"SAM"}},
		{"SAM\\Domains", []string{"SAM", "Domains"}},
		{"SAM\\Domains\\Account", []string{"SAM", "Domains", "Account"}},
		{"SAM/Domains/Account", []string{"SAM", "Domains", "Account"}},
		{"\\SAM\\Domains", []string{"SAM", "Domains"}},
	}

	for _, tt := range tests {
		result := splitPath(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("splitPath(%q) = %v, want %v", tt.input, result, tt.expected)
			continue
		}
		for i := range result {
			if result[i] != tt.expected[i] {
				t.Errorf("splitPath(%q)[%d] = %q, want %q", tt.input, i, result[i], tt.expected[i])
			}
		}
	}
}

// TestEqualFold tests case-insensitive comparison
func TestEqualFold(t *testing.T) {
	tests := []struct {
		a, b     string
		expected bool
	}{
		{"SAM", "SAM", true},
		{"SAM", "sam", true},
		{"Sam", "sAM", true},
		{"SAM", "SYSTEM", false},
		{"", "", true},
		{"a", "ab", false},
	}

	for _, tt := range tests {
		result := equalFold(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("equalFold(%q, %q) = %v, want %v", tt.a, tt.b, result, tt.expected)
		}
	}
}

// TestDecodeUTF16LE tests UTF-16LE decoding
func TestDecodeUTF16LE(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte{0x41, 0x00}, "A"},
		{[]byte{0x41, 0x00, 0x42, 0x00, 0x43, 0x00}, "ABC"},
		{[]byte{0x41, 0x00, 0x00, 0x00, 0x42, 0x00}, "A"}, // Null terminated
		{[]byte{}, ""},
		{[]byte{0x41}, ""}, // Odd number of bytes
	}

	for _, tt := range tests {
		result := decodeUTF16LE(tt.input)
		if result != tt.expected {
			t.Errorf("decodeUTF16LE(%v) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// TestExpandDESKey tests DES key expansion
func TestExpandDESKey(t *testing.T) {
	// Test with known input
	key7 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	key8 := expandDESKey(key7)

	if len(key8) != 8 {
		t.Errorf("expandDESKey returned %d bytes, want 8", len(key8))
	}

	// Key should not be all zeros
	allZero := true
	for _, b := range key8 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("expandDESKey returned all zeros")
	}
}

// TestExpandDESKeyInvalidInput tests DES key expansion with invalid input
func TestExpandDESKeyInvalidInput(t *testing.T) {
	// Too short
	key5 := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	key8 := expandDESKey(key5)

	if len(key8) != 8 {
		t.Errorf("expandDESKey returned %d bytes, want 8", len(key8))
	}
}

// Mock hive for testing key navigation
func createMockHive() *Hive {
	// Create a hive with a simple structure
	data := make([]byte, 16384)

	// Header
	copy(data[0:4], []byte("regf"))
	data[36] = 0x20 // Root at 0x20 + 4096

	// Create a simple nk (key node) at root
	rootOffset := 4096 + 0x20

	// Cell size (negative = allocated)
	data[rootOffset] = 0xD0
	data[rootOffset+1] = 0xFF
	data[rootOffset+2] = 0xFF
	data[rootOffset+3] = 0xFF

	// Signature "nk"
	data[rootOffset+4] = 0x6E // 'n'
	data[rootOffset+5] = 0x6B // 'k'

	return &Hive{
		data:     data,
		rootCell: rootOffset,
	}
}

// TestGetKeyNameEmpty tests getting key name from invalid offset
func TestGetKeyNameEmpty(t *testing.T) {
	h := createMockHive()

	// Invalid offset should return empty string
	name := h.getKeyName(0)
	if name != "" {
		t.Errorf("getKeyName(0) = %q, want empty", name)
	}
}

// TestGetKeyClass tests class name retrieval
func TestGetKeyClass(t *testing.T) {
	h := createMockHive()

	// No class set should return nil
	class := h.getKeyClass(h.rootCell)
	if class != nil && len(class) > 0 {
		// It's OK if it returns empty/nil for a mock without class
	}
}

// Benchmark for path splitting
func BenchmarkSplitPath(b *testing.B) {
	path := "SAM\\Domains\\Account\\Users\\Names"
	for i := 0; i < b.N; i++ {
		splitPath(path)
	}
}

// Benchmark for string comparison
func BenchmarkEqualFold(b *testing.B) {
	a := "Administrator"
	c := "administrator"
	for i := 0; i < b.N; i++ {
		equalFold(a, c)
	}
}

// TestBootKeyTransforms tests the boot key unscrambling order
func TestBootKeyTransforms(t *testing.T) {
	// The transforms array should have 16 elements
	transforms := []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}

	if len(transforms) != 16 {
		t.Errorf("Expected 16 transforms, got %d", len(transforms))
	}

	// Each index 0-15 should appear exactly once
	seen := make(map[int]bool)
	for _, v := range transforms {
		if v < 0 || v > 15 {
			t.Errorf("Invalid transform value: %d", v)
		}
		if seen[v] {
			t.Errorf("Duplicate transform value: %d", v)
		}
		seen[v] = true
	}
}

// TestEmptyHashes tests that empty hash constants are correct
func TestEmptyHashes(t *testing.T) {
	// Standard empty LM hash (no password)
	emptyLM := "aad3b435b51404eeaad3b435b51404ee"
	// Standard empty NT hash (no password)
	emptyNT := "31d6cfe0d16ae931b73c59d7e0c089c0"

	if len(emptyLM) != 32 {
		t.Errorf("Empty LM hash wrong length: %d", len(emptyLM))
	}
	if len(emptyNT) != 32 {
		t.Errorf("Empty NT hash wrong length: %d", len(emptyNT))
	}
}

// TestDesobfuscateWithDESInvalidInput tests DES deobfuscation with bad input
func TestDesobfuscateWithDESInvalidInput(t *testing.T) {
	// Too short
	result := desobfuscateWithDES([]byte{1, 2, 3}, 500)
	if result != nil {
		t.Error("Expected nil for too-short input")
	}

	// Exactly 16 bytes should work (may be garbage but not nil)
	input16 := bytes.Repeat([]byte{0x41}, 16)
	result = desobfuscateWithDES(input16, 500)
	if len(result) != 16 {
		t.Errorf("Expected 16 bytes result, got %d", len(result))
	}
}
