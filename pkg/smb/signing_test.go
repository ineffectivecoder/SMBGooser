package smb

import (
	"bytes"
	"testing"

	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

func TestComputeHMACSHA256(t *testing.T) {
	key := []byte("test-key-16bytes")
	message := []byte("test message to sign")

	signature := computeHMACSHA256(key, message)

	// Should return 32 bytes (SHA256 output)
	if len(signature) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(signature))
	}

	// Same input should produce same output
	signature2 := computeHMACSHA256(key, message)
	if !bytes.Equal(signature, signature2) {
		t.Error("expected consistent HMAC output")
	}

	// Different key should produce different output
	signature3 := computeHMACSHA256([]byte("different-key123"), message)
	if bytes.Equal(signature, signature3) {
		t.Error("expected different HMAC with different key")
	}
}

func TestComputeAESCMAC(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes for AES-128
	message := []byte("test message for AES-CMAC")

	signature := computeAESCMAC(key, message)

	// Should return 16 bytes (AES block size)
	if len(signature) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(signature))
	}

	// Same input should produce same output
	signature2 := computeAESCMAC(key, message)
	if !bytes.Equal(signature, signature2) {
		t.Error("expected consistent CMAC output")
	}
}

func TestSignMessage(t *testing.T) {
	key := []byte("0123456789abcdef")

	// Create a minimal valid SMB2 message (64 byte header + some payload)
	message := make([]byte, 80)
	copy(message[0:4], []byte{0xFE, 'S', 'M', 'B'}) // Protocol ID

	// Test SMB2 signing
	signed := signMessage(types.DialectSMB2_1, key, message)

	// Should have set signature field (bytes 48-63)
	hasSignature := false
	for i := 48; i < 64; i++ {
		if signed[i] != 0 {
			hasSignature = true
			break
		}
	}
	if !hasSignature {
		t.Error("expected signature to be set in header")
	}
}

func TestVerifySignature(t *testing.T) {
	key := []byte("0123456789abcdef")

	// Create a minimal valid SMB2 message
	message := make([]byte, 80)
	copy(message[0:4], []byte{0xFE, 'S', 'M', 'B'})

	// Sign the message
	signed := signMessage(types.DialectSMB2_1, key, message)

	// Verification should succeed
	if !verifySignature(types.DialectSMB2_1, key, signed) {
		t.Error("signature verification should succeed for correctly signed message")
	}

	// Tampering with the message should fail verification
	tampered := make([]byte, len(signed))
	copy(tampered, signed)
	tampered[70] ^= 0xFF // Flip bits in payload

	if verifySignature(types.DialectSMB2_1, key, tampered) {
		t.Error("signature verification should fail for tampered message")
	}
}

func TestDeriveSigningKey(t *testing.T) {
	sessionKey := []byte("0123456789abcdef")

	// SMB2 should return session key directly
	smb2Key := deriveSigningKey(sessionKey, types.DialectSMB2_1, nil)
	if !bytes.Equal(smb2Key, sessionKey) {
		t.Error("SMB2 should use session key directly")
	}

	// SMB3 should derive a different key
	smb3Key := deriveSigningKey(sessionKey, types.DialectSMB3_0, nil)
	if bytes.Equal(smb3Key, sessionKey) {
		t.Error("SMB3 should derive a different signing key")
	}

	// Key should be 16 bytes for AES-128
	if len(smb3Key) != 16 {
		t.Errorf("expected 16 byte signing key for SMB3, got %d", len(smb3Key))
	}
}

func TestKDF(t *testing.T) {
	ki := []byte("0123456789abcdef")
	label := []byte("TestLabel\x00")
	context := []byte("TestContext\x00")

	// Derive 128-bit key
	key128 := kdf(ki, label, context, 128)
	if len(key128) != 16 {
		t.Errorf("expected 16 bytes for 128-bit key, got %d", len(key128))
	}

	// Same input should produce same output
	key128_2 := kdf(ki, label, context, 128)
	if !bytes.Equal(key128, key128_2) {
		t.Error("KDF should be deterministic")
	}

	// Different label should produce different key
	key128_3 := kdf(ki, []byte("Different\x00"), context, 128)
	if bytes.Equal(key128, key128_3) {
		t.Error("different label should produce different key")
	}
}

func TestShiftLeft(t *testing.T) {
	// Test basic shift: 0x80 << 1 = 0x00 with carry
	// For [0x80, 0x00], shifting left by 1:
	// First byte: 0x80 << 1 = 0x00, but we also OR with next byte's MSB (0)
	// Second byte: 0x00 << 1 = 0x00
	input := []byte{0x80, 0x00}
	result := shiftLeft(input)
	// Result: [0x00, 0x00] - the high bit is lost
	expected := []byte{0x00, 0x00}
	if !bytes.Equal(result, expected) {
		t.Errorf("expected %x, got %x", expected, result)
	}

	// Test carry across bytes: [0x00, 0x80] shifts to [0x01, 0x00]
	input2 := []byte{0x00, 0x80}
	result2 := shiftLeft(input2)
	expected2 := []byte{0x01, 0x00}
	if !bytes.Equal(result2, expected2) {
		t.Errorf("expected %x, got %x", expected2, result2)
	}
}

func TestXorBytes(t *testing.T) {
	a := []byte{0xFF, 0x00, 0xAA}
	b := []byte{0x0F, 0xF0, 0x55}
	expected := []byte{0xF0, 0xF0, 0xFF}

	result := xorBytes(a, b)
	if !bytes.Equal(result, expected) {
		t.Errorf("expected %x, got %x", expected, result)
	}
}
