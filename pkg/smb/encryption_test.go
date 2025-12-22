package smb

import (
	"bytes"
	"testing"

	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

func TestTransformHeaderMarshalUnmarshal(t *testing.T) {
	header := TransformHeader{
		ProtocolID:          SMB2TransformID,
		Nonce:               [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 0, 0},
		OriginalMessageSize: 1024,
		Reserved:            0,
		Flags:               0x0001,
		SessionID:           0x123456789ABCDEF0,
	}
	copy(header.Signature[:], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00})

	// Marshal
	data := header.Marshal()
	if len(data) != TransformHeaderSize {
		t.Errorf("expected %d bytes, got %d", TransformHeaderSize, len(data))
	}

	// Verify protocol ID
	if data[0] != 0xFD || data[1] != 'S' || data[2] != 'M' || data[3] != 'B' {
		t.Errorf("invalid protocol ID: %v", data[:4])
	}

	// Unmarshal
	var parsed TransformHeader
	if err := parsed.Unmarshal(data); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Verify fields
	if parsed.OriginalMessageSize != 1024 {
		t.Errorf("expected OriginalMessageSize 1024, got %d", parsed.OriginalMessageSize)
	}
	if parsed.SessionID != 0x123456789ABCDEF0 {
		t.Errorf("expected SessionID 0x123456789ABCDEF0, got 0x%X", parsed.SessionID)
	}
	if parsed.Flags != 0x0001 {
		t.Errorf("expected Flags 0x0001, got 0x%04X", parsed.Flags)
	}
}

func TestIsEncryptedMessage(t *testing.T) {
	// Encrypted message (transform header)
	encrypted := []byte{0xFD, 'S', 'M', 'B', 0, 0, 0, 0}
	if !isEncryptedMessage(encrypted) {
		t.Error("should detect encrypted message")
	}

	// Normal SMB2 message
	normal := []byte{0xFE, 'S', 'M', 'B', 0, 0, 0, 0}
	if isEncryptedMessage(normal) {
		t.Error("should not detect normal message as encrypted")
	}

	// Too short
	short := []byte{0xFD, 'S'}
	if isEncryptedMessage(short) {
		t.Error("should not detect short message as encrypted")
	}
}

func TestAESGCMRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes
	nonce := []byte("123456789012")   // 12 bytes for GCM
	plaintext := []byte("This is a test message for AES-GCM encryption")
	aad := []byte("additional authenticated data")

	// Encrypt
	ciphertext, tag, err := encryptAESGCM(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Should produce different output
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	// Tag should be 16 bytes
	if len(tag) != 16 {
		t.Errorf("expected 16-byte tag, got %d", len(tag))
	}

	// Decrypt
	decrypted, err := decryptAESGCM(key, nonce, ciphertext, tag, aad)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	// Should match original
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted text doesn't match:\ngot: %s\nexpected: %s", decrypted, plaintext)
	}
}

func TestAESGCMAuthFailure(t *testing.T) {
	key := []byte("0123456789abcdef")
	nonce := []byte("123456789012")
	plaintext := []byte("Test message")
	aad := []byte("aad")

	ciphertext, tag, _ := encryptAESGCM(key, nonce, plaintext, aad)

	// Tamper with ciphertext
	ciphertext[0] ^= 0xFF

	// Should fail authentication
	_, err := decryptAESGCM(key, nonce, ciphertext, tag, aad)
	if err == nil {
		t.Error("should fail with tampered ciphertext")
	}
}

func TestAESCCMRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes
	nonce := []byte("12345678901")    // 11 bytes for CCM
	plaintext := []byte("This is a test message for AES-CCM encryption")
	aad := []byte("additional authenticated data")

	// Encrypt
	ciphertext, tag, err := encryptAESCCM(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Should produce different output
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	// Tag should be 16 bytes
	if len(tag) != 16 {
		t.Errorf("expected 16-byte tag, got %d", len(tag))
	}

	// Decrypt
	decrypted, err := decryptAESCCM(key, nonce, ciphertext, tag, aad)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	// Should match original
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted text doesn't match:\ngot: %s\nexpected: %s", decrypted, plaintext)
	}
}

func TestAESCCMAuthFailure(t *testing.T) {
	key := []byte("0123456789abcdef")
	nonce := []byte("12345678901")
	plaintext := []byte("Test message")
	aad := []byte("aad")

	ciphertext, tag, _ := encryptAESCCM(key, nonce, plaintext, aad)

	// Tamper with ciphertext
	ciphertext[0] ^= 0xFF

	// Should fail authentication
	_, err := decryptAESCCM(key, nonce, ciphertext, tag, aad)
	if err == nil {
		t.Error("should fail with tampered ciphertext")
	}
}

func TestEncryptDecryptMessage(t *testing.T) {
	key := []byte("0123456789abcdef")
	sessionID := uint64(0x1234567890ABCDEF)

	// Create a mock SMB message
	plaintext := make([]byte, 100)
	copy(plaintext[0:4], []byte{0xFE, 'S', 'M', 'B'}) // SMB2 header

	// Test with GCM
	encrypted, err := encryptMessage(EncryptionAES128GCM, key, sessionID, plaintext)
	if err != nil {
		t.Fatalf("encryptMessage failed: %v", err)
	}

	// Should be encrypted (has transform header)
	if !isEncryptedMessage(encrypted) {
		t.Error("encrypted message should have transform header")
	}

	// Decrypt
	decrypted, err := decryptMessage(EncryptionAES128GCM, key, encrypted)
	if err != nil {
		t.Fatalf("decryptMessage failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted message doesn't match original")
	}
}

func TestDeriveEncryptionKey(t *testing.T) {
	sessionKey := []byte("0123456789abcdef")

	// SMB2 should return nil (no encryption)
	smb2Key := deriveEncryptionKey(sessionKey, types.DialectSMB2_1, nil)
	if smb2Key != nil {
		t.Error("SMB2 should not have encryption key")
	}

	// SMB3 should derive a key
	smb3Key := deriveEncryptionKey(sessionKey, types.DialectSMB3_0, nil)
	if smb3Key == nil {
		t.Fatal("SMB3 should derive encryption key")
	}
	if len(smb3Key) != 16 {
		t.Errorf("expected 16-byte key, got %d", len(smb3Key))
	}

	// SMB 3.1.1 with preauth hash should derive different key
	preauthHash := make([]byte, 64)
	smb311Key := deriveEncryptionKey(sessionKey, types.DialectSMB3_1_1, preauthHash)
	if bytes.Equal(smb3Key, smb311Key) {
		t.Error("SMB 3.1.1 key should differ from SMB 3.0 key")
	}
}

func TestDeriveDecryptionKey(t *testing.T) {
	sessionKey := []byte("0123456789abcdef")

	// SMB3 encryption and decryption keys should differ
	encKey := deriveEncryptionKey(sessionKey, types.DialectSMB3_0, nil)
	decKey := deriveDecryptionKey(sessionKey, types.DialectSMB3_0, nil)

	if bytes.Equal(encKey, decKey) {
		t.Error("encryption and decryption keys should be different")
	}
}
