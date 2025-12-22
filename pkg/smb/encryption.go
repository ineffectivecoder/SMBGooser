package smb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

// Encryption cipher identifiers
const (
	EncryptionAES128CCM uint16 = 0x0001 // SMB 3.0/3.0.2
	EncryptionAES128GCM uint16 = 0x0002 // SMB 3.1.1
)

// Transform header size
const TransformHeaderSize = 52

// SMB2_TRANSFORM_HEADER protocol ID
var SMB2TransformID = [4]byte{0xFD, 'S', 'M', 'B'}

// TransformHeader represents an SMB2_TRANSFORM_HEADER for encrypted messages
// See MS-SMB2 section 2.2.41
type TransformHeader struct {
	ProtocolID          [4]byte  // 0xFD 'S' 'M' 'B'
	Signature           [16]byte // AES-CMAC or AES-GMAC signature
	Nonce               [16]byte // Nonce (11 bytes for CCM, 12 bytes for GCM, rest zero)
	OriginalMessageSize uint32   // Size of the original (unencrypted) message
	Reserved            uint16   // Reserved, must be 0
	Flags               uint16   // Encryption flags (0x0001 = encrypted)
	SessionID           uint64   // Session identifier
}

// Marshal serializes the transform header
func (h *TransformHeader) Marshal() []byte {
	buf := make([]byte, TransformHeaderSize)

	copy(buf[0:4], h.ProtocolID[:])
	copy(buf[4:20], h.Signature[:])
	copy(buf[20:36], h.Nonce[:])
	binary.LittleEndian.PutUint32(buf[36:40], h.OriginalMessageSize)
	binary.LittleEndian.PutUint16(buf[40:42], h.Reserved)
	binary.LittleEndian.PutUint16(buf[42:44], h.Flags)
	binary.LittleEndian.PutUint64(buf[44:52], h.SessionID)

	return buf
}

// Unmarshal deserializes a transform header
func (h *TransformHeader) Unmarshal(buf []byte) error {
	if len(buf) < TransformHeaderSize {
		return errors.New("buffer too small for transform header")
	}

	copy(h.ProtocolID[:], buf[0:4])

	// Verify protocol ID
	if h.ProtocolID != SMB2TransformID {
		return errors.New("invalid transform header protocol ID")
	}

	copy(h.Signature[:], buf[4:20])
	copy(h.Nonce[:], buf[20:36])
	h.OriginalMessageSize = binary.LittleEndian.Uint32(buf[36:40])
	h.Reserved = binary.LittleEndian.Uint16(buf[40:42])
	h.Flags = binary.LittleEndian.Uint16(buf[42:44])
	h.SessionID = binary.LittleEndian.Uint64(buf[44:52])

	return nil
}

// isEncryptedMessage checks if a message is encrypted (starts with transform header)
func isEncryptedMessage(msg []byte) bool {
	if len(msg) < 4 {
		return false
	}
	return msg[0] == 0xFD && msg[1] == 'S' && msg[2] == 'M' && msg[3] == 'B'
}

// encryptMessage encrypts an SMB message using the transform header format
func encryptMessage(cipherID uint16, key []byte, sessionID uint64, plaintext []byte) ([]byte, error) {
	if len(key) < 16 {
		return nil, errors.New("encryption key too short")
	}

	// Generate random nonce
	var nonce [16]byte
	nonceLen := 11 // CCM uses 11-byte nonce
	if cipherID == EncryptionAES128GCM {
		nonceLen = 12 // GCM uses 12-byte nonce
	}
	if _, err := rand.Read(nonce[:nonceLen]); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Build transform header (without signature yet)
	header := TransformHeader{
		ProtocolID:          SMB2TransformID,
		Nonce:               nonce,
		OriginalMessageSize: uint32(len(plaintext)),
		Reserved:            0,
		Flags:               0x0001, // Encrypted
		SessionID:           sessionID,
	}

	// Associated data for AEAD: transform header bytes 20-52 (nonce through session ID)
	aad := header.Marshal()[20:TransformHeaderSize]

	var ciphertext []byte
	var tag []byte
	var err error

	switch cipherID {
	case EncryptionAES128CCM:
		ciphertext, tag, err = encryptAESCCM(key[:16], nonce[:11], plaintext, aad)
	case EncryptionAES128GCM:
		ciphertext, tag, err = encryptAESGCM(key[:16], nonce[:12], plaintext, aad)
	default:
		return nil, fmt.Errorf("unsupported cipher: 0x%04X", cipherID)
	}

	if err != nil {
		return nil, err
	}

	// Copy signature (authentication tag) into header
	copy(header.Signature[:], tag)

	// Build final message: transform header + ciphertext
	result := make([]byte, TransformHeaderSize+len(ciphertext))
	copy(result[0:TransformHeaderSize], header.Marshal())
	copy(result[TransformHeaderSize:], ciphertext)

	return result, nil
}

// decryptMessage decrypts an encrypted SMB message
func decryptMessage(cipherID uint16, key []byte, encrypted []byte) ([]byte, error) {
	if len(key) < 16 {
		return nil, errors.New("decryption key too short")
	}

	if len(encrypted) < TransformHeaderSize {
		return nil, errors.New("encrypted message too short")
	}

	// Parse transform header
	var header TransformHeader
	if err := header.Unmarshal(encrypted[:TransformHeaderSize]); err != nil {
		return nil, err
	}

	ciphertext := encrypted[TransformHeaderSize:]

	// Associated data: bytes 20-52 of transform header
	aad := encrypted[20:TransformHeaderSize]

	var plaintext []byte
	var err error

	switch cipherID {
	case EncryptionAES128CCM:
		plaintext, err = decryptAESCCM(key[:16], header.Nonce[:11], ciphertext, header.Signature[:], aad)
	case EncryptionAES128GCM:
		plaintext, err = decryptAESGCM(key[:16], header.Nonce[:12], ciphertext, header.Signature[:], aad)
	default:
		return nil, fmt.Errorf("unsupported cipher: 0x%04X", cipherID)
	}

	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// encryptAESGCM encrypts using AES-128-GCM (SMB 3.1.1)
func encryptAESGCM(key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// GCM appends tag to ciphertext, we need to separate them
	sealed := aesGCM.Seal(nil, nonce, plaintext, aad)

	// Tag is last 16 bytes
	tagSize := aesGCM.Overhead()
	ciphertext = sealed[:len(sealed)-tagSize]
	tag = sealed[len(sealed)-tagSize:]

	return ciphertext, tag, nil
}

// decryptAESGCM decrypts using AES-128-GCM (SMB 3.1.1)
func decryptAESGCM(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// GCM expects tag appended to ciphertext
	sealed := append(ciphertext, tag...)

	plaintext, err := aesGCM.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, errors.New("authentication failed")
	}

	return plaintext, nil
}

// encryptAESCCM encrypts using AES-128-CCM (SMB 3.0/3.0.2)
// Implements CCM mode per RFC 3610
func encryptAESCCM(key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// CCM parameters for SMB:
	// - Nonce length (N): 11 bytes
	// - Tag length (T): 16 bytes
	// - Max message length determines L: L = 15 - N = 4 (supports up to 2^32 bytes)

	tagLen := 16
	L := 15 - len(nonce) // L = 4 for 11-byte nonce

	// Generate authentication tag (T)
	tag = ccmGenerateTag(block, nonce, plaintext, aad, tagLen, L)

	// Encrypt plaintext and tag using CTR mode
	ciphertext = ccmCTREncrypt(block, nonce, plaintext, tag, L)

	return ciphertext, tag, nil
}

// decryptAESCCM decrypts using AES-128-CCM (SMB 3.0/3.0.2)
func decryptAESCCM(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	tagLen := 16
	L := 15 - len(nonce)

	// Decrypt ciphertext using CTR mode
	plaintext, decryptedTag := ccmCTRDecrypt(block, nonce, ciphertext, tagLen, L)

	// Verify authentication tag
	expectedTag := ccmGenerateTag(block, nonce, plaintext, aad, tagLen, L)

	// Constant-time comparison
	valid := true
	for i := 0; i < len(tag) && i < len(expectedTag); i++ {
		if tag[i] != expectedTag[i] {
			valid = false
		}
	}
	_ = decryptedTag // Not used in verification

	if !valid {
		return nil, errors.New("authentication failed")
	}

	return plaintext, nil
}

// ccmGenerateTag generates the CCM authentication tag (CBC-MAC)
func ccmGenerateTag(block cipher.Block, nonce, plaintext, aad []byte, tagLen, L int) []byte {
	blockSize := block.BlockSize()

	// Build B_0 (first block for CBC-MAC)
	// Flags: Reserved(1) || Adata(1) || M'(3) || L'(3)
	// M' = (tagLen-2)/2, L' = L-1
	flags := byte(0)
	if len(aad) > 0 {
		flags |= 0x40 // Adata flag
	}
	flags |= byte(((tagLen-2)/2)&0x07) << 3 // M'
	flags |= byte((L - 1) & 0x07)           // L'

	b0 := make([]byte, blockSize)
	b0[0] = flags
	copy(b0[1:], nonce)

	// Encode message length in last L bytes (big-endian)
	msgLen := len(plaintext)
	for i := 0; i < L; i++ {
		b0[15-i] = byte(msgLen >> (8 * i))
	}

	// Initialize CBC-MAC with B_0
	x := make([]byte, blockSize)
	block.Encrypt(x, b0)

	// Process AAD if present
	if len(aad) > 0 {
		// Encode AAD length (assuming < 2^16 - 2^8)
		aadBlock := make([]byte, 0, blockSize)
		if len(aad) < 65280 {
			aadBlock = append(aadBlock, byte(len(aad)>>8), byte(len(aad)))
		}
		aadBlock = append(aadBlock, aad...)

		// Pad to block size
		for len(aadBlock)%blockSize != 0 {
			aadBlock = append(aadBlock, 0)
		}

		// Process AAD blocks
		for i := 0; i < len(aadBlock); i += blockSize {
			for j := 0; j < blockSize; j++ {
				x[j] ^= aadBlock[i+j]
			}
			block.Encrypt(x, x)
		}
	}

	// Process plaintext
	for i := 0; i < len(plaintext); i += blockSize {
		end := i + blockSize
		if end > len(plaintext) {
			// Pad last block
			padded := make([]byte, blockSize)
			copy(padded, plaintext[i:])
			for j := 0; j < blockSize; j++ {
				x[j] ^= padded[j]
			}
		} else {
			for j := 0; j < blockSize; j++ {
				x[j] ^= plaintext[i+j]
			}
		}
		block.Encrypt(x, x)
	}

	return x[:tagLen]
}

// ccmCTREncrypt encrypts plaintext and tag using CTR mode
func ccmCTREncrypt(block cipher.Block, nonce, plaintext, tag []byte, L int) []byte {
	blockSize := block.BlockSize()

	// Build A_0 (counter block format)
	// Flags: Reserved(2) || 0(3) || L'(3)
	a0 := make([]byte, blockSize)
	a0[0] = byte((L - 1) & 0x07)
	copy(a0[1:], nonce)
	// Counter starts at 0 for encrypting tag

	// Encrypt tag with A_0
	s0 := make([]byte, blockSize)
	block.Encrypt(s0, a0)
	encryptedTag := make([]byte, len(tag))
	for i := 0; i < len(tag); i++ {
		encryptedTag[i] = tag[i] ^ s0[i]
	}

	// Encrypt plaintext with A_1, A_2, ...
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += blockSize {
		// Increment counter
		for j := blockSize - 1; j >= blockSize-L; j-- {
			a0[j]++
			if a0[j] != 0 {
				break
			}
		}

		s := make([]byte, blockSize)
		block.Encrypt(s, a0)

		end := i + blockSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		for j := i; j < end; j++ {
			ciphertext[j] = plaintext[j] ^ s[j-i]
		}
	}

	return ciphertext
}

// ccmCTRDecrypt decrypts ciphertext using CTR mode and returns decrypted tag
func ccmCTRDecrypt(block cipher.Block, nonce, ciphertext []byte, tagLen, L int) (plaintext, tag []byte) {
	blockSize := block.BlockSize()

	// Build A_0
	a0 := make([]byte, blockSize)
	a0[0] = byte((L - 1) & 0x07)
	copy(a0[1:], nonce)

	// Decrypt plaintext with A_1, A_2, ...
	plaintext = make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += blockSize {
		// Increment counter
		for j := blockSize - 1; j >= blockSize-L; j-- {
			a0[j]++
			if a0[j] != 0 {
				break
			}
		}

		s := make([]byte, blockSize)
		block.Encrypt(s, a0)

		end := i + blockSize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		for j := i; j < end; j++ {
			plaintext[j] = ciphertext[j] ^ s[j-i]
		}
	}

	// Tag would be decrypted separately using S_0
	// For verification, we regenerate expected tag from plaintext
	tag = nil
	return plaintext, tag
}

// deriveEncryptionKey derives the client-to-server encryption key for SMB3
func deriveEncryptionKey(sessionKey []byte, dialect types.Dialect, preauthHash []byte) []byte {
	if dialect < types.DialectSMB3_0 {
		return nil // No encryption for SMB2
	}

	var label, context []byte
	if dialect >= types.DialectSMB3_1_1 {
		label = []byte("SMBC2SCipherKey\x00")
		context = preauthHash
	} else {
		label = []byte("SMB2AESCCM\x00")
		context = []byte("ServerIn \x00")
	}

	return kdf(sessionKey, label, context, 128)
}

// deriveDecryptionKey derives the server-to-client decryption key for SMB3
func deriveDecryptionKey(sessionKey []byte, dialect types.Dialect, preauthHash []byte) []byte {
	if dialect < types.DialectSMB3_0 {
		return nil // No encryption for SMB2
	}

	var label, context []byte
	if dialect >= types.DialectSMB3_1_1 {
		label = []byte("SMBS2CCipherKey\x00")
		context = preauthHash
	} else {
		label = []byte("SMB2AESCCM\x00")
		context = []byte("ServerOut\x00")
	}

	return kdf(sessionKey, label, context, 128)
}
