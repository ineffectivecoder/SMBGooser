package smb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"

	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

// Signing algorithms
const (
	SigningAlgoHMACSHA256 = 0 // SMB 2.x
	SigningAlgoAESCMAC    = 1 // SMB 3.x
)

// SMB2 header signature offset and size
const (
	signatureOffset = 48 // Signature field starts at byte 48 in SMB2 header
	signatureSize   = 16
)

// signMessage signs an SMB message and returns the message with signature
func signMessage(dialect types.Dialect, signingKey []byte, message []byte) []byte {
	if len(signingKey) == 0 || len(message) < types.SMB2HeaderSize {
		return message
	}

	// Make a copy to avoid modifying original
	signed := make([]byte, len(message))
	copy(signed, message)

	// Zero out signature field before computing
	for i := signatureOffset; i < signatureOffset+signatureSize; i++ {
		signed[i] = 0
	}

	// Compute signature based on dialect
	var signature []byte
	if dialect >= types.DialectSMB3_0 {
		// SMB3: Use AES-CMAC
		signature = computeAESCMAC(signingKey, signed)
	} else {
		// SMB2: Use HMAC-SHA256
		signature = computeHMACSHA256(signingKey, signed)
	}

	// Copy signature into message (first 16 bytes)
	copy(signed[signatureOffset:signatureOffset+signatureSize], signature[:signatureSize])

	return signed
}

// verifySignature verifies an SMB message signature
func verifySignature(dialect types.Dialect, signingKey []byte, message []byte) bool {
	if len(signingKey) == 0 || len(message) < types.SMB2HeaderSize {
		return false
	}

	// Extract the signature from the message
	expectedSig := make([]byte, signatureSize)
	copy(expectedSig, message[signatureOffset:signatureOffset+signatureSize])

	// Zero out signature field
	msgCopy := make([]byte, len(message))
	copy(msgCopy, message)
	for i := signatureOffset; i < signatureOffset+signatureSize; i++ {
		msgCopy[i] = 0
	}

	// Compute expected signature
	var computedSig []byte
	if dialect >= types.DialectSMB3_0 {
		computedSig = computeAESCMAC(signingKey, msgCopy)
	} else {
		computedSig = computeHMACSHA256(signingKey, msgCopy)
	}

	// Compare signatures (constant time)
	return hmac.Equal(expectedSig, computedSig[:signatureSize])
}

// computeHMACSHA256 computes HMAC-SHA256 signature for SMB2
func computeHMACSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil) // Returns 32 bytes, we use first 16
}

// computeAESCMAC computes AES-CMAC signature for SMB3
// Implements RFC 4493
func computeAESCMAC(key, message []byte) []byte {
	block, err := aes.NewCipher(key[:16]) // AES-128
	if err != nil {
		return make([]byte, signatureSize)
	}

	// Generate subkeys K1, K2
	k1, k2 := generateCMACSubkeys(block)

	// Pad message and XOR with appropriate subkey
	blockSize := block.BlockSize()
	numBlocks := (len(message) + blockSize - 1) / blockSize
	if numBlocks == 0 {
		numBlocks = 1
	}

	// Process all blocks except last
	x := make([]byte, blockSize)
	for i := 0; i < numBlocks-1; i++ {
		start := i * blockSize
		y := xorBytes(x, message[start:start+blockSize])
		block.Encrypt(x, y)
	}

	// Process last block with padding
	lastBlockStart := (numBlocks - 1) * blockSize
	lastBlock := make([]byte, blockSize)
	lastBlockLen := len(message) - lastBlockStart

	if lastBlockLen > 0 && lastBlockLen == blockSize {
		// Complete block - XOR with K1
		copy(lastBlock, message[lastBlockStart:])
		lastBlock = xorBytes(lastBlock, k1)
	} else {
		// Incomplete block - pad and XOR with K2
		if lastBlockLen > 0 {
			copy(lastBlock, message[lastBlockStart:])
		}
		lastBlock[lastBlockLen] = 0x80 // Padding
		lastBlock = xorBytes(lastBlock, k2)
	}

	y := xorBytes(x, lastBlock)
	result := make([]byte, blockSize)
	block.Encrypt(result, y)

	return result
}

// generateCMACSubkeys generates K1 and K2 subkeys for CMAC
func generateCMACSubkeys(block cipher.Block) (k1, k2 []byte) {
	blockSize := block.BlockSize()

	// L = AES(K, 0^n)
	l := make([]byte, blockSize)
	block.Encrypt(l, l)

	// K1 = L << 1 (with conditional XOR)
	k1 = shiftLeft(l)
	if l[0]&0x80 != 0 {
		k1[blockSize-1] ^= 0x87 // R_b for AES (0x87)
	}

	// K2 = K1 << 1 (with conditional XOR)
	k2 = shiftLeft(k1)
	if k1[0]&0x80 != 0 {
		k2[blockSize-1] ^= 0x87
	}

	return k1, k2
}

// shiftLeft shifts a byte slice left by 1 bit
func shiftLeft(data []byte) []byte {
	result := make([]byte, len(data))
	for i := 0; i < len(data)-1; i++ {
		result[i] = (data[i] << 1) | (data[i+1] >> 7)
	}
	result[len(data)-1] = data[len(data)-1] << 1
	return result
}

// xorBytes XORs two byte slices
func xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// deriveSigningKey derives the SMB3 signing key using KDF
// For SMB 3.0/3.0.2: KDF(SessionKey, "SMB2AESCMAC", "SmbSign")
// For SMB 3.1.1: KDF(SessionKey, "SMBSigningKey", PreauthIntegrityHash)
func deriveSigningKey(sessionKey []byte, dialect types.Dialect, preauthHash []byte) []byte {
	if dialect < types.DialectSMB3_0 {
		// SMB2: Use session key directly
		return sessionKey
	}

	var label, context []byte
	if dialect >= types.DialectSMB3_1_1 {
		// SMB 3.1.1
		label = []byte("SMBSigningKey\x00")
		context = preauthHash
	} else {
		// SMB 3.0/3.0.2
		label = []byte("SMB2AESCMAC\x00")
		context = []byte("SmbSign\x00")
	}

	return kdf(sessionKey, label, context, 128)
}

// kdf implements SP800-108 Counter Mode KDF with HMAC-SHA256
// Matches Impacket's KDF_CounterMode implementation exactly
func kdf(ki, label, context []byte, bitLen int) []byte {
	// Counter mode: K(i) = PRF(KI, [i]_2 || Label || 0x00 || Context || [L]_2)
	// Note: Label already includes null terminator, add separator after
	h := hmac.New(sha256.New, ki)

	// i = 1 (32-bit BIG-ENDIAN counter - matches Impacket pack('>L', i))
	h.Write([]byte{0x00, 0x00, 0x00, 0x01})
	h.Write(label)
	h.Write([]byte{0x00}) // Separator after label
	h.Write(context)

	// L = bit length (32-bit BIG-ENDIAN - matches Impacket pack('>L', L))
	l := uint32(bitLen)
	h.Write([]byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)})

	result := h.Sum(nil)

	// Return first L/8 bytes
	return result[:bitLen/8]
}
