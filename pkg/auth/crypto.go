package auth

import (
	"crypto/rand"
	"crypto/rc4"
	"strings"
	"time"

	"github.com/ineffectivecoder/SMBGooser/internal/crypto"
	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// randomBytes fills the slice with random bytes
func randomBytes(b []byte) {
	rand.Read(b)
}

// rc4Encrypt encrypts data with RC4 using the given key
func rc4Encrypt(key, plaintext []byte) []byte {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return plaintext
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

// NTHash computes the NT hash from a password
// NT Hash = MD4(UTF-16LE(password))
func NTHash(password string) []byte {
	return crypto.MD4Hash(encoding.ToUTF16LE(password))
}

// NTLMv2Hash computes the NTLMv2 hash
// NTLMv2 Hash = HMAC-MD5(NT Hash, UPPERCASE(username) + domain)
func NTLMv2Hash(ntHash []byte, username, domain string) []byte {
	userDomain := encoding.ToUTF16LE(strings.ToUpper(username) + domain)
	return crypto.HMACMD5(ntHash, userDomain)
}

// ComputeNTLMv2HashFromPassword computes NTLMv2 hash from password
func ComputeNTLMv2HashFromPassword(password, username, domain string) []byte {
	ntHash := NTHash(password)
	return NTLMv2Hash(ntHash, username, domain)
}

// NTLMv2Response computes the NTLMv2 response and session base key
func NTLMv2Response(ntlmv2Hash, serverChallenge, clientChallenge []byte,
	timestamp []byte, targetInfo []byte) (response []byte, sessionBaseKey []byte) {

	// Build NTLMv2 client blob
	blob := buildNTLMv2Blob(clientChallenge, timestamp, targetInfo)

	// NTProofStr = HMAC-MD5(NTLMv2 Hash, ServerChallenge + Blob)
	data := append(serverChallenge, blob...)
	ntProofStr := crypto.HMACMD5(ntlmv2Hash, data)

	// Response = NTProofStr + Blob
	response = append(ntProofStr, blob...)

	// Session Base Key = HMAC-MD5(NTLMv2 Hash, NTProofStr)
	sessionBaseKey = crypto.HMACMD5(ntlmv2Hash, ntProofStr)

	return response, sessionBaseKey
}

// buildNTLMv2Blob builds the NTLMv2 client blob/temp structure
func buildNTLMv2Blob(clientChallenge, timestamp, targetInfo []byte) []byte {
	// If no timestamp provided, use current time
	if len(timestamp) != 8 {
		timestamp = make([]byte, 8)
		// FILETIME: 100-nanosecond intervals since January 1, 1601
		// Convert Unix timestamp to Windows FILETIME
		ft := uint64(time.Now().UnixNano()/100 + 116444736000000000)
		encoding.PutUint64LE(timestamp, ft)
	}

	// Blob structure:
	// RespType (1) + HiRespType (1) + Reserved1 (2) + Reserved2 (4) +
	// TimeStamp (8) + ClientChallenge (8) + Reserved3 (4) + TargetInfo + Reserved4 (4)
	blobLen := 28 + len(targetInfo) + 4
	blob := make([]byte, blobLen)

	offset := 0
	blob[offset] = 0x01 // RespType
	offset++
	blob[offset] = 0x01 // HiRespType
	offset++
	// Reserved1 (2 bytes) - already zero
	offset += 2
	// Reserved2 (4 bytes) - already zero
	offset += 4
	// Timestamp (8 bytes)
	copy(blob[offset:offset+8], timestamp)
	offset += 8
	// Client Challenge (8 bytes)
	copy(blob[offset:offset+8], clientChallenge)
	offset += 8
	// Reserved3 (4 bytes) - already zero
	offset += 4
	// TargetInfo
	copy(blob[offset:], targetInfo)
	offset += len(targetInfo)
	// Reserved4 (4 bytes) - already zero

	return blob
}

// GenerateClientChallenge generates a random 8-byte client challenge
func GenerateClientChallenge() []byte {
	challenge := make([]byte, 8)
	rand.Read(challenge)
	return challenge
}

// LMv2Response computes the LMv2 response (usually empty for NTLMv2)
func LMv2Response(ntlmv2Hash, serverChallenge, clientChallenge []byte) []byte {
	// LMv2 Response = HMAC-MD5(NTLMv2 Hash, ServerChallenge + ClientChallenge) + ClientChallenge
	data := append(serverChallenge, clientChallenge...)
	resp := crypto.HMACMD5(ntlmv2Hash, data)
	return append(resp, clientChallenge...)
}
