package auth

import (
	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// AuthenticateMessage represents NTLMSSP Type 3 message (AUTHENTICATE_MESSAGE)
type AuthenticateMessage struct {
	Signature                       [8]byte
	MessageType                     uint32 // Always 3
	LmChallengeResponseFields       SecurityBuffer
	NtChallengeResponseFields       SecurityBuffer
	DomainNameFields                SecurityBuffer
	UserNameFields                  SecurityBuffer
	WorkstationFields               SecurityBuffer
	EncryptedRandomSessionKeyFields SecurityBuffer
	NegotiateFlags                  uint32
	Version                         NTLMVersion
	MIC                             [16]byte

	// Payload data
	LmChallengeResponse       []byte
	NtChallengeResponse       []byte
	DomainName                []byte
	UserName                  []byte
	Workstation               []byte
	EncryptedRandomSessionKey []byte

	// For MIC calculation
	SessionBaseKey []byte
}

// AuthenticateOptions configures Type 3 message generation
type AuthenticateOptions struct {
	Domain      string
	Username    string
	Workstation string
	NTLMv2Hash  []byte // Provide directly for pass-the-hash
	Password    string // Or provide password
	IncludeMIC  bool
}

// NewAuthenticateMessage creates a Type 3 message
func NewAuthenticateMessage(challenge *ChallengeMessage, opts AuthenticateOptions) *AuthenticateMessage {
	m := &AuthenticateMessage{
		Signature:      ntlmSignature,
		MessageType:    NtLmAuthenticate,
		NegotiateFlags: challenge.NegotiateFlags,
		Version:        DefaultVersion(),
	}

	// Compute NTLMv2 hash
	var ntlmv2Hash []byte
	if len(opts.NTLMv2Hash) > 0 {
		ntlmv2Hash = opts.NTLMv2Hash
	} else if opts.Password != "" {
		ntlmv2Hash = ComputeNTLMv2HashFromPassword(opts.Password, opts.Username, opts.Domain)
	}

	// Generate client challenge
	clientChallenge := GenerateClientChallenge()

	// Get timestamp from challenge, or generate new one
	timestamp := challenge.GetTimestamp()

	// Compute NTLMv2 response
	ntResponse, sessionBaseKey := NTLMv2Response(
		ntlmv2Hash,
		challenge.ServerChallenge[:],
		clientChallenge,
		timestamp,
		challenge.TargetInfo,
	)
	m.NtChallengeResponse = ntResponse
	m.SessionBaseKey = sessionBaseKey

	// LMv2 response (can be empty or use same client challenge)
	m.LmChallengeResponse = LMv2Response(ntlmv2Hash, challenge.ServerChallenge[:], clientChallenge)

	// Domain and username
	m.DomainName = encoding.ToUTF16LE(opts.Domain)
	m.UserName = encoding.ToUTF16LE(opts.Username)
	m.Workstation = encoding.ToUTF16LE(opts.Workstation)

	// Handle KEY_EXCH flag (0x40000000)
	// MS-NLMP says if set, encrypt a random key and send it. However,
	// in practice servers (at least Windows) appear to use sessionBaseKey directly
	// for SMB3 signing key derivation regardless of key exchange.
	// To maintain protocol compliance, we still send the encrypted key
	// but use sessionBaseKey for our signing operations.
	if m.NegotiateFlags&NtlmsspNegotiateKeyExchange != 0 {
		// Generate and encrypt random session key for protocol compliance
		exportedSessionKey := make([]byte, 16)
		randomBytes(exportedSessionKey)
		m.EncryptedRandomSessionKey = rc4Encrypt(sessionBaseKey, exportedSessionKey)
	} else {
		m.EncryptedRandomSessionKey = []byte{}
	}

	// Always use sessionBaseKey for signing
	// This matches observed Windows behavior for SMB3 signing
	m.SessionBaseKey = sessionBaseKey

	return m
}

// Marshal serializes the Type 3 message
func (m *AuthenticateMessage) Marshal() []byte {
	// Calculate payload offsets
	// Fixed part: 88 bytes (with MIC) or 72 bytes (without MIC)
	fixedLen := 88 // Including MIC

	// Build payload and calculate offsets
	payloadOffset := uint32(fixedLen)

	// LmChallengeResponse
	m.LmChallengeResponseFields.Len = uint16(len(m.LmChallengeResponse))
	m.LmChallengeResponseFields.MaxLen = uint16(len(m.LmChallengeResponse))
	m.LmChallengeResponseFields.Offset = payloadOffset
	payloadOffset += uint32(len(m.LmChallengeResponse))

	// NtChallengeResponse
	m.NtChallengeResponseFields.Len = uint16(len(m.NtChallengeResponse))
	m.NtChallengeResponseFields.MaxLen = uint16(len(m.NtChallengeResponse))
	m.NtChallengeResponseFields.Offset = payloadOffset
	payloadOffset += uint32(len(m.NtChallengeResponse))

	// DomainName
	m.DomainNameFields.Len = uint16(len(m.DomainName))
	m.DomainNameFields.MaxLen = uint16(len(m.DomainName))
	m.DomainNameFields.Offset = payloadOffset
	payloadOffset += uint32(len(m.DomainName))

	// UserName
	m.UserNameFields.Len = uint16(len(m.UserName))
	m.UserNameFields.MaxLen = uint16(len(m.UserName))
	m.UserNameFields.Offset = payloadOffset
	payloadOffset += uint32(len(m.UserName))

	// Workstation
	m.WorkstationFields.Len = uint16(len(m.Workstation))
	m.WorkstationFields.MaxLen = uint16(len(m.Workstation))
	m.WorkstationFields.Offset = payloadOffset
	payloadOffset += uint32(len(m.Workstation))

	// EncryptedRandomSessionKey
	m.EncryptedRandomSessionKeyFields.Len = uint16(len(m.EncryptedRandomSessionKey))
	m.EncryptedRandomSessionKeyFields.MaxLen = uint16(len(m.EncryptedRandomSessionKey))
	m.EncryptedRandomSessionKeyFields.Offset = payloadOffset

	// Allocate buffer
	totalLen := int(payloadOffset) + len(m.EncryptedRandomSessionKey)
	buf := make([]byte, totalLen)

	// Write fixed part
	offset := 0

	// Signature (8 bytes)
	copy(buf[offset:offset+8], m.Signature[:])
	offset += 8

	// MessageType (4 bytes)
	encoding.PutUint32LE(buf[offset:offset+4], m.MessageType)
	offset += 4

	// LmChallengeResponseFields (8 bytes)
	encoding.PutUint16LE(buf[offset:offset+2], m.LmChallengeResponseFields.Len)
	encoding.PutUint16LE(buf[offset+2:offset+4], m.LmChallengeResponseFields.MaxLen)
	encoding.PutUint32LE(buf[offset+4:offset+8], m.LmChallengeResponseFields.Offset)
	offset += 8

	// NtChallengeResponseFields (8 bytes)
	encoding.PutUint16LE(buf[offset:offset+2], m.NtChallengeResponseFields.Len)
	encoding.PutUint16LE(buf[offset+2:offset+4], m.NtChallengeResponseFields.MaxLen)
	encoding.PutUint32LE(buf[offset+4:offset+8], m.NtChallengeResponseFields.Offset)
	offset += 8

	// DomainNameFields (8 bytes)
	encoding.PutUint16LE(buf[offset:offset+2], m.DomainNameFields.Len)
	encoding.PutUint16LE(buf[offset+2:offset+4], m.DomainNameFields.MaxLen)
	encoding.PutUint32LE(buf[offset+4:offset+8], m.DomainNameFields.Offset)
	offset += 8

	// UserNameFields (8 bytes)
	encoding.PutUint16LE(buf[offset:offset+2], m.UserNameFields.Len)
	encoding.PutUint16LE(buf[offset+2:offset+4], m.UserNameFields.MaxLen)
	encoding.PutUint32LE(buf[offset+4:offset+8], m.UserNameFields.Offset)
	offset += 8

	// WorkstationFields (8 bytes)
	encoding.PutUint16LE(buf[offset:offset+2], m.WorkstationFields.Len)
	encoding.PutUint16LE(buf[offset+2:offset+4], m.WorkstationFields.MaxLen)
	encoding.PutUint32LE(buf[offset+4:offset+8], m.WorkstationFields.Offset)
	offset += 8

	// EncryptedRandomSessionKeyFields (8 bytes)
	encoding.PutUint16LE(buf[offset:offset+2], m.EncryptedRandomSessionKeyFields.Len)
	encoding.PutUint16LE(buf[offset+2:offset+4], m.EncryptedRandomSessionKeyFields.MaxLen)
	encoding.PutUint32LE(buf[offset+4:offset+8], m.EncryptedRandomSessionKeyFields.Offset)
	offset += 8

	// NegotiateFlags (4 bytes)
	encoding.PutUint32LE(buf[offset:offset+4], m.NegotiateFlags)
	offset += 4

	// Version (8 bytes)
	copy(buf[offset:offset+8], m.Version.Marshal())
	offset += 8

	// MIC (16 bytes) - initially zero, can be computed later
	copy(buf[offset:offset+16], m.MIC[:])
	offset += 16

	// Payload
	copy(buf[m.LmChallengeResponseFields.Offset:], m.LmChallengeResponse)
	copy(buf[m.NtChallengeResponseFields.Offset:], m.NtChallengeResponse)
	copy(buf[m.DomainNameFields.Offset:], m.DomainName)
	copy(buf[m.UserNameFields.Offset:], m.UserName)
	copy(buf[m.WorkstationFields.Offset:], m.Workstation)
	if len(m.EncryptedRandomSessionKey) > 0 {
		copy(buf[m.EncryptedRandomSessionKeyFields.Offset:], m.EncryptedRandomSessionKey)
	}

	return buf
}

// GetSessionBaseKey returns the session base key for signing/encryption
func (m *AuthenticateMessage) GetSessionBaseKey() []byte {
	return m.SessionBaseKey
}
