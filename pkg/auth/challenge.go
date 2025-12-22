package auth

import (
	"errors"

	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// ChallengeMessage represents NTLMSSP Type 2 message (CHALLENGE_MESSAGE)
type ChallengeMessage struct {
	Signature        [8]byte
	MessageType      uint32 // Always 2
	TargetNameFields SecurityBuffer
	NegotiateFlags   uint32
	ServerChallenge  [8]byte
	Reserved         [8]byte
	TargetInfoFields SecurityBuffer
	Version          NTLMVersion
	TargetName       []byte   // From payload
	TargetInfo       []byte   // From payload
	AvPairs          []AvPair // Parsed from TargetInfo
}

// ParseChallengeMessage parses a Type 2 message
func ParseChallengeMessage(data []byte) (*ChallengeMessage, error) {
	if len(data) < 32 {
		return nil, errors.New("challenge message too short")
	}

	m := &ChallengeMessage{}

	copy(m.Signature[:], data[0:8])
	if m.Signature != ntlmSignature {
		return nil, errors.New("invalid NTLMSSP signature")
	}

	m.MessageType = encoding.Uint32LE(data[8:12])
	if m.MessageType != NtLmChallenge {
		return nil, errors.New("not a challenge message")
	}

	// TargetNameFields
	m.TargetNameFields.Len = encoding.Uint16LE(data[12:14])
	m.TargetNameFields.MaxLen = encoding.Uint16LE(data[14:16])
	m.TargetNameFields.Offset = encoding.Uint32LE(data[16:20])

	// NegotiateFlags
	m.NegotiateFlags = encoding.Uint32LE(data[20:24])

	// ServerChallenge
	copy(m.ServerChallenge[:], data[24:32])

	// Reserved
	if len(data) >= 40 {
		copy(m.Reserved[:], data[32:40])
	}

	// Check for TargetInfo
	if len(data) >= 48 {
		m.TargetInfoFields.Len = encoding.Uint16LE(data[40:42])
		m.TargetInfoFields.MaxLen = encoding.Uint16LE(data[42:44])
		m.TargetInfoFields.Offset = encoding.Uint32LE(data[44:48])
	}

	// Version (if present)
	if len(data) >= 56 && (m.NegotiateFlags&NtlmsspNegotiateVersion != 0) {
		m.Version.ProductMajorVersion = data[48]
		m.Version.ProductMinorVersion = data[49]
		m.Version.ProductBuild = encoding.Uint16LE(data[50:52])
		copy(m.Version.Reserved[:], data[52:55])
		m.Version.NTLMRevisionCurrent = data[55]
	}

	// Extract TargetName from payload
	if m.TargetNameFields.Len > 0 {
		start := int(m.TargetNameFields.Offset)
		end := start + int(m.TargetNameFields.Len)
		if end <= len(data) {
			m.TargetName = make([]byte, m.TargetNameFields.Len)
			copy(m.TargetName, data[start:end])
		}
	}

	// Extract TargetInfo from payload
	if m.TargetInfoFields.Len > 0 {
		start := int(m.TargetInfoFields.Offset)
		end := start + int(m.TargetInfoFields.Len)
		if end <= len(data) {
			m.TargetInfo = make([]byte, m.TargetInfoFields.Len)
			copy(m.TargetInfo, data[start:end])
			m.AvPairs = ParseAvPairs(m.TargetInfo)
		}
	}

	return m, nil
}

// GetTimestamp extracts MsvAvTimestamp from TargetInfo if present
func (m *ChallengeMessage) GetTimestamp() []byte {
	if pair := FindAvPair(m.AvPairs, MsvAvTimestamp); pair != nil {
		return pair.Value
	}
	return nil
}

// GetTargetNameString returns the target name as string
func (m *ChallengeMessage) GetTargetNameString() string {
	if len(m.TargetName) > 0 {
		return encoding.FromUTF16LE(m.TargetName)
	}
	return ""
}
