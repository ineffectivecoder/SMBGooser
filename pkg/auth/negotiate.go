package auth

import (
	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// NegotiateMessage represents NTLMSSP Type 1 message (NEGOTIATE_MESSAGE)
type NegotiateMessage struct {
	Signature         [8]byte
	MessageType       uint32 // Always 1
	NegotiateFlags    uint32
	DomainNameFields  SecurityBuffer
	WorkstationFields SecurityBuffer
	Version           NTLMVersion
	Payload           []byte // Domain + Workstation (optional)
}

// SecurityBuffer represents the Len/MaxLen/Offset structure
type SecurityBuffer struct {
	Len    uint16
	MaxLen uint16
	Offset uint32
}

// NewNegotiateMessage creates a Type 1 message
func NewNegotiateMessage() *NegotiateMessage {
	return &NegotiateMessage{
		Signature:      ntlmSignature,
		MessageType:    NtLmNegotiate,
		NegotiateFlags: DefaultNegotiateFlags,
		Version:        DefaultVersion(),
	}
}

// Marshal serializes the Type 1 message
func (m *NegotiateMessage) Marshal() []byte {
	// Fixed size without domain/workstation: 32 bytes + 8 (version) = 40 bytes
	// We send minimal message without domain/workstation
	buf := make([]byte, 40)

	copy(buf[0:8], m.Signature[:])
	encoding.PutUint32LE(buf[8:12], m.MessageType)
	encoding.PutUint32LE(buf[12:16], m.NegotiateFlags)

	// DomainNameFields (empty)
	encoding.PutUint16LE(buf[16:18], 0) // Len
	encoding.PutUint16LE(buf[18:20], 0) // MaxLen
	encoding.PutUint32LE(buf[20:24], 0) // Offset

	// WorkstationFields (empty)
	encoding.PutUint16LE(buf[24:26], 0) // Len
	encoding.PutUint16LE(buf[26:28], 0) // MaxLen
	encoding.PutUint32LE(buf[28:32], 0) // Offset

	// Version
	copy(buf[32:40], m.Version.Marshal())

	return buf
}
