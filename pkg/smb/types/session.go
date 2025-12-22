package types

import (
	"errors"

	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// SessionSetupRequest represents an SMB2 SESSION_SETUP request
type SessionSetupRequest struct {
	StructureSize        uint16 // 25
	Flags                uint8
	SecurityMode         SecurityMode
	Capabilities         Capabilities
	Channel              uint32
	SecurityBufferOffset uint16
	SecurityBufferLength uint16
	PreviousSessionID    uint64
	SecurityBuffer       []byte // SPNEGO/NTLMSSP token
}

// NewSessionSetupRequest creates a new session setup request
func NewSessionSetupRequest(securityBuffer []byte) *SessionSetupRequest {
	return &SessionSetupRequest{
		StructureSize:  25,
		SecurityMode:   NegotiateSigningEnabled,
		Capabilities:   GlobalCapDFS, // Required for SMB3
		SecurityBuffer: securityBuffer,
	}
}

// Marshal serializes the session setup request
func (r *SessionSetupRequest) Marshal() []byte {
	// Fixed part: 24 bytes, variable: security buffer
	// SecurityBufferOffset is from start of SMB2 header (64 bytes)
	r.SecurityBufferOffset = SMB2HeaderSize + 24
	r.SecurityBufferLength = uint16(len(r.SecurityBuffer))

	bufLen := 24 + len(r.SecurityBuffer)
	buf := make([]byte, bufLen)

	encoding.PutUint16LE(buf[0:2], r.StructureSize)
	buf[2] = r.Flags
	buf[3] = byte(r.SecurityMode)
	encoding.PutUint32LE(buf[4:8], uint32(r.Capabilities))
	encoding.PutUint32LE(buf[8:12], r.Channel)
	encoding.PutUint16LE(buf[12:14], r.SecurityBufferOffset)
	encoding.PutUint16LE(buf[14:16], r.SecurityBufferLength)
	encoding.PutUint64LE(buf[16:24], r.PreviousSessionID)

	// Security buffer
	copy(buf[24:], r.SecurityBuffer)

	return buf
}

// SessionSetupResponse represents an SMB2 SESSION_SETUP response
type SessionSetupResponse struct {
	StructureSize        uint16 // 9
	SessionFlags         uint16
	SecurityBufferOffset uint16
	SecurityBufferLength uint16
	SecurityBuffer       []byte // SPNEGO/NTLMSSP token
}

// SessionFlags
const (
	SessionFlagIsGuest     uint16 = 0x0001
	SessionFlagIsNull      uint16 = 0x0002
	SessionFlagEncryptData uint16 = 0x0004
)

// Unmarshal deserializes a session setup response
func (r *SessionSetupResponse) Unmarshal(buf []byte) error {
	if len(buf) < 8 {
		return errors.New("buffer too small for session setup response")
	}

	r.StructureSize = encoding.Uint16LE(buf[0:2])
	if r.StructureSize != 9 {
		return errors.New("invalid session setup response structure size")
	}

	r.SessionFlags = encoding.Uint16LE(buf[2:4])
	r.SecurityBufferOffset = encoding.Uint16LE(buf[4:6])
	r.SecurityBufferLength = encoding.Uint16LE(buf[6:8])

	// Extract security buffer
	if r.SecurityBufferLength > 0 {
		// Offset is from start of SMB2 header
		actualOffset := int(r.SecurityBufferOffset) - SMB2HeaderSize
		if actualOffset >= 0 && actualOffset+int(r.SecurityBufferLength) <= len(buf) {
			r.SecurityBuffer = make([]byte, r.SecurityBufferLength)
			copy(r.SecurityBuffer, buf[actualOffset:actualOffset+int(r.SecurityBufferLength)])
		}
	}

	return nil
}

// IsGuest returns true if this is a guest session
func (r *SessionSetupResponse) IsGuest() bool {
	return r.SessionFlags&SessionFlagIsGuest != 0
}

// IsNull returns true if this is a null/anonymous session
func (r *SessionSetupResponse) IsNull() bool {
	return r.SessionFlags&SessionFlagIsNull != 0
}
