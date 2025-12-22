package types

import (
	"errors"

	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// Header represents an SMB2 message header (64 bytes)
type Header struct {
	ProtocolID    [4]byte     // 0xFE 'S' 'M' 'B'
	StructureSize uint16      // Always 64
	CreditCharge  uint16      // Number of credits consumed
	Status        NTStatus    // NT Status code (response) / ChannelSequence (request)
	Command       Command     // Command code
	CreditRequest uint16      // Credits requested (request) / Credits granted (response)
	Flags         HeaderFlags // Flags
	NextCommand   uint32      // Offset to next command (for compounding)
	MessageID     uint64      // Message identifier
	Reserved      uint32      // Reserved (or async ID high bits)
	TreeID        uint32      // Tree identifier
	SessionID     uint64      // Session identifier
	Signature     [16]byte    // Signature for signed messages
}

// NewHeader creates a new SMB2 header with default values
func NewHeader(cmd Command, messageID uint64) *Header {
	h := &Header{
		ProtocolID:    SMB2ProtocolID,
		StructureSize: SMB2HeaderSize,
		CreditCharge:  1, // Required for SMB 2.1+
		Command:       cmd,
		MessageID:     messageID,
		CreditRequest: 1, // Request at least one credit
	}
	return h
}

// Marshal serializes the header to bytes
func (h *Header) Marshal() []byte {
	buf := make([]byte, SMB2HeaderSize)

	// Protocol ID
	copy(buf[0:4], h.ProtocolID[:])

	// Structure Size (always 64)
	encoding.PutUint16LE(buf[4:6], h.StructureSize)

	// Credit Charge
	encoding.PutUint16LE(buf[6:8], h.CreditCharge)

	// Status/ChannelSequence
	encoding.PutUint32LE(buf[8:12], uint32(h.Status))

	// Command
	encoding.PutUint16LE(buf[12:14], uint16(h.Command))

	// Credit Request/Response
	encoding.PutUint16LE(buf[14:16], h.CreditRequest)

	// Flags
	encoding.PutUint32LE(buf[16:20], uint32(h.Flags))

	// Next Command
	encoding.PutUint32LE(buf[20:24], h.NextCommand)

	// Message ID
	encoding.PutUint64LE(buf[24:32], h.MessageID)

	// Reserved
	encoding.PutUint32LE(buf[32:36], h.Reserved)

	// Tree ID
	encoding.PutUint32LE(buf[36:40], h.TreeID)

	// Session ID
	encoding.PutUint64LE(buf[40:48], h.SessionID)

	// Signature
	copy(buf[48:64], h.Signature[:])

	return buf
}

// Unmarshal deserializes a header from bytes
func (h *Header) Unmarshal(buf []byte) error {
	if len(buf) < SMB2HeaderSize {
		return errors.New("buffer too small for SMB2 header")
	}

	// Protocol ID
	copy(h.ProtocolID[:], buf[0:4])

	// Validate protocol ID
	if h.ProtocolID != SMB2ProtocolID {
		return errors.New("invalid SMB2 protocol ID")
	}

	// Structure Size
	h.StructureSize = encoding.Uint16LE(buf[4:6])

	// Credit Charge
	h.CreditCharge = encoding.Uint16LE(buf[6:8])

	// Status
	h.Status = NTStatus(encoding.Uint32LE(buf[8:12]))

	// Command
	h.Command = Command(encoding.Uint16LE(buf[12:14]))

	// Credit Request/Response
	h.CreditRequest = encoding.Uint16LE(buf[14:16])

	// Flags
	h.Flags = HeaderFlags(encoding.Uint32LE(buf[16:20]))

	// Next Command
	h.NextCommand = encoding.Uint32LE(buf[20:24])

	// Message ID
	h.MessageID = encoding.Uint64LE(buf[24:32])

	// Reserved
	h.Reserved = encoding.Uint32LE(buf[32:36])

	// Tree ID
	h.TreeID = encoding.Uint32LE(buf[36:40])

	// Session ID
	h.SessionID = encoding.Uint64LE(buf[40:48])

	// Signature
	copy(h.Signature[:], buf[48:64])

	return nil
}

// IsResponse returns true if this is a response from the server
func (h *Header) IsResponse() bool {
	return h.Flags&FlagsServerToRedir != 0
}

// IsSigned returns true if the message is signed
func (h *Header) IsSigned() bool {
	return h.Flags&FlagsSigned != 0
}

// IsAsync returns true if this is an async response
func (h *Header) IsAsync() bool {
	return h.Flags&FlagsAsyncCommand != 0
}
