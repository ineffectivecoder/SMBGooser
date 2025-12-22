// Package smb1 implements SMB1 (NT LM 0.12) protocol support for legacy systems.
package smb1

import (
	"encoding/binary"
	"fmt"
)

// SMB1 Command codes
type Command uint8

const (
	CommandNegotiate        Command = 0x72
	CommandSessionSetupAndX Command = 0x73
	CommandLogoffAndX       Command = 0x74
	CommandTreeConnectAndX  Command = 0x75
	CommandTreeDisconnect   Command = 0x71
	CommandNTCreateAndX     Command = 0x0A2 // Actually uses AndX structure differently
	CommandReadAndX         Command = 0x2E
	CommandWriteAndX        Command = 0x2F
	CommandClose            Command = 0x04
	CommandTrans            Command = 0x25
	CommandTrans2           Command = 0x32
)

// SMB1 header flags
const (
	FlagsLockAndRead   uint8 = 0x01
	FlagsReceiveBufAvl uint8 = 0x02
	FlagsCaseless      uint8 = 0x08
	FlagsCanonical     uint8 = 0x10
	FlagsOplock        uint8 = 0x20
	FlagsNotify        uint8 = 0x40
	FlagsResponse      uint8 = 0x80
)

// SMB1 header flags2
const (
	Flags2LongNames    uint16 = 0x0001
	Flags2EAS          uint16 = 0x0002
	Flags2SecuritySig  uint16 = 0x0004
	Flags2ExtendedSec  uint16 = 0x0800
	Flags2DFSPathnames uint16 = 0x1000
	Flags2ReadIfExec   uint16 = 0x2000
	Flags2NTStatusCode uint16 = 0x4000
	Flags2Unicode      uint16 = 0x8000
)

// Header represents an SMB1 header (32 bytes)
type Header struct {
	Protocol    [4]byte // 0xFF, 'S', 'M', 'B'
	Command     Command // Command code
	Status      uint32  // NT Status code (in NT_STATUS mode)
	Flags       uint8   // Flags
	Flags2      uint16  // Flags2
	PIDHigh     uint16  // High part of PID
	SecuritySig [8]byte // Security signature
	Reserved    uint16  // Reserved
	TID         uint16  // Tree ID
	PIDLow      uint16  // Low part of PID
	UID         uint16  // User ID
	MID         uint16  // Multiplex ID
}

const HeaderSize = 32

// NewHeader creates a new SMB1 header
func NewHeader(cmd Command, mid uint16) *Header {
	return &Header{
		Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
		Command:  cmd,
		Flags:    FlagsCaseless | FlagsCanonical,
		Flags2:   Flags2LongNames | Flags2ExtendedSec | Flags2NTStatusCode | Flags2Unicode,
		MID:      mid,
	}
}

// Marshal serializes the header to bytes
func (h *Header) Marshal() []byte {
	buf := make([]byte, HeaderSize)
	copy(buf[0:4], h.Protocol[:])
	buf[4] = byte(h.Command)
	binary.LittleEndian.PutUint32(buf[5:9], h.Status)
	buf[9] = h.Flags
	binary.LittleEndian.PutUint16(buf[10:12], h.Flags2)
	binary.LittleEndian.PutUint16(buf[12:14], h.PIDHigh)
	copy(buf[14:22], h.SecuritySig[:])
	binary.LittleEndian.PutUint16(buf[22:24], h.Reserved)
	binary.LittleEndian.PutUint16(buf[24:26], h.TID)
	binary.LittleEndian.PutUint16(buf[26:28], h.PIDLow)
	binary.LittleEndian.PutUint16(buf[28:30], h.UID)
	binary.LittleEndian.PutUint16(buf[30:32], h.MID)
	return buf
}

// Unmarshal parses bytes into the header
func (h *Header) Unmarshal(buf []byte) error {
	if len(buf) < HeaderSize {
		return fmt.Errorf("buffer too short: %d < %d", len(buf), HeaderSize)
	}
	copy(h.Protocol[:], buf[0:4])
	h.Command = Command(buf[4])
	h.Status = binary.LittleEndian.Uint32(buf[5:9])
	h.Flags = buf[9]
	h.Flags2 = binary.LittleEndian.Uint16(buf[10:12])
	h.PIDHigh = binary.LittleEndian.Uint16(buf[12:14])
	copy(h.SecuritySig[:], buf[14:22])
	h.Reserved = binary.LittleEndian.Uint16(buf[22:24])
	h.TID = binary.LittleEndian.Uint16(buf[24:26])
	h.PIDLow = binary.LittleEndian.Uint16(buf[26:28])
	h.UID = binary.LittleEndian.Uint16(buf[28:30])
	h.MID = binary.LittleEndian.Uint16(buf[30:32])
	return nil
}

// IsResponse returns true if this is a response message
func (h *Header) IsResponse() bool {
	return h.Flags&FlagsResponse != 0
}

// IsSuccess returns true if the status indicates success
func (h *Header) IsSuccess() bool {
	return h.Status == 0 || h.Status == 0xC0000016 // STATUS_MORE_PROCESSING_REQUIRED
}

// Dialect strings for SMB1 negotiate
var (
	DialectNTLM012 = "NT LM 0.12"
)
