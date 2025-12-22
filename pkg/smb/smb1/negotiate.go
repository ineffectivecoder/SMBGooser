// Negotiate implements SMB1 dialect negotiation
package smb1

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// NegotiateRequest represents an SMB1 negotiate request
type NegotiateRequest struct {
	WordCount uint8
	ByteCount uint16
	Dialects  []string
}

// Marshal serializes the negotiate request
func (r *NegotiateRequest) Marshal() []byte {
	// Build dialect buffer
	var dialectBuf []byte
	for _, d := range r.Dialects {
		dialectBuf = append(dialectBuf, 0x02) // Dialect buffer format
		dialectBuf = append(dialectBuf, []byte(d)...)
		dialectBuf = append(dialectBuf, 0x00) // Null terminator
	}

	buf := make([]byte, 3+len(dialectBuf))
	buf[0] = 0 // WordCount = 0
	binary.LittleEndian.PutUint16(buf[1:3], uint16(len(dialectBuf)))
	copy(buf[3:], dialectBuf)
	return buf
}

// NegotiateResponse represents an SMB1 negotiate response
type NegotiateResponse struct {
	DialectIndex    uint16
	SecurityMode    uint8
	MaxMpxCount     uint16
	MaxNumberVcs    uint16
	MaxBufferSize   uint32
	MaxRawSize      uint32
	SessionKey      uint32
	Capabilities    uint32
	SystemTime      uint64
	ServerTimeZone  int16
	ChallengeLength uint8
	DomainName      string
	ServerName      string
	SecurityBlob    []byte // For extended security
}

// Capability flags
const (
	CapRawMode         uint32 = 0x00000001
	CapMpxMode         uint32 = 0x00000002
	CapUnicode         uint32 = 0x00000004
	CapLargeFiles      uint32 = 0x00000008
	CapNTSMBs          uint32 = 0x00000010
	CapRPCRemoteAPIs   uint32 = 0x00000020
	CapNTStatusCodes   uint32 = 0x00000040
	CapLevel2Oplocks   uint32 = 0x00000080
	CapLockAndRead     uint32 = 0x00000100
	CapNTFind          uint32 = 0x00000200
	CapDFS             uint32 = 0x00001000
	CapInfoLevelPassth uint32 = 0x00002000
	CapLargeReadX      uint32 = 0x00004000
	CapLargeWriteX     uint32 = 0x00008000
	CapLWIO            uint32 = 0x00010000
	CapUnix            uint32 = 0x00800000
	CapCompressed      uint32 = 0x02000000
	CapDynamicReauth   uint32 = 0x20000000
	CapExtendedSec     uint32 = 0x80000000
)

// Unmarshal parses the negotiate response
func (r *NegotiateResponse) Unmarshal(buf []byte) error {
	if len(buf) < 1 {
		return errors.New("buffer too short")
	}

	wordCount := buf[0]
	if wordCount < 17 {
		return fmt.Errorf("unexpected word count: %d", wordCount)
	}

	offset := 1
	r.DialectIndex = binary.LittleEndian.Uint16(buf[offset:])
	offset += 2
	r.SecurityMode = buf[offset]
	offset++
	r.MaxMpxCount = binary.LittleEndian.Uint16(buf[offset:])
	offset += 2
	r.MaxNumberVcs = binary.LittleEndian.Uint16(buf[offset:])
	offset += 2
	r.MaxBufferSize = binary.LittleEndian.Uint32(buf[offset:])
	offset += 4
	r.MaxRawSize = binary.LittleEndian.Uint32(buf[offset:])
	offset += 4
	r.SessionKey = binary.LittleEndian.Uint32(buf[offset:])
	offset += 4
	r.Capabilities = binary.LittleEndian.Uint32(buf[offset:])
	offset += 4
	r.SystemTime = binary.LittleEndian.Uint64(buf[offset:])
	offset += 8
	r.ServerTimeZone = int16(binary.LittleEndian.Uint16(buf[offset:]))
	offset += 2
	r.ChallengeLength = buf[offset]
	offset++

	// ByteCount
	if offset+2 > len(buf) {
		return nil
	}
	byteCount := binary.LittleEndian.Uint16(buf[offset:])
	offset += 2

	// Extended security - security blob follows
	if r.Capabilities&CapExtendedSec != 0 && byteCount > 16 {
		// Skip GUID (16 bytes)
		if offset+16 <= len(buf) {
			offset += 16
			blobLen := int(byteCount) - 16
			if offset+blobLen <= len(buf) {
				r.SecurityBlob = make([]byte, blobLen)
				copy(r.SecurityBlob, buf[offset:offset+blobLen])
			}
		}
	}

	return nil
}

// SupportsExtendedSecurity returns true if server supports extended security
func (r *NegotiateResponse) SupportsExtendedSecurity() bool {
	return r.Capabilities&CapExtendedSec != 0
}

// SupportsUnicode returns true if server supports Unicode
func (r *NegotiateResponse) SupportsUnicode() bool {
	return r.Capabilities&CapUnicode != 0
}
