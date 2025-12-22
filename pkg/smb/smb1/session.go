// Session implements SMB1 session setup with NTLMSSP
package smb1

import (
	"encoding/binary"
	"fmt"
)

// SessionSetupAndXRequest represents a SESSION_SETUP_ANDX request
type SessionSetupAndXRequest struct {
	WordCount          uint8
	AndXCommand        uint8
	AndXReserved       uint8
	AndXOffset         uint16
	MaxBufferSize      uint16
	MaxMpxCount        uint16
	VcNumber           uint16
	SessionKey         uint32
	SecurityBlobLength uint16
	Reserved           uint32
	Capabilities       uint32
	ByteCount          uint16
	SecurityBlob       []byte
	NativeOS           string
	NativeLanMan       string
}

// Marshal serializes the session setup request
func (r *SessionSetupAndXRequest) Marshal() []byte {
	// Word count = 12 (for extended security)
	wordCount := 12

	// Build parameter words
	params := make([]byte, wordCount*2)
	offset := 0

	params[offset] = 0xFF // No AndX
	offset++
	params[offset] = 0 // Reserved
	offset++
	binary.LittleEndian.PutUint16(params[offset:], 0) // AndX offset
	offset += 2
	binary.LittleEndian.PutUint16(params[offset:], r.MaxBufferSize)
	offset += 2
	binary.LittleEndian.PutUint16(params[offset:], r.MaxMpxCount)
	offset += 2
	binary.LittleEndian.PutUint16(params[offset:], r.VcNumber)
	offset += 2
	binary.LittleEndian.PutUint32(params[offset:], r.SessionKey)
	offset += 4
	binary.LittleEndian.PutUint16(params[offset:], uint16(len(r.SecurityBlob)))
	offset += 2
	binary.LittleEndian.PutUint32(params[offset:], 0) // Reserved
	offset += 4
	binary.LittleEndian.PutUint32(params[offset:], r.Capabilities)

	// Build data section
	data := make([]byte, 0, len(r.SecurityBlob)+100)
	data = append(data, r.SecurityBlob...)

	// Add native OS and LanMan (Unicode with null terminators)
	if r.NativeOS != "" {
		for _, c := range r.NativeOS {
			data = append(data, byte(c), 0)
		}
	}
	data = append(data, 0, 0) // Null terminator

	if r.NativeLanMan != "" {
		for _, c := range r.NativeLanMan {
			data = append(data, byte(c), 0)
		}
	}
	data = append(data, 0, 0) // Null terminator

	// Combine everything
	buf := make([]byte, 1+len(params)+2+len(data))
	buf[0] = uint8(wordCount)
	copy(buf[1:], params)
	binary.LittleEndian.PutUint16(buf[1+len(params):], uint16(len(data)))
	copy(buf[1+len(params)+2:], data)

	return buf
}

// SessionSetupAndXResponse represents a SESSION_SETUP_ANDX response
type SessionSetupAndXResponse struct {
	WordCount          uint8
	AndXCommand        uint8
	AndXReserved       uint8
	AndXOffset         uint16
	Action             uint16
	SecurityBlobLength uint16
	SecurityBlob       []byte
	NativeOS           string
	NativeLanMan       string
	PrimaryDomain      string
}

// Unmarshal parses the session setup response
func (r *SessionSetupAndXResponse) Unmarshal(buf []byte) error {
	if len(buf) < 1 {
		return fmt.Errorf("buffer too short")
	}

	r.WordCount = buf[0]
	if r.WordCount < 4 {
		return fmt.Errorf("unexpected word count: %d", r.WordCount)
	}

	offset := 1
	r.AndXCommand = buf[offset]
	offset++
	r.AndXReserved = buf[offset]
	offset++
	r.AndXOffset = binary.LittleEndian.Uint16(buf[offset:])
	offset += 2
	r.Action = binary.LittleEndian.Uint16(buf[offset:])
	offset += 2
	r.SecurityBlobLength = binary.LittleEndian.Uint16(buf[offset:])
	offset += 2

	// ByteCount
	byteCount := binary.LittleEndian.Uint16(buf[offset:])
	offset += 2

	// Security blob
	if r.SecurityBlobLength > 0 && offset+int(r.SecurityBlobLength) <= len(buf) {
		r.SecurityBlob = make([]byte, r.SecurityBlobLength)
		copy(r.SecurityBlob, buf[offset:offset+int(r.SecurityBlobLength)])
		offset += int(r.SecurityBlobLength)
	}

	// Remaining bytes are native OS, LanMan, domain (optional)
	_ = byteCount

	return nil
}

// IsGuestLogon returns true if this is a guest logon
func (r *SessionSetupAndXResponse) IsGuestLogon() bool {
	return r.Action&0x01 != 0
}
