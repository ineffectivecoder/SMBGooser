// Tree implements SMB1 tree connect operations
package smb1

import (
	"encoding/binary"
	"fmt"
)

// TreeConnectAndXRequest represents a TREE_CONNECT_ANDX request
type TreeConnectAndXRequest struct {
	AndXCommand  uint8
	AndXReserved uint8
	AndXOffset   uint16
	Flags        uint16
	PasswordLen  uint16
	Password     []byte
	Path         string
	Service      string
}

// Service types
const (
	ServiceDisk    = "A:"
	ServicePrinter = "LPT1:"
	ServicePipe    = "IPC"
	ServiceAny     = "?????"
)

// Marshal serializes the tree connect request
func (r *TreeConnectAndXRequest) Marshal() []byte {
	// Word count = 4
	wordCount := 4

	// Build path and service as null-terminated strings
	// Path needs padding for Unicode alignment after password
	pathBytes := make([]byte, 0, len(r.Path)*2+2)
	for _, c := range r.Path {
		pathBytes = append(pathBytes, byte(c), 0)
	}
	pathBytes = append(pathBytes, 0, 0) // Null terminator

	serviceBytes := append([]byte(r.Service), 0)

	// Parameters
	params := make([]byte, wordCount*2)
	offset := 0
	params[offset] = 0xFF // No AndX
	offset++
	params[offset] = 0 // Reserved
	offset++
	binary.LittleEndian.PutUint16(params[offset:], 0) // AndX offset
	offset += 2
	binary.LittleEndian.PutUint16(params[offset:], r.Flags)
	offset += 2
	binary.LittleEndian.PutUint16(params[offset:], r.PasswordLen)

	// Build data section
	data := make([]byte, 0, int(r.PasswordLen)+len(pathBytes)+len(serviceBytes)+1)
	data = append(data, r.Password...)
	// Padding for Unicode alignment if needed
	if len(data)%2 != 0 {
		data = append(data, 0)
	}
	data = append(data, pathBytes...)
	data = append(data, serviceBytes...)

	// Combine everything
	buf := make([]byte, 1+len(params)+2+len(data))
	buf[0] = uint8(wordCount)
	copy(buf[1:], params)
	binary.LittleEndian.PutUint16(buf[1+len(params):], uint16(len(data)))
	copy(buf[1+len(params)+2:], data)

	return buf
}

// TreeConnectAndXResponse represents a TREE_CONNECT_ANDX response
type TreeConnectAndXResponse struct {
	WordCount        uint8
	AndXCommand      uint8
	AndXReserved     uint8
	AndXOffset       uint16
	OptionalSupport  uint16
	Service          string
	NativeFileSystem string
}

// Unmarshal parses the tree connect response
func (r *TreeConnectAndXResponse) Unmarshal(buf []byte) error {
	if len(buf) < 1 {
		return fmt.Errorf("buffer too short")
	}

	r.WordCount = buf[0]
	if r.WordCount < 3 {
		return fmt.Errorf("unexpected word count: %d", r.WordCount)
	}

	offset := 1
	r.AndXCommand = buf[offset]
	offset++
	r.AndXReserved = buf[offset]
	offset++
	r.AndXOffset = binary.LittleEndian.Uint16(buf[offset:])
	offset += 2
	r.OptionalSupport = binary.LittleEndian.Uint16(buf[offset:])
	offset += 2

	// Skip additional words if present
	if r.WordCount > 3 {
		offset += (int(r.WordCount) - 3) * 2
	}

	// ByteCount
	if offset+2 > len(buf) {
		return nil
	}
	byteCount := binary.LittleEndian.Uint16(buf[offset:])
	offset += 2
	_ = byteCount

	// Service (ASCII null-terminated)
	for i := offset; i < len(buf); i++ {
		if buf[i] == 0 {
			r.Service = string(buf[offset:i])
			offset = i + 1
			break
		}
	}

	// NativeFileSystem (Unicode null-terminated) - skip for now
	return nil
}
