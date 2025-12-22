// Package ndr provides Network Data Representation encoding/decoding helpers
// for parsing DCE/RPC responses with proper conformant array handling
package ndr

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// Reader provides sequential reading of NDR-encoded data
type Reader struct {
	data   []byte
	offset int
}

// NewReader creates an NDR reader
func NewReader(data []byte) *Reader {
	return &Reader{data: data, offset: 0}
}

// Remaining returns bytes left to read
func (r *Reader) Remaining() int {
	return len(r.data) - r.offset
}

// Skip advances the offset
func (r *Reader) Skip(n int) error {
	if r.offset+n > len(r.data) {
		return fmt.Errorf("skip beyond buffer")
	}
	r.offset += n
	return nil
}

// Align aligns to n-byte boundary
func (r *Reader) Align(n int) {
	if n > 0 && r.offset%n != 0 {
		r.offset += n - (r.offset % n)
	}
}

// ReadUint8 reads a uint8
func (r *Reader) ReadUint8() (uint8, error) {
	if r.offset >= len(r.data) {
		return 0, fmt.Errorf("buffer underflow")
	}
	v := r.data[r.offset]
	r.offset++
	return v, nil
}

// ReadUint16 reads a little-endian uint16
func (r *Reader) ReadUint16() (uint16, error) {
	r.Align(2)
	if r.offset+2 > len(r.data) {
		return 0, fmt.Errorf("buffer underflow")
	}
	v := binary.LittleEndian.Uint16(r.data[r.offset:])
	r.offset += 2
	return v, nil
}

// ReadUint32 reads a little-endian uint32
func (r *Reader) ReadUint32() (uint32, error) {
	r.Align(4)
	if r.offset+4 > len(r.data) {
		return 0, fmt.Errorf("buffer underflow")
	}
	v := binary.LittleEndian.Uint32(r.data[r.offset:])
	r.offset += 4
	return v, nil
}

// ReadUint64 reads a little-endian uint64
func (r *Reader) ReadUint64() (uint64, error) {
	r.Align(8)
	if r.offset+8 > len(r.data) {
		return 0, fmt.Errorf("buffer underflow")
	}
	v := binary.LittleEndian.Uint64(r.data[r.offset:])
	r.offset += 8
	return v, nil
}

// ReadBytes reads n bytes
func (r *Reader) ReadBytes(n int) ([]byte, error) {
	if r.offset+n > len(r.data) {
		return nil, fmt.Errorf("buffer underflow")
	}
	data := make([]byte, n)
	copy(data, r.data[r.offset:r.offset+n])
	r.offset += n
	return data, nil
}

// ReadPointer reads a pointer (4 bytes) and returns true if non-null
func (r *Reader) ReadPointer() (bool, error) {
	ptr, err := r.ReadUint32()
	if err != nil {
		return false, err
	}
	return ptr != 0, nil
}

// ReadConformantString reads an NDR conformant varying string
func (r *Reader) ReadConformantString() (string, error) {
	// MaxCount
	maxCount, err := r.ReadUint32()
	if err != nil {
		return "", err
	}

	// Offset
	_, err = r.ReadUint32()
	if err != nil {
		return "", err
	}

	// ActualCount
	actualCount, err := r.ReadUint32()
	if err != nil {
		return "", err
	}

	if actualCount > maxCount || actualCount > 65535 {
		return "", fmt.Errorf("invalid string count: %d", actualCount)
	}

	// Read UTF-16LE bytes
	byteLen := int(actualCount * 2)
	if r.offset+byteLen > len(r.data) {
		return "", fmt.Errorf("string extends beyond buffer")
	}

	strData := r.data[r.offset : r.offset+byteLen]
	r.offset += byteLen

	// Align to 4 bytes
	r.Align(4)

	return DecodeUTF16LE(strData), nil
}

// ReadRPCUnicodeString reads RPC_UNICODE_STRING (length, maxLength, pointer)
func (r *Reader) ReadRPCUnicodeString() (uint16, uint16, bool, error) {
	length, err := r.ReadUint16()
	if err != nil {
		return 0, 0, false, err
	}

	maxLength, err := r.ReadUint16()
	if err != nil {
		return 0, 0, false, err
	}

	hasPtr, err := r.ReadPointer()
	if err != nil {
		return 0, 0, false, err
	}

	return length, maxLength, hasPtr, nil
}

// ReadConformantArray reads a conformant array header and returns count
func (r *Reader) ReadConformantArray() (uint32, error) {
	return r.ReadUint32() // MaxCount
}

// ReadSID reads a Windows SID
func (r *Reader) ReadSID() (string, error) {
	revision, err := r.ReadUint8()
	if err != nil {
		return "", err
	}

	subAuthCount, err := r.ReadUint8()
	if err != nil {
		return "", err
	}

	if subAuthCount > 15 {
		return "", fmt.Errorf("invalid SID subauthority count")
	}

	// IdentifierAuthority (6 bytes, big-endian for first 2, then 4 bytes)
	authBytes, err := r.ReadBytes(6)
	if err != nil {
		return "", err
	}

	authority := uint64(authBytes[0])<<40 | uint64(authBytes[1])<<32 |
		uint64(authBytes[2])<<24 | uint64(authBytes[3])<<16 |
		uint64(authBytes[4])<<8 | uint64(authBytes[5])

	sid := fmt.Sprintf("S-%d-%d", revision, authority)

	// SubAuthorities
	for i := 0; i < int(subAuthCount); i++ {
		subAuth, err := r.ReadUint32()
		if err != nil {
			return sid, err
		}
		sid += fmt.Sprintf("-%d", subAuth)
	}

	return sid, nil
}

// DecodeUTF16LE decodes UTF-16LE bytes to a Go string
func DecodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}

	// Convert to uint16 slice
	u16s := make([]uint16, len(b)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}

	// Remove null terminator if present
	for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}

	return string(utf16.Decode(u16s))
}

// Writer provides NDR encoding
type Writer struct {
	data []byte
}

// NewWriter creates an NDR writer
func NewWriter() *Writer {
	return &Writer{data: make([]byte, 0, 256)}
}

// Bytes returns the written data
func (w *Writer) Bytes() []byte {
	return w.data
}

// WriteUint8 writes a uint8
func (w *Writer) WriteUint8(v uint8) {
	w.data = append(w.data, v)
}

// WriteUint16 writes a little-endian uint16
func (w *Writer) WriteUint16(v uint16) {
	w.Align(2)
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	w.data = append(w.data, b...)
}

// WriteUint32 writes a little-endian uint32
func (w *Writer) WriteUint32(v uint32) {
	w.Align(4)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	w.data = append(w.data, b...)
}

// WriteBytes writes raw bytes
func (w *Writer) WriteBytes(b []byte) {
	w.data = append(w.data, b...)
}

// Align pads to n-byte boundary
func (w *Writer) Align(n int) {
	for len(w.data)%n != 0 {
		w.data = append(w.data, 0)
	}
}

// WriteConformantString writes an NDR conformant string
func (w *Writer) WriteConformantString(s string) {
	length := uint32(len(s) + 1)
	w.WriteUint32(length) // MaxCount
	w.WriteUint32(0)      // Offset
	w.WriteUint32(length) // ActualCount

	// UTF-16LE
	for _, c := range s {
		w.WriteUint8(byte(c))
		w.WriteUint8(0)
	}
	w.WriteUint8(0)
	w.WriteUint8(0)

	w.Align(4)
}

// WritePointer writes a non-null pointer reference
func (w *Writer) WritePointer(refID uint32) {
	w.WriteUint32(refID)
}

// WriteNullPointer writes a null pointer
func (w *Writer) WriteNullPointer() {
	w.WriteUint32(0)
}
