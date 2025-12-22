package dcerpc

import (
	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// NDR encoding utilities for marshaling RPC stub data

// NDRWriter helps build NDR-encoded stub data
type NDRWriter struct {
	buf []byte
}

// NewNDRWriter creates a new NDR writer
func NewNDRWriter() *NDRWriter {
	return &NDRWriter{}
}

// Bytes returns the encoded data
func (w *NDRWriter) Bytes() []byte {
	return w.buf
}

// WriteUint8 writes a uint8
func (w *NDRWriter) WriteUint8(v uint8) {
	w.buf = append(w.buf, v)
}

// WriteUint16 writes a uint16 (little-endian)
func (w *NDRWriter) WriteUint16(v uint16) {
	w.buf = encoding.AppendUint16LE(w.buf, v)
}

// WriteUint32 writes a uint32 (little-endian)
func (w *NDRWriter) WriteUint32(v uint32) {
	w.buf = encoding.AppendUint32LE(w.buf, v)
}

// WriteUint64 writes a uint64 (little-endian)
func (w *NDRWriter) WriteUint64(v uint64) {
	w.buf = encoding.AppendUint64LE(w.buf, v)
}

// WriteBytes writes raw bytes
func (w *NDRWriter) WriteBytes(data []byte) {
	w.buf = append(w.buf, data...)
}

// WriteUnicodeString writes a conformant varying string (UTF-16LE)
func (w *NDRWriter) WriteUnicodeString(s string) {
	utf16 := encoding.ToUTF16LE(s)
	chars := len(utf16) / 2

	// MaximumCount (number of UTF-16 chars including null)
	w.WriteUint32(uint32(chars + 1))
	// Offset (always 0)
	w.WriteUint32(0)
	// ActualCount
	w.WriteUint32(uint32(chars + 1))
	// String data
	w.WriteBytes(utf16)
	// Null terminator
	w.WriteUint16(0)
	// Align to 4 bytes
	w.Align(4)
}

// WriteConformantArray writes a conformant array
func (w *NDRWriter) WriteConformantArray(data []byte) {
	// MaximumCount
	w.WriteUint32(uint32(len(data)))
	// Data
	w.WriteBytes(data)
	// Align to 4 bytes
	w.Align(4)
}

// WritePointer writes a unique pointer (non-null)
func (w *NDRWriter) WritePointer() {
	// Use a simple non-null referent ID
	w.WriteUint32(0x00020000)
}

// WriteNullPointer writes a null pointer
func (w *NDRWriter) WriteNullPointer() {
	w.WriteUint32(0)
}

// Align aligns the buffer to the specified boundary
func (w *NDRWriter) Align(n int) {
	padding := (n - (len(w.buf) % n)) % n
	for i := 0; i < padding; i++ {
		w.buf = append(w.buf, 0)
	}
}

// Len returns the current length
func (w *NDRWriter) Len() int {
	return len(w.buf)
}

// NDRReader helps parse NDR-encoded data
type NDRReader struct {
	buf    []byte
	offset int
}

// NewNDRReader creates a new NDR reader
func NewNDRReader(data []byte) *NDRReader {
	return &NDRReader{buf: data}
}

// ReadUint8 reads a uint8
func (r *NDRReader) ReadUint8() (uint8, error) {
	if r.offset+1 > len(r.buf) {
		return 0, ErrBufferTooSmall
	}
	v := r.buf[r.offset]
	r.offset++
	return v, nil
}

// ReadUint16 reads a uint16
func (r *NDRReader) ReadUint16() (uint16, error) {
	if r.offset+2 > len(r.buf) {
		return 0, ErrBufferTooSmall
	}
	v := encoding.Uint16LE(r.buf[r.offset:])
	r.offset += 2
	return v, nil
}

// ReadUint32 reads a uint32
func (r *NDRReader) ReadUint32() (uint32, error) {
	if r.offset+4 > len(r.buf) {
		return 0, ErrBufferTooSmall
	}
	v := encoding.Uint32LE(r.buf[r.offset:])
	r.offset += 4
	return v, nil
}

// ReadUint64 reads a uint64
func (r *NDRReader) ReadUint64() (uint64, error) {
	if r.offset+8 > len(r.buf) {
		return 0, ErrBufferTooSmall
	}
	v := encoding.Uint64LE(r.buf[r.offset:])
	r.offset += 8
	return v, nil
}

// ReadBytes reads n bytes
func (r *NDRReader) ReadBytes(n int) ([]byte, error) {
	if r.offset+n > len(r.buf) {
		return nil, ErrBufferTooSmall
	}
	data := make([]byte, n)
	copy(data, r.buf[r.offset:r.offset+n])
	r.offset += n
	return data, nil
}

// ReadUnicodeString reads a conformant varying string
func (r *NDRReader) ReadUnicodeString() (string, error) {
	// MaxCount
	_, err := r.ReadUint32()
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

	// Read chars (2 bytes each)
	data, err := r.ReadBytes(int(actualCount) * 2)
	if err != nil {
		return "", err
	}

	// Remove null terminator if present
	if len(data) >= 2 && data[len(data)-2] == 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-2]
	}

	r.Align(4)
	return encoding.FromUTF16LE(data), nil
}

// Align aligns the offset to the specified boundary
func (r *NDRReader) Align(n int) {
	padding := (n - (r.offset % n)) % n
	r.offset += padding
}

// Skip skips n bytes
func (r *NDRReader) Skip(n int) error {
	if r.offset+n > len(r.buf) {
		return ErrBufferTooSmall
	}
	r.offset += n
	return nil
}

// Remaining returns remaining bytes
func (r *NDRReader) Remaining() int {
	return len(r.buf) - r.offset
}

// Offset returns current offset
func (r *NDRReader) Offset() int {
	return r.offset
}
