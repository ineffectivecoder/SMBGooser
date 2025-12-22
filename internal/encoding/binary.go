// Package encoding provides binary encoding utilities for SMB protocol messages.
// All SMB2/SMB3 messages use little-endian byte order.
package encoding

import "encoding/binary"

// PutUint16LE writes a uint16 in little-endian format to the buffer.
func PutUint16LE(b []byte, v uint16) {
	binary.LittleEndian.PutUint16(b, v)
}

// PutUint32LE writes a uint32 in little-endian format to the buffer.
func PutUint32LE(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b, v)
}

// PutUint64LE writes a uint64 in little-endian format to the buffer.
func PutUint64LE(b []byte, v uint64) {
	binary.LittleEndian.PutUint64(b, v)
}

// Uint16LE reads a uint16 in little-endian format from the buffer.
func Uint16LE(b []byte) uint16 {
	return binary.LittleEndian.Uint16(b)
}

// Uint32LE reads a uint32 in little-endian format from the buffer.
func Uint32LE(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}

// Uint64LE reads a uint64 in little-endian format from the buffer.
func Uint64LE(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}

// AppendUint16LE appends a uint16 in little-endian format to the buffer.
func AppendUint16LE(b []byte, v uint16) []byte {
	return binary.LittleEndian.AppendUint16(b, v)
}

// AppendUint32LE appends a uint32 in little-endian format to the buffer.
func AppendUint32LE(b []byte, v uint32) []byte {
	return binary.LittleEndian.AppendUint32(b, v)
}

// AppendUint64LE appends a uint64 in little-endian format to the buffer.
func AppendUint64LE(b []byte, v uint64) []byte {
	return binary.LittleEndian.AppendUint64(b, v)
}
