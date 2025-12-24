// Package encoding provides UTF-16LE string encoding utilities for SMB protocol.
// SMB2/SMB3 uses UTF-16LE for all string data.
package encoding

import (
	"unicode/utf16"
)

// ToUTF16LE converts a Go string to UTF-16LE encoded bytes.
// This is the standard string encoding for SMB2/SMB3 messages.
func ToUTF16LE(s string) []byte {
	// Convert string to UTF-16 code points
	runes := utf16.Encode([]rune(s))

	// Convert to bytes (little-endian)
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	return b
}

// FromUTF16LE converts UTF-16LE encoded bytes to a Go string.
// Handles Windows garbage in FileNameLength by detecting invalid UTF-16 pairs.
func FromUTF16LE(b []byte) string {
	if len(b) == 0 {
		return ""
	}

	// Ensure even number of bytes
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}

	// Find where valid UTF-16LE ends
	// For ASCII filenames, valid UTF-16LE has pattern: [ASCII byte][0x00]
	// Windows may include garbage like pool tags (LMEMP) where high byte != 0
	validEnd := len(b)
	for i := 0; i < len(b)-1; i += 2 {
		low := b[i]
		high := b[i+1]

		// Null terminator
		if low == 0 && high == 0 {
			validEnd = i
			break
		}

		// For printable ASCII range (0x20-0x7E), high byte should be 0
		// If we see high byte != 0 for what should be ASCII, it's garbage
		if low >= 0x20 && low <= 0x7E && high != 0 {
			validEnd = i
			break
		}

		// Also check for Windows pool tag pattern: two consecutive ASCII bytes
		// like "LM" (0x4C 0x4D) which is invalid UTF-16LE for a filename
		if high >= 0x41 && high <= 0x5A { // high byte is uppercase letter = garbage
			validEnd = i
			break
		}
	}

	b = b[:validEnd]
	if len(b) == 0 {
		return ""
	}

	// Convert bytes to UTF-16 code points
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
	}

	// Decode UTF-16 to runes
	return string(utf16.Decode(u16s))
}

// ToUTF16LEWithNull converts a string to UTF-16LE with a null terminator.
func ToUTF16LEWithNull(s string) []byte {
	b := ToUTF16LE(s)
	return append(b, 0, 0) // null terminator (2 bytes for UTF-16)
}
