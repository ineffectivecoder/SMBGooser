package rrp

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// encodeOpenKey encodes BaseRegOpenKey request
// NDR layout (from Impacket analysis):
//
//	hKey (20 bytes)
//	lpSubKey: Length(2) + MaxLen(2) + Ptr(4) + MaxCount(4) + Offset(4) + ActualCount(4) + StringData + Padding
//	dwOptions (4 bytes)
//	samDesired (4 bytes)
func encodeOpenKey(parent Handle, subkey string, access uint32) []byte {
	stub := make([]byte, 0, 256)

	// hKey (handle) - 20 bytes
	stub = append(stub, parent[:]...)

	// lpSubKey (RPC_UNICODE_STRING) - INLINE string data
	runes := []rune(subkey + "\x00")
	utf16Chars := utf16.Encode(runes)
	charCount := uint32(len(utf16Chars))
	byteLen := charCount * 2

	// Length and MaximumLength (both include null terminator per Impacket)
	stub = appendUint16(stub, uint16(byteLen))
	stub = appendUint16(stub, uint16(byteLen))
	// Pointer (non-null referent ID)
	stub = appendUint32(stub, 0x00020000)

	// INLINE string data (conformant varying array)
	// MaxCount
	stub = appendUint32(stub, charCount)
	// Offset
	stub = appendUint32(stub, 0)
	// ActualCount
	stub = appendUint32(stub, charCount)

	// String data (UTF-16LE)
	for _, c := range utf16Chars {
		stub = append(stub, byte(c), byte(c>>8))
	}

	// Pad to 4-byte boundary (alignment pad before next field)
	for len(stub)%4 != 0 {
		stub = append(stub, 0xbf) // Use 0xbf like Impacket
	}

	// dwOptions (0 = REG_OPTION_RESERVED)
	stub = appendUint32(stub, 0)

	// samDesired (access mask)
	stub = appendUint32(stub, access)

	return stub
}

// encodeQueryValue encodes BaseRegQueryValue request
// Structure: hKey, lpValueName, lpType, lpData, lpcbData, lpcbLen
// Each pointer is followed immediately by its referent (interleaved layout)
func encodeQueryValue(handle Handle, valueName string) []byte {
	dataSize := uint32(512) // Buffer size for value data

	stub := make([]byte, 0, 128+int(dataSize))

	// hKey (20 bytes)
	stub = append(stub, handle[:]...)

	// lpValueName (RRP_UNICODE_STRING) with inline referent
	runes := []rune(valueName + "\x00")
	utf16Chars := utf16.Encode(runes)
	charCount := uint32(len(utf16Chars))
	byteLen := charCount * 2

	// RRP_UNICODE_STRING header
	stub = appendUint16(stub, uint16(byteLen)) // Length
	stub = appendUint16(stub, uint16(byteLen)) // MaximumLength
	stub = appendUint32(stub, 0x00020000)      // Buffer pointer

	// RRP_UNICODE_STRING referent (conformant varying array)
	stub = appendUint32(stub, charCount) // MaxCount
	stub = appendUint32(stub, 0)         // Offset
	stub = appendUint32(stub, charCount) // ActualCount
	for _, c := range utf16Chars {
		stub = append(stub, byte(c), byte(c>>8))
	}
	// Align to 4 bytes
	for len(stub)%4 != 0 {
		stub = append(stub, 0xaa) // Use 0xaa like Impacket
	}

	// lpType (LPULONG) - pointer + referent
	stub = appendUint32(stub, 0x00020004)
	stub = appendUint32(stub, 0) // lpType value = 0

	// lpData (PBYTE_ARRAY) - pointer + referent
	stub = appendUint32(stub, 0x00020008)
	stub = appendUint32(stub, dataSize) // MaxCount
	stub = appendUint32(stub, 0)        // Offset
	stub = appendUint32(stub, dataSize) // ActualCount
	// Add buffer data (zeros)
	for i := uint32(0); i < dataSize; i++ {
		stub = append(stub, 0)
	}

	// lpcbData (LPULONG) - pointer + referent
	stub = appendUint32(stub, 0x0002000C)
	stub = appendUint32(stub, dataSize)

	// lpcbLen (LPULONG) - pointer + referent
	stub = appendUint32(stub, 0x00020010)
	stub = appendUint32(stub, dataSize)

	return stub
}

// encodeEnumValue encodes BaseRegEnumValue request
// Structure per MS-RRP (interleaved pointers + referents):
//
//	hKey (RPC_HKEY - 20 bytes)
//	dwIndex (DWORD)
//	lpValueNameIn (RRP_UNICODE_STRING with buffer)
//	lpType (LPULONG) - pointer + value
//	lpData (PBYTE_ARRAY) - pointer + array
//	lpcbData (LPULONG) - pointer + value
//	lpcbLen (LPULONG) - pointer + value
func encodeEnumValue(handle Handle, index uint32) []byte {
	dataSize := uint32(512) // Buffer size

	stub := make([]byte, 0, 128+int(dataSize))

	// hKey (20 bytes)
	stub = append(stub, handle[:]...)

	// dwIndex
	stub = appendUint32(stub, index)

	// lpValueNameIn (RRP_UNICODE_STRING) with inline referent
	// Empty string input with buffer for output
	maxLen := uint16(512)                 // buffer size for value name
	stub = appendUint16(stub, 0)          // Length = 0
	stub = appendUint16(stub, maxLen)     // MaximumLength
	stub = appendUint32(stub, 0x00020000) // Buffer pointer

	// RRP_UNICODE_STRING referent (conformant varying array)
	maxCount := uint32(maxLen / 2)      // Max chars
	stub = appendUint32(stub, maxCount) // MaxCount
	stub = appendUint32(stub, 0)        // Offset
	stub = appendUint32(stub, 0)        // ActualCount = 0

	// lpType (LPULONG) - pointer + value
	stub = appendUint32(stub, 0x00020004)
	stub = appendUint32(stub, 0) // Initial type = 0

	// lpData (PBYTE_ARRAY) - pointer + array
	stub = appendUint32(stub, 0x00020008)
	stub = appendUint32(stub, dataSize) // MaxCount
	stub = appendUint32(stub, 0)        // Offset
	stub = appendUint32(stub, dataSize) // ActualCount
	// Add buffer data
	for i := uint32(0); i < dataSize; i++ {
		stub = append(stub, 0)
	}

	// lpcbData (LPULONG) - pointer + value
	stub = appendUint32(stub, 0x0002000C)
	stub = appendUint32(stub, dataSize)

	// lpcbLen (LPULONG) - pointer + value
	stub = appendUint32(stub, 0x00020010)
	stub = appendUint32(stub, dataSize)

	return stub
}

// encodeEnumKey encodes BaseRegEnumKey request
// Structure per MS-RRP:
//
//	hKey (RPC_HKEY - 20 bytes)
//	dwIndex (DWORD)
//	lpNameIn (RRP_UNICODE_STRING with buffer)
//	lpClassIn (PRRP_UNICODE_STRING - null pointer OK)
//	lpftLastWriteTime (PFILETIME - some systems need non-null)
func encodeEnumKey(handle Handle, index uint32) []byte {
	stub := make([]byte, 0, 128)

	// hKey (20 bytes)
	stub = append(stub, handle[:]...)

	// dwIndex
	stub = appendUint32(stub, index)

	// lpNameIn (RRP_UNICODE_STRING) - need to provide buffer for output
	// Structure: Length (2) + MaximumLength (2) + Buffer pointer (4)
	// Then pointer referent: MaxCount (4) + Offset (4) + ActualCount (4)
	maxLen := uint16(512)                 // buffer size for key name (256 chars * 2 bytes)
	stub = appendUint16(stub, 0)          // Length = 0 (empty input)
	stub = appendUint16(stub, maxLen)     // MaximumLength = 512 bytes
	stub = appendUint32(stub, 0x00020000) // Non-null buffer pointer

	// Buffer referent data (conformant varying array)
	maxCount := uint32(maxLen / 2)      // Max chars
	stub = appendUint32(stub, maxCount) // MaxCount
	stub = appendUint32(stub, 0)        // Offset
	stub = appendUint32(stub, 0)        // ActualCount = 0 (empty input)

	// lpClassIn (PRRP_UNICODE_STRING) - pointer to RRP_UNICODE_STRING
	// Non-null pointer with empty string buffer (like Impacket does)
	stub = appendUint32(stub, 0x00020004) // Non-null pointer
	// Referent: Length (2) + MaxLen (2) + BufferPtr (4)
	stub = appendUint16(stub, 0)  // Length = 0
	stub = appendUint16(stub, 64) // MaxLen
	stub = appendUint32(stub, 0)  // NULL buffer (no actual data needed)

	// lpftLastWriteTime (PFILETIME) - non-null pointer
	stub = appendUint32(stub, 0x00020008) // Non-null pointer
	// Referent: FILETIME (8 bytes)
	stub = appendUint32(stub, 0) // dwLowDateTime
	stub = appendUint32(stub, 0) // dwHighDateTime

	return stub
}

// encodeSetValue encodes BaseRegSetValue request
func encodeSetValue(handle Handle, valueName string, valueType uint32, data []byte) []byte {
	stub := make([]byte, 0, 256+len(data))

	// hKey
	stub = append(stub, handle[:]...)

	// lpValueName
	stub = append(stub, encodeRpcUnicodeString(valueName)...)

	// dwType
	stub = appendUint32(stub, valueType)

	// lpData (conformant array)
	stub = appendUint32(stub, uint32(len(data)))
	stub = append(stub, data...)
	// Pad to 4-byte boundary
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// cbData
	stub = appendUint32(stub, uint32(len(data)))

	return stub
}

// encodeDeleteValue encodes BaseRegDeleteValue request
func encodeDeleteValue(handle Handle, valueName string) []byte {
	stub := make([]byte, 0, 128)

	// hKey
	stub = append(stub, handle[:]...)

	// lpValueName
	stub = append(stub, encodeRpcUnicodeString(valueName)...)

	return stub
}

// encodeCreateKey encodes BaseRegCreateKey request
// Uses same inline string structure as encodeOpenKey for RPC_UNICODE_STRING
func encodeCreateKey(handle Handle, subkey string) []byte {
	stub := make([]byte, 0, 256)

	// hKey (handle) - 20 bytes
	stub = append(stub, handle[:]...)

	// lpSubKey (RRP_UNICODE_STRING) - INLINE string data
	runes := []rune(subkey + "\x00")
	utf16Chars := utf16.Encode(runes)
	charCount := uint32(len(utf16Chars))
	byteLen := charCount * 2

	// Length and MaximumLength (both include null terminator per Impacket)
	stub = appendUint16(stub, uint16(byteLen))
	stub = appendUint16(stub, uint16(byteLen))
	// Pointer (non-null referent ID)
	stub = appendUint32(stub, 0x00020000)

	// INLINE string data (conformant varying array)
	// MaxCount
	stub = appendUint32(stub, charCount)
	// Offset
	stub = appendUint32(stub, 0)
	// ActualCount
	stub = appendUint32(stub, charCount)

	// String data (UTF-16LE)
	for _, c := range utf16Chars {
		stub = append(stub, byte(c), byte(c>>8))
	}

	// Pad to 4-byte boundary
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// lpClass (RRP_UNICODE_STRING) - empty string
	// Length = 0, MaxLen = 0
	stub = appendUint16(stub, 0)
	stub = appendUint16(stub, 0)
	// NULL pointer
	stub = appendUint32(stub, 0)

	// dwOptions (REG_OPTION_NON_VOLATILE = 0x00000001, as used by Impacket)
	stub = appendUint32(stub, 0x00000001)

	// samDesired (MAXIMUM_ALLOWED = 0x02000000)
	stub = appendUint32(stub, 0x02000000)

	// lpSecurityAttributes (null pointer)
	stub = appendUint32(stub, 0)

	// lpdwDisposition (non-null pointer, value = 0)
	stub = appendUint32(stub, 0x00020004)
	stub = appendUint32(stub, 0)

	return stub
}

// encodeDeleteKey encodes BaseRegDeleteKey request
func encodeDeleteKey(handle Handle, subkey string) []byte {
	stub := make([]byte, 0, 128)

	// hKey
	stub = append(stub, handle[:]...)

	// lpSubKey
	stub = append(stub, encodeRpcUnicodeString(subkey)...)

	return stub
}

// encodeSaveKey encodes BaseRegSaveKey request
// Correct NDR layout (from Impacket analysis):
//
//	hKey (20 bytes context handle)
//	lpFile: Length(2) + MaxLen(2) + Ptr(4) + MaxCount(4) + Offset(4) + ActualCount(4) + StringData + Padding
//	pSecurityAttributes: Ptr(4) [NULL pointer]
func encodeSaveKey(handle Handle, filepath string) []byte {
	stub := make([]byte, 0, 256)

	// hKey (20 bytes)
	stub = append(stub, handle[:]...)

	// lpFile (RPC_UNICODE_STRING) - INLINE string data
	// Convert to UTF-16LE with null terminator
	runes := []rune(filepath + "\x00")
	utf16Chars := utf16.Encode(runes)
	charCount := uint32(len(utf16Chars))
	byteLen := charCount * 2

	// Length and MaximumLength (both include null terminator per Impacket)
	stub = appendUint16(stub, uint16(byteLen))
	stub = appendUint16(stub, uint16(byteLen))
	// Pointer (non-null referent ID)
	stub = appendUint32(stub, 0x00020000)

	// INLINE string data (conformant varying array)
	// MaxCount
	stub = appendUint32(stub, charCount)
	// Offset
	stub = appendUint32(stub, 0)
	// ActualCount
	stub = appendUint32(stub, charCount)

	// String data (UTF-16LE)
	for _, c := range utf16Chars {
		stub = append(stub, byte(c), byte(c>>8))
	}

	// Pad to 4-byte boundary (alignment pad before next field)
	for len(stub)%4 != 0 {
		stub = append(stub, 0xbf) // Use 0xbf like Impacket
	}

	// pSecurityAttributes (NULL pointer) - comes AFTER string data
	stub = appendUint32(stub, 0)

	return stub
}

// encodeRpcUnicodeString encodes an RPC_UNICODE_STRING
func encodeRpcUnicodeString(s string) []byte {
	// Convert to UTF-16LE with null terminator
	runes := []rune(s + "\x00")
	utf16Chars := utf16.Encode(runes)

	charCount := uint32(len(utf16Chars))
	byteLen := charCount * 2

	buf := make([]byte, 0, 16+int(byteLen))

	// Length and MaximumLength (both include null terminator per Impacket)
	buf = appendUint16(buf, uint16(byteLen))
	buf = appendUint16(buf, uint16(byteLen))
	// Pointer (non-null)
	buf = appendUint32(buf, 0x00020000)

	// Conformant array: MaxCount, Offset, ActualCount
	buf = appendUint32(buf, charCount)
	buf = appendUint32(buf, 0)
	buf = appendUint32(buf, charCount)

	// String data
	for _, c := range utf16Chars {
		buf = append(buf, byte(c), byte(c>>8))
	}

	// Pad to 4-byte boundary
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}

	return buf
}

// parseQueryValueResponse parses BaseRegQueryValue response
// Response structure (interleaved pointers + referents):
//
//	lpType (LPULONG) - ptr + value
//	lpData (PBYTE_ARRAY) - ptr + array (MaxCount, Offset, ActualCount, data)
//	lpcbData (LPULONG) - ptr + value
//	lpcbLen (LPULONG) - ptr + value
//	ErrorCode (ULONG)
func parseQueryValueResponse(name string, resp []byte) (*RegistryValue, error) {
	if len(resp) < 4 {
		return nil, nil
	}

	// Check return code at end
	retCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retCode != 0 {
		return nil, fmt.Errorf("query value failed: 0x%08X", retCode)
	}

	if len(resp) < 28 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	offset := 0

	// lpType (LPULONG): ptr + value
	// ptr at offset, value at offset+4
	offset += 4 // skip ptr
	valType := binary.LittleEndian.Uint32(resp[offset : offset+4])
	offset += 4

	// lpData (PBYTE_ARRAY): ptr + MaxCount + Offset + ActualCount + data
	offset += 4 // skip ptr
	if len(resp) < offset+12 {
		return nil, fmt.Errorf("response too short for lpData")
	}
	// maxCount := binary.LittleEndian.Uint32(resp[offset : offset+4])
	offset += 4 // skip MaxCount
	offset += 4 // skip Offset
	actualCount := binary.LittleEndian.Uint32(resp[offset : offset+4])
	offset += 4

	// Read the data
	if len(resp) < offset+int(actualCount) {
		return nil, fmt.Errorf("response too short for data: need %d, have %d", offset+int(actualCount), len(resp))
	}
	data := make([]byte, actualCount)
	copy(data, resp[offset:offset+int(actualCount)])
	offset += int(actualCount)

	// Align to 4 bytes
	if offset%4 != 0 {
		offset += 4 - (offset % 4)
	}

	// lpcbData, lpcbLen, ErrorCode follow but we don't need them

	return &RegistryValue{
		Name: name,
		Type: valType,
		Data: data,
	}, nil
}

// parseEnumValueResponse parses BaseRegEnumValue response
// Response structure:
//
//	lpValueNameOut (RRP_UNICODE_STRING)
//	lpType (LPULONG)
//	lpData (PBYTE_ARRAY)
//	lpcbData (LPULONG)
//	lpcbLen (LPULONG)
//	ErrorCode (ULONG)
func parseEnumValueResponse(resp []byte) (*RegistryValue, error) {
	if len(resp) < 4 {
		return nil, fmt.Errorf("response too short")
	}

	retCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retCode != 0 {
		return nil, fmt.Errorf("enum value returned: 0x%08X", retCode)
	}

	if len(resp) < 28 {
		return nil, fmt.Errorf("response too short for value data")
	}

	// Parse lpValueNameOut (RRP_UNICODE_STRING)
	// Structure: Length (2) + MaxLen (2) + Ptr (4) + MaxCount (4) + Offset (4) + ActualCount (4) + StringData
	nameLen := binary.LittleEndian.Uint16(resp[0:2])
	// maxLen := binary.LittleEndian.Uint16(resp[2:4])
	// ptr at 4:8

	offset := 8 // After Length, MaxLen, Ptr

	// Read conformant array header
	if len(resp) < offset+12 {
		return nil, fmt.Errorf("response too short for name array")
	}
	// maxCount := binary.LittleEndian.Uint32(resp[offset : offset+4])
	// arrayOffset := binary.LittleEndian.Uint32(resp[offset+4 : offset+8])
	actualCount := binary.LittleEndian.Uint32(resp[offset+8 : offset+12])
	offset += 12

	// Read value name
	valueName := ""
	if actualCount > 0 && nameLen > 0 {
		stringBytes := int(actualCount) * 2
		if len(resp) < offset+stringBytes {
			return nil, fmt.Errorf("response too short for name string")
		}

		u16s := make([]uint16, actualCount)
		for i := range u16s {
			u16s[i] = binary.LittleEndian.Uint16(resp[offset+i*2:])
		}
		// Remove null terminator
		for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
			u16s = u16s[:len(u16s)-1]
		}
		valueName = string(utf16.Decode(u16s))
		offset += stringBytes
	}

	// Align to 4 bytes
	if offset%4 != 0 {
		offset += 4 - (offset % 4)
	}

	// Parse lpType (pointer + value)
	if len(resp) < offset+8 {
		return nil, fmt.Errorf("response too short for type")
	}
	// Skip pointer
	offset += 4
	valueType := binary.LittleEndian.Uint32(resp[offset : offset+4])
	offset += 4

	// Parse lpData (PBYTE_ARRAY)
	// Pointer + MaxCount + Offset + ActualCount + Data
	if len(resp) < offset+16 {
		return nil, fmt.Errorf("response too short for data header")
	}
	// Skip pointer
	offset += 4
	// dataMaxCount := binary.LittleEndian.Uint32(resp[offset : offset+4])
	offset += 4 // skip MaxCount
	offset += 4 // skip Offset
	dataActualCount := binary.LittleEndian.Uint32(resp[offset : offset+4])
	offset += 4

	// Read data
	var valueData []byte
	if dataActualCount > 0 && len(resp) >= offset+int(dataActualCount) {
		valueData = make([]byte, dataActualCount)
		copy(valueData, resp[offset:offset+int(dataActualCount)])
	}

	return &RegistryValue{
		Name: valueName,
		Type: valueType,
		Data: valueData,
	}, nil
}

// parseEnumKeyResponse parses BaseRegEnumKey response
func parseEnumKeyResponse(resp []byte) (string, error) {
	if len(resp) < 4 {
		return "", fmt.Errorf("response too short")
	}

	retCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retCode != 0 {
		return "", fmt.Errorf("enum key returned: 0x%08X", retCode)
	}

	// BaseRegEnumKey response NDR layout:
	// lpNameOut: RRP_UNICODE_STRING (Length [2] + MaxLen [2] + Ptr [4] + MaxCount [4] + Offset [4] + ActualCount [4] + StringData)
	// lpClassOut: RRP_UNICODE_STRING (same structure)  - can be NULL
	// lpftLastWriteTime: PFILETIME (pointer + optional 8 bytes)
	// ReturnValue: DWORD

	if len(resp) < 20 {
		return "", fmt.Errorf("response too short for name")
	}

	// Parse lpNameOut (RRP_UNICODE_STRING)
	length := binary.LittleEndian.Uint16(resp[0:2])
	// maxLen at 2:4
	// ptr at 4:8

	if length == 0 {
		return "", nil
	}

	// After the header (8 bytes), we have the conformant array
	// MaxCount (4) + Offset (4) + ActualCount (4) + StringData
	if len(resp) < 20 {
		return "", fmt.Errorf("response too short for string data")
	}

	actualCount := binary.LittleEndian.Uint32(resp[16:20])
	if actualCount == 0 {
		return "", nil
	}

	// String data starts at offset 20
	stringDataStart := 20
	stringDataLen := int(actualCount) * 2 // UTF-16LE

	if len(resp) < stringDataStart+stringDataLen {
		return "", fmt.Errorf("response too short for string content")
	}

	// Decode UTF-16LE string
	stringData := resp[stringDataStart : stringDataStart+stringDataLen]
	u16s := make([]uint16, actualCount)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(stringData[i*2:])
	}

	// Remove null terminator if present
	for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}

	return string(utf16.Decode(u16s)), nil
}

func appendUint32(buf []byte, val uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, val)
	return append(buf, b...)
}

func appendUint16(buf []byte, val uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, val)
	return append(buf, b...)
}
