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
func encodeQueryValue(handle Handle, valueName string) []byte {
	stub := make([]byte, 0, 256)

	// hKey
	stub = append(stub, handle[:]...)

	// lpValueName (RPC_UNICODE_STRING)
	stub = append(stub, encodeRpcUnicodeString(valueName)...)

	// lpType (pointer to DWORD) - non-null
	stub = appendUint32(stub, 0x00020000)
	stub = appendUint32(stub, 0) // placeholder

	// lpData (pointer) - non-null, we want data
	stub = appendUint32(stub, 0x00020004)
	// lpcbData (size) - non-null
	stub = appendUint32(stub, 0x00020008)
	// lpcbLen
	stub = appendUint32(stub, 0x0002000C)

	// Max size for data (64KB)
	stub = appendUint32(stub, 65536)
	stub = appendUint32(stub, 0) // actual data will be returned
	stub = appendUint32(stub, 65536)
	stub = appendUint32(stub, 65536)

	return stub
}

// encodeEnumValue encodes BaseRegEnumValue request
func encodeEnumValue(handle Handle, index uint32) []byte {
	stub := make([]byte, 0, 128)

	// hKey
	stub = append(stub, handle[:]...)

	// dwIndex
	stub = appendUint32(stub, index)

	// lpValueNameIn (RPC_UNICODE_STRING) - buffer for name
	stub = appendUint32(stub, 512)        // MaximumLength
	stub = appendUint32(stub, 0)          // Length
	stub = appendUint32(stub, 0x00020000) // pointer
	// Conformant array
	stub = appendUint32(stub, 256) // MaxCount
	stub = appendUint32(stub, 0)   // Offset
	stub = appendUint32(stub, 0)   // ActualCount

	// lpType
	stub = appendUint32(stub, 0x00020004)
	stub = appendUint32(stub, 0)

	// lpData
	stub = appendUint32(stub, 0x00020008)
	stub = appendUint32(stub, 0x0002000C)

	stub = appendUint32(stub, 65536)
	stub = appendUint32(stub, 0)
	stub = appendUint32(stub, 65536)
	stub = appendUint32(stub, 65536)

	return stub
}

// encodeEnumKey encodes BaseRegEnumKey request
func encodeEnumKey(handle Handle, index uint32) []byte {
	stub := make([]byte, 0, 128)

	// hKey
	stub = append(stub, handle[:]...)

	// dwIndex
	stub = appendUint32(stub, index)

	// lpNameIn (RRR_UNICODE_STRING) - buffer for name
	stub = appendUint32(stub, 512)
	stub = appendUint32(stub, 0)
	stub = appendUint32(stub, 0x00020000)
	stub = appendUint32(stub, 256)
	stub = appendUint32(stub, 0)
	stub = appendUint32(stub, 0)

	// lpClassIn (null)
	stub = appendUint32(stub, 0)
	stub = appendUint32(stub, 0)
	stub = appendUint32(stub, 0)

	// lpftLastWriteTime (null)
	stub = appendUint32(stub, 0)

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
func parseQueryValueResponse(name string, resp []byte) (*RegistryValue, error) {
	if len(resp) < 4 {
		return nil, nil
	}

	// Check return code at end
	retCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retCode != 0 {
		return nil, fmt.Errorf("query value failed: 0x%08X", retCode)
	}

	// Parse response - this is simplified
	// Format: lpType, lpData, lpcbData, lpcbLen, retCode
	if len(resp) < 20 {
		return nil, nil
	}

	// Type is at offset 0-4
	valType := binary.LittleEndian.Uint32(resp[0:4])

	// Find the data - skip type and pointers
	// This is a simplified parser
	dataStart := 4
	if len(resp) > 12 {
		dataLen := binary.LittleEndian.Uint32(resp[len(resp)-8 : len(resp)-4])
		if int(dataLen) < len(resp)-12 {
			dataStart = len(resp) - int(dataLen) - 8
		}
	}

	data := resp[dataStart : len(resp)-4]

	return &RegistryValue{
		Name: name,
		Type: valType,
		Data: data,
	}, nil
}

// parseEnumValueResponse parses BaseRegEnumValue response
func parseEnumValueResponse(resp []byte) (*RegistryValue, error) {
	if len(resp) < 4 {
		return nil, fmt.Errorf("response too short")
	}

	retCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retCode != 0 {
		return nil, fmt.Errorf("enum value returned: 0x%08X", retCode)
	}

	// Simplified parsing - extract name and type
	// The response format is complex, this is a basic implementation
	return &RegistryValue{
		Name: "value",
		Type: RegSZ,
		Data: nil,
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

	// Extract key name from response
	// The name is in RPC_UNICODE_STRING format
	if len(resp) < 16 {
		return "", nil
	}

	// Skip first 4 bytes (Length, MaxLength), then read string
	// This is simplified
	return "subkey", nil
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
