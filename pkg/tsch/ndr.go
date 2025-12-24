package tsch

import (
	"encoding/binary"
	"unicode/utf16"
)

// encodeRegisterTask encodes SchRpcRegisterTask request
// Fields: path (LPWSTR), xml (WSTR), flags (DWORD), sddl (LPWSTR), logonType (DWORD), cCreds (DWORD), pCreds (LPTASK_USER_CRED_ARRAY)
func encodeRegisterTask(taskPath, taskXML string) []byte {
	stub := make([]byte, 0, 2048)

	// path (LPWSTR) - pointer to string
	stub = append(stub, encodeNdrLPWStr(taskPath)...)

	// xmlTaskDefinition (WSTR) - inline string (NO referent ID!)
	stub = append(stub, encodeNdrWStr(taskXML)...)

	// flags (DWORD) - TASK_CREATE
	stub = appendUint32(stub, TaskCreate)

	// sddl (LPWSTR) - NULL
	stub = append(stub, 0, 0, 0, 0)

	// logonType (DWORD) - TASK_LOGON_NONE (use principal from XML)
	stub = appendUint32(stub, TaskLogonNone)

	// cCreds (DWORD) - 0
	stub = appendUint32(stub, 0)

	// pCreds (TASK_USER_CRED*) - NULL
	stub = append(stub, 0, 0, 0, 0)

	return stub
}

// encodeRunTask encodes SchRpcRun request
func encodeRunTask(taskPath string) []byte {
	stub := make([]byte, 0, 256)

	// path (WSTR) - inline string for SchRpcRun
	stub = append(stub, encodeNdrWStr(taskPath)...)

	// cArgs (DWORD) - 0 arguments
	stub = appendUint32(stub, 0)

	// pArgs (wchar_t**) - NULL
	stub = append(stub, 0, 0, 0, 0)

	// flags (DWORD) - 0 (Impacket default, not TASK_RUN_IGNORE_CONSTRAINTS)
	stub = appendUint32(stub, 0)

	// sessionId (DWORD) - 0
	stub = appendUint32(stub, 0)

	// user (LPWSTR) - NULL (run as registered user)
	stub = append(stub, 0, 0, 0, 0)

	return stub
}

// encodeDeleteTask encodes SchRpcDelete request
func encodeDeleteTask(taskPath string) []byte {
	stub := make([]byte, 0, 256)

	// path (WSTR) - inline string
	stub = append(stub, encodeNdrWStr(taskPath)...)

	// flags (DWORD) - 0
	stub = appendUint32(stub, 0)

	return stub
}

// encodeNdrLPWStr encodes a string as LPWSTR (pointer to wide string)
// This includes a referent ID followed by the conformant/varying string
func encodeNdrLPWStr(s string) []byte {
	// Convert to UTF-16 with null terminator
	runes := []rune(s + "\x00")
	utf16Chars := utf16.Encode(runes)
	charCount := uint32(len(utf16Chars))

	// LPWSTR: Referent ID + MaxCount + Offset + ActualCount + Data
	buf := make([]byte, 0, 16+len(utf16Chars)*2)
	buf = appendUint32(buf, 0x00020000) // Referent ID (non-null pointer)

	// Conformant varying array
	buf = appendUint32(buf, charCount) // MaxCount
	buf = appendUint32(buf, 0)         // Offset
	buf = appendUint32(buf, charCount) // ActualCount

	// String data (UTF-16LE)
	for _, c := range utf16Chars {
		buf = append(buf, byte(c), byte(c>>8))
	}

	// Pad to 4-byte boundary
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}

	return buf
}

// encodeNdrWStr encodes a string as WSTR (inline wide string, no referent ID)
// This is a conformant varying array without a pointer referent
func encodeNdrWStr(s string) []byte {
	// Convert to UTF-16 with null terminator
	runes := []rune(s + "\x00")
	utf16Chars := utf16.Encode(runes)
	charCount := uint32(len(utf16Chars))

	// WSTR: MaxCount + Offset + ActualCount + Data (no referent ID!)
	buf := make([]byte, 0, 12+len(utf16Chars)*2)

	// Conformant varying array header
	buf = appendUint32(buf, charCount) // MaxCount
	buf = appendUint32(buf, 0)         // Offset
	buf = appendUint32(buf, charCount) // ActualCount

	// String data (UTF-16LE)
	for _, c := range utf16Chars {
		buf = append(buf, byte(c), byte(c>>8))
	}

	// Pad to 4-byte boundary
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}

	return buf
}

// appendUint32 appends a little-endian uint32
func appendUint32(buf []byte, val uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, val)
	return append(buf, b...)
}

// Enum flags
const (
	TaskEnumHidden = 1
)

// encodeEnumTasks encodes SchRpcEnumTasks request
// path (WSTR), flags (DWORD), startIndex (DWORD), cRequested (DWORD)
func encodeEnumTasks(path string, flags, startIndex, cRequested uint32) []byte {
	stub := make([]byte, 0, 256)

	// path (WSTR) - inline string
	stub = append(stub, encodeNdrWStr(path)...)

	// flags (DWORD)
	stub = appendUint32(stub, flags)

	// startIndex (DWORD)
	stub = appendUint32(stub, startIndex)

	// cRequested (DWORD)
	stub = appendUint32(stub, cRequested)

	return stub
}

// encodeEnumFolders encodes SchRpcEnumFolders request
// path (WSTR), flags (DWORD), startIndex (DWORD), cRequested (DWORD)
func encodeEnumFolders(path string, flags, startIndex, cRequested uint32) []byte {
	stub := make([]byte, 0, 256)

	// path (WSTR) - inline string
	stub = append(stub, encodeNdrWStr(path)...)

	// flags (DWORD)
	stub = appendUint32(stub, flags)

	// startIndex (DWORD)
	stub = appendUint32(stub, startIndex)

	// cRequested (DWORD)
	stub = appendUint32(stub, cRequested)

	return stub
}

// parseEnumResponse parses the response from SchRpcEnumTasks/SchRpcEnumFolders
// Response: startIndex (DWORD), pcNames (DWORD), pNames (PTASK_NAMES_ARRAY), ErrorCode (ULONG)
func parseEnumResponse(resp []byte) ([]string, uint32, error) {
	if len(resp) < 16 {
		return nil, 0, nil
	}

	offset := 0

	// startIndex (DWORD) - returned start index
	offset += 4

	// pcNames (DWORD) - number of names returned
	pcNames := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// pNames - pointer to array (if pcNames > 0)
	if pcNames == 0 {
		// No names, skip to error code
		if offset+8 <= len(resp) {
			// Skip null pointer + error code read
			errCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
			return nil, errCode, nil
		}
		return nil, 0, nil
	}

	// Skip array pointer referent ID
	offset += 4

	// Read MaxCount of the array
	if offset+4 > len(resp) {
		return nil, 0, nil
	}
	offset += 4 // maxCount

	// Now we have array of LPWSTR pointers (referent IDs)
	for i := uint32(0); i < pcNames && offset+4 <= len(resp); i++ {
		offset += 4 // Skip referent ID for each string
	}

	// Now parse the actual string data
	var names []string
	for i := uint32(0); i < pcNames && offset+12 <= len(resp); i++ {
		// Each string: MaxCount (4) + Offset (4) + ActualCount (4) + Data
		maxCount := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
		offset += 4 // skip offset (always 0)
		actualCount := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		if actualCount > 1000 || maxCount > 1000 {
			break // Sanity check
		}

		strBytes := int(actualCount) * 2
		if offset+strBytes > len(resp) {
			break
		}

		name := decodeUTF16LE(resp[offset : offset+strBytes])
		names = append(names, name)
		offset += strBytes

		// Align to 4 bytes
		for offset%4 != 0 && offset < len(resp) {
			offset++
		}
	}

	// Error code at end
	var errCode uint32
	if len(resp) >= 4 {
		errCode = binary.LittleEndian.Uint32(resp[len(resp)-4:])
	}

	return names, errCode, nil
}

// decodeUTF16LE decodes UTF-16LE bytes to string
func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	u16 := make([]uint16, len(data)/2)
	for i := 0; i < len(data)/2; i++ {
		u16[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	// Find null terminator
	for i, v := range u16 {
		if v == 0 {
			u16 = u16[:i]
			break
		}
	}
	runes := make([]rune, len(u16))
	for i, v := range u16 {
		runes[i] = rune(v)
	}
	return string(runes)
}
