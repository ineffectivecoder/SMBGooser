package tsch

import (
	"encoding/binary"
	"unicode/utf16"
)

// encodeRegisterTask encodes SchRpcRegisterTask request
func encodeRegisterTask(taskPath, taskXML string) []byte {
	stub := make([]byte, 0, 1024)

	// path (wchar_t*)
	stub = append(stub, encodeNdrWString(taskPath)...)

	// xmlTaskDefinition (wchar_t*)
	stub = append(stub, encodeNdrWString(taskXML)...)

	// flags (DWORD) - TASK_CREATE
	stub = appendUint32(stub, TaskCreate)

	// sddl (wchar_t*) - NULL
	stub = append(stub, 0, 0, 0, 0)

	// logonType (DWORD) - TASK_LOGON_S4U (run as SYSTEM)
	stub = appendUint32(stub, TaskLogonS4U)

	// cCreds (DWORD) - 0
	stub = appendUint32(stub, 0)

	// pCreds (TASK_USER_CRED*) - NULL
	stub = append(stub, 0, 0, 0, 0)

	return stub
}

// encodeRunTask encodes SchRpcRun request
func encodeRunTask(taskPath string) []byte {
	stub := make([]byte, 0, 256)

	// path (wchar_t*)
	stub = append(stub, encodeNdrWString(taskPath)...)

	// cArgs (DWORD) - 0 arguments
	stub = appendUint32(stub, 0)

	// pArgs (wchar_t**) - NULL
	stub = append(stub, 0, 0, 0, 0)

	// flags (DWORD) - TASK_RUN_IGNORE_CONSTRAINTS
	stub = appendUint32(stub, TaskRunIgnoreConstraints)

	// sessionId (DWORD) - 0
	stub = appendUint32(stub, 0)

	// user (wchar_t*) - NULL (run as registered user)
	stub = append(stub, 0, 0, 0, 0)

	return stub
}

// encodeDeleteTask encodes SchRpcDelete request
func encodeDeleteTask(taskPath string) []byte {
	stub := make([]byte, 0, 256)

	// path (wchar_t*)
	stub = append(stub, encodeNdrWString(taskPath)...)

	// flags (DWORD) - 0
	stub = appendUint32(stub, 0)

	return stub
}

// encodeNdrWString encodes a string as NDR conformant/varying wide string (UTF-16LE)
func encodeNdrWString(s string) []byte {
	// Convert to UTF-16 with null terminator
	runes := []rune(s + "\x00")
	utf16Chars := utf16.Encode(runes)
	charCount := uint32(len(utf16Chars))

	// Referent ID (non-null pointer)
	buf := make([]byte, 0, 16+len(utf16Chars)*2)
	buf = appendUint32(buf, 0x00020000) // referent ID

	// MaxCount
	buf = appendUint32(buf, charCount)
	// Offset
	buf = appendUint32(buf, 0)
	// ActualCount
	buf = appendUint32(buf, charCount)

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
