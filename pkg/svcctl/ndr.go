package svcctl

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// encodeOpenSCManager encodes ROpenSCManagerW request
// lpMachineName: machine to connect to (empty for local)
// dwDesiredAccess: access mask
func encodeOpenSCManager(machineName string, access SCMAccessMask) []byte {
	stub := make([]byte, 0, 256)

	// lpMachineName (unique pointer to Unicode string)
	if machineName == "" {
		// Null pointer
		stub = append(stub, 0, 0, 0, 0)
	} else {
		// Non-null pointer (use 0x00020000 as referent ID)
		stub = append(stub, 0x00, 0x00, 0x02, 0x00)
		stub = append(stub, encodeNdrString(machineName)...)
	}

	// lpDatabaseName (null - use default SERVICES_ACTIVE_DATABASE)
	stub = append(stub, 0, 0, 0, 0)

	// dwDesiredAccess
	stub = appendUint32(stub, uint32(access))

	return stub
}

// encodeCreateService encodes RCreateServiceW request
func encodeCreateService(scmHandle Handle, serviceName, displayName, binPath string) []byte {
	stub := make([]byte, 0, 512)

	// hSCManager handle (20 bytes)
	stub = append(stub, scmHandle[:]...)

	// lpServiceName (Unicode string)
	stub = append(stub, encodeNdrString(serviceName)...)

	// lpDisplayName (unique pointer to Unicode string)
	stub = append(stub, 0x00, 0x00, 0x02, 0x00) // non-null referent
	stub = append(stub, encodeNdrString(displayName)...)

	// dwDesiredAccess
	stub = appendUint32(stub, uint32(ServiceAllAccess|Delete))

	// dwServiceType (SERVICE_WIN32_OWN_PROCESS)
	stub = appendUint32(stub, uint32(ServiceWin32OwnProcess))

	// dwStartType (SERVICE_DEMAND_START)
	stub = appendUint32(stub, uint32(ServiceDemandStart))

	// dwErrorControl (SERVICE_ERROR_IGNORE)
	stub = appendUint32(stub, uint32(ServiceErrorIgnore))

	// lpBinaryPathName
	stub = append(stub, encodeNdrString(binPath)...)

	// lpLoadOrderGroup (null)
	stub = append(stub, 0, 0, 0, 0)

	// lpdwTagId (null)
	stub = append(stub, 0, 0, 0, 0)

	// lpDependencies (null)
	stub = append(stub, 0, 0, 0, 0)

	// dwDependSize
	stub = appendUint32(stub, 0)

	// lpServiceStartName (null - LocalSystem)
	stub = append(stub, 0, 0, 0, 0)

	// lpPassword (null)
	stub = append(stub, 0, 0, 0, 0)

	// dwPwSize
	stub = appendUint32(stub, 0)

	return stub
}

// encodeOpenService encodes ROpenServiceW request
func encodeOpenService(scmHandle Handle, serviceName string, access ServiceAccessMask) []byte {
	stub := make([]byte, 0, 256)

	// hSCManager handle (20 bytes)
	stub = append(stub, scmHandle[:]...)

	// lpServiceName
	stub = append(stub, encodeNdrString(serviceName)...)

	// dwDesiredAccess
	stub = appendUint32(stub, uint32(access))

	return stub
}

// encodeStartService encodes RStartServiceW request
func encodeStartService(serviceHandle Handle) []byte {
	stub := make([]byte, 0, 64)

	// hService handle (20 bytes)
	stub = append(stub, serviceHandle[:]...)

	// argc (number of arguments)
	stub = appendUint32(stub, 0)

	// argv (null - no arguments)
	stub = append(stub, 0, 0, 0, 0)

	return stub
}

// encodeDeleteService encodes RDeleteService request
func encodeDeleteService(serviceHandle Handle) []byte {
	stub := make([]byte, 20)
	copy(stub, serviceHandle[:])
	return stub
}

// encodeNdrString encodes a string as NDR conformant/varying Unicode string
func encodeNdrString(s string) []byte {
	// Convert to UTF-16LE with null terminator
	runes := []rune(s + "\x00")
	utf16Chars := utf16.Encode(runes)

	// MaxCount, Offset, ActualCount (all in characters, not bytes)
	charCount := uint32(len(utf16Chars))

	buf := make([]byte, 12+len(utf16Chars)*2)

	// MaxCount
	binary.LittleEndian.PutUint32(buf[0:4], charCount)
	// Offset
	binary.LittleEndian.PutUint32(buf[4:8], 0)
	// ActualCount
	binary.LittleEndian.PutUint32(buf[8:12], charCount)

	// String data (UTF-16LE)
	for i, c := range utf16Chars {
		binary.LittleEndian.PutUint16(buf[12+i*2:], c)
	}

	// Pad to 4-byte boundary
	padding := (4 - (len(buf) % 4)) % 4
	for i := 0; i < padding; i++ {
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

// encodeEnumServicesStatus encodes REnumServicesStatusW request
func encodeEnumServicesStatus(scmHandle Handle, serviceType ServiceType, serviceState uint32) []byte {
	stub := make([]byte, 0, 64)

	// hSCManager handle (20 bytes)
	stub = append(stub, scmHandle[:]...)

	// dwServiceType (SERVICE_WIN32 = 0x30 for all Win32 services)
	stub = appendUint32(stub, uint32(serviceType))

	// dwServiceState (SERVICE_STATE_ALL = 3)
	stub = appendUint32(stub, serviceState)

	// cbBufSize - buffer size (we'll request a large buffer)
	stub = appendUint32(stub, 65536)

	// lpResumeHandle (null for first call)
	stub = appendUint32(stub, 0)

	return stub
}

// encodeControlService encodes RControlService request
func encodeControlService(serviceHandle Handle, control uint32) []byte {
	stub := make([]byte, 0, 24)

	// hService handle (20 bytes)
	stub = append(stub, serviceHandle[:]...)

	// dwControl
	stub = appendUint32(stub, control)

	return stub
}

// parseEnumServicesResponse parses REnumServicesStatusW response
func parseEnumServicesResponse(resp []byte) ([]ServiceInfo, error) {
	if len(resp) < 16 {
		return nil, nil
	}

	// Response format:
	// lpBuffer (variable) - ENUM_SERVICE_STATUSW array
	// pcbBytesNeeded (4 bytes)
	// lpServicesReturned (4 bytes)
	// lpResumeHandle (4 bytes) - optional
	// return code (4 bytes)

	// Get count of services (near end of response)
	// The exact offset depends on the buffer layout
	// This is a simplified parser that tries to extract service info

	var services []ServiceInfo

	// Try to find service count - it's typically at offset after the buffer
	// For now, let's parse what we can from the response
	// The buffer contains ENUM_SERVICE_STATUS_PROCESSW structures

	if len(resp) < 20 {
		return services, nil
	}

	// Check return code at end
	retCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retCode != 0 && retCode != 234 { // 234 = ERROR_MORE_DATA
		return nil, nil
	}

	// Try to parse the service entries from the buffer
	// ENUM_SERVICE_STATUSW is: ServiceName (ptr), DisplayName (ptr), ServiceStatus (28 bytes)
	// This is complex due to pointer indirection - we'll do a simplified parse

	// The response contains offset-based strings
	// For now, return a placeholder showing we got data
	if len(resp) > 64 {
		// We got data, try to extract some service info
		// This requires proper NDR parsing of the response buffer
		// For a complete implementation, we'd need to parse the conformant array

		// Count is typically at the end before return code
		if len(resp) >= 16 {
			countOffset := len(resp) - 12
			if countOffset > 0 && countOffset < len(resp)-4 {
				count := binary.LittleEndian.Uint32(resp[countOffset:])
				if count > 0 && count < 1000 {
					// We have services but need to parse the buffer properly
					// For now, indicate success
					services = append(services, ServiceInfo{
						ServiceName: "(enumeration returned data - see raw response)",
						DisplayName: fmt.Sprintf("%d services found (full parsing pending)", count),
						Status: ServiceStatus{
							CurrentState: ServiceRunning,
						},
					})
				}
			}
		}
	}

	return services, nil
}
