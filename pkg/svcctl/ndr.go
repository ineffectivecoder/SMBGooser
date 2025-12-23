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
func encodeEnumServicesStatus(scmHandle Handle, serviceType ServiceType, serviceState uint32, bufSize uint32) []byte {
	stub := make([]byte, 0, 64)

	// hSCManager handle (20 bytes)
	stub = append(stub, scmHandle[:]...)

	// dwServiceType (SERVICE_WIN32 = 0x30 for all Win32 services)
	stub = appendUint32(stub, uint32(serviceType))

	// dwServiceState (SERVICE_STATE_ALL = 3)
	stub = appendUint32(stub, serviceState)

	// cbBufSize - buffer size
	stub = appendUint32(stub, bufSize)

	// lpResumeHandle - unique pointer to DWORD (initial value 0)
	// Pointer referent ID (non-null)
	stub = append(stub, 0x00, 0x00, 0x02, 0x00)
	// The actual value pointed to
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
// bufferSize is the pcbBytesNeeded from the first-phase call
func parseEnumServicesResponse(resp []byte, bufferSize uint32) ([]ServiceInfo, error) {
	// Response format for REnumServicesStatusW:
	// - MaxCount (4 bytes) - NDR conformant array header
	// - Buffer data (variable, may be truncated due to fragmentation)
	// - pcbBytesNeeded (4 bytes)
	// - lpServicesReturned (4 bytes)
	// - lpResumeIndex pointer (4 bytes) + optional value (4 bytes)
	// - ErrorCode (4 bytes)
	//
	// NOTE: Due to DCE/RPC fragmentation, response may be smaller than expected.
	// We read trailer from END of response and calculate actual buffer size.

	if len(resp) < 20 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	// Read MaxCount from header
	maxCount := binary.LittleEndian.Uint32(resp[0:4])

	if Debug {
		fmt.Printf("[DEBUG] parseEnumServicesResponse: resp=%d bytes, maxCount=%d, expected bufferSize=%d\n",
			len(resp), maxCount, bufferSize)
	}

	// Read trailer from END of response
	// Try to determine trailer size by checking if resume pointer is null
	// Trailer options:
	// - 16 bytes: pcbBytesNeeded(4) + lpServicesReturned(4) + resumePtr(4, null) + retCode(4)
	// - 20 bytes: pcbBytesNeeded(4) + lpServicesReturned(4) + resumePtr(4) + resumeVal(4) + retCode(4)

	var retCode, servicesReturned, pcbBytesNeeded uint32
	var trailerSize int

	// Try 20-byte trailer first
	if len(resp) >= 24 {
		retCode = binary.LittleEndian.Uint32(resp[len(resp)-4:])
		resumeVal := binary.LittleEndian.Uint32(resp[len(resp)-8:])
		resumePtr := binary.LittleEndian.Uint32(resp[len(resp)-12:])
		servicesReturned = binary.LittleEndian.Uint32(resp[len(resp)-16:])
		pcbBytesNeeded = binary.LittleEndian.Uint32(resp[len(resp)-20:])

		if Debug {
			fmt.Printf("[DEBUG] Trying 20-byte trailer: pcbNeeded=%d, svcRet=%d, resumePtr=0x%X, resumeVal=%d, retCode=0x%X\n",
				pcbBytesNeeded, servicesReturned, resumePtr, resumeVal, retCode)
		}

		// Validate: retCode should be 0 or valid error, servicesReturned should be reasonable
		if retCode == 0 && servicesReturned > 0 && servicesReturned < 1000 {
			trailerSize = 20
		}
	}

	// Try 16-byte trailer if 20-byte didn't work
	if trailerSize == 0 && len(resp) >= 20 {
		retCode = binary.LittleEndian.Uint32(resp[len(resp)-4:])
		resumePtr := binary.LittleEndian.Uint32(resp[len(resp)-8:])
		servicesReturned = binary.LittleEndian.Uint32(resp[len(resp)-12:])
		pcbBytesNeeded = binary.LittleEndian.Uint32(resp[len(resp)-16:])

		if Debug {
			fmt.Printf("[DEBUG] Trying 16-byte trailer: pcbNeeded=%d, svcRet=%d, resumePtr=0x%X, retCode=0x%X\n",
				pcbBytesNeeded, servicesReturned, resumePtr, retCode)
		}

		// Validate
		if retCode == 0 && servicesReturned > 0 && servicesReturned < 1000 {
			trailerSize = 16
		}
	}

	if trailerSize == 0 {
		return nil, fmt.Errorf("could not find valid trailer in response")
	}

	if Debug {
		fmt.Printf("[DEBUG] Using %d-byte trailer: servicesReturned=%d, retCode=0x%X\n",
			trailerSize, servicesReturned, retCode)
	}

	if retCode != 0 {
		return nil, fmt.Errorf("enumeration failed with error: 0x%08X", retCode)
	}

	if servicesReturned == 0 {
		return nil, nil
	}

	// Calculate actual buffer size from response
	actualBufferSize := len(resp) - 4 - trailerSize
	if actualBufferSize <= 0 {
		return nil, fmt.Errorf("invalid buffer size: %d", actualBufferSize)
	}

	bufferData := resp[4 : 4+actualBufferSize]

	if Debug {
		fmt.Printf("[DEBUG] Buffer data: %d bytes (expected %d), parsing %d services\n",
			actualBufferSize, maxCount, servicesReturned)
	}

	if servicesReturned > 10000 {
		return nil, fmt.Errorf("invalid service count: %d", servicesReturned)
	}

	// The buffer contains ENUM_SERVICE_STATUSW structures:
	// Each entry is 36 bytes on wire:
	// - lpServiceName: 4 byte offset from start of buffer
	// - lpDisplayName: 4 byte offset from start of buffer
	// - ServiceStatus: 28 bytes (7 DWORDs)
	//
	// The offset values point to null-terminated UTF-16LE strings within the same buffer.

	var services []ServiceInfo
	entrySize := 36 // 4 + 4 + 28

	for i := uint32(0); i < servicesReturned; i++ {
		entryOffset := int(i) * entrySize
		if entryOffset+entrySize > len(bufferData) {
			if Debug {
				fmt.Printf("[DEBUG] Entry %d at offset %d exceeds buffer size %d\n", i, entryOffset, len(bufferData))
			}
			break
		}

		entry := bufferData[entryOffset:]

		// Read offsets - these are byte offsets from start of buffer
		serviceNameOffset := binary.LittleEndian.Uint32(entry[0:4])
		displayNameOffset := binary.LittleEndian.Uint32(entry[4:8])

		// Parse ServiceStatus (28 bytes starting at offset 8)
		status := ServiceStatus{
			ServiceType:      ServiceType(binary.LittleEndian.Uint32(entry[8:12])),
			CurrentState:     ServiceState(binary.LittleEndian.Uint32(entry[12:16])),
			ControlsAccepted: binary.LittleEndian.Uint32(entry[16:20]),
			Win32ExitCode:    binary.LittleEndian.Uint32(entry[20:24]),
			ServiceExitCode:  binary.LittleEndian.Uint32(entry[24:28]),
			CheckPoint:       binary.LittleEndian.Uint32(entry[28:32]),
			WaitHint:         binary.LittleEndian.Uint32(entry[32:36]),
		}

		// Read the string names from the buffer at their offsets
		serviceName := readUTF16StringFromBuffer(bufferData, serviceNameOffset)
		displayName := readUTF16StringFromBuffer(bufferData, displayNameOffset)

		if Debug && i < 3 {
			fmt.Printf("[DEBUG] Service %d: nameOffset=%d, dispOffset=%d, name=%q\n",
				i, serviceNameOffset, displayNameOffset, serviceName)
		}

		services = append(services, ServiceInfo{
			ServiceName: serviceName,
			DisplayName: displayName,
			Status:      status,
		})
	}

	return services, nil
}

// readUTF16StringFromBuffer reads a null-terminated UTF-16LE string from buffer at given offset
func readUTF16StringFromBuffer(buf []byte, offset uint32) string {
	if int(offset) >= len(buf) {
		return ""
	}

	data := buf[offset:]
	var chars []uint16

	for i := 0; i+1 < len(data); i += 2 {
		c := binary.LittleEndian.Uint16(data[i:])
		if c == 0 {
			break
		}
		chars = append(chars, c)
	}

	return string(utf16.Decode(chars))
}
