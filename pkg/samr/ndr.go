package samr

import (
	"encoding/binary"
	"unicode/utf16"
)

// NDR encoding functions for SAMR RPC calls
// Based on MS-RPCE and Impacket's implementation

// Pointer referent IDs - increment for each unique pointer in a request
var nextReferentID uint32 = 0x00020000

func nextPointer() uint32 {
	id := nextReferentID
	nextReferentID += 4
	return id
}

func resetPointers() {
	nextReferentID = 0x00020000
}

// encodeConnect encodes SamrConnect request (opnum 0)
// Matches Impacket's exact format:
// - ReferentID (4 bytes) - non-zero pointer reference
// - ServerName data (4 bytes) - 4 zero bytes
// - DesiredAccess (4 bytes)
func encodeConnect() []byte {
	resetPointers()
	stub := make([]byte, 0, 12)

	// ServerName - PSAMPR_SERVER_NAME2 (pointer with referent)
	// ReferentID - random non-zero value (Impacket uses 0x3052)
	stub = appendUint32(stub, 0x00003052)
	// ServerName data - 4 bytes (referent data for '4s=b""')
	stub = appendUint32(stub, 0)

	// DesiredAccess - MAXIMUM_ALLOWED = 0x02000000
	stub = appendUint32(stub, 0x02000000)

	return stub
}

// encodeLookupDomain encodes SamrLookupDomainInSamServer request (opnum 5)
// NTSTATUS SamrLookupDomainInSamServer(
//
//	[in] SAMPR_HANDLE ServerHandle,
//	[in] RPC_UNICODE_STRING* Name,
//	[out] PRPC_SID* DomainId
//
// );
func encodeLookupDomain(serverHandle Handle, domainName string) []byte {
	resetPointers()
	stub := make([]byte, 0, 128)

	// ServerHandle (20 bytes context handle)
	stub = append(stub, serverHandle[:]...)

	// Name (RPC_UNICODE_STRING) - embedded string, not pointer
	stub = append(stub, encodeRpcUnicodeStringInline(domainName)...)

	return stub
}

// encodeOpenDomain encodes SamrOpenDomain request (opnum 7)
// NTSTATUS SamrOpenDomain(
//
//	[in] SAMPR_HANDLE ServerHandle,
//	[in] ACCESS_MASK DesiredAccess,
//	[in] PRPC_SID DomainId,
//	[out] SAMPR_HANDLE* DomainHandle
//
// );
func encodeOpenDomain(serverHandle Handle, domainSID []byte) []byte {
	resetPointers()
	stub := make([]byte, 0, 64)

	// ServerHandle (20 bytes)
	stub = append(stub, serverHandle[:]...)

	// DesiredAccess - MAXIMUM_ALLOWED = 0x02000000
	stub = appendUint32(stub, 0x02000000)

	// DomainId (RPC_SID - conformant structure)
	stub = append(stub, encodeRpcSid(domainSID)...)

	return stub
}

// encodeEnumerateUsers encodes SamrEnumerateUsersInDomain request (opnum 13)
func encodeEnumerateUsers(domainHandle Handle) []byte {
	resetPointers()
	stub := make([]byte, 0, 48)

	// DomainHandle (20 bytes)
	stub = append(stub, domainHandle[:]...)

	// EnumerationContext (start from 0)
	stub = appendUint32(stub, 0)

	// UserAccountControl (0 = all users)
	stub = appendUint32(stub, 0)

	// PreferedMaximumLength
	stub = appendUint32(stub, 65536)

	return stub
}

// encodeEnumerateGroups encodes SamrEnumerateGroupsInDomain request
func encodeEnumerateGroups(domainHandle Handle) []byte {
	resetPointers()
	stub := make([]byte, 0, 48)

	// DomainHandle
	stub = append(stub, domainHandle[:]...)

	// EnumerationContext
	stub = appendUint32(stub, 0)

	// PreferedMaximumLength
	stub = appendUint32(stub, 65536)

	return stub
}

// encodeRpcUnicodeStringInline encodes RPC_UNICODE_STRING matching Impacket's format exactly
// Impacket's format for "TEST" (48 bytes total stub):
//
//	08 00             - Length (8 bytes = 4 chars * 2)
//	08 00             - MaximumLength (same as Length)
//	xx xx 00 00       - ReferentID
//	04 00 00 00       - MaxCount (4 chars)
//	00 00 00 00       - Offset (0)
//	04 00 00 00       - ActualCount (4 chars)
//	54 00 45 00 53 00 54 00 - "TEST" in UTF-16LE (no null!)
func encodeRpcUnicodeStringInline(s string) []byte {
	// Convert to UTF-16LE
	runes := utf16.Encode([]rune(s))
	charCount := uint32(len(runes))
	byteLen := uint16(charCount * 2) // Length = chars * 2 (no null!)

	buf := make([]byte, 0, 20+int(byteLen))

	// RPC_UNICODE_STRING structure (embedded, not top-level)
	buf = appendUint16(buf, byteLen) // Length (bytes)
	buf = appendUint16(buf, byteLen) // MaximumLength (same as Length!)

	// Buffer pointer - ReferentID (use a random-looking value like Impacket)
	buf = appendUint32(buf, 0x0000878d)

	// Conformant varying array header
	buf = appendUint32(buf, charCount) // MaxCount
	buf = appendUint32(buf, 0)         // Offset
	buf = appendUint32(buf, charCount) // ActualCount

	// String data in UTF-16LE (no null terminator!)
	for _, c := range runes {
		buf = append(buf, byte(c), byte(c>>8))
	}

	// Pad to 4-byte boundary if needed
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}

	return buf
}

// encodeRpcSid encodes an RPC_SID from raw SID bytes
// RPC_SID structure (conformant):
//
//	UCHAR Revision;
//	UCHAR SubAuthorityCount;
//	RPC_SID_IDENTIFIER_AUTHORITY IdentifierAuthority;  // 6 bytes
//	[size_is(SubAuthorityCount)] ULONG SubAuthority[];
//
// The conformant array requires a MaxCount at the start!
func encodeRpcSid(sidBytes []byte) []byte {
	if len(sidBytes) < 8 {
		// Invalid SID, return empty
		return make([]byte, 0)
	}

	revision := sidBytes[0]
	subAuthCount := sidBytes[1]
	identAuth := sidBytes[2:8] // 6 bytes

	buf := make([]byte, 0, 12+4*int(subAuthCount))

	// MaxCount for conformant array (before the struct!)
	buf = appendUint32(buf, uint32(subAuthCount))

	// Revision (1 byte, padded to 4)
	buf = append(buf, revision)
	// SubAuthorityCount (1 byte)
	buf = append(buf, subAuthCount)

	// IdentifierAuthority (6 bytes)
	buf = append(buf, identAuth...)

	// SubAuthority array (each is 4 bytes, already little-endian in sidBytes)
	subAuthStart := 8
	for i := 0; i < int(subAuthCount); i++ {
		if subAuthStart+4 <= len(sidBytes) {
			buf = append(buf, sidBytes[subAuthStart:subAuthStart+4]...)
			subAuthStart += 4
		}
	}

	return buf
}

// parseEnumerateUsersResponse parses SamrEnumerateUsersInDomain response
func parseEnumerateUsersResponse(resp []byte) ([]UserInfo, error) {
	var users []UserInfo

	if len(resp) < 20 {
		return users, nil
	}

	// Check return code at end
	retCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retCode != 0 && retCode != 0x105 { // STATUS_MORE_ENTRIES
		return users, nil
	}

	// Response format:
	// DWORD EnumerationContext
	// PSAMPR_ENUMERATION_BUFFER Buffer (pointer)
	// DWORD CountReturned
	// NTSTATUS Return

	offset := 0

	// EnumerationContext
	if offset+4 > len(resp) {
		return users, nil
	}
	offset += 4

	// Buffer pointer
	if offset+4 > len(resp) {
		return users, nil
	}
	bufferPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if bufferPtr == 0 {
		return users, nil
	}

	// CountReturned
	if offset+4 > len(resp) {
		return users, nil
	}
	countReturned := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if countReturned == 0 {
		return users, nil
	}

	// SAMPR_ENUMERATION_BUFFER:
	//   DWORD EntriesRead
	//   [size_is(EntriesRead)] PSAMPR_RID_ENUMERATION Buffer

	// EntriesRead (in referred data)
	if offset+4 > len(resp) {
		return users, nil
	}
	entriesRead := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if entriesRead == 0 {
		return users, nil
	}

	// Buffer array pointer
	if offset+4 > len(resp) {
		return users, nil
	}
	offset += 4

	// MaxCount of array
	if offset+4 > len(resp) {
		return users, nil
	}
	offset += 4

	// === FIRST PASS: Read RIDs and string headers ===
	type entryHeader struct {
		RID       uint32
		Length    uint16
		MaxLength uint16
		StrPtr    uint32 // pointer to string data (non-zero if present)
	}

	headers := make([]entryHeader, 0, entriesRead)
	for i := uint32(0); i < entriesRead && offset+12 <= len(resp)-4; i++ {
		rid := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		length := binary.LittleEndian.Uint16(resp[offset:])
		offset += 2

		maxLen := binary.LittleEndian.Uint16(resp[offset:])
		offset += 2

		strPtr := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		headers = append(headers, entryHeader{
			RID:       rid,
			Length:    length,
			MaxLength: maxLen,
			StrPtr:    strPtr,
		})
	}

	// === SECOND PASS: Read string data ===
	for _, h := range headers {
		user := UserInfo{RID: h.RID}

		if h.StrPtr != 0 && h.Length > 0 {
			// MaxCount
			if offset+4 > len(resp)-4 {
				break
			}
			offset += 4

			// Offset
			if offset+4 > len(resp)-4 {
				break
			}
			offset += 4

			// ActualCount
			if offset+4 > len(resp)-4 {
				break
			}
			actualCount := binary.LittleEndian.Uint32(resp[offset:])
			offset += 4

			// Read string bytes (UTF-16LE)
			strBytes := int(actualCount) * 2
			if offset+strBytes > len(resp)-4 {
				strBytes = len(resp) - 4 - offset
			}

			if strBytes > 0 && offset+strBytes <= len(resp) {
				name := decodeUTF16LE(resp[offset : offset+strBytes])
				user.Name = name
				offset += strBytes

				// Align to 4 bytes
				for offset%4 != 0 && offset < len(resp) {
					offset++
				}
			}
		}

		users = append(users, user)
	}

	return users, nil
}

// parseLookupDomainResponse parses SamrLookupDomainInSamServer response
func parseLookupDomainResponse(resp []byte) ([]byte, error) {
	if len(resp) < 12 {
		return nil, nil
	}

	// Response: PRPC_SID DomainId, NTSTATUS Return
	// Check return code
	retCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retCode != 0 {
		return nil, nil
	}

	// DomainId pointer
	if binary.LittleEndian.Uint32(resp[0:4]) == 0 {
		return nil, nil // NULL pointer
	}

	// MaxCount (conformant array size)
	offset := 4
	if offset+4 > len(resp)-4 {
		return nil, nil
	}
	subAuthCount := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// Build SID bytes
	if offset+8+int(subAuthCount)*4 > len(resp)-4 {
		// Try smaller estimate
		subAuthCount = 0
	}

	// Revision
	revision := resp[offset]
	offset++

	// SubAuthorityCount
	actualCount := resp[offset]
	offset++

	if actualCount > 0 {
		subAuthCount = uint32(actualCount)
	}

	// IdentifierAuthority (6 bytes)
	if offset+6 > len(resp)-4 {
		return nil, nil
	}
	identAuth := resp[offset : offset+6]
	offset += 6

	// Build SID
	sid := make([]byte, 8+int(subAuthCount)*4)
	sid[0] = revision
	sid[1] = byte(subAuthCount)
	copy(sid[2:8], identAuth)

	for i := uint32(0); i < subAuthCount && offset+4 <= len(resp)-4; i++ {
		copy(sid[8+i*4:8+i*4+4], resp[offset:offset+4])
		offset += 4
	}

	return sid, nil
}

func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	// Decode UTF-16LE
	u16 := make([]uint16, len(data)/2)
	for i := 0; i < len(data)/2; i++ {
		u16[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	// Remove null terminators
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}

// parseEnumerateGroupsResponse parses SamrEnumerateGroupsInDomain response
func parseEnumerateGroupsResponse(resp []byte) ([]GroupInfo, error) {
	var groups []GroupInfo

	if len(resp) < 20 {
		return groups, nil
	}

	// Similar structure to users, but returns GroupInfo
	retCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retCode != 0 && retCode != 0x105 {
		return groups, nil
	}

	offset := 0

	// EnumerationContext
	if offset+4 > len(resp) {
		return groups, nil
	}
	offset += 4

	// Buffer pointer
	if offset+4 > len(resp) {
		return groups, nil
	}
	bufferPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if bufferPtr == 0 {
		return groups, nil
	}

	// CountReturned
	if offset+4 > len(resp) {
		return groups, nil
	}
	countReturned := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if countReturned == 0 {
		return groups, nil
	}

	// EntriesRead
	if offset+4 > len(resp) {
		return groups, nil
	}
	entriesRead := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if entriesRead == 0 {
		return groups, nil
	}

	// Skip array pointer and maxcount
	offset += 8

	// Parse entries
	for i := uint32(0); i < entriesRead && offset+12 <= len(resp)-4; i++ {
		rid := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		// Skip RPC_UNICODE_STRING header (8 bytes)
		offset += 8

		groups = append(groups, GroupInfo{
			RID:  rid,
			Name: "",
		})
	}

	return groups, nil
}

func appendUint32(buf []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return append(buf, b...)
}

func appendUint16(buf []byte, v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return append(buf, b...)
}
