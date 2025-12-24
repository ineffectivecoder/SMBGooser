package minidump

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

// DPAPIMasterKey represents a DPAPI master key
type DPAPIMasterKey struct {
	GUID      string
	MasterKey string
	SHA1      string
	LUID      uint64
}

// DPAPIPattern contains signature and offsets for finding DPAPI credentials
type DPAPIPattern struct {
	Signature        []byte
	FirstEntryOffset int
	BuildNumber      uint32
}

// GetDPAPIPattern returns the pattern for the given Windows build number
// Patterns taken from pypykatz dpapi/templates.py
func GetDPAPIPattern(buildNumber uint32) *DPAPIPattern {
	// Windows 10 1607+ (Build 14393+)
	if buildNumber >= 14393 {
		return &DPAPIPattern{
			Signature:        []byte{0x48, 0x89, 0x4f, 0x08, 0x48, 0x89, 0x78, 0x08},
			FirstEntryOffset: 11,
			BuildNumber:      buildNumber,
		}
	}
	// Windows 10 1507-1511 (Build 10240-14392)
	if buildNumber >= 10240 {
		return &DPAPIPattern{
			Signature:        []byte{0x48, 0x89, 0x4e, 0x08, 0x48, 0x39, 0x48, 0x08},
			FirstEntryOffset: -7,
			BuildNumber:      buildNumber,
		}
	}
	// Windows 8.1 (Build 9600)
	if buildNumber >= 9600 {
		return &DPAPIPattern{
			Signature:        []byte{0x08, 0x48, 0x39, 0x48, 0x08, 0x0f, 0x85},
			FirstEntryOffset: -10,
			BuildNumber:      buildNumber,
		}
	}
	// Windows 8 (Build 9200)
	if buildNumber >= 9200 {
		return &DPAPIPattern{
			Signature:        []byte{0x4c, 0x89, 0x1f, 0x48, 0x89, 0x47, 0x08, 0x49, 0x39, 0x43, 0x08, 0x0f, 0x85},
			FirstEntryOffset: -4,
			BuildNumber:      buildNumber,
		}
	}
	// Windows 7 (Build 7600-7601)
	if buildNumber >= 7600 {
		return &DPAPIPattern{
			Signature:        []byte{0x33, 0xc0, 0xeb, 0x20, 0x48, 0x8d, 0x05},
			FirstEntryOffset: 7,
			BuildNumber:      buildNumber,
		}
	}
	return nil
}

// FindDPAPICredentials searches for DPAPI master keys in the dump
func (d *Dump) FindDPAPICredentials(keys *LSAKeys) ([]DPAPIMasterKey, error) {
	if keys == nil {
		return nil, nil
	}

	pattern := GetDPAPIPattern(d.SystemInfo.BuildNumber)
	if pattern == nil {
		return nil, fmt.Errorf("unsupported build for DPAPI: %d", d.SystemInfo.BuildNumber)
	}

	// Find dpapisrv.dll or lsasrv.dll (DPAPI keys can be in lsasrv.dll)
	var dpapiMem []byte
	var dpapiBase uint64

	dpapiDll := d.FindModule("dpapisrv.dll")
	if dpapiDll != nil {
		dpapiMem, dpapiBase = d.GetModuleMemory(dpapiDll)
	}

	if dpapiMem == nil {
		// Try lsasrv.dll as fallback
		lsasrvDll := d.FindModule("lsasrv.dll")
		if lsasrvDll != nil {
			dpapiMem, dpapiBase = d.GetModuleMemory(lsasrvDll)
		}
	}

	if dpapiMem == nil {
		return nil, fmt.Errorf("dpapisrv.dll/lsasrv.dll not found")
	}

	// Search for signature
	sigOffset := bytes.Index(dpapiMem, pattern.Signature)
	if sigOffset < 0 {
		return nil, fmt.Errorf("DPAPI signature not found")
	}

	// Read RIP-relative offset
	ripOffset := sigOffset + pattern.FirstEntryOffset
	if ripOffset < 0 || ripOffset+4 > len(dpapiMem) {
		return nil, fmt.Errorf("invalid RIP offset for DPAPI")
	}

	relOffset := int32(binary.LittleEndian.Uint32(dpapiMem[ripOffset:]))
	firstEntryVA := dpapiBase + uint64(sigOffset) + uint64(pattern.FirstEntryOffset) + 4 + uint64(relOffset)

	// Read pointer to first entry
	firstEntryOffset := d.VAToOffset(firstEntryVA)
	if firstEntryOffset < 0 || int(firstEntryOffset)+8 > len(d.Memory) {
		return nil, fmt.Errorf("invalid first DPAPI entry offset")
	}

	firstKeyVA := binary.LittleEndian.Uint64(d.Memory[firstEntryOffset:])
	if firstKeyVA == 0 {
		return nil, nil
	}

	var masterKeys []DPAPIMasterKey
	visited := make(map[uint64]bool)
	currentVA := firstKeyVA

	// Walk the linked list of master key cache entries
	for i := 0; i < 256 && currentVA != 0; i++ {
		if visited[currentVA] {
			break
		}
		visited[currentVA] = true

		mk := d.parseDPAPIEntry(currentVA, keys)
		if mk != nil && mk.MasterKey != "" {
			masterKeys = append(masterKeys, *mk)
		}

		// Get next entry
		entryOffset := d.VAToOffset(currentVA)
		if entryOffset < 0 || int(entryOffset)+8 > len(d.Memory) {
			break
		}
		currentVA = binary.LittleEndian.Uint64(d.Memory[entryOffset:])
		if currentVA == firstKeyVA {
			break
		}
	}

	return masterKeys, nil
}

// parseDPAPIEntry parses a KIWI_MASTERKEY_CACHE_ENTRY structure
func (d *Dump) parseDPAPIEntry(entryVA uint64, keys *LSAKeys) *DPAPIMasterKey {
	entryOffset := d.VAToOffset(entryVA)
	if entryOffset < 0 || int(entryOffset)+0x100 > len(d.Memory) {
		return nil
	}

	data := d.Memory[entryOffset:]

	// KIWI_MASTERKEY_CACHE_ENTRY structure (x64):
	// 0x00: Flink (8)
	// 0x08: Blink (8)
	// 0x10: LogonId (LUID, 8)
	// 0x18: KeyUid (GUID, 16)
	// 0x28: insertTime (FILETIME, 8)
	// 0x30: keySize (4)
	// 0x34: key[] (variable)

	mk := &DPAPIMasterKey{}
	mk.LUID = binary.LittleEndian.Uint64(data[0x10:])

	// Parse GUID
	mk.GUID = formatGUID(data[0x18:0x28])

	// Read key size and encrypted key
	keySize := binary.LittleEndian.Uint32(data[0x30:])
	if keySize == 0 || keySize > 256 {
		return nil
	}

	// The key data starts at offset 0x34
	if int(entryOffset)+0x34+int(keySize) > len(d.Memory) {
		return nil
	}

	encKey := data[0x34 : 0x34+keySize]
	decKey := d.decryptKerberosBlob(encKey, keys)
	if decKey != nil && len(decKey) >= 64 {
		// The master key is the first 64 bytes
		masterKeyBytes := decKey[:64]
		mk.MasterKey = bytesToHex(masterKeyBytes)
		// SHA1 is computed from the master key bytes
		sha1Hash := sha1.Sum(masterKeyBytes)
		mk.SHA1 = bytesToHex(sha1Hash[:])
	}

	return mk
}

// formatGUID formats a GUID from binary data
func formatGUID(data []byte) string {
	if len(data) < 16 {
		return ""
	}
	// GUID format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
	// Data1 (4 bytes, little-endian), Data2 (2 bytes, LE), Data3 (2 bytes, LE), Data4 (8 bytes)
	data1 := binary.LittleEndian.Uint32(data[0:4])
	data2 := binary.LittleEndian.Uint16(data[4:6])
	data3 := binary.LittleEndian.Uint16(data[6:8])
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		data1, data2, data3,
		data[8], data[9],
		data[10], data[11], data[12], data[13], data[14], data[15])
}

// FormatDPAPIMasterKey formats a DPAPI master key for display
func FormatDPAPIMasterKey(mk DPAPIMasterKey) string {
	result := fmt.Sprintf("LUID: %d | GUID: %s", mk.LUID, mk.GUID)
	if mk.MasterKey != "" {
		result += fmt.Sprintf(" | MasterKey: %s", mk.MasterKey)
	}
	if mk.SHA1 != "" {
		result += fmt.Sprintf(" | SHA1: %s", mk.SHA1)
	}
	return result
}
