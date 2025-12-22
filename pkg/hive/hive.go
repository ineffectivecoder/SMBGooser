// Package hive implements Windows registry hive format parsing
// for extracting boot keys and SAM hashes
package hive

import (
	"encoding/binary"
	"fmt"
)

// Hive represents a parsed Windows registry hive
type Hive struct {
	data     []byte
	rootCell int
}

// regfHeader is the registry file header (4096 bytes)
type regfHeader struct {
	Signature    [4]byte // "regf"
	Sequence1    uint32
	Sequence2    uint32
	LastModified uint64
	MajorVersion uint32
	MinorVersion uint32
	Type         uint32
	Format       uint32
	RootCellOff  uint32 // Offset to root cell
	HiveSize     uint32
	Cluster      uint32
	FileName     [64]uint16
}

// Cell types
const (
	cellKeyNode  = 0x6B6E // "nk"
	cellKeyValue = 0x6B76 // "vk"
	cellKeyList  = 0x666C // "lf"
	cellHashList = 0x686C // "lh"
	cellRIList   = 0x6972 // "ri"
)

// Parse parses a registry hive from raw bytes
func Parse(data []byte) (*Hive, error) {
	if len(data) < 4096 {
		return nil, fmt.Errorf("hive too small: %d bytes", len(data))
	}

	// Check signature
	if string(data[0:4]) != "regf" {
		return nil, fmt.Errorf("invalid hive signature: %s", string(data[0:4]))
	}

	rootCellOff := binary.LittleEndian.Uint32(data[36:40])
	rootCell := int(rootCellOff) + 4096

	return &Hive{
		data:     data,
		rootCell: rootCell,
	}, nil
}

// GetValue reads a registry value by path
func (h *Hive) GetValue(path, valueName string) ([]byte, error) {
	// Navigate to the key
	keyOffset, err := h.findKey(path)
	if err != nil {
		return nil, err
	}

	// Find the value
	return h.readValue(keyOffset, valueName)
}

// GetSubkeys returns subkey names for a path
func (h *Hive) GetSubkeys(path string) ([]string, error) {
	keyOffset, err := h.findKey(path)
	if err != nil {
		return nil, err
	}

	return h.listSubkeys(keyOffset)
}

// findKey navigates the hive to find a key by path
func (h *Hive) findKey(path string) (int, error) {
	if path == "" || path == "\\" {
		return h.rootCell, nil
	}

	// Parse path components
	parts := splitPath(path)
	currentOffset := h.rootCell

	for _, part := range parts {
		subkeys, err := h.listSubkeysWithOffsets(currentOffset)
		if err != nil {
			return 0, err
		}

		found := false
		for name, offset := range subkeys {
			if equalFold(name, part) {
				currentOffset = offset
				found = true
				break
			}
		}

		if !found {
			return 0, fmt.Errorf("key not found: %s", part)
		}
	}

	return currentOffset, nil
}

// readValue reads a value from a key
func (h *Hive) readValue(keyOffset int, valueName string) ([]byte, error) {
	// Read key node
	if keyOffset+80 > len(h.data) {
		return nil, fmt.Errorf("invalid key offset")
	}

	// Check signature
	sig := binary.LittleEndian.Uint16(h.data[keyOffset+4 : keyOffset+6])
	if sig != cellKeyNode {
		return nil, fmt.Errorf("not a key node")
	}

	// Key node layout:
	// 40-43: values count
	// 44-47: values list offset

	// Get values count (at offset 40)
	valuesCount := binary.LittleEndian.Uint32(h.data[keyOffset+40 : keyOffset+44])
	if valuesCount == 0 {
		return nil, fmt.Errorf("no values in key")
	}

	// Get values list offset (at offset 44)
	valuesListOff := binary.LittleEndian.Uint32(h.data[keyOffset+44 : keyOffset+48])
	if valuesListOff == 0xFFFFFFFF {
		return nil, fmt.Errorf("no values list")
	}

	valuesListAbs := int(valuesListOff) + 4096
	if valuesListAbs+4 > len(h.data) {
		return nil, fmt.Errorf("invalid values list offset")
	}

	// Iterate values
	for i := uint32(0); i < valuesCount; i++ {
		valueOff := binary.LittleEndian.Uint32(h.data[valuesListAbs+4+int(i)*4:])
		valueAbs := int(valueOff) + 4096

		if valueAbs+24 > len(h.data) {
			continue
		}

		// Check vk signature
		vkSig := binary.LittleEndian.Uint16(h.data[valueAbs+4 : valueAbs+6])
		if vkSig != cellKeyValue {
			continue
		}

		// Get value name
		nameLen := binary.LittleEndian.Uint16(h.data[valueAbs+6 : valueAbs+8])
		dataLen := binary.LittleEndian.Uint32(h.data[valueAbs+8 : valueAbs+12])
		dataOff := binary.LittleEndian.Uint32(h.data[valueAbs+12 : valueAbs+16])

		var vName string
		if nameLen > 0 && valueAbs+24+int(nameLen) <= len(h.data) {
			vName = string(h.data[valueAbs+24 : valueAbs+24+int(nameLen)])
		}

		if !equalFold(vName, valueName) && !(valueName == "" && nameLen == 0) {
			continue
		}

		// Read data
		if dataLen&0x80000000 != 0 {
			// Data is stored inline
			dataLen &= 0x7FFFFFFF
			if dataLen <= 4 {
				return h.data[valueAbs+12 : valueAbs+12+int(dataLen)], nil
			}
		}

		dataAbs := int(dataOff) + 4096
		if dataAbs+4+int(dataLen) > len(h.data) {
			return nil, fmt.Errorf("invalid data offset")
		}

		return h.data[dataAbs+4 : dataAbs+4+int(dataLen)], nil
	}

	return nil, fmt.Errorf("value not found: %s", valueName)
}

// listSubkeys returns subkey names for a key
func (h *Hive) listSubkeys(keyOffset int) ([]string, error) {
	subkeys, err := h.listSubkeysWithOffsets(keyOffset)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(subkeys))
	for name := range subkeys {
		names = append(names, name)
	}
	return names, nil
}

// listSubkeysWithOffsets returns subkey names and offsets
func (h *Hive) listSubkeysWithOffsets(keyOffset int) (map[string]int, error) {
	result := make(map[string]int)

	if keyOffset+80 > len(h.data) {
		return result, nil
	}

	// Check signature (at offset 4 from cell start, after 4-byte cell size)
	sig := binary.LittleEndian.Uint16(h.data[keyOffset+4 : keyOffset+6])
	if sig != cellKeyNode {
		return result, nil
	}

	// Key node layout (offsets from cell start):
	// 0-3: cell size
	// 4-5: "nk" signature
	// 6-7: flags
	// 8-15: timestamp
	// 16-19: access bits
	// 20-23: parent key offset
	// 24-27: stable subkeys count
	// 28-31: volatile subkeys count
	// 32-35: stable subkeys list offset
	// 36-39: volatile subkeys list offset
	// 40-43: values count
	// 44-47: values list offset
	// ...

	// Get subkeys count (stable) - at offset 24
	subkeysCount := binary.LittleEndian.Uint32(h.data[keyOffset+24 : keyOffset+28])
	if subkeysCount == 0 {
		return result, nil
	}

	// Get subkeys list offset (stable) - at offset 32
	subkeysListOff := binary.LittleEndian.Uint32(h.data[keyOffset+32 : keyOffset+36])
	if subkeysListOff == 0xFFFFFFFF {
		return result, nil
	}

	subkeysListAbs := int(subkeysListOff) + 4096
	if subkeysListAbs+4 > len(h.data) {
		return result, nil
	}

	// Parse list based on type
	listSig := binary.LittleEndian.Uint16(h.data[subkeysListAbs+4 : subkeysListAbs+6])

	switch listSig {
	case cellKeyList, cellHashList:
		// lf/lh list
		count := binary.LittleEndian.Uint16(h.data[subkeysListAbs+6 : subkeysListAbs+8])
		for i := uint16(0); i < count; i++ {
			offset := subkeysListAbs + 8 + int(i)*8
			if offset+4 > len(h.data) {
				break
			}
			subkeyOff := binary.LittleEndian.Uint32(h.data[offset:])
			subkeyAbs := int(subkeyOff) + 4096

			name := h.getKeyName(subkeyAbs)
			if name != "" {
				result[name] = subkeyAbs
			}
		}

	case cellRIList:
		// ri list - contains offsets to other lists
		count := binary.LittleEndian.Uint16(h.data[subkeysListAbs+6 : subkeysListAbs+8])
		for i := uint16(0); i < count; i++ {
			offset := subkeysListAbs + 8 + int(i)*4
			if offset+4 > len(h.data) {
				break
			}
			listOff := binary.LittleEndian.Uint32(h.data[offset:])
			listAbs := int(listOff) + 4096

			// Recurse into sublist
			subResult := h.parseSubkeyList(listAbs)
			for k, v := range subResult {
				result[k] = v
			}
		}
	}

	return result, nil
}

func (h *Hive) parseSubkeyList(listAbs int) map[string]int {
	result := make(map[string]int)

	if listAbs+8 > len(h.data) {
		return result
	}

	listSig := binary.LittleEndian.Uint16(h.data[listAbs+4 : listAbs+6])
	count := binary.LittleEndian.Uint16(h.data[listAbs+6 : listAbs+8])

	if listSig == cellKeyList || listSig == cellHashList {
		for i := uint16(0); i < count; i++ {
			offset := listAbs + 8 + int(i)*8
			if offset+4 > len(h.data) {
				break
			}
			subkeyOff := binary.LittleEndian.Uint32(h.data[offset:])
			subkeyAbs := int(subkeyOff) + 4096

			name := h.getKeyName(subkeyAbs)
			if name != "" {
				result[name] = subkeyAbs
			}
		}
	}

	return result
}

func (h *Hive) getKeyName(keyOffset int) string {
	if keyOffset+80 > len(h.data) {
		return ""
	}

	sig := binary.LittleEndian.Uint16(h.data[keyOffset+4 : keyOffset+6])
	if sig != cellKeyNode {
		return ""
	}

	// Key node layout:
	// ...
	// 76-77: name length
	// 78-79: class name length
	// 80+: key name
	nameLen := binary.LittleEndian.Uint16(h.data[keyOffset+76 : keyOffset+78])
	if nameLen == 0 || keyOffset+80+int(nameLen) > len(h.data) {
		return ""
	}

	return string(h.data[keyOffset+80 : keyOffset+80+int(nameLen)])
}

// Helper functions
func splitPath(path string) []string {
	var parts []string
	current := ""
	for _, c := range path {
		if c == '\\' || c == '/' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
