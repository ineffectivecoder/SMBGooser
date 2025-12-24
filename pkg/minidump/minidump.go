// Package minidump provides parsing for Windows minidump files
// to extract credentials from LSASS memory dumps.
package minidump

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Minidump file signature
const minidumpSignature = 0x504D444D // "MDMP"

// Stream types
const (
	UnusedStream         = 0
	ThreadListStream     = 3
	ModuleListStream     = 4
	MemoryListStream     = 5
	SystemInfoStream     = 7
	Memory64ListStream   = 9
	MemoryInfoListStream = 16
)

// Header represents the minidump file header
type Header struct {
	Signature          uint32
	Version            uint32
	NumberOfStreams    uint32
	StreamDirectoryRVA uint32
	Checksum           uint32
	TimeDateStamp      uint32
	Flags              uint64
}

// Directory entry for streams
type Directory struct {
	StreamType uint32
	DataSize   uint32
	RVA        uint32
}

// SystemInfo from the dump
type SystemInfo struct {
	ProcessorArchitecture uint16
	ProcessorLevel        uint16
	ProcessorRevision     uint16
	NumberOfProcessors    uint8
	ProductType           uint8
	MajorVersion          uint32
	MinorVersion          uint32
	BuildNumber           uint32
	PlatformId            uint32
	CSDVersionRva         uint32
}

// Module represents a loaded DLL
type Module struct {
	BaseOfImage uint64
	SizeOfImage uint32
	ModuleName  string
}

// Credential represents extracted credentials
type Credential struct {
	Username string
	Domain   string
	NTHash   string
	LMHash   string
	SHA1Hash string
	Password string // Plaintext if available (WDigest)
	CredType string // MSV1_0, Kerberos, WDigest, etc.
}

// KerberosTicket represents an extracted Kerberos ticket
type KerberosTicket struct {
	ServiceName string
	TargetName  string
	ClientName  string
	DomainName  string
	StartTime   string
	EndTime     string
	TicketData  []byte
	SessionKey  []byte
	KeyType     uint32
}

// MemoryRange represents a memory region with its virtual address
type MemoryRange struct {
	StartVA    uint64 // Virtual address start
	DataSize   uint64 // Size of the region
	FileOffset uint64 // Offset in file/Memory where this data starts
}

// Dump represents a parsed minidump file
type Dump struct {
	Header       Header
	SystemInfo   *SystemInfo
	Modules      []Module
	Memory       []byte        // Full memory for searching
	MemoryRanges []MemoryRange // Memory ranges with VA mapping
	MemoryBase   uint64        // File offset where memory data starts

	// Parsed credentials
	Credentials         []Credential
	Tickets             []KerberosTicket
	KerberosCredentials []KerberosCredential
	WdigestCredentials  []WdigestCredential
	DPAPIMasterKeys     []DPAPIMasterKey
}

// ReadVA reads bytes from a virtual address
func (d *Dump) ReadVA(va uint64, size int) []byte {
	for _, r := range d.MemoryRanges {
		if va >= r.StartVA && va < r.StartVA+r.DataSize {
			offset := va - r.StartVA + r.FileOffset - d.MemoryBase
			if int(offset)+size <= len(d.Memory) {
				result := make([]byte, size)
				copy(result, d.Memory[offset:int(offset)+size])
				return result
			}
		}
	}
	return nil
}

// VAToOffset converts a virtual address to a memory buffer offset
func (d *Dump) VAToOffset(va uint64) int64 {
	for _, r := range d.MemoryRanges {
		if va >= r.StartVA && va < r.StartVA+r.DataSize {
			return int64(va - r.StartVA + r.FileOffset - d.MemoryBase)
		}
	}
	return -1
}

// OffsetToVA converts an offset in d.Memory to a virtual address
func (d *Dump) OffsetToVA(offset int64) uint64 {
	// offset is relative to d.Memory start
	// We need to find which memory range contains this offset
	currentOffset := int64(0)
	for _, r := range d.MemoryRanges {
		rangeSize := int64(r.DataSize)
		rangeStart := int64(r.FileOffset - d.MemoryBase)
		if offset >= rangeStart && offset < rangeStart+rangeSize {
			// Found the range
			return r.StartVA + uint64(offset-rangeStart)
		}
		currentOffset += rangeSize
	}
	return 0
}

// GetModuleMemory returns the memory slice for a given module
// Returns the memory data and the base virtual address
func (d *Dump) GetModuleMemory(mod *Module) ([]byte, uint64) {
	if mod == nil {
		return nil, 0
	}

	// Find the memory range that contains this module
	for _, r := range d.MemoryRanges {
		if mod.BaseOfImage >= r.StartVA && mod.BaseOfImage < r.StartVA+r.DataSize {
			offset := d.VAToOffset(mod.BaseOfImage)
			if offset < 0 {
				return nil, 0
			}
			endOffset := int(offset) + int(mod.SizeOfImage)
			if endOffset > len(d.Memory) {
				endOffset = len(d.Memory)
			}
			return d.Memory[offset:endOffset], mod.BaseOfImage
		}
	}
	return nil, 0
}

// Parse parses a minidump file from raw bytes
func Parse(data []byte) (*Dump, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("file too small for minidump header")
	}

	r := bytes.NewReader(data)
	dump := &Dump{}

	// Read header
	if err := binary.Read(r, binary.LittleEndian, &dump.Header); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	if dump.Header.Signature != minidumpSignature {
		return nil, fmt.Errorf("invalid minidump signature: 0x%08X", dump.Header.Signature)
	}

	// Parse stream directory
	if err := dump.parseStreams(data); err != nil {
		return nil, fmt.Errorf("failed to parse streams: %w", err)
	}

	return dump, nil
}

// parseStreams parses the stream directory and relevant streams
func (d *Dump) parseStreams(data []byte) error {
	r := bytes.NewReader(data)

	// Seek to stream directory
	if _, err := r.Seek(int64(d.Header.StreamDirectoryRVA), io.SeekStart); err != nil {
		return err
	}

	for i := uint32(0); i < d.Header.NumberOfStreams; i++ {
		var dir Directory
		if err := binary.Read(r, binary.LittleEndian, &dir); err != nil {
			return err
		}

		// Save position and parse stream
		pos, _ := r.Seek(0, io.SeekCurrent)

		switch dir.StreamType {
		case SystemInfoStream:
			if err := d.parseSystemInfo(data, dir); err != nil {
				// Non-fatal
			}
		case ModuleListStream:
			if err := d.parseModules(data, dir); err != nil {
				// Non-fatal
			}
		case Memory64ListStream:
			if err := d.parseMemory64(data, dir); err != nil {
				// Non-fatal
			}
		}

		// Restore position
		r.Seek(pos, io.SeekStart)
	}

	return nil
}

// parseSystemInfo parses the system info stream
func (d *Dump) parseSystemInfo(data []byte, dir Directory) error {
	if int(dir.RVA)+56 > len(data) {
		return fmt.Errorf("system info stream out of bounds")
	}

	r := bytes.NewReader(data[dir.RVA:])
	d.SystemInfo = &SystemInfo{}
	return binary.Read(r, binary.LittleEndian, d.SystemInfo)
}

// parseModules parses the module list stream
func (d *Dump) parseModules(data []byte, dir Directory) error {
	if int(dir.RVA)+4 > len(data) {
		return fmt.Errorf("module list out of bounds")
	}

	r := bytes.NewReader(data[dir.RVA:])

	var count uint32
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
		return err
	}

	// MINIDUMP_MODULE is 108 bytes:
	// BaseOfImage: ULONG64 (8)
	// SizeOfImage: ULONG (4)
	// CheckSum: ULONG (4)
	// TimeDateStamp: ULONG (4)
	// ModuleNameRva: RVA (4)
	// VersionInfo: VS_FIXEDFILEINFO (52)
	// CvRecord: MINIDUMP_LOCATION_DESCRIPTOR (8)
	// MiscRecord: MINIDUMP_LOCATION_DESCRIPTOR (8)
	// Reserved0: ULONG64 (8)
	// Reserved1: ULONG64 (8)
	// Total: 8+4+4+4+4+52+8+8+8+8 = 108

	for i := uint32(0); i < count && i < 256; i++ {
		var baseAddr uint64
		var sizeOfImage uint32
		var checksum uint32
		var timeDateStamp uint32
		var moduleNameRva uint32

		binary.Read(r, binary.LittleEndian, &baseAddr)
		binary.Read(r, binary.LittleEndian, &sizeOfImage)
		binary.Read(r, binary.LittleEndian, &checksum)
		binary.Read(r, binary.LittleEndian, &timeDateStamp)
		binary.Read(r, binary.LittleEndian, &moduleNameRva)

		// Skip rest of structure: VersionInfo(52) + CvRecord(8) + MiscRecord(8) + Reserved0(8) + Reserved1(8) = 84 bytes
		r.Seek(84, io.SeekCurrent)

		// Read module name
		name := d.readString(data, moduleNameRva)

		d.Modules = append(d.Modules, Module{
			BaseOfImage: baseAddr,
			SizeOfImage: sizeOfImage,
			ModuleName:  name,
		})
	}

	return nil
}

// parseMemory64 parses the 64-bit memory list stream
func (d *Dump) parseMemory64(data []byte, dir Directory) error {
	if int(dir.RVA)+16 > len(data) {
		return fmt.Errorf("memory64 list out of bounds")
	}

	r := bytes.NewReader(data[dir.RVA:])

	var numberOfMemoryRanges uint64
	var baseRva uint64

	binary.Read(r, binary.LittleEndian, &numberOfMemoryRanges)
	binary.Read(r, binary.LittleEndian, &baseRva)

	d.MemoryBase = baseRva

	// Parse MINIDUMP_MEMORY_DESCRIPTOR64 entries
	// Each entry: StartOfMemoryRange (8 bytes) + DataSize (8 bytes)
	currentOffset := baseRva
	for i := uint64(0); i < numberOfMemoryRanges && i < 10000; i++ {
		var startVA uint64
		var dataSize uint64

		err := binary.Read(r, binary.LittleEndian, &startVA)
		if err != nil {
			break
		}
		err = binary.Read(r, binary.LittleEndian, &dataSize)
		if err != nil {
			break
		}

		d.MemoryRanges = append(d.MemoryRanges, MemoryRange{
			StartVA:    startVA,
			DataSize:   dataSize,
			FileOffset: currentOffset,
		})

		currentOffset += dataSize
	}

	// Store the full memory blob for searches
	if int(baseRva) < len(data) {
		d.Memory = data[baseRva:]
	}

	return nil
}

// readString reads a MINIDUMP_STRING at the given RVA
func (d *Dump) readString(data []byte, rva uint32) string {
	if int(rva)+4 > len(data) {
		return ""
	}

	length := binary.LittleEndian.Uint32(data[rva:])
	if length > 512 || int(rva)+4+int(length) > len(data) {
		return ""
	}

	// UTF-16LE string
	strData := data[rva+4 : rva+4+length]
	return decodeUTF16LE(strData)
}

// decodeUTF16LE decodes a UTF-16LE byte slice to a string
func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}

	var chars []rune
	for i := 0; i+1 < len(b); i += 2 {
		c := uint16(b[i]) | uint16(b[i+1])<<8
		if c == 0 {
			break
		}
		chars = append(chars, rune(c))
	}
	return string(chars)
}

// GetBuildVersion returns a formatted OS build string
func (d *Dump) GetBuildVersion() string {
	if d.SystemInfo == nil {
		return "Unknown"
	}
	return fmt.Sprintf("%d.%d.%d",
		d.SystemInfo.MajorVersion,
		d.SystemInfo.MinorVersion,
		d.SystemInfo.BuildNumber)
}

// FindModule finds a module by name (case-insensitive partial match)
func (d *Dump) FindModule(name string) *Module {
	nameLower := bytes.ToLower([]byte(name))
	for i := range d.Modules {
		if bytes.Contains(bytes.ToLower([]byte(d.Modules[i].ModuleName)), nameLower) {
			return &d.Modules[i]
		}
	}
	return nil
}
