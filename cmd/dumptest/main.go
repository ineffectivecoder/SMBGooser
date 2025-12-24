package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

// Minidump constants
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: dumptest <minidump.dmp>")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("File size: %d bytes\n\n", len(data))

	// Parse header
	r := bytes.NewReader(data)
	var header Header
	binary.Read(r, binary.LittleEndian, &header)

	fmt.Printf("=== HEADER ===\n")
	fmt.Printf("Signature: 0x%08X (%s)\n", header.Signature, string(data[0:4]))
	fmt.Printf("Version: 0x%08X\n", header.Version)
	fmt.Printf("NumberOfStreams: %d\n", header.NumberOfStreams)
	fmt.Printf("StreamDirectoryRVA: 0x%08X\n", header.StreamDirectoryRVA)
	fmt.Printf("Flags: 0x%016X\n\n", header.Flags)

	// Parse stream directory
	r.Seek(int64(header.StreamDirectoryRVA), io.SeekStart)

	fmt.Printf("=== STREAMS ===\n")
	for i := uint32(0); i < header.NumberOfStreams; i++ {
		var dir Directory
		binary.Read(r, binary.LittleEndian, &dir)

		typeName := streamTypeName(dir.StreamType)
		fmt.Printf("[%02d] Type: %2d (%s), Size: %d, RVA: 0x%08X\n",
			i, dir.StreamType, typeName, dir.DataSize, dir.RVA)
	}
	fmt.Println()

	// Parse SystemInfo
	parseSystemInfo(data, header)

	// Parse Modules
	parseModules(data, header)
}

func streamTypeName(t uint32) string {
	names := map[uint32]string{
		0:  "Unused",
		3:  "ThreadList",
		4:  "ModuleList",
		5:  "MemoryList",
		7:  "SystemInfo",
		9:  "Memory64List",
		16: "MemoryInfoList",
		15: "MiscInfo",
		21: "SystemMemoryInfo",
		22: "ProcessVmCounters",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", t)
}

func parseSystemInfo(data []byte, header Header) {
	r := bytes.NewReader(data)
	r.Seek(int64(header.StreamDirectoryRVA), io.SeekStart)

	for i := uint32(0); i < header.NumberOfStreams; i++ {
		var dir Directory
		binary.Read(r, binary.LittleEndian, &dir)

		if dir.StreamType == SystemInfoStream {
			fmt.Printf("=== SYSTEM INFO (at 0x%08X) ===\n", dir.RVA)

			// MINIDUMP_SYSTEM_INFO structure
			sr := bytes.NewReader(data[dir.RVA:])

			var procArch, procLevel, procRev uint16
			var numProc, prodType uint8
			var majorVer, minorVer, buildNum, platformId, csdRva uint32

			binary.Read(sr, binary.LittleEndian, &procArch)
			binary.Read(sr, binary.LittleEndian, &procLevel)
			binary.Read(sr, binary.LittleEndian, &procRev)
			binary.Read(sr, binary.LittleEndian, &numProc)
			binary.Read(sr, binary.LittleEndian, &prodType)
			binary.Read(sr, binary.LittleEndian, &majorVer)
			binary.Read(sr, binary.LittleEndian, &minorVer)
			binary.Read(sr, binary.LittleEndian, &buildNum)
			binary.Read(sr, binary.LittleEndian, &platformId)
			binary.Read(sr, binary.LittleEndian, &csdRva)

			fmt.Printf("ProcessorArchitecture: %d\n", procArch)
			fmt.Printf("Processors: %d\n", numProc)
			fmt.Printf("OS Version: %d.%d.%d\n", majorVer, minorVer, buildNum)
			fmt.Printf("CSDVersionRva: 0x%08X\n", csdRva)

			// Read CSD (Service Pack) string
			if csdRva > 0 && int(csdRva)+4 < len(data) {
				strLen := binary.LittleEndian.Uint32(data[csdRva:])
				if strLen > 0 && strLen < 256 && int(csdRva)+4+int(strLen) <= len(data) {
					strData := data[csdRva+4 : csdRva+4+strLen]
					csd := decodeUTF16LE(strData)
					fmt.Printf("CSDVersion: %s\n", csd)
				}
			}
			fmt.Println()
			break
		}
	}
}

func parseModules(data []byte, header Header) {
	r := bytes.NewReader(data)
	r.Seek(int64(header.StreamDirectoryRVA), io.SeekStart)

	for i := uint32(0); i < header.NumberOfStreams; i++ {
		var dir Directory
		binary.Read(r, binary.LittleEndian, &dir)

		if dir.StreamType == ModuleListStream {
			fmt.Printf("=== MODULES (at 0x%08X, size %d) ===\n", dir.RVA, dir.DataSize)

			mr := bytes.NewReader(data[dir.RVA:])

			var count uint32
			binary.Read(mr, binary.LittleEndian, &count)
			fmt.Printf("Module count: %d\n\n", count)

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

			for j := uint32(0); j < count && j < 150; j++ {
				var baseAddr uint64
				var sizeOfImage, checksum, timeDateStamp, moduleNameRva uint32

				binary.Read(mr, binary.LittleEndian, &baseAddr)
				binary.Read(mr, binary.LittleEndian, &sizeOfImage)
				binary.Read(mr, binary.LittleEndian, &checksum)
				binary.Read(mr, binary.LittleEndian, &timeDateStamp)
				binary.Read(mr, binary.LittleEndian, &moduleNameRva)

				// Skip rest of structure: VersionInfo(52) + CvRecord(8) + MiscRecord(8) + Reserved0(8) + Reserved1(8) = 84 bytes
				mr.Seek(84, io.SeekCurrent)

				// Read module name
				name := readString(data, moduleNameRva)

				// Only show interesting modules
				lowerName := strings.ToLower(name)
				if strings.Contains(lowerName, "lsasrv") ||
					strings.Contains(lowerName, "msv1_0") ||
					strings.Contains(lowerName, "wdigest") ||
					strings.Contains(lowerName, "kerberos") ||
					strings.Contains(lowerName, "lsass") ||
					strings.Contains(lowerName, "ntdll") ||
					j < 5 {
					fmt.Printf("[%03d] 0x%016X  %8d KB  %s\n", j, baseAddr, sizeOfImage/1024, name)
				}
			}
			fmt.Println()
			break
		}
	}
}

func readString(data []byte, rva uint32) string {
	if int(rva)+4 > len(data) {
		return ""
	}
	length := binary.LittleEndian.Uint32(data[rva:])
	if length > 512 || int(rva)+4+int(length) > len(data) {
		return ""
	}
	strData := data[rva+4 : rva+4+length]
	return decodeUTF16LE(strData)
}

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
