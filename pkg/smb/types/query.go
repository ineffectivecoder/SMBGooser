package types

import (
	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// QueryDirectoryRequest represents an SMB2 QUERY_DIRECTORY request
type QueryDirectoryRequest struct {
	StructureSize        uint16 // 33
	FileInformationClass uint8
	Flags                uint8
	FileIndex            uint32
	FileID               FileID
	FileNameOffset       uint16
	FileNameLength       uint16
	OutputBufferLength   uint32
	FileName             []byte // Search pattern (UTF-16LE)
}

// FileInformationClass values for QUERY_DIRECTORY
const (
	FileDirectoryInformation       uint8 = 0x01
	FileFullDirectoryInformation   uint8 = 0x02
	FileBothDirectoryInformation   uint8 = 0x03
	FileNamesInformation           uint8 = 0x0C
	FileIdBothDirectoryInformation uint8 = 0x25
	FileIdFullDirectoryInformation uint8 = 0x26
)

// QueryDirectoryFlags
const (
	QueryDirectoryRestart     uint8 = 0x01
	QueryDirectorySingleEntry uint8 = 0x02
	QueryDirectoryReturnIndex uint8 = 0x04
	QueryDirectoryReopen      uint8 = 0x10
)

// NewQueryDirectoryRequest creates a QUERY_DIRECTORY request
func NewQueryDirectoryRequest(fileID FileID, pattern []byte, infoClass uint8) *QueryDirectoryRequest {
	return &QueryDirectoryRequest{
		StructureSize:        33,
		FileInformationClass: infoClass,
		FileID:               fileID,
		OutputBufferLength:   65536, // 64KB
		FileName:             pattern,
	}
}

// Marshal serializes the QUERY_DIRECTORY request
func (r *QueryDirectoryRequest) Marshal() []byte {
	// Fixed: 32 bytes + 1 buffer byte + filename
	r.FileNameOffset = SMB2HeaderSize + 32
	r.FileNameLength = uint16(len(r.FileName))

	bufLen := 33 + len(r.FileName)
	if len(r.FileName) == 0 {
		bufLen = 33 // Still need 1 byte buffer
	}
	buf := make([]byte, bufLen)

	encoding.PutUint16LE(buf[0:2], r.StructureSize)
	buf[2] = r.FileInformationClass
	buf[3] = r.Flags
	encoding.PutUint32LE(buf[4:8], r.FileIndex)
	copy(buf[8:24], r.FileID.Marshal())
	encoding.PutUint16LE(buf[24:26], r.FileNameOffset)
	encoding.PutUint16LE(buf[26:28], r.FileNameLength)
	encoding.PutUint32LE(buf[28:32], r.OutputBufferLength)

	if len(r.FileName) > 0 {
		copy(buf[32:], r.FileName)
	}

	return buf
}

// QueryDirectoryResponse represents an SMB2 QUERY_DIRECTORY response
type QueryDirectoryResponse struct {
	StructureSize      uint16 // 9
	OutputBufferOffset uint16
	OutputBufferLength uint32
	OutputBuffer       []byte
}

// Unmarshal deserializes a QUERY_DIRECTORY response
func (r *QueryDirectoryResponse) Unmarshal(buf []byte) error {
	if len(buf) < 8 {
		return ErrBufferTooSmall
	}

	r.StructureSize = encoding.Uint16LE(buf[0:2])
	r.OutputBufferOffset = encoding.Uint16LE(buf[2:4])
	r.OutputBufferLength = encoding.Uint32LE(buf[4:8])

	if r.OutputBufferLength > 0 {
		dataStart := int(r.OutputBufferOffset) - SMB2HeaderSize
		if dataStart >= 0 && dataStart+int(r.OutputBufferLength) <= len(buf) {
			r.OutputBuffer = make([]byte, r.OutputBufferLength)
			copy(r.OutputBuffer, buf[dataStart:dataStart+int(r.OutputBufferLength)])
		}
	}

	return nil
}

// FileBothDirInfo represents FILE_BOTH_DIR_INFORMATION structure
type FileBothDirInfo struct {
	NextEntryOffset uint32
	FileIndex       uint32
	CreationTime    uint64
	LastAccessTime  uint64
	LastWriteTime   uint64
	ChangeTime      uint64
	EndOfFile       uint64
	AllocationSize  uint64
	FileAttributes  FileAttributes
	FileNameLength  uint32
	EaSize          uint32
	ShortNameLength uint8
	Reserved        uint8
	ShortName       [24]byte // 12 UTF-16LE chars
	FileName        string
}

// ParseFileBothDirInfo parses FILE_BOTH_DIR_INFORMATION entries
func ParseFileBothDirInfo(data []byte) []FileBothDirInfo {
	var entries []FileBothDirInfo
	offset := 0

	for offset < len(data) {
		if offset+94 > len(data) {
			break
		}

		entry := FileBothDirInfo{}
		entry.NextEntryOffset = encoding.Uint32LE(data[offset:])
		entry.FileIndex = encoding.Uint32LE(data[offset+4:])
		entry.CreationTime = encoding.Uint64LE(data[offset+8:])
		entry.LastAccessTime = encoding.Uint64LE(data[offset+16:])
		entry.LastWriteTime = encoding.Uint64LE(data[offset+24:])
		entry.ChangeTime = encoding.Uint64LE(data[offset+32:])
		entry.EndOfFile = encoding.Uint64LE(data[offset+40:])
		entry.AllocationSize = encoding.Uint64LE(data[offset+48:])
		entry.FileAttributes = FileAttributes(encoding.Uint32LE(data[offset+56:]))
		entry.FileNameLength = encoding.Uint32LE(data[offset+60:])
		entry.EaSize = encoding.Uint32LE(data[offset+64:])
		entry.ShortNameLength = data[offset+68]
		entry.Reserved = data[offset+69]
		copy(entry.ShortName[:], data[offset+70:offset+94])

		// Extract filename
		fileNameStart := offset + 94
		fileNameEnd := fileNameStart + int(entry.FileNameLength)
		if fileNameEnd <= len(data) {
			entry.FileName = encoding.FromUTF16LE(data[fileNameStart:fileNameEnd])
		}

		entries = append(entries, entry)

		if entry.NextEntryOffset == 0 {
			break
		}
		offset += int(entry.NextEntryOffset)
	}

	return entries
}

// FileIdBothDirInfo represents FILE_ID_BOTH_DIR_INFORMATION structure
type FileIdBothDirInfo struct {
	FileBothDirInfo
	FileID uint64
}

// ParseFileIdBothDirInfo parses FILE_ID_BOTH_DIR_INFORMATION entries
func ParseFileIdBothDirInfo(data []byte) []FileIdBothDirInfo {
	var entries []FileIdBothDirInfo
	offset := 0

	for offset < len(data) {
		if offset+104 > len(data) {
			break
		}

		entry := FileIdBothDirInfo{}
		entry.NextEntryOffset = encoding.Uint32LE(data[offset:])
		entry.FileIndex = encoding.Uint32LE(data[offset+4:])
		entry.CreationTime = encoding.Uint64LE(data[offset+8:])
		entry.LastAccessTime = encoding.Uint64LE(data[offset+16:])
		entry.LastWriteTime = encoding.Uint64LE(data[offset+24:])
		entry.ChangeTime = encoding.Uint64LE(data[offset+32:])
		entry.EndOfFile = encoding.Uint64LE(data[offset+40:])
		entry.AllocationSize = encoding.Uint64LE(data[offset+48:])
		entry.FileAttributes = FileAttributes(encoding.Uint32LE(data[offset+56:]))
		entry.FileNameLength = encoding.Uint32LE(data[offset+60:])
		entry.EaSize = encoding.Uint32LE(data[offset+64:])
		entry.ShortNameLength = data[offset+68]
		entry.Reserved = data[offset+69]
		copy(entry.ShortName[:], data[offset+70:offset+94])
		// Reserved2 at offset 94-95
		entry.FileID = encoding.Uint64LE(data[offset+96:])

		// Extract filename
		fileNameStart := offset + 104
		fileNameEnd := fileNameStart + int(entry.FileNameLength)
		if fileNameEnd <= len(data) {
			entry.FileName = encoding.FromUTF16LE(data[fileNameStart:fileNameEnd])
		}

		entries = append(entries, entry)

		if entry.NextEntryOffset == 0 {
			break
		}
		offset += int(entry.NextEntryOffset)
	}

	return entries
}
