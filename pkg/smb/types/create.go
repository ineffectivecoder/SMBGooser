package types

import (
	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// FileID represents a 16-byte file handle
type FileID struct {
	Persistent [8]byte
	Volatile   [8]byte
}

// Marshal serializes the FileID
func (f *FileID) Marshal() []byte {
	buf := make([]byte, 16)
	copy(buf[0:8], f.Persistent[:])
	copy(buf[8:16], f.Volatile[:])
	return buf
}

// Unmarshal deserializes a FileID
func (f *FileID) Unmarshal(buf []byte) {
	if len(buf) >= 16 {
		copy(f.Persistent[:], buf[0:8])
		copy(f.Volatile[:], buf[8:16])
	}
}

// IsZero returns true if the FileID is zero/invalid
func (f *FileID) IsZero() bool {
	for i := 0; i < 8; i++ {
		if f.Persistent[i] != 0 || f.Volatile[i] != 0 {
			return false
		}
	}
	return true
}

// CreateRequest represents an SMB2 CREATE request
type CreateRequest struct {
	StructureSize        uint16 // 57
	SecurityFlags        uint8
	RequestedOplockLevel uint8
	ImpersonationLevel   uint32
	SmbCreateFlags       uint64
	Reserved             uint64
	DesiredAccess        AccessMask
	FileAttributes       FileAttributes
	ShareAccess          ShareAccess
	CreateDisposition    CreateDisposition
	CreateOptions        CreateOptions
	NameOffset           uint16
	NameLength           uint16
	CreateContextsOffset uint32
	CreateContextsLength uint32
	Name                 []byte // Filename (UTF-16LE)
	CreateContexts       []byte // Optional create contexts
}

// ImpersonationLevel values
const (
	ImpersonationAnonymous      uint32 = 0
	ImpersonationIdentification uint32 = 1
	ImpersonationImpersonation  uint32 = 2
	ImpersonationDelegation     uint32 = 3
)

// OplockLevel values
const (
	OplockLevelNone      uint8 = 0x00
	OplockLevelII        uint8 = 0x01
	OplockLevelExclusive uint8 = 0x08
	OplockLevelBatch     uint8 = 0x09
	OplockLevelLease     uint8 = 0xFF
)

// NewCreateRequest creates a CREATE request for a file or directory
func NewCreateRequest(name []byte, access AccessMask, disposition CreateDisposition, options CreateOptions) *CreateRequest {
	return &CreateRequest{
		StructureSize:      57,
		ImpersonationLevel: ImpersonationImpersonation,
		DesiredAccess:      access,
		FileAttributes:     FileAttributeNormal,
		ShareAccess:        FileShareRead | FileShareWrite | FileShareDelete,
		CreateDisposition:  disposition,
		CreateOptions:      options,
		Name:               name,
	}
}

// NewCreatePipeRequest creates a CREATE request for named pipes
// Named pipes need FileAttributes=0 (not Normal), and different ShareAccess
func NewCreatePipeRequest(name []byte, access AccessMask) *CreateRequest {
	return &CreateRequest{
		StructureSize:      57,
		ImpersonationLevel: ImpersonationImpersonation,
		DesiredAccess:      access,
		FileAttributes:     0,                              // Pipes don't use FileAttributeNormal
		ShareAccess:        FileShareRead | FileShareWrite, // No Delete for pipes
		CreateDisposition:  FileOpen,
		CreateOptions:      0, // No options like FileNonDirectoryFile for pipes
		Name:               name,
	}
}

// NewCreateRequestImpacket creates a CREATE request with Impacket's exact openFile() parameters
// Critical: ShareAccess=FileShareRead only (not FileShareRead|FileShareWrite|FileShareDelete)
// This matches Impacket's smbconnection.py openFile() defaults
func NewCreateRequestImpacket(name []byte, access AccessMask, disposition CreateDisposition) *CreateRequest {
	return &CreateRequest{
		StructureSize:      57,
		ImpersonationLevel: ImpersonationImpersonation,
		DesiredAccess:      access,
		FileAttributes:     FileAttributeNormal,
		ShareAccess:        FileShareRead, // KEY DIFFERENCE: Impacket uses only FileShareRead!
		CreateDisposition:  disposition,
		CreateOptions:      FileNonDirectoryFile,
		Name:               name,
	}
}

// Marshal serializes the CREATE request
func (r *CreateRequest) Marshal() []byte {
	// Fixed part: 56 bytes (StructureSize says 57, but last byte is Buffer[0])
	// NameOffset is from start of SMB2 header (64 bytes) + fixed part (56 bytes) = 120
	r.NameOffset = SMB2HeaderSize + 56 // 64 + 56 = 120 = 0x78
	r.NameLength = uint16(len(r.Name))

	// Calculate CreateContexts offset if present
	if len(r.CreateContexts) > 0 {
		// Contexts must be 8-byte aligned
		nameEnd := int(r.NameOffset) + len(r.Name)
		padding := (8 - (nameEnd % 8)) % 8
		r.CreateContextsOffset = uint32(nameEnd + padding)
		r.CreateContextsLength = uint32(len(r.CreateContexts))
	}

	// Buffer size: 57 bytes fixed + name + padding + contexts
	bufLen := 57 + len(r.Name)
	if len(r.CreateContexts) > 0 {
		bufLen = int(r.CreateContextsOffset) - SMB2HeaderSize + len(r.CreateContexts)
	}
	buf := make([]byte, bufLen)

	offset := 0
	encoding.PutUint16LE(buf[offset:], r.StructureSize)
	offset += 2
	buf[offset] = r.SecurityFlags
	offset++
	buf[offset] = r.RequestedOplockLevel
	offset++
	encoding.PutUint32LE(buf[offset:], r.ImpersonationLevel)
	offset += 4
	encoding.PutUint64LE(buf[offset:], r.SmbCreateFlags)
	offset += 8
	encoding.PutUint64LE(buf[offset:], r.Reserved)
	offset += 8
	encoding.PutUint32LE(buf[offset:], uint32(r.DesiredAccess))
	offset += 4
	encoding.PutUint32LE(buf[offset:], uint32(r.FileAttributes))
	offset += 4
	encoding.PutUint32LE(buf[offset:], uint32(r.ShareAccess))
	offset += 4
	encoding.PutUint32LE(buf[offset:], uint32(r.CreateDisposition))
	offset += 4
	encoding.PutUint32LE(buf[offset:], uint32(r.CreateOptions))
	offset += 4
	encoding.PutUint16LE(buf[offset:], r.NameOffset)
	offset += 2
	encoding.PutUint16LE(buf[offset:], r.NameLength)
	offset += 2
	encoding.PutUint32LE(buf[offset:], r.CreateContextsOffset)
	offset += 4
	encoding.PutUint32LE(buf[offset:], r.CreateContextsLength)
	offset += 4

	// Buffer (1 byte minimum even if name is empty)
	if len(r.Name) > 0 {
		copy(buf[offset:], r.Name)
	}

	// CreateContexts if present
	if len(r.CreateContexts) > 0 {
		ctxOffset := int(r.CreateContextsOffset) - SMB2HeaderSize
		copy(buf[ctxOffset:], r.CreateContexts)
	}

	return buf
}

// CreateResponse represents an SMB2 CREATE response
type CreateResponse struct {
	StructureSize        uint16 // 89
	OplockLevel          uint8
	Flags                uint8
	CreateAction         uint32
	CreationTime         uint64
	LastAccessTime       uint64
	LastWriteTime        uint64
	ChangeTime           uint64
	AllocationSize       uint64
	EndOfFile            uint64
	FileAttributes       FileAttributes
	Reserved2            uint32
	FileID               FileID
	CreateContextsOffset uint32
	CreateContextsLength uint32
	CreateContexts       []byte
}

// CreateAction values
const (
	FileSuperseded  uint32 = 0
	FileOpened      uint32 = 1
	FileCreated     uint32 = 2
	FileOverwritten uint32 = 3
)

// Unmarshal deserializes a CREATE response
func (r *CreateResponse) Unmarshal(buf []byte) error {
	if len(buf) < 88 {
		return ErrBufferTooSmall
	}

	offset := 0
	r.StructureSize = encoding.Uint16LE(buf[offset:])
	offset += 2
	r.OplockLevel = buf[offset]
	offset++
	r.Flags = buf[offset]
	offset++
	r.CreateAction = encoding.Uint32LE(buf[offset:])
	offset += 4
	r.CreationTime = encoding.Uint64LE(buf[offset:])
	offset += 8
	r.LastAccessTime = encoding.Uint64LE(buf[offset:])
	offset += 8
	r.LastWriteTime = encoding.Uint64LE(buf[offset:])
	offset += 8
	r.ChangeTime = encoding.Uint64LE(buf[offset:])
	offset += 8
	r.AllocationSize = encoding.Uint64LE(buf[offset:])
	offset += 8
	r.EndOfFile = encoding.Uint64LE(buf[offset:])
	offset += 8
	r.FileAttributes = FileAttributes(encoding.Uint32LE(buf[offset:]))
	offset += 4
	r.Reserved2 = encoding.Uint32LE(buf[offset:])
	offset += 4
	r.FileID.Unmarshal(buf[offset:])
	offset += 16
	r.CreateContextsOffset = encoding.Uint32LE(buf[offset:])
	offset += 4
	r.CreateContextsLength = encoding.Uint32LE(buf[offset:])

	return nil
}

// CloseRequest represents an SMB2 CLOSE request
type CloseRequest struct {
	StructureSize uint16 // 24
	Flags         uint16
	Reserved      uint32
	FileID        FileID
}

// CloseFlags
const (
	CloseFlagPostQueryAttrib uint16 = 0x0001
)

// NewCloseRequest creates a CLOSE request
func NewCloseRequest(fileID FileID) *CloseRequest {
	return &CloseRequest{
		StructureSize: 24,
		FileID:        fileID,
	}
}

// Marshal serializes the CLOSE request
func (r *CloseRequest) Marshal() []byte {
	buf := make([]byte, 24)
	encoding.PutUint16LE(buf[0:2], r.StructureSize)
	encoding.PutUint16LE(buf[2:4], r.Flags)
	encoding.PutUint32LE(buf[4:8], r.Reserved)
	copy(buf[8:24], r.FileID.Marshal())
	return buf
}

// CloseResponse represents an SMB2 CLOSE response
type CloseResponse struct {
	StructureSize  uint16 // 60
	Flags          uint16
	Reserved       uint32
	CreationTime   uint64
	LastAccessTime uint64
	LastWriteTime  uint64
	ChangeTime     uint64
	AllocationSize uint64
	EndOfFile      uint64
	FileAttributes FileAttributes
}

// Unmarshal deserializes a CLOSE response
func (r *CloseResponse) Unmarshal(buf []byte) error {
	if len(buf) < 60 {
		return ErrBufferTooSmall
	}

	r.StructureSize = encoding.Uint16LE(buf[0:2])
	r.Flags = encoding.Uint16LE(buf[2:4])
	r.Reserved = encoding.Uint32LE(buf[4:8])
	r.CreationTime = encoding.Uint64LE(buf[8:16])
	r.LastAccessTime = encoding.Uint64LE(buf[16:24])
	r.LastWriteTime = encoding.Uint64LE(buf[24:32])
	r.ChangeTime = encoding.Uint64LE(buf[32:40])
	r.AllocationSize = encoding.Uint64LE(buf[40:48])
	r.EndOfFile = encoding.Uint64LE(buf[48:56])
	r.FileAttributes = FileAttributes(encoding.Uint32LE(buf[56:60]))

	return nil
}

// QueryInfoRequest represents an SMB2 QUERY_INFO request
type QueryInfoRequest struct {
	StructureSize      uint16 // 41
	InfoType           uint8
	FileInfoClass      uint8
	OutputBufferLength uint32
	InputBufferOffset  uint16
	Reserved           uint16
	InputBufferLength  uint32
	AdditionalInfo     uint32
	Flags              uint32
	FileID             FileID
}

// NewQueryInfoRequest creates a QUERY_INFO request
func NewQueryInfoRequest(fileID FileID, infoType, infoClass uint8, additionalInfo, outputLength uint32) *QueryInfoRequest {
	return &QueryInfoRequest{
		StructureSize:      41,
		InfoType:           infoType,
		FileInfoClass:      infoClass,
		OutputBufferLength: outputLength,
		AdditionalInfo:     additionalInfo,
		FileID:             fileID,
	}
}

// Marshal serializes the QUERY_INFO request
func (r *QueryInfoRequest) Marshal() []byte {
	buf := make([]byte, 40)
	encoding.PutUint16LE(buf[0:2], r.StructureSize)
	buf[2] = r.InfoType
	buf[3] = r.FileInfoClass
	encoding.PutUint32LE(buf[4:8], r.OutputBufferLength)
	encoding.PutUint16LE(buf[8:10], r.InputBufferOffset)
	encoding.PutUint16LE(buf[10:12], r.Reserved)
	encoding.PutUint32LE(buf[12:16], r.InputBufferLength)
	encoding.PutUint32LE(buf[16:20], r.AdditionalInfo)
	encoding.PutUint32LE(buf[20:24], r.Flags)
	copy(buf[24:40], r.FileID.Marshal())
	return buf
}

// SetInfoRequest represents an SMB2 SET_INFO request
type SetInfoRequest struct {
	StructureSize  uint16 // 33
	InfoType       uint8
	FileInfoClass  uint8
	BufferLength   uint32
	BufferOffset   uint16
	Reserved       uint16
	AdditionalInfo uint32
	FileID         FileID
	Buffer         []byte
}

// NewSetInfoRequest creates a SET_INFO request
func NewSetInfoRequest(fileID FileID, infoType, infoClass uint8, buffer []byte) *SetInfoRequest {
	return &SetInfoRequest{
		StructureSize: 33,
		InfoType:      infoType,
		FileInfoClass: infoClass,
		BufferLength:  uint32(len(buffer)),
		BufferOffset:  SMB2HeaderSize + 32, // Fixed header is 32 bytes
		FileID:        fileID,
		Buffer:        buffer,
	}
}

// Marshal serializes the SET_INFO request
func (r *SetInfoRequest) Marshal() []byte {
	buf := make([]byte, 32+len(r.Buffer))
	encoding.PutUint16LE(buf[0:2], r.StructureSize)
	buf[2] = r.InfoType
	buf[3] = r.FileInfoClass
	encoding.PutUint32LE(buf[4:8], r.BufferLength)
	encoding.PutUint16LE(buf[8:10], r.BufferOffset)
	encoding.PutUint16LE(buf[10:12], r.Reserved)
	encoding.PutUint32LE(buf[12:16], r.AdditionalInfo)
	copy(buf[16:32], r.FileID.Marshal())
	copy(buf[32:], r.Buffer)
	return buf
}
