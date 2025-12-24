// File operations for SMB1 protocol
package smb1

import (
	"encoding/binary"
	"fmt"
)

// File represents an open SMB1 file handle
type File struct {
	FID    uint16
	client *Client
}

// FileInfo represents file metadata from directory listing
type FileInfo struct {
	Name          string
	Size          int64
	IsDirectory   bool
	CreationTime  uint64
	LastWriteTime uint64
	Attributes    uint32
}

// NT_CREATE_ANDX request constants
const (
	// Desired access flags
	FileReadData        uint32 = 0x00000001
	FileWriteData       uint32 = 0x00000002
	FileAppendData      uint32 = 0x00000004
	FileReadEA          uint32 = 0x00000008
	FileWriteEA         uint32 = 0x00000010
	FileExecute         uint32 = 0x00000020
	FileDeleteChild     uint32 = 0x00000040
	FileReadAttributes  uint32 = 0x00000080
	FileWriteAttributes uint32 = 0x00000100
	Delete              uint32 = 0x00010000
	ReadControl         uint32 = 0x00020000
	WriteDac            uint32 = 0x00040000
	WriteOwner          uint32 = 0x00080000
	Synchronize         uint32 = 0x00100000
	GenericAll          uint32 = 0x10000000
	GenericExecute      uint32 = 0x20000000
	GenericWrite        uint32 = 0x40000000
	GenericRead         uint32 = 0x80000000
	MaximumAllowed      uint32 = 0x02000000

	// Share access
	FileShareRead   uint32 = 0x00000001
	FileShareWrite  uint32 = 0x00000002
	FileShareDelete uint32 = 0x00000004

	// Disposition
	FileSupersede   uint32 = 0x00000000
	FileOpen        uint32 = 0x00000001
	FileCreate      uint32 = 0x00000002
	FileOpenIf      uint32 = 0x00000003
	FileOverwrite   uint32 = 0x00000004
	FileOverwriteIf uint32 = 0x00000005

	// Create options
	FileDirectoryFile           uint32 = 0x00000001
	FileNonDirectoryFile        uint32 = 0x00000040
	FileWriteThrough            uint32 = 0x00000002
	FileSequentialOnly          uint32 = 0x00000004
	FileNoIntermediateBuffering uint32 = 0x00000008

	// File attributes
	AttrReadOnly  uint32 = 0x00000001
	AttrHidden    uint32 = 0x00000002
	AttrSystem    uint32 = 0x00000004
	AttrDirectory uint32 = 0x00000010
	AttrArchive   uint32 = 0x00000020
	AttrNormal    uint32 = 0x00000080
)

// NTCreateAndXRequest represents SMB_COM_NT_CREATE_ANDX request
type NTCreateAndXRequest struct {
	// Words
	AndXCommand        uint8
	AndXReserved       uint8
	AndXOffset         uint16
	Reserved           uint8
	NameLength         uint16
	Flags              uint32
	RootDirectoryFID   uint32
	DesiredAccess      uint32
	AllocationSize     uint64
	ExtFileAttributes  uint32
	ShareAccess        uint32
	CreateDisposition  uint32
	CreateOptions      uint32
	ImpersonationLevel uint32
	SecurityFlags      uint8
	// Data
	FileName string
}

// Marshal serializes NT_CREATE_ANDX request
func (r *NTCreateAndXRequest) Marshal() []byte {
	// Encode filename as Unicode
	fileNameBytes := encodeUnicode(r.FileName)
	r.NameLength = uint16(len(fileNameBytes))

	// WordCount = 24
	wordCount := 24
	params := make([]byte, wordCount*2)

	offset := 0
	params[offset] = 0xFF // AndXCommand = no further commands
	offset++
	params[offset] = 0 // Reserved
	offset++
	binary.LittleEndian.PutUint16(params[offset:], 0) // AndXOffset
	offset += 2
	params[offset] = 0 // Reserved byte
	offset++
	binary.LittleEndian.PutUint16(params[offset:], r.NameLength)
	offset += 2
	binary.LittleEndian.PutUint32(params[offset:], r.Flags)
	offset += 4
	binary.LittleEndian.PutUint32(params[offset:], r.RootDirectoryFID)
	offset += 4
	binary.LittleEndian.PutUint32(params[offset:], r.DesiredAccess)
	offset += 4
	binary.LittleEndian.PutUint64(params[offset:], r.AllocationSize)
	offset += 8
	binary.LittleEndian.PutUint32(params[offset:], r.ExtFileAttributes)
	offset += 4
	binary.LittleEndian.PutUint32(params[offset:], r.ShareAccess)
	offset += 4
	binary.LittleEndian.PutUint32(params[offset:], r.CreateDisposition)
	offset += 4
	binary.LittleEndian.PutUint32(params[offset:], r.CreateOptions)
	offset += 4
	binary.LittleEndian.PutUint32(params[offset:], r.ImpersonationLevel)
	offset += 4
	params[offset] = r.SecurityFlags

	// Build data: padding byte + filename
	data := make([]byte, 1+len(fileNameBytes))
	data[0] = 0 // Padding for Unicode alignment
	copy(data[1:], fileNameBytes)

	// Combine: WordCount + params + ByteCount + data
	buf := make([]byte, 1+len(params)+2+len(data))
	buf[0] = uint8(wordCount)
	copy(buf[1:], params)
	binary.LittleEndian.PutUint16(buf[1+len(params):], uint16(len(data)))
	copy(buf[1+len(params)+2:], data)

	return buf
}

// NTCreateAndXResponse represents SMB_COM_NT_CREATE_ANDX response
type NTCreateAndXResponse struct {
	AndXCommand       uint8
	AndXOffset        uint16
	OpLockLevel       uint8
	FID               uint16
	CreateAction      uint32
	CreationTime      uint64
	LastAccessTime    uint64
	LastWriteTime     uint64
	ChangeTime        uint64
	ExtFileAttributes uint32
	AllocationSize    uint64
	EndOfFile         uint64
	FileType          uint16
	DeviceState       uint16
	Directory         bool
}

// Unmarshal parses NT_CREATE_ANDX response
func (r *NTCreateAndXResponse) Unmarshal(buf []byte) error {
	if len(buf) < 1 {
		return fmt.Errorf("buffer too short")
	}

	wordCount := buf[0]
	if wordCount < 34 {
		return fmt.Errorf("unexpected word count: %d", wordCount)
	}

	offset := 1
	r.AndXCommand = buf[offset]
	offset++
	offset++ // Reserved
	r.AndXOffset = binary.LittleEndian.Uint16(buf[offset:])
	offset += 2
	r.OpLockLevel = buf[offset]
	offset++
	r.FID = binary.LittleEndian.Uint16(buf[offset:])
	offset += 2
	r.CreateAction = binary.LittleEndian.Uint32(buf[offset:])
	offset += 4
	r.CreationTime = binary.LittleEndian.Uint64(buf[offset:])
	offset += 8
	r.LastAccessTime = binary.LittleEndian.Uint64(buf[offset:])
	offset += 8
	r.LastWriteTime = binary.LittleEndian.Uint64(buf[offset:])
	offset += 8
	r.ChangeTime = binary.LittleEndian.Uint64(buf[offset:])
	offset += 8
	r.ExtFileAttributes = binary.LittleEndian.Uint32(buf[offset:])
	offset += 4
	r.AllocationSize = binary.LittleEndian.Uint64(buf[offset:])
	offset += 8
	r.EndOfFile = binary.LittleEndian.Uint64(buf[offset:])
	offset += 8
	r.FileType = binary.LittleEndian.Uint16(buf[offset:])
	offset += 2
	r.DeviceState = binary.LittleEndian.Uint16(buf[offset:])
	offset += 2
	r.Directory = buf[offset] != 0

	return nil
}

// CreateFile opens a file or pipe
func (c *Client) CreateFile(path string, desiredAccess, shareAccess, disposition, createOptions uint32) (*File, error) {
	req := &NTCreateAndXRequest{
		Flags:              0x16, // NT_CREATE_REQUEST_OPLOCK | NT_CREATE_REQUEST_OPBATCH | NT_CREATE_OPEN_TARGET_DIR
		DesiredAccess:      desiredAccess,
		ExtFileAttributes:  AttrNormal,
		ShareAccess:        shareAccess,
		CreateDisposition:  disposition,
		CreateOptions:      createOptions,
		ImpersonationLevel: 2, // Impersonation
		FileName:           path,
	}

	header := NewHeader(CommandNTCreateAndX, c.nextMID())
	header.UID = c.uid
	header.TID = c.tid

	msg := append(header.Marshal(), req.Marshal()...)

	resp, err := c.transport.SendRecv(msg)
	if err != nil {
		return nil, fmt.Errorf("create file failed: %w", err)
	}

	var respHeader Header
	if err := respHeader.Unmarshal(resp); err != nil {
		return nil, fmt.Errorf("failed to parse response header: %w", err)
	}

	if !respHeader.IsSuccess() {
		return nil, fmt.Errorf("create file error: 0x%08X", respHeader.Status)
	}

	var createResp NTCreateAndXResponse
	if err := createResp.Unmarshal(resp[HeaderSize:]); err != nil {
		return nil, fmt.Errorf("failed to parse create response: %w", err)
	}

	return &File{
		FID:    createResp.FID,
		client: c,
	}, nil
}

// ReadAndXRequest represents SMB_COM_READ_ANDX request
type ReadAndXRequest struct {
	FID          uint16
	Offset       uint64
	MaxCountHigh uint16
	MinCount     uint16
	MaxCount     uint16
	Remaining    uint16
}

// Marshal serializes READ_ANDX request
func (r *ReadAndXRequest) Marshal() []byte {
	// WordCount = 12 for large files
	wordCount := 12
	params := make([]byte, wordCount*2)

	offset := 0
	params[offset] = 0xFF // AndXCommand
	offset++
	params[offset] = 0 // Reserved
	offset++
	binary.LittleEndian.PutUint16(params[offset:], 0) // AndXOffset
	offset += 2
	binary.LittleEndian.PutUint16(params[offset:], r.FID)
	offset += 2
	binary.LittleEndian.PutUint32(params[offset:], uint32(r.Offset))
	offset += 4
	binary.LittleEndian.PutUint16(params[offset:], r.MaxCount)
	offset += 2
	binary.LittleEndian.PutUint16(params[offset:], r.MinCount)
	offset += 2
	binary.LittleEndian.PutUint32(params[offset:], uint32(r.MaxCountHigh))
	offset += 4
	binary.LittleEndian.PutUint16(params[offset:], r.Remaining)
	offset += 2
	binary.LittleEndian.PutUint32(params[offset:], uint32(r.Offset>>32)) // OffsetHigh

	buf := make([]byte, 1+len(params)+2)
	buf[0] = uint8(wordCount)
	copy(buf[1:], params)
	binary.LittleEndian.PutUint16(buf[1+len(params):], 0) // ByteCount = 0

	return buf
}

// ReadFile reads data from an open file
func (c *Client) ReadFile(fid uint16, offset uint64, length uint32) ([]byte, error) {
	req := &ReadAndXRequest{
		FID:      fid,
		Offset:   offset,
		MaxCount: uint16(length),
		MinCount: uint16(length),
	}
	if length > 0xFFFF {
		req.MaxCount = 0xFFFF
		req.MaxCountHigh = uint16(length >> 16)
	}

	header := NewHeader(CommandReadAndX, c.nextMID())
	header.UID = c.uid
	header.TID = c.tid

	msg := append(header.Marshal(), req.Marshal()...)

	resp, err := c.transport.SendRecv(msg)
	if err != nil {
		return nil, fmt.Errorf("read file failed: %w", err)
	}

	var respHeader Header
	if err := respHeader.Unmarshal(resp); err != nil {
		return nil, err
	}

	if !respHeader.IsSuccess() {
		return nil, fmt.Errorf("read file error: 0x%08X", respHeader.Status)
	}

	// Parse READ_ANDX response
	if len(resp) < HeaderSize+13 {
		return nil, fmt.Errorf("response too short")
	}

	respData := resp[HeaderSize:]
	if respData[0] < 12 {
		return nil, fmt.Errorf("unexpected word count: %d", respData[0])
	}

	dataLength := binary.LittleEndian.Uint16(respData[11:13])
	dataOffset := binary.LittleEndian.Uint16(respData[13:15])

	if int(dataOffset)+int(dataLength) > len(resp) {
		return nil, fmt.Errorf("data out of bounds")
	}

	return resp[dataOffset : dataOffset+dataLength], nil
}

// WriteAndXRequest represents SMB_COM_WRITE_ANDX request
type WriteAndXRequest struct {
	FID            uint16
	Offset         uint64
	WriteMode      uint16
	Remaining      uint16
	DataLength     uint16
	DataLengthHigh uint16
	DataOffset     uint16
	Data           []byte
}

// Marshal serializes WRITE_ANDX request
func (r *WriteAndXRequest) Marshal() []byte {
	// WordCount = 14 for large files
	wordCount := 14
	params := make([]byte, wordCount*2)

	// Calculate data offset: header(32) + wordcount(1) + params(28) + bytecount(2) + padding(1)
	r.DataOffset = uint16(HeaderSize + 1 + wordCount*2 + 2 + 1)
	r.DataLength = uint16(len(r.Data))

	offset := 0
	params[offset] = 0xFF // AndXCommand
	offset++
	params[offset] = 0 // Reserved
	offset++
	binary.LittleEndian.PutUint16(params[offset:], 0) // AndXOffset
	offset += 2
	binary.LittleEndian.PutUint16(params[offset:], r.FID)
	offset += 2
	binary.LittleEndian.PutUint32(params[offset:], uint32(r.Offset))
	offset += 4
	binary.LittleEndian.PutUint32(params[offset:], 0) // Reserved
	offset += 4
	binary.LittleEndian.PutUint16(params[offset:], r.WriteMode)
	offset += 2
	binary.LittleEndian.PutUint16(params[offset:], r.Remaining)
	offset += 2
	binary.LittleEndian.PutUint16(params[offset:], r.DataLengthHigh)
	offset += 2
	binary.LittleEndian.PutUint16(params[offset:], r.DataLength)
	offset += 2
	binary.LittleEndian.PutUint16(params[offset:], r.DataOffset)
	offset += 2
	binary.LittleEndian.PutUint32(params[offset:], uint32(r.Offset>>32)) // OffsetHigh

	// Data section: padding + data
	data := make([]byte, 1+len(r.Data))
	data[0] = 0 // Padding
	copy(data[1:], r.Data)

	buf := make([]byte, 1+len(params)+2+len(data))
	buf[0] = uint8(wordCount)
	copy(buf[1:], params)
	binary.LittleEndian.PutUint16(buf[1+len(params):], uint16(len(data)))
	copy(buf[1+len(params)+2:], data)

	return buf
}

// WriteFile writes data to an open file
func (c *Client) WriteFile(fid uint16, offset uint64, data []byte) (int, error) {
	req := &WriteAndXRequest{
		FID:    fid,
		Offset: offset,
		Data:   data,
	}

	header := NewHeader(CommandWriteAndX, c.nextMID())
	header.UID = c.uid
	header.TID = c.tid

	msg := append(header.Marshal(), req.Marshal()...)

	resp, err := c.transport.SendRecv(msg)
	if err != nil {
		return 0, fmt.Errorf("write file failed: %w", err)
	}

	var respHeader Header
	if err := respHeader.Unmarshal(resp); err != nil {
		return 0, err
	}

	if !respHeader.IsSuccess() {
		return 0, fmt.Errorf("write file error: 0x%08X", respHeader.Status)
	}

	// Parse WRITE_ANDX response
	if len(resp) < HeaderSize+7 {
		return 0, fmt.Errorf("response too short")
	}

	respData := resp[HeaderSize:]
	written := int(binary.LittleEndian.Uint16(respData[5:7]))

	return written, nil
}

// CloseRequest represents SMB_COM_CLOSE request
type CloseRequest struct {
	FID           uint16
	LastWriteTime uint32
}

// Marshal serializes CLOSE request
func (r *CloseRequest) Marshal() []byte {
	buf := make([]byte, 7)
	buf[0] = 3 // WordCount = 3
	binary.LittleEndian.PutUint16(buf[1:], r.FID)
	binary.LittleEndian.PutUint32(buf[3:], r.LastWriteTime)
	binary.LittleEndian.PutUint16(buf[7:], 0) // ByteCount = 0
	return buf[:9]
}

// CloseFile closes an open file
func (c *Client) CloseFile(fid uint16) error {
	req := &CloseRequest{
		FID:           fid,
		LastWriteTime: 0xFFFFFFFF, // Don't change
	}

	header := NewHeader(CommandClose, c.nextMID())
	header.UID = c.uid
	header.TID = c.tid

	msg := append(header.Marshal(), req.Marshal()...)

	resp, err := c.transport.SendRecv(msg)
	if err != nil {
		return fmt.Errorf("close file failed: %w", err)
	}

	var respHeader Header
	if err := respHeader.Unmarshal(resp); err != nil {
		return err
	}

	if !respHeader.IsSuccess() {
		return fmt.Errorf("close file error: 0x%08X", respHeader.Status)
	}

	return nil
}

// File method wrappers
func (f *File) Read(offset uint64, length uint32) ([]byte, error) {
	return f.client.ReadFile(f.FID, offset, length)
}

func (f *File) Write(offset uint64, data []byte) (int, error) {
	return f.client.WriteFile(f.FID, offset, data)
}

func (f *File) Close() error {
	return f.client.CloseFile(f.FID)
}

// encodeUnicode encodes a string as UTF-16LE with null terminator
func encodeUnicode(s string) []byte {
	buf := make([]byte, (len(s)+1)*2)
	for i, r := range s {
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}
	return buf
}
