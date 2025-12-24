package smb

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

// File represents an open file or named pipe handle
type File struct {
	tree       *Tree
	fileID     types.FileID
	name       string
	size       uint64
	attributes types.FileAttributes
	offset     int64
	isDir      bool
}

// OpenFile opens a file on the share
func (t *Tree) OpenFile(ctx context.Context, path string, access types.AccessMask, disposition types.CreateDisposition) (*File, error) {
	return t.open(ctx, path, access, disposition, types.FileNonDirectoryFile)
}

// OpenFileImpacket opens a file with Impacket's exact openFile() parameters
// Critical difference: ShareAccess=FileShareRead only (not FileShareRead|FileShareWrite|FileShareDelete)
func (t *Tree) OpenFileImpacket(ctx context.Context, path string, access types.AccessMask, disposition types.CreateDisposition) (*File, error) {
	// Convert path to UTF-16LE
	pathBytes := encoding.ToUTF16LE(path)

	// Build CREATE request with Impacket's exact parameters
	req := types.NewCreateRequestImpacket(pathBytes, access, disposition)

	// Build header
	header := types.NewHeader(types.CommandCreate, t.session.nextMessageID())
	header.SessionID = t.session.sessionID
	header.TreeID = t.treeID

	// Send request
	resp, err := t.session.sendRecv(header, req.Marshal())
	if err != nil {
		return nil, fmt.Errorf("create failed: %w", err)
	}

	// Parse response header
	var respHeader types.Header
	if err := respHeader.Unmarshal(resp[:types.SMB2HeaderSize]); err != nil {
		return nil, fmt.Errorf("failed to parse response header: %w", err)
	}

	// Check status
	if !respHeader.Status.IsSuccess() {
		return nil, StatusToError(respHeader.Status)
	}

	// Parse CREATE response
	var createResp types.CreateResponse
	if err := createResp.Unmarshal(resp[types.SMB2HeaderSize:]); err != nil {
		return nil, fmt.Errorf("failed to parse create response: %w", err)
	}

	return &File{
		tree:       t,
		fileID:     createResp.FileID,
		name:       path,
		size:       createResp.EndOfFile,
		attributes: createResp.FileAttributes,
		isDir:      false,
	}, nil
}

// OpenPipe opens a named pipe on the IPC$ share
// Named pipes need different options than regular files
func (t *Tree) OpenPipe(ctx context.Context, pipeName string, access types.AccessMask) (*File, error) {
	// Convert path to UTF-16LE
	pathBytes := encoding.ToUTF16LE(pipeName)

	// Build CREATE request with pipe-specific options
	req := types.NewCreatePipeRequest(pathBytes, access)

	// Build header
	header := types.NewHeader(types.CommandCreate, t.session.nextMessageID())
	header.SessionID = t.session.sessionID
	header.TreeID = t.treeID

	// Send request
	resp, err := t.session.sendRecv(header, req.Marshal())
	if err != nil {
		return nil, fmt.Errorf("create failed: %w", err)
	}

	// Parse response header
	var respHeader types.Header
	if err := respHeader.Unmarshal(resp[:types.SMB2HeaderSize]); err != nil {
		return nil, fmt.Errorf("failed to parse response header: %w", err)
	}

	// Check status
	if !respHeader.Status.IsSuccess() {
		return nil, StatusToError(respHeader.Status)
	}

	// Parse CREATE response
	var createResp types.CreateResponse
	if err := createResp.Unmarshal(resp[types.SMB2HeaderSize:]); err != nil {
		return nil, fmt.Errorf("failed to parse create response: %w", err)
	}

	return &File{
		tree:       t,
		fileID:     createResp.FileID,
		name:       pipeName,
		size:       createResp.EndOfFile,
		attributes: createResp.FileAttributes,
		isDir:      false,
	}, nil
}

// OpenDirectory opens a directory handle
func (t *Tree) OpenDirectory(ctx context.Context, path string) (*File, error) {
	access := types.FileReadData | types.FileReadAttributes | types.ReadControl | types.Synchronize
	return t.open(ctx, path, access, types.FileOpen, types.FileDirectoryFile)
}

// open performs the CREATE operation
func (t *Tree) open(ctx context.Context, path string, access types.AccessMask, disposition types.CreateDisposition, options types.CreateOptions) (*File, error) {
	// Convert path to UTF-16LE
	pathBytes := encoding.ToUTF16LE(path)

	// Build CREATE request
	req := types.NewCreateRequest(pathBytes, access, disposition, options)

	// Build header
	header := types.NewHeader(types.CommandCreate, t.session.nextMessageID())
	header.SessionID = t.session.sessionID
	header.TreeID = t.treeID

	// Send request
	resp, err := t.session.sendRecv(header, req.Marshal())
	if err != nil {
		return nil, fmt.Errorf("create failed: %w", err)
	}

	// Parse response header
	var respHeader types.Header
	if err := respHeader.Unmarshal(resp[:types.SMB2HeaderSize]); err != nil {
		return nil, fmt.Errorf("failed to parse response header: %w", err)
	}

	// Check status
	if !respHeader.Status.IsSuccess() {
		return nil, StatusToError(respHeader.Status)
	}

	// Parse CREATE response
	var createResp types.CreateResponse
	if err := createResp.Unmarshal(resp[types.SMB2HeaderSize:]); err != nil {
		return nil, fmt.Errorf("failed to parse create response: %w", err)
	}

	return &File{
		tree:       t,
		fileID:     createResp.FileID,
		name:       path,
		size:       createResp.EndOfFile,
		attributes: createResp.FileAttributes,
		isDir:      createResp.FileAttributes&types.FileAttributeDirectory != 0,
	}, nil
}

// Read reads data from the file
func (f *File) Read(p []byte) (n int, err error) {
	if f.isDir {
		return 0, fmt.Errorf("cannot read from directory")
	}

	n, err = f.ReadAt(p, f.offset)
	if err == nil {
		f.offset += int64(n)
	}
	return n, err
}

// ReadAt reads data at a specific offset
func (f *File) ReadAt(p []byte, off int64) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	maxRead := f.tree.session.maxReadSize
	if maxRead == 0 {
		maxRead = 65536
	}

	readLen := uint32(len(p))
	if readLen > maxRead {
		readLen = maxRead
	}

	// Build READ request
	req := types.NewReadRequest(f.fileID, uint64(off), readLen)

	// Build header
	header := types.NewHeader(types.CommandRead, f.tree.session.nextMessageID())
	header.SessionID = f.tree.session.sessionID
	header.TreeID = f.tree.treeID

	// Send request
	resp, err := f.tree.session.sendRecv(header, req.Marshal())
	if err != nil {
		return 0, fmt.Errorf("read failed: %w", err)
	}

	// Parse response header
	var respHeader types.Header
	if err := respHeader.Unmarshal(resp[:types.SMB2HeaderSize]); err != nil {
		return 0, fmt.Errorf("failed to parse response header: %w", err)
	}

	// Check status
	if respHeader.Status == types.StatusEndOfFile {
		return 0, io.EOF
	}
	if !respHeader.Status.IsSuccess() {
		return 0, StatusToError(respHeader.Status)
	}

	// Parse READ response
	var readResp types.ReadResponse
	if err := readResp.Unmarshal(resp[types.SMB2HeaderSize:]); err != nil {
		return 0, fmt.Errorf("failed to parse read response: %w", err)
	}

	n = copy(p, readResp.Data)
	if n == 0 && len(p) > 0 {
		return 0, io.EOF
	}

	return n, nil
}

// Write writes data to the file
func (f *File) Write(p []byte) (n int, err error) {
	if f.isDir {
		return 0, fmt.Errorf("cannot write to directory")
	}

	n, err = f.WriteAt(p, f.offset)
	if err == nil {
		f.offset += int64(n)
	}
	return n, err
}

// WriteAt writes data at a specific offset
func (f *File) WriteAt(p []byte, off int64) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	maxWrite := f.tree.session.maxWriteSize
	if maxWrite == 0 {
		maxWrite = 65536
	}

	// Write in chunks if needed
	totalWritten := 0
	for len(p) > 0 {
		writeLen := len(p)
		if uint32(writeLen) > maxWrite {
			writeLen = int(maxWrite)
		}

		// Build WRITE request
		req := types.NewWriteRequest(f.fileID, uint64(off), p[:writeLen])

		// Build header
		header := types.NewHeader(types.CommandWrite, f.tree.session.nextMessageID())
		header.SessionID = f.tree.session.sessionID
		header.TreeID = f.tree.treeID

		// Send request
		resp, err := f.tree.session.sendRecv(header, req.Marshal())
		if err != nil {
			return totalWritten, fmt.Errorf("write failed: %w", err)
		}

		// Parse response header
		var respHeader types.Header
		if err := respHeader.Unmarshal(resp[:types.SMB2HeaderSize]); err != nil {
			return totalWritten, fmt.Errorf("failed to parse response header: %w", err)
		}

		// Check status
		if !respHeader.Status.IsSuccess() {
			return totalWritten, StatusToError(respHeader.Status)
		}

		// Parse WRITE response
		var writeResp types.WriteResponse
		if err := writeResp.Unmarshal(resp[types.SMB2HeaderSize:]); err != nil {
			return totalWritten, fmt.Errorf("failed to parse write response: %w", err)
		}

		totalWritten += int(writeResp.Count)
		off += int64(writeResp.Count)
		p = p[writeResp.Count:]
	}

	return totalWritten, nil
}

// Seek sets the file offset
func (f *File) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		f.offset = offset
	case io.SeekCurrent:
		f.offset += offset
	case io.SeekEnd:
		f.offset = int64(f.size) + offset
	default:
		return 0, fmt.Errorf("invalid whence: %d", whence)
	}
	return f.offset, nil
}

// Close closes the file handle
func (f *File) Close() error {
	if f.fileID.IsZero() {
		return nil
	}

	// Build CLOSE request
	req := types.NewCloseRequest(f.fileID)

	// Build header
	header := types.NewHeader(types.CommandClose, f.tree.session.nextMessageID())
	header.SessionID = f.tree.session.sessionID
	header.TreeID = f.tree.treeID

	// Send request
	resp, err := f.tree.session.sendRecv(header, req.Marshal())
	if err != nil {
		return fmt.Errorf("close failed: %w", err)
	}

	// Parse response header
	var respHeader types.Header
	if err := respHeader.Unmarshal(resp[:types.SMB2HeaderSize]); err != nil {
		return fmt.Errorf("failed to parse response header: %w", err)
	}

	// Check status
	if !respHeader.Status.IsSuccess() {
		return StatusToError(respHeader.Status)
	}

	// Clear file ID
	f.fileID = types.FileID{}

	return nil
}

// Name returns the file name
func (f *File) Name() string {
	return f.name
}

// Size returns the file size
func (f *File) Size() int64 {
	return int64(f.size)
}

// IsDirectory returns true if this is a directory
func (f *File) IsDirectory() bool {
	return f.isDir
}

// FileID returns the SMB file ID
func (f *File) FileID() types.FileID {
	return f.fileID
}

// Attributes returns the file attributes
func (f *File) Attributes() types.FileAttributes {
	return f.attributes
}

// GetSecurityDescriptor retrieves the security descriptor for the file
func (f *File) GetSecurityDescriptor(ctx context.Context) ([]byte, error) {
	// QUERY_INFO request for security descriptor
	// InfoType = 0x03 (Security)
	// FileInfoClass = 0x00 (not used for security)
	// Additional info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
	additionalInfo := uint32(0x07) // OWNER|GROUP|DACL

	// Build QUERY_INFO request
	req := types.NewQueryInfoRequest(f.fileID, 0x03, 0x00, additionalInfo, 65536)

	// Build header
	header := types.NewHeader(types.CommandQueryInfo, f.tree.session.nextMessageID())
	header.SessionID = f.tree.session.sessionID
	header.TreeID = f.tree.treeID

	// Send request
	resp, err := f.tree.session.sendRecv(header, req.Marshal())
	if err != nil {
		return nil, fmt.Errorf("query info failed: %w", err)
	}

	// Parse response header
	var respHeader types.Header
	if err := respHeader.Unmarshal(resp[:types.SMB2HeaderSize]); err != nil {
		return nil, fmt.Errorf("failed to parse response header: %w", err)
	}

	// Check status
	if !respHeader.Status.IsSuccess() {
		return nil, StatusToError(respHeader.Status)
	}

	// Parse QUERY_INFO response
	if len(resp) < types.SMB2HeaderSize+8 {
		return nil, fmt.Errorf("response too short")
	}

	queryResp := resp[types.SMB2HeaderSize:]
	outputOffset := uint16(queryResp[2]) | uint16(queryResp[3])<<8
	outputLength := uint32(queryResp[4]) | uint32(queryResp[5])<<8 | uint32(queryResp[6])<<16 | uint32(queryResp[7])<<24

	if outputLength == 0 {
		return nil, fmt.Errorf("empty security descriptor")
	}

	// Calculate actual offset in response buffer
	dataStart := int(outputOffset) - types.SMB2HeaderSize
	if dataStart < 0 || dataStart+int(outputLength) > len(queryResp) {
		// Try alternative offset calculation
		dataStart = 8 // Typically right after the header fields
		if dataStart+int(outputLength) > len(queryResp) {
			return nil, fmt.Errorf("security descriptor offset out of range")
		}
	}

	return queryResp[dataStart : dataStart+int(outputLength)], nil
}

// SetTimes sets the file timestamps (timestomping)
// Pass nil for any time you don't want to change
func (f *File) SetTimes(created, accessed, modified *time.Time) error {
	// Build FILE_BASIC_INFORMATION structure (40 bytes)
	// CreationTime (8), LastAccessTime (8), LastWriteTime (8), ChangeTime (8), FileAttributes (4)
	info := make([]byte, 40)

	if created != nil {
		binary.LittleEndian.PutUint64(info[0:8], timeToFiletime(*created))
	}
	if accessed != nil {
		binary.LittleEndian.PutUint64(info[8:16], timeToFiletime(*accessed))
	}
	if modified != nil {
		binary.LittleEndian.PutUint64(info[16:24], timeToFiletime(*modified))
		// ChangeTime typically matches LastWriteTime
		binary.LittleEndian.PutUint64(info[24:32], timeToFiletime(*modified))
	}
	// FileAttributes = 0 means don't change
	binary.LittleEndian.PutUint32(info[32:36], 0)

	// Build SET_INFO request
	// InfoType = 0x01 (File), FileInfoClass = 0x04 (FileBasicInformation)
	req := types.NewSetInfoRequest(f.fileID, 0x01, 0x04, info)

	// Build header
	header := types.NewHeader(types.CommandSetInfo, f.tree.session.nextMessageID())
	header.SessionID = f.tree.session.sessionID
	header.TreeID = f.tree.treeID

	// Send request
	resp, err := f.tree.session.sendRecv(header, req.Marshal())
	if err != nil {
		return fmt.Errorf("set info failed: %w", err)
	}

	// Parse response header
	var respHeader types.Header
	if err := respHeader.Unmarshal(resp[:types.SMB2HeaderSize]); err != nil {
		return fmt.Errorf("failed to parse response header: %w", err)
	}

	// Check status
	if !respHeader.Status.IsSuccess() {
		return StatusToError(respHeader.Status)
	}

	return nil
}

// timeToFiletime converts Go time to Windows FILETIME
func timeToFiletime(t time.Time) uint64 {
	// FILETIME is 100-nanosecond intervals since January 1, 1601
	const windowsEpochDiff = 116444736000000000 // 100-ns intervals from 1601 to 1970
	unixNano := t.UnixNano()
	return uint64(unixNano/100) + windowsEpochDiff
}
