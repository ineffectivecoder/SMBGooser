package smb

import (
	"context"
	"fmt"
	"time"

	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

// FileInfo represents information about a file or directory
type FileInfo struct {
	Name           string
	Size           int64
	IsDir          bool
	Attributes     types.FileAttributes
	CreationTime   time.Time
	LastAccessTime time.Time
	LastWriteTime  time.Time
	ChangeTime     time.Time
}

// ListDirectory lists the contents of a directory
func (t *Tree) ListDirectory(ctx context.Context, path string) ([]FileInfo, error) {
	return t.ListDirectoryWithPattern(ctx, path, "*")
}

// ListDirectoryWithPattern lists directory contents matching a pattern
func (t *Tree) ListDirectoryWithPattern(ctx context.Context, path, pattern string) ([]FileInfo, error) {
	// Open directory handle
	dir, err := t.OpenDirectory(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to open directory: %w", err)
	}
	defer dir.Close()

	var allFiles []FileInfo
	patternBytes := encoding.ToUTF16LE(pattern)
	isFirst := true

	for {
		// Build QUERY_DIRECTORY request
		req := types.NewQueryDirectoryRequest(dir.fileID, patternBytes, types.FileBothDirectoryInformation)
		if !isFirst {
			// Clear pattern for subsequent requests
			req.FileName = nil
			req.FileNameLength = 0
		}
		isFirst = false

		// Build header
		header := types.NewHeader(types.CommandQueryDirectory, t.session.nextMessageID())
		header.SessionID = t.session.sessionID
		header.TreeID = t.treeID

		// Send request
		resp, err := t.session.sendRecv(header, req.Marshal())
		if err != nil {
			return allFiles, fmt.Errorf("query directory failed: %w", err)
		}

		// Parse response header
		var respHeader types.Header
		if err := respHeader.Unmarshal(resp[:types.SMB2HeaderSize]); err != nil {
			return allFiles, fmt.Errorf("failed to parse response header: %w", err)
		}

		// Check for end of directory
		if respHeader.Status == types.StatusNoMoreFiles {
			break
		}
		if !respHeader.Status.IsSuccess() {
			return allFiles, StatusToError(respHeader.Status)
		}

		// Parse QUERY_DIRECTORY response
		var queryResp types.QueryDirectoryResponse
		if err := queryResp.Unmarshal(resp[types.SMB2HeaderSize:]); err != nil {
			return allFiles, fmt.Errorf("failed to parse query directory response: %w", err)
		}

		// Parse directory entries
		entries := types.ParseFileBothDirInfo(queryResp.OutputBuffer)
		for _, entry := range entries {
			// Skip . and ..
			if entry.FileName == "." || entry.FileName == ".." {
				continue
			}

			allFiles = append(allFiles, FileInfo{
				Name:           entry.FileName,
				Size:           int64(entry.EndOfFile),
				IsDir:          entry.FileAttributes&types.FileAttributeDirectory != 0,
				Attributes:     entry.FileAttributes,
				CreationTime:   filetimeToTime(entry.CreationTime),
				LastAccessTime: filetimeToTime(entry.LastAccessTime),
				LastWriteTime:  filetimeToTime(entry.LastWriteTime),
				ChangeTime:     filetimeToTime(entry.ChangeTime),
			})
		}

		// If we got fewer entries than expected, we're done
		if len(entries) == 0 {
			break
		}
	}

	return allFiles, nil
}

// Mkdir creates a directory
func (t *Tree) Mkdir(ctx context.Context, path string) error {
	pathBytes := encoding.ToUTF16LE(path)

	// Build CREATE request for directory
	req := types.NewCreateRequest(
		pathBytes,
		types.FileReadAttributes|types.Synchronize,
		types.FileCreate,
		types.FileDirectoryFile,
	)

	// Build header
	header := types.NewHeader(types.CommandCreate, t.session.nextMessageID())
	header.SessionID = t.session.sessionID
	header.TreeID = t.treeID

	// Send request
	resp, err := t.session.sendRecv(header, req.Marshal())
	if err != nil {
		return fmt.Errorf("create directory failed: %w", err)
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

	// Parse CREATE response to get file ID
	var createResp types.CreateResponse
	if err := createResp.Unmarshal(resp[types.SMB2HeaderSize:]); err != nil {
		return fmt.Errorf("failed to parse create response: %w", err)
	}

	// Close the handle immediately
	closeReq := types.NewCloseRequest(createResp.FileID)
	closeHeader := types.NewHeader(types.CommandClose, t.session.nextMessageID())
	closeHeader.SessionID = t.session.sessionID
	closeHeader.TreeID = t.treeID
	t.session.sendRecv(closeHeader, closeReq.Marshal())

	return nil
}

// Rmdir removes an empty directory
func (t *Tree) Rmdir(ctx context.Context, path string) error {
	return t.Delete(ctx, path, true)
}

// DeleteFile deletes a file
func (t *Tree) DeleteFile(ctx context.Context, path string) error {
	return t.Delete(ctx, path, false)
}

// Delete deletes a file or directory
func (t *Tree) Delete(ctx context.Context, path string, isDir bool) error {
	pathBytes := encoding.ToUTF16LE(path)

	// Build CREATE request with DELETE_ON_CLOSE
	options := types.FileDeleteOnClose
	if isDir {
		options |= types.FileDirectoryFile
	} else {
		options |= types.FileNonDirectoryFile
	}

	req := types.NewCreateRequest(
		pathBytes,
		types.Delete,
		types.FileOpen,
		options,
	)

	// Build header
	header := types.NewHeader(types.CommandCreate, t.session.nextMessageID())
	header.SessionID = t.session.sessionID
	header.TreeID = t.treeID

	// Send request
	resp, err := t.session.sendRecv(header, req.Marshal())
	if err != nil {
		return fmt.Errorf("delete failed: %w", err)
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

	// Parse CREATE response to get file ID
	var createResp types.CreateResponse
	if err := createResp.Unmarshal(resp[types.SMB2HeaderSize:]); err != nil {
		return fmt.Errorf("failed to parse create response: %w", err)
	}

	// Close the handle - this triggers deletion
	closeReq := types.NewCloseRequest(createResp.FileID)
	closeHeader := types.NewHeader(types.CommandClose, t.session.nextMessageID())
	closeHeader.SessionID = t.session.sessionID
	closeHeader.TreeID = t.treeID

	closeResp, err := t.session.sendRecv(closeHeader, closeReq.Marshal())
	if err != nil {
		return fmt.Errorf("close failed: %w", err)
	}

	var closeRespHeader types.Header
	if err := closeRespHeader.Unmarshal(closeResp[:types.SMB2HeaderSize]); err != nil {
		return fmt.Errorf("failed to parse close response header: %w", err)
	}

	if !closeRespHeader.Status.IsSuccess() {
		return StatusToError(closeRespHeader.Status)
	}

	return nil
}

// filetimeToTime converts Windows FILETIME to Go time.Time
func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	// FILETIME is 100-nanosecond intervals since January 1, 1601
	// Convert to Unix nanoseconds
	const windowsEpochDiff = 116444736000000000 // 100-ns intervals from 1601 to 1970
	unixNano := int64(ft-windowsEpochDiff) * 100
	return time.Unix(0, unixNano)
}
