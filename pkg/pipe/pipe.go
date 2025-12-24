// Package pipe provides named pipe operations over SMB.
package pipe

import (
	"context"
	"fmt"

	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

// Pipe represents a named pipe connection
type Pipe struct {
	file *smb.File
	tree *smb.Tree
	name string
}

// Open opens a named pipe on the IPC$ share using standard pipe options
func Open(ctx context.Context, tree *smb.Tree, pipeName string) (*Pipe, error) {
	if !tree.IsPipe() {
		return nil, fmt.Errorf("tree is not an IPC$ share")
	}

	// Named pipes need specific access flags
	access := types.FileReadData | types.FileWriteData |
		types.FileReadEA | types.FileReadAttributes |
		types.ReadControl | types.Synchronize

	// Use OpenPipe which has correct CreateOptions for named pipes
	file, err := tree.OpenPipe(ctx, pipeName, access)
	if err != nil {
		return nil, fmt.Errorf("failed to open pipe %s: %w", pipeName, err)
	}

	return &Pipe{
		file: file,
		tree: tree,
		name: pipeName,
	}, nil
}

// OpenForRPC opens a named pipe for authenticated RPC (matches Impacket's openFile() exactly)
// Critical: Uses ShareAccess=FileShareRead only, not FileShareRead|FileShareWrite|FileShareDelete
func OpenForRPC(ctx context.Context, tree *smb.Tree, pipeName string) (*Pipe, error) {
	if !tree.IsPipe() {
		return nil, fmt.Errorf("tree is not an IPC$ share")
	}

	// Access flags matching Impacket's SMBConnection.openFile() defaults
	// desiredAccess = FILE_READ_DATA | FILE_WRITE_DATA
	access := types.FileReadData | types.FileWriteData

	// Use OpenFileImpacket with ShareAccess=FileShareRead to match Impacket exactly
	file, err := tree.OpenFileImpacket(ctx, pipeName, access, types.FileOpen)
	if err != nil {
		return nil, fmt.Errorf("failed to open pipe %s: %w", pipeName, err)
	}

	return &Pipe{
		file: file,
		tree: tree,
		name: pipeName,
	}, nil
}

// Read reads data from the pipe
// Named pipes MUST use offset 0, not tracked file offset!
func (p *Pipe) Read(buf []byte) (int, error) {
	return p.file.ReadAt(buf, 0)
}

// Write writes data to the pipe
// Named pipes MUST use offset 0, not tracked file offset!
func (p *Pipe) Write(data []byte) (int, error) {
	return p.file.WriteAt(data, 0)
}

// Transact performs a write followed by read (common for RPC)
func (p *Pipe) Transact(request []byte) ([]byte, error) {
	// Write request
	_, err := p.Write(request)
	if err != nil {
		return nil, fmt.Errorf("transact write failed: %w", err)
	}

	// Read response (use reasonable buffer size)
	response := make([]byte, 65536)
	n, err := p.Read(response)
	if err != nil {
		return nil, fmt.Errorf("transact read failed: %w", err)
	}

	return response[:n], nil
}

// Close closes the pipe
func (p *Pipe) Close() error {
	if p.file != nil {
		return p.file.Close()
	}
	return nil
}

// Name returns the pipe name
func (p *Pipe) Name() string {
	return p.name
}

// Tree returns the parent tree
func (p *Pipe) Tree() *smb.Tree {
	return p.tree
}
