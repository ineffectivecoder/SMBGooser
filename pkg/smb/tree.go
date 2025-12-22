package smb

import (
	"context"
	"fmt"

	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

// Tree represents a connected share
type Tree struct {
	session   *Session
	treeID    uint32
	shareType types.ShareType
	shareName string
	maxAccess types.AccessMask
}

// TreeConnect connects to a share
func (s *Session) TreeConnect(ctx context.Context, shareName string) (*Tree, error) {
	if !s.isAuthenticated {
		return nil, ErrNotConnected
	}

	// Build UNC path: \\server\share
	// Get server from transport remote addr
	serverAddr := s.transport.RemoteAddr()
	if serverAddr == nil {
		return nil, ErrNotConnected
	}

	// Extract host from address (remove port)
	host := serverAddr.String()
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			host = host[:i]
			break
		}
	}

	uncPath := fmt.Sprintf("\\\\%s\\%s", host, shareName)
	pathBytes := encoding.ToUTF16LE(uncPath)

	// Build TREE_CONNECT request
	req := types.NewTreeConnectRequest(pathBytes)

	// Build header
	header := types.NewHeader(types.CommandTreeConnect, s.nextMessageID())
	header.SessionID = s.sessionID

	// Send request
	resp, err := s.sendRecv(header, req.Marshal())
	if err != nil {
		return nil, fmt.Errorf("tree connect failed: %w", err)
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

	// Parse TREE_CONNECT response
	var treeResp types.TreeConnectResponse
	if err := treeResp.Unmarshal(resp[types.SMB2HeaderSize:]); err != nil {
		return nil, fmt.Errorf("failed to parse tree connect response: %w", err)
	}

	return &Tree{
		session:   s,
		treeID:    respHeader.TreeID,
		shareType: treeResp.ShareType,
		shareName: shareName,
		maxAccess: treeResp.MaximalAccess,
	}, nil
}

// TreeDisconnect disconnects from a share
func (s *Session) TreeDisconnect(ctx context.Context, tree *Tree) error {
	if tree == nil {
		return nil
	}

	// Build TREE_DISCONNECT request
	req := types.NewTreeDisconnectRequest()

	// Build header
	header := types.NewHeader(types.CommandTreeDisconnect, s.nextMessageID())
	header.SessionID = s.sessionID
	header.TreeID = tree.treeID

	// Send request
	resp, err := s.sendRecv(header, req.Marshal())
	if err != nil {
		return fmt.Errorf("tree disconnect failed: %w", err)
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

// TreeID returns the tree ID
func (t *Tree) TreeID() uint32 {
	return t.treeID
}

// ShareType returns the share type
func (t *Tree) ShareType() types.ShareType {
	return t.shareType
}

// ShareName returns the share name
func (t *Tree) ShareName() string {
	return t.shareName
}

// MaximalAccess returns the maximal access rights
func (t *Tree) MaximalAccess() types.AccessMask {
	return t.maxAccess
}

// IsPipe returns true if this is an IPC$ (named pipe) share
func (t *Tree) IsPipe() bool {
	return t.shareType == types.ShareTypePipe
}

// IsDisk returns true if this is a disk share
func (t *Tree) IsDisk() bool {
	return t.shareType == types.ShareTypeDisk
}

// Session returns the parent session
func (t *Tree) Session() *Session {
	return t.session
}
