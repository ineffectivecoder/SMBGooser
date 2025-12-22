package types

import (
	"errors"

	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// TreeConnectRequest represents an SMB2 TREE_CONNECT request
type TreeConnectRequest struct {
	StructureSize uint16 // 9
	Flags         uint16 // Reserved (SMB 3.1.1: SMB2_TREE_CONNECT_FLAG_*)
	PathOffset    uint16
	PathLength    uint16
	Path          []byte // UNC path (UTF-16LE)
}

// TreeConnectFlags (SMB 3.1.1)
const (
	TreeConnectFlagClusterReconnect uint16 = 0x0001
	TreeConnectFlagRedirectToOwner  uint16 = 0x0002
	TreeConnectFlagExtensionPresent uint16 = 0x0004
)

// NewTreeConnectRequest creates a tree connect request
func NewTreeConnectRequest(path []byte) *TreeConnectRequest {
	return &TreeConnectRequest{
		StructureSize: 9,
		Path:          path,
	}
}

// Marshal serializes the tree connect request
func (r *TreeConnectRequest) Marshal() []byte {
	// Fixed: 8 bytes, Variable: path
	// PathOffset is from start of SMB2 header
	r.PathOffset = SMB2HeaderSize + 8
	r.PathLength = uint16(len(r.Path))

	bufLen := 8 + len(r.Path)
	buf := make([]byte, bufLen)

	encoding.PutUint16LE(buf[0:2], r.StructureSize)
	encoding.PutUint16LE(buf[2:4], r.Flags)
	encoding.PutUint16LE(buf[4:6], r.PathOffset)
	encoding.PutUint16LE(buf[6:8], r.PathLength)
	copy(buf[8:], r.Path)

	return buf
}

// TreeConnectResponse represents an SMB2 TREE_CONNECT response
type TreeConnectResponse struct {
	StructureSize uint16 // 16
	ShareType     ShareType
	Reserved      uint8
	ShareFlags    uint32
	Capabilities  uint32
	MaximalAccess AccessMask
}

// Unmarshal deserializes a tree connect response
func (r *TreeConnectResponse) Unmarshal(buf []byte) error {
	if len(buf) < 16 {
		return errors.New("buffer too small for tree connect response")
	}

	r.StructureSize = encoding.Uint16LE(buf[0:2])
	if r.StructureSize != 16 {
		return errors.New("invalid tree connect response structure size")
	}

	r.ShareType = ShareType(buf[2])
	r.Reserved = buf[3]
	r.ShareFlags = encoding.Uint32LE(buf[4:8])
	r.Capabilities = encoding.Uint32LE(buf[8:12])
	r.MaximalAccess = AccessMask(encoding.Uint32LE(buf[12:16]))

	return nil
}

// TreeDisconnectRequest represents an SMB2 TREE_DISCONNECT request
type TreeDisconnectRequest struct {
	StructureSize uint16 // 4
	Reserved      uint16
}

// NewTreeDisconnectRequest creates a tree disconnect request
func NewTreeDisconnectRequest() *TreeDisconnectRequest {
	return &TreeDisconnectRequest{
		StructureSize: 4,
	}
}

// Marshal serializes the tree disconnect request
func (r *TreeDisconnectRequest) Marshal() []byte {
	buf := make([]byte, 4)
	encoding.PutUint16LE(buf[0:2], r.StructureSize)
	encoding.PutUint16LE(buf[2:4], r.Reserved)
	return buf
}

// TreeDisconnectResponse represents an SMB2 TREE_DISCONNECT response
type TreeDisconnectResponse struct {
	StructureSize uint16 // 4
	Reserved      uint16
}

// Unmarshal deserializes a tree disconnect response
func (r *TreeDisconnectResponse) Unmarshal(buf []byte) error {
	if len(buf) < 4 {
		return errors.New("buffer too small for tree disconnect response")
	}

	r.StructureSize = encoding.Uint16LE(buf[0:2])
	r.Reserved = encoding.Uint16LE(buf[2:4])
	return nil
}
