// Tree implements SMB1 tree connect operations
package smb1

import (
	"encoding/binary"
	"fmt"
)

// TreeConnectAndXRequest represents a TREE_CONNECT_ANDX request
type TreeConnectAndXRequest struct {
	AndXCommand  uint8
	AndXReserved uint8
	AndXOffset   uint16
	Flags        uint16
	PasswordLen  uint16
	Password     []byte
	Path         string
	Service      string
}

// Service types
const (
	ServiceDisk    = "A:"
	ServicePrinter = "LPT1:"
	ServicePipe    = "IPC"
	ServiceAny     = "?????"
)

// Marshal serializes the tree connect request
func (r *TreeConnectAndXRequest) Marshal() []byte {
	// Word count = 4
	wordCount := 4

	// Build path and service as null-terminated strings
	// Path needs padding for Unicode alignment after password
	pathBytes := make([]byte, 0, len(r.Path)*2+2)
	for _, c := range r.Path {
		pathBytes = append(pathBytes, byte(c), 0)
	}
	pathBytes = append(pathBytes, 0, 0) // Null terminator

	serviceBytes := append([]byte(r.Service), 0)

	// Parameters
	params := make([]byte, wordCount*2)
	offset := 0
	params[offset] = 0xFF // No AndX
	offset++
	params[offset] = 0 // Reserved
	offset++
	binary.LittleEndian.PutUint16(params[offset:], 0) // AndX offset
	offset += 2
	binary.LittleEndian.PutUint16(params[offset:], r.Flags)
	offset += 2
	binary.LittleEndian.PutUint16(params[offset:], r.PasswordLen)

	// Build data section
	data := make([]byte, 0, int(r.PasswordLen)+len(pathBytes)+len(serviceBytes)+1)
	data = append(data, r.Password...)
	// Padding for Unicode alignment if needed
	if len(data)%2 != 0 {
		data = append(data, 0)
	}
	data = append(data, pathBytes...)
	data = append(data, serviceBytes...)

	// Combine everything
	buf := make([]byte, 1+len(params)+2+len(data))
	buf[0] = uint8(wordCount)
	copy(buf[1:], params)
	binary.LittleEndian.PutUint16(buf[1+len(params):], uint16(len(data)))
	copy(buf[1+len(params)+2:], data)

	return buf
}

// TreeConnectAndXResponse represents a TREE_CONNECT_ANDX response
type TreeConnectAndXResponse struct {
	WordCount        uint8
	AndXCommand      uint8
	AndXReserved     uint8
	AndXOffset       uint16
	OptionalSupport  uint16
	Service          string
	NativeFileSystem string
}

// Unmarshal parses the tree connect response
func (r *TreeConnectAndXResponse) Unmarshal(buf []byte) error {
	if len(buf) < 1 {
		return fmt.Errorf("buffer too short")
	}

	r.WordCount = buf[0]
	if r.WordCount < 3 {
		return fmt.Errorf("unexpected word count: %d", r.WordCount)
	}

	offset := 1
	r.AndXCommand = buf[offset]
	offset++
	r.AndXReserved = buf[offset]
	offset++
	r.AndXOffset = binary.LittleEndian.Uint16(buf[offset:])
	offset += 2
	r.OptionalSupport = binary.LittleEndian.Uint16(buf[offset:])
	offset += 2

	// Skip additional words if present
	if r.WordCount > 3 {
		offset += (int(r.WordCount) - 3) * 2
	}

	// ByteCount
	if offset+2 > len(buf) {
		return nil
	}
	byteCount := binary.LittleEndian.Uint16(buf[offset:])
	offset += 2
	_ = byteCount

	// Service (ASCII null-terminated)
	for i := offset; i < len(buf); i++ {
		if buf[i] == 0 {
			r.Service = string(buf[offset:i])
			offset = i + 1
			break
		}
	}

	// NativeFileSystem (Unicode null-terminated) - skip for now
	return nil
}

// Tree represents an SMB1 tree (share) connection
type Tree struct {
	TID     uint16
	Service string
	client  *Client
}

// TreeDisconnect disconnects from a share
func (c *Client) TreeDisconnect(tid uint16) error {
	header := NewHeader(CommandTreeDisconnect, c.nextMID())
	header.UID = c.uid
	header.TID = tid

	// SMB_COM_TREE_DISCONNECT has no parameters
	// WordCount = 0, ByteCount = 0
	params := []byte{0, 0, 0}

	msg := append(header.Marshal(), params...)

	resp, err := c.transport.SendRecv(msg)
	if err != nil {
		return fmt.Errorf("tree disconnect failed: %w", err)
	}

	var respHeader Header
	if err := respHeader.Unmarshal(resp); err != nil {
		return err
	}

	if !respHeader.IsSuccess() {
		return fmt.Errorf("tree disconnect error: 0x%08X", respHeader.Status)
	}

	return nil
}

// TreeConnectFull connects to a share and returns a Tree object
func (c *Client) TreeConnectFull(path string, service string) (*Tree, error) {
	req := &TreeConnectAndXRequest{
		Flags:       0x0008, // TREE_CONNECT_ANDX_DISCONNECT_TID
		PasswordLen: 1,
		Password:    []byte{0},
		Path:        path,
		Service:     service,
	}

	header := NewHeader(CommandTreeConnectAndX, c.nextMID())
	header.UID = c.uid

	headerBytes := header.Marshal()
	reqBytes := req.Marshal()
	msg := append(headerBytes, reqBytes...)

	resp, err := c.transport.SendRecv(msg)
	if err != nil {
		return nil, fmt.Errorf("tree connect failed: %w", err)
	}

	var respHeader Header
	if err := respHeader.Unmarshal(resp); err != nil {
		return nil, fmt.Errorf("failed to parse response header: %w", err)
	}

	if !respHeader.IsSuccess() {
		return nil, fmt.Errorf("tree connect error: 0x%08X", respHeader.Status)
	}

	var treeResp TreeConnectAndXResponse
	if err := treeResp.Unmarshal(resp[HeaderSize:]); err != nil {
		return nil, err
	}

	c.tid = respHeader.TID

	return &Tree{
		TID:     respHeader.TID,
		Service: treeResp.Service,
		client:  c,
	}, nil
}

// CreateFile opens a file on this tree
func (t *Tree) CreateFile(path string, desiredAccess, shareAccess, disposition, createOptions uint32) (*File, error) {
	// Temporarily set the tree's TID
	oldTID := t.client.tid
	t.client.tid = t.TID
	defer func() { t.client.tid = oldTID }()

	return t.client.CreateFile(path, desiredAccess, shareAccess, disposition, createOptions)
}

// Disconnect disconnects from this tree
func (t *Tree) Disconnect() error {
	return t.client.TreeDisconnect(t.TID)
}
