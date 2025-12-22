// Package srvsvc implements the Server Service Remote Protocol (MS-SRVS)
// for session enumeration, share enumeration, and connected user discovery
package srvsvc

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
)

// SRVSVC UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188
var SRVSVC_UUID = dcerpc.UUID{
	0xc8, 0x4f, 0x32, 0x4b, // TimeLow (little-endian)
	0x70, 0x16, // TimeMid (little-endian)
	0xd3, 0x01, // TimeHiAndVersion (little-endian)
	0x12, 0x78, // ClockSeq
	0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88, // Node
}

// Opnums
const (
	OpNetShareEnum   = 15
	OpNetSessionEnum = 12
)

// Client is a SRVSVC RPC client
type Client struct {
	rpc       *dcerpc.Client
	pipe      *pipe.Pipe
	tree      *smb.Tree
	smbClient *smb.Client
}

// SessionInfo represents a connected session
type SessionInfo struct {
	ClientName string
	UserName   string
	NumOpens   uint32
	Time       uint32
	IdleTime   uint32
}

// ShareInfo represents a network share
type ShareInfo struct {
	Name   string
	Type   uint32
	Remark string
}

// NewClient creates a new SRVSVC client
func NewClient(smbClient *smb.Client) (*Client, error) {
	ctx := context.Background()

	// Get IPC$ tree (creates new tree each time per Impacket pattern)
	tree, err := smbClient.GetIPCTree(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get IPC$ tree: %w", err)
	}

	// Open srvsvc pipe
	p, err := pipe.Open(ctx, tree, "srvsvc")
	if err != nil {
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to open srvsvc pipe: %w", err)
	}

	// Create RPC client
	rpc := dcerpc.NewClient(p)

	// Bind to SRVSVC interface
	if err := rpc.Bind(SRVSVC_UUID, 3); err != nil {
		p.Close()
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to bind to SRVSVC: %w", err)
	}

	return &Client{
		rpc:       rpc,
		pipe:      p,
		tree:      tree,
		smbClient: smbClient,
	}, nil
}

// EnumSessions enumerates active sessions
func (c *Client) EnumSessions(serverName string) ([]SessionInfo, error) {
	stub := encodeNetSessionEnum(serverName, 10)

	resp, err := c.rpc.Call(OpNetSessionEnum, stub)
	if err != nil {
		return nil, fmt.Errorf("NetSessionEnum failed: %w", err)
	}

	return parseSessionEnumResponse(resp)
}

// EnumShares enumerates shares
func (c *Client) EnumShares(serverName string) ([]ShareInfo, error) {
	stub := encodeNetShareEnum(serverName, 1)

	resp, err := c.rpc.Call(OpNetShareEnum, stub)
	if err != nil {
		return nil, fmt.Errorf("NetShareEnum failed: %w", err)
	}

	return parseShareEnumResponse(resp)
}

// Close closes the client and disconnects the IPC$ tree
func (c *Client) Close() error {
	if c.rpc != nil {
		c.rpc.Close()
	}
	if c.pipe != nil {
		c.pipe.Close()
	}
	// Disconnect the IPC$ tree (following Impacket pattern)
	if c.tree != nil && c.smbClient != nil {
		c.smbClient.TreeDisconnect(context.Background(), c.tree)
	}
	return nil
}

func encodeNetSessionEnum(serverName string, level uint32) []byte {
	stub := make([]byte, 0, 64)

	// ServerName - null for local
	stub = appendUint32(stub, 0) // Null pointer

	// ClientName - null for all
	stub = appendUint32(stub, 0)

	// UserName - null for all
	stub = appendUint32(stub, 0)

	// InfoStruct
	stub = appendUint32(stub, level)      // Level
	stub = appendUint32(stub, level)      // Switch
	stub = appendUint32(stub, 0x00020004) // Pointer to container
	stub = appendUint32(stub, 0)          // EntriesRead
	stub = appendUint32(stub, 0)          // Buffer null

	// PrefMaxLen
	stub = appendUint32(stub, 0xFFFFFFFF)

	// ResumeHandle
	stub = appendUint32(stub, 0x00020008)
	stub = appendUint32(stub, 0)

	return stub
}

func encodeNetShareEnum(serverName string, level uint32) []byte {
	stub := make([]byte, 0, 48)

	// ServerName
	stub = appendUint32(stub, 0)

	// InfoStruct
	stub = appendUint32(stub, level)
	stub = appendUint32(stub, level)
	stub = appendUint32(stub, 0x00020004)
	stub = appendUint32(stub, 0)
	stub = appendUint32(stub, 0)

	// PrefMaxLen
	stub = appendUint32(stub, 0xFFFFFFFF)

	// ResumeHandle
	stub = appendUint32(stub, 0x00020008)
	stub = appendUint32(stub, 0)

	return stub
}

func parseSessionEnumResponse(resp []byte) ([]SessionInfo, error) {
	// Response format: Level(4) + InfoStruct ptr(4) + EntriesRead(4) + TotalEntries(4) + ResumeHandle ptr(4) + ErrorCode(4)
	// Then deferred data with SESSION_INFO_10 array

	if len(resp) < 24 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	var sessions []SessionInfo

	// Skip Level (4) + InfoStruct ptr (4)
	offset := 8

	// EntriesRead
	entriesRead := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// TotalEntries
	offset += 4

	// Skip ResumeHandle ptr (4)
	offset += 4

	if entriesRead == 0 || entriesRead > 100 {
		return sessions, nil
	}

	// Deferred data: MaxCount(4) + array of SESSION_INFO_10
	// Each SESSION_INFO_10: cname ptr(4) + username ptr(4) + time(4) + idle_time(4)
	if offset+4 > len(resp)-4 {
		return sessions, nil
	}
	offset += 4 // MaxCount

	// Read pointer entries (each has 4 pointers + 2 uint32s = 16 bytes per entry)
	// But for level 10, it's: cname_ptr(4) + username_ptr(4) + time(4) + idle_time(4)
	type sessionEntry struct {
		time     uint32
		idleTime uint32
	}
	var entries []sessionEntry

	for i := uint32(0); i < entriesRead && offset+16 <= len(resp); i++ {
		// Skip cname ptr and username ptr
		offset += 8
		// Read time and idle_time
		t := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
		it := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
		entries = append(entries, sessionEntry{time: t, idleTime: it})
	}

	// Parse deferred string data (cname then username for each entry)
	for i := range entries {
		session := SessionInfo{Time: entries[i].time, IdleTime: entries[i].idleTime}

		// Parse cname (conformant varying string)
		if offset+12 > len(resp)-4 {
			break
		}
		offset += 8 // Skip MaxCount + Offset
		actualCount := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
		strBytes := int(actualCount) * 2
		if strBytes > 0 && offset+strBytes <= len(resp) {
			session.ClientName = decodeUTF16LE(resp[offset : offset+strBytes])
			offset += strBytes
			for offset%4 != 0 && offset < len(resp) {
				offset++
			}
		}

		// Parse username
		if offset+12 > len(resp)-4 {
			sessions = append(sessions, session)
			break
		}
		offset += 8 // Skip MaxCount + Offset
		actualCount = binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
		strBytes = int(actualCount) * 2
		if strBytes > 0 && offset+strBytes <= len(resp) {
			session.UserName = decodeUTF16LE(resp[offset : offset+strBytes])
			offset += strBytes
			for offset%4 != 0 && offset < len(resp) {
				offset++
			}
		}

		sessions = append(sessions, session)
	}

	return sessions, nil
}

func parseShareEnumResponse(resp []byte) ([]ShareInfo, error) {
	// Response format: Level(4) + InfoStruct ptr(4) + EntriesRead(4) + TotalEntries(4) + ResumeHandle ptr(4) + ErrorCode(4)
	// Then deferred data with SHARE_INFO_1 array

	if len(resp) < 24 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	var shares []ShareInfo

	// Skip Level (4) + InfoStruct ptr (4)
	offset := 8

	// EntriesRead
	entriesRead := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// TotalEntries
	offset += 4

	// Skip ResumeHandle ptr (4)
	offset += 4

	if entriesRead == 0 || entriesRead > 100 {
		return shares, nil
	}

	// Deferred data: MaxCount(4) + array of SHARE_INFO_1
	// Each SHARE_INFO_1: netname ptr(4) + type(4) + remark ptr(4)
	if offset+4 > len(resp)-4 {
		return shares, nil
	}
	offset += 4 // MaxCount

	// Read fixed entries
	var types []uint32
	for i := uint32(0); i < entriesRead && offset+12 <= len(resp); i++ {
		offset += 4 // netname ptr
		shareType := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
		offset += 4 // remark ptr
		types = append(types, shareType)
	}

	// Parse deferred string data
	for i := range types {
		share := ShareInfo{Type: types[i]}

		// Parse netname
		if offset+12 > len(resp)-4 {
			break
		}
		offset += 8 // Skip MaxCount + Offset
		actualCount := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
		strBytes := int(actualCount) * 2
		if strBytes > 0 && offset+strBytes <= len(resp) {
			share.Name = decodeUTF16LE(resp[offset : offset+strBytes])
			offset += strBytes
			for offset%4 != 0 && offset < len(resp) {
				offset++
			}
		}

		// Parse remark
		if offset+12 > len(resp)-4 {
			shares = append(shares, share)
			continue
		}
		offset += 8 // Skip MaxCount + Offset
		actualCount = binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
		strBytes = int(actualCount) * 2
		if strBytes > 0 && offset+strBytes <= len(resp) {
			share.Remark = decodeUTF16LE(resp[offset : offset+strBytes])
			offset += strBytes
			for offset%4 != 0 && offset < len(resp) {
				offset++
			}
		}

		shares = append(shares, share)
	}

	return shares, nil
}

// decodeUTF16LE decodes UTF-16LE bytes to string
func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	u16 := make([]uint16, len(data)/2)
	for i := 0; i < len(data)/2; i++ {
		u16[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	// Remove null terminators
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	runes := make([]rune, len(u16))
	for i, v := range u16 {
		runes[i] = rune(v)
	}
	return string(runes)
}

func appendUint32(buf []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return append(buf, b...)
}
