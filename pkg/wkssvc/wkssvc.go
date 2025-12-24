// Package wkssvc implements the Workstation Service Remote Protocol (MS-WKST)
// for enumerating logged-on users
package wkssvc

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
)

// WKSSVC UUID: 6bffd098-a112-3610-9833-46c3f87e345a
var WKSSVC_UUID = dcerpc.UUID{
	0x98, 0xd0, 0xff, 0x6b, // TimeLow (little-endian)
	0x12, 0xa1, // TimeMid (little-endian)
	0x10, 0x36, // TimeHiAndVersion (little-endian)
	0x98, 0x33, // ClockSeq
	0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a, // Node
}

// Opnums
const (
	OpNetrWkstaUserEnum = 2
	OpNetrWkstaGetInfo  = 0
)

// Client is a WKSSVC client
type Client struct {
	rpc       *dcerpc.Client
	pipe      *pipe.Pipe
	tree      *smb.Tree
	smbClient *smb.Client
}

// LoggedOnUser represents a logged-on user
type LoggedOnUser struct {
	UserName    string
	LogonDomain string
	LogonServer string
}

// WorkstationInfo represents workstation information
type WorkstationInfo struct {
	ComputerName string
	Domain       string
}

// NewClient creates a new WKSSVC client
func NewClient(smbClient *smb.Client) (*Client, error) {
	ctx := context.Background()

	// Get cached IPC$ tree
	tree, err := smbClient.GetIPCTree(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get IPC$ tree: %w", err)
	}

	// Open wkssvc pipe
	p, err := pipe.Open(ctx, tree, "wkssvc")
	if err != nil {
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to open wkssvc pipe: %w", err)
	}

	// Create RPC client
	rpc := dcerpc.NewClient(p)

	// Bind to WKSSVC interface
	if err := rpc.Bind(WKSSVC_UUID, 1); err != nil {
		p.Close()
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to bind to WKSSVC: %w", err)
	}

	return &Client{
		rpc:       rpc,
		pipe:      p,
		tree:      tree,
		smbClient: smbClient,
	}, nil
}

// EnumLoggedOnUsers enumerates logged-on users
func (c *Client) EnumLoggedOnUsers(serverName string) ([]LoggedOnUser, error) {
	stub := encodeNetrWkstaUserEnum(serverName, 1)

	resp, err := c.rpc.Call(OpNetrWkstaUserEnum, stub)
	if err != nil {
		return nil, fmt.Errorf("NetrWkstaUserEnum failed: %w", err)
	}

	return parseWkstaUserEnumResponse(resp)
}

// GetWorkstationInfo gets workstation info
func (c *Client) GetWorkstationInfo(serverName string) (*WorkstationInfo, error) {
	stub := encodeNetrWkstaGetInfo(serverName, 100)

	resp, err := c.rpc.Call(OpNetrWkstaGetInfo, stub)
	if err != nil {
		return nil, fmt.Errorf("NetrWkstaGetInfo failed: %w", err)
	}

	return parseWkstaGetInfoResponse(resp)
}

// Close closes the client
func (c *Client) Close() error {
	if c.rpc != nil {
		c.rpc.Close()
	}
	if c.pipe != nil {
		c.pipe.Close()
	}
	if c.tree != nil && c.smbClient != nil {
		c.smbClient.TreeDisconnect(context.Background(), c.tree)
	}
	return nil
}

func encodeNetrWkstaUserEnum(serverName string, level uint32) []byte {
	stub := make([]byte, 0, 48)

	// ServerName - null for local
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

func encodeNetrWkstaGetInfo(serverName string, level uint32) []byte {
	stub := make([]byte, 0, 16)
	stub = appendUint32(stub, 0) // ServerName null
	stub = appendUint32(stub, level)
	return stub
}

func parseWkstaUserEnumResponse(resp []byte) ([]LoggedOnUser, error) {
	// Response format (NetrWkstaUserEnum level 1):
	// 0-3:   Level (4)
	// 4-7:   InfoStruct level (4)
	// 8-11:  Container Ptr (4)
	// 12-15: EntriesRead (4)
	// 16-19: Array Ptr (4)
	// 20-23: TotalEntries (4)
	// 24+:   Pointer referent IDs
	// Then string data

	if len(resp) < 24 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	var users []LoggedOnUser

	// EntriesRead at offset 12
	entriesRead := binary.LittleEndian.Uint32(resp[12:16])

	if entriesRead == 0 || entriesRead > 100 {
		return users, nil
	}

	// Find where string data starts by scanning for valid conformant varying string header
	offset := 24 // Start after fixed header
	for offset+12 <= len(resp) {
		maxCount := binary.LittleEndian.Uint32(resp[offset:])
		nextVal := binary.LittleEndian.Uint32(resp[offset+4:])
		actualCount := binary.LittleEndian.Uint32(resp[offset+8:])
		// Valid string header: MaxCount > 0 && MaxCount < 100, Offset = 0, ActualCount = MaxCount
		if maxCount > 0 && maxCount < 100 && nextVal == 0 && actualCount == maxCount {
			break
		}
		offset += 4
	}

	// Parse strings - each WKSTA_USER_INFO_1 has 4 strings: username, logon_domain, oth_domains, logon_server
	for i := uint32(0); i < entriesRead && offset+12 <= len(resp); i++ {
		user := LoggedOnUser{}

		for j := 0; j < 4 && offset+12 <= len(resp); j++ {
			// Conformant varying string: MaxCount(4) + Offset(4) + ActualCount(4) + Data
			maxCount := binary.LittleEndian.Uint32(resp[offset:])
			stringOffset := binary.LittleEndian.Uint32(resp[offset+4:])
			actualCount := binary.LittleEndian.Uint32(resp[offset+8:])

			// Validate this looks like a string header
			if maxCount > 100 || actualCount > 100 || stringOffset != 0 {
				offset += 4
				j-- // Retry this slot
				continue
			}

			offset += 12 // Skip header

			strBytes := int(actualCount) * 2
			if strBytes > 0 && offset+strBytes <= len(resp) {
				str := decodeUTF16LE(resp[offset : offset+strBytes])
				switch j {
				case 0:
					user.UserName = str
				case 1:
					user.LogonDomain = str
				case 3:
					user.LogonServer = str
				}
				offset += strBytes
				// Align to 4 bytes
				for offset%4 != 0 && offset < len(resp) {
					offset++
				}
			}
		}

		if user.UserName != "" {
			users = append(users, user)
		}
	}

	return users, nil
}

// decodeUTF16LE decodes UTF-16LE bytes to string
// Stops at first null terminator to avoid garbage data
func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	u16 := make([]uint16, len(data)/2)
	for i := 0; i < len(data)/2; i++ {
		u16[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	// Find first null terminator and stop there
	for i, v := range u16 {
		if v == 0 {
			u16 = u16[:i]
			break
		}
	}
	runes := make([]rune, len(u16))
	for i, v := range u16 {
		runes[i] = rune(v)
	}
	return string(runes)
}

func parseWkstaGetInfoResponse(resp []byte) (*WorkstationInfo, error) {
	// Response format for level 100:
	// [0-3]   Level (4)
	// [4-7]   Info ptr (4)
	// [8-11]  platform_id (4)
	// [12-15] computername_ptr (4)
	// [16-19] langroup_ptr (4)
	// [20-23] ver_major (4)
	// [24-27] ver_minor (4)
	// Then deferred string data for computername and langroup

	if len(resp) < 28 {
		return &WorkstationInfo{ComputerName: "Unknown", Domain: "Unknown"}, nil
	}

	info := &WorkstationInfo{}

	// Find where string data starts by scanning for valid string header
	offset := 28 // Start after fixed header
	for offset+12 <= len(resp) {
		maxCount := binary.LittleEndian.Uint32(resp[offset:])
		nextVal := binary.LittleEndian.Uint32(resp[offset+4:])
		actualCount := binary.LittleEndian.Uint32(resp[offset+8:])
		if maxCount > 0 && maxCount < 100 && nextVal == 0 && actualCount == maxCount {
			break
		}
		offset += 4
	}

	// Parse computer name
	if offset+12 <= len(resp) {
		offset += 8 // Skip MaxCount + Offset
		actualCount := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
		strBytes := int(actualCount) * 2
		if strBytes > 0 && offset+strBytes <= len(resp) {
			info.ComputerName = decodeUTF16LE(resp[offset : offset+strBytes])
			offset += strBytes
			for offset%4 != 0 && offset < len(resp) {
				offset++
			}
		}
	}

	// Parse domain/langroup
	if offset+12 <= len(resp) {
		offset += 8 // Skip MaxCount + Offset
		actualCount := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
		strBytes := int(actualCount) * 2
		if strBytes > 0 && offset+strBytes <= len(resp) {
			info.Domain = decodeUTF16LE(resp[offset : offset+strBytes])
		}
	}

	if info.ComputerName == "" {
		info.ComputerName = "Unknown"
	}
	if info.Domain == "" {
		info.Domain = "Unknown"
	}

	return info, nil
}

func appendUint32(buf []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return append(buf, b...)
}
