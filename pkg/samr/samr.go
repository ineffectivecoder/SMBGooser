package samr

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
)

// Client represents a SAMR RPC client
type Client struct {
	rpc          *dcerpc.Client
	pipe         *pipe.Pipe
	tree         *smb.Tree
	smbClient    *smb.Client
	serverHandle Handle
	domainHandle Handle
	domainSID    []byte
}

// NewClient creates a new SAMR client
func NewClient(ctx context.Context, smbClient *smb.Client) (*Client, error) {
	// Get cached IPC$ tree
	tree, err := smbClient.GetIPCTree(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get IPC$ tree: %w", err)
	}

	// Open samr pipe
	p, err := pipe.Open(ctx, tree, "samr")
	if err != nil {
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to open samr pipe: %w", err)
	}

	// Create RPC client
	rpc := dcerpc.NewClient(p)

	// Bind to SAMR interface
	if err := rpc.Bind(SAMR_UUID, 1); err != nil {
		p.Close()
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to bind to SAMR: %w", err)
	}

	return &Client{
		rpc:       rpc,
		pipe:      p,
		tree:      tree,
		smbClient: smbClient,
	}, nil
}

// Connect connects to the SAM server
func (c *Client) Connect() error {
	stub := encodeConnect()

	resp, err := c.rpc.Call(OpSamrConnect, stub)
	if err != nil {
		return fmt.Errorf("SamrConnect failed: %w", err)
	}

	if len(resp) < 24 {
		return fmt.Errorf("invalid response size: %d", len(resp))
	}

	copy(c.serverHandle[:], resp[:20])

	retCode := binary.LittleEndian.Uint32(resp[20:24])
	if retCode != 0 {
		return fmt.Errorf("SamrConnect returned error: 0x%08X", retCode)
	}

	return nil
}

// EnumerateDomains enumerates available domains and returns their names
// This uses the NetBIOS domain names which are what SAMR requires
func (c *Client) EnumerateDomains() ([]string, error) {
	// SamrEnumerateDomainsInSamServer request:
	// - ServerHandle (20 bytes)
	// - EnumerationContext (4 bytes) = 0
	// - PreferedMaximumLength (4 bytes) = 65536
	stub := make([]byte, 28)
	copy(stub[0:20], c.serverHandle[:])
	binary.LittleEndian.PutUint32(stub[20:], 0)     // EnumerationContext
	binary.LittleEndian.PutUint32(stub[24:], 65536) // PreferedMaximumLength

	resp, err := c.rpc.Call(OpSamrEnumerateDomainsInSamServer, stub)
	if err != nil {
		return nil, fmt.Errorf("SamrEnumerateDomainsInSamServer failed: %w", err)
	}

	// Parse response - contains list of domain names
	// Response: EnumerationContext(4) + Buffer(ptr) + CountReturned(4) + ErrorCode(4)
	var domains []string
	if len(resp) < 16 {
		return domains, nil
	}

	// Skip EnumerationContext
	offset := 4

	// Check buffer pointer
	bufferPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if bufferPtr == 0 {
		return domains, nil
	}

	// CountReturned
	countReturned := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// Skip to buffer content (after error code check)
	if countReturned > 0 && offset+8 < len(resp) {
		// Parse SAMPR_ENUMERATION_BUFFER
		entriesRead := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		// Array pointer
		offset += 4

		// MaxCount
		if offset+4 < len(resp) {
			offset += 4
		}

		// Parse each entry: RelativeId (4) + RPC_UNICODE_STRING (8)
		for i := uint32(0); i < entriesRead && offset+12 < len(resp)-4; i++ {
			// Skip RelativeId (not used for domain names)
			offset += 4

			// RPC_UNICODE_STRING: Length(2) + MaxLen(2) + Ptr(4)
			strLen := binary.LittleEndian.Uint16(resp[offset:])
			offset += 8 // Skip Length + MaxLen + Ptr

			if strLen == 0 {
				domains = append(domains, "")
			}
		}

		// Parse string data (deferred)
		for i := uint32(0); i < entriesRead && offset < len(resp)-4; i++ {
			// Conformant varying array: MaxCount(4) + Offset(4) + ActualCount(4) + Data
			if offset+12 > len(resp)-4 {
				break
			}

			// Skip MaxCount, Offset
			offset += 8

			actualCount := binary.LittleEndian.Uint32(resp[offset:])
			offset += 4

			// Read string data
			strBytes := int(actualCount) * 2
			if offset+strBytes <= len(resp)-4 {
				name := decodeUTF16LE(resp[offset : offset+strBytes])
				domains = append(domains, name)
				offset += strBytes

				// Align to 4 bytes
				for offset%4 != 0 && offset < len(resp) {
					offset++
				}
			}
		}
	}

	return domains, nil
}

// LookupDomain looks up a domain by name and gets its SID
func (c *Client) LookupDomain(domainName string) error {
	stub := encodeLookupDomain(c.serverHandle, domainName)

	resp, err := c.rpc.Call(OpSamrLookupDomainInServer, stub)
	if err != nil {
		return fmt.Errorf("SamrLookupDomainInSamServer failed: %w", err)
	}

	// Response format (PRPC_SID + ErrorCode):
	// - ReferentID (4 bytes) - pointer reference
	// - MaxCount (4 bytes) - conformant array count (= SubAuthorityCount)
	// - Revision (1 byte)
	// - SubAuthorityCount (1 byte)
	// - IdentifierAuthority (6 bytes)
	// - SubAuthority[] (4 bytes each)
	// - ErrorCode (4 bytes)

	// Minimum response: 4 + 4 + 8 + 4 = 20 bytes (for SID with 0 sub-authorities)
	if len(resp) < 12 {
		return fmt.Errorf("response too short: %d bytes", len(resp))
	}

	// Check error code at the end
	errorCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if errorCode != 0 {
		return fmt.Errorf("LookupDomain returned error: 0x%08X", errorCode)
	}

	// Check for NULL pointer (domain not found)
	referentID := binary.LittleEndian.Uint32(resp[0:4])
	if referentID == 0 {
		return fmt.Errorf("domain not found")
	}

	// MaxCount for conformant array
	offset := 4
	if offset+4 > len(resp)-4 {
		return fmt.Errorf("invalid response: missing MaxCount")
	}
	// maxCount := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// Now parse RPC_SID body
	if offset+2 > len(resp)-4 {
		return fmt.Errorf("invalid response: missing SID header")
	}

	revision := resp[offset]
	subAuthCount := resp[offset+1]

	// Validate
	if revision != 1 {
		return fmt.Errorf("invalid SID revision: %d", revision)
	}

	// Calculate SID length: 8 bytes header + 4*subAuthCount
	sidLen := 8 + 4*int(subAuthCount)
	if offset+sidLen > len(resp)-4 {
		return fmt.Errorf("invalid response: SID truncated")
	}

	// Store the domain SID (binary format)
	c.domainSID = make([]byte, sidLen)
	copy(c.domainSID, resp[offset:offset+sidLen])

	return nil
}

// OpenDomain opens a domain for enumeration
func (c *Client) OpenDomain() error {
	if len(c.domainSID) == 0 {
		return fmt.Errorf("domain SID not set - call LookupDomain first")
	}

	stub := encodeOpenDomain(c.serverHandle, c.domainSID)

	resp, err := c.rpc.Call(OpSamrOpenDomain, stub)
	if err != nil {
		return fmt.Errorf("SamrOpenDomain failed: %w", err)
	}

	if len(resp) < 24 {
		return fmt.Errorf("invalid response size")
	}

	copy(c.domainHandle[:], resp[:20])

	retCode := binary.LittleEndian.Uint32(resp[20:24])
	if retCode != 0 {
		return fmt.Errorf("SamrOpenDomain returned error: 0x%08X", retCode)
	}

	return nil
}

// EnumerateUsers enumerates users in the domain
func (c *Client) EnumerateUsers() ([]UserInfo, error) {
	stub := encodeEnumerateUsers(c.domainHandle)

	resp, err := c.rpc.Call(OpSamrEnumerateUsersInDom, stub)
	if err != nil {
		return nil, fmt.Errorf("SamrEnumerateUsersInDomain failed: %w", err)
	}

	return parseEnumerateUsersResponse(resp)
}

// EnumerateGroups enumerates groups in the domain
func (c *Client) EnumerateGroups() ([]GroupInfo, error) {
	stub := encodeEnumerateGroups(c.domainHandle)

	resp, err := c.rpc.Call(OpSamrEnumerateGroupsInDom, stub)
	if err != nil {
		return nil, fmt.Errorf("SamrEnumerateGroupsInDomain failed: %w", err)
	}

	return parseEnumerateGroupsResponse(resp)
}

// Close closes the client
func (c *Client) Close() error {
	// Close domain handle
	if c.domainHandle != (Handle{}) {
		c.closeHandle(c.domainHandle)
	}
	// Close server handle
	if c.serverHandle != (Handle{}) {
		c.closeHandle(c.serverHandle)
	}
	if c.rpc != nil {
		c.rpc.Close()
	}
	if c.pipe != nil {
		c.pipe.Close()
	}
	// Disconnect IPC$ tree (Impacket pattern)
	if c.tree != nil && c.smbClient != nil {
		c.smbClient.TreeDisconnect(context.Background(), c.tree)
	}
	return nil
}

func (c *Client) closeHandle(handle Handle) {
	stub := make([]byte, 20)
	copy(stub, handle[:])
	c.rpc.Call(OpSamrCloseHandle, stub)
}
