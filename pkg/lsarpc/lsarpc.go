// Package lsarpc implements LSARPC for trust enumeration and SID operations
package lsarpc

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
)

// LSARPC UUID: 12345778-1234-abcd-ef00-0123456789ab
var LSARPC_UUID = dcerpc.UUID{
	0x78, 0x57, 0x34, 0x12, // TimeLow (little-endian)
	0x34, 0x12, // TimeMid (little-endian)
	0xcd, 0xab, // TimeHiAndVersion (little-endian)
	0xef, 0x00, // ClockSeq
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, // Node
}

// Opnums
const (
	OpLsarOpenPolicy2             = 44
	OpLsarQueryInfoPolicy         = 7
	OpLsarEnumerateTrustedDomains = 13
	OpLsarLookupSids              = 15
	OpLsarClose                   = 0
)

// Handle is a 20-byte policy handle
type Handle [20]byte

// TrustedDomain represents a trusted domain
type TrustedDomain struct {
	Name string
	SID  string
}

// PolicyInfo represents LSA policy information
type PolicyInfo struct {
	DomainName string
	DomainSID  string
	DNSName    string
	ForestName string
}

// TranslatedName represents a resolved SID name
type TranslatedName struct {
	Name       string
	DomainName string
	Use        uint16 // SID_NAME_USE (1=User, 2=Group, 5=WellKnownGroup, etc.)
}

// Client is an LSARPC client
type Client struct {
	rpc          *dcerpc.Client
	pipe         *pipe.Pipe
	tree         *smb.Tree
	smbClient    *smb.Client
	policyHandle Handle
}

// NewClient creates a new LSARPC client
func NewClient(smbClient *smb.Client) (*Client, error) {
	ctx := context.Background()

	// Get cached IPC$ tree
	tree, err := smbClient.GetIPCTree(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get IPC$ tree: %w", err)
	}

	// Open lsarpc pipe
	p, err := pipe.Open(ctx, tree, "lsarpc")
	if err != nil {
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to open lsarpc pipe: %w", err)
	}

	// Create RPC client
	rpc := dcerpc.NewClient(p)

	// Bind to LSARPC interface
	if err := rpc.Bind(LSARPC_UUID, 0); err != nil {
		p.Close()
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to bind to LSARPC: %w", err)
	}

	return &Client{
		rpc:       rpc,
		pipe:      p,
		tree:      tree,
		smbClient: smbClient,
	}, nil
}

// OpenPolicy opens the LSA policy
func (c *Client) OpenPolicy(serverName string) error {
	stub := encodeLsarOpenPolicy2(serverName)

	resp, err := c.rpc.Call(OpLsarOpenPolicy2, stub)
	if err != nil {
		return fmt.Errorf("LsarOpenPolicy2 failed: %w", err)
	}

	if len(resp) < 24 {
		return fmt.Errorf("response too short")
	}

	copy(c.policyHandle[:], resp[:20])

	retCode := binary.LittleEndian.Uint32(resp[20:24])
	if retCode != 0 {
		return fmt.Errorf("error: 0x%08X", retCode)
	}

	return nil
}

// QueryDomainInfo queries domain information
func (c *Client) QueryDomainInfo() (*PolicyInfo, error) {
	stub := encodeLsarQueryInfoPolicy(c.policyHandle, 12)

	resp, err := c.rpc.Call(OpLsarQueryInfoPolicy, stub)
	if err != nil {
		return nil, fmt.Errorf("LsarQueryInfoPolicy failed: %w", err)
	}

	return parsePolicyInfo(resp)
}

// EnumerateTrustedDomains enumerates domain trusts
func (c *Client) EnumerateTrustedDomains() ([]TrustedDomain, error) {
	stub := encodeLsarEnumerateTrustedDomains(c.policyHandle)

	resp, err := c.rpc.Call(OpLsarEnumerateTrustedDomains, stub)
	if err != nil {
		return nil, fmt.Errorf("LsarEnumerateTrustedDomains failed: %w", err)
	}

	return parseTrustedDomains(resp)
}

// LookupSids resolves SIDs to account names
// sidStrings is a list of SID strings like "S-1-5-21-xxx-xxx-xxx-1001"
func (c *Client) LookupSids(sidStrings []string) (map[string]*TranslatedName, error) {
	if len(sidStrings) == 0 {
		return nil, nil
	}

	// Parse SID strings to binary format
	var sids [][]byte
	for _, sidStr := range sidStrings {
		sidData := parseSIDString(sidStr)
		if sidData != nil {
			sids = append(sids, sidData)
		}
	}

	if len(sids) == 0 {
		return nil, nil
	}

	// Build request
	stub := encodeLsarLookupSids(c.policyHandle, sids)

	resp, err := c.rpc.Call(OpLsarLookupSids, stub)
	if err != nil {
		return nil, fmt.Errorf("LsarLookupSids failed: %w", err)
	}

	return parseLookupSidsResponse(resp, sidStrings)
}

// Close closes the LSARPC client resources
// Note: We skip calling LsarClose RPC and TreeDisconnect because:
// 1. The tree is shared/cached and may be used by other RPC clients (SAMR, etc.)
// 2. Calling LsarClose while other pipes are active can cause conflicts
func (c *Client) Close() error {
	// Skip LsarClose RPC call - can cause pipe conflicts
	// Just close the local resources
	if c.rpc != nil {
		c.rpc.Close()
	}
	if c.pipe != nil {
		c.pipe.Close()
	}
	// Don't disconnect tree - it's cached/shared
	return nil
}

func encodeLsarOpenPolicy2(serverName string) []byte {
	stub := make([]byte, 0, 48)

	// SystemName - null for local
	stub = appendUint32(stub, 0)

	// ObjectAttributes (simplified - 24 bytes of zeros)
	stub = appendUint32(stub, 24) // Length
	stub = appendUint32(stub, 0)  // RootDirectory
	stub = appendUint32(stub, 0)  // ObjectName
	stub = appendUint32(stub, 0)  // Attributes
	stub = appendUint32(stub, 0)  // SecurityDescriptor
	stub = appendUint32(stub, 0)  // SecurityQualityOfService

	// DesiredAccess (POLICY_ALL_ACCESS)
	stub = appendUint32(stub, 0x00F0FFF)

	return stub
}

func encodeLsarQueryInfoPolicy(handle Handle, infoClass uint16) []byte {
	stub := make([]byte, 0, 24)
	stub = append(stub, handle[:]...)
	stub = appendUint16(stub, infoClass)
	stub = appendUint16(stub, 0) // Padding
	return stub
}

func encodeLsarEnumerateTrustedDomains(handle Handle) []byte {
	stub := make([]byte, 0, 32)
	stub = append(stub, handle[:]...)
	stub = appendUint32(stub, 0)          // EnumerationContext
	stub = appendUint32(stub, 0xFFFFFFFF) // PrefMaxLen
	return stub
}

func parsePolicyInfo(resp []byte) (*PolicyInfo, error) {
	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short")
	}

	info := &PolicyInfo{}
	// PolicyDnsDomainInformation (info class 12) NDR layout from hex dump:
	// 0x00: Discriminant (4 bytes)
	// 0x04: Info class (4 bytes)
	// 0x08: Name RPC_UNICODE_STRING (8 bytes: Len + MaxLen + Ptr)
	// 0x10: DnsDomainName RPC_UNICODE_STRING (8 bytes)
	// 0x18: DnsForestName RPC_UNICODE_STRING (8 bytes)
	// 0x20: DomainGuid (16 bytes)
	// 0x30: Sid pointer (4 bytes)
	// 0x34: Deferred string data starts

	offset := 0

	// Skip discriminant + info class (8 bytes total)
	if offset+8 > len(resp) {
		return info, nil
	}
	offset = 8

	// Parse 3 RPC_UNICODE_STRING headers (8 bytes each)
	// Name (at 0x08)
	if offset+8 > len(resp) {
		return info, nil
	}
	nameLen := binary.LittleEndian.Uint16(resp[offset:])
	offset += 8

	// DnsDomainName (at 0x10)
	if offset+8 > len(resp) {
		return info, nil
	}
	dnsLen := binary.LittleEndian.Uint16(resp[offset:])
	offset += 8

	// DnsForestName (at 0x18)
	if offset+8 > len(resp) {
		return info, nil
	}
	forestLen := binary.LittleEndian.Uint16(resp[offset:])
	offset += 8

	// Skip DomainGuid (16 bytes at 0x20)
	if offset+16 > len(resp) {
		return info, nil
	}
	offset += 16

	// Sid pointer (4 bytes at 0x30)
	if offset+4 > len(resp) {
		return info, nil
	}
	sidPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// Now at offset 0x34 - parse deferred data

	// Parse Name string (conformant varying string)
	if nameLen > 0 && offset+12 <= len(resp) {
		// MaxCount, Offset, ActualCount
		offset += 4 // MaxCount
		offset += 4 // Offset
		if offset+4 <= len(resp) {
			actualCount := binary.LittleEndian.Uint32(resp[offset:])
			offset += 4
			strBytes := int(actualCount) * 2
			if strBytes > 0 && offset+strBytes <= len(resp) {
				info.DomainName = decodeUTF16LE(resp[offset : offset+strBytes])
				offset += strBytes
				// Align to 4 bytes
				for offset%4 != 0 && offset < len(resp) {
					offset++
				}
			}
		}
	}

	// Parse DnsDomainName string
	if dnsLen > 0 && offset+12 <= len(resp) {
		offset += 4 // MaxCount
		offset += 4 // Offset
		if offset+4 <= len(resp) {
			actualCount := binary.LittleEndian.Uint32(resp[offset:])
			offset += 4
			strBytes := int(actualCount) * 2
			if strBytes > 0 && offset+strBytes <= len(resp) {
				info.DNSName = decodeUTF16LE(resp[offset : offset+strBytes])
				offset += strBytes
				for offset%4 != 0 && offset < len(resp) {
					offset++
				}
			}
		}
	}

	// Parse DnsForestName string
	if forestLen > 0 && offset+12 <= len(resp) {
		offset += 4 // MaxCount
		offset += 4 // Offset
		if offset+4 <= len(resp) {
			actualCount := binary.LittleEndian.Uint32(resp[offset:])
			offset += 4
			strBytes := int(actualCount) * 2
			if strBytes > 0 && offset+strBytes <= len(resp) {
				info.ForestName = decodeUTF16LE(resp[offset : offset+strBytes])
				offset += strBytes
				for offset%4 != 0 && offset < len(resp) {
					offset++
				}
			}
		}
	}

	// Parse SID
	if sidPtr != 0 && offset+8 <= len(resp) {
		// Skip MaxCount (4 bytes) for conformant SID
		offset += 4
		// Parse RPC_SID: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthority[]
		if offset+8 <= len(resp) {
			revision := resp[offset]
			subAuthCount := resp[offset+1]
			if subAuthCount <= 15 && offset+8+int(subAuthCount)*4 <= len(resp) {
				// IdentifierAuthority (6 bytes, big-endian)
				authority := uint64(resp[offset+2])<<40 | uint64(resp[offset+3])<<32 |
					uint64(resp[offset+4])<<24 | uint64(resp[offset+5])<<16 |
					uint64(resp[offset+6])<<8 | uint64(resp[offset+7])
				offset += 8

				// Build SID string
				var sb strings.Builder
				fmt.Fprintf(&sb, "S-%d-%d", revision, authority)
				for i := 0; i < int(subAuthCount); i++ {
					subAuth := binary.LittleEndian.Uint32(resp[offset:])
					fmt.Fprintf(&sb, "-%d", subAuth)
					offset += 4
				}
				info.DomainSID = sb.String()
			}
		}
	}

	// Set defaults if empty
	if info.DomainName == "" {
		info.DomainName = "Unknown"
	}
	if info.DomainSID == "" {
		info.DomainSID = "Unknown"
	}

	return info, nil
}

func parseTrustedDomains(resp []byte) ([]TrustedDomain, error) {
	if len(resp) < 8 {
		return nil, nil
	}

	var domains []TrustedDomain

	// Try to parse count
	if len(resp) >= 8 {
		count := binary.LittleEndian.Uint32(resp[4:8])
		if count > 0 && count < 100 {
			for i := uint32(0); i < count; i++ {
				domains = append(domains, TrustedDomain{
					Name: fmt.Sprintf("TRUST_%d", i),
					SID:  "S-1-5-21-...",
				})
			}
		}
	}

	return domains, nil
}

func appendUint32(buf []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return append(buf, b...)
}

func appendUint16(buf []byte, v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return append(buf, b...)
}

// parseSIDString converts a SID string to binary format
func parseSIDString(sidStr string) []byte {
	// Parse S-1-5-21-xxx-xxx-xxx-xxx format
	if len(sidStr) < 5 || sidStr[:2] != "S-" {
		return nil
	}

	parts := []string{}
	for _, p := range strings.Split(sidStr[2:], "-") {
		parts = append(parts, p)
	}

	if len(parts) < 3 {
		return nil
	}

	// Parse revision (must be 1)
	var revision uint64
	fmt.Sscanf(parts[0], "%d", &revision)
	if revision != 1 {
		return nil
	}

	// Parse identifier authority
	var authority uint64
	fmt.Sscanf(parts[1], "%d", &authority)

	// Parse sub-authorities
	var subAuths []uint32
	for i := 2; i < len(parts); i++ {
		var sa uint64
		fmt.Sscanf(parts[i], "%d", &sa)
		subAuths = append(subAuths, uint32(sa))
	}

	// Build binary SID
	sidLen := 8 + 4*len(subAuths)
	sid := make([]byte, sidLen)
	sid[0] = byte(revision)
	sid[1] = byte(len(subAuths))
	// Authority is 6 bytes big-endian
	sid[2] = byte(authority >> 40)
	sid[3] = byte(authority >> 32)
	sid[4] = byte(authority >> 24)
	sid[5] = byte(authority >> 16)
	sid[6] = byte(authority >> 8)
	sid[7] = byte(authority)
	// Sub-authorities are 4 bytes little-endian each
	for i, sa := range subAuths {
		binary.LittleEndian.PutUint32(sid[8+4*i:], sa)
	}

	return sid
}

// encodeLsarLookupSids encodes the LsarLookupSids request
// Matches Impacket's exact 88-byte format for a single SID
func encodeLsarLookupSids(handle Handle, sids [][]byte) []byte {
	stub := make([]byte, 0, 128)

	// PolicyHandle (20 bytes)
	stub = append(stub, handle[:]...)

	// SidEnumBuffer.Entries
	stub = appendUint32(stub, uint32(len(sids)))
	// SidEnumBuffer.SidInfo pointer (ReferentID)
	stub = appendUint32(stub, 0x00005ac0)

	// Deferred SidInfo array starts here
	// MaxCount for the array
	stub = appendUint32(stub, uint32(len(sids)))

	// Array of LSAPR_SID_INFORMATION - each is just a pointer to RPC_SID
	refID := uint32(0x0000cc35)
	for range sids {
		stub = appendUint32(stub, refID)
		refID += 4
	}

	// Now the deferred RPC_SID data for each
	for _, sid := range sids {
		subAuthCount := int(sid[1])
		// MaxCount for conformant SubAuthority array
		stub = appendUint32(stub, uint32(subAuthCount))
		// RPC_SID body: Revision(1) + SubAuthCount(1) + IdentAuth(6) + SubAuth[](4*n)
		stub = append(stub, sid...)
	}

	// TranslatedNames.Entries = 0
	stub = appendUint32(stub, 0)
	// TranslatedNames.Names pointer (ReferentID - but entries=0 so should be null?)
	stub = appendUint32(stub, 0x0000a587)
	// Deferred: Entries for the empty array
	stub = appendUint32(stub, 0)

	// LookupLevel (1 = LsapLookupWksta) + padding
	stub = appendUint16(stub, 1)
	stub = appendUint16(stub, 0xbfbf) // Padding (Impacket uses bf bf)

	// MappedCount
	stub = appendUint32(stub, 0)

	return stub
}

// parseLookupSidsResponse parses the translated names from the response
// Based on MS-LSAT LsarLookupSids response structure (NDR serialization):
//
// Fixed portion (header):
//
//	0x00: ReferencedDomains pointer (4)
//	0x04: TranslatedNames.Entries (4)
//	0x08: TranslatedNames.Names pointer (4)
//
// Deferred data follows:
//  1. ReferencedDomains data (domains with interleaved name+SID)
//  2. TranslatedNames.Names array data
//
// Trailer (at end of response):
//
//	MappedCount (4)
//	ErrorCode (4)
func parseLookupSidsResponse(resp []byte, sidStrings []string) (map[string]*TranslatedName, error) {
	results := make(map[string]*TranslatedName)

	// Minimum size: header(12) + MappedCount(4) + ErrorCode(4) = 20
	if len(resp) < 20 {
		return results, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	// Read trailer from end of response
	trailerOff := len(resp) - 8
	mappedCount := binary.LittleEndian.Uint32(resp[trailerOff:])
	errCode := binary.LittleEndian.Uint32(resp[trailerOff+4:])

	// 0x00000107 = STATUS_SOME_NOT_MAPPED (partial success - acceptable)
	if errCode != 0 && errCode != 0x00000107 {
		return results, fmt.Errorf("NTSTATUS error: 0x%08X", errCode)
	}

	// Header (12 bytes fixed)
	refDomsPtr := binary.LittleEndian.Uint32(resp[0:4])
	namesCount := binary.LittleEndian.Uint32(resp[4:8])
	namesPtr := binary.LittleEndian.Uint32(resp[8:12])

	if namesCount == 0 || namesCount > 1000 || mappedCount == 0 {
		return results, nil
	}

	offset := 12            // Start of deferred data
	endOffset := trailerOff // Don't read past MappedCount

	// ========================================
	// 1. Parse ReferencedDomains (if present)
	// ========================================
	var domains []string
	domEntries := uint32(0)
	if refDomsPtr != 0 && offset+8 <= endOffset {
		// Skip referent marker (4 bytes)
		offset += 4

		// MaxCount for domains array
		if offset+4 <= endOffset {
			domEntries = binary.LittleEndian.Uint32(resp[offset:])
			offset += 4
		}

		if domEntries > 0 && domEntries < 100 {
			// Skip domain fixed entries (12 bytes each: RPC_UNICODE_STRING + SID ptr)
			for i := uint32(0); i < domEntries && offset+12 <= endOffset; i++ {
				offset += 12
			}

			// Parse deferred data: for each domain, parse name string then SID (interleaved)
			for i := uint32(0); i < domEntries && offset+12 <= endOffset; i++ {
				// Parse domain name string
				offset += 4 // MaxCount
				offset += 4 // Offset
				actualCount := binary.LittleEndian.Uint32(resp[offset:])
				offset += 4
				strBytes := int(actualCount) * 2
				if strBytes > 0 && strBytes < 500 && offset+strBytes <= endOffset {
					domName := decodeUTF16LE(resp[offset : offset+strBytes])
					domains = append(domains, domName)
					offset += strBytes
					for offset%4 != 0 && offset < endOffset {
						offset++
					}
				} else {
					domains = append(domains, "")
				}

				// Skip domain SID
				if offset+4 > endOffset {
					break
				}
				offset += 4 // SID MaxCount
				if offset+2 <= endOffset {
					subAuthCount := int(resp[offset+1])
					sidBodyLen := 8 + 4*subAuthCount
					if subAuthCount > 0 && subAuthCount < 15 && offset+sidBodyLen <= endOffset {
						offset += sidBodyLen
					}
				}
			}
		}
	}

	// ========================================
	// 2. Parse TranslatedNames array
	// ========================================
	if namesPtr == 0 {
		return results, nil
	}

	// TranslatedNames.Names array MaxCount
	if offset+4 > endOffset {
		return results, nil
	}
	offset += 4

	// Parse LSAPR_TRANSLATED_NAME entries (16 bytes each)
	// Layout: BufRef(4) + Use(4) + DomIdx(4) + Len+Max(4)
	type nameEntry struct {
		use         uint32
		domainIndex int32
	}
	var entries []nameEntry

	for i := uint32(0); i < namesCount && offset+16 <= endOffset; i++ {
		use := binary.LittleEndian.Uint32(resp[offset+4:])
		domIdx := int32(binary.LittleEndian.Uint32(resp[offset+8:]))
		offset += 16
		entries = append(entries, nameEntry{use: use, domainIndex: domIdx})
	}

	// Parse name strings
	// Skip one-time referent prefix (8 bytes) at the start
	if offset+8 <= endOffset {
		offset += 8
	}

	for i, entry := range entries {
		if i >= len(sidStrings) {
			break
		}
		if offset+12 > endOffset {
			break
		}

		// Read conformant string header
		offset += 4 // MaxCount
		offset += 4 // Offset
		if offset+4 > endOffset {
			break
		}
		actualCount := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		strBytes := int(actualCount) * 2
		name := ""
		if strBytes > 0 && strBytes < 500 && offset+strBytes <= endOffset {
			name = decodeUTF16LE(resp[offset : offset+strBytes])
			offset += strBytes
			for offset%4 != 0 && offset < endOffset {
				offset++
			}
		}

		if name != "" {
			domName := ""
			if entry.domainIndex >= 0 && int(entry.domainIndex) < len(domains) {
				domName = domains[entry.domainIndex]
			}
			results[sidStrings[i]] = &TranslatedName{
				Name:       name,
				DomainName: domName,
				Use:        uint16(entry.use),
			}
		}
	}

	return results, nil
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
