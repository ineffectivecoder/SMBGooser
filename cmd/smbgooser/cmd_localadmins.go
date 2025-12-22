package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/lsarpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
)

func init() {
	commands.Register(&Command{
		Name:        "localadmins",
		Aliases:     []string{"admins", "localgroup"},
		Description: "Enumerate local Administrators group members",
		Usage:       "localadmins [group]",
		Handler:     cmdLocalAdmins,
	})
}

// SAMR opnums for alias (local group) operations
const (
	opSamrConnect              = 0
	opSamrOpenDomain           = 7
	opSamrOpenAlias            = 27
	opSamrGetMembersInAlias    = 33
	opSamrLookupDomainInServer = 5
)

// Well-known RIDs
const (
	ridAdministrators = 544
	ridUsers          = 545
	ridGuests         = 546
	ridPowerUsers     = 547
	ridBackupOps      = 551
	ridRemoteDesktop  = 555
)

// SAMR UUID: 12345778-1234-abcd-ef00-0123456789ac
var samrUUID = dcerpc.UUID{
	0x78, 0x57, 0x34, 0x12, // TimeLow (little-endian)
	0x34, 0x12, // TimeMid
	0xcd, 0xab, // TimeHiAndVersion
	0xef, 0x00, // ClockSeq
	0x01, 0x23, 0x45, 0x67, 0x89, 0xac, // Node
}

// cmdLocalAdmins enumerates local admin group members
func cmdLocalAdmins(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	groupRID := uint32(ridAdministrators)
	groupName := "Administrators"

	if len(args) > 0 {
		switch strings.ToLower(args[0]) {
		case "users":
			groupRID = ridUsers
			groupName = "Users"
		case "guests":
			groupRID = ridGuests
			groupName = "Guests"
		case "rdp", "remotedesktop":
			groupRID = ridRemoteDesktop
			groupName = "Remote Desktop Users"
		case "backup":
			groupRID = ridBackupOps
			groupName = "Backup Operators"
		case "help":
			printLocalAdminsHelp()
			return nil
		}
	}

	info_("Connecting to SAMR service...")

	// Connect to IPC$
	tree, err := client.GetIPCTree(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to IPC$: %w", err)
	}
	defer client.TreeDisconnect(ctx, tree)

	// Open samr pipe
	p, err := pipe.Open(ctx, tree, "samr")
	if err != nil {
		return fmt.Errorf("failed to open samr pipe: %w", err)
	}
	defer p.Close()

	rpc := dcerpc.NewClient(p)
	defer rpc.Close()

	// Bind to SAMR
	if err := rpc.Bind(samrUUID, 1); err != nil {
		return fmt.Errorf("failed to bind: %w", err)
	}

	// Connect to SAM - matches Impacket's exact 12-byte format
	info_("Connecting to SAM server...")
	connectStub := make([]byte, 12)
	// ReferentID for ServerName pointer
	binary.LittleEndian.PutUint32(connectStub[0:], 0x00003052)
	// ServerName data (4 bytes of zeros)
	binary.LittleEndian.PutUint32(connectStub[4:], 0x00000000)
	// DesiredAccess - MAXIMUM_ALLOWED
	binary.LittleEndian.PutUint32(connectStub[8:], 0x02000000)

	resp, err := rpc.Call(opSamrConnect, connectStub)
	if err != nil {
		return fmt.Errorf("SamrConnect failed: %w", err)
	}

	if len(resp) < 24 {
		return fmt.Errorf("invalid response")
	}

	var serverHandle [20]byte
	copy(serverHandle[:], resp[:20])

	// Open builtin domain (S-1-5-32) - matches Impacket's exact 40-byte format
	info_("Opening BUILTIN domain...")
	// SamrOpenDomain format:
	// - ServerHandle (20 bytes)
	// - DesiredAccess (4 bytes) - MAXIMUM_ALLOWED = 0x02000000
	// - SubAuthorityCount for conformant array (4 bytes) - comes BEFORE RPC_SID
	// - RPC_SID structure:
	//   - Revision (1 byte)
	//   - SubAuthorityCount (1 byte)
	//   - IdentifierAuthority (6 bytes)
	//   - SubAuthority array (4 bytes each)
	openDomainStub := make([]byte, 0, 40)
	openDomainStub = append(openDomainStub, serverHandle[:]...)
	// DesiredAccess - MAXIMUM_ALLOWED
	openDomainStub = appendUint32LA(openDomainStub, 0x02000000)
	// MaxCount for conformant array (SubAuthorityCount = 1 for BUILTIN)
	openDomainStub = appendUint32LA(openDomainStub, 1)
	// RPC_SID for S-1-5-32 (BUILTIN)
	openDomainStub = append(openDomainStub, 0x01)                               // Revision
	openDomainStub = append(openDomainStub, 0x01)                               // SubAuthorityCount
	openDomainStub = append(openDomainStub, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05) // IdentifierAuthority (5)
	openDomainStub = appendUint32LA(openDomainStub, 32)                         // SubAuthority[0] = 32 (BUILTIN)

	resp, err = rpc.Call(opSamrOpenDomain, openDomainStub)
	if err != nil {
		return fmt.Errorf("SamrOpenDomain failed: %w", err)
	}

	if len(resp) < 24 {
		return fmt.Errorf("invalid response")
	}

	var domainHandle [20]byte
	copy(domainHandle[:], resp[:20])

	// Open alias (local group)
	info_("Opening %s group (RID %d)...", groupName, groupRID)
	openAliasStub := make([]byte, 0, 32)
	openAliasStub = append(openAliasStub, domainHandle[:]...)
	openAliasStub = appendUint32LA(openAliasStub, 0x0002000c) // Access
	openAliasStub = appendUint32LA(openAliasStub, groupRID)

	resp, err = rpc.Call(opSamrOpenAlias, openAliasStub)
	if err != nil {
		return fmt.Errorf("SamrOpenAlias failed: %w", err)
	}

	if len(resp) < 24 {
		return fmt.Errorf("invalid response")
	}

	var aliasHandle [20]byte
	copy(aliasHandle[:], resp[:20])

	// Get members
	info_("Enumerating members...")
	getMembersStub := make([]byte, 20)
	copy(getMembersStub, aliasHandle[:])

	resp, err = rpc.Call(opSamrGetMembersInAlias, getMembersStub)
	if err != nil {
		return fmt.Errorf("SamrGetMembersInAlias failed: %w", err)
	}

	// Parse response
	fmt.Println()
	fmt.Printf("  %sMembers of %s:%s\n", colorBold, groupName, colorReset)
	fmt.Println("  " + strings.Repeat("-", 50))

	rawSids := parseAliasMembersResponse(resp)

	// Collect SIDs that need lookup (not well-known)
	var sidsToLookup []string
	for _, sid := range rawSids {
		// Check if it's an unresolved domain SID (starts with "S-1-5-21-" and no parentheses)
		if strings.HasPrefix(sid, "S-1-5-21-") && !strings.Contains(sid, "(") {
			sidsToLookup = append(sidsToLookup, sid)
		}
	}

	// Try to resolve SIDs via LsaLookupSids
	resolvedNames := make(map[string]string)
	if len(sidsToLookup) > 0 {
		// Create LSA client (uses separate pipe on same tree)
		lsaClient, err := lsarpc.NewClient(client)
		if err == nil {
			err = lsaClient.OpenPolicy("")
			if err == nil {
				names, err := lsaClient.LookupSids(sidsToLookup)
				if err == nil && names != nil {
					for sid, name := range names {
						if name.DomainName != "" {
							resolvedNames[sid] = fmt.Sprintf("%s\\%s", name.DomainName, name.Name)
						} else {
							resolvedNames[sid] = name.Name
						}
					}
				}
			}
			lsaClient.Close()
		}
	}

	// Display members with resolved names
	if len(rawSids) == 0 {
		fmt.Println("  No members found (or access denied)")
	} else {
		for _, sid := range rawSids {
			displayName := sid
			// Apply well-known SID mapping first
			mapped := mapKnownSID(sid)
			if mapped != sid {
				displayName = mapped
			} else if resolved, ok := resolvedNames[sid]; ok {
				// Use LsaLookupSids result
				displayName = fmt.Sprintf("%s (%s)", resolved, sid)
			}
			fmt.Printf("  %s%s%s\n", colorGreen, displayName, colorReset)
		}
	}

	fmt.Println()
	success_("Found %d member(s)", len(rawSids))

	return nil
}

func parseAliasMembersResponse(resp []byte) []string {
	var sids []string

	// Response format: SAMPR_PSID_ARRAY_OUT + ErrorCode
	// SAMPR_PSID_ARRAY_OUT:
	// - Count (4 bytes)
	// - Sids pointer (4 bytes) - pointer to array of SAMPR_SID_INFORMATION
	// Deferred referent data:
	// - MaxCount (4 bytes) - for conformant array
	// - Array of SID pointers (4 bytes each)
	// Deferred SID data:
	// - For each non-null pointer: MaxCount(4) + RPC_SID body
	// Then ErrorCode (4 bytes)

	if len(resp) < 12 {
		return sids
	}

	// Member count
	count := binary.LittleEndian.Uint32(resp[0:4])
	if count == 0 || count > 100 {
		return sids
	}

	// Sids pointer
	sidsPtr := binary.LittleEndian.Uint32(resp[4:8])
	if sidsPtr == 0 {
		return sids
	}

	// Skip to deferred data (after fixed part)
	offset := 8

	// MaxCount for conformant array of pointers
	if offset+4 > len(resp)-4 {
		return sids
	}
	// maxCount := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// Array of SID pointers (each is 4 bytes)
	if offset+int(count)*4 > len(resp)-4 {
		return sids
	}

	// Store pointer values to know which SIDs to expect
	var pointers []uint32
	for i := uint32(0); i < count && offset+4 <= len(resp)-4; i++ {
		ptr := binary.LittleEndian.Uint32(resp[offset:])
		pointers = append(pointers, ptr)
		offset += 4
	}

	// Now parse the deferred SID data
	for _, ptr := range pointers {
		if ptr == 0 {
			continue
		}

		// Each RPC_SID as deferred data: MaxCount(4) + Revision(1) + SubAuthCount(1) + IdentAuth(6) + SubAuth[]
		if offset+12 > len(resp)-4 {
			break
		}

		// MaxCount for SID's conformant SubAuthority array
		maxCount := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		// RPC_SID body
		if offset+8 > len(resp)-4 {
			break
		}

		revision := resp[offset]
		subAuthCount := resp[offset+1]

		// Verify we have enough data
		sidLen := 8 + 4*int(subAuthCount)
		if offset+sidLen > len(resp)-4 {
			break
		}

		// Validate
		if revision == 1 && subAuthCount <= byte(maxCount) {
			sid := formatSID(resp[offset : offset+sidLen])
			sids = append(sids, sid)
		}
		offset += sidLen
	}

	return sids
}

func formatSID(data []byte) string {
	if len(data) < 8 {
		return "(invalid)"
	}

	revision := data[0]
	subAuthCount := int(data[1])

	// Authority (6 bytes, big endian)
	authority := uint64(data[2])<<40 | uint64(data[3])<<32 | uint64(data[4])<<24 |
		uint64(data[5])<<16 | uint64(data[6])<<8 | uint64(data[7])

	sid := fmt.Sprintf("S-%d-%d", revision, authority)

	for i := 0; i < subAuthCount && 8+i*4+4 <= len(data); i++ {
		subAuth := binary.LittleEndian.Uint32(data[8+i*4:])
		sid += fmt.Sprintf("-%d", subAuth)
	}

	// Map well-known
	return mapKnownSID(sid)
}

func mapKnownSID(sid string) string {
	// Well-known SIDs (complete list)
	wellKnown := map[string]string{
		// NT AUTHORITY
		"S-1-5-18": "SYSTEM",
		"S-1-5-19": "LOCAL SERVICE",
		"S-1-5-20": "NETWORK SERVICE",
		// BUILTIN groups
		"S-1-5-32-544": "BUILTIN\\Administrators",
		"S-1-5-32-545": "BUILTIN\\Users",
		"S-1-5-32-546": "BUILTIN\\Guests",
		"S-1-5-32-547": "BUILTIN\\Power Users",
		"S-1-5-32-548": "BUILTIN\\Account Operators",
		"S-1-5-32-549": "BUILTIN\\Server Operators",
		"S-1-5-32-550": "BUILTIN\\Print Operators",
		"S-1-5-32-551": "BUILTIN\\Backup Operators",
		"S-1-5-32-552": "BUILTIN\\Replicator",
		"S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
		"S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
		"S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
		"S-1-5-32-559": "BUILTIN\\Performance Log Users",
		"S-1-5-32-562": "BUILTIN\\Distributed COM Users",
		"S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
		"S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
		"S-1-5-32-573": "BUILTIN\\Event Log Readers",
		"S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
		"S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
		"S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
		"S-1-5-32-577": "BUILTIN\\RDS Management Servers",
		"S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
		"S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
		"S-1-5-32-580": "BUILTIN\\Remote Management Users",
		// Other well-known
		"S-1-1-0":  "Everyone",
		"S-1-2-0":  "LOCAL",
		"S-1-3-0":  "CREATOR OWNER",
		"S-1-3-1":  "CREATOR GROUP",
		"S-1-5-1":  "DIALUP",
		"S-1-5-2":  "NETWORK",
		"S-1-5-3":  "BATCH",
		"S-1-5-4":  "INTERACTIVE",
		"S-1-5-6":  "SERVICE",
		"S-1-5-7":  "ANONYMOUS LOGON",
		"S-1-5-9":  "Enterprise Domain Controllers",
		"S-1-5-10": "SELF",
		"S-1-5-11": "Authenticated Users",
		"S-1-5-12": "RESTRICTED",
		"S-1-5-13": "TERMINAL SERVER USER",
		"S-1-5-14": "REMOTE INTERACTIVE LOGON",
	}

	if name, ok := wellKnown[sid]; ok {
		return fmt.Sprintf("%s (%s)", name, sid)
	}

	// Check for domain accounts (S-1-5-21-xxx-xxx-xxx-RID)
	if strings.HasPrefix(sid, "S-1-5-21-") {
		parts := strings.Split(sid, "-")
		if len(parts) >= 8 {
			rid := parts[len(parts)-1]
			// Well-known domain RIDs
			ridNames := map[string]string{
				"500":  "Administrator",
				"501":  "Guest",
				"502":  "krbtgt",
				"512":  "Domain Admins",
				"513":  "Domain Users",
				"514":  "Domain Guests",
				"515":  "Domain Computers",
				"516":  "Domain Controllers",
				"517":  "Cert Publishers",
				"518":  "Schema Admins",
				"519":  "Enterprise Admins",
				"520":  "Group Policy Creator Owners",
				"521":  "Read-only Domain Controllers",
				"522":  "Cloneable Domain Controllers",
				"525":  "Protected Users",
				"526":  "Key Admins",
				"527":  "Enterprise Key Admins",
				"553":  "RAS and IAS Servers",
				"571":  "Allowed RODC Password Replication Group",
				"572":  "Denied RODC Password Replication Group",
				"1000": "First Custom User/Group",
			}
			if name, ok := ridNames[rid]; ok {
				return fmt.Sprintf("%s (%s)", name, sid)
			}
		}
	}

	return sid
}

func appendUint32LA(buf []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return append(buf, b...)
}

func printLocalAdminsHelp() {
	fmt.Println("\nUsage: localadmins [group]")
	fmt.Println("\nEnumerates members of local groups via SAMR.")
	fmt.Println("\nGroups:")
	fmt.Println("  (default)     Administrators")
	fmt.Println("  users         Users")
	fmt.Println("  rdp           Remote Desktop Users")
	fmt.Println("  backup        Backup Operators")
	fmt.Println("\nExamples:")
	fmt.Println("  localadmins")
	fmt.Println("  localadmins rdp")
	fmt.Println()
}
