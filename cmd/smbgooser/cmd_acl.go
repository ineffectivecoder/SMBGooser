package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/lsarpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

func init() {
	commands.Register(&Command{
		Name:        "acl",
		Aliases:     []string{"getacl", "permissions"},
		Description: "Show file/directory security descriptor",
		Usage:       "acl <path>",
		Handler:     cmdAcl,
	})
}

// cmdAcl displays the security descriptor for a file or directory
func cmdAcl(ctx context.Context, args []string) error {
	if currentTree == nil {
		return fmt.Errorf("not connected to a share (use 'use <share>' first)")
	}

	if currentTree.ShareType() == types.ShareTypePipe {
		return fmt.Errorf("cannot read ACLs on IPC$ share")
	}

	if len(args) < 1 {
		printAclHelp()
		return nil
	}

	path := resolvePath(args[0])

	info_("Reading security descriptor for: %s", path)

	// Try opening as directory first, then as file
	// Use FILE_OPEN_FOR_BACKUP_INTENT which works for both
	file, err := currentTree.OpenFile(ctx, path, types.ReadControl, types.FileOpen)
	if err != nil {
		// Try as directory (OpenDirectory uses correct flags internally)
		file, err = currentTree.OpenDirectory(ctx, path)
		if err != nil {
			return fmt.Errorf("failed to open: %w", err)
		}
	}
	defer file.Close()

	// Query security descriptor
	sd, err := file.GetSecurityDescriptor(ctx)
	if err != nil {
		return fmt.Errorf("failed to get security descriptor: %w", err)
	}

	// Collect all SIDs from the security descriptor for resolution
	var sidsToResolve []string
	extractSIDsFromSD(sd, &sidsToResolve)

	// Resolve domain SIDs via LsaLookupSids
	resolvedSids := make(map[string]string)
	if len(sidsToResolve) > 0 {
		lsaClient, err := lsarpc.NewClient(client)
		if err == nil {
			defer lsaClient.Close()
			if lsaClient.OpenPolicy("") == nil {
				names, err := lsaClient.LookupSids(sidsToResolve)
				if err == nil && names != nil {
					for sid, name := range names {
						if name.DomainName != "" {
							resolvedSids[sid] = fmt.Sprintf("%s\\%s", name.DomainName, name.Name)
						} else {
							resolvedSids[sid] = name.Name
						}
					}
				}
			}
		}
	}

	fmt.Println()
	fmt.Printf("  %sSecurity Descriptor for %s:%s\n", colorBold, path, colorReset)
	fmt.Println("  " + strings.Repeat("-", 60))

	// Parse and display the security descriptor with resolved SIDs
	displaySecurityDescriptorWithNames(sd, resolvedSids)

	return nil
}

// extractSIDsFromSD extracts all SIDs from a security descriptor for resolution
func extractSIDsFromSD(sd []byte, sids *[]string) {
	if len(sd) < 20 {
		return
	}

	ownerOffset := binary.LittleEndian.Uint32(sd[4:8])
	groupOffset := binary.LittleEndian.Uint32(sd[8:12])
	daclOffset := binary.LittleEndian.Uint32(sd[16:20])

	// Owner SID
	if ownerOffset > 0 && int(ownerOffset) < len(sd) {
		sidStr := extractSIDString(sd[ownerOffset:])
		if strings.HasPrefix(sidStr, "S-1-5-21-") && !containsParens(sidStr) {
			*sids = append(*sids, sidStr)
		}
	}

	// Group SID
	if groupOffset > 0 && int(groupOffset) < len(sd) {
		sidStr := extractSIDString(sd[groupOffset:])
		if strings.HasPrefix(sidStr, "S-1-5-21-") && !containsParens(sidStr) {
			*sids = append(*sids, sidStr)
		}
	}

	// DACL ACEs
	if daclOffset > 0 && int(daclOffset) < len(sd) {
		extractSIDsFromACL(sd[daclOffset:], sids)
	}
}

// containsParens checks if string contains parentheses (already resolved)
func containsParens(s string) bool {
	return strings.Contains(s, "(")
}

// extractSIDsFromACL extracts SIDs from an ACL
func extractSIDsFromACL(data []byte, sids *[]string) {
	if len(data) < 8 {
		return
	}

	aceCount := binary.LittleEndian.Uint16(data[4:6])
	offset := 8

	for i := 0; i < int(aceCount) && offset+4 < len(data); i++ {
		aceSize := int(binary.LittleEndian.Uint16(data[offset+2:]))
		if aceSize < 8 || offset+aceSize > len(data) {
			break
		}

		// SID starts at offset+8 in ACE
		if offset+8 < len(data) {
			sidStr := extractSIDString(data[offset+8:])
			if strings.HasPrefix(sidStr, "S-1-5-21-") && !containsParens(sidStr) {
				// Check if already in list
				found := false
				for _, s := range *sids {
					if s == sidStr {
						found = true
						break
					}
				}
				if !found {
					*sids = append(*sids, sidStr)
				}
			}
		}

		offset += aceSize
	}
}

// extractSIDString extracts a SID string from binary data
func extractSIDString(data []byte) string {
	if len(data) < 8 {
		return ""
	}

	revision := data[0]
	subAuthCount := int(data[1])

	if len(data) < 8+subAuthCount*4 {
		return ""
	}

	authority := uint64(data[2])<<40 | uint64(data[3])<<32 | uint64(data[4])<<24 |
		uint64(data[5])<<16 | uint64(data[6])<<8 | uint64(data[7])

	sidStr := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < subAuthCount && 8+i*4+4 <= len(data); i++ {
		subAuth := binary.LittleEndian.Uint32(data[8+i*4:])
		sidStr += fmt.Sprintf("-%d", subAuth)
	}

	return sidStr
}

// displaySecurityDescriptorWithNames parses and displays a security descriptor with resolved SID names
func displaySecurityDescriptorWithNames(sd []byte, resolvedSids map[string]string) {
	if len(sd) < 20 {
		fmt.Println("  (empty or invalid security descriptor)")
		return
	}

	// Security descriptor header
	revision := sd[0]
	control := binary.LittleEndian.Uint16(sd[2:4])
	ownerOffset := binary.LittleEndian.Uint32(sd[4:8])
	groupOffset := binary.LittleEndian.Uint32(sd[8:12])
	saclOffset := binary.LittleEndian.Uint32(sd[12:16])
	daclOffset := binary.LittleEndian.Uint32(sd[16:20])

	fmt.Printf("  Revision: %d\n", revision)
	fmt.Printf("  Control:  0x%04X\n", control)

	// Owner SID
	if ownerOffset > 0 && int(ownerOffset) < len(sd) {
		owner := parseSIDWithResolvedNames(sd[ownerOffset:], resolvedSids)
		fmt.Printf("  Owner:    %s\n", owner)
	}

	// Group SID
	if groupOffset > 0 && int(groupOffset) < len(sd) {
		group := parseSIDWithResolvedNames(sd[groupOffset:], resolvedSids)
		fmt.Printf("  Group:    %s\n", group)
	}

	// DACL
	if daclOffset > 0 && int(daclOffset) < len(sd) {
		fmt.Println()
		fmt.Printf("  %sDACL (Discretionary ACL):%s\n", colorBold, colorReset)
		parseACLWithResolvedNames(sd[daclOffset:], resolvedSids)
	}

	// SACL (if present)
	if saclOffset > 0 && int(saclOffset) < len(sd) {
		fmt.Println()
		fmt.Printf("  %sSACL (System ACL):%s\n", colorBold, colorReset)
		parseACLWithResolvedNames(sd[saclOffset:], resolvedSids)
	}

	fmt.Println()
}

// parseSIDWithResolvedNames parses a SID and returns its string representation with resolved name
func parseSIDWithResolvedNames(data []byte, resolvedSids map[string]string) string {
	sidStr := extractSIDString(data)
	if sidStr == "" {
		return "(invalid SID)"
	}

	// Check if we have a resolved name for this SID
	if resolved, ok := resolvedSids[sidStr]; ok {
		return fmt.Sprintf("%s (%s)", resolved, sidStr)
	}

	// Fall back to well-known SID mapping
	return mapWellKnownSID(sidStr)
}

// parseACLWithResolvedNames parses an ACL with resolved SID names
func parseACLWithResolvedNames(data []byte, resolvedSids map[string]string) {
	if len(data) < 8 {
		return
	}

	// ACL header
	aclSize := binary.LittleEndian.Uint16(data[2:4])
	aceCount := binary.LittleEndian.Uint16(data[4:6])

	fmt.Printf("  ACL Size: %d, ACE Count: %d\n", aclSize, aceCount)

	// Parse ACEs
	offset := 8
	for i := 0; i < int(aceCount) && offset+4 < len(data); i++ {
		aceType := data[offset]
		aceFlags := data[offset+1]
		aceSize := int(binary.LittleEndian.Uint16(data[offset+2:]))

		if aceSize < 8 || offset+aceSize > len(data) {
			break
		}

		// Extract access mask and SID
		mask := binary.LittleEndian.Uint32(data[offset+4:])
		sidStr := extractSIDString(data[offset+8:])

		// Resolve SID
		displayName := sidStr
		if resolved, ok := resolvedSids[sidStr]; ok {
			displayName = fmt.Sprintf("%s (%s)", resolved, sidStr)
		} else {
			displayName = mapWellKnownSID(sidStr)
		}

		typeStr := aceTypeToString(aceType)
		flagsStr := aceFlagsToString(aceFlags)
		permStr := accessMaskToString(mask)

		if aceFlags != 0 {
			fmt.Printf("    [%s] %s\n", typeStr, displayName)
			fmt.Printf("       Flags: %s\n", flagsStr)
			fmt.Printf("       Access: %s\n", permStr)
		} else {
			fmt.Printf("    [%s] %s\n", typeStr, displayName)
			fmt.Printf("       Access: %s\n", permStr)
		}

		offset += aceSize
	}
}

// displaySecurityDescriptor parses and displays a security descriptor
func displaySecurityDescriptor(sd []byte) {
	if len(sd) < 20 {
		fmt.Println("  (empty or invalid security descriptor)")
		return
	}

	// Security descriptor header
	revision := sd[0]
	control := binary.LittleEndian.Uint16(sd[2:4])
	ownerOffset := binary.LittleEndian.Uint32(sd[4:8])
	groupOffset := binary.LittleEndian.Uint32(sd[8:12])
	saclOffset := binary.LittleEndian.Uint32(sd[12:16])
	daclOffset := binary.LittleEndian.Uint32(sd[16:20])

	fmt.Printf("  Revision: %d\n", revision)
	fmt.Printf("  Control:  0x%04X\n", control)

	// Owner SID
	if ownerOffset > 0 && int(ownerOffset) < len(sd) {
		owner := parseSID(sd[ownerOffset:])
		fmt.Printf("  Owner:    %s\n", owner)
	}

	// Group SID
	if groupOffset > 0 && int(groupOffset) < len(sd) {
		group := parseSID(sd[groupOffset:])
		fmt.Printf("  Group:    %s\n", group)
	}

	// DACL
	if daclOffset > 0 && int(daclOffset) < len(sd) {
		fmt.Println()
		fmt.Printf("  %sDACL (Discretionary ACL):%s\n", colorBold, colorReset)
		parseACL(sd[daclOffset:])
	}

	// SACL (if present)
	if saclOffset > 0 && int(saclOffset) < len(sd) {
		fmt.Println()
		fmt.Printf("  %sSACL (System ACL):%s\n", colorBold, colorReset)
		parseACL(sd[saclOffset:])
	}

	fmt.Println()
}

// parseSID parses a SID and returns its string representation
func parseSID(data []byte) string {
	if len(data) < 8 {
		return "(invalid SID)"
	}

	revision := data[0]
	subAuthCount := int(data[1])

	if len(data) < 8+subAuthCount*4 {
		return "(truncated SID)"
	}

	// Identifier authority (6 bytes, big endian for display)
	authority := uint64(data[2])<<40 | uint64(data[3])<<32 | uint64(data[4])<<24 |
		uint64(data[5])<<16 | uint64(data[6])<<8 | uint64(data[7])

	// Build SID string
	sidStr := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < subAuthCount && 8+i*4+4 <= len(data); i++ {
		subAuth := binary.LittleEndian.Uint32(data[8+i*4:])
		sidStr += fmt.Sprintf("-%d", subAuth)
	}

	// Map well-known SIDs
	return mapWellKnownSID(sidStr)
}

// mapWellKnownSID maps common SIDs to human-readable names
func mapWellKnownSID(sid string) string {
	wellKnown := map[string]string{
		"S-1-0-0":      "Nobody",
		"S-1-1-0":      "Everyone",
		"S-1-2-0":      "Local",
		"S-1-3-0":      "Creator Owner",
		"S-1-3-1":      "Creator Group",
		"S-1-5-2":      "Network",
		"S-1-5-7":      "Anonymous",
		"S-1-5-11":     "Authenticated Users",
		"S-1-5-18":     "SYSTEM",
		"S-1-5-19":     "Local Service",
		"S-1-5-20":     "Network Service",
		"S-1-5-32-544": "BUILTIN\\Administrators",
		"S-1-5-32-545": "BUILTIN\\Users",
		"S-1-5-32-546": "BUILTIN\\Guests",
	}

	if name, ok := wellKnown[sid]; ok {
		return fmt.Sprintf("%s (%s)", sid, name)
	}

	// Check for domain RIDs
	if strings.HasPrefix(sid, "S-1-5-21-") {
		parts := strings.Split(sid, "-")
		if len(parts) >= 8 {
			rid := parts[len(parts)-1]
			switch rid {
			case "500":
				return sid + " (Administrator)"
			case "501":
				return sid + " (Guest)"
			case "502":
				return sid + " (KRBTGT)"
			case "512":
				return sid + " (Domain Admins)"
			case "513":
				return sid + " (Domain Users)"
			case "514":
				return sid + " (Domain Guests)"
			case "515":
				return sid + " (Domain Computers)"
			case "516":
				return sid + " (Domain Controllers)"
			}
		}
	}

	return sid
}

// parseACL parses and displays an ACL
func parseACL(data []byte) {
	if len(data) < 8 {
		fmt.Println("    (empty or invalid ACL)")
		return
	}

	// ACL header
	revision := data[0]
	aceCount := binary.LittleEndian.Uint16(data[4:6])

	fmt.Printf("    Revision: %d, ACE Count: %d\n", revision, aceCount)

	// Parse ACEs
	offset := 8
	for i := uint16(0); i < aceCount && offset < len(data); i++ {
		if offset+4 > len(data) {
			break
		}

		aceType := data[offset]
		aceFlags := data[offset+1]
		aceSize := binary.LittleEndian.Uint16(data[offset+2 : offset+4])

		if aceSize < 4 || offset+int(aceSize) > len(data) {
			break
		}

		// Parse access mask and SID
		if aceSize >= 8 && offset+8 <= len(data) {
			accessMask := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
			sidData := data[offset+8 : offset+int(aceSize)]
			sid := parseSID(sidData)

			aceTypeStr := aceTypeToString(aceType)
			accessStr := accessMaskToString(accessMask)
			flagsStr := aceFlagsToString(aceFlags)

			fmt.Printf("    [%s] %s\n", aceTypeStr, sid)
			fmt.Printf("      Access: %s\n", accessStr)
			if flagsStr != "" {
				fmt.Printf("      Flags:  %s\n", flagsStr)
			}
		}

		offset += int(aceSize)
	}
}

func aceTypeToString(t byte) string {
	switch t {
	case 0:
		return colorGreen + "ALLOW" + colorReset
	case 1:
		return colorRed + "DENY" + colorReset
	case 2:
		return "AUDIT"
	default:
		return fmt.Sprintf("TYPE_%d", t)
	}
}

func accessMaskToString(mask uint32) string {
	var perms []string

	// Generic rights
	if mask&0x80000000 != 0 {
		perms = append(perms, "GENERIC_READ")
	}
	if mask&0x40000000 != 0 {
		perms = append(perms, "GENERIC_WRITE")
	}
	if mask&0x20000000 != 0 {
		perms = append(perms, "GENERIC_EXECUTE")
	}
	if mask&0x10000000 != 0 {
		perms = append(perms, "GENERIC_ALL")
	}

	// Standard rights
	if mask&0x00010000 != 0 {
		perms = append(perms, "DELETE")
	}
	if mask&0x00020000 != 0 {
		perms = append(perms, "READ_CONTROL")
	}
	if mask&0x00040000 != 0 {
		perms = append(perms, "WRITE_DAC")
	}
	if mask&0x00080000 != 0 {
		perms = append(perms, "WRITE_OWNER")
	}

	// File specific
	if mask&0x0001 != 0 {
		perms = append(perms, "READ_DATA")
	}
	if mask&0x0002 != 0 {
		perms = append(perms, "WRITE_DATA")
	}
	if mask&0x0004 != 0 {
		perms = append(perms, "APPEND_DATA")
	}
	if mask&0x0020 != 0 {
		perms = append(perms, "EXECUTE")
	}

	if len(perms) == 0 {
		return fmt.Sprintf("0x%08X", mask)
	}

	return strings.Join(perms, " | ")
}

func aceFlagsToString(flags byte) string {
	var f []string
	if flags&0x01 != 0 {
		f = append(f, "OBJECT_INHERIT")
	}
	if flags&0x02 != 0 {
		f = append(f, "CONTAINER_INHERIT")
	}
	if flags&0x04 != 0 {
		f = append(f, "NO_PROPAGATE")
	}
	if flags&0x08 != 0 {
		f = append(f, "INHERIT_ONLY")
	}
	return strings.Join(f, " | ")
}

func printAclHelp() {
	fmt.Println("\nUsage: acl <path>")
	fmt.Println("\nDisplays the security descriptor (ACL) for a file or directory.")
	fmt.Println("\nShows:")
	fmt.Println("  - Owner and Group SIDs")
	fmt.Println("  - DACL (who has access)")
	fmt.Println("  - SACL (auditing rules)")
	fmt.Println("\nExamples:")
	fmt.Println("  acl secret.txt")
	fmt.Println("  acl Users\\Administrator\\Desktop")
	fmt.Println()
}
