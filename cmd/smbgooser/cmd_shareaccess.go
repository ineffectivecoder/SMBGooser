package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

func init() {
	commands.Register(&Command{
		Name:        "shareaccess",
		Aliases:     []string{"access", "perms"},
		Description: "Check access permissions on shares",
		Usage:       "shareaccess [share1 share2 ...]",
		Handler:     cmdShareAccess,
	})
}

// cmdShareAccess checks access levels on shares
func cmdShareAccess(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	// Shares to check
	sharesToCheck := []string{
		"ADMIN$", "C$", "D$", "E$",
		"IPC$", "NETLOGON", "SYSVOL",
		"Users", "Public",
	}

	// If specific shares provided, use those
	if len(args) > 0 {
		sharesToCheck = args
	}

	info_("Checking share access on %s...", targetHost)
	fmt.Println()
	fmt.Printf("  %s%-15s %-8s %-8s %-8s%s\n", colorBold, "SHARE", "READ", "WRITE", "ADMIN", colorReset)
	fmt.Println("  " + strings.Repeat("-", 50))

	for _, shareName := range sharesToCheck {
		// Try to connect
		tree, err := client.TreeConnect(ctx, shareName)
		if err != nil {
			if verbose {
				fmt.Printf("  %-15s %s[DENIED]%s\n", shareName, colorRed, colorReset)
			}
			continue
		}

		// Check access levels
		canRead := false
		canWrite := false
		isAdmin := false

		// For IPC$, just mark as accessible
		if tree.ShareType() == types.ShareTypePipe {
			canRead = true
			fmt.Printf("  %-15s %s%-8s%s %-8s %-8s  [IPC]\n",
				shareName,
				colorGreen, "YES", colorReset,
				"-", "-")
			client.TreeDisconnect(ctx, tree)
			continue
		}

		// Try to list root (read access)
		_, err = tree.ListDirectory(ctx, "")
		if err == nil {
			canRead = true
		}

		// Try to create a test file (write access)
		testFile := fmt.Sprintf("smbgtest_%d.tmp", ctx.Value("test"))
		file, err := tree.OpenFile(ctx, testFile, types.GenericWrite, types.FileCreate)
		if err == nil {
			canWrite = true
			file.Close()
			tree.DeleteFile(ctx, testFile) // Clean up
		}

		// ADMIN$ or C$ access typically indicates admin
		if shareName == "ADMIN$" || shareName == "C$" {
			isAdmin = canRead || canWrite
		}

		// Format output
		readStr := colorRed + "NO" + colorReset
		writeStr := colorRed + "NO" + colorReset
		adminStr := "-"

		if canRead {
			readStr = colorGreen + "YES" + colorReset
		}
		if canWrite {
			writeStr = colorGreen + "YES" + colorReset
		}
		if isAdmin {
			adminStr = colorYellow + "YES" + colorReset
		}

		fmt.Printf("  %-15s %-17s %-17s %-8s\n", shareName, readStr, writeStr, adminStr)

		client.TreeDisconnect(ctx, tree)
	}

	fmt.Println()
	return nil
}
