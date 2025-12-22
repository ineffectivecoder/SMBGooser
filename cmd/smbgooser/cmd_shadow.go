package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

func init() {
	commands.Register(&Command{
		Name:        "shadow",
		Aliases:     []string{"vss", "snapshot"},
		Description: "Access Volume Shadow Copies",
		Usage:       "shadow [list|read <path>]",
		Handler:     cmdShadow,
	})
}

// Common shadow copy paths
var shadowPaths = []string{
	"@GMT-",                     // Prefix for VSS snapshots
	"System Volume Information", // VSS metadata
}

// cmdShadow accesses Volume Shadow Copies
func cmdShadow(ctx context.Context, args []string) error {
	if currentTree == nil {
		return fmt.Errorf("not connected to a share (use 'use C$' first)")
	}

	if currentTree.ShareType() == types.ShareTypePipe {
		return fmt.Errorf("shadow copies not available on IPC$ share")
	}

	if len(args) == 0 || args[0] == "list" {
		return listShadowCopies(ctx)
	}

	if args[0] == "help" {
		printShadowHelp()
		return nil
	}

	if args[0] == "read" && len(args) > 1 {
		return readShadowCopy(ctx, args[1])
	}

	printShadowHelp()
	return nil
}

// listShadowCopies lists available shadow copies
func listShadowCopies(ctx context.Context) error {
	info_("Looking for Volume Shadow Copies...")
	fmt.Println()

	// Method 1: Try to list @GMT- prefixed entries
	info_("Checking for @GMT- snapshots (Previous Versions)...")

	// List root and look for @GMT- entries
	files, err := currentTree.ListDirectory(ctx, "")
	if err == nil {
		found := false
		for _, f := range files {
			if strings.HasPrefix(f.Name, "@GMT-") {
				if !found {
					fmt.Printf("  %sPrevious Versions found:%s\n", colorBold, colorReset)
					fmt.Println("  " + strings.Repeat("-", 50))
					found = true
				}
				fmt.Printf("  %s%s%s\n", colorGreen, f.Name, colorReset)
			}
		}
		if !found {
			fmt.Println("  No @GMT- snapshots visible at root")
			fmt.Println("  (May need to access via specific path)")
		}
	}

	// Method 2: Try System Volume Information
	fmt.Println()
	info_("Checking System Volume Information...")
	sviPath := "System Volume Information"
	_, err = currentTree.ListDirectory(ctx, sviPath)
	if err == nil {
		fmt.Printf("  %sSystem Volume Information accessible!%s\n", colorGreen, colorReset)
		fmt.Println("  Use: ls \"System Volume Information\"")
	} else {
		fmt.Println("  System Volume Information not accessible (normal)")
	}

	fmt.Println()
	fmt.Println("  To access a Previous Version:")
	fmt.Println("    ls \"@GMT-YYYY.MM.DD-HH.MM.SS\"")
	fmt.Println("    cat \"@GMT-YYYY.MM.DD-HH.MM.SS\\Windows\\System32\\config\\SAM\"")
	fmt.Println()

	return nil
}

// readShadowCopy reads a file from a shadow copy
func readShadowCopy(ctx context.Context, path string) error {
	// Normalize path - should start with @GMT-
	if !strings.HasPrefix(path, "@GMT-") {
		fmt.Println("  Shadow copy paths should start with @GMT-")
		fmt.Println("  Example: shadow read @GMT-2024.01.15-10.30.00\\Windows\\System32\\config\\SAM")
		return nil
	}

	info_("Attempting to access: %s", path)

	// Try to open the file
	file, err := currentTree.OpenFile(ctx, path, types.FileReadData, types.FileOpen)
	if err != nil {
		return fmt.Errorf("failed to open: %w", err)
	}
	defer file.Close()

	// Read first 1KB to verify access
	buf := make([]byte, 1024)
	n, err := file.Read(buf)
	if err != nil && n == 0 {
		return fmt.Errorf("failed to read: %w", err)
	}

	success_("Successfully read %d bytes from shadow copy", n)
	fmt.Println("  Use 'get' command to download the file")

	return nil
}

func printShadowHelp() {
	fmt.Println("\nUsage: shadow [command]")
	fmt.Println("\nAccess Volume Shadow Copies (Previous Versions)")
	fmt.Println("\nCommands:")
	fmt.Println("  list              List available shadow copies")
	fmt.Println("  read <path>       Test reading a file from shadow copy")
	fmt.Println("\nHow it works:")
	fmt.Println("  Windows exposes VSS snapshots via @GMT-YYYY.MM.DD-HH.MM.SS paths")
	fmt.Println("  You can access old versions of files, including locked files")
	fmt.Println("\nExamples:")
	fmt.Println("  shadow list")
	fmt.Println("  ls \"@GMT-2024.01.15-10.30.00\"")
	fmt.Println("  get \"@GMT-2024.01.15-10.30.00\\Windows\\NTDS\\ntds.dit\"")
	fmt.Println()
}
