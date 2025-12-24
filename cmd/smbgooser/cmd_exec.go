package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/svcctl"
)

func init() {
	commands.Register(&Command{
		Name:        "exec",
		Description: "Execute command on remote host via SCM",
		Usage:       "exec <command>",
		Handler:     cmdExec,
	})
}

// cmdExec executes a command on the remote host via the Service Control Manager
func cmdExec(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	if len(args) < 1 {
		fmt.Println("\nUsage: exec <command>")
		fmt.Println("\nExecutes a command on the remote host via Service Control Manager.")
		fmt.Println("Runs as SYSTEM. Best for fire-and-forget commands.")
		fmt.Println("Requires admin privileges on the target.")
		fmt.Println("\nExamples:")
		fmt.Println("  exec \"net user hacker Password123! /add\"")
		fmt.Println("  exec \"reg add HKLM\\...\"")
		fmt.Println("  exec \"powershell -c Start-Process ...\"")
		fmt.Println("\nNote: For commands requiring output capture, use 'atexec' instead:")
		fmt.Println("  atexec whoami")
		fmt.Println("  atexec \"dir C:\\Users\"")
		fmt.Println()
		return nil
	}

	// Join all args as the command
	command := strings.Join(args, " ")

	// Enable debug output if verbose mode
	svcctl.Debug = verbose

	info_("Creating SCMR client...")
	creds := svcctl.Credentials{
		Username: currentUser,
		Password: currentPassword,
		Hash:     currentHash,
		Domain:   currentDomain,
	}
	svcClient, err := svcctl.NewClientWithCreds(ctx, client, creds)
	if err != nil {
		return fmt.Errorf("failed to create SCMR client: %w", err)
	}
	defer svcClient.Close()

	info_("Opening Service Control Manager...")
	err = svcClient.OpenSCManager("", svcctl.SCManagerConnect|svcctl.SCManagerCreateService)
	if err != nil {
		return fmt.Errorf("failed to open SCM: %w", err)
	}

	info_("Executing command: %s", command)
	err = svcClient.Execute(command)
	if err != nil {
		return fmt.Errorf("execution failed: %w", err)
	}

	success_("Command sent (fire-and-forget)")
	info_("For output capture, use 'atexec' command instead")

	return nil
}
