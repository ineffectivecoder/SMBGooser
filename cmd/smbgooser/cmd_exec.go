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
		fmt.Println("\nExecutes a command on the remote host by creating a temporary service.")
		fmt.Println("Requires admin privileges on the target.")
		fmt.Println("\nExamples:")
		fmt.Println("  exec whoami")
		fmt.Println("  exec \"net user hacker Password123! /add\"")
		fmt.Println("  exec \"powershell -c \\\"Get-Process\\\"\"")
		fmt.Println("\nNote: Output is not returned. Use file redirection to capture output:")
		fmt.Println("  exec \"whoami > C:\\\\temp\\\\output.txt\"")
		fmt.Println()
		return nil
	}

	// Join all args as the command
	command := strings.Join(args, " ")

	info_("Creating SCMR client...")
	svcClient, err := svcctl.NewClient(ctx, client)
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

	success_("Command executed successfully")
	info_("Note: Use file redirection to capture output (e.g., whoami > C:\\temp\\out.txt)")

	return nil
}
