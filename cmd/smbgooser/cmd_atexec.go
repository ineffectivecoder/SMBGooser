package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/tsch"
)

func init() {
	commands.Register(&Command{
		Name:        "atexec",
		Description: "Execute command via Task Scheduler",
		Usage:       "atexec <command>",
		Handler:     cmdAtexec,
	})
}

// cmdAtexec executes a command on the remote host via Task Scheduler
func cmdAtexec(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	if len(args) < 1 {
		fmt.Println("\nUsage: atexec <command>")
		fmt.Println("\nExecutes a command on the remote host by creating a scheduled task.")
		fmt.Println("Alternative to 'exec' when svcctl is blocked.")
		fmt.Println("Requires admin privileges on the target.")
		fmt.Println("\nExamples:")
		fmt.Println("  atexec whoami")
		fmt.Println("  atexec \"net user hacker Password123! /add\"")
		fmt.Println("  atexec \"powershell -c \\\"Get-Process\\\"\"")
		fmt.Println("\nNote: Output is not returned. Use file redirection to capture output:")
		fmt.Println("  atexec \"whoami > C:\\\\temp\\\\output.txt\"")
		fmt.Println()
		return nil
	}

	// Join all args as the command
	command := strings.Join(args, " ")

	info_("Creating Task Scheduler client...")
	tschClient, err := tsch.NewClient(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create TSCH client: %w", err)
	}
	defer tschClient.Close()

	info_("Executing command via scheduled task: %s", command)
	err = tschClient.Execute(command)
	if err != nil {
		return fmt.Errorf("execution failed: %w", err)
	}

	success_("Command executed successfully via Task Scheduler")
	info_("Note: Use file redirection to capture output (e.g., whoami > C:\\temp\\out.txt)")

	return nil
}
