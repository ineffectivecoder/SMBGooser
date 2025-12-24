package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/tsch"
)

func init() {
	commands.Register(&Command{
		Name:        "tsch",
		Aliases:     []string{"tasks", "schtasks"},
		Description: "Task Scheduler operations",
		Usage:       "tsch <subcommand> [args]",
		Handler:     cmdTsch,
	})
}

// cmdTsch handles Task Scheduler operations
func cmdTsch(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	if len(args) < 1 {
		printTschHelp()
		return nil
	}

	subCmd := strings.ToLower(args[0])
	subArgs := args[1:]

	switch subCmd {
	case "list", "ls":
		return cmdTschList(ctx, subArgs)
	case "folders":
		return cmdTschFolders(ctx, subArgs)
	case "help", "?":
		printTschHelp()
		return nil
	default:
		error_("Unknown subcommand: %s", subCmd)
		printTschHelp()
		return nil
	}
}

func printTschHelp() {
	fmt.Println("\nUsage: tsch <subcommand> [args]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  list [path]    - List scheduled tasks (default: \\)")
	fmt.Println("  folders [path] - List task folders")
	fmt.Println("\nExamples:")
	fmt.Println("  tsch list")
	fmt.Println("  tsch list \\Microsoft\\Windows")
	fmt.Println("  tsch folders")
	fmt.Println("  tsch folders \\Microsoft")
	fmt.Println()
}

// cmdTschList lists scheduled tasks
func cmdTschList(ctx context.Context, args []string) error {
	path := "\\"
	if len(args) > 0 {
		path = args[0]
	}

	creds := tsch.Credentials{
		Username: currentUser,
		Password: currentPassword,
		Hash:     currentHash,
		Domain:   currentDomain,
	}

	info_("Creating Task Scheduler client...")
	tschClient, err := tsch.NewClient(ctx, client, creds)
	if err != nil {
		return fmt.Errorf("failed to create tsch client: %w", err)
	}
	defer tschClient.Close()

	info_("Enumerating tasks in %s...", path)
	tasks, err := tschClient.EnumTasks(path)
	if err != nil {
		return fmt.Errorf("failed to enumerate tasks: %w", err)
	}

	if len(tasks) == 0 {
		fmt.Printf("\n  No tasks found in %s\n", path)
		fmt.Println("  Try listing subfolders with: tsch folders", path)
		fmt.Println()
		return nil
	}

	fmt.Printf("\n  %sScheduled Tasks in %s%s\n", colorBold, path, colorReset)
	fmt.Println("  " + strings.Repeat("-", 50))
	for _, task := range tasks {
		fmt.Printf("  %s\n", task)
	}
	fmt.Printf("\n  %d task(s) found\n\n", len(tasks))

	return nil
}

// cmdTschFolders lists task scheduler folders
func cmdTschFolders(ctx context.Context, args []string) error {
	path := "\\"
	if len(args) > 0 {
		path = args[0]
	}

	creds := tsch.Credentials{
		Username: currentUser,
		Password: currentPassword,
		Hash:     currentHash,
		Domain:   currentDomain,
	}

	info_("Creating Task Scheduler client...")
	tschClient, err := tsch.NewClient(ctx, client, creds)
	if err != nil {
		return fmt.Errorf("failed to create tsch client: %w", err)
	}
	defer tschClient.Close()

	info_("Enumerating folders in %s...", path)
	folders, err := tschClient.EnumFolders(path)
	if err != nil {
		return fmt.Errorf("failed to enumerate folders: %w", err)
	}

	if len(folders) == 0 {
		fmt.Printf("\n  No folders found in %s\n\n", path)
		return nil
	}

	fmt.Printf("\n  %sTask Folders in %s%s\n", colorBold, path, colorReset)
	fmt.Println("  " + strings.Repeat("-", 50))
	for _, folder := range folders {
		fmt.Printf("  %s/\n", folder)
	}
	fmt.Printf("\n  %d folder(s) found\n\n", len(folders))

	return nil
}
