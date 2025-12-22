package main

import (
	"context"
	"fmt"
	"time"

	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

func init() {
	commands.Register(&Command{
		Name:        "touch",
		Description: "Modify file timestamps (timestomping)",
		Usage:       "touch <file> [--created <time>] [--modified <time>] [--accessed <time>]",
		Handler:     cmdTouch,
	})
}

func cmdTouch(ctx context.Context, args []string) error {
	if currentTree == nil {
		return fmt.Errorf("not connected to a share")
	}
	if len(args) < 1 {
		printTouchHelp()
		return nil
	}

	// Parse arguments
	var filePath string
	var createdTime, modifiedTime, accessedTime *time.Time

	i := 0
	for i < len(args) {
		arg := args[i]
		switch arg {
		case "--created", "-c":
			if i+1 >= len(args) {
				return fmt.Errorf("--created requires a time argument")
			}
			t, err := parseTimeArg(args[i+1])
			if err != nil {
				return fmt.Errorf("invalid created time: %v", err)
			}
			createdTime = &t
			i += 2
		case "--modified", "-m":
			if i+1 >= len(args) {
				return fmt.Errorf("--modified requires a time argument")
			}
			t, err := parseTimeArg(args[i+1])
			if err != nil {
				return fmt.Errorf("invalid modified time: %v", err)
			}
			modifiedTime = &t
			i += 2
		case "--accessed", "-a":
			if i+1 >= len(args) {
				return fmt.Errorf("--accessed requires a time argument")
			}
			t, err := parseTimeArg(args[i+1])
			if err != nil {
				return fmt.Errorf("invalid accessed time: %v", err)
			}
			accessedTime = &t
			i += 2
		case "help":
			printTouchHelp()
			return nil
		default:
			if filePath == "" {
				filePath = arg
			}
			i++
		}
	}

	if filePath == "" {
		return fmt.Errorf("usage: touch <file> [--created <time>] [--modified <time>] [--accessed <time>]")
	}

	// If no times specified, set all to now
	if createdTime == nil && modifiedTime == nil && accessedTime == nil {
		now := time.Now()
		createdTime = &now
		modifiedTime = &now
		accessedTime = &now
	}

	remotePath := resolvePath(filePath)
	info_("Modifying timestamps for %s", remotePath)

	// Open file with write attributes permission
	file, err := currentTree.OpenFile(ctx, remotePath,
		types.FileWriteAttributes|types.Synchronize,
		types.FileOpen)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Set file times
	if err := file.SetTimes(createdTime, accessedTime, modifiedTime); err != nil {
		return fmt.Errorf("failed to set times: %v", err)
	}

	// Report what was changed
	if createdTime != nil {
		success_("Created:   %s", createdTime.Format("2006-01-02 15:04:05"))
	}
	if accessedTime != nil {
		success_("Accessed:  %s", accessedTime.Format("2006-01-02 15:04:05"))
	}
	if modifiedTime != nil {
		success_("Modified:  %s", modifiedTime.Format("2006-01-02 15:04:05"))
	}

	return nil
}

// parseTimeArg parses various time formats
func parseTimeArg(s string) (time.Time, error) {
	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
		"01/02/2006 15:04:05",
		"01/02/2006",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unrecognized time format (use YYYY-MM-DD HH:MM:SS)")
}

func printTouchHelp() {
	fmt.Println("\nUsage: touch <file> [options]")
	fmt.Println("\nModify file timestamps (timestomping for forensic evasion)")
	fmt.Println("\nOptions:")
	fmt.Println("  --created, -c <time>   Set creation time")
	fmt.Println("  --modified, -m <time>  Set modification time")
	fmt.Println("  --accessed, -a <time>  Set last access time")
	fmt.Println("\nTime formats:")
	fmt.Println("  YYYY-MM-DD HH:MM:SS    (e.g., 2020-01-15 09:30:00)")
	fmt.Println("  YYYY-MM-DD             (e.g., 2020-01-15)")
	fmt.Println("\nExamples:")
	fmt.Println("  touch malware.exe                           # Set all times to now")
	fmt.Println("  touch file.txt --modified \"2020-01-15 09:30:00\"")
	fmt.Println("  touch file.txt -c \"2019-06-01\" -m \"2019-06-15\"")
	fmt.Println()
}
