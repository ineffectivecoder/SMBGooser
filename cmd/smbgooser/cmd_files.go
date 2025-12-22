package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

func registerShareCommands() {
	commands.Register(&Command{
		Name:        "shares",
		Description: "List available shares",
		Usage:       "shares",
		Handler:     cmdShares,
	})

	commands.Register(&Command{
		Name:        "use",
		Aliases:     []string{"connect"},
		Description: "Connect to a share",
		Usage:       "use <sharename>",
		Handler:     cmdUse,
	})

	commands.Register(&Command{
		Name:        "disconnect",
		Aliases:     []string{"disc"},
		Description: "Disconnect from current share",
		Handler:     cmdDisconnect,
	})
}

func cmdShares(ctx context.Context, args []string) error {
	if session == nil {
		return fmt.Errorf("not connected")
	}

	// Common shares to check
	commonShares := []string{
		"ADMIN$", "C$", "D$", "E$",
		"IPC$", "NETLOGON", "SYSVOL",
		"print$", "Users", "Public",
	}

	info_("Enumerating shares on %s...", targetHost)
	fmt.Println()

	found := 0
	for _, shareName := range commonShares {
		tree, err := client.TreeConnect(ctx, shareName)
		if err != nil {
			if verbose {
				debug_("%-15s %s", shareName, err)
			}
			continue
		}

		shareType := "Disk"
		if tree.IsPipe() {
			shareType = "IPC"
		}

		fmt.Printf("  %s%-15s%s [%s]\n", colorGreen, shareName, colorReset, shareType)
		found++

		client.TreeDisconnect(ctx, tree)
	}

	if found == 0 {
		warn_("No accessible shares found")
	} else {
		success_("Found %d accessible share(s)", found)
	}

	return nil
}

func cmdUse(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: use <sharename>")
	}

	if session == nil {
		return fmt.Errorf("not connected")
	}

	shareName := args[0]

	// Disconnect from current share if any
	if currentTree != nil {
		client.TreeDisconnect(ctx, currentTree)
		currentTree = nil
		currentPath = ""
	}

	info_("Connecting to \\\\%s\\%s...", targetHost, shareName)

	tree, err := client.TreeConnect(ctx, shareName)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}

	currentTree = tree
	currentPath = ""

	shareType := "disk"
	if tree.IsPipe() {
		shareType = "IPC"
	}

	success_("Connected to %s (%s share)", shareName, shareType)

	return nil
}

func cmdDisconnect(ctx context.Context, args []string) error {
	if currentTree == nil {
		return fmt.Errorf("not connected to any share")
	}

	shareName := currentTree.ShareName()
	client.TreeDisconnect(ctx, currentTree)
	currentTree = nil
	currentPath = ""

	success_("Disconnected from %s", shareName)

	return nil
}

func registerFileCommands() {
	commands.Register(&Command{
		Name:        "ls",
		Aliases:     []string{"dir", "list"},
		Description: "List directory contents",
		Usage:       "ls [path]",
		Handler:     cmdLs,
	})

	commands.Register(&Command{
		Name:        "cd",
		Description: "Change directory",
		Usage:       "cd <path>",
		Handler:     cmdCd,
	})

	commands.Register(&Command{
		Name:        "pwd",
		Description: "Print working directory",
		Handler:     cmdPwd,
	})

	commands.Register(&Command{
		Name:        "cat",
		Aliases:     []string{"type"},
		Description: "Display file contents",
		Usage:       "cat <file>",
		Handler:     cmdCat,
	})

	commands.Register(&Command{
		Name:        "get",
		Aliases:     []string{"download"},
		Description: "Download a file",
		Usage:       "get <remote> [local]",
		Handler:     cmdGet,
	})

	commands.Register(&Command{
		Name:        "put",
		Aliases:     []string{"upload"},
		Description: "Upload a file",
		Usage:       "put <local> [remote]",
		Handler:     cmdPut,
	})

	commands.Register(&Command{
		Name:        "mkdir",
		Aliases:     []string{"md"},
		Description: "Create a directory",
		Usage:       "mkdir <path>",
		Handler:     cmdMkdir,
	})

	commands.Register(&Command{
		Name:        "rmdir",
		Aliases:     []string{"rd"},
		Description: "Remove a directory",
		Usage:       "rmdir <path>",
		Handler:     cmdRmdir,
	})

	commands.Register(&Command{
		Name:        "rm",
		Aliases:     []string{"del", "delete"},
		Description: "Delete a file",
		Usage:       "rm <file>",
		Handler:     cmdRm,
	})
}

func cmdLs(ctx context.Context, args []string) error {
	if currentTree == nil {
		return fmt.Errorf("not connected to a share (use 'use <share>' first)")
	}

	// IPC$ shares don't support file operations
	if currentTree.ShareType() == types.ShareTypePipe {
		return fmt.Errorf("IPC$ shares don't support file operations. Use 'pipes' or 'rpc' commands instead")
	}

	path := currentPath
	if len(args) > 0 {
		path = resolvePath(args[0])
	}

	files, err := currentTree.ListDirectory(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to list: %v", err)
	}

	fmt.Println()
	for _, f := range files {
		attrs := ""
		if f.IsDir {
			attrs = colorBlue + "DIR " + colorReset
		} else {
			attrs = "    "
		}

		sizeStr := formatSize(f.Size)
		timeStr := f.LastWriteTime.Format("2006-01-02 15:04")

		name := f.Name
		if f.IsDir {
			name = colorBlue + name + "/" + colorReset
		}

		fmt.Printf("  %s %10s  %s  %s\n", attrs, sizeStr, timeStr, name)
	}
	fmt.Printf("\n  %d item(s)\n\n", len(files))

	return nil
}

func cmdCd(ctx context.Context, args []string) error {
	if currentTree == nil {
		return fmt.Errorf("not connected to a share")
	}

	if len(args) < 1 {
		currentPath = ""
		return nil
	}

	newPath := resolvePath(args[0])

	// Try to list directory to verify it exists
	_, err := currentTree.ListDirectory(ctx, newPath)
	if err != nil {
		return fmt.Errorf("cannot access: %v", err)
	}

	currentPath = newPath
	return nil
}

func cmdPwd(ctx context.Context, args []string) error {
	if currentTree == nil {
		return fmt.Errorf("not connected to a share")
	}

	path := "\\\\" + targetHost + "\\" + currentTree.ShareName()
	if currentPath != "" {
		path += "\\" + currentPath
	}
	fmt.Println(path)
	return nil
}

func cmdCat(ctx context.Context, args []string) error {
	if currentTree == nil {
		return fmt.Errorf("not connected to a share")
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: cat <file>")
	}

	path := resolvePath(args[0])

	file, err := currentTree.OpenFile(ctx, path, types.GenericRead, types.FileOpen)
	if err != nil {
		return fmt.Errorf("failed to open: %v", err)
	}
	defer file.Close()

	// Read in chunks
	buf := make([]byte, 4096)
	for {
		n, err := file.Read(buf)
		if n > 0 {
			fmt.Print(string(buf[:n]))
		}
		if err != nil {
			break
		}
	}
	fmt.Println()

	return nil
}

func cmdGet(ctx context.Context, args []string) error {
	if currentTree == nil {
		return fmt.Errorf("not connected to a share")
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: get <remote> [local]")
	}

	remotePath := resolvePath(args[0])
	localPath := args[0]
	if len(args) > 1 {
		localPath = args[1]
	}
	// Use just the filename if no local path specified
	if !strings.Contains(localPath, "/") && !strings.Contains(localPath, "\\") {
		parts := strings.Split(remotePath, "\\")
		localPath = parts[len(parts)-1]
	}

	info_("Downloading %s -> %s", remotePath, localPath)

	file, err := currentTree.OpenFile(ctx, remotePath, types.GenericRead, types.FileOpen)
	if err != nil {
		return fmt.Errorf("failed to open remote: %v", err)
	}
	defer file.Close()

	localFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local: %v", err)
	}
	defer localFile.Close()

	buf := make([]byte, 65536)
	total := int64(0)
	for {
		n, err := file.Read(buf)
		if n > 0 {
			localFile.Write(buf[:n])
			total += int64(n)
		}
		if err != nil {
			break
		}
	}

	success_("Downloaded %s (%s)", localPath, formatSize(total))
	return nil
}

func cmdPut(ctx context.Context, args []string) error {
	if currentTree == nil {
		return fmt.Errorf("not connected to a share")
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: put <local> [remote]")
	}

	localPath := args[0]
	remotePath := localPath
	if len(args) > 1 {
		remotePath = args[1]
	}
	remotePath = resolvePath(remotePath)

	info_("Uploading %s -> %s", localPath, remotePath)

	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local: %v", err)
	}
	defer localFile.Close()

	file, err := currentTree.OpenFile(ctx, remotePath,
		types.GenericWrite|types.GenericRead,
		types.FileCreate)
	if err != nil {
		return fmt.Errorf("failed to create remote: %v", err)
	}
	defer file.Close()

	buf := make([]byte, 65536)
	total := int64(0)
	for {
		n, err := localFile.Read(buf)
		if n > 0 {
			file.Write(buf[:n])
			total += int64(n)
		}
		if err != nil {
			break
		}
	}

	success_("Uploaded %s (%s)", remotePath, formatSize(total))
	return nil
}

func cmdMkdir(ctx context.Context, args []string) error {
	if currentTree == nil {
		return fmt.Errorf("not connected to a share")
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: mkdir <path>")
	}

	path := resolvePath(args[0])

	if err := currentTree.Mkdir(ctx, path); err != nil {
		return fmt.Errorf("failed: %v", err)
	}

	success_("Created directory: %s", path)
	return nil
}

func cmdRmdir(ctx context.Context, args []string) error {
	if currentTree == nil {
		return fmt.Errorf("not connected to a share")
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: rmdir <path>")
	}

	path := resolvePath(args[0])

	if err := currentTree.Rmdir(ctx, path); err != nil {
		return fmt.Errorf("failed: %v", err)
	}

	success_("Removed directory: %s", path)
	return nil
}

func cmdRm(ctx context.Context, args []string) error {
	if currentTree == nil {
		return fmt.Errorf("not connected to a share")
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: rm <file>")
	}

	path := resolvePath(args[0])

	if err := currentTree.DeleteFile(ctx, path); err != nil {
		return fmt.Errorf("failed: %v", err)
	}

	success_("Deleted: %s", path)
	return nil
}

// Path utilities
func resolvePath(path string) string {
	// Normalize backslashes to forward slashes first, then back
	path = strings.ReplaceAll(path, "/", "\\")

	// Strip drive letter if present (e.g., C:\Windows -> Windows)
	if len(path) >= 2 && path[1] == ':' {
		path = path[2:]
	}

	// Handle absolute vs relative paths
	if strings.HasPrefix(path, "\\") {
		// Absolute path - strip leading backslash
		return strings.TrimPrefix(path, "\\")
	}

	// Handle .. and .
	if path == ".." {
		if currentPath == "" {
			return ""
		}
		parts := strings.Split(currentPath, "\\")
		if len(parts) > 1 {
			return strings.Join(parts[:len(parts)-1], "\\")
		}
		return ""
	}

	if path == "." {
		return currentPath
	}

	// Relative path
	if currentPath == "" {
		return path
	}
	return currentPath + "\\" + path
}

func formatSize(size int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case size >= GB:
		return fmt.Sprintf("%.1f GB", float64(size)/GB)
	case size >= MB:
		return fmt.Sprintf("%.1f MB", float64(size)/MB)
	case size >= KB:
		return fmt.Sprintf("%.1f KB", float64(size)/KB)
	default:
		return fmt.Sprintf("%d B", size)
	}
}
