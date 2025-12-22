package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

func init() {
	commands.Register(&Command{
		Name:        "find",
		Aliases:     []string{"search"},
		Description: "Search for files in current share",
		Usage:       "find <pattern> [options]",
		Handler:     cmdFind,
	})
}

// cmdFind searches for files matching a pattern
func cmdFind(ctx context.Context, args []string) error {
	if currentTree == nil {
		return fmt.Errorf("not connected to a share (use 'use <share>' first)")
	}

	if currentTree.ShareType() == types.ShareTypePipe {
		return fmt.Errorf("cannot search IPC$ share")
	}

	if len(args) < 1 {
		printFindHelp()
		return nil
	}

	pattern := strings.ToLower(args[0])
	maxDepth := 5
	maxResults := 100
	searchPath := currentPath

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-d", "--depth":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &maxDepth)
				i++
			}
		case "-n", "--max":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &maxResults)
				i++
			}
		case "-p", "--path":
			if i+1 < len(args) {
				searchPath = args[i+1]
				i++
			}
		}
	}

	info_("Searching for '%s' (max depth: %d)...", pattern, maxDepth)
	fmt.Println()

	results := 0
	err := searchDir(ctx, searchPath, pattern, 0, maxDepth, &results, maxResults)
	if err != nil && results == 0 {
		return fmt.Errorf("search failed: %w", err)
	}

	fmt.Println()
	success_("Found %d matching file(s)", results)

	return nil
}

func searchDir(ctx context.Context, path, pattern string, depth, maxDepth int, results *int, maxResults int) error {
	if depth > maxDepth || *results >= maxResults {
		return nil
	}

	files, err := currentTree.ListDirectory(ctx, path)
	if err != nil {
		return err
	}

	for _, f := range files {
		if *results >= maxResults {
			break
		}

		if f.Name == "." || f.Name == ".." {
			continue
		}

		fullPath := f.Name
		if path != "" {
			fullPath = path + "\\" + f.Name
		}

		// Check if name matches pattern
		nameLower := strings.ToLower(f.Name)
		if matchPattern(nameLower, pattern) {
			*results++
			if f.IsDir {
				fmt.Printf("  %s[DIR]%s  %s\n", colorBlue, colorReset, fullPath)
			} else {
				fmt.Printf("  %s  %s\n", formatSize(f.Size), fullPath)
			}
		}

		// Recurse into directories
		if f.IsDir {
			searchDir(ctx, fullPath, pattern, depth+1, maxDepth, results, maxResults)
		}
	}

	return nil
}

// matchPattern checks if name matches glob-like pattern
func matchPattern(name, pattern string) bool {
	// Simple glob matching
	if pattern == "*" {
		return true
	}

	// Handle *.ext patterns
	if strings.HasPrefix(pattern, "*") {
		suffix := pattern[1:]
		return strings.HasSuffix(name, suffix)
	}

	// Handle prefix* patterns
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(name, prefix)
	}

	// Handle *middle* patterns
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		middle := pattern[1 : len(pattern)-1]
		return strings.Contains(name, middle)
	}

	// Exact match or contains
	matched, _ := filepath.Match(pattern, name)
	if matched {
		return true
	}

	return strings.Contains(name, pattern)
}

func printFindHelp() {
	fmt.Println("\nUsage: find <pattern> [options]")
	fmt.Println("\nSearches for files matching the pattern in the current share.")
	fmt.Println("\nOptions:")
	fmt.Println("  -d, --depth <n>    Maximum depth (default: 5)")
	fmt.Println("  -n, --max <n>      Maximum results (default: 100)")
	fmt.Println("  -p, --path <path>  Start path (default: current directory)")
	fmt.Println("\nPatterns:")
	fmt.Println("  *.txt              Files ending in .txt")
	fmt.Println("  pass*              Files starting with 'pass'")
	fmt.Println("  *secret*           Files containing 'secret'")
	fmt.Println("\nExamples:")
	fmt.Println("  find *.xlsx")
	fmt.Println("  find password")
	fmt.Println("  find *.kdbx -d 10")
	fmt.Println()
}
