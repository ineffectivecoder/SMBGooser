package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

func init() {
	commands.Register(&Command{
		Name:        "gpo",
		Aliases:     []string{"policy"},
		Description: "Access Group Policy Objects on SYSVOL",
		Usage:       "gpo [list|scripts|read <path>]",
		Handler:     cmdGPO,
	})
}

// cmdGPO accesses Group Policy Objects
func cmdGPO(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	if len(args) == 0 || args[0] == "list" {
		return listGPOs(ctx)
	}

	if args[0] == "scripts" {
		return listStartupScripts(ctx)
	}

	if args[0] == "help" {
		printGPOHelp()
		return nil
	}

	printGPOHelp()
	return nil
}

// listGPOs lists available GPOs
func listGPOs(ctx context.Context) error {
	// Connect to SYSVOL
	info_("Connecting to SYSVOL share...")
	tree, err := client.TreeConnect(ctx, "SYSVOL")
	if err != nil {
		return fmt.Errorf("failed to connect to SYSVOL: %w", err)
	}
	defer client.TreeDisconnect(ctx, tree)

	// List domain folders
	info_("Enumerating GPOs...")
	domains, err := tree.ListDirectory(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to list SYSVOL: %w", err)
	}

	for _, domain := range domains {
		if !domain.IsDir || domain.Name == "." || domain.Name == ".." {
			continue
		}

		fmt.Println()
		fmt.Printf("  %sDomain: %s%s\n", colorBold, domain.Name, colorReset)
		fmt.Println("  " + strings.Repeat("-", 50))

		// List Policies folder
		policiesPath := domain.Name + "\\Policies"
		policies, err := tree.ListDirectory(ctx, policiesPath)
		if err != nil {
			fmt.Printf("  Could not list policies: %v\n", err)
			continue
		}

		for _, p := range policies {
			if !p.IsDir || p.Name == "." || p.Name == ".." {
				continue
			}

			// Check if it's a GUID
			if strings.HasPrefix(p.Name, "{") {
				fmt.Printf("  %s%s%s\n", colorGreen, p.Name, colorReset)

				// Try to read gpt.ini
				gptPath := policiesPath + "\\" + p.Name + "\\gpt.ini"
				file, err := tree.OpenFile(ctx, gptPath, types.FileReadData, types.FileOpen)
				if err == nil {
					buf := make([]byte, 256)
					n, _ := file.Read(buf)
					if n > 0 {
						fmt.Printf("    gpt.ini: %s\n", strings.TrimSpace(string(buf[:n])))
					}
					file.Close()
				}
			}
		}
	}

	fmt.Println()
	return nil
}

// listStartupScripts lists startup/logon scripts
func listStartupScripts(ctx context.Context) error {
	// Connect to SYSVOL
	info_("Connecting to SYSVOL share...")
	tree, err := client.TreeConnect(ctx, "SYSVOL")
	if err != nil {
		return fmt.Errorf("failed to connect to SYSVOL: %w", err)
	}
	defer client.TreeDisconnect(ctx, tree)

	// Get domain
	domains, err := tree.ListDirectory(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to list SYSVOL: %w", err)
	}

	fmt.Println()
	fmt.Printf("  %sStartup/Logon Scripts:%s\n", colorBold, colorReset)
	fmt.Println("  " + strings.Repeat("-", 60))

	for _, domain := range domains {
		if !domain.IsDir || domain.Name == "." || domain.Name == ".." {
			continue
		}

		// Check Scripts folder
		scriptsPath := domain.Name + "\\scripts"
		scripts, err := tree.ListDirectory(ctx, scriptsPath)
		if err != nil {
			continue
		}

		for _, s := range scripts {
			if s.Name == "." || s.Name == ".." {
				continue
			}
			fmt.Printf("  %s\\scripts\\%s\n", domain.Name, s.Name)
		}

		// Check Policies for scripts
		policiesPath := domain.Name + "\\Policies"
		policies, err := tree.ListDirectory(ctx, policiesPath)
		if err != nil {
			continue
		}

		for _, p := range policies {
			if !p.IsDir || !strings.HasPrefix(p.Name, "{") {
				continue
			}

			// Check Machine\Scripts and User\Scripts
			for _, scriptType := range []string{"Machine\\Scripts\\Startup", "Machine\\Scripts\\Shutdown", "User\\Scripts\\Logon", "User\\Scripts\\Logoff"} {
				scriptPath := policiesPath + "\\" + p.Name + "\\" + scriptType
				scriptFiles, err := tree.ListDirectory(ctx, scriptPath)
				if err != nil {
					continue
				}

				for _, sf := range scriptFiles {
					if sf.Name == "." || sf.Name == ".." {
						continue
					}
					fmt.Printf("  %s[%s]%s %s\\%s\\%s\n",
						colorGreen, scriptType, colorReset,
						p.Name[:8], scriptType, sf.Name)
				}
			}
		}
	}

	fmt.Println()
	return nil
}

func printGPOHelp() {
	fmt.Println("\nUsage: gpo [command]")
	fmt.Println("\nAccess Group Policy Objects on SYSVOL")
	fmt.Println("\nCommands:")
	fmt.Println("  list       List GPOs and their GUIDs")
	fmt.Println("  scripts    List startup/logon scripts")
	fmt.Println("\nCommon GPO abuse:")
	fmt.Println("  1. Find writable GPO scripts folder")
	fmt.Println("  2. Add malicious script")
	fmt.Println("  3. Wait for execution")
	fmt.Println("\nExample:")
	fmt.Println("  gpo list")
	fmt.Println("  gpo scripts")
	fmt.Println("  use SYSVOL")
	fmt.Println("  put backdoor.bat DOMAIN\\Policies\\{GUID}\\Machine\\Scripts\\Startup\\")
	fmt.Println()
}
