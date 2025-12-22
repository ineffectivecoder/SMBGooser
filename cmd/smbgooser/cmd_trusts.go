package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/lsarpc"
)

func init() {
	commands.Register(&Command{
		Name:        "trusts",
		Aliases:     []string{"trust"},
		Description: "Enumerate domain trusts",
		Usage:       "trusts",
		Handler:     cmdTrusts,
	})
}

// cmdTrusts enumerates domain trusts
func cmdTrusts(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	info_("Connecting to LSA RPC...")
	lsaClient, err := lsarpc.NewClient(client)
	if err != nil {
		return fmt.Errorf("failed to create LSARPC client: %w", err)
	}
	defer lsaClient.Close()

	info_("Opening LSA policy...")
	if err := lsaClient.OpenPolicy(""); err != nil {
		return fmt.Errorf("failed to open policy: %w", err)
	}

	// Get domain info
	info_("Querying domain information...")
	domainInfo, err := lsaClient.QueryDomainInfo()
	if err != nil {
		warn_("Failed to query domain info: %v", err)
	} else {
		fmt.Println()
		fmt.Printf("  %sDomain Information:%s\n", colorBold, colorReset)
		fmt.Println("  " + strings.Repeat("-", 50))
		fmt.Printf("  Domain:     %s\n", domainInfo.DomainName)
		fmt.Printf("  DNS:        %s\n", domainInfo.DNSName)
		fmt.Printf("  Forest:     %s\n", domainInfo.ForestName)
		fmt.Printf("  SID:        %s\n", domainInfo.DomainSID)
	}

	// Enumerate trusts
	info_("Enumerating domain trusts...")
	trusts, err := lsaClient.EnumerateTrustedDomains()
	if err != nil {
		return fmt.Errorf("failed to enumerate trusts: %w", err)
	}

	fmt.Println()
	fmt.Printf("  %sTrusted Domains:%s\n", colorBold, colorReset)
	fmt.Println("  " + strings.Repeat("-", 50))

	if len(trusts) == 0 {
		fmt.Println("  No trusts found (standalone or access denied)")
	} else {
		for _, t := range trusts {
			fmt.Printf("  %s%-25s%s  %s\n", colorGreen, t.Name, colorReset, t.SID)
		}
	}

	fmt.Println()
	success_("Found %d trust(s)", len(trusts))

	return nil
}
