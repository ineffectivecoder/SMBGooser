package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/samr"
)

func init() {
	commands.Register(&Command{
		Name:        "users",
		Aliases:     []string{"enum"},
		Description: "Enumerate domain users via SAMR",
		Usage:       "users [-d DOMAIN]",
		Handler:     cmdUsers,
	})

	commands.Register(&Command{
		Name:        "groups",
		Aliases:     []string{},
		Description: "Enumerate domain groups via SAMR",
		Usage:       "groups [-d DOMAIN]",
		Handler:     cmdGroups,
	})

	commands.Register(&Command{
		Name:        "computers",
		Aliases:     []string{"machines"},
		Description: "Enumerate domain computers via SAMR",
		Usage:       "computers [-d DOMAIN]",
		Handler:     cmdComputers,
	})
}

// cmdUsers enumerates users and groups
func cmdUsers(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	// Default domain is the target's domain
	domainName := currentDomain
	showGroups := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				domainName = args[i+1]
				i++
			}
		case "-g", "--groups":
			showGroups = true
		case "-c", "--computers":
			return cmdEnumComputers(ctx, domainName)
		case "-p", "--policy":
			return cmdPasswordPolicy(ctx, domainName)
		case "help":
			printUsersHelp()
			return nil
		}
	}

	if domainName == "" {
		return fmt.Errorf("domain not specified (use -d DOMAIN or connect with -d)")
	}

	info_("Connecting to SAMR service...")
	samrClient, err := samr.NewClient(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create SAMR client: %w", err)
	}
	defer samrClient.Close()

	info_("Connecting to SAM server...")
	if err := samrClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// First try to enumerate available domains to get NetBIOS names
	info_("Enumerating available domains...")
	domains, err := samrClient.EnumerateDomains()
	if err != nil {
		warn_("Could not enumerate domains: %v", err)
	} else if len(domains) > 0 {
		info_("Available domains: %v", domains)
		// Use the first non-Builtin domain
		for _, d := range domains {
			if d != "" && d != "Builtin" {
				info_("Using domain: %s", d)
				domainName = d
				break
			}
		}
	}

	info_("Looking up domain: %s", domainName)
	if err := samrClient.LookupDomain(domainName); err != nil {
		return fmt.Errorf("failed to lookup domain: %w\n  Hint: SAMR uses NetBIOS domain names (e.g., ROOTSHELL) not DNS names (rootshell.ninja)", err)
	}

	info_("Opening domain...")
	if err := samrClient.OpenDomain(); err != nil {
		return fmt.Errorf("failed to open domain: %w", err)
	}

	if showGroups {
		// Enumerate groups
		info_("Enumerating groups...")
		groups, err := samrClient.EnumerateGroups()
		if err != nil {
			return fmt.Errorf("failed to enumerate groups: %w", err)
		}

		fmt.Println()
		fmt.Printf("  %sGroups in %s:%s\n", colorBold, domainName, colorReset)
		fmt.Println("  " + strings.Repeat("-", 50))

		if len(groups) == 0 {
			fmt.Println("  No groups found (or enumeration returned no data)")
		} else {
			for _, g := range groups {
				fmt.Printf("  RID: %-6d  %s\n", g.RID, g.Name)
			}
		}
	} else {
		// Enumerate users
		info_("Enumerating users...")
		users, err := samrClient.EnumerateUsers()
		if err != nil {
			return fmt.Errorf("failed to enumerate users: %w", err)
		}

		fmt.Println()
		fmt.Printf("  %sUsers in %s:%s\n", colorBold, domainName, colorReset)
		fmt.Println("  " + strings.Repeat("-", 50))

		if len(users) == 0 {
			fmt.Println("  No users found (or enumeration returned no data)")
		} else {
			for _, u := range users {
				name := u.Name
				if name == "" {
					name = fmt.Sprintf("(RID %d)", u.RID)
				}
				fmt.Printf("  RID: %-6d  %s\n", u.RID, name)
			}
		}
	}

	fmt.Println()
	return nil
}

// cmdGroups enumerates domain groups
func cmdGroups(ctx context.Context, args []string) error {
	domainName := currentDomain
	for i := 0; i < len(args); i++ {
		if (args[i] == "-d" || args[i] == "--domain") && i+1 < len(args) {
			domainName = args[i+1]
			i++
		}
	}

	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	if domainName == "" {
		return fmt.Errorf("domain not specified (use -d DOMAIN)")
	}

	info_("Connecting to SAMR service...")
	samrClient, err := samr.NewClient(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create SAMR client: %w", err)
	}
	defer samrClient.Close()

	if err := samrClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	info_("Looking up domain: %s", domainName)
	if err := samrClient.LookupDomain(domainName); err != nil {
		return fmt.Errorf("failed to lookup domain: %w", err)
	}

	if err := samrClient.OpenDomain(); err != nil {
		return fmt.Errorf("failed to open domain: %w", err)
	}

	info_("Enumerating groups...")
	groups, err := samrClient.EnumerateGroups()
	if err != nil {
		return fmt.Errorf("failed to enumerate groups: %w", err)
	}

	fmt.Println()
	fmt.Printf("  %sGroups in %s:%s\n", colorBold, domainName, colorReset)
	fmt.Println("  " + strings.Repeat("-", 50))

	if len(groups) == 0 {
		fmt.Println("  No groups found")
	} else {
		for _, g := range groups {
			fmt.Printf("  RID: %-6d  %s\n", g.RID, g.Name)
		}
	}

	fmt.Println()
	success_("Found %d group(s)", len(groups))
	return nil
}

// cmdComputers enumerates domain computers
func cmdComputers(ctx context.Context, args []string) error {
	domainName := currentDomain
	for i := 0; i < len(args); i++ {
		if (args[i] == "-d" || args[i] == "--domain") && i+1 < len(args) {
			domainName = args[i+1]
			i++
		}
	}
	return cmdEnumComputers(ctx, domainName)
}

// cmdPasswordPolicy queries domain password policy
func cmdPasswordPolicy(ctx context.Context, domainName string) error {
	if domainName == "" {
		domainName = currentDomain
	}
	if domainName == "" {
		return fmt.Errorf("domain not specified (use -d DOMAIN)")
	}

	info_("Connecting to SAMR service...")
	samrClient, err := samr.NewClient(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create SAMR client: %w", err)
	}
	defer samrClient.Close()

	if err := samrClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	info_("Looking up domain: %s", domainName)
	if err := samrClient.LookupDomain(domainName); err != nil {
		return fmt.Errorf("failed to lookup domain: %w", err)
	}

	if err := samrClient.OpenDomain(); err != nil {
		return fmt.Errorf("failed to open domain: %w", err)
	}

	info_("Querying password policy...")
	policy, err := samrClient.QueryPasswordPolicy()
	if err != nil {
		return fmt.Errorf("failed to query policy: %w", err)
	}

	fmt.Println()
	fmt.Printf("  %sPassword Policy for %s:%s\n", colorBold, domainName, colorReset)
	fmt.Println("  " + strings.Repeat("-", 50))
	fmt.Printf("  %-25s %d\n", "Min Password Length:", policy.MinPasswordLength)
	fmt.Printf("  %-25s %d\n", "Password History:", policy.PasswordHistoryLen)
	fmt.Printf("  %-25s %s\n", "Max Password Age:", samr.FormatPasswordAge(policy.MaxPasswordAge))
	fmt.Printf("  %-25s %s\n", "Min Password Age:", samr.FormatPasswordAge(policy.MinPasswordAge))
	fmt.Printf("  %-25s %s\n", "Properties:", strings.Join(samr.DescribePasswordProperties(policy.PasswordProperties), ", "))
	fmt.Println()

	return nil
}

// cmdEnumComputers enumerates domain computers
func cmdEnumComputers(ctx context.Context, domainName string) error {
	if domainName == "" {
		domainName = currentDomain
	}
	if domainName == "" {
		return fmt.Errorf("domain not specified (use -d DOMAIN)")
	}

	info_("Connecting to SAMR service...")
	samrClient, err := samr.NewClient(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create SAMR client: %w", err)
	}
	defer samrClient.Close()

	if err := samrClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	info_("Looking up domain: %s", domainName)
	if err := samrClient.LookupDomain(domainName); err != nil {
		return fmt.Errorf("failed to lookup domain: %w", err)
	}

	if err := samrClient.OpenDomain(); err != nil {
		return fmt.Errorf("failed to open domain: %w", err)
	}

	// Use EnumerateUsers with filter for machine accounts
	// Machine accounts have USER_WORKSTATION_TRUST_ACCOUNT flag (0x80)
	info_("Enumerating computer accounts...")
	users, err := samrClient.EnumerateUsers()
	if err != nil {
		return fmt.Errorf("failed to enumerate: %w", err)
	}

	fmt.Println()
	fmt.Printf("  %sComputers in %s:%s\n", colorBold, domainName, colorReset)
	fmt.Println("  " + strings.Repeat("-", 50))

	count := 0
	for _, u := range users {
		// Machine accounts typically end with $
		if strings.HasSuffix(u.Name, "$") {
			fmt.Printf("  RID: %-6d  %s\n", u.RID, u.Name)
			count++
		}
	}

	if count == 0 {
		// Try to show any user with high RID (computers often > 1000)
		for _, u := range users {
			if u.RID >= 1000 {
				fmt.Printf("  RID: %-6d  %s\n", u.RID, u.Name)
				count++
			}
		}
	}

	if count == 0 {
		fmt.Println("  No computer accounts found")
		fmt.Println("  (Try: users -g to see Domain Computers group)")
	}

	fmt.Println()
	success_("Found %d computer(s)", count)
	return nil
}

func printUsersHelp() {
	fmt.Println("\nUsage: users [options]")
	fmt.Println("\nEnumerates users, groups, computers, and password policy via SAMR.")
	fmt.Println("\nOptions:")
	fmt.Println("  -d, --domain <name>   Domain to enumerate (default: connection domain)")
	fmt.Println("  -g, --groups          Enumerate groups")
	fmt.Println("  -c, --computers       Enumerate computer accounts")
	fmt.Println("  -p, --policy          Show password policy")
	fmt.Println("\nExamples:")
	fmt.Println("  users")
	fmt.Println("  users -d CORP")
	fmt.Println("  users -g")
	fmt.Println("  users -c")
	fmt.Println("  users -p")
	fmt.Println()
}
