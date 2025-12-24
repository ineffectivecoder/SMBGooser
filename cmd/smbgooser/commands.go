package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

// Command represents a shell command
type Command struct {
	Name        string
	Aliases     []string
	Description string
	Usage       string
	Handler     func(ctx context.Context, args []string) error
}

// CommandRegistry holds all available commands
type CommandRegistry struct {
	commands map[string]*Command
}

// Global command registry
var commands = NewCommandRegistry()

// NewCommandRegistry creates a new command registry
func NewCommandRegistry() *CommandRegistry {
	return &CommandRegistry{
		commands: make(map[string]*Command),
	}
}

// Register adds a command to the registry
func (r *CommandRegistry) Register(cmd *Command) {
	r.commands[cmd.Name] = cmd
	for _, alias := range cmd.Aliases {
		r.commands[alias] = cmd
	}
}

// Get retrieves a command by name or alias
func (r *CommandRegistry) Get(name string) *Command {
	return r.commands[name]
}

// List returns all unique commands sorted by name
func (r *CommandRegistry) List() []*Command {
	seen := make(map[string]bool)
	var list []*Command

	for _, cmd := range r.commands {
		if !seen[cmd.Name] {
			seen[cmd.Name] = true
			list = append(list, cmd)
		}
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Name < list[j].Name
	})

	return list
}

// executeCommand runs a command by name
func executeCommand(ctx context.Context, name string, args []string) bool {
	cmd := commands.Get(name)
	if cmd == nil {
		error_("Unknown command: %s (type 'help' for commands)", name)
		return true
	}

	if err := cmd.Handler(ctx, args); err != nil {
		error_("%v", err)
	}

	// Return false if we should exit
	return name != "exit" && name != "quit"
}

// Initialize all commands
func init() {
	registerCoreCommands()
	registerShareCommands()
	registerFileCommands()
	registerPipeCommands()
	registerCoerceCommands()
}

// registerCoreCommands registers basic commands
func registerCoreCommands() {
	commands.Register(&Command{
		Name:        "help",
		Aliases:     []string{"?", "h"},
		Description: "Show available commands",
		Usage:       "help [command]",
		Handler:     cmdHelp,
	})

	commands.Register(&Command{
		Name:        "exit",
		Aliases:     []string{"quit", "q"},
		Description: "Exit the shell",
		Handler:     cmdExit,
	})

	commands.Register(&Command{
		Name:        "whoami",
		Description: "Show current session info",
		Handler:     cmdWhoami,
	})

	commands.Register(&Command{
		Name:        "info",
		Description: "Show connection info",
		Handler:     cmdInfo,
	})

	commands.Register(&Command{
		Name:        "clear",
		Aliases:     []string{"cls"},
		Description: "Clear the screen",
		Handler:     cmdClear,
	})
}

// Command handlers
func cmdHelp(ctx context.Context, args []string) error {
	if len(args) > 0 {
		// Show help for specific command
		cmd := commands.Get(args[0])
		if cmd == nil {
			return fmt.Errorf("unknown command: %s", args[0])
		}
		fmt.Printf("\n%s%s%s - %s\n", colorBold, cmd.Name, colorReset, cmd.Description)
		if cmd.Usage != "" {
			fmt.Printf("Usage: %s\n", cmd.Usage)
		}
		if len(cmd.Aliases) > 0 {
			fmt.Printf("Aliases: %s\n", strings.Join(cmd.Aliases, ", "))
		}
		fmt.Println()
		return nil
	}

	// Show eventlog-specific help when in eventlog mode
	if eventlogMode {
		fmt.Println()
		fmt.Printf("%s=== Event Log Virtual Filesystem ===%s\n\n", colorBold, colorReset)
		fmt.Printf("%sNavigation:%s\n", colorCyan, colorReset)
		fmt.Println("  ls                List logs (at root) or events (in log)")
		fmt.Println("  cd <log>          Enter log (Security, System, Application)")
		fmt.Println("  cd ..             Return to log list")
		fmt.Println("  cat <id>          Show full details of event by record ID")
		fmt.Println()
		fmt.Printf("%sSearch:%s\n", colorCyan, colorReset)
		fmt.Println("  find <pattern>    Search all logs for pattern")
		fmt.Println("                    (matches event ID, source, or strings)")
		fmt.Println()
		fmt.Printf("%sOther:%s\n", colorCyan, colorReset)
		fmt.Println("  disconnect        Exit eventlog mode")
		fmt.Println("  help              Show this help")
		fmt.Println("  exit              Exit SMBGooser")
		fmt.Println()
		return nil
	}

	// Show registry-specific help when in registry mode
	if registryMode {
		fmt.Println()
		fmt.Printf("%s=== Registry Virtual Filesystem ===%s\n\n", colorBold, colorReset)
		fmt.Printf("%sNavigation:%s\n", colorCyan, colorReset)
		fmt.Println("  ls                List subkeys and values")
		fmt.Println("  cd <key>          Navigate into a registry key")
		fmt.Println("  cd ..             Go up one level")
		fmt.Println("  pwd               Show current registry path")
		fmt.Println()
		fmt.Printf("%sValues:%s\n", colorCyan, colorReset)
		fmt.Println("  cat <value>       Display full details of a registry value")
		fmt.Println()
		fmt.Printf("%sHives:%s\n", colorCyan, colorReset)
		fmt.Println("  HKLM              HKEY_LOCAL_MACHINE")
		fmt.Println("  HKCU              HKEY_CURRENT_USER")
		fmt.Println("  HKU               HKEY_USERS")
		fmt.Println("  HKCR              HKEY_CLASSES_ROOT")
		fmt.Println("  HKCC              HKEY_CURRENT_CONFIG")
		fmt.Println()
		fmt.Printf("%sOther:%s\n", colorCyan, colorReset)
		fmt.Println("  disconnect        Exit registry mode")
		fmt.Println("  help              Show this help")
		fmt.Println("  exit              Exit SMBGooser")
		fmt.Println()
		return nil
	}

	// Show all commands grouped by category
	fmt.Println()
	fmt.Printf("%s=== SMBGooser Commands ===%s\n\n", colorBold, colorReset)

	categories := map[string][]string{
		"Core":      {"help", "exit", "whoami", "info", "clear"},
		"Shares":    {"shares", "use", "disconnect", "shareaccess"},
		"Files":     {"ls", "cd", "pwd", "cat", "get", "put", "mkdir", "rmdir", "rm", "find", "acl", "touch"},
		"Pipes":     {"pipes", "rpc"},
		"Coercion":  {"coerce", "discover"},
		"Execution": {"exec", "atexec", "ishell"},
		"Registry":  {"reg"},
		"Secrets":   {"secretsdump"},
		"Services":  {"svc"},
		"Recon":     {"users", "sessions", "loggedon", "trusts", "localadmins"},
		"Advanced":  {"shadow", "gpo", "eventlog"},
	}

	order := []string{"Core", "Shares", "Files", "Pipes", "Coercion", "Execution", "Registry", "Secrets", "Services", "Recon", "Advanced"}

	for _, cat := range order {
		cmdNames := categories[cat]
		fmt.Printf("%s%s:%s\n", colorCyan, cat, colorReset)
		for _, name := range cmdNames {
			cmd := commands.Get(name)
			if cmd != nil {
				fmt.Printf("  %-12s %s\n", cmd.Name, cmd.Description)
			}
		}
		fmt.Println()
	}

	return nil
}

func cmdExit(ctx context.Context, args []string) error {
	info_("Goodbye! 🪿")
	return nil
}

func cmdWhoami(ctx context.Context, args []string) error {
	if session == nil {
		return fmt.Errorf("not connected")
	}

	fmt.Println()
	// Show user identity
	if currentDomain != "" {
		fmt.Printf("  %sLogged in as:%s %s\\%s\n", colorBold, colorReset, currentDomain, currentUser)
	} else {
		fmt.Printf("  %sLogged in as:%s %s\n", colorBold, colorReset, currentUser)
	}

	fmt.Printf("\n%sSession Info:%s\n", colorBold, colorReset)
	fmt.Printf("  Session ID:   0x%016X\n", session.SessionID())
	fmt.Printf("  Dialect:      %s\n", smb.DialectName(session.Dialect()))
	fmt.Printf("  Guest:        %v\n", session.IsGuest())
	fmt.Printf("  Max Read:     %d bytes\n", session.MaxReadSize())
	fmt.Printf("  Max Write:    %d bytes\n", session.MaxWriteSize())
	fmt.Println()

	return nil
}

func cmdInfo(ctx context.Context, args []string) error {
	if client == nil {
		return fmt.Errorf("not connected")
	}

	fmt.Printf("\n%sConnection Info:%s\n", colorBold, colorReset)
	fmt.Printf("  Target:       %s\n", targetHost)
	fmt.Printf("  Dialect:      %s\n", client.DialectName())
	fmt.Printf("  Connected:    %v\n", client.IsConnected())

	if currentTree != nil {
		fmt.Printf("  Share:        %s\n", currentTree.ShareName())
		fmt.Printf("  Share Type:   %s\n", shareTypeName(currentTree.ShareType()))
	}
	fmt.Println()

	return nil
}

func cmdClear(ctx context.Context, args []string) error {
	fmt.Print("\033[H\033[2J")
	return nil
}

// Helper to get share type name
func shareTypeName(t types.ShareType) string {
	switch t {
	case types.ShareTypeDisk:
		return "Disk"
	case types.ShareTypePipe:
		return "IPC (Pipe)"
	case types.ShareTypePrint:
		return "Printer"
	default:
		return "Unknown"
	}
}
