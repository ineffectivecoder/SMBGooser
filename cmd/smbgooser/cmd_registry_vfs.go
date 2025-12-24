package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ineffectivecoder/SMBGooser/pkg/rrp"
)

// Registry VFS state (set in main.go)
// registryMode bool
// registryPath string - "" = root (hive selection), "HKLM" = in hive, "HKLM\SOFTWARE" = deeper
// registryClient *rrp.Client

// Known registry hives
var knownHives = []string{"HKLM", "HKCU", "HKU", "HKCR", "HKCC"}

// cmdUseRegistry enters registry VFS mode
func cmdUseRegistry(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	// Exit other modes first
	if eventlogMode {
		eventlogMode = false
		eventlogPath = ""
	}

	// Disconnect from file share if connected
	if currentTree != nil {
		client.TreeDisconnect(ctx, currentTree)
		currentTree = nil
		currentPath = ""
	}

	// Create registry client with retry (Remote Registry service may need time to start)
	info_("Connecting to Remote Registry service...")

	var regClient *rrp.Client
	var err error

	// Try up to 3 times with 1 second delay between attempts
	for attempt := 1; attempt <= 3; attempt++ {
		regClient, err = rrp.NewClient(ctx, client)
		if err == nil {
			break
		}

		if attempt < 3 {
			// Service might be starting up (trigger start), wait and retry
			debug_("Attempt %d failed, retrying in 1s... (%v)", attempt, err)
			time.Sleep(1 * time.Second)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to connect to remote registry: %w (is RemoteRegistry service running?)", err)
	}

	registryClient = regClient
	registryMode = true
	registryPath = ""

	success_("Connected to Remote Registry")
	info_("Use 'ls' to list hives, 'cd HKLM' to enter a hive")

	return nil
}

// cmdRegistryDisconnect exits registry VFS mode
func cmdRegistryDisconnect(ctx context.Context, args []string) error {
	if registryClient != nil {
		registryClient.Close()
		registryClient = nil
	}
	registryMode = false
	registryPath = ""

	success_("Disconnected from Remote Registry")
	return nil
}

// cmdRegistryLs lists hives (at root) or subkeys/values (in key)
func cmdRegistryLs(ctx context.Context, args []string) error {
	if registryClient == nil {
		return fmt.Errorf("registry client not connected")
	}

	// At root - show available hives
	if registryPath == "" {
		return listRegistryHives(ctx)
	}

	// In a key - show subkeys and values
	return listRegistryKey(ctx, registryPath)
}

// listRegistryHives shows available registry hives
func listRegistryHives(ctx context.Context) error {
	fmt.Println()
	fmt.Printf("  %sRegistry Hives:%s\n", colorBold, colorReset)
	fmt.Println("  " + strings.Repeat("-", 40))

	for _, hive := range knownHives {
		// Try to open each hive to check accessibility
		handle, err := registryClient.OpenKey(hive, "")
		if err != nil {
			fmt.Printf("  %s/  %s(inaccessible)%s\n", hive, colorRed, colorReset)
		} else {
			fmt.Printf("  %s%s/%s\n", colorBlue, hive, colorReset)
			registryClient.CloseKey(handle)
		}
	}

	fmt.Println()
	info_("Use 'cd <hive>' to enter (e.g., 'cd HKLM')")
	return nil
}

// listRegistryKey shows subkeys and values for a key path
func listRegistryKey(ctx context.Context, keyPath string) error {
	hive, subkey := parseRegistryPath(keyPath)
	if hive == "" {
		return fmt.Errorf("invalid registry path: %s", keyPath)
	}

	handle, err := registryClient.OpenKey(hive, subkey)
	if err != nil {
		return fmt.Errorf("failed to open key: %w", err)
	}
	defer registryClient.CloseKey(handle)

	fmt.Println()
	fmt.Printf("  %s%s%s\n", colorBold, keyPath, colorReset)
	fmt.Println("  " + strings.Repeat("-", 60))

	// Enumerate subkeys
	keys, err := registryClient.EnumKeys(handle)
	if err == nil && len(keys) > 0 {
		fmt.Printf("\n  %sSubkeys:%s\n", colorCyan, colorReset)
		for _, k := range keys {
			fmt.Printf("    %s%s/%s\n", colorBlue, k, colorReset)
		}
	}

	// Enumerate values
	values, _ := registryClient.EnumValues(handle)
	if len(values) > 0 {
		fmt.Printf("\n  %sValues:%s\n", colorCyan, colorReset)
		fmt.Printf("    %-25s %-15s %s\n", "NAME", "TYPE", "DATA")
		fmt.Println("    " + strings.Repeat("-", 55))
		for _, v := range values {
			printRegistryValueShort(&v)
		}
	}

	if len(keys) == 0 && len(values) == 0 {
		fmt.Println("  (empty key)")
	}

	fmt.Println()
	return nil
}

// cmdRegistryCd navigates into/out of registry keys
func cmdRegistryCd(ctx context.Context, args []string) error {
	if registryClient == nil {
		return fmt.Errorf("registry client not connected")
	}

	// No args or ".." at root -> stay at root
	if len(args) == 0 {
		registryPath = ""
		return nil
	}

	target := args[0]

	// Handle special cases
	switch target {
	case "/", "~", "\\":
		registryPath = ""
		return nil
	case "..":
		if registryPath == "" {
			return nil // Already at root
		}
		// Go up one level
		if idx := strings.LastIndex(registryPath, "\\"); idx > 0 {
			registryPath = registryPath[:idx]
		} else {
			registryPath = "" // Back to root (hive selection)
		}
		return nil
	}

	// Normalize path separators
	target = strings.ReplaceAll(target, "/", "\\")

	// Handle absolute vs relative paths
	var newPath string
	if isHive(target) {
		// Starting fresh from a hive
		newPath = strings.ToUpper(strings.Split(target, "\\")[0])
		if idx := strings.Index(target, "\\"); idx > 0 {
			newPath += target[idx:]
		}
	} else if registryPath == "" {
		// At root, entering a hive
		newPath = strings.ToUpper(target)
	} else {
		// Relative path from current location
		newPath = registryPath + "\\" + target
	}

	// Validate the path exists
	hive, subkey := parseRegistryPath(newPath)
	if hive == "" {
		return fmt.Errorf("invalid path: %s", target)
	}

	handle, err := registryClient.OpenKey(hive, subkey)
	if err != nil {
		return fmt.Errorf("cannot access: %w", err)
	}
	registryClient.CloseKey(handle)

	registryPath = newPath
	return nil
}

// cmdRegistryCat displays full details of a registry value
func cmdRegistryCat(ctx context.Context, args []string) error {
	if registryClient == nil {
		return fmt.Errorf("registry client not connected")
	}

	if len(args) == 0 {
		return fmt.Errorf("usage: cat <value_name>")
	}

	if registryPath == "" {
		return fmt.Errorf("must be inside a registry key (use 'cd HKLM' first)")
	}

	valueName := args[0]

	hive, subkey := parseRegistryPath(registryPath)
	if hive == "" {
		return fmt.Errorf("invalid registry path")
	}

	handle, err := registryClient.OpenKey(hive, subkey)
	if err != nil {
		return fmt.Errorf("failed to open key: %w", err)
	}
	defer registryClient.CloseKey(handle)

	value, err := registryClient.QueryValue(handle, valueName)
	if err != nil {
		return fmt.Errorf("failed to query value: %w", err)
	}

	if value == nil {
		return fmt.Errorf("value not found: %s", valueName)
	}

	printRegistryValueFull(value)
	return nil
}

// cmdRegistryPwd shows current registry path
func cmdRegistryPwd(ctx context.Context, args []string) error {
	if registryPath == "" {
		fmt.Println("\\\\<registry root>")
	} else {
		fmt.Printf("\\\\%s\\%s\n", targetHost, registryPath)
	}
	return nil
}

// Helper functions

// parseRegistryPath splits "HKLM\Path\To\Key" into hive and subkey
func parseRegistryPath(path string) (hive, subkey string) {
	if path == "" {
		return "", ""
	}

	parts := strings.SplitN(path, "\\", 2)
	if len(parts) == 0 {
		return "", ""
	}

	hive = strings.ToUpper(parts[0])
	if len(parts) > 1 {
		subkey = parts[1]
	}

	// Validate hive
	switch hive {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		hive = "HKLM"
	case "HKCU", "HKEY_CURRENT_USER":
		hive = "HKCU"
	case "HKU", "HKEY_USERS":
		hive = "HKU"
	case "HKCR", "HKEY_CLASSES_ROOT":
		hive = "HKCR"
	case "HKCC", "HKEY_CURRENT_CONFIG":
		hive = "HKCC"
	default:
		return "", ""
	}

	return hive, subkey
}

// isHive checks if a string starts with a valid hive name
func isHive(s string) bool {
	upper := strings.ToUpper(s)
	for _, h := range knownHives {
		if strings.HasPrefix(upper, h) {
			return true
		}
	}
	return false
}

// printRegistryValueShort prints a compact value representation
func printRegistryValueShort(val *rrp.RegistryValue) {
	typeName := rrp.ValueTypeName(val.Type)
	dataStr := formatRegistryData(val, 40)
	fmt.Printf("    %-25s %-15s %s\n", truncateStr(val.Name, 25), typeName, dataStr)
}

// printRegistryValueFull prints detailed value information
func printRegistryValueFull(val *rrp.RegistryValue) {
	fmt.Println()
	fmt.Printf("  %sName:%s  %s\n", colorBold, colorReset, val.Name)
	fmt.Printf("  %sType:%s  %s\n", colorBold, colorReset, rrp.ValueTypeName(val.Type))
	fmt.Printf("  %sSize:%s  %d bytes\n", colorBold, colorReset, len(val.Data))
	fmt.Printf("  %sData:%s\n", colorBold, colorReset)

	switch val.Type {
	case rrp.RegSZ, rrp.RegExpandSZ:
		fmt.Printf("    %s\n", rrp.DecodeString(val.Data))
	case rrp.RegDWORD:
		v := rrp.DecodeDWORD(val.Data)
		fmt.Printf("    0x%08X (%d)\n", v, v)
	case rrp.RegQWORD:
		v := rrp.DecodeQWORD(val.Data)
		fmt.Printf("    0x%016X (%d)\n", v, v)
	case rrp.RegMultiSZ:
		// Multi-string: null-separated, double-null terminated
		strs := decodeMultiString(val.Data)
		for i, s := range strs {
			fmt.Printf("    [%d] %s\n", i, s)
		}
	case rrp.RegBinary:
		// Hex dump
		if len(val.Data) <= 256 {
			fmt.Printf("    %s\n", hex.EncodeToString(val.Data))
		} else {
			fmt.Printf("    %s...\n", hex.EncodeToString(val.Data[:256]))
			fmt.Printf("    (%d more bytes)\n", len(val.Data)-256)
		}
	default:
		fmt.Printf("    %s\n", hex.EncodeToString(val.Data))
	}
	fmt.Println()
}

// formatRegistryData formats registry data for short display
func formatRegistryData(val *rrp.RegistryValue, maxLen int) string {
	switch val.Type {
	case rrp.RegSZ, rrp.RegExpandSZ:
		s := rrp.DecodeString(val.Data)
		if len(s) > maxLen {
			return s[:maxLen-3] + "..."
		}
		return s
	case rrp.RegDWORD:
		return fmt.Sprintf("0x%08X", rrp.DecodeDWORD(val.Data))
	case rrp.RegQWORD:
		return fmt.Sprintf("0x%016X", rrp.DecodeQWORD(val.Data))
	case rrp.RegBinary:
		if len(val.Data) > 16 {
			return hex.EncodeToString(val.Data[:16]) + "..."
		}
		return hex.EncodeToString(val.Data)
	case rrp.RegMultiSZ:
		strs := decodeMultiString(val.Data)
		if len(strs) == 0 {
			return "(empty)"
		}
		return fmt.Sprintf("[%d strings]", len(strs))
	default:
		return hex.EncodeToString(val.Data)
	}
}

// decodeMultiString decodes REG_MULTI_SZ (null-separated, double-null terminated)
func decodeMultiString(data []byte) []string {
	var result []string
	var current []rune

	for i := 0; i+1 < len(data); i += 2 {
		ch := uint16(data[i]) | uint16(data[i+1])<<8
		if ch == 0 {
			if len(current) > 0 {
				result = append(result, string(current))
				current = nil
			} else {
				// Double null = end
				break
			}
		} else {
			current = append(current, rune(ch))
		}
	}

	if len(current) > 0 {
		result = append(result, string(current))
	}

	return result
}
