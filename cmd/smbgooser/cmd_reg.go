package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/rrp"
)

func init() {
	commands.Register(&Command{
		Name:        "reg",
		Description: "Remote registry operations",
		Usage:       "reg <query|add|delete> ...",
		Handler:     cmdReg,
	})
}

// cmdReg handles registry operations
func cmdReg(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	if len(args) < 1 {
		printRegHelp()
		return nil
	}

	switch strings.ToLower(args[0]) {
	case "query":
		return cmdRegQuery(ctx, args[1:])
	case "add":
		return cmdRegAdd(ctx, args[1:])
	case "delete":
		return cmdRegDelete(ctx, args[1:])
	default:
		printRegHelp()
		return nil
	}
}

func printRegHelp() {
	fmt.Println("\nRegistry subcommands:")
	fmt.Println("  query <key> [value]     Query registry key or value")
	fmt.Println("  add <key> <value> <type> <data>  Add/set registry value")
	fmt.Println("  delete <key> [value]    Delete key or value")
	fmt.Println("\nKey format: HIVE\\Path\\To\\Key")
	fmt.Println("Hives: HKLM, HKCU, HKU, HKCR, HKCC")
	fmt.Println("\nExamples:")
	fmt.Println("  reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion")
	fmt.Println("  reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion ProductName")
	fmt.Println("  reg add HKLM\\SOFTWARE\\Test MyValue REG_SZ \"Hello World\"")
	fmt.Println("  reg delete HKLM\\SOFTWARE\\Test MyValue")
	fmt.Println()
}

// cmdRegQuery queries registry keys/values
func cmdRegQuery(ctx context.Context, args []string) error {
	if len(args) < 1 {
		fmt.Println("Usage: reg query <key> [value]")
		return nil
	}

	keyPath := args[0]
	valueName := ""
	if len(args) > 1 {
		valueName = args[1]
	}

	// Parse hive and subkey
	hive, subkey := parseRegPath(keyPath)
	if hive == "" {
		return fmt.Errorf("invalid key path, must start with HKLM, HKCU, etc.")
	}

	info_("Connecting to remote registry...")
	regClient, err := rrp.NewClient(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create registry client: %w", err)
	}
	defer regClient.Close()

	// Open the key
	info_("Opening %s\\%s...", hive, subkey)
	handle, err := regClient.OpenKey(hive, subkey)
	if err != nil {
		return fmt.Errorf("failed to open key: %w", err)
	}
	defer regClient.CloseKey(handle)

	if valueName != "" {
		// Query specific value
		val, err := regClient.QueryValue(handle, valueName)
		if err != nil {
			return fmt.Errorf("failed to query value: %w", err)
		}
		if val != nil {
			printRegValue(val)
		}
	} else {
		// Enumerate subkeys and values
		fmt.Printf("\n  %s%s\\%s%s\n\n", colorBold, hive, subkey, colorReset)

		// Enumerate subkeys
		keys, _ := regClient.EnumKeys(handle)
		if len(keys) > 0 {
			fmt.Printf("  %sSubkeys:%s\n", colorCyan, colorReset)
			for _, k := range keys {
				fmt.Printf("    %s\n", k)
			}
			fmt.Println()
		}

		// Enumerate values
		values, _ := regClient.EnumValues(handle)
		if len(values) > 0 {
			fmt.Printf("  %sValues:%s\n", colorCyan, colorReset)
			for _, v := range values {
				printRegValue(&v)
			}
		}
		fmt.Println()
	}

	return nil
}

// cmdRegAdd adds/sets a registry value
func cmdRegAdd(ctx context.Context, args []string) error {
	if len(args) < 4 {
		fmt.Println("Usage: reg add <key> <value_name> <type> <data>")
		fmt.Println("Types: REG_SZ, REG_DWORD, REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ")
		return nil
	}

	keyPath := args[0]
	valueName := args[1]
	valueType := strings.ToUpper(args[2])
	valueData := strings.Join(args[3:], " ")

	hive, subkey := parseRegPath(keyPath)
	if hive == "" {
		return fmt.Errorf("invalid key path")
	}

	// Parse value type
	var regType uint32
	switch valueType {
	case "REG_SZ":
		regType = rrp.RegSZ
	case "REG_EXPAND_SZ":
		regType = rrp.RegExpandSZ
	case "REG_DWORD":
		regType = rrp.RegDWORD
	case "REG_BINARY":
		regType = rrp.RegBinary
	case "REG_MULTI_SZ":
		regType = rrp.RegMultiSZ
	case "REG_QWORD":
		regType = rrp.RegQWORD
	default:
		return fmt.Errorf("unsupported type: %s", valueType)
	}

	// Encode data based on type
	var data []byte
	switch regType {
	case rrp.RegSZ, rrp.RegExpandSZ:
		data = encodeRegString(valueData)
	case rrp.RegDWORD:
		var val uint32
		fmt.Sscanf(valueData, "%d", &val)
		data = make([]byte, 4)
		data[0] = byte(val)
		data[1] = byte(val >> 8)
		data[2] = byte(val >> 16)
		data[3] = byte(val >> 24)
	case rrp.RegBinary:
		data, _ = hex.DecodeString(valueData)
	default:
		data = []byte(valueData)
	}

	info_("Connecting to remote registry...")
	regClient, err := rrp.NewClient(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create registry client: %w", err)
	}
	defer regClient.Close()

	handle, err := regClient.OpenKey(hive, subkey)
	if err != nil {
		return fmt.Errorf("failed to open key: %w", err)
	}
	defer regClient.CloseKey(handle)

	info_("Setting %s = %s...", valueName, valueData)
	if err := regClient.SetValue(handle, valueName, regType, data); err != nil {
		return fmt.Errorf("failed to set value: %w", err)
	}

	success_("Value set successfully")
	return nil
}

// cmdRegDelete deletes a registry key or value
func cmdRegDelete(ctx context.Context, args []string) error {
	if len(args) < 1 {
		fmt.Println("Usage: reg delete <key> [value_name]")
		return nil
	}

	keyPath := args[0]
	valueName := ""
	if len(args) > 1 {
		valueName = args[1]
	}

	hive, subkey := parseRegPath(keyPath)
	if hive == "" {
		return fmt.Errorf("invalid key path")
	}

	info_("Connecting to remote registry...")
	regClient, err := rrp.NewClient(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create registry client: %w", err)
	}
	defer regClient.Close()

	if valueName != "" {
		// Delete value
		handle, err := regClient.OpenKey(hive, subkey)
		if err != nil {
			return fmt.Errorf("failed to open key: %w", err)
		}
		defer regClient.CloseKey(handle)

		info_("Deleting value %s...", valueName)
		if err := regClient.DeleteValue(handle, valueName); err != nil {
			return fmt.Errorf("failed to delete value: %w", err)
		}
		success_("Value deleted")
	} else {
		// Delete key - need parent handle
		parentPath := ""
		keyName := subkey
		if idx := strings.LastIndex(subkey, "\\"); idx >= 0 {
			parentPath = subkey[:idx]
			keyName = subkey[idx+1:]
		}

		handle, err := regClient.OpenKey(hive, parentPath)
		if err != nil {
			return fmt.Errorf("failed to open parent key: %w", err)
		}
		defer regClient.CloseKey(handle)

		info_("Deleting key %s...", keyName)
		if err := regClient.DeleteKey(handle, keyName); err != nil {
			return fmt.Errorf("failed to delete key: %w", err)
		}
		success_("Key deleted")
	}

	return nil
}

// parseRegPath splits "HKLM\Path\To\Key" into hive and subkey
func parseRegPath(path string) (hive, subkey string) {
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

// printRegValue prints a registry value
func printRegValue(val *rrp.RegistryValue) {
	typeName := rrp.ValueTypeName(val.Type)
	dataStr := ""

	switch val.Type {
	case rrp.RegSZ, rrp.RegExpandSZ:
		dataStr = rrp.DecodeString(val.Data)
	case rrp.RegDWORD:
		dataStr = fmt.Sprintf("0x%08X (%d)", rrp.DecodeDWORD(val.Data), rrp.DecodeDWORD(val.Data))
	case rrp.RegQWORD:
		dataStr = fmt.Sprintf("0x%016X", rrp.DecodeQWORD(val.Data))
	case rrp.RegBinary:
		if len(val.Data) > 32 {
			dataStr = hex.EncodeToString(val.Data[:32]) + "..."
		} else {
			dataStr = hex.EncodeToString(val.Data)
		}
	default:
		dataStr = hex.EncodeToString(val.Data)
	}

	fmt.Printf("    %-20s %-15s %s\n", val.Name, typeName, dataStr)
}

// encodeRegString encodes a string for REG_SZ (UTF-16LE with null terminator)
func encodeRegString(s string) []byte {
	// Add null terminator
	runes := []rune(s + "\x00")

	// Convert to UTF-16LE
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}
	return buf
}
