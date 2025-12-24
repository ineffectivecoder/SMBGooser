package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/minidump"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: parsetest <minidump.dmp>")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Parsing %s (%d bytes)...\n\n", os.Args[1], len(data))

	dump, err := minidump.Parse(data)
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("=== SYSTEM INFO ===\n")
	fmt.Printf("OS Build: %s\n", dump.GetBuildVersion())
	fmt.Printf("Modules loaded: %d\n\n", len(dump.Modules))

	fmt.Printf("=== KEY MODULES ===\n")
	for i, mod := range dump.Modules {
		name := strings.ToLower(mod.ModuleName)
		if strings.Contains(name, "lsasrv") ||
			strings.Contains(name, "msv1_0") ||
			strings.Contains(name, "wdigest") ||
			strings.Contains(name, "kerberos") ||
			strings.Contains(name, "lsass") {
			fmt.Printf("[%03d] 0x%016X  %8d KB  %s\n", i, mod.BaseOfImage, mod.SizeOfImage/1024, mod.ModuleName)
		}
	}
	fmt.Println()

	// Test FindModule
	fmt.Printf("=== FINDING MODULES ===\n")
	lsasrv := dump.FindModule("lsasrv.dll")
	if lsasrv != nil {
		fmt.Printf("lsasrv.dll: 0x%016X (%d KB)\n", lsasrv.BaseOfImage, lsasrv.SizeOfImage/1024)
	} else {
		fmt.Println("lsasrv.dll: NOT FOUND")
	}

	msv := dump.FindModule("msv1_0.dll")
	if msv != nil {
		fmt.Printf("msv1_0.dll: 0x%016X (%d KB)\n", msv.BaseOfImage, msv.SizeOfImage/1024)
	} else {
		fmt.Println("msv1_0.dll: NOT FOUND")
	}
	fmt.Println()

	// Test credential extraction
	fmt.Printf("=== CREDENTIAL EXTRACTION ===\n")
	if err := dump.ExtractCredentials(); err != nil {
		fmt.Printf("Extraction error: %v\n", err)
	}

	if len(dump.Credentials) > 0 {
		fmt.Printf("Found %d credentials:\n", len(dump.Credentials))
		for _, cred := range dump.Credentials {
			fmt.Printf("  %s\n", minidump.FormatCredential(cred))
		}
	} else {
		fmt.Println("No credentials extracted")
	}
	fmt.Println()

	// Test LSA key finding
	fmt.Printf("=== LSA KEY FINDING ===\n")
	keys, err := dump.FindLSAKeys()
	if err != nil {
		fmt.Printf("Key finding error: %v\n", err)
	} else {
		fmt.Printf("IV (%d bytes): %x\n", len(keys.IV), keys.IV)
		if keys.AESKey != nil {
			fmt.Printf("AES Key (%d bytes): %x\n", len(keys.AESKey), keys.AESKey)
		} else {
			fmt.Println("AES Key: not found")
		}
		if keys.DESKey != nil {
			fmt.Printf("DES Key (%d bytes): %x\n", len(keys.DESKey), keys.DESKey)
		} else {
			fmt.Println("DES Key: not found")
		}
	}
	fmt.Println()

	// Debug MSV credential finding
	fmt.Printf("=== MSV DEBUG ===\n")
	fmt.Println(dump.DebugMSV())
}
