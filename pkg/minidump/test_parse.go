//go:build ignore

package main

import (
	"fmt"
	"os"

	"github.com/ineffectivecoder/SMBGooser/pkg/minidump"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run test_parse.go <dump.dmp>")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("File size: %d bytes\n", len(data))

	dump, err := minidump.Parse(data)
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("OS Build: %s\n", dump.GetBuildVersion())
	fmt.Printf("Modules: %d\n", len(dump.Modules))

	lsasrv := dump.FindModule("lsasrv.dll")
	if lsasrv != nil {
		fmt.Printf("lsasrv.dll: 0x%016X (%d bytes)\n", lsasrv.BaseOfImage, lsasrv.SizeOfImage)
	}

	// Extract credentials
	if err := dump.ExtractCredentials(); err != nil {
		fmt.Printf("Extraction error: %v\n", err)
	}

	fmt.Printf("\n=== MSV Credentials: %d ===\n", len(dump.Credentials))
	for _, cred := range dump.Credentials {
		fmt.Printf("  %s\n", minidump.FormatCredential(cred))
	}

	fmt.Printf("\n=== Kerberos Credentials: %d ===\n", len(dump.KerberosCredentials))
	for _, cred := range dump.KerberosCredentials {
		fmt.Printf("  %s\n", minidump.FormatKerberosCredential(cred))
	}

	fmt.Printf("\n=== WDIGEST Credentials: %d ===\n", len(dump.WdigestCredentials))
	for _, cred := range dump.WdigestCredentials {
		fmt.Printf("  %s\n", minidump.FormatWdigestCredential(cred))
	}

	fmt.Printf("\n=== DPAPI Master Keys: %d ===\n", len(dump.DPAPIMasterKeys))
	for _, mk := range dump.DPAPIMasterKeys {
		fmt.Printf("  %s\n", minidump.FormatDPAPIMasterKey(mk))
	}
}
