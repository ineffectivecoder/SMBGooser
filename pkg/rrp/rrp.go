package rrp

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
)

// Client represents a Remote Registry client
type Client struct {
	rpc       *dcerpc.Client
	pipe      *pipe.Pipe
	tree      *smb.Tree
	smbClient *smb.Client
}

// NewClient creates a new Remote Registry client
func NewClient(ctx context.Context, smbClient *smb.Client) (*Client, error) {
	// Get cached IPC$ tree
	tree, err := smbClient.GetIPCTree(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get IPC$ tree: %w", err)
	}

	// Open winreg pipe
	p, err := pipe.Open(ctx, tree, "winreg")
	if err != nil {
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to open winreg pipe: %w", err)
	}

	// Create RPC client
	rpc := dcerpc.NewClient(p)

	// Bind to WINREG interface
	if err := rpc.Bind(WINREG_UUID, 1); err != nil {
		p.Close()
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to bind to WINREG: %w", err)
	}

	return &Client{
		rpc:       rpc,
		pipe:      p,
		tree:      tree,
		smbClient: smbClient,
	}, nil
}

// OpenKey opens a registry key with default read access
func (c *Client) OpenKey(hive string, subkey string) (Handle, error) {
	return c.OpenKeyWithAccess(hive, subkey, KeyRead)
}

// OpenKeyWithAccess opens a registry key with specified access mask
func (c *Client) OpenKeyWithAccess(hive string, subkey string, access uint32) (Handle, error) {
	// First open the hive
	hiveHandle, err := c.openHive(hive)
	if err != nil {
		return Handle{}, err
	}

	// If no subkey, return hive handle
	if subkey == "" {
		return hiveHandle, nil
	}

	// Open the subkey
	keyHandle, err := c.openSubKey(hiveHandle, subkey, access)
	if err != nil {
		c.CloseKey(hiveHandle)
		return Handle{}, err
	}

	c.CloseKey(hiveHandle)
	return keyHandle, nil
}

// openHive opens a root registry hive
func (c *Client) openHive(hive string) (Handle, error) {
	var opnum uint16
	hive = strings.ToUpper(hive)

	switch hive {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		opnum = OpOpenLocalMachine
	case "HKCU", "HKEY_CURRENT_USER":
		opnum = OpOpenCurrentUser
	case "HKU", "HKEY_USERS":
		opnum = OpOpenUsers
	case "HKCR", "HKEY_CLASSES_ROOT":
		opnum = OpOpenClassesRoot
	case "HKCC", "HKEY_CURRENT_CONFIG":
		opnum = OpOpenCurrentConfig
	default:
		return Handle{}, fmt.Errorf("unknown hive: %s", hive)
	}

	// Build request: just access mask
	stub := make([]byte, 8)
	// ServerName (null pointer)
	binary.LittleEndian.PutUint32(stub[0:4], 0)
	// Access mask (MAXIMUM_ALLOWED = 0x02000000, same as Impacket)
	binary.LittleEndian.PutUint32(stub[4:8], 0x02000000)

	resp, err := c.rpc.Call(opnum, stub)
	if err != nil {
		return Handle{}, err
	}

	if len(resp) < 24 {
		return Handle{}, fmt.Errorf("invalid response size: %d", len(resp))
	}

	var handle Handle
	copy(handle[:], resp[:20])

	retCode := binary.LittleEndian.Uint32(resp[20:24])
	if retCode != 0 {
		return Handle{}, fmt.Errorf("open hive failed: 0x%08X", retCode)
	}

	return handle, nil
}

// openSubKey opens a subkey under a parent key
func (c *Client) openSubKey(parent Handle, subkey string, access uint32) (Handle, error) {
	stub := encodeOpenKey(parent, subkey, access)

	resp, err := c.rpc.Call(OpBaseRegOpenKey, stub)
	if err != nil {
		return Handle{}, err
	}

	if len(resp) < 24 {
		return Handle{}, fmt.Errorf("invalid response size: %d", len(resp))
	}

	var handle Handle
	copy(handle[:], resp[:20])

	retCode := binary.LittleEndian.Uint32(resp[20:24])
	if retCode != 0 {
		return Handle{}, fmt.Errorf("open key failed: 0x%08X", retCode)
	}

	return handle, nil
}

// QueryValue reads a registry value
func (c *Client) QueryValue(handle Handle, valueName string) (*RegistryValue, error) {
	stub := encodeQueryValue(handle, valueName)

	resp, err := c.rpc.Call(OpBaseRegQueryValue, stub)
	if err != nil {
		return nil, err
	}

	return parseQueryValueResponse(valueName, resp)
}

// EnumValues enumerates all values under a key
func (c *Client) EnumValues(handle Handle) ([]RegistryValue, error) {
	var values []RegistryValue

	for index := uint32(0); ; index++ {
		stub := encodeEnumValue(handle, index)

		resp, err := c.rpc.Call(OpBaseRegEnumValue, stub)
		if err != nil {
			// ERROR_NO_MORE_ITEMS
			break
		}

		val, err := parseEnumValueResponse(resp)
		if err != nil {
			// No more items or error
			break
		}

		values = append(values, *val)
	}

	return values, nil
}

// EnumKeys enumerates subkeys under a key
func (c *Client) EnumKeys(handle Handle) ([]string, error) {
	var keys []string

	for index := uint32(0); ; index++ {
		stub := encodeEnumKey(handle, index)

		resp, err := c.rpc.Call(OpBaseRegEnumKey, stub)
		if err != nil {
			break
		}

		keyName, err := parseEnumKeyResponse(resp)
		if err != nil {
			break
		}

		keys = append(keys, keyName)
	}

	return keys, nil
}

// SetValue sets a registry value
func (c *Client) SetValue(handle Handle, valueName string, valueType uint32, data []byte) error {
	stub := encodeSetValue(handle, valueName, valueType, data)

	resp, err := c.rpc.Call(OpBaseRegSetValue, stub)
	if err != nil {
		return err
	}

	if len(resp) >= 4 {
		retCode := binary.LittleEndian.Uint32(resp[:4])
		if retCode != 0 {
			return fmt.Errorf("set value failed: 0x%08X", retCode)
		}
	}

	return nil
}

// DeleteValue deletes a registry value
func (c *Client) DeleteValue(handle Handle, valueName string) error {
	stub := encodeDeleteValue(handle, valueName)

	resp, err := c.rpc.Call(OpBaseRegDeleteValue, stub)
	if err != nil {
		return err
	}

	if len(resp) >= 4 {
		retCode := binary.LittleEndian.Uint32(resp[:4])
		if retCode != 0 {
			return fmt.Errorf("delete value failed: 0x%08X", retCode)
		}
	}

	return nil
}

// CreateKey creates a registry key
func (c *Client) CreateKey(handle Handle, subkey string) (Handle, error) {
	stub := encodeCreateKey(handle, subkey)

	resp, err := c.rpc.Call(OpBaseRegCreateKey, stub)
	if err != nil {
		return Handle{}, err
	}

	if len(resp) < 28 {
		return Handle{}, fmt.Errorf("invalid response size: %d", len(resp))
	}

	var newHandle Handle
	copy(newHandle[:], resp[:20])

	// disposition at 20-24, retCode at 24-28
	retCode := binary.LittleEndian.Uint32(resp[24:28])
	if retCode != 0 {
		return Handle{}, fmt.Errorf("create key failed: 0x%08X", retCode)
	}

	return newHandle, nil
}

// DeleteKey deletes a registry key
func (c *Client) DeleteKey(handle Handle, subkey string) error {
	stub := encodeDeleteKey(handle, subkey)

	resp, err := c.rpc.Call(OpBaseRegDeleteKey, stub)
	if err != nil {
		return err
	}

	if len(resp) >= 4 {
		retCode := binary.LittleEndian.Uint32(resp[:4])
		if retCode != 0 {
			return fmt.Errorf("delete key failed: 0x%08X", retCode)
		}
	}

	return nil
}

// SaveKey saves a registry key to a file (requires backup privileges)
func (c *Client) SaveKey(handle Handle, filepath string) error {
	stub := encodeSaveKey(handle, filepath)

	resp, err := c.rpc.Call(OpBaseRegSaveKey, stub)
	if err != nil {
		return err
	}

	if len(resp) >= 4 {
		retCode := binary.LittleEndian.Uint32(resp[:4])
		if retCode != 0 {
			return fmt.Errorf("save key failed: 0x%08X", retCode)
		}
	}

	return nil
}

// CloseKey closes a registry key handle
func (c *Client) CloseKey(handle Handle) error {
	stub := make([]byte, 20)
	copy(stub, handle[:])

	_, err := c.rpc.Call(OpBaseRegCloseKey, stub)
	return err
}

// Close closes the client
func (c *Client) Close() error {
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

// DecodeString decodes a REG_SZ value to string
func DecodeString(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// Decode UTF-16LE
	u16s := make([]uint16, len(data)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(data[i*2:])
	}

	// Remove null terminator
	for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}

	return string(utf16.Decode(u16s))
}

// DecodeDWORD decodes a REG_DWORD value
func DecodeDWORD(data []byte) uint32 {
	if len(data) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(data)
}

// DecodeQWORD decodes a REG_QWORD value
func DecodeQWORD(data []byte) uint64 {
	if len(data) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(data)
}
