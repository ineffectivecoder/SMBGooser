package samr

import (
	"encoding/binary"
	"fmt"
)

// PasswordPolicy represents domain password policy
type PasswordPolicy struct {
	MinPasswordLength  uint16
	PasswordHistoryLen uint16
	MaxPasswordAge     int64 // In 100ns intervals (negative = days)
	MinPasswordAge     int64
	LockoutThreshold   uint16
	LockoutDuration    int64
	LockoutWindow      int64
	PasswordProperties uint32
}

// PasswordPropertyFlags
const (
	DomainPasswordComplex        = 0x00000001
	DomainPasswordNoAnonChange   = 0x00000002
	DomainPasswordNoClearChange  = 0x00000004
	DomainLockoutAdmins          = 0x00000008
	DomainPasswordStoreCleartext = 0x00000010
	DomainRefusePwdChange        = 0x00000020
)

// Opnum for QueryDomainInfo
const (
	OpSamrQueryDomainInfo = 8
)

// QueryPasswordPolicy queries the domain password policy
func (c *Client) QueryPasswordPolicy() (*PasswordPolicy, error) {
	if c.domainHandle == (Handle{}) {
		return nil, fmt.Errorf("domain not opened - call OpenDomain first")
	}

	stub := encodeQueryDomainInfo(c.domainHandle, 1) // InformationClass 1 = PasswordInformation

	resp, err := c.rpc.Call(OpSamrQueryDomainInfo, stub)
	if err != nil {
		return nil, fmt.Errorf("SamrQueryDomainInfo failed: %w", err)
	}

	return parsePasswordPolicy(resp)
}

// encodeQueryDomainInfo encodes SamrQueryInformationDomain request
func encodeQueryDomainInfo(domainHandle Handle, infoClass uint16) []byte {
	stub := make([]byte, 0, 24)

	// DomainHandle
	stub = append(stub, domainHandle[:]...)

	// DomainInformationClass
	stub = appendUint16(stub, infoClass)
	stub = appendUint16(stub, 0) // Padding

	return stub
}

// parsePasswordPolicy parses the password policy response
func parsePasswordPolicy(resp []byte) (*PasswordPolicy, error) {
	if len(resp) < 28 {
		return nil, fmt.Errorf("response too short")
	}

	// Check return code at end
	retCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retCode != 0 {
		return nil, fmt.Errorf("error: 0x%08X", retCode)
	}

	// Parse DOMAIN_PASSWORD_INFORMATION
	// Skip pointer + info class header
	offset := 4

	if offset+24 > len(resp) {
		return nil, fmt.Errorf("response too short for policy")
	}

	policy := &PasswordPolicy{
		MinPasswordLength:  binary.LittleEndian.Uint16(resp[offset:]),
		PasswordHistoryLen: binary.LittleEndian.Uint16(resp[offset+2:]),
		PasswordProperties: binary.LittleEndian.Uint32(resp[offset+4:]),
		MaxPasswordAge:     int64(binary.LittleEndian.Uint64(resp[offset+8:])),
		MinPasswordAge:     int64(binary.LittleEndian.Uint64(resp[offset+16:])),
	}

	return policy, nil
}

// FormatPasswordAge formats a FILETIME duration to days
func FormatPasswordAge(ft int64) string {
	if ft == 0 {
		return "Never"
	}
	// Convert 100ns intervals to days (negative values)
	if ft < 0 {
		days := float64(-ft) / (10000000 * 60 * 60 * 24)
		return fmt.Sprintf("%.1f days", days)
	}
	return "Unlimited"
}

// DescribePasswordProperties returns a description of password properties
func DescribePasswordProperties(props uint32) []string {
	var desc []string
	if props&DomainPasswordComplex != 0 {
		desc = append(desc, "Complexity required")
	}
	if props&DomainPasswordStoreCleartext != 0 {
		desc = append(desc, "Cleartext storage")
	}
	if props&DomainLockoutAdmins != 0 {
		desc = append(desc, "Lockout admins")
	}
	if len(desc) == 0 {
		desc = append(desc, "None")
	}
	return desc
}
