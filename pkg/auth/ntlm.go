package auth

import (
	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// NTLM message signatures and types
var ntlmSignature = [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}

const (
	NtLmNegotiate    = 0x00000001 // Type 1
	NtLmChallenge    = 0x00000002 // Type 2
	NtLmAuthenticate = 0x00000003 // Type 3
)

// NTLMSSP negotiate flags
const (
	NtlmsspNegotiateUnicode                 uint32 = 0x00000001
	NtlmsspNegotiateOEM                     uint32 = 0x00000002
	NtlmsspRequestTarget                    uint32 = 0x00000004
	NtlmsspReserved10                       uint32 = 0x00000008
	NtlmsspNegotiateSign                    uint32 = 0x00000010
	NtlmsspNegotiateSeal                    uint32 = 0x00000020
	NtlmsspNegotiateDatagram                uint32 = 0x00000040
	NtlmsspNegotiateLmKey                   uint32 = 0x00000080
	NtlmsspReserved9                        uint32 = 0x00000100
	NtlmsspNegotiateNTLM                    uint32 = 0x00000200
	NtlmsspReserved8                        uint32 = 0x00000400
	NtlmsspNegotiateAnonymous               uint32 = 0x00000800
	NtlmsspNegotiateOEMDomainSupplied       uint32 = 0x00001000
	NtlmsspNegotiateOEMWorkstationSupplied  uint32 = 0x00002000
	NtlmsspReserved7                        uint32 = 0x00004000
	NtlmsspNegotiateAlwaysSign              uint32 = 0x00008000
	NtlmsspTargetTypeDomain                 uint32 = 0x00010000
	NtlmsspTargetTypeServer                 uint32 = 0x00020000
	NtlmsspReserved6                        uint32 = 0x00040000
	NtlmsspNegotiateExtendedSessionSecurity uint32 = 0x00080000
	NtlmsspNegotiateIdentify                uint32 = 0x00100000
	NtlmsspReserved5                        uint32 = 0x00200000
	NtlmsspRequestNonNTSessionKey           uint32 = 0x00400000
	NtlmsspNegotiateTargetInfo              uint32 = 0x00800000
	NtlmsspReserved4                        uint32 = 0x01000000
	NtlmsspNegotiateVersion                 uint32 = 0x02000000
	NtlmsspReserved3                        uint32 = 0x04000000
	NtlmsspReserved2                        uint32 = 0x08000000
	NtlmsspReserved1                        uint32 = 0x10000000
	NtlmsspNegotiate128                     uint32 = 0x20000000
	NtlmsspNegotiateKeyExchange             uint32 = 0x40000000
	NtlmsspNegotiate56                      uint32 = 0x80000000
)

// DefaultNegotiateFlags for NTLMv2 authentication
var DefaultNegotiateFlags = NtlmsspNegotiateUnicode |
	NtlmsspRequestTarget |
	NtlmsspNegotiateNTLM |
	NtlmsspNegotiateAlwaysSign |
	NtlmsspNegotiateExtendedSessionSecurity |
	NtlmsspNegotiateTargetInfo |
	NtlmsspNegotiateVersion |
	NtlmsspNegotiate128 |
	NtlmsspNegotiateKeyExchange |
	NtlmsspNegotiate56

// NTLMVersion represents the Version field in NTLM messages
type NTLMVersion struct {
	ProductMajorVersion uint8
	ProductMinorVersion uint8
	ProductBuild        uint16
	Reserved            [3]byte
	NTLMRevisionCurrent uint8
}

// DefaultVersion returns a Windows 10 compatible version
func DefaultVersion() NTLMVersion {
	return NTLMVersion{
		ProductMajorVersion: 10,
		ProductMinorVersion: 0,
		ProductBuild:        19041,
		NTLMRevisionCurrent: 15, // NTLMSSP_REVISION_W2K3
	}
}

// Marshal serializes the version
func (v *NTLMVersion) Marshal() []byte {
	buf := make([]byte, 8)
	buf[0] = v.ProductMajorVersion
	buf[1] = v.ProductMinorVersion
	encoding.PutUint16LE(buf[2:4], v.ProductBuild)
	copy(buf[4:7], v.Reserved[:])
	buf[7] = v.NTLMRevisionCurrent
	return buf
}

// AvPair represents an AV_PAIR structure in TargetInfo
type AvPair struct {
	AvID  uint16
	Value []byte
}

// AV_PAIR IDs
const (
	MsvAvEOL             uint16 = 0x0000 // End of list
	MsvAvNbComputerName  uint16 = 0x0001 // NetBIOS computer name
	MsvAvNbDomainName    uint16 = 0x0002 // NetBIOS domain name
	MsvAvDnsComputerName uint16 = 0x0003 // DNS computer name
	MsvAvDnsDomainName   uint16 = 0x0004 // DNS domain name
	MsvAvDnsTreeName     uint16 = 0x0005 // DNS tree name
	MsvAvFlags           uint16 = 0x0006 // Flags
	MsvAvTimestamp       uint16 = 0x0007 // Timestamp
	MsvAvSingleHost      uint16 = 0x0008 // Single Host Data
	MsvAvTargetName      uint16 = 0x0009 // Target name (SPN)
	MsvAvChannelBindings uint16 = 0x000A // Channel Bindings
)

// ParseAvPairs parses AV_PAIR list from TargetInfo buffer
func ParseAvPairs(data []byte) []AvPair {
	var pairs []AvPair
	offset := 0

	for offset+4 <= len(data) {
		avID := encoding.Uint16LE(data[offset : offset+2])
		avLen := encoding.Uint16LE(data[offset+2 : offset+4])
		offset += 4

		if avID == MsvAvEOL {
			break
		}

		if offset+int(avLen) > len(data) {
			break
		}

		pairs = append(pairs, AvPair{
			AvID:  avID,
			Value: data[offset : offset+int(avLen)],
		})
		offset += int(avLen)
	}

	return pairs
}

// MarshalAvPairs serializes AV_PAIR list
func MarshalAvPairs(pairs []AvPair) []byte {
	var buf []byte

	for _, p := range pairs {
		pair := make([]byte, 4+len(p.Value))
		encoding.PutUint16LE(pair[0:2], p.AvID)
		encoding.PutUint16LE(pair[2:4], uint16(len(p.Value)))
		copy(pair[4:], p.Value)
		buf = append(buf, pair...)
	}

	// Add MsvAvEOL
	eol := make([]byte, 4)
	buf = append(buf, eol...)

	return buf
}

// FindAvPair finds an AV_PAIR by ID
func FindAvPair(pairs []AvPair, id uint16) *AvPair {
	for i := range pairs {
		if pairs[i].AvID == id {
			return &pairs[i]
		}
	}
	return nil
}
