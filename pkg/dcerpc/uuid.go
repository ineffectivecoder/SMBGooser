package dcerpc

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// UUID represents a DCE UUID (16 bytes)
type UUID [16]byte

// String formats the UUID as a string
func (u UUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		encoding.Uint32LE(u[0:4]),
		encoding.Uint16LE(u[4:6]),
		encoding.Uint16LE(u[6:8]),
		u[8:10],
		u[10:16])
}

// ParseUUID parses a UUID string (with or without dashes)
func ParseUUID(s string) (UUID, error) {
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return UUID{}, fmt.Errorf("invalid UUID length: %d", len(s))
	}

	bytes, err := hex.DecodeString(s)
	if err != nil {
		return UUID{}, err
	}

	var uuid UUID
	// Convert from string representation to wire format (mixed endianness)
	uuid[0] = bytes[3]
	uuid[1] = bytes[2]
	uuid[2] = bytes[1]
	uuid[3] = bytes[0]
	uuid[4] = bytes[5]
	uuid[5] = bytes[4]
	uuid[6] = bytes[7]
	uuid[7] = bytes[6]
	copy(uuid[8:16], bytes[8:16])

	return uuid, nil
}

// MustParseUUID parses a UUID and panics on error
func MustParseUUID(s string) UUID {
	uuid, err := ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return uuid
}

// SyntaxID represents an interface or transfer syntax identifier
type SyntaxID struct {
	UUID    UUID
	Version uint32
}

// Marshal serializes the syntax ID
func (s *SyntaxID) Marshal() []byte {
	buf := make([]byte, 20)
	copy(buf[0:16], s.UUID[:])
	encoding.PutUint32LE(buf[16:20], s.Version)
	return buf
}

// Unmarshal deserializes a syntax ID
func (s *SyntaxID) Unmarshal(buf []byte) error {
	if len(buf) < 20 {
		return ErrBufferTooSmall
	}
	copy(s.UUID[:], buf[0:16])
	s.Version = encoding.Uint32LE(buf[16:20])
	return nil
}

// Well-known interface UUIDs
var (
	// NDR Transfer Syntax
	NDRSyntax = SyntaxID{
		UUID:    MustParseUUID("8a885d04-1ceb-11c9-9fe8-08002b104860"),
		Version: 2,
	}

	// NDR64 Transfer Syntax
	NDR64Syntax = SyntaxID{
		UUID:    MustParseUUID("71710533-beba-4937-8319-b5dbef9ccc36"),
		Version: 1,
	}

	// MS-EFSR (PetitPotam)
	EFSR_UUID = MustParseUUID("c681d488-d850-11d0-8c52-00c04fd90f7e")

	// MS-RPRN (PrinterBug/SpoolSample)
	RPRN_UUID = MustParseUUID("12345678-1234-abcd-ef00-0123456789ab")

	// MS-DFSNM (DFSCoerce)
	DFSNM_UUID = MustParseUUID("4fc742e0-4a10-11cf-8273-00aa004ae673")

	// MS-FSRVP (ShadowCoerce)
	FSRVP_UUID = MustParseUUID("a8e0653c-2744-4389-a61d-7373df8b2292")

	// MS-SAMR
	SAMR_UUID = MustParseUUID("12345778-1234-abcd-ef00-0123456789ac")

	// MS-LSAD/LSAR
	LSAR_UUID = MustParseUUID("12345778-1234-abcd-ef00-0123456789ab")

	// MS-SRVS (Server Service)
	SRVS_UUID = MustParseUUID("4b324fc8-1670-01d3-1278-5a47bf6ee188")

	// Endpoint Mapper
	EPM_UUID = MustParseUUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa")
)

// InterfaceInfo describes an RPC interface
type InterfaceInfo struct {
	Name        string
	UUID        UUID
	Version     uint32
	Pipe        string
	Description string
}

// Well-known interfaces
var WellKnownInterfaces = []InterfaceInfo{
	{Name: "EFSR", UUID: EFSR_UUID, Version: 1, Pipe: "efsrpc,lsarpc", Description: "Encrypting File System Remote (PetitPotam)"},
	{Name: "RPRN", UUID: RPRN_UUID, Version: 1, Pipe: "spoolss", Description: "Print System Remote (PrinterBug)"},
	{Name: "DFSNM", UUID: DFSNM_UUID, Version: 3, Pipe: "netdfs", Description: "DFS Namespace Management (DFSCoerce)"},
	{Name: "FSRVP", UUID: FSRVP_UUID, Version: 1, Pipe: "FssagentRpc", Description: "File Server VSS Agent (ShadowCoerce)"},
	{Name: "SAMR", UUID: SAMR_UUID, Version: 1, Pipe: "samr", Description: "SAM Remote Protocol"},
	{Name: "LSAR", UUID: LSAR_UUID, Version: 0, Pipe: "lsarpc", Description: "LSA Remote Protocol"},
	{Name: "SRVS", UUID: SRVS_UUID, Version: 3, Pipe: "srvsvc", Description: "Server Service"},
	{Name: "EPM", UUID: EPM_UUID, Version: 3, Pipe: "epmapper", Description: "Endpoint Mapper"},
}

// LookupInterface finds interface info by UUID
func LookupInterface(uuid UUID) *InterfaceInfo {
	for i := range WellKnownInterfaces {
		if WellKnownInterfaces[i].UUID == uuid {
			return &WellKnownInterfaces[i]
		}
	}
	return nil
}

// LookupInterfaceByName finds interface info by name (case-insensitive)
func LookupInterfaceByName(name string) *InterfaceInfo {
	name = strings.ToUpper(name)
	for i := range WellKnownInterfaces {
		if strings.ToUpper(WellKnownInterfaces[i].Name) == name {
			return &WellKnownInterfaces[i]
		}
	}
	return nil
}
