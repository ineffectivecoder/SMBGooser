package coerce

import "github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"

// CoercionStatus represents the testing status of a method
type CoercionStatus int

const (
	StatusUnknown   CoercionStatus = iota
	StatusCandidate                // Has path param, untested
	StatusConfirmed                // Tested, works
	StatusNegative                 // Tested, doesn't work
)

// InterfaceInfo describes an RPC interface for coercion exploration
type InterfaceInfo struct {
	Name        string // e.g., "MS-EFSR"
	Description string // e.g., "Encrypting File System Remote Protocol"
	UUID        dcerpc.UUID
	Version     uint32
	Pipe        string // e.g., "lsarpc"
	Methods     []MethodInfo
}

// MethodInfo describes a single RPC method
type MethodInfo struct {
	Opnum      uint16
	Name       string
	PathParams []PathParam    // Parameters that accept paths
	StubType   StubType       // Expected stub layout for this method
	Status     CoercionStatus // Confirmed, Candidate, Negative, Unknown
	Notes      string         // Community notes or description
}

// PathParam describes a parameter that could accept a UNC path
type PathParam struct {
	Position int    // Parameter position (0-indexed)
	Name     string // e.g., "FileName"
	Type     string // e.g., "RPC_UNICODE_STRING"
}

// Database returns all known interfaces for coercion exploration
func Database() []InterfaceInfo {
	return knownInterfaces
}

// GetInterface returns an interface by name
func GetInterface(name string) *InterfaceInfo {
	for i := range knownInterfaces {
		if knownInterfaces[i].Name == name {
			return &knownInterfaces[i]
		}
	}
	return nil
}

// GetMethod returns a method by interface and opnum
func GetMethod(ifaceName string, opnum uint16) *MethodInfo {
	iface := GetInterface(ifaceName)
	if iface == nil {
		return nil
	}
	for i := range iface.Methods {
		if iface.Methods[i].Opnum == opnum {
			return &iface.Methods[i]
		}
	}
	return nil
}
