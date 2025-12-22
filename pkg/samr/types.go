// Package samr implements MS-SAMR (Security Account Manager Remote Protocol)
// for user and group enumeration.
package samr

import (
	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
)

// SAMR interface UUID: 12345778-1234-ABCD-EF00-0123456789AC
var SAMR_UUID = dcerpc.MustParseUUID("12345778-1234-abcd-ef00-0123456789ac")

// SAMR Opnums
const (
	OpSamrConnect                     = 0
	OpSamrCloseHandle                 = 1
	OpSamrLookupDomainInServer        = 5
	OpSamrEnumerateDomainsInSamServer = 6
	OpSamrOpenDomain                  = 7
	OpSamrEnumerateUsersInDom         = 13
	OpSamrEnumerateGroupsInDom        = 11
	OpSamrEnumerateAliasesInDom       = 15
	OpSamrOpenUser                    = 34
	OpSamrQueryInfoUser               = 36
	OpSamrGetMembersInGroup           = 25
	OpSamrConnect5                    = 64
)

// Access masks
const (
	SamServerConnect      = 0x00000001
	SamServerEnumDomains  = 0x00000010
	SamServerLookupDomain = 0x00000020

	DomainReadPasswordParams = 0x00000001
	DomainListAccounts       = 0x00000100
	DomainLookup             = 0x00000200
	DomainGetAliasMembership = 0x00000020

	UserReadGeneral     = 0x00000001
	UserReadPreferences = 0x00000002
	UserReadLogon       = 0x00000004
	UserListGroups      = 0x00000008
	UserReadAccount     = 0x00000010
)

// Handle represents an RPC context handle (20 bytes)
type Handle [20]byte

// UserInfo represents enumerated user information
type UserInfo struct {
	RID         uint32
	Name        string
	FullName    string
	Description string
	Disabled    bool
}

// GroupInfo represents enumerated group information
type GroupInfo struct {
	RID         uint32
	Name        string
	Description string
	MemberCount uint32
}

// DomainInfo represents domain information
type DomainInfo struct {
	Name string
	SID  string
}
