// Package rrp implements MS-RRP (Windows Remote Registry Protocol)
// for remote registry operations over SMB.
package rrp

import (
	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
)

// WINREG interface UUID: 338CD001-2244-31F1-AAAA-900038001003
var WINREG_UUID = dcerpc.MustParseUUID("338cd001-2244-31f1-aaaa-900038001003")

// RRP Opnums
const (
	OpOpenClassesRoot             = 0
	OpOpenCurrentUser             = 1
	OpOpenLocalMachine            = 2
	OpOpenPerformanceData         = 3
	OpOpenUsers                   = 4
	OpBaseRegCloseKey             = 5
	OpBaseRegCreateKey            = 6
	OpBaseRegDeleteKey            = 7
	OpBaseRegDeleteValue          = 8
	OpBaseRegEnumKey              = 9
	OpBaseRegEnumValue            = 10
	OpBaseRegFlushKey             = 11
	OpBaseRegGetKeySec            = 12
	OpBaseRegLoadKey              = 13
	OpBaseRegOpenKey              = 15
	OpBaseRegQueryInfoKey         = 16
	OpBaseRegQueryValue           = 17
	OpBaseRegReplaceKey           = 18
	OpBaseRegRestoreKey           = 19
	OpBaseRegSaveKey              = 20
	OpBaseRegSetKeySec            = 21
	OpBaseRegSetValue             = 22
	OpBaseRegUnloadKey            = 23
	OpOpenCurrentConfig           = 27
	OpBaseRegQueryMultipleValues  = 29
	OpBaseRegSaveKeyEx            = 31
	OpOpenPerformanceText         = 32
	OpOpenPerformanceNlsText      = 33
	OpBaseRegQueryMultipleValues2 = 34
	OpBaseRegDeleteKeyEx          = 35
)

// Registry value types
const (
	RegNone             = 0
	RegSZ               = 1 // Unicode null-terminated string
	RegExpandSZ         = 2 // Unicode with env vars
	RegBinary           = 3 // Binary data
	RegDWORD            = 4 // 32-bit number (little-endian)
	RegDWORDBigEndian   = 5 // 32-bit number (big-endian)
	RegLink             = 6 // Symbolic link
	RegMultiSZ          = 7 // Multiple unicode strings
	RegResourceList     = 8
	RegFullResourceDesc = 9
	RegResourceReqList  = 10
	RegQWORD            = 11 // 64-bit number
)

// Registry access rights
const (
	KeyQueryValue       = 0x0001
	KeySetValue         = 0x0002
	KeyCreateSubKey     = 0x0004
	KeyEnumerateSubKeys = 0x0008
	KeyNotify           = 0x0010
	KeyCreateLink       = 0x0020
	KeyWow64_64Key      = 0x0100
	KeyWow64_32Key      = 0x0200
	KeyRead             = 0x20019
	KeyWrite            = 0x20006
	KeyExecute          = 0x20019
	KeyAllAccess        = 0xF003F
)

// Handle represents an RPC context handle (20 bytes)
type Handle [20]byte

// RegistryValue represents a registry value
type RegistryValue struct {
	Name string
	Type uint32
	Data []byte
}

// ValueTypeName returns a human-readable type name
func ValueTypeName(t uint32) string {
	switch t {
	case RegNone:
		return "REG_NONE"
	case RegSZ:
		return "REG_SZ"
	case RegExpandSZ:
		return "REG_EXPAND_SZ"
	case RegBinary:
		return "REG_BINARY"
	case RegDWORD:
		return "REG_DWORD"
	case RegDWORDBigEndian:
		return "REG_DWORD_BIG_ENDIAN"
	case RegLink:
		return "REG_LINK"
	case RegMultiSZ:
		return "REG_MULTI_SZ"
	case RegQWORD:
		return "REG_QWORD"
	default:
		return "REG_UNKNOWN"
	}
}
