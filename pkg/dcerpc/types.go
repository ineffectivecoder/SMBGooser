// Package dcerpc provides DCE/RPC over SMB named pipes.
package dcerpc

import (
	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// RPC Protocol versions
const (
	RPCVersionMajor = 5
	RPCVersionMinor = 0
)

// Packet types
type PacketType uint8

const (
	PacketTypeRequest          PacketType = 0
	PacketTypePing             PacketType = 1
	PacketTypeResponse         PacketType = 2
	PacketTypeFault            PacketType = 3
	PacketTypeWorking          PacketType = 4
	PacketTypeNoCall           PacketType = 5
	PacketTypeReject           PacketType = 6
	PacketTypeAck              PacketType = 7
	PacketTypeCLCancel         PacketType = 8
	PacketTypeFack             PacketType = 9
	PacketTypeCancelAck        PacketType = 10
	PacketTypeBind             PacketType = 11
	PacketTypeBindAck          PacketType = 12
	PacketTypeBindNak          PacketType = 13
	PacketTypeAlterContext     PacketType = 14
	PacketTypeAlterContextResp PacketType = 15
	PacketTypeShutdown         PacketType = 17
	PacketTypeCOCancel         PacketType = 18
	PacketTypeOrphaned         PacketType = 19
)

// Packet flags
const (
	PacketFlagFirstFrag  uint8 = 0x01
	PacketFlagLastFrag   uint8 = 0x02
	PacketFlagPending    uint8 = 0x03
	PacketFlagConcMpx    uint8 = 0x10
	PacketFlagDidNotExec uint8 = 0x20
	PacketFlagMaybe      uint8 = 0x40
	PacketFlagObject     uint8 = 0x80
)

// CommonHeader represents the common RPC header (16 bytes)
type CommonHeader struct {
	Version            uint8
	VersionMinor       uint8
	PacketType         PacketType
	PacketFlags        uint8
	DataRepresentation uint32 // NDR format (little-endian)
	FragLength         uint16
	AuthLength         uint16
	CallID             uint32
}

// NDR Data Representation (little-endian, ASCII, IEEE float)
const NDRDataRepresentation = 0x00000010

// Marshal serializes the common header
func (h *CommonHeader) Marshal() []byte {
	buf := make([]byte, 16)
	buf[0] = h.Version
	buf[1] = h.VersionMinor
	buf[2] = byte(h.PacketType)
	buf[3] = h.PacketFlags
	encoding.PutUint32LE(buf[4:8], h.DataRepresentation)
	encoding.PutUint16LE(buf[8:10], h.FragLength)
	encoding.PutUint16LE(buf[10:12], h.AuthLength)
	encoding.PutUint32LE(buf[12:16], h.CallID)
	return buf
}

// Unmarshal deserializes a common header
func (h *CommonHeader) Unmarshal(buf []byte) error {
	if len(buf) < 16 {
		return ErrBufferTooSmall
	}
	h.Version = buf[0]
	h.VersionMinor = buf[1]
	h.PacketType = PacketType(buf[2])
	h.PacketFlags = buf[3]
	h.DataRepresentation = encoding.Uint32LE(buf[4:8])
	h.FragLength = encoding.Uint16LE(buf[8:10])
	h.AuthLength = encoding.Uint16LE(buf[10:12])
	h.CallID = encoding.Uint32LE(buf[12:16])
	return nil
}
