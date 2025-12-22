package dcerpc

import (
	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// Request represents an RPC REQUEST message
type Request struct {
	Header    CommonHeader
	AllocHint uint32
	ContextID uint16
	Opnum     uint16
	StubData  []byte
}

// NewRequest creates an RPC request
func NewRequest(opnum uint16, stubData []byte, callID uint32) *Request {
	return &Request{
		Header: CommonHeader{
			Version:            RPCVersionMajor,
			VersionMinor:       RPCVersionMinor,
			PacketType:         PacketTypeRequest,
			PacketFlags:        PacketFlagFirstFrag | PacketFlagLastFrag,
			DataRepresentation: NDRDataRepresentation,
			CallID:             callID,
		},
		AllocHint: uint32(len(stubData)),
		ContextID: 0,
		Opnum:     opnum,
		StubData:  stubData,
	}
}

// Marshal serializes the request
func (r *Request) Marshal() []byte {
	// Header: 16, Request fixed: 8, Stub data: variable
	totalSize := 16 + 8 + len(r.StubData)
	r.Header.FragLength = uint16(totalSize)
	r.AllocHint = uint32(len(r.StubData))

	buf := make([]byte, totalSize)
	offset := 0

	// Header
	copy(buf[offset:], r.Header.Marshal())
	offset += 16

	// Request specific
	encoding.PutUint32LE(buf[offset:], r.AllocHint)
	offset += 4
	encoding.PutUint16LE(buf[offset:], r.ContextID)
	offset += 2
	encoding.PutUint16LE(buf[offset:], r.Opnum)
	offset += 2

	// Stub data
	copy(buf[offset:], r.StubData)

	return buf
}

// Response represents an RPC RESPONSE message
type Response struct {
	Header      CommonHeader
	AllocHint   uint32
	ContextID   uint16
	CancelCount uint8
	Reserved    uint8
	StubData    []byte
}

// Unmarshal deserializes a response
func (r *Response) Unmarshal(buf []byte) error {
	if len(buf) < 24 {
		return ErrBufferTooSmall
	}

	offset := 0

	// Header
	if err := r.Header.Unmarshal(buf[offset:]); err != nil {
		return err
	}
	offset += 16

	r.AllocHint = encoding.Uint32LE(buf[offset:])
	offset += 4
	r.ContextID = encoding.Uint16LE(buf[offset:])
	offset += 2
	r.CancelCount = buf[offset]
	offset++
	r.Reserved = buf[offset]
	offset++

	// Stub data
	stubLen := int(r.Header.FragLength) - offset
	if stubLen > 0 && offset+stubLen <= len(buf) {
		r.StubData = make([]byte, stubLen)
		copy(r.StubData, buf[offset:offset+stubLen])
	}

	return nil
}

// Fault represents an RPC FAULT response
type Fault struct {
	Header      CommonHeader
	AllocHint   uint32
	ContextID   uint16
	CancelCount uint8
	Reserved    uint8
	Status      uint32 // NTSTATUS or RPC status
}

// Unmarshal deserializes a fault response
func (r *Fault) Unmarshal(buf []byte) error {
	if len(buf) < 28 {
		return ErrBufferTooSmall
	}

	offset := 0
	if err := r.Header.Unmarshal(buf[offset:]); err != nil {
		return err
	}
	offset += 16

	r.AllocHint = encoding.Uint32LE(buf[offset:])
	offset += 4
	r.ContextID = encoding.Uint16LE(buf[offset:])
	offset += 2
	r.CancelCount = buf[offset]
	offset++
	r.Reserved = buf[offset]
	offset++
	r.Status = encoding.Uint32LE(buf[offset:])

	return nil
}

// Common RPC status codes
const (
	RPCStatusOK                  uint32 = 0
	RPCStatusAccessDenied        uint32 = 0x00000005
	RPCStatusInvalidParameter    uint32 = 0x00000057
	RPCStatusUnknownIf           uint32 = 0x1C010003
	RPCStatusProtseqNotSupported uint32 = 0x1C010004
	RPCStatusProcedureOutOfRange uint32 = 0x1C010002
)
