package dcerpc

import (
	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// BindRequest represents an RPC BIND request
type BindRequest struct {
	Header      CommonHeader
	MaxXmitFrag uint16
	MaxRecvFrag uint16
	AssocGroup  uint32
	NumCtxItems uint8
	Reserved    [3]byte
	CtxItems    []ContextItem
}

// ContextItem represents a presentation context for binding
type ContextItem struct {
	ContextID        uint16
	NumTransItems    uint8
	Reserved         uint8
	AbstractSyntax   SyntaxID
	TransferSyntaxes []SyntaxID
}

// NewBindRequest creates a bind request for an interface
func NewBindRequest(interfaceUUID UUID, interfaceVersion uint32, callID uint32) *BindRequest {
	req := &BindRequest{
		Header: CommonHeader{
			Version:            RPCVersionMajor,
			VersionMinor:       RPCVersionMinor,
			PacketType:         PacketTypeBind,
			PacketFlags:        PacketFlagFirstFrag | PacketFlagLastFrag,
			DataRepresentation: NDRDataRepresentation,
			CallID:             callID,
		},
		MaxXmitFrag: 4280,
		MaxRecvFrag: 4280,
		NumCtxItems: 1,
		CtxItems: []ContextItem{
			{
				ContextID:     0,
				NumTransItems: 1,
				AbstractSyntax: SyntaxID{
					UUID:    interfaceUUID,
					Version: interfaceVersion,
				},
				TransferSyntaxes: []SyntaxID{NDRSyntax},
			},
		},
	}
	return req
}

// Marshal serializes the bind request
func (r *BindRequest) Marshal() []byte {
	// Calculate total size
	// Header: 16, Bind fixed: 12, Context items: 44 each (with 1 transfer syntax)
	ctxSize := 0
	for _, ctx := range r.CtxItems {
		ctxSize += 4 + 20 + len(ctx.TransferSyntaxes)*20
	}
	totalSize := 16 + 12 + ctxSize

	r.Header.FragLength = uint16(totalSize)

	buf := make([]byte, totalSize)
	offset := 0

	// Header
	copy(buf[offset:], r.Header.Marshal())
	offset += 16

	// Bind specific
	encoding.PutUint16LE(buf[offset:], r.MaxXmitFrag)
	offset += 2
	encoding.PutUint16LE(buf[offset:], r.MaxRecvFrag)
	offset += 2
	encoding.PutUint32LE(buf[offset:], r.AssocGroup)
	offset += 4
	buf[offset] = r.NumCtxItems
	offset += 4 // +3 reserved

	// Context items
	for _, ctx := range r.CtxItems {
		encoding.PutUint16LE(buf[offset:], ctx.ContextID)
		offset += 2
		buf[offset] = ctx.NumTransItems
		offset += 2 // +1 reserved

		// Abstract syntax
		copy(buf[offset:], ctx.AbstractSyntax.Marshal())
		offset += 20

		// Transfer syntaxes
		for _, ts := range ctx.TransferSyntaxes {
			copy(buf[offset:], ts.Marshal())
			offset += 20
		}
	}

	return buf
}

// BindAckResult represents the result of a context negotiation
type BindAckResult struct {
	Result         uint16
	Reason         uint16
	TransferSyntax SyntaxID
}

// BindAck represents an RPC BIND_ACK response
type BindAck struct {
	Header      CommonHeader
	MaxXmitFrag uint16
	MaxRecvFrag uint16
	AssocGroup  uint32
	SecAddrLen  uint16
	SecAddr     string
	NumResults  uint8
	Results     []BindAckResult
}

// Unmarshal deserializes a bind ack response
func (r *BindAck) Unmarshal(buf []byte) error {
	if len(buf) < 24 {
		return ErrBufferTooSmall
	}

	offset := 0

	// Header
	if err := r.Header.Unmarshal(buf[offset:]); err != nil {
		return err
	}
	offset += 16

	r.MaxXmitFrag = encoding.Uint16LE(buf[offset:])
	offset += 2
	r.MaxRecvFrag = encoding.Uint16LE(buf[offset:])
	offset += 2
	r.AssocGroup = encoding.Uint32LE(buf[offset:])
	offset += 4
	r.SecAddrLen = encoding.Uint16LE(buf[offset:])
	offset += 2

	// Secondary address
	if int(r.SecAddrLen) > 0 && offset+int(r.SecAddrLen) <= len(buf) {
		r.SecAddr = string(buf[offset : offset+int(r.SecAddrLen)-1]) // -1 for null terminator
		offset += int(r.SecAddrLen)
	}

	// Align to 4 bytes
	if offset%4 != 0 {
		offset += 4 - (offset % 4)
	}

	if offset+4 > len(buf) {
		return ErrBufferTooSmall
	}

	r.NumResults = buf[offset]
	offset += 4 // +3 reserved

	// Results
	for i := 0; i < int(r.NumResults) && offset+24 <= len(buf); i++ {
		result := BindAckResult{
			Result: encoding.Uint16LE(buf[offset:]),
			Reason: encoding.Uint16LE(buf[offset+2:]),
		}
		offset += 4
		result.TransferSyntax.Unmarshal(buf[offset:])
		offset += 20
		r.Results = append(r.Results, result)
	}

	return nil
}

// IsAccepted returns true if the bind was accepted
func (r *BindAck) IsAccepted() bool {
	return len(r.Results) > 0 && r.Results[0].Result == 0
}
