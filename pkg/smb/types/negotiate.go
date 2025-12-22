package types

import (
	"errors"

	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// NegotiateRequest represents an SMB2 NEGOTIATE request
type NegotiateRequest struct {
	StructureSize          uint16 // 36
	DialectCount           uint16 // Number of dialects
	SecurityMode           SecurityMode
	Reserved               uint16
	Capabilities           Capabilities
	ClientGUID             [16]byte
	NegotiateContextOffset uint32 // SMB 3.1.1
	NegotiateContextCount  uint16 // SMB 3.1.1
	Reserved2              uint16
	Dialects               []Dialect
	// NegotiateContexts for SMB 3.1.1 (optional)
}

// NewNegotiateRequest creates a negotiate request with standard dialects
func NewNegotiateRequest() *NegotiateRequest {
	return &NegotiateRequest{
		StructureSize: 36,
		SecurityMode:  NegotiateSigningEnabled,
		Capabilities:  GlobalCapDFS | GlobalCapLargeMTU,
		Dialects: []Dialect{
			DialectSMB2_0_2,
			DialectSMB2_1,
			DialectSMB3_0,
			DialectSMB3_0_2,
		},
	}
}

// Marshal serializes the negotiate request
func (r *NegotiateRequest) Marshal() []byte {
	r.DialectCount = uint16(len(r.Dialects))

	// Fixed part: 36 bytes
	// Variable part: 2 bytes per dialect
	bufLen := 36 + len(r.Dialects)*2
	buf := make([]byte, bufLen)

	// Offset 0: Structure size (36)
	encoding.PutUint16LE(buf[0:2], r.StructureSize)

	// Offset 2: Dialect count
	encoding.PutUint16LE(buf[2:4], r.DialectCount)

	// Offset 4: Security mode (2 bytes)
	encoding.PutUint16LE(buf[4:6], uint16(r.SecurityMode))

	// Offset 6: Reserved (2 bytes)
	encoding.PutUint16LE(buf[6:8], r.Reserved)

	// Offset 8: Capabilities (4 bytes)
	encoding.PutUint32LE(buf[8:12], uint32(r.Capabilities))

	// Offset 12: Client GUID (16 bytes)
	copy(buf[12:28], r.ClientGUID[:])

	// Offset 28: NegotiateContextOffset (4 bytes, SMB 3.1.1)
	encoding.PutUint32LE(buf[28:32], r.NegotiateContextOffset)

	// Offset 32: NegotiateContextCount (2 bytes, SMB 3.1.1)
	encoding.PutUint16LE(buf[32:34], r.NegotiateContextCount)

	// Offset 34: Reserved2 (2 bytes)
	encoding.PutUint16LE(buf[34:36], r.Reserved2)

	// Dialects (variable, 2 bytes each)
	offset := 36
	for _, d := range r.Dialects {
		encoding.PutUint16LE(buf[offset:offset+2], uint16(d))
		offset += 2
	}

	return buf
}

// NegotiateResponse represents an SMB2 NEGOTIATE response
type NegotiateResponse struct {
	StructureSize          uint16
	SecurityMode           SecurityMode
	DialectRevision        Dialect
	NegotiateContextCount  uint16 // SMB 3.1.1
	ServerGUID             [16]byte
	Capabilities           Capabilities
	MaxTransactSize        uint32
	MaxReadSize            uint32
	MaxWriteSize           uint32
	SystemTime             uint64 // FILETIME
	ServerStartTime        uint64 // FILETIME
	SecurityBufferOffset   uint16
	SecurityBufferLength   uint16
	NegotiateContextOffset uint32 // SMB 3.1.1
	SecurityBuffer         []byte // GSS token (SPNEGO)
}

// Unmarshal deserializes a negotiate response
func (r *NegotiateResponse) Unmarshal(buf []byte) error {
	if len(buf) < 65 { // Minimum size
		return errors.New("buffer too small for negotiate response")
	}

	// Offset 0: StructureSize (2 bytes) - must be 65
	r.StructureSize = encoding.Uint16LE(buf[0:2])
	if r.StructureSize != 65 {
		return errors.New("invalid negotiate response structure size")
	}

	// Offset 2: SecurityMode (2 bytes)
	r.SecurityMode = SecurityMode(encoding.Uint16LE(buf[2:4]))

	// Offset 4: DialectRevision (2 bytes)
	r.DialectRevision = Dialect(encoding.Uint16LE(buf[4:6]))

	// Offset 6: NegotiateContextCount (2 bytes, SMB 3.1.1 only)
	r.NegotiateContextCount = encoding.Uint16LE(buf[6:8])

	// Offset 8: ServerGUID (16 bytes)
	copy(r.ServerGUID[:], buf[8:24])

	// Offset 24: Capabilities (4 bytes)
	r.Capabilities = Capabilities(encoding.Uint32LE(buf[24:28]))

	// Offset 28: MaxTransactSize (4 bytes)
	r.MaxTransactSize = encoding.Uint32LE(buf[28:32])

	// Offset 32: MaxReadSize (4 bytes)
	r.MaxReadSize = encoding.Uint32LE(buf[32:36])

	// Offset 36: MaxWriteSize (4 bytes)
	r.MaxWriteSize = encoding.Uint32LE(buf[36:40])

	// Offset 40: SystemTime (8 bytes)
	r.SystemTime = encoding.Uint64LE(buf[40:48])

	// Offset 48: ServerStartTime (8 bytes)
	r.ServerStartTime = encoding.Uint64LE(buf[48:56])

	// Offset 56: SecurityBufferOffset (2 bytes)
	r.SecurityBufferOffset = encoding.Uint16LE(buf[56:58])

	// Offset 58: SecurityBufferLength (2 bytes)
	r.SecurityBufferLength = encoding.Uint16LE(buf[58:60])

	// Offset 60: NegotiateContextOffset (4 bytes, SMB 3.1.1 only)
	r.NegotiateContextOffset = encoding.Uint32LE(buf[60:64])

	// Security buffer (offset relative to start of SMB2 header)
	if r.SecurityBufferLength > 0 {
		actualOffset := int(r.SecurityBufferOffset) - SMB2HeaderSize
		if actualOffset >= 0 && actualOffset+int(r.SecurityBufferLength) <= len(buf) {
			r.SecurityBuffer = make([]byte, r.SecurityBufferLength)
			copy(r.SecurityBuffer, buf[actualOffset:actualOffset+int(r.SecurityBufferLength)])
		}
	}

	return nil
}

// SupportsDialect checks if the response supports a specific dialect
func (r *NegotiateResponse) SupportsDialect(d Dialect) bool {
	return r.DialectRevision >= d
}

// IsSMB3 returns true if SMB3.x was negotiated
func (r *NegotiateResponse) IsSMB3() bool {
	return r.DialectRevision >= DialectSMB3_0
}

// RequiresSigning returns true if signing is required
func (r *NegotiateResponse) RequiresSigning() bool {
	return r.SecurityMode&NegotiateSigningRequired != 0
}
