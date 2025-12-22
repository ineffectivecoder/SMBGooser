package types

import (
	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
)

// ReadRequest represents an SMB2 READ request
type ReadRequest struct {
	StructureSize         uint16 // 49
	Padding               uint8
	Flags                 uint8
	Length                uint32
	Offset                uint64
	FileID                FileID
	MinimumCount          uint32
	Channel               uint32
	RemainingBytes        uint32
	ReadChannelInfoOffset uint16
	ReadChannelInfoLength uint16
}

// ReadFlags
const (
	ReadFlagRequestCompressed uint8 = 0x01 // SMB 3.1.1
	ReadFlagReadUnbuffered    uint8 = 0x02 // SMB 3.0.2
)

// NewReadRequest creates a READ request
func NewReadRequest(fileID FileID, offset uint64, length uint32) *ReadRequest {
	return &ReadRequest{
		StructureSize: 49,
		Padding:       0x50, // Read buffer offset
		Length:        length,
		Offset:        offset,
		FileID:        fileID,
	}
}

// Marshal serializes the READ request
func (r *ReadRequest) Marshal() []byte {
	buf := make([]byte, 49)

	encoding.PutUint16LE(buf[0:2], r.StructureSize)
	buf[2] = r.Padding
	buf[3] = r.Flags
	encoding.PutUint32LE(buf[4:8], r.Length)
	encoding.PutUint64LE(buf[8:16], r.Offset)
	copy(buf[16:32], r.FileID.Marshal())
	encoding.PutUint32LE(buf[32:36], r.MinimumCount)
	encoding.PutUint32LE(buf[36:40], r.Channel)
	encoding.PutUint32LE(buf[40:44], r.RemainingBytes)
	encoding.PutUint16LE(buf[44:46], r.ReadChannelInfoOffset)
	encoding.PutUint16LE(buf[46:48], r.ReadChannelInfoLength)
	buf[48] = 0 // Buffer (1 byte)

	return buf
}

// ReadResponse represents an SMB2 READ response
type ReadResponse struct {
	StructureSize uint16 // 17
	DataOffset    uint8
	Reserved      uint8
	DataLength    uint32
	DataRemaining uint32
	Reserved2     uint32
	Data          []byte
}

// Unmarshal deserializes a READ response
func (r *ReadResponse) Unmarshal(buf []byte) error {
	if len(buf) < 16 {
		return ErrBufferTooSmall
	}

	r.StructureSize = encoding.Uint16LE(buf[0:2])
	r.DataOffset = buf[2]
	r.Reserved = buf[3]
	r.DataLength = encoding.Uint32LE(buf[4:8])
	r.DataRemaining = encoding.Uint32LE(buf[8:12])
	r.Reserved2 = encoding.Uint32LE(buf[12:16])

	// Extract data
	if r.DataLength > 0 {
		// DataOffset is from start of SMB2 header
		dataStart := int(r.DataOffset) - SMB2HeaderSize
		if dataStart >= 0 && dataStart+int(r.DataLength) <= len(buf) {
			r.Data = make([]byte, r.DataLength)
			copy(r.Data, buf[dataStart:dataStart+int(r.DataLength)])
		}
	}

	return nil
}

// WriteRequest represents an SMB2 WRITE request
type WriteRequest struct {
	StructureSize          uint16 // 49
	DataOffset             uint16
	Length                 uint32
	Offset                 uint64
	FileID                 FileID
	Channel                uint32
	RemainingBytes         uint32
	WriteChannelInfoOffset uint16
	WriteChannelInfoLength uint16
	Flags                  uint32
	Data                   []byte
}

// WriteFlags
const (
	WriteFlagWriteThrough    uint32 = 0x00000001
	WriteFlagWriteUnbuffered uint32 = 0x00000002 // SMB 3.0.2
)

// NewWriteRequest creates a WRITE request
func NewWriteRequest(fileID FileID, offset uint64, data []byte) *WriteRequest {
	return &WriteRequest{
		StructureSize: 49,
		DataOffset:    SMB2HeaderSize + 48 + 1, // Header + fixed - 1 + buffer
		Length:        uint32(len(data)),
		Offset:        offset,
		FileID:        fileID,
		Data:          data,
	}
}

// Marshal serializes the WRITE request
func (r *WriteRequest) Marshal() []byte {
	// Fixed: 48 bytes + 1 buffer byte + data
	bufLen := 49 + len(r.Data)
	buf := make([]byte, bufLen)

	encoding.PutUint16LE(buf[0:2], r.StructureSize)
	encoding.PutUint16LE(buf[2:4], r.DataOffset)
	encoding.PutUint32LE(buf[4:8], r.Length)
	encoding.PutUint64LE(buf[8:16], r.Offset)
	copy(buf[16:32], r.FileID.Marshal())
	encoding.PutUint32LE(buf[32:36], r.Channel)
	encoding.PutUint32LE(buf[36:40], r.RemainingBytes)
	encoding.PutUint16LE(buf[40:42], r.WriteChannelInfoOffset)
	encoding.PutUint16LE(buf[42:44], r.WriteChannelInfoLength)
	encoding.PutUint32LE(buf[44:48], r.Flags)

	// Data (starts at buffer offset, which is byte 48)
	copy(buf[49:], r.Data)

	return buf
}

// WriteResponse represents an SMB2 WRITE response
type WriteResponse struct {
	StructureSize          uint16 // 17
	Reserved               uint16
	Count                  uint32
	Remaining              uint32
	WriteChannelInfoOffset uint16
	WriteChannelInfoLength uint16
}

// Unmarshal deserializes a WRITE response
func (r *WriteResponse) Unmarshal(buf []byte) error {
	if len(buf) < 16 {
		return ErrBufferTooSmall
	}

	r.StructureSize = encoding.Uint16LE(buf[0:2])
	r.Reserved = encoding.Uint16LE(buf[2:4])
	r.Count = encoding.Uint32LE(buf[4:8])
	r.Remaining = encoding.Uint32LE(buf[8:12])
	r.WriteChannelInfoOffset = encoding.Uint16LE(buf[12:14])
	r.WriteChannelInfoLength = encoding.Uint16LE(buf[14:16])

	return nil
}
