package smb

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

// NegotiateResult holds the result of dialect negotiation
type NegotiateResult struct {
	Dialect         types.Dialect
	ServerGUID      [16]byte
	MaxTransactSize uint32
	MaxReadSize     uint32
	MaxWriteSize    uint32
	RequiresSigning bool
	SecurityBuffer  []byte // SPNEGO token
	Capabilities    types.Capabilities

	// Encryption (SMB 3.x)
	SupportsEncryption bool   // Server supports encryption
	RequiresEncryption bool   // Server requires encryption
	EncryptionCipher   uint16 // Negotiated cipher (CCM or GCM)
}

// Negotiator handles SMB2 dialect negotiation
type Negotiator struct {
	transport  *Transport
	messageID  uint64
	clientGUID [16]byte
}

// NewNegotiator creates a new negotiator
func NewNegotiator(transport *Transport) *Negotiator {
	n := &Negotiator{
		transport: transport,
		messageID: 0,
	}
	// Generate random client GUID
	rand.Read(n.clientGUID[:])
	return n
}

// Negotiate performs SMB2 dialect negotiation
func (n *Negotiator) Negotiate(ctx context.Context) (*NegotiateResult, error) {
	return n.NegotiateWithDialects(ctx, nil)
}

// NegotiateWithDialects performs negotiation with specific dialects
func (n *Negotiator) NegotiateWithDialects(ctx context.Context, dialects []types.Dialect) (*NegotiateResult, error) {
	// Build negotiate request
	req := types.NewNegotiateRequest()
	if len(dialects) > 0 {
		req.Dialects = dialects
	}
	req.ClientGUID = n.clientGUID

	// Build header
	header := types.NewHeader(types.CommandNegotiate, n.messageID)
	n.messageID++

	// Marshal
	headerBytes := header.Marshal()
	reqBytes := req.Marshal()

	// Combine header + request
	msg := append(headerBytes, reqBytes...)

	// Send and receive
	resp, err := n.transport.SendRecv(msg)
	if err != nil {
		return nil, fmt.Errorf("negotiate failed: %w", err)
	}

	// Parse response
	rawMsg, err := ParseRawMessage(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Parse header
	var respHeader types.Header
	if err := respHeader.Unmarshal(rawMsg.Header); err != nil {
		return nil, fmt.Errorf("failed to parse response header: %w", err)
	}

	// Check status
	if !respHeader.Status.IsSuccess() && respHeader.Status != types.StatusMoreProcessingReq {
		return nil, fmt.Errorf("negotiate failed with status: 0x%08X", respHeader.Status)
	}

	// Parse negotiate response
	var negResp types.NegotiateResponse
	if err := negResp.Unmarshal(rawMsg.Payload); err != nil {
		return nil, fmt.Errorf("failed to parse negotiate response: %w", err)
	}

	// Validate negotiated dialect
	if negResp.DialectRevision == types.DialectWildcard {
		return nil, errors.New("server returned wildcard dialect")
	}

	// Determine encryption support
	supportsEncryption := negResp.Capabilities&types.GlobalCapEncryption != 0
	var encryptionCipher uint16
	if supportsEncryption && negResp.DialectRevision >= types.DialectSMB3_0 {
		// Default cipher selection (negotiate contexts would override this for 3.1.1)
		if negResp.DialectRevision >= types.DialectSMB3_1_1 {
			encryptionCipher = EncryptionAES128GCM
		} else {
			encryptionCipher = EncryptionAES128CCM
		}
	}

	return &NegotiateResult{
		Dialect:            negResp.DialectRevision,
		ServerGUID:         negResp.ServerGUID,
		MaxTransactSize:    negResp.MaxTransactSize,
		MaxReadSize:        negResp.MaxReadSize,
		MaxWriteSize:       negResp.MaxWriteSize,
		RequiresSigning:    negResp.RequiresSigning(),
		SecurityBuffer:     negResp.SecurityBuffer,
		Capabilities:       negResp.Capabilities,
		SupportsEncryption: supportsEncryption,
		EncryptionCipher:   encryptionCipher,
	}, nil
}

// DialectName returns a human-readable dialect name
func DialectName(d types.Dialect) string {
	switch d {
	case types.DialectSMB1:
		return "NT LM 0.12"
	case types.DialectSMB2_0_2:
		return "SMB 2.0.2"
	case types.DialectSMB2_1:
		return "SMB 2.1"
	case types.DialectSMB3_0:
		return "SMB 3.0"
	case types.DialectSMB3_0_2:
		return "SMB 3.0.2"
	case types.DialectSMB3_1_1:
		return "SMB 3.1.1"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", uint16(d))
	}
}

// IsSMB1 returns true if this is an SMB1 dialect
func IsSMB1(d types.Dialect) bool {
	return d == types.DialectSMB1
}
