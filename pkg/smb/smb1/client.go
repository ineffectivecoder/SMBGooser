// Client provides SMB1 protocol client functionality
package smb1

import (
	"context"
	"fmt"
)

// Transport interface for sending/receiving SMB1 messages
type Transport interface {
	SendRecv(data []byte) ([]byte, error)
	Close() error
}

// Client represents an SMB1 client
type Client struct {
	transport     Transport
	sessionKey    uint32
	uid           uint16
	tid           uint16
	mid           uint16
	maxBufferSize uint32
	capabilities  uint32
	securityBlob  []byte // From negotiate
}

// NewClient creates a new SMB1 client
func NewClient(transport Transport) *Client {
	return &Client{
		transport:     transport,
		maxBufferSize: 16644,
	}
}

// Negotiate performs SMB1 dialect negotiation
func (c *Client) Negotiate(ctx context.Context) (*NegotiateResponse, error) {
	// Build negotiate request
	req := &NegotiateRequest{
		Dialects: []string{DialectNTLM012},
	}

	header := NewHeader(CommandNegotiate, c.nextMID())

	// Combine header + request
	headerBytes := header.Marshal()
	reqBytes := req.Marshal()
	msg := append(headerBytes, reqBytes...)

	// Send and receive
	resp, err := c.transport.SendRecv(msg)
	if err != nil {
		return nil, fmt.Errorf("negotiate failed: %w", err)
	}

	// Parse response header
	var respHeader Header
	if err := respHeader.Unmarshal(resp); err != nil {
		return nil, fmt.Errorf("failed to parse response header: %w", err)
	}

	if !respHeader.IsSuccess() {
		return nil, fmt.Errorf("negotiate error: 0x%08X", respHeader.Status)
	}

	// Parse negotiate response
	var negResp NegotiateResponse
	if err := negResp.Unmarshal(resp[HeaderSize:]); err != nil {
		return nil, fmt.Errorf("failed to parse negotiate response: %w", err)
	}

	// Save capabilities and security blob
	c.capabilities = negResp.Capabilities
	c.securityBlob = negResp.SecurityBlob
	c.maxBufferSize = negResp.MaxBufferSize

	return &negResp, nil
}

// GetSecurityBlob returns the security blob from negotiate
func (c *Client) GetSecurityBlob() []byte {
	return c.securityBlob
}

// SessionSetup performs NTLMSSP authentication
func (c *Client) SessionSetup(ctx context.Context, securityBlob []byte) ([]byte, bool, error) {
	req := &SessionSetupAndXRequest{
		MaxBufferSize: uint16(c.maxBufferSize),
		MaxMpxCount:   50,
		VcNumber:      1,
		SessionKey:    c.sessionKey,
		Capabilities:  c.capabilities | CapExtendedSec,
		SecurityBlob:  securityBlob,
		NativeOS:      "Windows",
		NativeLanMan:  "SMBGooser",
	}

	header := NewHeader(CommandSessionSetupAndX, c.nextMID())

	headerBytes := header.Marshal()
	reqBytes := req.Marshal()
	msg := append(headerBytes, reqBytes...)

	resp, err := c.transport.SendRecv(msg)
	if err != nil {
		return nil, false, fmt.Errorf("session setup failed: %w", err)
	}

	var respHeader Header
	if err := respHeader.Unmarshal(resp); err != nil {
		return nil, false, fmt.Errorf("failed to parse response header: %w", err)
	}

	// Save UID
	c.uid = respHeader.UID

	var sessResp SessionSetupAndXResponse
	if err := sessResp.Unmarshal(resp[HeaderSize:]); err != nil {
		return nil, false, fmt.Errorf("failed to parse session response: %w", err)
	}

	// Check if complete
	isComplete := respHeader.Status == 0

	return sessResp.SecurityBlob, isComplete, nil
}

// TreeConnect connects to a share
func (c *Client) TreeConnect(ctx context.Context, path string) (uint16, error) {
	req := &TreeConnectAndXRequest{
		Flags:       0x0008, // TREE_CONNECT_ANDX_DISCONNECT_TID
		PasswordLen: 1,
		Password:    []byte{0},
		Path:        path,
		Service:     ServiceAny,
	}

	header := NewHeader(CommandTreeConnectAndX, c.nextMID())
	header.UID = c.uid

	headerBytes := header.Marshal()
	reqBytes := req.Marshal()
	msg := append(headerBytes, reqBytes...)

	resp, err := c.transport.SendRecv(msg)
	if err != nil {
		return 0, fmt.Errorf("tree connect failed: %w", err)
	}

	var respHeader Header
	if err := respHeader.Unmarshal(resp); err != nil {
		return 0, fmt.Errorf("failed to parse response header: %w", err)
	}

	if !respHeader.IsSuccess() {
		return 0, fmt.Errorf("tree connect error: 0x%08X", respHeader.Status)
	}

	// Save TID
	c.tid = respHeader.TID

	return respHeader.TID, nil
}

// UID returns the session UID
func (c *Client) UID() uint16 {
	return c.uid
}

// TID returns the current tree ID
func (c *Client) TID() uint16 {
	return c.tid
}

func (c *Client) nextMID() uint16 {
	c.mid++
	return c.mid
}
