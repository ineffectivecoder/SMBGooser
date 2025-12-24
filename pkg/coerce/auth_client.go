package coerce

import (
	"encoding/binary"
	"fmt"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
)

// AuthenticatedClient is an RPC client with PKT_PRIVACY (encrypted/signed RPC)
type AuthenticatedClient struct {
	pipe   *pipe.Pipe
	auth   *dcerpc.NTLMAuth
	callID uint32
}

// NewAuthenticatedClient creates an authenticated RPC client
func NewAuthenticatedClient(p *pipe.Pipe, opts CoerceOptions, interfaceUUID dcerpc.UUID, interfaceVersion uint32) (*AuthenticatedClient, error) {
	// Create NTLM auth context
	auth := &dcerpc.NTLMAuth{
		User:     opts.Username,
		Password: opts.Password,
		Hash:     opts.Hash,
		Domain:   opts.Domain,
	}

	// Perform authenticated bind (3-way handshake)
	if err := performAuthenticatedBind(p, auth, interfaceUUID, interfaceVersion); err != nil {
		return nil, fmt.Errorf("authenticated bind failed: %w", err)
	}

	return &AuthenticatedClient{
		pipe:   p,
		auth:   auth,
		callID: 2, // Start at 2 after auth binding
	}, nil
}

// performAuthenticatedBind performs a 3-way DCERPC auth handshake
func performAuthenticatedBind(p *pipe.Pipe, auth *dcerpc.NTLMAuth, interfaceUUID dcerpc.UUID, version uint32) error {
	// Step 1: Send Bind with NTLM Negotiate
	bindReq := auth.CreateBindWithAuth(interfaceUUID, version)

	if _, err := p.Write(bindReq); err != nil {
		return fmt.Errorf("bind write failed: %w", err)
	}

	// Read BindAck
	bindAck := make([]byte, 4096)
	n, err := p.Read(bindAck)
	if err != nil {
		return fmt.Errorf("bind read failed: %w", err)
	}
	bindAck = bindAck[:n]

	if len(bindAck) < 24 {
		return fmt.Errorf("BindAck too short: %d bytes", len(bindAck))
	}

	// Check packet type (offset 2)
	if bindAck[2] == 13 { // BindNak
		return fmt.Errorf("bind rejected (BindNak)")
	}
	if bindAck[2] != 12 { // BindAck
		return fmt.Errorf("unexpected bind response: type=%d", bindAck[2])
	}

	// Extract auth data from BindAck
	authLen := binary.LittleEndian.Uint16(bindAck[10:12])
	if authLen == 0 {
		return fmt.Errorf("no auth data in BindAck")
	}

	fragLen := binary.LittleEndian.Uint16(bindAck[8:10])
	authTrailerStart := int(fragLen) - int(authLen) - 8

	if authTrailerStart < 24 || authTrailerStart+int(authLen)+8 > int(fragLen) {
		return fmt.Errorf("invalid auth trailer position")
	}

	// Extract auth_context_id from auth trailer
	serverAuthContextID := binary.LittleEndian.Uint32(bindAck[authTrailerStart+4 : authTrailerStart+8])
	auth.SetAuthContextID(serverAuthContextID)

	// Extract NTLM Challenge
	challengeMsg := bindAck[authTrailerStart+8 : authTrailerStart+8+int(authLen)]

	// Step 2: Process challenge and create Authenticate message
	authenticateMsg, err := auth.ProcessChallenge(challengeMsg)
	if err != nil {
		return fmt.Errorf("failed to process challenge: %w", err)
	}

	// Step 3: Send Auth3
	auth3Req := auth.CreateAuth3(authenticateMsg)
	if _, err := p.Write(auth3Req); err != nil {
		return fmt.Errorf("Auth3 write failed: %w", err)
	}

	// Auth3 has no response - success!
	return nil
}

// Call makes an authenticated RPC call
func (c *AuthenticatedClient) Call(opnum uint16, stubData []byte) ([]byte, error) {
	// Create authenticated request
	req := c.auth.CreateAuthenticatedRequest(opnum, stubData, c.callID)
	c.callID++

	// Send request
	if _, err := c.pipe.Write(req); err != nil {
		return nil, fmt.Errorf("request write failed: %w", err)
	}

	// Read response
	resp := make([]byte, 65536)
	n, err := c.pipe.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("request read failed: %w", err)
	}
	resp = resp[:n]

	// Check for DCERPC fault (type 3)
	if len(resp) >= 24 && resp[2] == 3 {
		status := binary.LittleEndian.Uint32(resp[24:28])
		return nil, fmt.Errorf("DCERPC fault: 0x%08X", status)
	}

	// Decrypt the authenticated response
	decryptedStub, err := c.auth.ProcessAuthenticatedResponse(resp)
	if err != nil {
		// Fall back to skipping header (for responses without encrypted data)
		if len(resp) > 24 {
			return resp[24:], nil
		}
		return resp, nil
	}

	return decryptedStub, nil
}
