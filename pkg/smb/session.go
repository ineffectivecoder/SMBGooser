package smb

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/ineffectivecoder/SMBGooser/pkg/auth"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

// Session represents an authenticated SMB session
type Session struct {
	transport       *Transport
	sessionID       uint64
	messageID       uint64
	signingRequired bool
	signingKey      []byte
	dialect         types.Dialect
	maxTransactSize uint32
	maxReadSize     uint32
	maxWriteSize    uint32

	// Encryption state (SMB 3.x)
	encryptMessages bool   // Whether to encrypt messages
	encryptionKey   []byte // Client->Server encryption key
	decryptionKey   []byte // Server->Client decryption key
	cipherID        uint16 // Negotiated cipher (CCM or GCM)

	// State
	isAuthenticated bool
	isGuest         bool
}

// SessionConfig configures session behavior
type SessionConfig struct {
	RequireSigning    bool
	RequireEncryption bool // Force encryption for SMB 3.x
}

// NewSession creates a new session from a negotiation result
func NewSession(transport *Transport, negResult *NegotiateResult) *Session {
	s := &Session{
		transport:       transport,
		signingRequired: negResult.RequiresSigning,
		dialect:         negResult.Dialect,
		maxTransactSize: negResult.MaxTransactSize,
		maxReadSize:     negResult.MaxReadSize,
		maxWriteSize:    negResult.MaxWriteSize,
		messageID:       1, // Start at 1 since Negotiate used MessageID 0
	}

	// Set encryption cipher if available
	if negResult.SupportsEncryption && negResult.Dialect >= types.DialectSMB3_0 {
		s.cipherID = negResult.EncryptionCipher
		if s.cipherID == 0 {
			// Default to CCM for SMB 3.0/3.0.2, GCM for 3.1.1
			if negResult.Dialect >= types.DialectSMB3_1_1 {
				s.cipherID = EncryptionAES128GCM
			} else {
				s.cipherID = EncryptionAES128CCM
			}
		}
		// Encryption will be enabled after authentication if server requires it
		s.encryptMessages = negResult.RequiresEncryption
	}

	return s
}

// Authenticate performs authentication (NTLM or Kerberos)
func (s *Session) Authenticate(ctx context.Context, creds auth.Credentials, negResult *NegotiateResult) error {
	// Check if this is Kerberos auth
	if krbCreds, ok := creds.(auth.KerberosProvider); ok && krbCreds.IsKerberos() {
		return s.authenticateKerberos(ctx, krbCreds, negResult)
	}

	// Otherwise use NTLM
	return s.authenticateNTLM(ctx, creds, negResult)
}

// authenticateKerberos performs Kerberos/SPNEGO authentication
func (s *Session) authenticateKerberos(ctx context.Context, krbCreds auth.KerberosProvider, negResult *NegotiateResult) error {
	// Build SPN for the target
	// SMB uses "cifs/hostname" SPN
	spn := "cifs/" + s.transport.RemoteHost()

	// Get SPNEGO token from Kerberos credentials
	spnegoToken, err := krbCreds.GetSPNEGOToken(spn)
	if err != nil {
		return fmt.Errorf("failed to get SPNEGO token: %w", err)
	}

	// Build SESSION_SETUP request with SPNEGO token
	req := types.NewSessionSetupRequest(spnegoToken)

	// Build header
	header := types.NewHeader(types.CommandSessionSetup, s.nextMessageID())

	// Send request
	resp, err := s.sendRecv(header, req.Marshal())
	if err != nil {
		return fmt.Errorf("kerberos session setup failed: %w", err)
	}

	// Parse response header
	var respHeader types.Header
	if err := respHeader.Unmarshal(resp[:types.SMB2HeaderSize]); err != nil {
		return fmt.Errorf("failed to parse response header: %w", err)
	}

	// Check status - could be success or MORE_PROCESSING_REQUIRED for mutual auth
	if respHeader.Status != types.StatusSuccess && respHeader.Status != types.StatusMoreProcessingReq {
		return StatusToError(respHeader.Status)
	}

	// Get session ID from response
	s.sessionID = respHeader.SessionID

	// Parse SESSION_SETUP response
	var setupResp types.SessionSetupResponse
	if err := setupResp.Unmarshal(resp[types.SMB2HeaderSize:]); err != nil {
		return fmt.Errorf("failed to parse session setup response: %w", err)
	}

	// If we got MORE_PROCESSING_REQUIRED, handle mutual authentication
	if respHeader.Status == types.StatusMoreProcessingReq {
		// For mutual auth, we'd process the response token
		// For simplicity, we'll try another round with the same token
		// In a full implementation, we'd verify the server's AP-REP

		req2 := types.NewSessionSetupRequest(nil) // Empty security buffer for continuation
		header2 := types.NewHeader(types.CommandSessionSetup, s.nextMessageID())
		header2.SessionID = s.sessionID

		resp2, err := s.sendRecv(header2, req2.Marshal())
		if err != nil {
			return fmt.Errorf("kerberos session setup continuation failed: %w", err)
		}

		var respHeader2 types.Header
		if err := respHeader2.Unmarshal(resp2[:types.SMB2HeaderSize]); err != nil {
			return fmt.Errorf("failed to parse response header: %w", err)
		}

		if !respHeader2.Status.IsSuccess() {
			return StatusToError(respHeader2.Status)
		}

		if err := setupResp.Unmarshal(resp2[types.SMB2HeaderSize:]); err != nil {
			return fmt.Errorf("failed to parse session setup response: %w", err)
		}
	}

	s.isAuthenticated = true
	s.isGuest = setupResp.IsGuest()

	return nil
}

// authenticateNTLM performs NTLM authentication
func (s *Session) authenticateNTLM(ctx context.Context, creds auth.Credentials, negResult *NegotiateResult) error {
	// Step 1: Send Type 1 (NEGOTIATE) message
	type1 := auth.NewNegotiateMessage()
	type1Bytes := type1.Marshal()

	// Wrap in SPNEGO if server sent SPNEGO token
	securityBuffer := wrapNTLMSSP(type1Bytes, true)

	// Build SESSION_SETUP request
	req := types.NewSessionSetupRequest(securityBuffer)

	// Build header
	header := types.NewHeader(types.CommandSessionSetup, s.nextMessageID())

	// Send request
	resp, err := s.sendRecv(header, req.Marshal())
	if err != nil {
		return fmt.Errorf("session setup (type1) failed: %w", err)
	}

	// Parse response header
	var respHeader types.Header
	if err := respHeader.Unmarshal(resp[:types.SMB2HeaderSize]); err != nil {
		return fmt.Errorf("failed to parse response header: %w", err)
	}

	// Check for MORE_PROCESSING_REQUIRED (expected for NTLM)
	if respHeader.Status != types.StatusMoreProcessingReq {
		return StatusToError(respHeader.Status)
	}

	// Get session ID from response
	s.sessionID = respHeader.SessionID

	// Parse SESSION_SETUP response
	var setupResp types.SessionSetupResponse
	if err := setupResp.Unmarshal(resp[types.SMB2HeaderSize:]); err != nil {
		return fmt.Errorf("failed to parse session setup response: %w", err)
	}

	// Extract NTLMSSP CHALLENGE (Type 2) from response
	type2Bytes := unwrapNTLMSSP(setupResp.SecurityBuffer)
	if type2Bytes == nil {
		return errors.New("failed to extract NTLMSSP challenge")
	}

	challenge, err := auth.ParseChallengeMessage(type2Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse challenge: %w", err)
	}

	// Step 2: Build and send Type 3 (AUTHENTICATE) message
	var authOpts auth.AuthenticateOptions
	authOpts.Domain = creds.Domain()
	authOpts.Username = creds.Username()
	authOpts.Workstation = "WORKSTATION"

	switch c := creds.(type) {
	case *auth.PasswordCredentials:
		authOpts.Password = c.Password()
	case *auth.HashCredentials:
		// For pass-the-hash, compute NTLMv2 hash from NT hash
		authOpts.NTLMv2Hash = auth.NTLMv2Hash(c.NTHash(), c.Username(), c.Domain())
	case *auth.AnonymousCredentials:
		// Anonymous auth - send empty credentials
		authOpts.Username = ""
		authOpts.Domain = ""
	}

	type3 := auth.NewAuthenticateMessage(challenge, authOpts)
	type3Bytes := type3.Marshal()

	// Wrap in SPNEGO NegTokenResp
	securityBuffer = wrapNTLMSSP(type3Bytes, false)

	// Build second SESSION_SETUP request
	req2 := types.NewSessionSetupRequest(securityBuffer)

	// Build header with session ID
	header2 := types.NewHeader(types.CommandSessionSetup, s.nextMessageID())
	header2.SessionID = s.sessionID

	// Send request
	resp2, err := s.sendRecv(header2, req2.Marshal())
	if err != nil {
		return fmt.Errorf("session setup (type3) failed: %w", err)
	}

	// Parse response header
	var respHeader2 types.Header
	if err := respHeader2.Unmarshal(resp2[:types.SMB2HeaderSize]); err != nil {
		return fmt.Errorf("failed to parse response header: %w", err)
	}

	// Check for success
	if !respHeader2.Status.IsSuccess() {
		return StatusToError(respHeader2.Status)
	}

	// Parse final SESSION_SETUP response
	var setupResp2 types.SessionSetupResponse
	if err := setupResp2.Unmarshal(resp2[types.SMB2HeaderSize:]); err != nil {
		return fmt.Errorf("failed to parse session setup response: %w", err)
	}

	s.isAuthenticated = true
	s.isGuest = setupResp2.IsGuest()

	// Derive session keys
	sessionBaseKey := type3.GetSessionBaseKey()

	// Derive signing key if signing is required
	if s.signingRequired {
		// For SMB3, derive signing key using KDF
		// For SMB2, use session key directly
		s.signingKey = deriveSigningKey(sessionBaseKey, s.dialect, nil)
	}

	// Derive encryption keys for SMB 3.x if encryption is enabled
	if s.encryptMessages && s.dialect >= types.DialectSMB3_0 {
		s.encryptionKey = deriveEncryptionKey(sessionBaseKey, s.dialect, nil)
		s.decryptionKey = deriveDecryptionKey(sessionBaseKey, s.dialect, nil)
	}

	return nil
}

// sendRecv sends a request and receives the response
func (s *Session) sendRecv(header *types.Header, payload []byte) ([]byte, error) {
	// Set signing flag if required (and not encrypting - encryption provides integrity)
	if s.signingRequired && len(s.signingKey) > 0 && s.isAuthenticated && !s.encryptMessages {
		header.Flags |= types.FlagsSigned
	}

	// Combine header + payload
	msg := append(header.Marshal(), payload...)

	// Sign message if required (and not encrypting)
	if s.signingRequired && len(s.signingKey) > 0 && s.isAuthenticated && !s.encryptMessages {
		msg = signMessage(s.dialect, s.signingKey, msg)
	}

	// Encrypt message if required (SMB 3.x)
	if s.encryptMessages && len(s.encryptionKey) > 0 && s.isAuthenticated {
		encrypted, err := encryptMessage(s.cipherID, s.encryptionKey, s.sessionID, msg)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt message: %w", err)
		}
		msg = encrypted
	}

	// Send request
	if err := s.transport.Send(msg); err != nil {
		return nil, err
	}

	// Receive response, handling STATUS_PENDING
	resp, err := s.recvResponse()
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// recvResponse receives a response, handling STATUS_PENDING for async operations
func (s *Session) recvResponse() ([]byte, error) {
	for {
		resp, err := s.transport.Recv()
		if err != nil {
			return nil, err
		}

		// Decrypt response if encrypted
		if isEncryptedMessage(resp) && len(s.decryptionKey) > 0 {
			decrypted, err := decryptMessage(s.cipherID, s.decryptionKey, resp)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt response: %w", err)
			}
			resp = decrypted
		}

		// Check for STATUS_PENDING - if so, keep reading
		if len(resp) >= types.SMB2HeaderSize {
			var respHeader types.Header
			if err := respHeader.Unmarshal(resp[:types.SMB2HeaderSize]); err == nil {
				if respHeader.Status == types.StatusPending {
					// Async operation pending, wait for final response
					continue
				}
			}
		}

		// Verify response signature if signing is required (and response was not encrypted)
		if s.signingRequired && len(s.signingKey) > 0 && s.isAuthenticated && len(resp) >= types.SMB2HeaderSize {
			// Check if response is signed (skip if it was encrypted - encryption provides integrity)
			if !isEncryptedMessage(resp) {
				var respHeader types.Header
				if err := respHeader.Unmarshal(resp[:types.SMB2HeaderSize]); err == nil {
					if respHeader.Flags&types.FlagsSigned != 0 {
						if !verifySignature(s.dialect, s.signingKey, resp) {
							return nil, errors.New("invalid message signature")
						}
					}
				}
			}
		}

		return resp, nil
	}
}

// nextMessageID returns the next message ID
func (s *Session) nextMessageID() uint64 {
	id := s.messageID
	s.messageID++
	return id
}

// SessionID returns the session ID
func (s *Session) SessionID() uint64 {
	return s.sessionID
}

// IsAuthenticated returns true if authenticated
func (s *Session) IsAuthenticated() bool {
	return s.isAuthenticated
}

// IsGuest returns true if this is a guest session
func (s *Session) IsGuest() bool {
	return s.isGuest
}

// Dialect returns the negotiated dialect
func (s *Session) Dialect() types.Dialect {
	return s.dialect
}

// MaxTransactSize returns the max transaction size
func (s *Session) MaxTransactSize() uint32 {
	return s.maxTransactSize
}

// MaxReadSize returns the max read size
func (s *Session) MaxReadSize() uint32 {
	return s.maxReadSize
}

// MaxWriteSize returns the max write size
func (s *Session) MaxWriteSize() uint32 {
	return s.maxWriteSize
}

// IsEncrypted returns true if message encryption is enabled
func (s *Session) IsEncrypted() bool {
	return s.encryptMessages && len(s.encryptionKey) > 0
}

// EnableEncryption enables message encryption for SMB 3.x sessions
// This should be called after authentication if not automatically enabled
func (s *Session) EnableEncryption() error {
	if s.dialect < types.DialectSMB3_0 {
		return errors.New("encryption requires SMB 3.0 or later")
	}
	if s.cipherID == 0 {
		return errors.New("no encryption cipher negotiated")
	}
	if len(s.encryptionKey) == 0 {
		return errors.New("encryption keys not derived - authentication required")
	}
	s.encryptMessages = true
	return nil
}

// SetEncryptionKeys manually sets encryption keys (for testing or custom key management)
func (s *Session) SetEncryptionKeys(encKey, decKey []byte, cipherID uint16) {
	s.encryptionKey = encKey
	s.decryptionKey = decKey
	s.cipherID = cipherID
}

// Close closes the session (sends LOGOFF)
func (s *Session) Close() error {
	if !s.isAuthenticated {
		return nil
	}

	// TODO: Send LOGOFF request
	s.isAuthenticated = false
	return nil
}

// SPNEGO OIDs
var (
	oidSPNEGO  = []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}                         // 1.3.6.1.5.5.2
	oidNTLMSSP = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a} // 1.3.6.1.4.1.311.2.2.10
)

// wrapNTLMSSP wraps NTLMSSP message in SPNEGO
func wrapNTLMSSP(ntlmssp []byte, isNegotiate bool) []byte {
	if isNegotiate {
		return wrapSPNEGOInit(ntlmssp)
	}
	return wrapSPNEGOResponse(ntlmssp)
}

// wrapSPNEGOInit creates a NegTokenInit for the first NTLMSSP message
// Using proper ASN.1 DER encoding per RFC 4178
func wrapSPNEGOInit(ntlmssp []byte) []byte {
	// SPNEGO OID: 1.3.6.1.5.5.2
	spnegoOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
	// NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
	ntlmsspOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}

	// NegTokenInit structure
	type negTokenInit struct {
		MechTypes []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
		MechToken []byte                  `asn1:"explicit,tag:2"`
	}

	// Encode NegTokenInit
	negInit := negTokenInit{
		MechTypes: []asn1.ObjectIdentifier{ntlmsspOID},
		MechToken: ntlmssp,
	}
	negInitBytes, err := asn1.Marshal(negInit)
	if err != nil {
		return ntlmssp // Fall back to raw
	}

	// Wrap in context [0] for CHOICE NegTokenInit
	negToken := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      negInitBytes,
	}
	negTokenBytes, err := asn1.Marshal(negToken)
	if err != nil {
		return ntlmssp
	}

	// Encode SPNEGO OID
	oidBytes, err := asn1.Marshal(spnegoOID)
	if err != nil {
		return ntlmssp
	}

	// Combine: APPLICATION 0 { OID, NegTokenInit }
	content := append(oidBytes, negTokenBytes...)
	gssToken := asn1.RawValue{
		Class:      asn1.ClassApplication,
		Tag:        0,
		IsCompound: true,
		Bytes:      content,
	}
	result, err := asn1.Marshal(gssToken)
	if err != nil {
		return ntlmssp
	}

	return result
}

// wrapSPNEGOResponse creates a NegTokenResp for subsequent NTLMSSP messages
func wrapSPNEGOResponse(ntlmssp []byte) []byte {
	// NegTokenResp structure:
	// [1] SEQUENCE {
	//     [0] negState OPTIONAL
	//     [2] responseToken OPTIONAL
	// }

	// Build responseToken [2] OCTET STRING
	type negTokenResp struct {
		NegState      asn1.Enumerated `asn1:"optional,explicit,tag:0"`
		ResponseToken []byte          `asn1:"optional,explicit,tag:2"`
	}

	resp := negTokenResp{
		NegState:      1, // accept-incomplete
		ResponseToken: ntlmssp,
	}

	respBytes, err := asn1.Marshal(resp)
	if err != nil {
		return ntlmssp // Fall back to raw
	}

	// Wrap in context [1] for NegTokenResp
	wrapped := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      respBytes,
	}

	result, err := asn1.Marshal(wrapped)
	if err != nil {
		return ntlmssp
	}

	return result
}

// asn1Length encodes length in ASN.1 DER format
func asn1Length(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	if n < 256 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

// unwrapNTLMSSP extracts NTLMSSP from SPNEGO or raw format
func unwrapNTLMSSP(data []byte) []byte {
	// Look for NTLMSSP signature
	sig := []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}
	for i := 0; i <= len(data)-8; i++ {
		match := true
		for j := 0; j < 8; j++ {
			if data[i+j] != sig[j] {
				match = false
				break
			}
		}
		if match {
			return data[i:]
		}
	}
	return nil
}
