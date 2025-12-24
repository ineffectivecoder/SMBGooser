// Package dcerpc implements DCE/RPC protocol with PKT_PRIVACY authentication support.
// This enables authenticated RPC calls required by some Windows services like Task Scheduler.
package dcerpc

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

const (
	// DCERPC packet types (MS-RPCE section 2.2.1.1)
	dcerpcAuth3 = 16 // Client → Server: Complete 3-way auth (no response expected)

	// DCERPC authentication
	dcerpcAuthTypeNTLMSSP  = 10 // NTLMSSP authentication
	dcerpcAuthLevelPrivacy = 6  // PKT_PRIVACY: sign + seal (encrypt)
)

// NTLMAuth holds NTLM authentication state for DCERPC PKT_PRIVACY
// This struct maintains the cryptographic state across multiple DCERPC requests.
//
// CRITICAL: The clientSealHandle RC4 cipher is a CONTINUOUS STREAM and must NEVER be reset.
// Each encryption operation uses the continued RC4 stream.
type NTLMAuth struct {
	User             string      // Username for authentication
	Password         string      // Password for NT hash calculation
	Hash             []byte      // Pre-computed NT hash (16 bytes) - if provided, password is ignored
	Domain           string      // Domain name
	challenge        []byte      // 8-byte server challenge from Type 2 (Challenge) message
	flags            uint32      // Negotiated NTLM flags from server's Challenge message
	sessionBaseKey   []byte      // 16-byte session base key derived from NTLMv2 response
	clientSignKey    []byte      // 16-byte signing key
	clientSealKey    []byte      // 16-byte sealing key
	serverSignKey    []byte      // 16-byte server signing key for verifying responses
	serverSealKey    []byte      // 16-byte server sealing key for decrypting responses
	seqNum           uint32      // Sequence number for DCERPC requests (starts at 0)
	authContextID    uint32      // Auth context ID assigned by server in BindAck
	negotiateMsg     []byte      // Complete Type 1 message (saved for MIC calculation)
	challengeMsg     []byte      // Complete Type 2 message (saved for MIC calculation)
	clientSealHandle *rc4.Cipher // RC4 cipher handle for encryption - MUST be continuous stream
	serverSealHandle *rc4.Cipher // RC4 cipher for decrypting server responses
}

// CreateNTLMNegotiate creates an NTLM Negotiate message (Type 1)
//
// CRITICAL SUCCESS FACTORS:
// 1. MUST include NTLMSSP_NEGOTIATE_TARGET_INFO (0x00800000) - Without this, Windows rejects authentication
// 2. MUST include NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (0x00080000) - Required for NTLMv2
// 3. Using Impacket's exact flags for signingRequired=True,use_ntlmv2=True: 0xe0888235
// Note: Timeout is better than PIPE_DISCONNECTED - server at least processes the request
func (auth *NTLMAuth) CreateNTLMNegotiate() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("NTLMSSP\x00")                    // Signature
	binary.Write(buf, binary.LittleEndian, uint32(1)) // Message Type: 1 (Negotiate)

	// Impacket getNTLMSSPType1 with signingRequired=True, use_ntlmv2=True: 0xe0888235
	// From Impacket ntlm.py lines 608-614
	flags := uint32(0x80000000 | // NTLMSSP_NEGOTIATE_56
		0x40000000 | // NTLMSSP_NEGOTIATE_KEY_EXCH
		0x20000000 | // NTLMSSP_NEGOTIATE_128
		0x00800000 | // NTLMSSP_NEGOTIATE_TARGET_INFO
		0x00080000 | // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
		0x00008000 | // NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		0x00000200 | // NTLMSSP_NEGOTIATE_NTLM
		0x00000020 | // NTLMSSP_NEGOTIATE_SEAL
		0x00000010 | // NTLMSSP_NEGOTIATE_SIGN
		0x00000004 | // NTLMSSP_REQUEST_TARGET
		0x00000001) // NTLMSSP_NEGOTIATE_UNICODE
	// Total: 0xe0888235 - Impacket's PKT_PRIVACY flags (NO VERSION flag!)

	binary.Write(buf, binary.LittleEndian, flags)

	// Domain fields (empty)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Len
	binary.Write(buf, binary.LittleEndian, uint16(0)) // MaxLen
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset

	// Workstation fields (empty)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Len
	binary.Write(buf, binary.LittleEndian, uint16(0)) // MaxLen
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset

	// NO VERSION structure - Impacket doesn't include it when VERSION flag is not set

	auth.negotiateMsg = buf.Bytes()
	return auth.negotiateMsg
}

// ProcessChallenge processes the NTLM Challenge (Type 2) from BindAck and creates Authenticate (Type 3)
func (auth *NTLMAuth) ProcessChallenge(challengeMsg []byte) ([]byte, error) {
	auth.challengeMsg = challengeMsg

	if len(challengeMsg) < 32 {
		return nil, fmt.Errorf("challenge message too short: %d bytes", len(challengeMsg))
	}

	// Extract server challenge (8 bytes at offset 24)
	auth.challenge = challengeMsg[24:32]

	// Extract challenge flags (4 bytes at offset 20)
	auth.flags = binary.LittleEndian.Uint32(challengeMsg[20:24])

	// Extract target info from challenge message
	targetInfo := createMinimalTargetInfo()
	var hostname []byte
	if len(challengeMsg) > 48 {
		targetInfoLen := binary.LittleEndian.Uint16(challengeMsg[40:42])
		targetInfoOffset := binary.LittleEndian.Uint32(challengeMsg[44:48])
		if int(targetInfoOffset)+int(targetInfoLen) <= len(challengeMsg) {
			targetInfo = challengeMsg[targetInfoOffset : targetInfoOffset+uint32(targetInfoLen)]
			hostname = extractHostnameFromTargetInfo(targetInfo)
		}
	}

	// Add TARGET_NAME AV_PAIR for SPN target name validation
	if len(hostname) > 0 {
		targetInfo = addTargetNameToAVPairs(targetInfo, hostname)
	}

	// Calculate NTLMv2 response
	timestamp := time.Now().UnixNano() / 100
	timestamp += 116444736000000000

	clientChallenge := make([]byte, 8)
	rand.Read(clientChallenge)

	temp := buildTempBlob(timestamp, clientChallenge, targetInfo)

	// Use pre-computed hash if available, otherwise compute from password
	var ntHashBytes []byte
	if len(auth.Hash) == 16 {
		ntHashBytes = auth.Hash
	} else {
		ntHashBytes = ntHash(auth.Password)
	}

	ntlmv2Hash := ntlmv2HashFunc(ntHashBytes, auth.User, auth.Domain)
	ntlmv2Resp := calculateNTLMv2Response(ntlmv2Hash, auth.challenge, temp)

	// Calculate session keys from this NTLMv2 response
	auth.sessionBaseKey = calculateSessionBaseKey(ntlmv2Hash, ntlmv2Resp[:16])
	auth.clientSignKey = calculateSignKey(auth.sessionBaseKey, true)
	auth.clientSealKey = calculateSealKey(auth.sessionBaseKey, true)

	return auth.buildAuthenticateMessage(ntlmv2Resp, clientChallenge, targetInfo)
}

// SetAuthContextID sets the auth context ID from the server's BindAck response
func (auth *NTLMAuth) SetAuthContextID(id uint32) {
	auth.authContextID = id
}

// buildAuthenticateMessage builds the NTLM Authenticate (Type 3) message
func (auth *NTLMAuth) buildAuthenticateMessage(ntlmv2Resp, clientChallenge, targetInfo []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.WriteString("NTLMSSP\x00")
	binary.Write(buf, binary.LittleEndian, uint32(3)) // Type 3

	domainUTF16 := stringToUTF16LE(auth.Domain)
	userUTF16 := stringToUTF16LE(auth.User)
	workstationUTF16 := stringToUTF16LE("")

	// Create NTLMv2 LM response
	ntlmv2Hash := ntlmv2HashFunc(ntHash(auth.Password), auth.User, auth.Domain)
	if len(auth.Hash) == 16 {
		ntlmv2Hash = ntlmv2HashFunc(auth.Hash, auth.User, auth.Domain)
	}

	h := hmac.New(md5.New, ntlmv2Hash)
	h.Write(auth.challenge)
	h.Write(clientChallenge)
	lmResp := append(h.Sum(nil), clientChallenge...)

	// Calculate base offset: 64-byte standard header + VERSION (8) + MIC (16)
	baseOffset := 64
	if auth.flags&0x02000000 != 0 { // VERSION flag set
		baseOffset += 8  // VERSION field
		baseOffset += 16 // MIC field
	}
	offset := baseOffset

	// LM response
	binary.Write(buf, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(buf, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(lmResp)

	// NTLM response
	binary.Write(buf, binary.LittleEndian, uint16(len(ntlmv2Resp)))
	binary.Write(buf, binary.LittleEndian, uint16(len(ntlmv2Resp)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(ntlmv2Resp)

	// Domain
	binary.Write(buf, binary.LittleEndian, uint16(len(domainUTF16)))
	binary.Write(buf, binary.LittleEndian, uint16(len(domainUTF16)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(domainUTF16)

	// User
	binary.Write(buf, binary.LittleEndian, uint16(len(userUTF16)))
	binary.Write(buf, binary.LittleEndian, uint16(len(userUTF16)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(userUTF16)

	// Workstation
	binary.Write(buf, binary.LittleEndian, uint16(len(workstationUTF16)))
	binary.Write(buf, binary.LittleEndian, uint16(len(workstationUTF16)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))
	offset += len(workstationUTF16)

	// Handle session key export (for MIC and subsequent signing/sealing)
	var encryptedRandomSessionKey []byte
	var exportedSessionKey []byte

	keyExchangeKey := auth.sessionBaseKey

	if auth.flags&0x40000000 != 0 {
		// KEY_EXCH negotiated: generate random session key and encrypt it
		exportedSessionKey = make([]byte, 16)
		rand.Read(exportedSessionKey)

		// Encrypt it with keyExchangeKey
		cipher, _ := rc4.NewCipher(keyExchangeKey)
		encryptedRandomSessionKey = make([]byte, 16)
		cipher.XORKeyStream(encryptedRandomSessionKey, exportedSessionKey)
	} else {
		// KEY_EXCH not negotiated: exportedSessionKey = keyExchangeKey
		exportedSessionKey = keyExchangeKey
		encryptedRandomSessionKey = []byte{}
	}

	// Update our signing/sealing keys to use exportedSessionKey
	auth.sessionBaseKey = exportedSessionKey
	auth.clientSignKey = calculateSignKey(exportedSessionKey, true)
	auth.clientSealKey = calculateSealKey(exportedSessionKey, true)
	auth.serverSignKey = calculateSignKey(exportedSessionKey, false)
	auth.serverSealKey = calculateSealKey(exportedSessionKey, false)

	// Initialize RC4 cipher handles - these MUST be continuous streams (never reset!)
	auth.clientSealHandle, _ = rc4.NewCipher(auth.clientSealKey)
	auth.serverSealHandle, _ = rc4.NewCipher(auth.serverSealKey)

	// Session key
	binary.Write(buf, binary.LittleEndian, uint16(len(encryptedRandomSessionKey)))
	binary.Write(buf, binary.LittleEndian, uint16(len(encryptedRandomSessionKey)))
	binary.Write(buf, binary.LittleEndian, uint32(offset))

	// Flags
	type1Flags := uint32(0x62000231)
	responseFlags := type1Flags
	responseFlags |= 0x00080000 // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
	responseFlags |= 0x00800000 // NTLMSSP_NEGOTIATE_TARGET_INFO

	// Mask out flags that Challenge doesn't support
	if auth.flags&0x20000000 == 0 {
		responseFlags &= ^uint32(0x20000000)
	}
	if auth.flags&0x40000000 == 0 {
		responseFlags &= ^uint32(0x40000000)
	}
	if auth.flags&0x00000020 == 0 {
		responseFlags &= ^uint32(0x00000020)
	}
	if auth.flags&0x00000010 == 0 {
		responseFlags &= ^uint32(0x00000010)
	}

	binary.Write(buf, binary.LittleEndian, responseFlags)

	// Include VERSION field if NEGOTIATE_VERSION was set (8 bytes)
	if auth.flags&0x02000000 != 0 {
		buf.WriteByte(6)                                     // Major version
		buf.WriteByte(1)                                     // Minor version
		binary.Write(buf, binary.LittleEndian, uint16(7601)) // Build number
		buf.Write([]byte{0, 0, 0})                           // Reserved
		buf.WriteByte(15)                                    // NTLM revision
	}

	// MIC field (16 bytes) - will be computed later
	if auth.flags&0x02000000 != 0 {
		buf.Write(make([]byte, 16)) // Placeholder for MIC
	}

	buf.Write(lmResp)
	buf.Write(ntlmv2Resp)
	buf.Write(domainUTF16)
	buf.Write(userUTF16)
	buf.Write(workstationUTF16)
	buf.Write(encryptedRandomSessionKey)

	authenticateMsg := buf.Bytes()

	// Compute MIC if VERSION flag is set
	if auth.flags&0x02000000 != 0 && len(exportedSessionKey) > 0 {
		micFieldOffset := 64 + 8 // 64-byte header + 8-byte VERSION

		// Calculate MIC
		h := hmac.New(md5.New, exportedSessionKey)
		h.Write(auth.negotiateMsg)
		h.Write(auth.challengeMsg)
		h.Write(authenticateMsg)
		mic := h.Sum(nil)

		// Place MIC in the message
		copy(authenticateMsg[micFieldOffset:micFieldOffset+16], mic)
	}

	return authenticateMsg, nil
}

// CreateBindWithAuth creates a DCERPC Bind request with NTLM authentication
func (auth *NTLMAuth) CreateBindWithAuth(uuid UUID, version uint32) []byte {
	negotiateMsg := auth.CreateNTLMNegotiate()

	buf := new(bytes.Buffer)

	// DCERPC Header
	buf.WriteByte(RPCVersionMajor)
	buf.WriteByte(RPCVersionMinor)
	buf.WriteByte(byte(PacketTypeBind))
	buf.WriteByte(PacketFlagFirstFrag | PacketFlagLastFrag)
	binary.Write(buf, binary.LittleEndian, uint32(NDRDataRepresentation)) // MUST cast to uint32!

	fragLenPos := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint16(0))                 // Frag length (update later)
	binary.Write(buf, binary.LittleEndian, uint16(len(negotiateMsg))) // Auth length
	binary.Write(buf, binary.LittleEndian, uint32(1))                 // Call ID

	// Bind body
	binary.Write(buf, binary.LittleEndian, uint16(4280)) // Max xmit frag
	binary.Write(buf, binary.LittleEndian, uint16(4280)) // Max recv frag
	binary.Write(buf, binary.LittleEndian, uint32(0))    // Assoc group

	// Context list
	buf.WriteByte(1) // Num contexts
	buf.WriteByte(0) // Reserved
	buf.WriteByte(0) // Reserved2
	buf.WriteByte(0) // Reserved3

	// Context item 0
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Context ID
	buf.WriteByte(1)                                  // Num transfer syntaxes
	buf.WriteByte(0)                                  // Reserved

	// Abstract syntax (interface UUID)
	syntaxID := SyntaxID{UUID: uuid, Version: version}
	buf.Write(syntaxID.Marshal())

	// Transfer syntax (NDR)
	buf.Write(NDRSyntax.Marshal())

	// Pad to 4-byte boundary
	currentLen := buf.Len()
	padLen := (4 - (currentLen % 4)) % 4
	for i := 0; i < padLen; i++ {
		buf.WriteByte(0xFF)
	}

	// Auth verifier header
	buf.WriteByte(dcerpcAuthTypeNTLMSSP)
	buf.WriteByte(dcerpcAuthLevelPrivacy)
	buf.WriteByte(byte(padLen))
	buf.WriteByte(0)
	binary.Write(buf, binary.LittleEndian, uint32(0+79231)) // Auth context ID

	// Auth value (NTLM Negotiate)
	buf.Write(negotiateMsg)

	// Update frag length
	packet := buf.Bytes()
	binary.LittleEndian.PutUint16(packet[fragLenPos:], uint16(len(packet)))

	return packet
}

// CreateAuth3 creates a DCERPC Auth3 message to complete authenticated binding
func (auth *NTLMAuth) CreateAuth3(authenticateMsg []byte) []byte {
	buf := new(bytes.Buffer)

	// DCERPC Header
	buf.WriteByte(RPCVersionMajor)
	buf.WriteByte(RPCVersionMinor)
	buf.WriteByte(dcerpcAuth3)
	buf.WriteByte(PacketFlagFirstFrag | PacketFlagLastFrag)
	binary.Write(buf, binary.LittleEndian, uint32(NDRDataRepresentation)) // MUST cast to uint32!

	fragLenPos := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint16(0))                    // Frag length (update later)
	binary.Write(buf, binary.LittleEndian, uint16(len(authenticateMsg))) // Auth length
	binary.Write(buf, binary.LittleEndian, uint32(1))                    // Call ID

	// Auth3 requires 4 bytes of padding before the auth trailer
	buf.Write([]byte{0, 0, 0, 0})

	// Auth verifier header (8 bytes)
	buf.WriteByte(dcerpcAuthTypeNTLMSSP)
	buf.WriteByte(dcerpcAuthLevelPrivacy)
	buf.WriteByte(0) // Auth pad length
	buf.WriteByte(0) // Reserved
	binary.Write(buf, binary.LittleEndian, auth.authContextID)

	// Auth value (NTLM Authenticate)
	buf.Write(authenticateMsg)

	// Update frag length
	packet := buf.Bytes()
	binary.LittleEndian.PutUint16(packet[fragLenPos:], uint16(len(packet)))

	return packet
}

// CreateAuthenticatedRequest creates a DCERPC Request with PKT_PRIVACY encryption
func (auth *NTLMAuth) CreateAuthenticatedRequest(opnum uint16, stub []byte, callID uint32) []byte {
	buf := new(bytes.Buffer)

	// DCERPC Header
	buf.WriteByte(RPCVersionMajor)
	buf.WriteByte(RPCVersionMinor)
	buf.WriteByte(byte(PacketTypeRequest))
	buf.WriteByte(PacketFlagFirstFrag | PacketFlagLastFrag)
	binary.Write(buf, binary.LittleEndian, uint32(NDRDataRepresentation)) // MUST cast to uint32!

	fragLenPos := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint16(0))  // Frag length (update later)
	binary.Write(buf, binary.LittleEndian, uint16(16)) // Auth length (NTLM signature is always 16 bytes)
	binary.Write(buf, binary.LittleEndian, callID)     // Call ID

	// Calculate padding needed for 4-byte alignment
	stubPadLength := (4 - (len(stub) % 4)) % 4

	// Request body
	binary.Write(buf, binary.LittleEndian, uint32(len(stub))) // Alloc hint
	binary.Write(buf, binary.LittleEndian, uint16(0))         // Context ID
	binary.Write(buf, binary.LittleEndian, opnum)             // Opnum

	// PLAINTEXT stub with padding
	stubStartPos := buf.Len()

	// Create padded stub
	paddedStub := make([]byte, len(stub)+stubPadLength)
	copy(paddedStub, stub)
	for i := 0; i < stubPadLength; i++ {
		paddedStub[len(stub)+i] = 0xBB
	}

	buf.Write(paddedStub)

	// Auth verifier header
	buf.WriteByte(dcerpcAuthTypeNTLMSSP)
	buf.WriteByte(dcerpcAuthLevelPrivacy)
	buf.WriteByte(byte(stubPadLength))
	buf.WriteByte(0)
	binary.Write(buf, binary.LittleEndian, auth.authContextID)

	// Placeholder for signature (16 bytes)
	signaturePos := buf.Len()
	buf.Write(make([]byte, 16))

	// Update frag length
	packet := buf.Bytes()
	binary.LittleEndian.PutUint16(packet[fragLenPos:], uint16(len(packet)))

	// ========== CRITICAL ENCRYPTION/SIGNING SECTION ==========
	// Message to sign = entire packet EXCEPT the 16-byte signature placeholder
	messageToSign := packet[:len(packet)-16]

	// STEP 1: Encrypt stub+padding with RC4 cipher
	encryptedStub := make([]byte, len(paddedStub))
	auth.clientSealHandle.XORKeyStream(encryptedStub, paddedStub)

	// STEP 2: Create NTLM signature from PLAINTEXT packet
	verifier := auth.createNTLMSignature(messageToSign)

	// STEP 3: Replace plaintext stub with encrypted stub in packet
	copy(packet[stubStartPos:], encryptedStub)

	// STEP 4: Copy signature into packet
	copy(packet[signaturePos:], verifier)

	// Increment sequence number AFTER using it
	auth.seqNum++

	return packet
}

// createNTLMSignature creates the NTLM signature for a message
func (auth *NTLMAuth) createNTLMSignature(message []byte) []byte {
	// Compute HMAC-MD5 checksum over the message
	h := hmac.New(md5.New, auth.clientSignKey)
	seqNumBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqNumBytes, auth.seqNum)
	h.Write(seqNumBytes)
	h.Write(message)
	checksum := h.Sum(nil)[:8] // First 8 bytes

	// Encrypt checksum using the continuous RC4 cipher handle
	encryptedChecksum := make([]byte, 8)
	auth.clientSealHandle.XORKeyStream(encryptedChecksum, checksum)

	// Build signature: Version (4 bytes) + Encrypted Checksum (8 bytes) + SeqNum (4 bytes)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(1)) // Version
	buf.Write(encryptedChecksum)
	binary.Write(buf, binary.LittleEndian, uint32(auth.seqNum))

	return buf.Bytes()
}

// ProcessAuthenticatedResponse decrypts the response from a PKT_PRIVACY RPC call
// Returns the decrypted stub data
func (auth *NTLMAuth) ProcessAuthenticatedResponse(response []byte) ([]byte, error) {
	// Response format:
	// DCE/RPC header (24 bytes)
	// Encrypted stub data (variable)
	// Auth verifier (8 bytes + 16 bytes signature)

	if len(response) < 24 {
		return nil, fmt.Errorf("response too short: %d bytes", len(response))
	}

	// Parse header
	fragLen := binary.LittleEndian.Uint16(response[8:10])
	authLen := binary.LittleEndian.Uint16(response[10:12])

	if int(fragLen) > len(response) {
		fragLen = uint16(len(response))
	}

	// Stub data is between header and auth trailer
	// Auth trailer: auth_type(1) + auth_level(1) + auth_pad_length(1) + reserved(1) + auth_context_id(4) + signature(16)
	authTrailerLen := int(authLen) + 8 // 8 bytes header + authLen for signature

	stubEnd := int(fragLen) - authTrailerLen
	if stubEnd < 24 {
		stubEnd = 24
	}

	encryptedStub := response[24:stubEnd]
	if len(encryptedStub) == 0 {
		return nil, nil
	}

	// Decrypt the stub using server seal key
	if auth.serverSealHandle == nil {
		return nil, fmt.Errorf("server seal handle not initialized")
	}

	decryptedStub := make([]byte, len(encryptedStub))
	auth.serverSealHandle.XORKeyStream(decryptedStub, encryptedStub)

	return decryptedStub, nil
}

// ========== NTLM Cryptographic Helper Functions ==========

func ntHash(password string) []byte {
	h := md4.New()
	h.Write(stringToUTF16LE(password))
	return h.Sum(nil)
}

func ntlmv2HashFunc(ntHash []byte, user, domain string) []byte {
	h := hmac.New(md5.New, ntHash)
	// CRITICAL: Only uppercase the user, NOT the domain!
	identity := uppercaseString(user) + domain
	h.Write(stringToUTF16LE(identity))
	return h.Sum(nil)
}

func calculateNTLMv2Response(ntlmv2Hash, serverChallenge, temp []byte) []byte {
	h := hmac.New(md5.New, ntlmv2Hash)
	h.Write(serverChallenge)
	h.Write(temp)
	resp := h.Sum(nil) // NTProofStr
	return append(resp, temp...)
}

func calculateSessionBaseKey(ntlmv2Hash, ntProofStr []byte) []byte {
	h := hmac.New(md5.New, ntlmv2Hash)
	h.Write(ntProofStr)
	return h.Sum(nil)
}

func calculateSignKey(sessionKey []byte, client bool) []byte {
	var magic string
	if client {
		magic = "session key to client-to-server signing key magic constant\x00"
	} else {
		magic = "session key to server-to-client signing key magic constant\x00"
	}
	h := md5.New()
	h.Write(sessionKey)
	h.Write([]byte(magic))
	return h.Sum(nil)
}

func calculateSealKey(sessionKey []byte, client bool) []byte {
	var magic string
	if client {
		magic = "session key to client-to-server sealing key magic constant\x00"
	} else {
		magic = "session key to server-to-client sealing key magic constant\x00"
	}
	h := md5.New()
	h.Write(sessionKey)
	h.Write([]byte(magic))
	return h.Sum(nil)
}

func buildTempBlob(timestamp int64, clientChallenge, targetInfo []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(0x01)                 // RespType
	buf.WriteByte(0x01)                 // HiRespType
	buf.Write([]byte{0, 0, 0, 0, 0, 0}) // Reserved
	binary.Write(buf, binary.LittleEndian, uint64(timestamp))
	buf.Write(clientChallenge)
	buf.Write([]byte{0, 0, 0, 0}) // Reserved
	buf.Write(targetInfo)
	buf.Write([]byte{0, 0, 0, 0}) // End
	return buf.Bytes()
}

func createMinimalTargetInfo() []byte {
	return []byte{0, 0, 0, 0}
}

func extractHostnameFromTargetInfo(targetInfo []byte) []byte {
	offset := 0
	for offset+4 <= len(targetInfo) {
		avID := binary.LittleEndian.Uint16(targetInfo[offset : offset+2])
		avLen := binary.LittleEndian.Uint16(targetInfo[offset+2 : offset+4])
		offset += 4
		if avID == 0x0000 {
			break
		}
		if avID == 0x0001 || avID == 0x0003 { // HOSTNAME or DNS_HOSTNAME
			if offset+int(avLen) <= len(targetInfo) {
				hostname := make([]byte, avLen)
				copy(hostname, targetInfo[offset:offset+int(avLen)])
				return hostname
			}
		}
		offset += int(avLen)
	}
	return nil
}

func addTargetNameToAVPairs(targetInfo []byte, hostname []byte) []byte {
	filtered := new(bytes.Buffer)
	offset := 0
	for offset+4 <= len(targetInfo) {
		avID := binary.LittleEndian.Uint16(targetInfo[offset : offset+2])
		avLen := binary.LittleEndian.Uint16(targetInfo[offset+2 : offset+4])
		if avID == 0x0000 {
			break
		}
		filtered.Write(targetInfo[offset : offset+4+int(avLen)])
		offset += 4 + int(avLen)
	}
	targetInfo = filtered.Bytes()

	// Build TARGET_NAME: 'cifs/' + hostname
	cifsPrefix := stringToUTF16LE("cifs/")
	targetName := append(cifsPrefix, hostname...)

	// Add TARGET_NAME AV_PAIR
	buf := new(bytes.Buffer)
	buf.Write(targetInfo)
	binary.Write(buf, binary.LittleEndian, uint16(0x0009)) // NTLMSSP_AV_TARGET_NAME
	binary.Write(buf, binary.LittleEndian, uint16(len(targetName)))
	buf.Write(targetName)

	// Add EOL
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))

	return buf.Bytes()
}

func stringToUTF16LE(s string) []byte {
	runes := []rune(s)
	u16 := utf16.Encode(runes)
	buf := new(bytes.Buffer)
	for _, r := range u16 {
		binary.Write(buf, binary.LittleEndian, r)
	}
	return buf.Bytes()
}

func uppercaseString(s string) string {
	runes := []rune(s)
	for i, r := range runes {
		if r >= 'a' && r <= 'z' {
			runes[i] = r - 32
		}
	}
	return string(runes)
}
