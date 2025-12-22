package hive

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// LSASecret represents an extracted LSA secret
type LSASecret struct {
	Name    string
	Secret  []byte
	Decoded string // Human-readable if applicable
}

// CachedCredential represents a cached domain credential (DCC2)
type CachedCredential struct {
	Username string
	Domain   string
	Hash     string // DCC2/mscachev2 hash
}

// LSASecretKey is the decrypted LSA secret encryption key
type LSASecretKey struct {
	Key        []byte
	Revision   uint32
	VistaStyle bool // True if using AES encryption (Vista+), false for RC4 (XP)
}

// ExtractLSASecrets extracts LSA secrets from SECURITY hive
func ExtractLSASecrets(securityHive *Hive, bootKey []byte) ([]LSASecret, []CachedCredential, error) {
	var secrets []LSASecret
	var cachedCreds []CachedCredential

	// Get LSA encryption key
	lsaKey, err := extractLSAKey(securityHive, bootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract LSA key: %w", err)
	}

	// Extract LSA secrets from Policy\Secrets
	secretNames, err := securityHive.GetSubkeys("Policy\\Secrets")
	if err == nil {
		for _, name := range secretNames {
			secret, err := extractSecret(securityHive, lsaKey, name)
			if err != nil {
				continue
			}
			secrets = append(secrets, *secret)
		}
	}

	// Extract cached credentials from Cache
	creds, err := extractCachedCredentials(securityHive, lsaKey)
	if err == nil {
		cachedCreds = creds
	}

	return secrets, cachedCreds, nil
}

// extractLSAKey extracts the LSA encryption key from SECURITY hive
func extractLSAKey(securityHive *Hive, bootKey []byte) (*LSASecretKey, error) {
	// Try to get PolEKList (Vista+) or PolSecretEncryptionKey (XP)
	polEKList, err := securityHive.GetValue("Policy\\PolEKList", "")
	if err == nil && len(polEKList) > 0 {
		return decryptLSAKeyVista(polEKList, bootKey)
	}

	// Try XP-style key
	polSecretKey, err := securityHive.GetValue("Policy\\PolSecretEncryptionKey", "")
	if err == nil && len(polSecretKey) > 0 {
		return decryptLSAKeyXP(polSecretKey, bootKey)
	}

	return nil, fmt.Errorf("could not find LSA encryption key")
}

// decryptLSAKeyVista decrypts the Vista+ LSA key from PolEKList
// Uses LSA_SECRET structure: Version(4) + EncKeyID(16) + EncAlgorithm(4) + Flags(4) + EncryptedData
func decryptLSAKeyVista(polEKList, bootKey []byte) (*LSASecretKey, error) {
	// LSA_SECRET header is 28 bytes
	headerSize := 28
	if len(polEKList) < headerSize+64 {
		return nil, fmt.Errorf("PolEKList too short: %d bytes", len(polEKList))
	}

	revision := binary.LittleEndian.Uint32(polEKList[0:4])

	// EncryptedData starts after 28-byte header
	encData := polEKList[headerSize:]

	// Salt is first 32 bytes of EncryptedData
	salt := encData[:32]
	// Ciphertext is the rest
	ciphertext := encData[32:]

	if len(ciphertext) < 32 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Pad to block size
	if len(ciphertext)%16 != 0 {
		padded := (len(ciphertext) / 16) * 16
		if padded < 32 {
			padded = 32
		}
		ciphertext = ciphertext[:padded]
	}

	// Derive AES key using SHA256 with 1000 rounds
	aesKey := deriveAESKeyForLSA(bootKey, salt)

	// Decrypt using Impacket's method: new cipher per block with zero IV
	// This is NOT standard CBC - it's per-block decryption with IV reset each block
	decrypted := decryptAESPerBlock(aesKey, ciphertext)

	// Decrypted is LSA_SECRET_BLOB: Length(4) + Unknown(12) + Secret
	// The LSA key is at offset 52 within Secret for 32 bytes
	// So total offset is 16 (blob header) + 52 = 68
	keyOffset := 16 + 52
	if len(decrypted) < keyOffset+32 {
		return nil, fmt.Errorf("decrypted data too short for key: %d bytes", len(decrypted))
	}

	lsaKey := decrypted[keyOffset : keyOffset+32]

	return &LSASecretKey{
		Key:        lsaKey,
		Revision:   revision,
		VistaStyle: true, // Using AES encryption (Vista+)
	}, nil
}

// decryptLSAKeyXP decrypts the XP-style LSA key
func decryptLSAKeyXP(polSecretKey, bootKey []byte) (*LSASecretKey, error) {
	if len(polSecretKey) < 76 {
		return nil, fmt.Errorf("PolSecretEncryptionKey too short")
	}

	// XP uses RC4 with MD5-derived key
	encKey := polSecretKey[12:60]

	// Derive RC4 key
	h := md5.New()
	h.Write(bootKey)
	for i := 0; i < 1000; i++ {
		h.Write(polSecretKey[60:76])
	}
	rc4Key := h.Sum(nil)

	// Decrypt
	c, _ := rc4.NewCipher(rc4Key)
	decrypted := make([]byte, len(encKey))
	c.XORKeyStream(decrypted, encKey)

	return &LSASecretKey{
		Key:        decrypted[:16],
		Revision:   1,
		VistaStyle: false, // Using RC4 encryption (XP)
	}, nil
}

// deriveAESKeyForLSA derives the AES key for LSA decryption (Vista+)
func deriveAESKeyForLSA(bootKey, salt []byte) []byte {
	// SHA256-based key derivation with 1000 rounds
	h := sha256.New()
	h.Write(bootKey)
	for i := 0; i < 1000; i++ {
		h.Write(salt)
	}
	return h.Sum(nil)
}

// decryptAESPerBlock decrypts using Impacket's method: new cipher per block with zero IV
// This is NOT standard CBC - each 16-byte block is decrypted with a fresh cipher and zero IV
func decryptAESPerBlock(key, ciphertext []byte) []byte {
	result := make([]byte, 0, len(ciphertext))
	iv := make([]byte, 16)

	for i := 0; i < len(ciphertext); i += 16 {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil
		}

		chunk := ciphertext[i:]
		if len(chunk) > 16 {
			chunk = chunk[:16]
		}
		// Pad if less than 16 bytes
		if len(chunk) < 16 {
			padded := make([]byte, 16)
			copy(padded, chunk)
			chunk = padded
		}

		mode := cipher.NewCBCDecrypter(block, iv)
		decrypted := make([]byte, 16)
		mode.CryptBlocks(decrypted, chunk)
		result = append(result, decrypted...)
	}

	return result
}

// extractSecret extracts a single LSA secret
func extractSecret(securityHive *Hive, lsaKey *LSASecretKey, secretName string) (*LSASecret, error) {
	// Read CurrVal
	path := fmt.Sprintf("Policy\\Secrets\\%s\\CurrVal", secretName)
	currVal, err := securityHive.GetValue(path, "")
	if err != nil {
		return nil, err
	}

	if len(currVal) < 16 {
		return nil, fmt.Errorf("secret too short")
	}

	var decrypted []byte

	// NL$KM needs special handling - raw decryption without LSA_SECRET_BLOB parsing
	if secretName == "NL$KM" && lsaKey.VistaStyle {
		decrypted, err = decryptSecretRaw(currVal, lsaKey.Key)
	} else {
		decrypted, err = decryptSecret(currVal, lsaKey)
	}
	if err != nil {
		return nil, err
	}

	// Try to decode common secret formats
	decoded := decodeSecret(secretName, decrypted)

	return &LSASecret{
		Name:    secretName,
		Secret:  decrypted,
		Decoded: decoded,
	}, nil
}

// decryptSecretRaw performs raw AES decryption without LSA_SECRET_BLOB parsing
// Used for NL$KM which returns data directly
func decryptSecretRaw(encrypted, lsaKey []byte) ([]byte, error) {
	headerSize := 28
	if len(encrypted) < headerSize+32 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	encData := encrypted[headerSize:]
	salt := encData[:32]
	ciphertext := encData[32:]

	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("no encrypted data")
	}

	// Pad to block size
	if len(ciphertext)%16 != 0 {
		padLen := 16 - (len(ciphertext) % 16)
		ciphertext = append(ciphertext, make([]byte, padLen)...)
	}

	aesKey := deriveSecretAESKey(lsaKey, salt)

	// Use per-block decryption like Impacket
	decrypted := decryptAESPerBlock(aesKey, ciphertext)

	// Return 80 bytes for NL$KM (16-byte header + 64-byte key)
	if len(decrypted) > 80 {
		return decrypted[:80], nil
	}
	return decrypted, nil
}

// decryptSecret decrypts an LSA secret value
func decryptSecret(encrypted []byte, lsaKey *LSASecretKey) ([]byte, error) {
	if lsaKey.Revision >= 2 {
		// Vista+ AES encryption
		return decryptSecretAES(encrypted, lsaKey.Key)
	}
	// XP RC4 encryption
	return decryptSecretRC4(encrypted, lsaKey.Key)
}

// decryptSecretAES decrypts an AES-encrypted secret (Vista+)
// LSA_SECRET structure: Version(4) + EncKeyID(16) + EncAlgorithm(4) + Flags(4) + EncryptedData
func decryptSecretAES(encrypted, lsaKey []byte) ([]byte, error) {
	// Header is 28 bytes: Version(4) + EncKeyID(16) + EncAlgorithm(4) + Flags(4)
	headerSize := 28
	if len(encrypted) < headerSize+32 {
		return nil, fmt.Errorf("encrypted secret too short: %d bytes", len(encrypted))
	}

	// EncryptedData starts after header
	encData := encrypted[headerSize:]

	// Salt is first 32 bytes of EncryptedData
	salt := encData[:32]
	// Actual ciphertext is rest
	ciphertext := encData[32:]

	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("no encrypted data")
	}

	// Pad ciphertext to block size if needed
	if len(ciphertext)%16 != 0 {
		padLen := 16 - (len(ciphertext) % 16)
		ciphertext = append(ciphertext, make([]byte, padLen)...)
	}

	// Derive decryption key using SHA256 with 1000 rounds
	aesKey := deriveSecretAESKey(lsaKey, salt)

	// Use per-block decryption like Impacket
	decrypted := decryptAESPerBlock(aesKey, ciphertext)

	// Parse LSA_SECRET_BLOB: Length(4) + Unknown(12) + Secret(Length bytes)
	if len(decrypted) < 16 {
		return nil, fmt.Errorf("decrypted data too short")
	}

	secretLen := binary.LittleEndian.Uint32(decrypted[0:4])
	if secretLen > uint32(len(decrypted)-16) {
		// If length seems wrong, just return raw decrypted data
		return decrypted, nil
	}

	// Skip 16-byte header (Length + Unknown), return actual secret
	return decrypted[16 : 16+secretLen], nil
}

// decryptSecretRC4 decrypts an RC4-encrypted secret
func decryptSecretRC4(encrypted, lsaKey []byte) ([]byte, error) {
	if len(encrypted) < 16 {
		return nil, fmt.Errorf("encrypted secret too short")
	}

	// Derive RC4 key
	h := md5.New()
	h.Write(lsaKey)
	h.Write(encrypted[:8]) // Salt
	rc4Key := h.Sum(nil)

	// Decrypt
	c, _ := rc4.NewCipher(rc4Key)
	decrypted := make([]byte, len(encrypted)-16)
	c.XORKeyStream(decrypted, encrypted[16:])

	return decrypted, nil
}

// deriveSecretAESKey derives the AES key for secret decryption (Vista+)
// Uses SHA256 with 1000 rounds as per Impacket's implementation
func deriveSecretAESKey(lsaKey, salt []byte) []byte {
	h := sha256.New()
	h.Write(lsaKey)
	for i := 0; i < 1000; i++ {
		h.Write(salt)
	}
	return h.Sum(nil)
}

// decodeSecret attempts to decode a secret to human-readable form
func decodeSecret(name string, data []byte) string {
	if len(data) < 4 {
		return ""
	}

	// Check for common secret types
	switch {
	case len(name) > 4 && name[:4] == "_SC_":
		// Service account password (UTF-16LE)
		return "Service: " + decodeUTF16LEPassword(data)

	case name == "$MACHINE.ACC":
		// Machine account password (UTF-16LE)
		return "Machine$: " + decodeUTF16LEPassword(data)

	case name == "DPAPI_SYSTEM":
		// DPAPI master key
		if len(data) >= 44 {
			return "DPAPI: machineKey=" + hex.EncodeToString(data[4:24]) +
				" userKey=" + hex.EncodeToString(data[24:44])
		}

	case name == "NL$KM":
		// NL$KM key for cached credentials - skip 16-byte LSA_SECRET_BLOB header
		if len(data) > 16 {
			return "NL$KM: " + hex.EncodeToString(data[16:])
		}
		return "NL$KM: " + hex.EncodeToString(data)

	case name == "DefaultPassword":
		return "AutoLogon: " + decodeUTF16LEPassword(data)
	}

	// Return hex for unknown
	if len(data) > 64 {
		return hex.EncodeToString(data[:64]) + "..."
	}
	return hex.EncodeToString(data)
}

// decodeUTF16LEPassword decodes a UTF-16LE password, stopping at null
func decodeUTF16LEPassword(data []byte) string {
	// Skip length prefix if present (first 4 bytes might be length)
	start := 0
	if len(data) > 4 {
		length := binary.LittleEndian.Uint32(data[0:4])
		if length > 0 && length < uint32(len(data)) && length%2 == 0 {
			start = 4
			data = data[4 : 4+length]
		}
	}

	_ = start // Just for clarity

	return decodeUTF16LE(data)
}

// extractCachedCredentials extracts cached domain credentials (DCC2)
func extractCachedCredentials(securityHive *Hive, lsaKey *LSASecretKey) ([]CachedCredential, error) {
	var creds []CachedCredential

	// Get NL$KM key for decrypting cached creds
	nlkmData, err := extractNLKMKey(securityHive, lsaKey)
	if err != nil {
		return nil, err
	}

	// Enumerate Cache entries - these are VALUES under the Cache key, not subkeys
	// The format is NL$1, NL$2, etc. as value names under SECURITY\Cache
	for i := 1; i <= 128; i++ {
		valueName := fmt.Sprintf("NL$%d", i)
		cacheEntry, err := securityHive.GetValue("Cache", valueName)
		if err != nil {
			continue
		}
		if len(cacheEntry) < 96 {
			continue
		}

		cred, err := parseCacheEntry(cacheEntry, nlkmData)
		if err != nil {
			continue
		}

		if cred.Username != "" {
			creds = append(creds, *cred)
		}
	}

	return creds, nil
}

// extractNLKMKey extracts the NL$KM key using Impacket's approach
// NL$KM is special - we decrypt and return raw data without LSA_SECRET_BLOB parsing
func extractNLKMKey(securityHive *Hive, lsaKey *LSASecretKey) ([]byte, error) {

	// Get the encrypted NL$KM value
	encrypted, err := securityHive.GetValue("Policy\\Secrets\\NL$KM\\CurrVal", "")
	if err != nil {
		return nil, fmt.Errorf("failed to get NL$KM: %w", err)
	}

	if len(encrypted) < 60 { // 28 byte header + 32 byte salt minimum
		return nil, fmt.Errorf("NL$KM data too short: %d bytes", len(encrypted))
	}

	// LSA_SECRET header is 28 bytes
	headerSize := 28
	encData := encrypted[headerSize:]

	// Salt is first 32 bytes
	salt := encData[:32]
	// Ciphertext is rest
	ciphertext := encData[32:]

	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("no encrypted data in NL$KM")
	}

	// Pad to AES block size
	if len(ciphertext)%16 != 0 {
		padLen := 16 - (len(ciphertext) % 16)
		ciphertext = append(ciphertext, make([]byte, padLen)...)
	}

	// Derive AES key: SHA256(lsaKey + salt*1000)
	aesKey := deriveSecretAESKey(lsaKey.Key, salt)

	// Use per-block decryption like Impacket
	decrypted := decryptAESPerBlock(aesKey, ciphertext)

	// Return raw decrypted data (should be 64 bytes for NL$KM)
	// Trim any padding
	if len(decrypted) > 64 {
		decrypted = decrypted[:64]
	}

	return decrypted, nil
}

// parseCacheEntry parses a cached credential entry
func parseCacheEntry(entry, nlkmKey []byte) (*CachedCredential, error) {
	if len(entry) < 96 {
		return nil, fmt.Errorf("entry too short")
	}

	// NL_RECORD structure (from Impacket secretsdump.py):
	// 0-1: UserLength
	// 2-3: DomainNameLength
	// 4-5: EffectiveNameLength
	// 6-7: FullNameLength
	// 8-15: various lengths
	// 16-19: UserId
	// 20-23: PrimaryGroupId
	// 24-27: GroupCount
	// 28-29: logonDomainNameLength
	// 30-31: unk0
	// 32-39: LastWrite
	// 40-43: Revision
	// 44-47: SidCount
	// 48-51: Flags
	// 52-55: unk1
	// 56-59: LogonPackageLength
	// 60-61: DnsDomainNameLength
	// 62-63: UPN
	// 64-79: IV (16 bytes)
	// 80-95: CH (16 bytes)
	// 96+: EncryptedData

	userLen := binary.LittleEndian.Uint16(entry[0:2])
	domainNameLen := binary.LittleEndian.Uint16(entry[2:4])
	dnsDomainNameLen := binary.LittleEndian.Uint16(entry[60:62]) // Correct offset
	flags := binary.LittleEndian.Uint32(entry[48:52])

	iv := entry[64:80]
	encryptedData := entry[96:]

	// Check if IV is all zeros - skip if so (empty entry)
	allZero := true
	for _, b := range iv {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, fmt.Errorf("empty entry (IV is zero)")
	}

	// Check if encrypted (Flags & 1 == 1)
	if flags&1 != 1 {
		return nil, fmt.Errorf("unencrypted entry not supported")
	}

	// Need at least 16 bytes for decryption key
	if len(nlkmKey) < 32 {
		return nil, fmt.Errorf("NL$KM key too short")
	}

	// Decrypt using AES-CBC with NL$KM[16:32] as key
	aesKey := nlkmKey[16:32]

	// Ensure encrypted data is block-aligned
	encLen := len(encryptedData)
	if encLen%16 != 0 {
		encLen = (encLen / 16) * 16
	}
	if encLen == 0 || encLen > len(encryptedData) {
		return nil, fmt.Errorf("encrypted data size issue")
	}
	encryptedData = encryptedData[:encLen]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES init failed: %w", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(encryptedData))
	mode.CryptBlocks(plainText, encryptedData)

	// Decrypted structure:
	// 0-15: DCC2 hash
	// 16-71: padding/metadata
	// 72+: username (UTF-16LE), then domain, then DNS domain

	if len(plainText) < 0x48+int(userLen) {
		return nil, fmt.Errorf("decrypted data too short for username")
	}

	encHash := plainText[:16]

	// Username starts at offset 0x48 (72)
	userOffset := 0x48
	username := decodeUTF16LE(plainText[userOffset : userOffset+int(userLen)])

	// Domain is after username, padded to 4-byte boundary
	domainOffset := userOffset + pad4(int(userLen))
	var domain string
	if domainOffset+int(domainNameLen) <= len(plainText) {
		domain = decodeUTF16LE(plainText[domainOffset : domainOffset+int(domainNameLen)])
	}

	// DNS domain is after domain name, padded
	dnsDomainOffset := domainOffset + pad4(int(domainNameLen))
	var dnsDomain string
	if dnsDomainOffset+int(dnsDomainNameLen) <= len(plainText) {
		dnsDomain = decodeUTF16LE(plainText[dnsDomainOffset : dnsDomainOffset+int(dnsDomainNameLen)])
	}

	// Use DNS domain if available, otherwise short domain name
	displayDomain := dnsDomain
	if displayDomain == "" {
		displayDomain = domain
	}

	return &CachedCredential{
		Username: username,
		Domain:   displayDomain,
		Hash:     hex.EncodeToString(encHash),
	}, nil
}

// pad4 returns value padded per Impacket's logic: n + (n & 0x3)
func pad4(n int) int {
	if n&0x3 > 0 {
		return n + (n & 0x3)
	}
	return n
}
