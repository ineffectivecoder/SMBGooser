package hive

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// SAMHash represents an extracted SAM hash
type SAMHash struct {
	Username string
	RID      uint32
	LMHash   string
	NTHash   string
}

// ExtractBootKey extracts the boot key from a SYSTEM hive
func ExtractBootKey(systemHive *Hive) ([]byte, error) {
	// The boot key is stored scrambled across 4 registry values
	// HKLM\SYSTEM\CurrentControlSet\Control\Lsa\{JD, Skew1, GBG, Data}
	// Each contains a class name that holds part of the key

	// First, find CurrentControlSet (could be ControlSet001, ControlSet002, etc.)
	selectKey, err := systemHive.GetValue("Select", "Current")
	if err != nil {
		return nil, fmt.Errorf("failed to get CurrentControlSet: %w", err)
	}

	currentCS := "ControlSet001"
	if len(selectKey) >= 4 {
		csNum := binary.LittleEndian.Uint32(selectKey)
		currentCS = fmt.Sprintf("ControlSet%03d", csNum)
	}

	// Get the scrambled boot key parts
	lsaPath := currentCS + "\\Control\\Lsa"
	keyNames := []string{"JD", "Skew1", "GBG", "Data"}
	scrambledKey := make([]byte, 0, 16)

	for _, keyName := range keyNames {
		// The class name of each key contains part of the boot key
		// For now, we'll try to read the key's class data
		keyPath := lsaPath + "\\" + keyName
		keyOffset, err := systemHive.findKey(keyPath)
		if err != nil {
			// Try to extract from key class name
			continue
		}

		// Read class name from key node
		classData := systemHive.getKeyClass(keyOffset)
		if len(classData) > 0 {
			scrambledKey = append(scrambledKey, classData...)
		}
	}

	if len(scrambledKey) < 16 {
		return nil, fmt.Errorf("failed to extract full boot key (got %d bytes)", len(scrambledKey))
	}


	// Unscramble the boot key
	// The key is stored in a specific permutation
	transforms := []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}
	bootKey := make([]byte, 16)
	for i, t := range transforms {
		if t < len(scrambledKey) {
			bootKey[i] = scrambledKey[t]
		}
	}


	return bootKey, nil
}

// getKeyClass reads the class name from a key node
// NK record structure (offsets from NK signature at cell+4):
//
//	NK+44 = cell+48: Security key offset
//	NK+48 = cell+52: Class name offset (4 bytes)
//	NK+72 = cell+76: Name length
//	NK+74 = cell+78: Class name length (2 bytes)
//	NK+76 = cell+80: Key name
func (h *Hive) getKeyClass(keyOffset int) []byte {
	if keyOffset+82 > len(h.data) {
		return nil
	}

	// keyOffset points to cell start (4-byte size field)
	// NK signature is at keyOffset+4
	// classOffset is at NK+48 = cell+52
	classOff := binary.LittleEndian.Uint32(h.data[keyOffset+52 : keyOffset+56])
	// classLen is at NK+74 = cell+78
	classLen := binary.LittleEndian.Uint16(h.data[keyOffset+78 : keyOffset+80])

	if classLen == 0 || classOff == 0xFFFFFFFF {
		return nil
	}

	classAbs := int(classOff) + 4096
	if classAbs+4+int(classLen) > len(h.data) {
		return nil
	}

	// Class data is UTF-16LE encoded hex characters
	classData := h.data[classAbs+4 : classAbs+4+int(classLen)]

	// Convert UTF-16LE to ASCII hex string
	hexStr := decodeUTF16LE(classData)

	// Decode hex string to raw bytes
	result, err := hex.DecodeString(hexStr)
	if err != nil {
		// If hex decode fails, return raw class data
		return classData
	}

	return result
}

// ExtractSAMHashes extracts password hashes from SAM hive using boot key
func ExtractSAMHashes(samHive *Hive, bootKey []byte) ([]SAMHash, error) {
	var hashes []SAMHash

	// Get domain encryption key from SAM\Domains\Account\F
	fData, err := samHive.GetValue("SAM\\Domains\\Account", "F")
	if err != nil {
		return nil, fmt.Errorf("failed to get domain F: %w", err)
	}

	// Derive the hashed boot key
	hashedBootKey, err := deriveHashedBootKey(fData, bootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive hashed boot key: %w", err)
	}

	// Enumerate users
	usersPath := "SAM\\Domains\\Account\\Users"
	userRIDs, err := samHive.GetSubkeys(usersPath)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate users: %w", err)
	}

	for _, ridStr := range userRIDs {
		if ridStr == "Names" {
			continue
		}

		// Parse RID from hex string
		var rid uint32
		fmt.Sscanf(ridStr, "%08X", &rid)

		// Get user V data
		userPath := usersPath + "\\" + ridStr
		vData, err := samHive.GetValue(userPath, "V")
		if err != nil {
			continue
		}

		// Extract username and hashes from V structure
		hash := extractUserHash(vData, hashedBootKey, rid)
		if hash != nil {
			hashes = append(hashes, *hash)
		}
	}

	return hashes, nil
}

// deriveHashedBootKey derives the hashed boot key from domain F data
// F data contains DOMAIN_ACCOUNT_F structure, Key0 at offset 0x68 (104 bytes)
func deriveHashedBootKey(fData, bootKey []byte) ([]byte, error) {
	if len(fData) < 0x80 {
		return nil, fmt.Errorf("F data too short")
	}

	// Key0 starts at offset 0x68 in DOMAIN_ACCOUNT_F (after 104 bytes of fixed fields)
	// First byte of Key0 indicates the revision
	key0Offset := 0x68
	revision := fData[key0Offset]


	if revision == 0x01 {
		// RC4 encryption (older Windows)
		return deriveHashedBootKeyRC4(fData, bootKey, key0Offset)
	} else if revision == 0x02 {
		// AES encryption (Windows 2016+)
		return deriveHashedBootKeyAES(fData, bootKey, key0Offset)
	}

	return nil, fmt.Errorf("unknown F key revision: 0x%02x", revision)
}

func deriveHashedBootKeyRC4(fData, bootKey []byte, key0Offset int) ([]byte, error) {
	// SAM_KEY_DATA structure at key0Offset:
	// 0: Revision (4 bytes)
	// 4: Length (4 bytes)
	// 8: Salt (16 bytes)
	// 24: Key (16 bytes)
	// 40: CheckSum (16 bytes)

	if len(fData) < key0Offset+56 {
		return nil, fmt.Errorf("F data too short for RC4 key data")
	}

	salt := fData[key0Offset+8 : key0Offset+24]
	encKey := fData[key0Offset+24 : key0Offset+40]
	checkSum := fData[key0Offset+40 : key0Offset+56]

	// Constants from Impacket
	QWERTY := []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
	DIGITS := []byte("0123456789012345678901234567890123456789\x00")

	// Derive RC4 key: MD5(Salt + QWERTY + bootKey + DIGITS)
	h := md5.New()
	h.Write(salt)
	h.Write(QWERTY)
	h.Write(bootKey)
	h.Write(DIGITS)
	rc4Key := h.Sum(nil)

	// Decrypt key + checksum
	c, _ := rc4.NewCipher(rc4Key)
	decrypted := make([]byte, 32)
	combined := append(encKey, checkSum...)
	c.XORKeyStream(decrypted, combined)

	hashedBootKey := decrypted[:16]
	decryptedCheckSum := decrypted[16:]

	// Verify checksum: MD5(hashedBootKey + DIGITS + hashedBootKey + QWERTY)
	h2 := md5.New()
	h2.Write(hashedBootKey)
	h2.Write(DIGITS)
	h2.Write(hashedBootKey)
	h2.Write(QWERTY)
	expectedCheckSum := h2.Sum(nil)

	if !bytesEqual(expectedCheckSum, decryptedCheckSum) {
		// Continue anyway - might be syskey password protected
	}

	return hashedBootKey, nil
}

func deriveHashedBootKeyAES(fData, bootKey []byte, key0Offset int) ([]byte, error) {
	// SAM_KEY_DATA_AES structure at key0Offset:
	// 0: Revision (4 bytes)
	// 4: Length (4 bytes)
	// 8: CheckSumLen (4 bytes)
	// 12: DataLen (4 bytes)
	// 16: Salt (16 bytes)
	// 32: Data (variable)

	if len(fData) < key0Offset+32 {
		return nil, fmt.Errorf("F data too short for AES header")
	}

	dataLen := binary.LittleEndian.Uint32(fData[key0Offset+12 : key0Offset+16])
	salt := fData[key0Offset+16 : key0Offset+32]

	if len(fData) < key0Offset+32+int(dataLen) {
		return nil, fmt.Errorf("F data too short for AES data")
	}

	encData := fData[key0Offset+32 : key0Offset+32+int(dataLen)]


	// Decrypt with AES-CBC using bootKey as key and salt as IV
	// Use bootKey as-is (16 bytes)
	if len(bootKey) < 16 {
		return nil, fmt.Errorf("boot key too short")
	}

	block, err := aes.NewCipher(bootKey[:16])
	if err != nil {
		return nil, err
	}

	// Pad encrypted data if needed
	encLen := len(encData)
	if encLen%16 != 0 {
		encLen = (encLen / 16) * 16
	}
	if encLen == 0 {
		encLen = 16
	}
	paddedEnc := make([]byte, encLen)
	copy(paddedEnc, encData)

	mode := cipher.NewCBCDecrypter(block, salt)
	decrypted := make([]byte, len(paddedEnc))
	mode.CryptBlocks(decrypted, paddedEnc)


	// Return first 16 bytes as hashed boot key
	return decrypted[:16], nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// extractUserHash extracts LM and NT hashes from user V data
func extractUserHash(vData, hashedBootKey []byte, rid uint32) *SAMHash {
	if len(vData) < 0xCC {
		return nil
	}

	// Parse V structure
	// Offset 0x0C: Name offset
	// Offset 0x10: Name length
	// Offset 0xA8: LM hash offset
	// Offset 0xAC: LM hash length
	// Offset 0xB0: NT hash offset
	// Offset 0xB4: NT hash length

	nameOffset := binary.LittleEndian.Uint32(vData[0x0C:0x10]) + 0xCC
	nameLength := binary.LittleEndian.Uint32(vData[0x10:0x14])

	var username string
	if int(nameOffset+nameLength) <= len(vData) && nameLength > 0 {
		// UTF-16LE encoded name
		nameBytes := vData[nameOffset : nameOffset+nameLength]
		username = decodeUTF16LE(nameBytes)
	}

	// V structure: hash at 0xA8 is what we need for NT hash
	// Modern Windows stores NT hash at what was historically the LM position
	// 0xB0 is typically 0 (no separate NT hash location)
	ntOffset := binary.LittleEndian.Uint32(vData[0xA8:0xAC]) + 0xCC
	ntLength := binary.LittleEndian.Uint32(vData[0xAC:0xB0])

	// Decrypt hashes
	lmHash := "aad3b435b51404eeaad3b435b51404ee" // Empty LM hash (not used for PTH)
	ntHash := "31d6cfe0d16ae931b73c59d7e0c089c0" // Empty NT hash

	if ntLength >= 20 && int(ntOffset+ntLength) <= len(vData) {
		encNT := vData[ntOffset : ntOffset+ntLength]
		decNT := decryptHash(encNT, hashedBootKey, rid)
		if len(decNT) == 16 {
			ntHash = hex.EncodeToString(decNT)
		}
	}

	return &SAMHash{
		Username: username,
		RID:      rid,
		LMHash:   lmHash,
		NTHash:   ntHash,
	}
}

// decryptHash decrypts a SAM hash
func decryptHash(encHash, hashedBootKey []byte, rid uint32) []byte {
	if len(encHash) < 4 {
		return nil
	}

	// Check revision
	revision := binary.LittleEndian.Uint16(encHash[0:2])

	if revision == 1 {
		// RC4 + DES
		return decryptHashRC4(encHash, hashedBootKey, rid)
	} else if revision == 2 {
		// AES
		return decryptHashAES(encHash, hashedBootKey, rid)
	}

	return nil
}

func decryptHashRC4(encHash, hashedBootKey []byte, rid uint32) []byte {
	if len(encHash) < 20 {
		return nil
	}

	// Skip revision (2 bytes) + padding (2 bytes)
	encrypted := encHash[4:20]

	// Derive RC4 key: MD5(hashedBootKey + RID + NTPASSWORD/LMPASSWORD)
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)

	passwordConst := []byte("NTPASSWORD\x00")

	h := md5.New()
	h.Write(hashedBootKey)
	h.Write(ridBytes)
	h.Write(passwordConst)
	rc4Key := h.Sum(nil)

	// Decrypt with RC4
	c, _ := rc4.NewCipher(rc4Key)
	obfuscated := make([]byte, 16)
	c.XORKeyStream(obfuscated, encrypted)

	// DES deobfuscation using RID
	return desobfuscateWithDES(obfuscated, rid)
}

func decryptHashAES(encHash, hashedBootKey []byte, rid uint32) []byte {
	// SAM_HASH_AES structure:
	// 0-1: PekID (2 bytes)
	// 2-3: Revision (2 bytes)
	// 4-7: DataOffset (4 bytes)
	// 8-23: Salt (16 bytes)
	// 24+: Hash (encrypted, if present)

	// Minimum is 24 bytes (header only, no hash = empty)
	if len(encHash) < 24 {
		return nil
	}

	salt := encHash[8:24]
	encrypted := encHash[24:]

	// If no encrypted data after salt, return nil (empty hash)
	if len(encrypted) < 16 {
		return nil
	}

	// Use hashedBootKey[:16] directly as AES key, salt as IV (Impacket style)
	if len(hashedBootKey) < 16 {
		return nil
	}

	block, err := aes.NewCipher(hashedBootKey[:16])
	if err != nil {
		return nil
	}

	// Pad to block size if needed
	encLen := len(encrypted)
	if encLen%16 != 0 {
		encLen = (encLen / 16) * 16
	}
	if encLen < 16 {
		encLen = 16
	}
	paddedEnc := make([]byte, encLen)
	copy(paddedEnc, encrypted)

	mode := cipher.NewCBCDecrypter(block, salt)
	decrypted := make([]byte, len(paddedEnc))
	mode.CryptBlocks(decrypted, paddedEnc)

	if len(decrypted) < 16 {
		return nil
	}

	// DES deobfuscation using RID
	return desobfuscateWithDES(decrypted[:16], rid)
}

// desobfuscateWithDES performs DES deobfuscation on the hash
func desobfuscateWithDES(obfuscated []byte, rid uint32) []byte {
	if len(obfuscated) != 16 {
		return nil
	}

	// Split into two 8-byte parts
	part1 := obfuscated[:8]
	part2 := obfuscated[8:]

	// Derive two 7-byte DES keys from RID
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)

	// Expand to 14 bytes by repeating
	ridExpanded := make([]byte, 14)
	for i := 0; i < 14; i++ {
		ridExpanded[i] = ridBytes[i%4]
	}

	key1 := expandDESKey(ridExpanded[:7])
	key2 := expandDESKey(ridExpanded[7:])

	// DES decrypt each part
	result := make([]byte, 16)

	c1, err := des.NewCipher(key1)
	if err == nil {
		c1.Decrypt(result[:8], part1)
	}

	c2, err := des.NewCipher(key2)
	if err == nil {
		c2.Decrypt(result[8:], part2)
	}

	return result
}

// expandDESKey expands a 7-byte key to 8-byte DES key with parity bits
func expandDESKey(key7 []byte) []byte {
	if len(key7) != 7 {
		return make([]byte, 8)
	}

	key8 := make([]byte, 8)
	key8[0] = key7[0] >> 1
	key8[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2)
	key8[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3)
	key8[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4)
	key8[4] = ((key7[3] & 0x0F) << 3) | (key7[4] >> 5)
	key8[5] = ((key7[4] & 0x1F) << 2) | (key7[5] >> 6)
	key8[6] = ((key7[5] & 0x3F) << 1) | (key7[6] >> 7)
	key8[7] = key7[6] & 0x7F

	// Set parity bits
	for i := 0; i < 8; i++ {
		key8[i] = (key8[i] << 1) & 0xFE
	}

	return key8
}

// decodeUTF16LE decodes UTF-16LE bytes to string
func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	runes := make([]rune, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		r := rune(binary.LittleEndian.Uint16(data[i:]))
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}
