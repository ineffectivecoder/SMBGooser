// Package crypto provides cryptographic primitives for NTLM authentication.
package crypto

import (
	"crypto/hmac"
	"crypto/md5"

	"golang.org/x/crypto/md4"
)

// MD4Hash computes the MD4 hash of data
func MD4Hash(data []byte) []byte {
	h := md4.New()
	h.Write(data)
	return h.Sum(nil)
}

// HMACMD5 computes HMAC-MD5
func HMACMD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}
