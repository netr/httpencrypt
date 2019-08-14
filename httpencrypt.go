package httpencrypt

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// B64Decode decodes base64 strings
func B64Decode(data string) []byte {
	dec, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil
	}

	return dec
}

// B64Encode encodes base64 strings
func B64Encode(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	return enc
}

// Sha256Hash returns a sha256 hash
func Sha256Hash(data []byte) [32]byte {
	sum := sha256.Sum256(data)
	return sum
}

// MD5Hash returns a md5 hash
func MD5Hash(data []byte) [16]byte {
	return md5.Sum(data)
}

// Sha256Hmac returns a sha256 with a secret hash
func Sha256Hmac(secret string, data string) string {
	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(secret))

	// Write Data to it
	h.Write([]byte(data))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))

	return sha
}
