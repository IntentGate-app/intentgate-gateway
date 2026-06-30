package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// sealer encrypts and decrypts credential values at rest with
// AES-256-GCM. The key is the gateway's credential-encryption key
// (32 bytes); the plaintext is the "Header-Name: value" string.
type sealer struct{ gcm cipher.AEAD }

// newSealer builds a sealer from a 32-byte key.
func newSealer(key []byte) (*sealer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("credentials: encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{gcm: gcm}, nil
}

// seal returns base64(nonce || ciphertext). A fresh random nonce is
// used per call, so encrypting the same value twice yields different
// ciphertexts.
func (s *sealer) seal(plain string) (string, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := s.gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// open reverses seal.
func (s *sealer) open(enc string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	ns := s.gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("credentials: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	plain, err := s.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
