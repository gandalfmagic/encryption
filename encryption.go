package encryption

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

var (
	ErrNoEncryptionKeys   = errors.New("no encryption keys provided")
	ErrEncryptionDisabled = errors.New("no cipher defined, the encryption is disabled")
)

type HexCipher interface {
	EncryptToHexString(plaintext []byte) (string, error)
	DecryptFromHexString(ciphertext string) ([]byte, error)
}

type dbCipher struct {
	aead, aeadOldKey cipher.AEAD
	nonceSize        int
}

// Encrypt encrypts the given plaintext using XChaCha20-Poly1305 with a randomly generated nonce.
// It returns a slice of bytes that combines the nonce and the encrypted data.
func (c *dbCipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// rotation special case: if no cipher was defines, returns the plaintext
	if c.aead == nil {
		return nil, ErrEncryptionDisabled
	}

	// Encrypt the plaintext
	ciphertext := c.aead.Seal(nil, nonce, plaintext, nil)

	return append(nonce, ciphertext...), nil
}

// EncryptToHexString encrypts the given plaintext using XChaCha20-Poly1305 with a randomly generated nonce.
// It returns a hex-encoded string that combines the nonce and the encrypted data.
func (c *dbCipher) EncryptToHexString(plaintext []byte) (string, error) {
	enc, err := c.Encrypt(plaintext)
	if err != nil {
		switch {
		case errors.Is(err, ErrEncryptionDisabled):
			// rotation special case: if no cipher was defines, returns the plaintext
			return string(plaintext), nil
		default:
			return "", err
		}
	}

	return hex.EncodeToString(enc), nil
}

// Decrypt decrypts the given ciphertext using XChaCha20-Poly1305 and the given nonce.
// The input ciphertext parameter is a slice of bytes that combines the nonce and the encrypted data.
func (c *dbCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < c.nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:c.nonceSize]
	ciphertextBytes := ciphertext[c.nonceSize:]

	// rotation special case 1: current aead is not nil and old aead is nil
	// we want to decrypt the encrypted storage, so we should first try if the aeadOldKey works,
	// and return that, else we return the ciphertext text as plaintext
	if c.aead == nil && c.aeadOldKey != nil {
		plaintext, err := c.aeadOldKey.Open(nil, nonce, ciphertextBytes, nil)
		if err != nil {
			return ciphertext, nil
		}

		return plaintext, nil
	}

	// rotation special case 2: current aead is not nil and old aead is nil
	// we want to encrypt the encrypted storage, so we should first try if the aead works,
	// and return that, else we return the ciphertext text as plaintext
	if c.aead != nil && c.aeadOldKey == nil {
		plaintext, err := c.aead.Open(nil, nonce, ciphertextBytes, nil)
		if err != nil {
			return ciphertext, nil
		}

		return plaintext, nil
	}

	// In case both aead and old aead are not nil, we proceed with the standard key rotation
	plaintext, err := c.aead.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil && c.aeadOldKey != nil {
		plaintext, err = c.aeadOldKey.Open(nil, nonce, ciphertextBytes, nil)
	}
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// DecryptFromHexString decrypts the given ciphertext using XChaCha20-Poly1305 and the given nonce.
// The input ciphertext parameter is a hex-encoded string that combines the nonce and the encrypted data.
func (c *dbCipher) DecryptFromHexString(ciphertext string) ([]byte, error) {
	enc := make([]byte, hex.DecodedLen(len(ciphertext)))
	_, err := hex.Decode(enc, []byte(ciphertext))
	if err != nil {
		switch {
		case c.aead == nil && c.aeadOldKey != nil:
			// rotation special case 1: current aead is nil and old aead is not nil
			return []byte(ciphertext), nil
		case c.aead != nil && c.aeadOldKey == nil:
			// rotation special case 2: current aead is not nil and old aead is nil
			enc = []byte(ciphertext)
		default:
			return nil, err
		}
	}

	plaintext, err := c.Decrypt(enc)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
