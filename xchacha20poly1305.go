package encryption

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func NewXChaCha20Cipher(key, oldKey string) (HexCipher, error) {
	if key == "" && oldKey == "" {
		return nil, ErrNoEncryptionKeys
	}

	var aead, aeadOldKey cipher.AEAD
	var err error

	// Create a new XChaCha20-Poly1305 cipher with the key and nonce
	if key != "" {
		aead, err = chacha20poly1305.NewX([]byte(key))
		if err != nil {
			return nil, fmt.Errorf("cannot initialize the xchacha20 cipher using the key: %w", err)
		}
	}

	if oldKey != "" {
		aeadOldKey, err = chacha20poly1305.NewX([]byte(oldKey))
		if err != nil {
			return nil, fmt.Errorf("cannot initialize the xchacha20 cipher using the old key: %w", err)
		}
	}

	return &dbCipher{aead: aead, aeadOldKey: aeadOldKey, nonceSize: chacha20poly1305.NonceSizeX}, nil
}
