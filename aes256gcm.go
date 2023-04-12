package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func NewAESCipher(key, oldKey string) (HexCipher, error) {
	if key == "" && oldKey == "" {
		return nil, ErrNoEncryptionKeys
	}

	var aead, aeadOldKey cipher.AEAD

	// Create a new AES256-GCM cipher with the key and nonce
	if key != "" {
		block, err := aes.NewCipher([]byte(key))
		if err != nil {
			return nil, fmt.Errorf("cannot create the aes cipher using the key: %w", err)
		}

		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("cannot create the gcm using the key: %w", err)
		}
	}

	if oldKey != "" {
		blockOldKey, err := aes.NewCipher([]byte(oldKey))
		if err != nil {
			return nil, fmt.Errorf("cannot create the aes cipher using the old key: %w", err)
		}

		aeadOldKey, err = cipher.NewGCM(blockOldKey)
		if err != nil {
			return nil, fmt.Errorf("cannot create the gcm using the old key: %w", err)
		}
	}

	return &dbCipher{aead: aead, aeadOldKey: aeadOldKey, nonceSize: aead.NonceSize()}, nil
}
