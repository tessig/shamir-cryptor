package file

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

func EncryptFile(fileName, encryptedFileName string, secret []byte) (string, error) {
	plaintext, err := os.ReadFile(fileName)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	stat, err := os.Stat(fileName)
	if err != nil {
		return "", fmt.Errorf("failed to read stats: %w", err)
	}

	ciphertext, err := encrypt(plaintext, secret)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt file: %w", err)
	}

	if err := os.WriteFile(encryptedFileName, ciphertext, stat.Mode().Perm()); err != nil {
		return "", fmt.Errorf("failed to write to %q: %w", encryptedFileName, err)
	}

	return encryptedFileName, nil
}

// Encrypts the plaintext using AES GCM
func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// Funktion zum Entschlüsseln einer Datei
func DecryptFile(fileName, decryptedFileName string, secret []byte) (string, error) {
	ciphertext, err := os.ReadFile(fileName)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	stat, err := os.Stat(fileName)
	if err != nil {
		return "", fmt.Errorf("failed to read stats: %w", err)
	}

	plaintext, err := decrypt(ciphertext, secret)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt file: %w", err)
	}

	if err := os.WriteFile(decryptedFileName, plaintext, stat.Mode().Perm()); err != nil {
		return "", fmt.Errorf("failed to write to %q: %w", decryptedFileName, err)
	}

	return decryptedFileName, nil
}

// Decrypts the ciphertext using AES GCM
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
