package orchestrator

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DecryptQuarantine decrypts and decompresses an .enc.gz quarantine file.
// Format: gzip( IV[16] + AES-256-CBC(PKCS7(plaintext)) )
// Key: SHA256(password)
func DecryptQuarantine(encPath, outputPath, password string) error {
	// Read encrypted file
	compressed, err := os.ReadFile(encPath)
	if err != nil {
		return fmt.Errorf("read encrypted file: %w", err)
	}

	// Decompress gzip
	gzReader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("gzip decompress: %w", err)
	}
	data, err := io.ReadAll(gzReader)
	gzReader.Close()
	if err != nil {
		return fmt.Errorf("gzip read: %w", err)
	}

	if len(data) < 16+aes.BlockSize {
		return fmt.Errorf("encrypted data too short")
	}

	// Extract IV and ciphertext
	iv := data[:16]
	ciphertext := data[16:]

	// Derive key from password: SHA256(password)
	key := sha256.Sum256([]byte(password))

	// Decrypt AES-256-CBC
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return fmt.Errorf("ciphertext not block-aligned")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return fmt.Errorf("PKCS7 unpad: %w", err)
	}

	// Write output
	if outputPath == "" {
		// Remove .enc.gz extension
		outputPath = strings.TrimSuffix(encPath, ".enc.gz")
		if outputPath == encPath {
			outputPath = encPath + ".decrypted"
		}
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, plaintext, 0o644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	fmt.Printf("[OK] Decrypted: %s -> %s\n", encPath, outputPath)
	return nil
}

// pkcs7Unpad removes PKCS#7 padding.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, fmt.Errorf("invalid padding length: %d", padLen)
	}

	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("invalid PKCS7 padding")
		}
	}

	return data[:len(data)-padLen], nil
}
