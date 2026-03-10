// decrypt-tool: Quarantine暗号化ファイル(.enc.gz)をスタンドアロンで復号する
//
// ホストのDefenderがマルウェアを削除する問題を回避するため、
// 暗号化したままVMゲストにコピーし、ゲスト内で復号する。
//
// 暗号方式: gzip圧縮 → AES-256-CBC (IV先頭16byte, PKCS7パディング)
// 鍵導出: SHA256(password)
//
// Usage:
//
//	decrypt-tool -p <password> -i <input.enc.gz> [-o <output>]
package main

import (
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func removePKCS7Padding(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, fmt.Errorf("invalid padding length: %d", padLen)
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding byte at position %d", i)
		}
	}
	return data[:len(data)-padLen], nil
}

func decrypt(inputPath, outputPath, password string) error {
	// Read encrypted file
	encFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer encFile.Close()

	// Decompress gzip
	gzReader, err := gzip.NewReader(encFile)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gzReader.Close()

	data, err := io.ReadAll(gzReader)
	if err != nil {
		return fmt.Errorf("gzip read: %w", err)
	}

	if len(data) < 16 {
		return fmt.Errorf("data too short (need at least 16 bytes for IV)")
	}

	// Extract IV (first 16 bytes) and ciphertext
	iv := data[:16]
	ciphertext := data[16:]

	// Derive key: SHA256(password)
	keyHash := sha256.Sum256([]byte(password))
	key := keyHash[:]

	// Decrypt AES-256-CBC
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("aes cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return fmt.Errorf("ciphertext not multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	plaintext, err = removePKCS7Padding(plaintext, aes.BlockSize)
	if err != nil {
		return fmt.Errorf("padding: %w", err)
	}

	// Write output
	if err := os.WriteFile(outputPath, plaintext, 0644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	return nil
}

func main() {
	inputFile := flag.String("i", "", "Input file (.enc.gz)")
	outputFile := flag.String("o", "", "Output file (default: remove .enc.gz)")
	password := flag.String("p", "", "Decryption password")
	flag.Parse()

	if *inputFile == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "Usage: decrypt-tool -p <password> -i <input.enc.gz> [-o <output>]")
		os.Exit(1)
	}

	if *outputFile == "" {
		base := filepath.Base(*inputFile)
		base = strings.TrimSuffix(base, ".enc.gz")
		*outputFile = filepath.Join(filepath.Dir(*inputFile), base)
	}

	if err := decrypt(*inputFile, *outputFile, *password); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[OK] Decrypted: %s -> %s\n", *inputFile, *outputFile)
}
