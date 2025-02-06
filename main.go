package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	// "crypto/sha256"
	// "encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

func main() {
	for {
		fmt.Println("\n===== File Encryption/Decryption =====")
		fmt.Println("1. Encrypt File")
		fmt.Println("2. Decrypt File")
		fmt.Println("3. Exit")
		fmt.Print("Enter your choice: ")

		var choice int
		_, err := fmt.Scanln(&choice)
		if err != nil {
			fmt.Println("Invalid input! Please enter a number (1, 2, or 3).")
			continue
		}

		switch choice {
		case 1:
			encryptFile()
		case 2:
			decryptFile()
		case 3:
			fmt.Println("Exiting program. Goodbye!")
			return
		default:
			fmt.Println("Invalid choice! Please enter 1, 2, or 3.")
		}
	}
}

func encryptFile() {
	fmt.Println("\n🔒 Starting Encryption...")

	fmt.Print("Enter the plaintext file path: ")
	var inputFile string
	fmt.Scanln(&inputFile)

	fmt.Print("Enter the key file path: ")
	var keyFile string
	fmt.Scanln(&keyFile)

	plainText, err := os.ReadFile(inputFile)
	if err != nil {
		log.Fatalf("Error reading plaintext file: %v", err)
	}

	key, err := os.ReadFile(keyFile)
	if err != nil {
		log.Fatalf("Error reading key file: %v", err)
	}

	key = bytes.TrimSpace(key)

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		log.Fatalf("Invalid key size: %d bytes. Must be 16, 24, or 32 bytes.", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Cipher error: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("GCM mode error: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("Nonce error: %v", err)
	}

	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	outputDir := "outputs"
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		os.MkdirAll(outputDir, 0755)
	}

	outputFile := filepath.Join(outputDir, "ciphertext.bin")
	err = os.WriteFile(outputFile, cipherText, 0644)
	if err != nil {
		log.Fatalf("Error writing ciphertext file: %v", err)
	}

	fmt.Printf("✅ Encryption successful! Encrypted file saved as %s\n", outputFile)
}

func decryptFile() {
	fmt.Println("\n🔓 Starting Decryption...")

	fmt.Print("Enter the ciphertext file path: ")
	var inputFile string
	fmt.Scanln(&inputFile)

	fmt.Print("Enter the key file path: ")
	var keyFile string
	fmt.Scanln(&keyFile)

	cipherText, err := os.ReadFile(inputFile)
	if err != nil {
		log.Fatalf("Error reading ciphertext file: %v", err)
	}

	key, err := os.ReadFile(keyFile)
	if err != nil {
		log.Fatalf("Error reading key file: %v", err)
	}

	key = bytes.TrimSpace(key)

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		log.Fatalf("Invalid key size: %d bytes. Must be 16, 24, or 32 bytes.", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Cipher error: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("GCM mode error: %v", err)
	}

	if len(cipherText) < gcm.NonceSize() {
		log.Fatal("Ciphertext is too short, possible corruption.")
	}

	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.Fatalf("Decryption error: %v", err)
	}

	outputDir := "outputs"
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		os.MkdirAll(outputDir, 0755)
	}

	outputFile := filepath.Join(outputDir, "decrypted.txt")
	err = os.WriteFile(outputFile, plainText, 0644)
	if err != nil {
		log.Fatalf("Error writing decrypted file: %v", err)
	}

	fmt.Printf("✅ Decryption successful! File saved to %s\n", outputFile)
}
