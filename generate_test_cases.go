package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	// Generate a new private key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// Get the private key hex for documentation
	privateKeyBytes := crypto.FromECDSA(privateKey)
	privateKeyHex := hex.EncodeToString(privateKeyBytes)

	// Get the address
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	// Create test SIWE messages
	messages := []string{
		fmt.Sprintf(`example.com wants you to sign in with your Ethereum account:
%s

Sign in to Example App

URI: https://example.com
Version: 1
Chain ID: 1
Nonce: 12345678
Issued At: 2025-01-01T00:00:00.000Z`, address.Hex()),

		fmt.Sprintf(`example.com wants you to sign in with your Ethereum account:
%s

URI: https://example.com
Version: 1
Chain ID: 1
Nonce: 12345678
Issued At: 2025-01-01T00:00:00.000Z`, address.Hex()),
	}

	fmt.Printf("// Generated with private key: 0x%s\n", privateKeyHex)
	fmt.Println("// Generated test data:")
	fmt.Println("positiveExamples := []struct {")
	fmt.Println("    message   string")
	fmt.Println("    signature string")
	fmt.Println("}{")

	for i, message := range messages {
		// Hash the message with Ethereum prefix
		hash := crypto.Keccak256Hash(
			[]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message))),
			[]byte(message),
		)

		// Sign the hash
		signature, err := crypto.Sign(hash.Bytes(), privateKey)
		if err != nil {
			log.Fatal(err)
		}

		// Transform V from 0/1 to 27/28
		signature[64] += 27

		fmt.Printf("    {\n")
		fmt.Printf("        message: `%s`,\n", message)
		fmt.Printf("        signature: \"0x%s\",\n", hex.EncodeToString(signature))
		fmt.Printf("    },\n")

		if i == 0 {
			fmt.Printf("    // Address: %s\n", address.Hex())
		}
	}

	fmt.Println("}")
}
