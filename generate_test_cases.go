package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	// Check if message is provided as argument
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: go run generate_test_cases.go \"Your message here\"")
		os.Exit(1)
	}

	// Generate a new private key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// get the address
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	// Get the message from command line
	// Replace literal \n with actual newlines
	messageTemplate := strings.ReplaceAll(os.Args[1], "\\n", "\n")
	message := fmt.Sprintf(messageTemplate, address.Hex())

	// Hash the message with Ethereum prefix using the same method as accounts.TextHash
	hash := accounts.TextHash([]byte(message))

	// Sign the hash
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Transform V from 0/1 to 27/28
	signature[64] += 27

	// Output as {message, signature} format - escape the message for JSON
	escapedMessage := strings.ReplaceAll(message, "\n", "\\n")
	fmt.Printf("{message: \"%s\",\nsignature: \"0x%s\"}\n", escapedMessage, hex.EncodeToString(signature))
}
