package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"
	siws "github.com/supabase/auth/internal/utilities/web3/solana"
)

func LogSIWSExample() {
	// Configuration
	domain := "localhost:9999"
	statement := "Sign in with your Solana account"
	version := "1"
	chain := "solana:mainnet"

	// Generate keys
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error generating keys:", err)
		return
	}
	pubKeyBase58 := base58.Encode(pubKey)

	// Generate nonce
	nonce, err := siws.GenerateNonce()
	if err != nil {
		fmt.Println("Error generating nonce:", err)
		return
	}

	// Create SIWS message
	msg := siws.SIWSMessage{
		Domain:    domain,
		Address:   pubKeyBase58,
		Statement: statement,
		URI:       "https://example.com",
		Version:   version,
		Nonce:     nonce,
		IssuedAt:  time.Now().UTC(),
	}

	rawMessage := siws.ConstructMessage(msg)

	// Sign the message
	signature := ed25519.Sign(privKey, []byte(rawMessage))
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	// Generate JSON payload
	payload := map[string]string{
		"grant_type": "eip4361",
		"message":    rawMessage,
		"signature":  signatureBase64,
		"address":    pubKeyBase58,
		"chain":      chain,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Error generating payload JSON:", err)
		return
	}

	// Print JavaScript fetch code
	fmt.Println(string(payloadJSON))
}
func main() {
	LogSIWSExample()
}
