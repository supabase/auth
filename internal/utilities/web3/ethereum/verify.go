package ethereum

import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func VerifySignature(message string, signature string, address string) error {
	// Remove 0x prefix if present
	signature = removeHexPrefix(signature)
	address = removeHexPrefix(address)

	// Convert signature hex to bytes
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	// Adjust V value in signature (Ethereum specific)
	if len(sigBytes) != 65 {
		return fmt.Errorf("invalid signature length")
	}
	if sigBytes[64] < 27 {
		sigBytes[64] += 27
	}

	// Hash the message according to EIP-191
	prefixedMessage := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := crypto.Keccak256Hash([]byte(prefixedMessage))

	// Recover public key from signature
	pubKey, err := crypto.SigToPub(hash.Bytes(), sigBytes)
	if err != nil {
		return fmt.Errorf("error recovering public key: %w", err)
	}

	// Derive Ethereum address from public key
	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	checkAddr := common.HexToAddress(address)

	// Compare addresses
	if recoveredAddr != checkAddr {
		return fmt.Errorf("signature not from expected address")
	}

	return nil
}

func removeHexPrefix(s string) string {
	if len(s) > 2 && s[0:2] == "0x" {
		return s[2:]
	}
	return s
}
