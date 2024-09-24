package utilities

import (
	"crypto/rand"
	"math/big"
	"strings"
)

func GeneratePassword(requiredChars []string, length int) (string, error) {
	passwordBuilder := strings.Builder{}
	passwordBuilder.Grow(length)

	// Add required characters
	for _, group := range requiredChars {
		if len(group) > 0 {
			randomIndex, err := secureRandomInt(len(group))
			if err != nil {
				return "", err
			}
			passwordBuilder.WriteByte(group[randomIndex])
		}
	}

	// Define a default character set for random generation (if needed)
	const allChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// Fill the rest of the password
	for passwordBuilder.Len() < length {
		randomIndex, err := secureRandomInt(len(allChars))
		if err != nil {
			return "", err
		}
		passwordBuilder.WriteByte(allChars[randomIndex])
	}

	// Convert to byte slice for shuffling
	passwordBytes := []byte(passwordBuilder.String())

	// Secure shuffling
	for i := len(passwordBytes) - 1; i > 0; i-- {
		j, err := secureRandomInt(i + 1)
		if err != nil {
			return "", err
		}
		passwordBytes[i], passwordBytes[j] = passwordBytes[j], passwordBytes[i]
	}

	return string(passwordBytes), nil
}

func secureRandomInt(max int) (int, error) {
	randomInt, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(randomInt.Int64()), nil
}
