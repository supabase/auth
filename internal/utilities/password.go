package utilities

import (
	"math/rand"
	"strings"
	"time"
)

// parseGroups processes the required character groups from a slice of strings.
func parseGroups(requiredChars []string) []string {
	var groups []string
	groups = append(groups, requiredChars...)
	return groups
}

func GeneratePassword(requiredChars []string, length int) string {

	groups := parseGroups(requiredChars)
	passwordBuilder := strings.Builder{}

	for _, group := range groups {
		if len(group) > 0 {
			passwordBuilder.WriteString(string(group[rand.Intn(len(group))]))
		}
	}

	// Define a default character set for random generation (if needed)
	allChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	for passwordBuilder.Len() < length {
		passwordBuilder.WriteString(string(allChars[rand.Intn(len(allChars))]))
	}

	password := passwordBuilder.String()
	passwordBytes := []byte(password)
	rand.Shuffle(len(passwordBytes), func(i, j int) {
		passwordBytes[i], passwordBytes[j] = passwordBytes[j], passwordBytes[i]
	})

	return string(passwordBytes)
}
