package utilities

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

func parseGroups(requiredChars string) []string {
	var groups []string
	var currentGroup strings.Builder
	inEscape := false

	for _, ch := range requiredChars {
		if inEscape {
			if ch == ':' {
				currentGroup.WriteRune(ch)
				inEscape = false
			} else {
				currentGroup.WriteRune('\\')
				currentGroup.WriteRune(ch)
				inEscape = false
			}
		} else if ch == '\\' {
			inEscape = true
		} else if ch == ':' {
			groups = append(groups, currentGroup.String())
			currentGroup.Reset()
		} else {
			currentGroup.WriteRune(ch)
		}
	}

	if currentGroup.Len() > 0 {
		groups = append(groups, currentGroup.String())
	}

	return groups
}

func generatePassword(requiredChars string, length int) string {
	rand.Seed(time.Now().UnixNano())

	groups := parseGroups(requiredChars)
	passwordBuilder := strings.Builder{}

	for _, group := range groups {
		if len(group) > 0 {
			passwordBuilder.WriteString(string(group[rand.Intn(len(group))]))
		}
	}

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