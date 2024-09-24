package crypto

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArgon2(t *testing.T) {
	// all of these hash the `test` string with various parameters

	examples := []string{
		"$argon2i$v=19$m=16,t=2,p=1$bGJRWThNOHJJTVBSdHl2dQ$NfEnUOuUpb7F2fQkgFUG4g",
		"$argon2id$v=19$m=32,t=3,p=2$SFVpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk",
	}

	for _, example := range examples {
		assert.NoError(t, CompareHashAndPassword(context.Background(), example, "test"))
	}
}

func TestGeneratePassword(t *testing.T) {
	tests := []struct {
		name          string
		requiredChars []string
		length        int
		wantErr       bool
	}{
		{
			name:          "Valid password generation",
			requiredChars: []string{"ABC", "123", "@#$"},
			length:        12,
			wantErr:       false,
		},
		{
			name:          "Empty required chars",
			requiredChars: []string{},
			length:        8,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GeneratePassword(tt.requiredChars, tt.length)

			if (err != nil) != tt.wantErr {
				t.Errorf("GeneratePassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != tt.length {
				t.Errorf("GeneratePassword() returned password of length %d, want %d", len(got), tt.length)
			}

			// Check if all required characters are present
			for _, chars := range tt.requiredChars {
				found := false
				for _, c := range got {
					if strings.ContainsRune(chars, c) {
						found = true
						break
					}
				}
				if !found && len(chars) > 0 {
					t.Errorf("GeneratePassword() missing required character from set %s", chars)
				}
			}
		})
	}

	// Check for duplicates passwords
	passwords := make(map[string]bool)
	for i := 0; i < 30; i++ {
		p, err := GeneratePassword([]string{"ABC", "123", "@#$"}, 30)
		if err != nil {
			t.Errorf("GeneratePassword() unexpected error: %v", err)
		}
		if passwords[p] {
			t.Errorf("GeneratePassword() generated duplicate password: %s", p)
		}
		passwords[p] = true
	}
}
