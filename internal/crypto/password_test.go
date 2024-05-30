package crypto

import (
	"context"
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
