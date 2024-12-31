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

	for _, example := range examples {
		assert.Error(t, CompareHashAndPassword(context.Background(), example, "test1"))
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

type scryptTestCase struct {
	name       string
	hash       string
	password   string
	shouldPass bool
}

func TestScrypt(t *testing.T) {
	testCases := []scryptTestCase{
		{
			name:       "Firebase Scrypt: appropriate hash",
			hash:       "$fbscrypt$v=1,n=14,r=8,p=1,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$zKVTMvnWVw5BBOZNUdnsalx4c4c7y/w7IS5p6Ut2+CfEFFlz37J9huyQfov4iizN8dbjvEJlM5tQaJP84+hfTw==",
			password:   "mytestpassword",
			shouldPass: true,
		},
		{
			name:       "Firebase Scrypt: incorrect hash",
			hash:       "$fbscrypt$v=1,n=14,r=8,p=1,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$ZGlmZmVyZW50aGFzaA==",
			password:   "mytestpassword",
			shouldPass: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := CompareHashAndPassword(context.Background(), tc.hash, tc.password)
			if tc.shouldPass {
				assert.NoError(t, err, "Expected test case to pass, but it failed")
			} else {
				assert.Error(t, err, "Expected test case to fail, but it passed")
			}
		})
	}
}

type bcryptTestCase struct {
	name       string
	hash       string
	password   string
	shouldPass bool
}

func TestBcrypt(t *testing.T) {
	testCases := []bcryptTestCase{
		{
			name:       "Valid bcrypt hash, valid password",
			hash:       "$2a$10$vVz26aE3xkpSS9HFgafcH.M0Ina2tRm.Kp08WcVfjipXccGakj6i.",
			password:   "test",
			shouldPass: true,
		},
		{
			name:       "Invalid bycrypt hash format",
			hash:       "x2a$10$vVz26aE3xkpSS9HFgafcH.M0Ina2tRm.Kp08WcVfjipXccGakj6i.",
			password:   "test",
			shouldPass: false,
		},
		{
			name:       "Invalid bycrypt hash rounds, negative",
			hash:       "$2a$-1$vVz26aE3xkpSS9HFgafcH.M0Ina2tRm.Kp08WcVfjipXccGakj6i.",
			password:   "test",
			shouldPass: false,
		},
		{
			name:       "Invalid bycrypt hash rounds",
			hash:       "$2a$2000$vVz26aE3xkpSS9HFgafcH.M0Ina2tRm.Kp08WcVfjipXccGakj6i.",
			password:   "test",
			shouldPass: false,
		},
		{
			name:       "Valid bcrypt hash, invalid password",
			hash:       "$2a$10$vVz26aE3xkpSS9HFgafcH.M0Ina2tRm.Kp08WcVfjipXccGakj6i.",
			password:   "test_Password",
			shouldPass: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := CompareHashAndPassword(context.Background(), tc.hash, tc.password)
			if tc.shouldPass {
				assert.NoError(t, err, "Expected test case to pass, but it failed")
			} else {
				assert.Error(t, err, "Expected test case to fail, but it passed")
			}
		})
	}
}

func TestBcryptHashGeneration(t *testing.T) {
	plainText := "testPassword"
	ctx := context.Background()

	hashedPassword, e := GenerateFromPassword(ctx, plainText)
	assert.NoError(t, e, "No error was expected")
	assert.NotNil(t, hashedPassword)

	err := CompareHashAndPassword(context.Background(), hashedPassword, plainText)
	assert.NoError(t, err, "Expected hashedPassword to be valid")

	// validate hash is unique each time
	newHashedPassword, _ := GenerateFromPassword(ctx, plainText)
	assert.NotEqual(t, hashedPassword, newHashedPassword)
}
