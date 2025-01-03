package crypto

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type argonTestCase struct {
	name        string
	hash        string
	password    string
	shouldPass  bool
	expectedErr string
}

func TestArgon2(t *testing.T) {
	testCases := []argonTestCase{
		{
			name:       "Argon2: valid hash",
			hash:       "$argon2i$v=19$m=16,t=2,p=1$bGJRWThNOHJJTVBSdHl2dQ$NfEnUOuUpb7F2fQkgFUG4g",
			password:   "test",
			shouldPass: true,
		},
		{
			name:       "Argon2: valid hash2",
			hash:       "$argon2id$v=19$m=32,t=3,p=2$SFVpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk",
			password:   "test",
			shouldPass: true,
		},
		{
			name:        "Argon2: valid hash, wrong plaintext",
			hash:        "$argon2id$v=19$m=32,t=3,p=2$SFVpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk",
			password:    "test1",
			shouldPass:  false,
			expectedErr: "crypto: argon2 hash and password mismatch",
		},
		{
			name:        "Argon2: unsupported algorith",
			hash:        "$argon2d$v=19$m=32,t=3,p=2$SFVpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk",
			password:    "test1",
			shouldPass:  false,
			expectedErr: "crypto: argon2 hash uses unsupported algorithm \"argon2d\" only argon2i and argon2id supported",
		},
		{
			name:        "Argon2: invalid hash alg",
			hash:        "$argon2ix$v=19$m=32,t=3,p=2$SFVpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk",
			password:    "test1",
			shouldPass:  false,
			expectedErr: "crypto: incorrect argon2 hash format",
		},
		{
			name:        "Argon2: invalid hash v",
			hash:        "$argon2id$v=16$m=32,t=3,p=2$SFVpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk",
			password:    "test1",
			shouldPass:  false,
			expectedErr: "crypto: argon2 hash uses unsupported version \"16\" only 19 is supported",
		},
		{
			name:        "Argon2: invalid hash keyid",
			hash:        "$argon2id$v=19$m=32,t=3,p=2,keyid=1$SFVpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk",
			password:    "test1",
			shouldPass:  false,
			expectedErr: "crypto: argon2 hashes with the keyid parameter not supported",
		},
		{
			name:        "Argon2: invalid hash data",
			hash:        "$argon2id$v=19$m=32,t=3,p=2,data=1$SFVpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk",
			password:    "test1",
			shouldPass:  false,
			expectedErr: "crypto: argon2 hashes with the data parameter not supported",
		},
		{
			name:        "Argon2: invalid hash memory",
			hash:        "$argon2id$v=19$m=4294967296,t=3,p=2$SFVpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk",
			password:    "test",
			shouldPass:  false,
			expectedErr: "crypto: argon2 hash has invalid m parameter \"4294967296\" strconv.ParseUint: parsing \"4294967296\": value out of range",
		},
		{
			name:        "Argon2: invalid hash time",
			hash:        "$argon2id$v=19$m=32,t=4294967296,p=2$SFVpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk",
			password:    "test",
			shouldPass:  false,
			expectedErr: "crypto: argon2 hash has invalid t parameter \"4294967296\" strconv.ParseUint: parsing \"4294967296\": value out of range",
		},
		{
			name:        "Argon2: invalid hash p",
			hash:        "$argon2id$v=19$m=32,t=3,p=4294967296$SFVpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk",
			password:    "test",
			shouldPass:  false,
			expectedErr: "crypto: argon2 hash has invalid p parameter \"4294967296\" strconv.ParseUint: parsing \"4294967296\": value out of range",
		},
		{
			name:        "Argon2: invalid hash, bad saltB64",
			hash:        "$argon2id$v=19$m=32,t=3,p=2$S!VpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk",
			password:    "test",
			shouldPass:  false,
			expectedErr: "crypto: argon2 hash has invalid base64 in the salt section illegal base64 data at input byte 1",
		},
		{
			name:        "Argon2: invalid hash, bad hashB64",
			hash:        "$argon2id$v=19$m=32,t=3,p=2$SFVpOWJ0eXhjRzVkdGN1RQ$-Xnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk",
			password:    "test",
			shouldPass:  false,
			expectedErr: "crypto: argon2 hash has invalid base64 in the hash section illegal base64 data at input byte 0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := CompareHashAndPassword(context.Background(), tc.hash, tc.password)
			if tc.shouldPass {
				assert.NoError(t, err, "Expected test case to pass, but it failed")
			} else {
				assert.Error(t, err, "Expected test case to fail, but it passed")
				if tc.expectedErr != "" {
					assert.Equal(t, tc.expectedErr, err.Error(), "Expected error doesn't match")
				}
			}
		})
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
	name        string
	hash        string
	password    string
	shouldPass  bool
	expectedErr string
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
		{
			name:       "Firebase Scrypt: mismatch hash plaintext",
			hash:       "$fbscrypt$v=1,n=14,r=8,p=1,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$zKVTMvnWVw5BBOZNUdnsalx4c4c7y/w7IS5p6Ut2+CfEFFlz37J9huyQfov4iizN8dbjvEJlM5tQaJP84+hfTw==",
			password:   "not_mytestpassword",
			shouldPass: false,
		},
		{
			name:        "Firebase Scrypt: mismatch hash plaintext",
			hash:        "$fbscrypt$v=1,n=14,r=8,p=1,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$zKVTMvnWVw5BBOZNUdnsalx4c4c7y/w7IS5p6Ut2+CfEFFlz37J9huyQfov4iizN8dbjvEJlM5tQaJP84+hfTw==",
			password:    "not_mytestpassword",
			shouldPass:  false,
			expectedErr: "crypto: fbscrypt hash and password mismatch",
		},
		{
			name:        "Firebase Scrypt: bad hash version",
			hash:        "$fbscrypt$v=2,n=14,r=8,p=1,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$zKVTMvnWVw5BBOZNUdnsalx4c4c7y/w7IS5p6Ut2+CfEFFlz37J9huyQfov4iizN8dbjvEJlM5tQaJP84+hfTw==",
			password:    "mytestpassword",
			shouldPass:  false,
			expectedErr: "crypto: Firebase scrypt hash uses unsupported version \"2\" only version 1 is supported",
		},
		{
			name:        "Firebase Scrypt: bad hash",
			hash:        "$fbscrypts$v=1,n=14,r=8,p=1,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$zKVTMvnWVw5BBOZNUdnsalx4c4c7y/w7IS5p6Ut2+CfEFFlz37J9huyQfov4iizN8dbjvEJlM5tQaJP84+hfTw==",
			password:    "mytestpassword",
			shouldPass:  false,
			expectedErr: "crypto: incorrect scrypt hash format",
		},
		{
			name:        "Firebase Scrypt: bad n",
			hash:        "$fbscrypt$v=1,n=4294967296,r=8,p=1,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$zKVTMvnWVw5BBOZNUdnsalx4c4c7y/w7IS5p6Ut2+CfEFFlz37J9huyQfov4iizN8dbjvEJlM5tQaJP84+hfTw==",
			password:    "mytestpassword",
			shouldPass:  false,
			expectedErr: "crypto: Firebase scrypt hash has invalid n parameter \"4294967296\" strconv.ParseUint: parsing \"4294967296\": value out of range",
		},
		{
			name:        "Firebase Scrypt: zero n",
			hash:        "$fbscrypt$v=1,n=0,r=8,p=1,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$zKVTMvnWVw5BBOZNUdnsalx4c4c7y/w7IS5p6Ut2+CfEFFlz37J9huyQfov4iizN8dbjvEJlM5tQaJP84+hfTw==",
			password:    "mytestpassword",
			shouldPass:  false,
			expectedErr: "crypto: Firebase scrypt hash has invalid n parameter \"0\": must be greater than 0",
		},
		{
			name:        "Firebase Scrypt: bad rounds",
			hash:        "$fbscrypt$v=1,n=14,r=18446744073709551616,p=1,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$zKVTMvnWVw5BBOZNUdnsalx4c4c7y/w7IS5p6Ut2+CfEFFlz37J9huyQfov4iizN8dbjvEJlM5tQaJP84+hfTw==",
			password:    "mytestpassword",
			shouldPass:  false,
			expectedErr: "crypto: Firebase scrypt hash has invalid r parameter \"18446744073709551616\": strconv.ParseUint: parsing \"18446744073709551616\": value out of range",
		},
		{
			name:        "Firebase Scrypt: bad threads - wrap around",
			hash:        "$fbscrypt$v=1,n=14,r=8,p=256,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$zKVTMvnWVw5BBOZNUdnsalx4c4c7y/w7IS5p6Ut2+CfEFFlz37J9huyQfov4iizN8dbjvEJlM5tQaJP84+hfTw==",
			password:    "mytestpassword",
			shouldPass:  false,
			expectedErr: "crypto: Firebase scrypt hash has invalid p parameter \"256\" strconv.ParseUint: parsing \"256\": value out of range",
		},
		{
			name:        "Firebase Scrypt: bad hash",
			hash:        "$fbscrypt$v=1,n=14,r=8,p=1,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$!KVTMvnWVw5BBOZNUdnsalx4c4c7y/w7IS5p6Ut2+CfEFFlz37J9huyQfov4iizN8dbjvEJlM5tQaJP84+hfTw==",
			password:    "mytestpassword",
			shouldPass:  false,
			expectedErr: "crypto: Firebase scrypt hash has invalid base64 in the hash section illegal base64 data at input byte 0",
		},
		{
			name:        "Firebase Scrypt: bad salt",
			hash:        "$fbscrypt$v=1,n=14,r=8,p=1,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$!0sHCg9ek77hsg==$zKVTMvnWVw5BBOZNUdnsalx4c4c7y/w7IS5p6Ut2+CfEFFlz37J9huyQfov4iizN8dbjvEJlM5tQaJP84+hfTw==",
			password:    "mytestpassword",
			shouldPass:  false,
			expectedErr: "crypto: Firebase scrypt salt has invalid base64 in the hash section illegal base64 data at input byte 0",
		},
		{
			name:        "Firebase Scrypt: bad ss",
			hash:        "$fbscrypt$v=1,n=14,r=8,p=1,ss=B!w==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$zKVTMvnWVw5BBOZNUdnsalx4c4c7y/w7IS5p6Ut2+CfEFFlz37J9huyQfov4iizN8dbjvEJlM5tQaJP84+hfTw==",
			password:    "mytestpassword",
			shouldPass:  false,
			expectedErr: "illegal base64 data at input byte 1",
		},
		{
			name:        "Firebase Scrypt: bad sk",
			hash:        "$fbscrypt$v=1,n=14,r=8,p=1,ss=Bw==,sk=!ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$zKVTMvnWVw5BBOZNUdnsalx4c4c7y/w7IS5p6Ut2+CfEFFlz37J9huyQfov4iizN8dbjvEJlM5tQaJP84+hfTw==",
			password:    "mytestpassword",
			shouldPass:  false,
			expectedErr: "illegal base64 data at input byte 0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := CompareHashAndPassword(context.Background(), tc.hash, tc.password)
			if tc.shouldPass {
				assert.NoError(t, err, "Expected test case to pass, but it failed")
			} else {
				assert.Error(t, err, "Expected test case to fail, but it passed")
				if tc.expectedErr != "" {
					assert.Equal(t, tc.expectedErr, err.Error(), "Expected error doesn't match")
				}
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

	// validate bcrypt format -- https://passlib.readthedocs.io/en/stable/lib/passlib.hash.bcrypt.html#format-algorithm
	bcryptRegex, _ := regexp.Compile(`^\$(?P<alg>2[abxy])\$(?P<rounds>[0-9]{1,})\$(?P<salt>[./A-Za-z0-9]{21}[.Oeu]{1})(?P<checksum>[./A-Za-z0-9]{31})$`)
	match := bcryptRegex.MatchString(hashedPassword)
	assert.Equal(t, match, true, "Produced hash not valid bcrypt format")

	// validate hash resolves to plainText
	err := CompareHashAndPassword(context.Background(), hashedPassword, plainText)
	assert.NoError(t, err, "Expected hashedPassword to be valid")

	// validate hash is unique each time
	newHashedPassword, _ := GenerateFromPassword(ctx, plainText)
	assert.NotEqual(t, hashedPassword, newHashedPassword)

	// validate password truncation causes error (passwords longer than 72 chars)
	// this is technically testing the bcrypt libary but make sure we are erroring because it
	// very much matters in the context of this package
	longPassword := strings.Repeat("A", 73)
	_, e = GenerateFromPassword(ctx, longPassword)
	assert.Error(t, e, "Password longer than 72 chars did not error")
}
