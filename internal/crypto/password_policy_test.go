package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestCheckPasswordHashPolicy(t *testing.T) {
	const (
		bcrypt10 = "$2y$10$va66S4MxFrH6G6L7BzYl0.QgcYgvSr/F92gc.3botlz7bG4p/g/1i"
		argon2i  = "$argon2i$v=19$m=16,t=2,p=1$bGJRWThNOHJJTVBSdHl2dQ$NfEnUOuUpb7F2fQkgFUG4g"
		argon2id = "$argon2id$v=19$m=32,t=3,p=2$SFVpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk"
		fbscrypt = "$fbscrypt$v=1,n=14,r=8,p=1,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$zKVTMvnWVw5BBOZNUdnsalx4c4c7y/w7IS5p6Ut2+CfEFFlz37J9huyQfov4iizN8dbjvEJlM5tQaJP84+hfTw=="
	)

	tests := []struct {
		name    string
		hash    string
		policy  *conf.PasswordHashPolicy
		allowed bool
	}{
		{"nil policy", bcrypt10, nil, true},
		{"zero policy", argon2id, &conf.PasswordHashPolicy{}, true},
		{"garbage hash is not rejected here", "garbage", &conf.PasswordHashPolicy{Bcrypt: &conf.BcryptHashPolicy{Disabled: true}}, true},

		{"allowlist: bcrypt not mentioned", bcrypt10, &conf.PasswordHashPolicy{Allowlist: true, Argon2: &conf.Argon2HashPolicy{}}, false},
		{"allowlist: argon2 not mentioned", argon2id, &conf.PasswordHashPolicy{Allowlist: true, Bcrypt: &conf.BcryptHashPolicy{}}, false},
		{"allowlist: argon2 mentioned allows all variants", argon2i, &conf.PasswordHashPolicy{Allowlist: true, Argon2: &conf.Argon2HashPolicy{}}, true},
		{"allowlist: fbscrypt not mentioned", fbscrypt, &conf.PasswordHashPolicy{Allowlist: true, Bcrypt: &conf.BcryptHashPolicy{}}, false},
		{"allowlist: fbscrypt mentioned", fbscrypt, &conf.PasswordHashPolicy{Allowlist: true, FirebaseScrypt: &conf.FirebaseScryptHashPolicy{}}, true},
		{"allowlist: empty allows nothing", bcrypt10, &conf.PasswordHashPolicy{Allowlist: true}, false},
		{"allowlist: mentioned but disabled", bcrypt10, &conf.PasswordHashPolicy{Allowlist: true, Bcrypt: &conf.BcryptHashPolicy{Disabled: true}}, false},
		{"allowlist: mentioned but over limit", bcrypt10, &conf.PasswordHashPolicy{Allowlist: true, Bcrypt: &conf.BcryptHashPolicy{MaxCost: 9}}, false},
		{"no allowlist: unmentioned allowed", bcrypt10, &conf.PasswordHashPolicy{Argon2: &conf.Argon2HashPolicy{}}, true},

		{"bcrypt disabled", bcrypt10, &conf.PasswordHashPolicy{Bcrypt: &conf.BcryptHashPolicy{Disabled: true}}, false},
		{"bcrypt unaffected by others disabled", bcrypt10, &conf.PasswordHashPolicy{Argon2: &conf.Argon2HashPolicy{Disabled: true}}, true},
		{"bcrypt at max cost", bcrypt10, &conf.PasswordHashPolicy{Bcrypt: &conf.BcryptHashPolicy{MaxCost: 10}}, true},
		{"bcrypt above max cost", bcrypt10, &conf.PasswordHashPolicy{Bcrypt: &conf.BcryptHashPolicy{MaxCost: 9}}, false},

		{"argon2 disabled (argon2i)", argon2i, &conf.PasswordHashPolicy{Argon2: &conf.Argon2HashPolicy{Disabled: true}}, false},
		{"argon2 disabled (argon2id)", argon2id, &conf.PasswordHashPolicy{Argon2: &conf.Argon2HashPolicy{Disabled: true}}, false},
		{"argon2 variants: argon2id only rejects argon2i", argon2i, &conf.PasswordHashPolicy{Argon2: &conf.Argon2HashPolicy{Variants: []string{"argon2id"}}}, false},
		{"argon2 variants: argon2id only allows argon2id", argon2id, &conf.PasswordHashPolicy{Argon2: &conf.Argon2HashPolicy{Variants: []string{"argon2id"}}}, true},
		{"argon2 variants: both", argon2i, &conf.PasswordHashPolicy{Argon2: &conf.Argon2HashPolicy{Variants: []string{"argon2i", "argon2id"}}}, true},
		{"argon2 variants omitted allows all", argon2i, &conf.PasswordHashPolicy{Argon2: &conf.Argon2HashPolicy{MaxMemoryKiB: 16}}, true},
		{"argon2 within limits", argon2id, &conf.PasswordHashPolicy{Argon2: &conf.Argon2HashPolicy{MaxMemoryKiB: 32, MaxTime: 3, MaxThreads: 2}}, true},
		{"argon2 memory too high", argon2id, &conf.PasswordHashPolicy{Argon2: &conf.Argon2HashPolicy{MaxMemoryKiB: 31}}, false},
		{"argon2 time too high", argon2id, &conf.PasswordHashPolicy{Argon2: &conf.Argon2HashPolicy{MaxTime: 2}}, false},
		{"argon2 threads too high", argon2id, &conf.PasswordHashPolicy{Argon2: &conf.Argon2HashPolicy{MaxThreads: 1}}, false},
		{"argon2 limits apply to argon2i too", argon2i, &conf.PasswordHashPolicy{Argon2: &conf.Argon2HashPolicy{MaxMemoryKiB: 8}}, false},

		{"fbscrypt disabled", fbscrypt, &conf.PasswordHashPolicy{FirebaseScrypt: &conf.FirebaseScryptHashPolicy{Disabled: true}}, false},
		{"fbscrypt within limits", fbscrypt, &conf.PasswordHashPolicy{FirebaseScrypt: &conf.FirebaseScryptHashPolicy{MaxMemoryCostLog2: 14, MaxRounds: 8, MaxThreads: 1}}, true},
		{"fbscrypt memory too high", fbscrypt, &conf.PasswordHashPolicy{FirebaseScrypt: &conf.FirebaseScryptHashPolicy{MaxMemoryCostLog2: 13}}, false},
		{"fbscrypt rounds too high", fbscrypt, &conf.PasswordHashPolicy{FirebaseScrypt: &conf.FirebaseScryptHashPolicy{MaxRounds: 7}}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPasswordHashPolicy(tc.hash, tc.policy)
			if tc.allowed {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrPasswordHashNotPermitted)
			}
		})
	}
}
