package models

import (
	"database/sql"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"time"
)

const challengeTokenExpirationDuration = 30 * time.Minute

var AlgorithmNotSupportedError = errors.New("Provided algorithm is not supported")
var WrongEthAddressFormatError = errors.New("Provided key cannot be ETH address")
var WrongSignatureFormatError = errors.New("Provided signature has wrong format")
var WrongPublicKeyError = errors.New("Provided signature does not match with Key")

// RefreshToken is the database model for refresh tokens.
type AsymmetricKey struct {
	ID        int64     `db:"id"`
	UserID    uuid.UUID `db:"user_id"`
	Key       string    `db:"key"`
	Algorithm string    `db:"algorithm"`
	Main      bool      `db:"main"`

	ChallengeToken          uuid.UUID `db:"challenge_token"`
	ChallengeTokenIssuedAt  time.Time `db:"challenge_token_issued_at"`
	ChallengeTokenExpiresAt time.Time `db:"challenge_token_expires_at"`
	ChallengePassed         bool      `db:"challenge_passed"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (AsymmetricKey) TableName() string {
	tableName := "asymmetric_keys"
	return tableName
}

func NewAsymmetricKey(userId uuid.UUID, pubkey, algorithm string, main bool) (*AsymmetricKey, error) {
	err := VerifyKeyAndAlgorithm(pubkey, algorithm)
	if err != nil {
		return nil, err
	}

	k := &AsymmetricKey{
		UserID:    userId,
		Key:       pubkey,
		Algorithm: algorithm,
		Main:      main,
	}

	k.generateChallengeToken()
	return k, nil
}

func (a *AsymmetricKey) IsChallengeTokenExpired() bool {
	return time.Now().Unix() >= a.ChallengeTokenExpiresAt.Unix() || a.ChallengePassed
}

func (a *AsymmetricKey) GetChallengeToken(tx *storage.Connection) (uuid.UUID, error) {
	if a.IsChallengeTokenExpired() {
		err := a.generateChallengeToken()
		if err != nil {
			return uuid.Nil, err
		}

		err = tx.UpdateOnly(
			a,
			"challenge_token",
			"challenge_token_issued_at",
			"challenge_token_expires_at",
			"challenge_passed")

		if err != nil {
			return uuid.Nil, err
		}
	}

	return a.ChallengeToken, nil
}

func (a *AsymmetricKey) generateChallengeToken() error {
	newToken, err := uuid.NewV4()
	if err != nil {
		return err
	}

	a.ChallengeToken = newToken
	a.ChallengeTokenIssuedAt = time.Now()
	a.ChallengeTokenExpiresAt = time.Now().Add(challengeTokenExpirationDuration)
	a.ChallengePassed = false

	return nil
}

func (a *AsymmetricKey) VerifySignature(signature string) error {
	var err error
	switch a.Algorithm {
	case "ETH":
		err = a.verifyEthKeySignature(signature)
	default:
		return AlgorithmNotSupportedError
	}

	if err == nil {
		a.ChallengePassed = true
	}
	return err
}

func (a *AsymmetricKey) verifyEthKeySignature(rawSignature string) error {
	signature, err := hexutil.Decode(rawSignature)
	if err != nil {
		return err
	}

	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	// Note, the signature must conform to the secp256k1 curve R, S and V values, where
	// the V value must be be 27 or 28 for legacy reasons.
	if signature[64] != 27 && signature[64] != 28 {
		return WrongSignatureFormatError
	}
	signature[64] -= 27

	signaturePublicKey, err := crypto.SigToPub(SignEthMessageHash([]byte(a.ChallengeToken.String())), signature)
	if err != nil {
		return err
	}

	addr := crypto.PubkeyToAddress(*signaturePublicKey)
	if addr.String() != a.Key {
		return WrongPublicKeyError
	}

	return nil
}

// verifyKeyAndAlgorithm verifies public key format for specific algorithm.
// If key satisfies conditions, nil is returned
func VerifyKeyAndAlgorithm(pubkey, algorithm string) error {
	var err error
	switch algorithm {
	case "ETH":
		err = verifyEthKey(pubkey)
	default:
		return AlgorithmNotSupportedError
	}
	return err
}

func verifyEthKey(key string) error {
	if common.IsHexAddress(key) {
		return nil
	}
	return WrongEthAddressFormatError
}

// SignEthMessageHash is a helper function that calculates a hash for the given message in the Ethereum format
// The hash is calculated as
//   keccak256("\x19Ethereum Signed Message:\n"${message length}${message}).
func SignEthMessageHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}

// FindMainAsymmetricKeyByUser is the helper function that finds the main( used for sign up) Asymmetric key for the given User.
func FindMainAsymmetricKeyByUser(tx *storage.Connection, user *User) (*AsymmetricKey, error) {
	key := &AsymmetricKey{}
	if err := tx.Q().Where("user_id = ? and main = true", user.ID).First(key); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return &AsymmetricKey{}, nil
		}
		return &AsymmetricKey{}, errors.Wrap(err, "error finding keys")
	}
	return key, nil
}
