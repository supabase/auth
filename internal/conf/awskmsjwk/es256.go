package awskmsjwk

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v5"
)

type KMSAPI interface {
	Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

type ES256Key struct {
	Client KMSAPI
	KeyID  string
	Raw    any
	Ctx    context.Context
}

type signingMethodKMSES256 struct{}

var SigningMethodES256KMS jwt.SigningMethod = &signingMethodKMSES256{}

func (m *signingMethodKMSES256) Alg() string {
	return jwt.SigningMethodES256.Alg() // "ES256"
}

func (m *signingMethodKMSES256) Sign(signingString string, key any) ([]byte, error) {
	k, ok := key.(*ES256Key)
	if !ok {
		return nil, errors.New("kmsjwt: key must be *ES256Key")
	}
	if k.Client == nil {
		return nil, errors.New("kmsjwt: nil KMS client")
	}
	if k.KeyID == "" {
		return nil, errors.New("kmsjwt: empty KMS key ID")
	}

	ctx := k.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// JWT ES256 signs SHA256(base64url(header) + "." + base64url(payload)).
	// Use DIGEST so large JWTs do not hit KMS RAW message size limits.
	digest := sha256.Sum256([]byte(signingString))

	out, err := k.Client.Sign(ctx, &kms.SignInput{
		KeyId:            &k.KeyID,
		Message:          digest[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, err
	}

	return derECDSAToJWT(out.Signature, 32)
}

func (m *signingMethodKMSES256) Verify(signingString string, sig []byte, key any) error {
	k, ok := key.(*ES256Key)
	if !ok {
		return nil, errors.New("kmsjwt: key must be *ES256Key")
	}

	return jwt.SigningMethodES256.Verify(signingString, sig, k.Raw)
}

type ecdsaDER struct {
	R, S *big.Int
}

func derECDSAToJWT(der []byte, size int) ([]byte, error) {
	var parsed ecdsaDER
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		return nil, err
	}
	if parsed.R == nil || parsed.S == nil {
		return nil, errors.New("kmsjwt: invalid ECDSA signature")
	}

	r := parsed.R.Bytes()
	s := parsed.S.Bytes()

	if len(r) > size || len(s) > size {
		return nil, errors.New("kmsjwt: ECDSA signature component too large")
	}

	out := make([]byte, size*2)
	copy(out[size-len(r):size], r)
	copy(out[size*2-len(s):], s)

	return out, nil
}
