package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	standardwebhooks "github.com/standard-webhooks/standard-webhooks/libraries/go"

	"github.com/pkg/errors"
)

// SecureToken creates a new random token
func SecureToken(options ...int) string {
	length := 16
	if len(options) > 0 {
		length = options[0]
	}
	b := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err.Error()) // rand should never fail
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// GenerateOtp generates a random n digit otp
func GenerateOtp(digits int) (string, error) {
	upper := math.Pow10(digits)
	val, err := rand.Int(rand.Reader, big.NewInt(int64(upper)))
	if err != nil {
		return "", errors.WithMessage(err, "Error generating otp")
	}
	// adds a variable zero-padding to the left to ensure otp is uniformly random
	expr := "%0" + strconv.Itoa(digits) + "v"
	otp := fmt.Sprintf(expr, val.String())
	return otp, nil
}
func GenerateTokenHash(emailOrPhone, otp string) string {
	return fmt.Sprintf("%x", sha256.Sum224([]byte(emailOrPhone+otp)))
}

func GenerateSignatures(secrets []string, msgID uuid.UUID, currentTime time.Time, inputPayload []byte) ([]string, error) {
	SymmetricSignaturePrefix := "v1,"
	// TODO(joel): Handle asymmetric case once library has been upgraded
	var signatureList []string
	for _, secret := range secrets {
		if strings.HasPrefix(secret, SymmetricSignaturePrefix) {
			trimmedSecret := strings.TrimPrefix(secret, SymmetricSignaturePrefix)
			wh, err := standardwebhooks.NewWebhook(trimmedSecret)
			if err != nil {
				return nil, err
			}
			signature, err := wh.Sign(msgID.String(), currentTime, inputPayload)
			if err != nil {
				return nil, err
			}
			signatureList = append(signatureList, signature)
		} else {
			return nil, errors.New("invalid signature format")
		}
	}
	return signatureList, nil
}
