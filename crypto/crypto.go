package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"

	"github.com/pkg/errors"
)

// SecureToken creates a new random token
func SecureToken() string {
	b := make([]byte, 16)
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

// GenerateOtpFromCharset generates a random n-length otp from a charset
func GenerateOtpFromCharset(length int, charset string) (string, error) {
	b := make([]byte, length)
	for i := range b {
		val, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", errors.WithMessage(err, "Error generating otp from charset")
		}
		b[i] = charset[val.Int64()]
	}
	return string(b), nil
}

// GenerateEmailOtp generates a random n-length alphanumeric otp
func GenerateEmailOtp(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	return GenerateOtpFromCharset(length, charset)
}
