package sbff

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
)

var (
	ctxKeySBFF     = &struct{}{}
	HeaderNameSBFF = "sb-forwarded-for"

	ErrHeaderNotFound = errors.New("Sb-Forwarded-For header not found")
	ErrHeaderInvalid  = errors.New("invalid Sb-Forwarded-For header value")
)

func parseSBFFHeader(headerVal string) (string, error) {
	values := strings.SplitN(headerVal, ",", 2)

	key := strings.TrimSpace(values[0])

	if ipAddr := net.ParseIP(key); ipAddr != nil {
		return ipAddr.String(), nil
	}

	return "", ErrHeaderInvalid
}

// GetSBForwardedForAddress returns the value of the IP address in Sb-Forwarded-For as defined by
// SBForwardedForMiddleware. If no value is present in the request context, this function will
// return ("", false).
func GetSBForwardedForAddress(r *http.Request) (addr string, found bool) {
	value := r.Context().Value(ctxKeySBFF)

	if value == nil {
		return "", false
	}

	ipAddr, ok := value.(string)

	return ipAddr, ok
}

// SetSBForwardedForAddress parses the Sb-Forwarded-For header and adds the leftmost value to the
// request context if it is a valid IP address, then returns a new request with modified context.
// If the leftmost value is not a valid IP address or the header is not set, this function returns
// an error.
func ParseSBForwardedForAddress(r *http.Request) (*http.Request, error) {
	ctx := r.Context()
	headerVal := r.Header.Get(HeaderNameSBFF)

	if headerVal == "" {
		return nil, ErrHeaderNotFound
	}

	parsedIPAddr, err := parseSBFFHeader(headerVal)

	if err != nil {
		return nil, err
	}

	newCtx := context.WithValue(ctx, ctxKeySBFF, parsedIPAddr)
	out := r.WithContext(newCtx)

	return out, nil
}
