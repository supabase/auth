package mailer

import (
	"context"
	"errors"
	"net"
	"net/mail"
	"strings"
	"time"
)

var invalidEmailMap = map[string]bool{
	"test@gmail.com": true,
	"test@test.com":  true,
	"test@email.com": true,
}

// https://www.rfc-editor.org/rfc/rfc2606
var invalidHostMap = map[string]bool{
	"test":        true,
	"example":     true,
	"invalid":     true,
	"example.com": true,
	"example.net": true,
	"example.org": true,
}

const (
	validateEmailTimeout = 250 * time.Millisecond
)

var (
	// We use the default resolver for this.
	validateEmailResolver net.Resolver
)

var (
	ErrInvalidEmailFormat  = errors.New("invalid email format")
	ErrInvalidEmailAddress = errors.New("invalid email address")
)

// ValidateEmail returns a nil error in all cases but the following:
// - `email` cannot be parsed by mail.ParseAddress
// - `email` has a domain with no DNS configured
func ValidateEmail(ctx context.Context, email string) error {
	ctx, cancel := context.WithTimeout(ctx, validateEmailTimeout)
	defer cancel()

	return validateEmail(ctx, email)
}

func validateEmail(ctx context.Context, email string) error {
	ea, err := mail.ParseAddress(email)
	if err != nil {
		return ErrInvalidEmailFormat
	}

	i := strings.LastIndex(ea.Address, "@")
	if i == -1 {
		return ErrInvalidEmailFormat
	}

	// few static lookups that are typed constantly and known to be invalid.
	if invalidEmailMap[email] {
		return ErrInvalidEmailAddress
	}

	host := email[i+1:]
	if invalidHostMap[host] {
		return ErrInvalidEmailAddress
	}
	return validateHostMX(ctx, host)
}

func validateHostMX(ctx context.Context, host string) error {
	_, err := validateEmailResolver.LookupMX(ctx, host)
	if err == nil {
		// We had no err, so we treat it as valid. We don't check the mx records
		// because RFC 5321 specifies that if an empty list of MX's are returned
		// the host should be treated as the MX[1].
		//
		// [1] https://www.rfc-editor.org/rfc/rfc5321.html#section-5.1
		return nil
	}

	// No names present, we will try to get a positive assertion that the
	// domain is not configured to receive email.
	var dnsError *net.DNSError
	if !errors.As(err, &dnsError) {
		// We will be unable to determine with absolute certainy the email was
		// invalid so we will err on the side of caution and return nil.
		return nil
	}

	// The type of err is dnsError, inspect it to see if we can be certain
	// the domain has no mx records currently. For this we require that
	// the error was not temporary or a timeout. If those are both false
	// we trust the value in IsNotFound.
	//
	// TODO(cstockton): I think that in this case, I need to then lookup the
	// host to ensure I'm following the section above. I think that if the
	// mx record list is empty Go will set IsNotFound here.
	if !dnsError.IsTemporary && !dnsError.IsTimeout && dnsError.IsNotFound {
		return ErrInvalidEmailAddress
	}
	return nil
}
