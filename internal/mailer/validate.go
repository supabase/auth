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

	// People type these often enough to be special cased.
	"test@gmail.com": true,
	"test@email.com": true,
}

var invalidHostSuffixes = []string{

	// These are a directly from Section 2 of RFC2606[1].
	//
	// [1] https://www.rfc-editor.org/rfc/rfc2606.html#section-2
	".test",
	".example",
	".invalid",
	".local",
	".localhost",
}

var invalidHostMap = map[string]bool{

	// These exist here too for when they are typed as "test@test"
	"test":      true,
	"example":   true,
	"invalid":   true,
	"local":     true,
	"localhost": true,

	// These are commonly typed and have DNS records which cause a
	// large enough volume of bounce backs to special case.
	"test.com":    true,
	"example.com": true,
	"example.net": true,
	"example.org": true,

	// Hundreds of typos per day for this.
	"gamil.com": true,

	// These are not email providers, but people often use them.
	"anonymous.com": true,
	"email.com":     true,
}

const (
	validateEmailTimeout = 500 * time.Millisecond
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

	for i := range invalidHostSuffixes {
		if strings.HasSuffix(host, invalidHostSuffixes[i]) {
			return ErrInvalidEmailAddress
		}
	}

	name := email[:i]
	if err := validateProviders(name, host); err != nil {
		return err
	}

	if err := validateHost(ctx, host); err != nil {
		return err
	}
	return nil
}

func validateProviders(name, host string) error {
	switch host {
	case "gmail.com":
		// Based on a sample of internal data, this reduces the number of
		// bounced emails by 23%. Gmail documentation specifies that the
		// min user name length is 6 characters. There may be some accounts
		// from early gmail beta with shorter email addresses, but I think
		// this reduces bounce rates enough to be worth adding for now.
		if len(name) < 6 {
			return ErrInvalidEmailAddress
		}
	}
	return nil
}

func validateHost(ctx context.Context, host string) error {
	_, err := validateEmailResolver.LookupMX(ctx, host)
	if !isHostNotFound(err) {
		return nil
	}

	_, err = validateEmailResolver.LookupHost(ctx, host)
	if !isHostNotFound(err) {
		return nil
	}

	// No addrs or mx records were found
	return ErrInvalidEmailAddress
}

func isHostNotFound(err error) bool {
	if err == nil {
		// We had no err, so we treat it as valid. We don't check the mx records
		// because RFC 5321 specifies that if an empty list of MX's are returned
		// the host should be treated as the MX[1].
		//
		// See section 2 and 3 of: https://www.rfc-editor.org/rfc/rfc2606
		// [1] https://www.rfc-editor.org/rfc/rfc5321.html#section-5.1
		return false
	}

	// No names present, we will try to get a positive assertion that the
	// domain is not configured to receive email.
	var dnsError *net.DNSError
	if !errors.As(err, &dnsError) {
		// We will be unable to determine with absolute certainy the email was
		// invalid so we will err on the side of caution and return nil.
		return false
	}

	// The type of err is dnsError, inspect it to see if we can be certain
	// the domain has no mx records currently. For this we require that
	// the error was not temporary or a timeout. If those are both false
	// we trust the value in IsNotFound.
	if !dnsError.IsTemporary && !dnsError.IsTimeout && dnsError.IsNotFound {
		return true
	}
	return false
}
