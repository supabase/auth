package redirecturi

import (
	"net"
	"net/url"
	"regexp"

	"github.com/sirupsen/logrus"
)

var decimalIPAddressPattern = regexp.MustCompile("^[0-9]+$")

// Note: RedirectPattern and RedirectConfig types are defined in patterns.go

// IsValidRedirectURL validates a redirect URL with comprehensive security checks and pattern matching
func IsValidRedirectURL(redirectConfig *RedirectConfig, redirectURL, siteURL string) bool {
	if redirectURL == "" {
		return false
	}

	// Parse the redirect URL for validation
	refurl, rerr := url.Parse(redirectURL)
	if rerr != nil {
		// redirect URL is invalid
		return false
	}

	// Security checks first
	if decimalIPAddressPattern.MatchString(refurl.Hostname()) {
		// IP address in decimal form not allowed in redirects
		return false
	} else if ip := net.ParseIP(refurl.Hostname()); ip != nil {
		// Only allow loopback IPs
		return ip.IsLoopback()
	}

	// Site URL check for backward compatibility
	// Keep explicit siteURL check as users may use `http://...`
	// and it doesn't fit to domain-only pattern matching
	if siteURL != "" {
		base, berr := url.Parse(siteURL)
		if berr == nil && base.Hostname() == refurl.Hostname() {
			return true
		}
	}

	// Check against configured patterns
	if redirectConfig == nil || len(redirectConfig.Patterns) == 0 {
		return false
	}

	for _, pattern := range redirectConfig.Patterns {
		if pattern.GlobPattern.Match(redirectURL) {
			return true
		}
	}

	return false
}

// RunShadowModeTest compares old vs new validation logic and logs mismatches
// TODO(cemal) :: This will be enabled in a future release
// to allow for gradual migration and testing of the new validation logic.
func RunShadowModeTest(redirectConfig *RedirectConfig, redirectURL, siteURL string, originalResult bool) {
	if redirectConfig == nil {
		return // No patterns configured
	}

	// Test new validator using the unified function
	newResult := IsValidRedirectURL(redirectConfig, redirectURL, siteURL)

	// Log mismatch if results differ
	if originalResult != newResult {
		logrus.WithFields(logrus.Fields{
			"redirect_url": redirectURL,
			"old_result":   originalResult,
			"new_result":   newResult,
		}).Warn("Redirect URI validation mismatch")
	}
}
