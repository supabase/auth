package redirecturi

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/gobwas/glob"
)

// RedirectPatternType represents the type of redirect pattern
type RedirectPatternType int

const (
	// PatternTypeExact represents an exact URL match
	PatternTypeExact RedirectPatternType = iota
	// PatternTypeDomainOnly represents a domain-only pattern
	PatternTypeDomainOnly
	// PatternTypeSchemeOnly represents a scheme-only pattern
	PatternTypeSchemeOnly
	// PatternTypeWildcard represents a wildcard pattern
	PatternTypeWildcard
)

// String returns the string representation of the RedirectPatternType
func (t RedirectPatternType) String() string {
	switch t {
	case PatternTypeExact:
		return "exact"
	case PatternTypeDomainOnly:
		return "domain-only"
	case PatternTypeSchemeOnly:
		return "scheme-only"
	case PatternTypeWildcard:
		return "wildcard"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// RedirectPattern represents a parsed redirect pattern
type RedirectPattern struct {
	Original    string
	Type        RedirectPatternType
	GlobPattern glob.Glob
}

// RedirectConfig holds the configuration for redirect patterns
type RedirectConfig struct {
	Patterns []RedirectPattern
}

// NewRedirectConfig creates a new RedirectConfig
func NewRedirectConfig(patterns []RedirectPattern) *RedirectConfig {
	return &RedirectConfig{
		Patterns: patterns,
	}
}

// CategorizePattern determines the type of a redirect uri and returns a RedirectPattern
func CategorizePattern(pattern string) (RedirectPattern, error) {
	rp := RedirectPattern{Original: pattern}

	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return rp, errors.New("pattern cannot be empty")
	}

	// Check if contains wildcard
	if strings.Contains(pattern, "*") {
		rp.Type = PatternTypeWildcard

		var globPattern string

		// Use Go's url package to validate wildcard patterns
		if strings.Contains(pattern, "://") {
			parts := strings.SplitN(pattern, "://", 2)
			if len(parts) == 2 {
				scheme := parts[0]
				restOfUri := parts[1]
				// Check if wildcard is in scheme - not allowed
				if strings.Contains(scheme, "*") {
					return rp, errors.New("invalid scheme in wildcard pattern")
				}

				// Let url package validate the scheme part
				testURL := scheme + "://example.com"
				if _, err := url.Parse(testURL); err != nil {
					return rp, fmt.Errorf("invalid scheme in wildcard pattern: %w", err)
				}

				// Check if wildcard is in path (not allowed)
				if strings.Contains(restOfUri, "/") && strings.Contains(restOfUri[strings.Index(restOfUri, "/"):], "*") {
					return rp, errors.New("wildcards are not allowed in URL paths")
				}
			}
			globPattern = pattern
		} else {
			// Domain-only wildcard pattern - add HTTPS prefix and path matching
			globPattern = "https://" + pattern + "{,/**}"
		}

		// Compile the glob pattern
		g, err := glob.Compile(globPattern, '.')
		if err != nil {
			return rp, fmt.Errorf("failed to compile glob pattern: %w", err)
		}
		rp.GlobPattern = g
		return rp, nil
	}

	// Check if it's scheme-only (e.g., "myapp://")
	if strings.HasSuffix(pattern, "://") {
		scheme := strings.TrimSuffix(pattern, "://")
		// Use url package to validate the scheme
		if _, err := url.Parse(scheme + "://example.com"); err != nil {
			return rp, fmt.Errorf("invalid scheme pattern: %w", err)
		}
		rp.Type = PatternTypeSchemeOnly
		// Use ** to match across all path components
		g, _ := glob.Compile(pattern+"**", '.')
		rp.GlobPattern = g
		return rp, nil
	}

	// Try to parse as URL to validate
	if strings.Contains(pattern, "://") {
		if _, err := url.Parse(pattern); err != nil {
			return rp, fmt.Errorf("invalid URL pattern: %w", err)
		}
		rp.Type = PatternTypeExact
		// Exact URLs match only the exact URL specified
		g, _ := glob.Compile(pattern, '.')
		rp.GlobPattern = g
		return rp, nil
	}

	// Domain-only pattern (no scheme, no path)
	if !strings.Contains(pattern, "/") {
		rp.Type = PatternTypeDomainOnly

		// Special handling for localhost - allow both HTTP and HTTPS, any port, any path
		if isLocalhostDomain(pattern) {
			// Match both HTTP and HTTPS schemes with any port and path
			g, _ := glob.Compile("{http,https}://"+pattern+"**", '.')
			rp.GlobPattern = g
			return rp, nil
		}

		// Regular domain-only patterns default to HTTPS (configure explicit URLs for other schemes)
		// Use {,/**} to match both with and without paths
		g, _ := glob.Compile("https://"+pattern+"{,/**}", '.')
		rp.GlobPattern = g
		return rp, nil
	}

	return rp, errors.New("invalid pattern format")
}

// isLocalhostDomain checks if a domain is localhost-like
func isLocalhostDomain(domain string) bool {
	return domain == "localhost" || domain == "127.0.0.1" || domain == "::1"
}
