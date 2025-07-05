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
		return rp, errors.New("redirecturi: pattern cannot be empty")
	}

	// Check if it's scheme-only first (e.g., "myapp://")
	if strings.HasSuffix(pattern, "://") {
		scheme := strings.TrimSuffix(pattern, "://")
		// Use url package to validate the scheme
		if _, err := url.Parse(scheme + "://example.com"); err != nil {
			return rp, fmt.Errorf("redirecturi: invalid scheme pattern: %w", err)
		}
		rp.Type = PatternTypeSchemeOnly
		// Use ** to match across all path components
		g, _ := glob.Compile(pattern+"**", '.')
		rp.GlobPattern = g
		return rp, nil
	}

	// Try to parse as URL to validate
	if strings.Contains(pattern, "://") {
		parsed, err := url.Parse(pattern)
		if err != nil {
			return rp, fmt.Errorf("redirecturi: invalid URL pattern: %w", err)
		}
		
		// Check if contains wildcard in hostname only (not in query/fragment)
		if strings.Contains(parsed.Host, "*") {
			// This is a wildcard pattern
			rp.Type = PatternTypeWildcard
			
			// Check if wildcard is in scheme - not allowed
			if strings.Contains(parsed.Scheme, "*") {
				return rp, errors.New("redirecturi: invalid scheme in wildcard pattern")
			}
			
			// Check if wildcard is in path (not allowed)
			if strings.Contains(parsed.Path, "*") {
				return rp, errors.New("redirecturi: wildcards are not allowed in URL paths")
			}
			
			// Compile the glob pattern
			g, err := glob.Compile(pattern, '.')
			if err != nil {
				return rp, fmt.Errorf("redirecturi: failed to compile glob pattern: %w", err)
			}
			rp.GlobPattern = g
			return rp, nil
		}
		
		// Check for wildcards anywhere except hostname (not allowed for exact URLs)
		if strings.Contains(parsed.Path, "*") {
			return rp, errors.New("redirecturi: wildcards are not allowed in URL paths")
		}
		if parsed.RawQuery != "" && strings.Contains(parsed.RawQuery, "*") {
			return rp, errors.New("redirecturi: wildcards are not allowed in query parameters")
		}
		if parsed.Fragment != "" && strings.Contains(parsed.Fragment, "*") {
			return rp, errors.New("redirecturi: wildcards are not allowed in URL fragments")
		}
		
		// No wildcard in hostname, this is an exact URL
		rp.Type = PatternTypeExact
		// For exact URLs, we need to escape glob special characters to ensure literal matching
		// This prevents '?' and '*' in URLs from being interpreted as wildcards
		escapedPattern := escapeGlobPattern(pattern)
		g, _ := glob.Compile(escapedPattern, '.')
		rp.GlobPattern = g
		return rp, nil
	}
	
	// Check if contains wildcard (for non-URL patterns like domain-only)
	if strings.Contains(pattern, "*") {
		rp.Type = PatternTypeWildcard
		
		// Domain-only wildcard pattern - add HTTPS prefix and path matching
		globPattern := "https://" + pattern + "{,/**}"
		
		// Compile the glob pattern
		g, err := glob.Compile(globPattern, '.')
		if err != nil {
			return rp, fmt.Errorf("redirecturi: failed to compile glob pattern: %w", err)
		}
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

	return rp, errors.New("redirecturi: invalid pattern format")
}

// isLocalhostDomain checks if a domain is localhost-like
func isLocalhostDomain(domain string) bool {
	return domain == "localhost" || domain == "127.0.0.1" || domain == "::1"
}

// escapeGlobPattern escapes special glob characters to ensure literal matching
func escapeGlobPattern(pattern string) string {
	// Escape characters that have special meaning in glob patterns
	// This ensures exact URL patterns match literally
	// Note: We must escape backslashes first to avoid double-escaping
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"*", "\\*",
		"?", "\\?",
		"[", "\\[",
		"]", "\\]",
		"{", "\\{",
		"}", "\\}",
	)
	return replacer.Replace(pattern)
}
