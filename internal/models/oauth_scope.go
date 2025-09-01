package models

import "strings"

// ParseScopeString parses a space-separated scope string into a slice
func ParseScopeString(scopeString string) []string {
	if scopeString == "" {
		return []string{}
	}
	scopes := strings.Split(strings.TrimSpace(scopeString), " ")
	var result []string
	for _, scope := range scopes {
		if strings.TrimSpace(scope) != "" {
			result = append(result, strings.TrimSpace(scope))
		}
	}
	// Always return empty slice instead of nil for consistency
	if result == nil {
		return []string{}
	}
	return result
}

// HasScope checks if the given scope list includes a specific scope
func HasScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAllScopes checks if the granted scopes include all of the requested scopes
func HasAllScopes(grantedScopes, requestedScopes []string) bool {
	grantedSet := make(map[string]bool)
	for _, scope := range grantedScopes {
		grantedSet[scope] = true
	}

	for _, requestedScope := range requestedScopes {
		if !grantedSet[requestedScope] {
			return false
		}
	}
	return true
}
