# Response to Security Feedback (Hostname-Matching Bypass)

Thank you for catching this! You're absolutely right - the hostname-matching shortcut is too permissive for OAuth Dynamic Client Registration.

## Issue Identified

The previous implementation used `utilities.IsRedirectURLValid()` for HTTPS URIs, which contains a hostname-matching shortcut:

```go
// In utilities.IsRedirectURLValid()
if base.Hostname() == refurl.Hostname() {
    return true  // ⚠️ Allows ANY path on same hostname!
}
```

This would allow an attacker to register:
- `https://auth.example.com/arbitrary/path`
- `https://auth.example.com/admin/redirect`
- Any path on the auth server

If the auth server has any open redirect or XSS vulnerability, this enables OAuth token theft.

## Fix Implemented

Replaced `utilities.IsRedirectURLValid()` with strict allow-list validation for **all schemes** (HTTP, HTTPS, and custom):

### Before
```go
if isStandardScheme {
    // Uses utilities.IsRedirectURLValid() - has hostname bypass
    if !utilities.IsRedirectURLValid(s.config, uri) {
        return fmt.Errorf("redirect URI not allowed by configuration")
    }
}
```

### After
```go
// For OAuth Dynamic Client Registration, require strict allow-list matching
// This prevents exploitation of hostname-matching shortcuts
if !isURIExplicitlyAllowed(s.config, uri) {
    return fmt.Errorf("redirect URI not allowed by configuration")
}
```

## New Validation Function

Created `isURIExplicitlyAllowed()` that:
- ✅ Requires exact glob pattern matches from `URIAllowListMap`
- ✅ No hostname-matching shortcuts
- ✅ Scheme-specific pattern matching (prevents cross-scheme exploitation)
- ✅ Works for all schemes (HTTP, HTTPS, custom)

```go
func isURIExplicitlyAllowed(config *conf.GlobalConfiguration, uri string) bool {
    // Only match patterns that start with the same scheme
    for pattern, glob := range config.URIAllowListMap {
        patternURL, _ := url.Parse(pattern)
        patternScheme := strings.ToLower(patternURL.Scheme)
        if patternScheme == scheme {
            if glob.Match(matchAgainst) {
                return true
            }
        }
    }
    return false
}
```

## Security Benefits

1. **Prevents Arbitrary Path Registration**
   - ❌ Before: `https://auth.example.com/any/path` allowed if hostname matches
   - ✅ After: Must explicitly match allow-list pattern

2. **Protects Against Open Redirects**
   - Attackers cannot register paths that exploit open redirect vulnerabilities

3. **Protects Against XSS**
   - Attackers cannot register paths that exploit XSS vulnerabilities

4. **Consistent Validation**
   - All schemes (HTTP, HTTPS, custom) use the same strict validation

## Configuration Required

Now **all** redirect URIs must be explicitly configured:

```toml
[auth]
additional_redirect_urls = [
  "https://app.example.com/**",           # Explicit pattern
  "http://localhost:3000/**",             # Localhost pattern
  "cursor://anysphere.cursor-mcp/**",     # Custom scheme
]
```

## Testing

All tests pass with strict validation:

```bash
go test ./internal/api/oauthserver/... -v
PASS: 50+ test cases
```

Test coverage includes:
- ✅ HTTPS URIs require allow-list match
- ✅ HTTP localhost requires allow-list match
- ✅ Custom schemes require allow-list match
- ✅ Dangerous schemes blocked
- ✅ No hostname-matching bypass

## Backward Compatibility

⚠️ **Configuration Update Required**

Deployments must ensure their `additional_redirect_urls` configuration includes:
- All HTTPS redirect URIs (not just custom schemes)
- Proper wildcard patterns for paths

Example migration:
```toml
# Before (relied on hostname matching)
additional_redirect_urls = []

# After (explicit patterns required)
additional_redirect_urls = [
  "https://app.example.com/**",
  "http://localhost:3000/**"
]
```

## Summary

This fix ensures that OAuth Dynamic Client Registration:
1. ✅ Blocks dangerous schemes (javascript, data, file)
2. ✅ Requires explicit allow-list matching for all schemes
3. ✅ Prevents hostname-matching bypass
4. ✅ Protects against open redirect and XSS exploitation
5. ✅ Uses consistent validation across all schemes

The OAuth server is now significantly more secure against authorization code interception attacks.

---

**Commits:**
- `68d688a` - Initial fix for custom URI schemes
- `9c2da99` - Security: block dangerous schemes
- `3d9df64` - Security: enforce strict allow-list validation (NEW)
