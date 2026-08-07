package models

// ProvisionedUser is a user as seen through one SSO provider. The identity
// carries the claims that provider supplied, so attributes read from it are
// scoped to that provider rather than to the user record, which is shared
// across every provider the user is linked to.
type ProvisionedUser struct {
	*User
	Identity *Identity
}

// Claim returns the string claim the provider supplied under key, or an empty
// string when it is absent or not a string.
func (p ProvisionedUser) Claim(key string) string {
	if p.Identity == nil {
		return ""
	}
	value, _ := p.Identity.IdentityData[key].(string)
	return value
}
