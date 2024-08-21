package conf

// OIDCConfiguration holds configuration for native OIDC SSO support.
type OIDCConfiguration struct {
	Enabled bool `json:"enabled"`
}

func (c *OIDCConfiguration) Validate() error {
	if c.Enabled {

	}

	return nil
}
