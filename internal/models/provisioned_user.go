package models

type ProvisionedUser struct {
	*User
	Identity *Identity
}

func (u *ProvisionedUser) Email() string {
	if email := u.Claim("email"); email != "" {
		return email
	}
	return u.GetEmail()
}

func (u *ProvisionedUser) UserName() string {
	if userName := u.Claim("preferred_username"); userName != "" {
		return userName
	}
	return u.Email()
}

func (p *ProvisionedUser) Claim(key string) string {
	if p.Identity == nil {
		return ""
	}
	value, _ := p.Identity.IdentityData[key].(string)
	return value
}
