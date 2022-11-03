package models

import (
	"database/sql"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v5"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
)

type Identity struct {
	ID           string     `json:"id" db:"id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	IdentityData JSONMap    `json:"identity_data,omitempty" db:"identity_data"`
	Provider     string     `json:"provider" db:"provider"`
	LastSignInAt *time.Time `json:"last_sign_in_at,omitempty" db:"last_sign_in_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" db:"updated_at"`
}

func (Identity) TableName() string {
	tableName := "identities"
	return tableName
}

// GetAccountLinkingDomain returns a string that describes the account linking
// domain. An account linking domain describes a set of Identity entities that
// _should_ generally fall under the same User entity. It's just a runtime
// string, and is not typically persisted in the database. This value can vary
// across time.
func GetAccountLinkingDomain(provider string) string {
	if strings.HasPrefix(provider, "sso:") {
		// when the provider ID is a SSO provider, then the linking
		// domain is the provider itself i.e. there can only be one
		// user + identity per identity provider
		return provider
	}

	// otherwise, the linking domain is the default linking domain that
	// links all accounts
	return "default"
}

type AccountLinkingDecision = int

const (
	AccountExists AccountLinkingDecision = iota
	CreateAccount
	LinkAccount
	MultipleAccounts
)

type AccountLinkingResult struct {
	Decision AccountLinkingDecision

	User       *User
	Identities []*Identity

	LinkingDomain string
}

// DetermineAccountLinking uses the provided data and database state to compute a decision on whether:
// - A new User should be created (CreateAccount)
// - A new Identity should be created (LinkAccount) with a UserID pointing to an existing user account
// - Nothing should be done (AccountExists)
// - It's not possible to decide due to data inconsistency (MultipleAccounts) and the caller should decide
//
// Errors signal failure in processing only, like database access errors.
func DetermineAccountLinking(tx *storage.Connection, provider, sub, email, phone string) (AccountLinkingResult, error) {
	var similarIdentities []*Identity

	if terr := tx.Q().Eager().Where("provider = ? and id = ?", provider, sub).All(&similarIdentities); terr != nil {
		return AccountLinkingResult{}, terr
	}

	if len(similarIdentities) == 1 {
		// identity and user already exist
		identity := similarIdentities[0]

		var user *User
		if terr := tx.Q().Eager().Where("id = ?", identity.UserID).First(&user); terr != nil {
			return AccountLinkingResult{}, terr
		}

		return AccountLinkingResult{
			Decision:      AccountExists,
			User:          user,
			Identities:    similarIdentities,
			LinkingDomain: GetAccountLinkingDomain(provider),
		}, nil
	}

	// identity and user not immediately identifiable, look for similar identities based on email or phone

	if email != "" {
		var emailIdentities []*Identity

		if terr := tx.Q().Eager().Where("email = ?", strings.ToLower(email)).All(&emailIdentities); terr != nil {
			return AccountLinkingResult{}, terr
		}

		similarIdentities = append(similarIdentities, emailIdentities...)
	}

	if phone != "" {
		var phoneIdentities []*Identity

		if terr := tx.Q().Eager().Where("phone = ?", phone).All(&phoneIdentities); terr != nil {
			return AccountLinkingResult{}, terr
		}

		similarIdentities = append(similarIdentities, phoneIdentities...)
	}

	if len(similarIdentities) == 0 {
		// there are no similar identities, clearly we have to create a new account

		return AccountLinkingResult{
			Decision:      CreateAccount,
			LinkingDomain: GetAccountLinkingDomain(provider),
		}, nil
	}

	// there are some similar identities, we now need to proceed in
	// identifying whether this supposed new identity should be assigned to
	// an existing user or to create a new user, according to the automatic
	// linking rules

	// this is the linking domain for the new identity
	linkingDomain := GetAccountLinkingDomain(provider)

	var linkingIdentities []*Identity

	// now let's see if there are any existing and similar identities in
	// the same linking domain
	for _, identity := range similarIdentities {
		if GetAccountLinkingDomain(identity.Provider) == linkingDomain {
			linkingIdentities = append(linkingIdentities, identity)
		}
	}

	if len(linkingIdentities) == 0 {
		// there are no identities in the linking domain, we have to
		// create a new identity and new user
		return AccountLinkingResult{
			Decision:      CreateAccount,
			LinkingDomain: linkingDomain,
		}, nil
	}

	// there is at least one identity in the linking domain let's do a
	// sanity check to see if all of the identities in the domain share the
	// same user ID

	for _, identity := range linkingIdentities {
		if identity.UserID != linkingIdentities[0].UserID {
			// ok this linking domain has more than one user account
			// caller should decide what to do

			return AccountLinkingResult{
				Decision:   MultipleAccounts,
				Identities: linkingIdentities,
			}, nil
		}
	}

	// there's only one user ID in this linking domain, we can go on and
	// create a new identity and link it to the existing account

	var user *User
	if terr := tx.Q().Eager().Where("id = ?", linkingIdentities[0].UserID).First(&user); terr != nil {
		return AccountLinkingResult{}, terr
	}

	return AccountLinkingResult{
		Decision:      LinkAccount,
		User:          user,
		Identities:    linkingIdentities,
		LinkingDomain: linkingDomain,
	}, nil
}

// NewIdentity returns an identity associated to the user's id.
func NewIdentity(user *User, provider string, identityData map[string]interface{}) (*Identity, error) {
	id, ok := identityData["sub"]
	if !ok {
		return nil, errors.New("error missing provider id")
	}
	now := time.Now()

	identity := &Identity{
		ID:           id.(string),
		UserID:       user.ID,
		IdentityData: identityData,
		Provider:     provider,
		LastSignInAt: &now,
	}

	return identity, nil
}

func (i *Identity) BeforeCreate(tx *pop.Connection) error {
	return i.BeforeUpdate(tx)
}

func (i *Identity) BeforeUpdate(tx *pop.Connection) error {
	if _, ok := i.IdentityData["email"]; ok {
		i.IdentityData["email"] = strings.ToLower(i.IdentityData["email"].(string))
	}
	return nil
}

// FindIdentityById searches for an identity with the matching provider_id and provider given.
func FindIdentityByIdAndProvider(tx *storage.Connection, providerId, provider string) (*Identity, error) {
	identity := &Identity{}
	if err := tx.Q().Where("id = ? AND provider = ?", providerId, provider).First(identity); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, IdentityNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding identity")
	}
	return identity, nil
}

// FindIdentitiesByUser returns all identities associated to a user
func FindIdentitiesByUser(tx *storage.Connection, user *User) ([]*Identity, error) {
	identities := []*Identity{}
	if err := tx.Q().Where("user_id = ?", user.ID).All(&identities); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return identities, nil
		}
		return nil, errors.Wrap(err, "error finding identities")
	}
	return identities, nil
}

// FindProvidersByUser returns all providers associated to a user
func FindProvidersByUser(tx *storage.Connection, user *User) ([]string, error) {
	identities := []Identity{}
	providers := make([]string, 0)
	if err := tx.Q().Select("provider").Where("user_id = ?", user.ID).All(&identities); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return providers, nil
		}
		return nil, errors.Wrap(err, "error finding providers")
	}
	for _, identity := range identities {
		providers = append(providers, identity.Provider)
	}
	return providers, nil
}
