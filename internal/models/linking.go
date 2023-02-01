package models

import (
	"strings"

	"github.com/netlify/gotrue/storage"
)

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
func DetermineAccountLinking(tx *storage.Connection, provider, sub string, emails []string) (AccountLinkingResult, error) {
	if identity, terr := FindIdentityByIdAndProvider(tx, sub, provider); terr == nil {
		// account exists

		var user *User
		if user, terr = FindUserByID(tx, identity.UserID); terr != nil {
			return AccountLinkingResult{}, terr
		}

		return AccountLinkingResult{
			Decision:      AccountExists,
			User:          user,
			Identities:    []*Identity{identity},
			LinkingDomain: GetAccountLinkingDomain(provider),
		}, nil
	} else if !IsNotFoundError(terr) {
		return AccountLinkingResult{}, terr
	}

	// account does not exist, identity and user not immediately
	// identifiable, look for similar identities based on email
	var similarIdentities []*Identity

	if len(emails) > 0 {
		if terr := tx.Q().Eager().Where("email in (?)", emails).All(&similarIdentities); terr != nil {
			return AccountLinkingResult{}, terr
		}
	}

	// TODO: determine linking behavior over phone too

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
	newAccountLinkingDomain := GetAccountLinkingDomain(provider)

	var linkingIdentities []*Identity

	// now let's see if there are any existing and similar identities in
	// the same linking domain
	for _, identity := range similarIdentities {
		if GetAccountLinkingDomain(identity.Provider) == newAccountLinkingDomain {
			linkingIdentities = append(linkingIdentities, identity)
		}
	}

	if len(linkingIdentities) == 0 {
		// there are no identities in the linking domain, we have to
		// create a new identity and new user
		return AccountLinkingResult{
			Decision:      CreateAccount,
			LinkingDomain: newAccountLinkingDomain,
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
				Decision:      MultipleAccounts,
				Identities:    linkingIdentities,
				LinkingDomain: newAccountLinkingDomain,
			}, nil
		}
	}

	// there's only one user ID in this linking domain, we can go on and
	// create a new identity and link it to the existing account

	var user *User
	var terr error

	if user, terr = FindUserByID(tx, linkingIdentities[0].UserID); terr != nil {
		return AccountLinkingResult{}, terr
	}

	return AccountLinkingResult{
		Decision:      LinkAccount,
		User:          user,
		Identities:    linkingIdentities,
		LinkingDomain: newAccountLinkingDomain,
	}, nil
}
