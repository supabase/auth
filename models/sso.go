package models

import (
	"database/sql"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
)

type SSOProvider struct {
	ID uuid.UUID `db:"id" json:"id"`

	SAMLProvider SAMLProvider `has_one:"saml_providers" fk_id:"sso_provider_id" json:"saml,omitempty"`
	SSODomains   []SSODomain  `has_many:"sso_domains" fk_id:"sso_provider_id" json:"domains"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

func (p SSOProvider) TableName() string {
	return "sso_providers"
}

type SAMLProvider struct {
	ID uuid.UUID `db:"id" json:"-"`

	SSOProvider   *SSOProvider `belongs_to:"sso_providers" json:"-"`
	SSOProviderID uuid.UUID    `db:"sso_provider_id" json:"-"`

	EntityID    string `db:"entity_id" json:"entity_id"`
	MetadataXML string `db:"metadata_xml" json:"metadata_xml,omitempty"`
	MetadataURL string `db:"metadata_url" json:"metadata_url,omitempty"`

	CreatedAt time.Time `db:"created_at" json:"-"`
	UpdatedAt time.Time `db:"updated_at" json:"-"`
}

func (p SAMLProvider) TableName() string {
	return "saml_providers"
}

type SSODomain struct {
	ID uuid.UUID `db:"id" json:"-"`

	SSOProvider   *SSOProvider `belongs_to:"sso_providers" json:"-"`
	SSOProviderID uuid.UUID    `db:"sso_provider_id" json:"-"`

	Domain string `db:"domain" json:"domain"`

	CreatedAt time.Time `db:"created_at" json:"-"`
	UpdatedAt time.Time `db:"updated_at" json:"-"`
}

func (d SSODomain) TableName() string {
	return "sso_domains"
}

func FindSSOProviderForEmailAddress(tx *storage.Connection, emailAddress string) (*SSOProvider, error) {
	parts := strings.Split(emailAddress, "@")
	emailDomain := parts[1]

	return FindSSOProviderByDomain(tx, emailDomain)
}

func FindSAMLProviderForEntityID(tx *storage.Connection, entityId string) (*SSOProvider, error) {
	var samlProvider SAMLProvider
	if err := tx.Q().Where("entity_id = ?", entityId).First(&samlProvider); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SSOProviderNotFoundError{}
		}

		return nil, errors.Wrap(err, "error finding SAML SSO provider by EntityID")
	}

	var ssoProvider SSOProvider
	if err := tx.Eager().Q().Where("id = ?", samlProvider.SSOProviderID).First(&ssoProvider); err != nil {
		return nil, errors.Wrap(err, "error finding SAML SSO provider by ID (via EntityID)")
	}

	return &ssoProvider, nil
}

func FindSAMLProviderByID(tx *storage.Connection, id uuid.UUID) (*SSOProvider, error) {
	var ssoProvider SSOProvider

	if err := tx.Eager().Q().Where("id = ?", id).First(&ssoProvider); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SSOProviderNotFoundError{}
		}

		return nil, errors.Wrap(err, "error finding SAML SSO provider by ID")
	}

	return &ssoProvider, nil
}

func FindSSOProviderByDomain(tx *storage.Connection, domain string) (*SSOProvider, error) {
	var ssoDomain SSODomain

	if err := tx.Q().Where("domain = ?", domain).First(&ssoDomain); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SSOProviderNotFoundError{}
		}

		return nil, errors.Wrap(err, "error finding SAML SSO domain")
	}

	var ssoProvider SSOProvider
	if err := tx.Eager().Q().Where("id = ?", ssoDomain.SSOProviderID).First(&ssoProvider); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SSOProviderNotFoundError{}
		}

		return nil, errors.Wrap(err, "error finding SAML SSO provider by ID (via domain)")
	}

	return &ssoProvider, nil
}

func FindAllSAMLProviders(tx *storage.Connection) ([]SSOProvider, error) {
	var providers []SSOProvider

	if err := tx.Eager().All(&providers); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, nil
		}

		return nil, errors.Wrap(err, "error loading all SAML SSO providers")
	}

	return providers, nil
}
