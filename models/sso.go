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
	ID uuid.UUID `db:"id"`

	SAMLProvider SAMLProvider `has_one:"saml_providers" fk_id:"sso_provider_id"`
	SSODomains   []SSODomain  `has_many:"sso_domains" fk_id:"sso_provider_id"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (p SSOProvider) TableName() string {
	return "sso_providers"
}

type SAMLProvider struct {
	ID uuid.UUID `db:"id"`

	SSOProvider   *SSOProvider `belongs_to:"sso_providers"`
	SSOProviderID uuid.UUID    `db:"sso_provider_id"`

	EntityID    string `db:"entity_id"`
	MetadataXML string `db:"metadata_xml"`
	MetadataURL string `db:"metadata_url"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (p SAMLProvider) TableName() string {
	return "saml_providers"
}

type SSODomain struct {
	ID uuid.UUID `db:"id"`

	SSOProvider   *SSOProvider `belongs_to:"sso_providers"`
	SSOProviderID uuid.UUID    `db:"sso_provider_id"`

	Domain string `db:"domain"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (d SSODomain) TableName() string {
	return "sso_domains"
}

func FindSSOProviderForEmailAddress(tx *storage.Connection, emailAddress string) (*SSOProvider, error) {
	parts := strings.Split(emailAddress, "@")
	emailDomain := parts[1]

	var ssoDomain SSODomain

	if err := tx.Eager().Q().Where("domain = ?", emailDomain).First(&ssoDomain); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, nil
		}

		return nil, errors.Wrap(err, "error finding SSO provider based on email address domain")
	}

	return ssoDomain.SSOProvider, nil
}

func FindSAMLProviderForEntityID(tx *storage.Connection, entityId string) (*SSOProvider, error) {
	var samlProvider SAMLProvider
	if err := tx.Eager().Q().Where("entity_id = ?", entityId).First(&samlProvider); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, nil
		}

		return nil, errors.Wrap(err, "error finding SAML SSO provider by EntityID")
	}

	return samlProvider.SSOProvider, nil
}
