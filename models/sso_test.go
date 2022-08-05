package models

import (
	tst "testing"

	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/storage/test"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type SSOTestSuite struct {
	suite.Suite

	db *storage.Connection
}

func (ts *SSOTestSuite) SetupTest() {
	TruncateAll(ts.db)
}

func TestSSO(t *tst.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	ts := &SSOTestSuite{
		db: conn,
	}
	defer ts.db.Close()

	suite.Run(t, ts)
}

func (ts *SSOTestSuite) TestConstraints() {
	type exampleSpec struct {
		Provider *SSOProvider
	}

	examples := []exampleSpec{
		{
			Provider: &SSOProvider{
				SAMLProvider: SAMLProvider{
					EntityID:    "",
					MetadataXML: "<example />",
				},
			},
		},
		{
			Provider: &SSOProvider{
				SAMLProvider: SAMLProvider{
					EntityID:    "https://example.com/saml/metadata",
					MetadataXML: "",
				},
			},
		},
		{
			Provider: &SSOProvider{
				SAMLProvider: SAMLProvider{
					EntityID:    "https://example.com/saml/metadata",
					MetadataXML: "<example />",
				},
				SSODomains: []SSODomain{
					{
						Domain: "",
					},
				},
			},
		},
	}

	for i, example := range examples {
		require.Error(ts.T(), ts.db.Eager().Create(example.Provider), "Example %d should have failed with error", i)
	}
}

func (ts *SSOTestSuite) TestDomainUniqueness() {
	require.NoError(ts.T(), ts.db.Eager().Create(&SSOProvider{
		SAMLProvider: SAMLProvider{
			EntityID:    "https://example.com/saml/metadata1",
			MetadataXML: "<example />",
		},
		SSODomains: []SSODomain{
			{
				Domain: "example.com",
			},
		},
	}))

	require.Error(ts.T(), ts.db.Eager().Create(&SSOProvider{
		SAMLProvider: SAMLProvider{
			EntityID:    "https://example.com/saml/metadata2",
			MetadataXML: "<example />",
		},
		SSODomains: []SSODomain{
			{
				Domain: "example.com",
			},
		},
	}))
}

func (ts *SSOTestSuite) TestEntityIDUniqueness() {
	require.NoError(ts.T(), ts.db.Eager().Create(&SSOProvider{
		SAMLProvider: SAMLProvider{
			EntityID:    "https://example.com/saml/metadata",
			MetadataXML: "<example />",
		},
		SSODomains: []SSODomain{
			{
				Domain: "example.com",
			},
		},
	}))

	require.Error(ts.T(), ts.db.Eager().Create(&SSOProvider{
		SAMLProvider: SAMLProvider{
			EntityID:    "https://example.com/saml/metadata",
			MetadataXML: "<example />",
		},
		SSODomains: []SSODomain{
			{
				Domain: "example.net",
			},
		},
	}))
}

func (ts *SSOTestSuite) TestFindSSOProviderForEmailAddress() {
	provider := &SSOProvider{
		SAMLProvider: SAMLProvider{
			EntityID:    "https://example.com/saml/metadata",
			MetadataXML: "<example />",
		},
		SSODomains: []SSODomain{
			{
				Domain: "example.com",
			},
			{
				Domain: "example.org",
			},
		},
	}

	require.NoError(ts.T(), ts.db.Eager().Create(provider), "provider creation failed")

	type exampleSpec struct {
		Address  string
		Provider *SSOProvider
	}

	examples := []exampleSpec{
		{
			Address:  "someone@example.com",
			Provider: provider,
		},
		{
			Address:  "someone@example.org",
			Provider: provider,
		},
		{
			Address:  "someone@example.net",
			Provider: nil,
		},
	}

	for i, example := range examples {
		rp, err := FindSSOProviderForEmailAddress(ts.db, example.Address)

		if nil == example.Provider {
			require.Nil(ts.T(), rp)
			require.True(ts.T(), IsNotFoundError(err), "Example %d failed with error %w", i, err)
		} else {
			require.Nil(ts.T(), err, "Example %d failed with error %w", i, err)
			require.Equal(ts.T(), rp.ID, example.Provider.ID)
		}
	}
}

func (ts *SSOTestSuite) TestFindSAMLProviderForEntityID() {
	provider := &SSOProvider{
		SAMLProvider: SAMLProvider{
			EntityID:    "https://example.com/saml/metadata",
			MetadataXML: "<example />",
		},
		SSODomains: []SSODomain{
			{
				Domain: "example.com",
			},
			{
				Domain: "example.org",
			},
		},
	}

	require.NoError(ts.T(), ts.db.Eager().Create(provider))

	type exampleSpec struct {
		EntityID string
		Provider *SSOProvider
	}

	examples := []exampleSpec{
		{
			EntityID: "https://example.com/saml/metadata",
			Provider: provider,
		},
		{
			EntityID: "https://example.com/saml/metadata/",
			Provider: nil,
		},
		{
			EntityID: "",
			Provider: nil,
		},
	}

	for i, example := range examples {
		rp, err := FindSAMLProviderForEntityID(ts.db, example.EntityID)

		if nil == example.Provider {
			require.True(ts.T(), IsNotFoundError(err), "Example %d failed with error", i)
			require.Nil(ts.T(), rp)
		} else {
			require.Nil(ts.T(), err, "Example %d failed with error %w", i, err)
			require.Equal(ts.T(), rp.ID, example.Provider.ID)
		}
	}
}
