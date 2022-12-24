package conf

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	defer os.Clearenv()
	os.Exit(m.Run())
}

func TestLoadTenantConfig(t *testing.T) {
	os.Setenv("GOTRUE_SITE_URL", "http://localhost:8080")
	os.Setenv("GOTRUE_DB_DRIVER", "postgres")
	os.Setenv("GOTRUE_DB_DATABASE_URL", "fake")
	os.Setenv("GOTRUE_API_REQUEST_ID_HEADER", "X-Request-ID")
	os.Setenv("GOTRUE_JWT_SECRET", "secret")
	tenantConfig, err := LoadTenant("")
	require.NoError(t, err)
	require.NotNil(t, tenantConfig)
	assert.Equal(t, "X-Request-ID", tenantConfig.API.RequestIDHeader)
	assert.Equal(t, "http://localhost:8080", tenantConfig.SiteURL)
	assert.Equal(t, "postgres", tenantConfig.DB.Driver)
	assert.Equal(t, "fake", tenantConfig.DB.URL)
	assert.Equal(t, "secret", tenantConfig.JWT.Secret)
}
