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

func TestGlobal(t *testing.T) {
	os.Setenv("GOTRUE_SITE_URL", "http://localhost:8080")
	os.Setenv("GOTRUE_DB_DRIVER", "mysql")
	os.Setenv("GOTRUE_DB_DATABASE_URL", "fake")
	os.Setenv("GOTRUE_OPERATOR_TOKEN", "token")
	os.Setenv("GOTRUE_API_REQUEST_ID_HEADER", "X-Request-ID")
	os.Setenv("GOTRUE_JWT_SECRET", "secret")
	os.Setenv("API_EXTERNAL_URL", "http://localhost:9999")
	gc, err := LoadGlobal("")
	require.NoError(t, err)
	require.NotNil(t, gc)
	assert.Equal(t, "X-Request-ID", gc.API.RequestIDHeader)
}
