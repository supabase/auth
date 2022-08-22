package api

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/storage/test"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const (
	apiTestVersion = "1"
	apiTestConfig  = "../hack/test.env"
)

func init() {
	rand.Seed(time.Now().UnixNano())
	models.PasswordHashCost = bcrypt.MinCost

}

// setupAPIForTest creates a new API to run tests with.
// Using this function allows us to keep track of the database connection
// and cleaning up data between tests.
func setupAPIForTest() (*API, *conf.GlobalConfiguration, error) {
	return setupAPIForTestWithCallback(nil)
}

func setupAPIForTestWithCallback(cb func(*conf.GlobalConfiguration, *storage.Connection) (uuid.UUID, error)) (*API, *conf.GlobalConfiguration, error) {
	config, err := conf.LoadGlobal(apiTestConfig)
	if err != nil {
		return nil, nil, err
	}

	conn, err := test.SetupDBConnection(config)
	if err != nil {
		return nil, nil, err
	}

	return NewAPIWithVersion(context.Background(), config, conn, apiTestVersion), config, nil
}

func TestEmailEnabledByDefault(t *testing.T) {
	api, _, err := setupAPIForTest()
	require.NoError(t, err)

	require.True(t, api.config.External.Email.Enabled)
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}
