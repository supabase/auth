package e2e

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestUtils(t *testing.T) {

	// check paths
	require.Equal(t, projectRoot, GetProjectRoot())
	require.Equal(t, configPath, GetConfigPath())

	// Config
	func() {

		// positive
		{
			testCfgPath := "../../hack/test.env"
			testCfg := Must(conf.LoadGlobal(testCfgPath))
			globalCfg := Must(Config())
			require.Equal(t, testCfg, globalCfg)
		}

		// negative
		{
			restore := configPath
			defer func() {
				configPath = restore
			}()
			configPath = "abc"

			globalCfg, err := Config()
			require.Error(t, err)
			require.Nil(t, globalCfg)
		}
	}()

	// Conn
	func() {
		// positive
		{
			globalCfg := Must(Config())
			conn := Must(Conn(globalCfg))
			require.NotNil(t, conn)
		}

		// negative
		{
			globalCfg := Must(Config())
			globalCfg.DB.Driver = ""
			globalCfg.DB.URL = "invalid"
			conn, err := Conn(globalCfg)
			require.Error(t, err)
			require.Nil(t, conn)
		}

	}()

	// Must
	func() {
		restore := configPath
		defer func() {
			configPath = restore
		}()
		configPath = "abc"

		var err error
		func() {
			defer func() {
				err = recover().(error)
			}()

			globalCfg := Must(Config())
			if globalCfg != nil {
				panic(errors.New("globalCfg != nil"))
			}
		}()
		require.Error(t, err)
	}()

	// block init from main()
	func() {
		restore := isTesting
		defer func() {
			isTesting = restore
		}()
		isTesting = func() bool { return false }

		var errStr string
		func() {
			defer func() {
				errStr = recover().(string)
			}()

			initPackage()
		}()

		exp := "package e2e may not be used in a main package"
		require.Equal(t, exp, errStr)
	}()
}
