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
			if err == nil {
				t.Fatal("exp non-nil err")
			}
			if globalCfg != nil {
				t.Fatal("exp nil conn")
			}
		}
	}()

	// Conn
	func() {
		// positive
		{
			globalCfg := Must(Config())
			conn := Must(Conn(globalCfg))
			if conn == nil {
				t.Fatal("exp non-nil conn")
			}
		}

		// negative
		{
			globalCfg := Must(Config())
			globalCfg.DB.Driver = ""
			globalCfg.DB.URL = "invalid"
			conn, err := Conn(globalCfg)
			if err == nil {
				t.Fatal("exp non-nil err")
			}
			if conn != nil {
				t.Fatal("exp nil conn")
			}
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

		if err == nil {
			t.Fatal("exp non-nil err")
		}
	}()
}
