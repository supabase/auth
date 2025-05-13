// Package e2e provides a few utilities for use in unit tests.
package e2e

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

var (
	projectRoot string
	configPath  string
)

func init() {
	if testing.Testing() {
		_, thisFile, _, _ := runtime.Caller(0)
		projectRoot = filepath.Join(filepath.Dir(thisFile), "../..")
		configPath = filepath.Join(GetProjectRoot(), "hack", "test.env")
	} else {
		panic("package e2e may not be used in a main package")
	}
}

// GetProjectRoot returns the path to the root of the project. This may be used
// to locate files without needing the relative path from a given test.
func GetProjectRoot() string {
	return projectRoot
}

// GetConfigPath returns the path for the "/hack/test.env" config file.
func GetConfigPath() string {
	return configPath
}

// Config calls conf.LoadGlobal using GetConfigPath().
func Config() (*conf.GlobalConfiguration, error) {
	globalCfg, err := conf.LoadGlobal(GetConfigPath())
	if err != nil {
		return nil, err
	}
	return globalCfg, nil
}

// Conn returns a connection for the given config.
func Conn(globalCfg *conf.GlobalConfiguration) (*storage.Connection, error) {
	conn, err := test.SetupDBConnection(globalCfg)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Must may be used by Config and Conn, i.e.:
//
//	cfg := e2e.Must(e2e.Config())
//	conn := e2e.Must(e2e.Conn(cfg))
func Must[T any](res T, err error) T {
	if err != nil {
		panic(err)
	}
	return res
}
