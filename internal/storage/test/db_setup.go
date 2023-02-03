package test

import (
	"github.com/netlify/gotrue/internal/conf"
	"github.com/netlify/gotrue/internal/storage"
)

func SetupDBConnection(globalConfig *conf.GlobalConfiguration) (*storage.Connection, error) {
	return storage.Dial(globalConfig)
}
