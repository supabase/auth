package test

import (
	"github.com/clanwyse/halo/internal/conf"
	"github.com/clanwyse/halo/internal/storage"
)

func SetupDBConnection(globalConfig *conf.GlobalConfiguration) (*storage.Connection, error) {
	return storage.Dial(globalConfig)
}
