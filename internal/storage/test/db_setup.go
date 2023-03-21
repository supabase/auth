package test

import (
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/storage"
)

func SetupDBConnection(globalConfig *conf.GlobalConfiguration) (*storage.Connection, error) {
	return storage.Dial(globalConfig)
}
