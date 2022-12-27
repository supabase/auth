package test

import (
	"github.com/supabase/gotrue/conf"
	"github.com/supabase/gotrue/storage"
)

func SetupDBConnection(globalConfig *conf.GlobalConfiguration) (*storage.Connection, error) {
	return storage.Dial(globalConfig)
}
