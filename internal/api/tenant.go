package api

import (
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/storage"

	"github.com/sirupsen/logrus"
)

// stores per-tenant settings here
// TODO: need to add tenant-specific rate limiting here
type Tenant struct {
	db       *storage.Connection
	config   *conf.GlobalConfiguration
	limiters *Limiters
}

func (t *Tenant) GetConnection() *storage.Connection {
	return t.db
}

func NewTenant(config *conf.GlobalConfiguration) (*Tenant, error) {
	// TODO: close db connection in cleanup
	db, err := storage.Dial(config)
	if err != nil {
		logrus.Fatalf("error opening database connection to tenant: %+v", err)
	}

	// create rate limiters for tenant
	// TODO: in multi-tenant mode, the rate limiters have to be obtained from a global store
	limiters := NewLimiters(config)

	return &Tenant{
		config:   config,
		db:       db,
		limiters: limiters,
	}, nil
}
