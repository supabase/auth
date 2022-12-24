package test

import (
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/storage"
)

func SetupDBConnection(tenantConfig *conf.TenantConfiguration) (*storage.Connection, error) {
	c := &storage.DialConfiguration{
		DB:      tenantConfig.DB,
		Tracing: tenantConfig.Tracing,
		Metrics: tenantConfig.Metrics,
	}
	return storage.Dial(c)
}
