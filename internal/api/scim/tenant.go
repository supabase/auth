package scim

import (
	"github.com/supabase/auth/internal/ctxkey"
	"github.com/supabase/auth/internal/models"
)

type Tenant = models.SSOProvider

var tenantKey = ctxkey.New[*Tenant]("tenant")
