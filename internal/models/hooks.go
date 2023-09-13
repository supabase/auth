package models

import (
	"database/sql"
	"github.com/gobuffalo/pop/v6"
	"github.com/pkg/errors"
	"github.com/supabase/gotrue/internal/storage"
)

type HookConfig struct {
	Name string `json:"name" db:"name"`
	// TODO: change this t o just URI
	HookURI            string  `json:"hook_uri" db:"hook_uri"`
	Secret             string  `json:"secret" db:"secret"`
	ExtensibilityPoint string  `json:"extensibility_point" db:"extensibility_point"`
	Metadata           JSONMap `json:"metadata" db:"metadata"`
}

// TableName overrides the table name used by pop
func (HookConfig) TableName() string {
	tableName := "hook_config"
	return tableName
}

func (h *HookConfig) BeforeSave(tx *pop.Connection) error {
	// TODO: Encrypt the Secret
	return nil
}

func NewHookConfig(name, hookURI, secret, extensibilityPoint string, metadata map[string]interface{}) (*HookConfig, error) {
	hookConfig := &HookConfig{
		Name:               name,
		HookURI:            hookURI,
		Secret:             secret,
		ExtensibilityPoint: extensibilityPoint,
		Metadata:           metadata,
	}
	return hookConfig, nil
}

func FetchHookConfiguration(tx *storage.Connection, query string, args ...interface{}) (*HookConfig, error) {
	obj := &HookConfig{}
	if err := tx.Eager().Q().Where(query, args...).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, HookConfigNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding user")
	}

	return obj, nil
}
