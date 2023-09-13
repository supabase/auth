package models

import (
	"github.com/gobuffalo/pop/v6"
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
