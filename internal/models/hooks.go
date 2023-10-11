package models

import (
	"database/sql"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/gotrue/internal/storage"
)

type HookConfig struct {
	ID                 uuid.UUID `json:"id" db:"id"`
	URI                string    `json:"uri" db:"uri"`
	Secret             []string  `json:"secret" db:"secret"`
	ExtensibilityPoint string    `json:"extensibility_point" db:"extensibility_point"`
	EventName          string    `json:"event_name" db:"event_name"`
	RequestSchema      JSONMap   `json:"request_schema" db:"request_schema"`
	ResponseSchema     JSONMap   `json:"response_schema" db:"response_schema"`
	Metadata           JSONMap   `json:"metadata" db:"metadata"`
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

func FindHookByExtensibilityPoint(tx *storage.Connection, name string) (*HookConfig, error) {
	return findHookConfiguration(tx, "extensibility_point = ?", name)

}

func findHookConfiguration(tx *storage.Connection, query string, args ...interface{}) (*HookConfig, error) {
	obj := &HookConfig{}
	if err := tx.Eager().Q().Where(query, args...).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, HookConfigNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding user")
	}

	return obj, nil
}
