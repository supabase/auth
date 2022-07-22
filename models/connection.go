package models

import (
	"github.com/gobuffalo/pop/v5"
	"github.com/netlify/gotrue/storage"
)

type Pagination struct {
	Page    uint64
	PerPage uint64
	Count   uint64
}

func (p *Pagination) Offset() uint64 {
	return (p.Page - 1) * p.PerPage
}

type SortDirection string

const Ascending SortDirection = "ASC"
const Descending SortDirection = "DESC"
const CreatedAt = "created_at"

type SortParams struct {
	Fields []SortField
}

type SortField struct {
	Name string
	Dir  SortDirection
}

func TruncateAll(conn *storage.Connection) error {
	return conn.Transaction(func(tx *storage.Connection) error {
		tables := []string{
			(&pop.Model{Value: User{}}).TableName(),
			(&pop.Model{Value: RefreshToken{}}).TableName(),
			(&pop.Model{Value: AuditLogEntry{}}).TableName(),
			(&pop.Model{Value: Instance{}}).TableName(),
			(&pop.Model{Value: SSOProvider{}}).TableName(),
			(&pop.Model{Value: SSODomain{}}).TableName(),
			(&pop.Model{Value: SAMLProvider{}}).TableName(),
		}

		for _, tableName := range tables {
			if err := tx.RawQuery("TRUNCATE " + tableName + " CASCADE").Exec(); err != nil {
				return err
			}
		}

		return nil
	})
}
