package storage

import (
	"context"
	"net/url"
	"reflect"

	"github.com/gobuffalo/pop/v5"
	"github.com/gobuffalo/pop/v5/columns"
	"github.com/netlify/gotrue/conf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Connection is the interface a storage provider must implement.
type Connection struct {
	*pop.Connection
}

// Dial will connect to that storage engine
func Dial(config *conf.GlobalConfiguration) (*Connection, error) {
	if config.DB.Driver == "" && config.DB.URL != "" {
		u, err := url.Parse(config.DB.URL)
		if err != nil {
			return nil, errors.Wrap(err, "parsing db connection url")
		}
		config.DB.Driver = u.Scheme
	}

	if config.DB.Driver != "postgres" {
		logrus.Warn("DEPRECATION NOTICE: only PostgreSQL is supported by Supabase's GoTrue, will be removed soon")
	}

	db, err := pop.NewConnection(&pop.ConnectionDetails{
		Dialect: config.DB.Driver,
		URL:     config.DB.URL,
		Pool:    config.DB.MaxPoolSize,
	})
	if err != nil {
		return nil, errors.Wrap(err, "opening database connection")
	}
	if err := db.Open(); err != nil {
		return nil, errors.Wrap(err, "checking database connection")
	}
	return &Connection{db}, nil
}

func (c *Connection) Transaction(fn func(*Connection) error) error {
	if c.TX == nil {
		return c.Connection.Transaction(func(tx *pop.Connection) error {
			return fn(&Connection{tx})
		})
	}
	return fn(c)
}

// WithContext returns a new connection with an updated context. This is
// typically used for tracing as the context contains trace span information.
func (c *Connection) WithContext(ctx context.Context) *Connection {
	return &Connection{c.Connection.WithContext(ctx)}
}

func getExcludedColumns(model interface{}, includeColumns ...string) ([]string, error) {
	sm := &pop.Model{Value: model}
	st := reflect.TypeOf(model)
	if st.Kind() == reflect.Ptr {
		_ = st.Elem()
	}

	// get all columns and remove included to get excluded set
	cols := columns.ForStructWithAlias(model, sm.TableName(), sm.As, sm.IDField())
	for _, f := range includeColumns {
		if _, ok := cols.Cols[f]; !ok {
			return nil, errors.Errorf("Invalid column name %s", f)
		}
		cols.Remove(f)
	}

	xcols := make([]string, len(cols.Cols))
	for n := range cols.Cols {
		// gobuffalo updates the updated_at column automatically
		if n == "updated_at" {
			continue
		}
		xcols = append(xcols, n)
	}
	return xcols, nil
}
