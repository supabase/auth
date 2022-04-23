package cmd

import (
	"database/sql"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/netlify/gotrue/conf"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	sqlmigrate "github.com/rubenv/sql-migrate"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var migrateCmd = cobra.Command{
	Use:  "migrate",
	Long: "Migrate database strucutures. This will create new tables and add missing columns and indexes.",
	Run:  migrate,
}

type statusRow struct {
	Id        string
	Migrated  bool
	AppliedAt time.Time
}

func migrate(cmd *cobra.Command, args []string) {
	globalConfig, err := conf.LoadGlobal(configFile)
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %+v", err)
	}
	if globalConfig.DB.Driver == "" && globalConfig.DB.URL != "" {
		u, err := url.Parse(globalConfig.DB.URL)
		if err != nil {
			logrus.Fatalf("%+v", errors.Wrap(err, "parsing db connection url"))
		}
		globalConfig.DB.Driver = u.Scheme
	}

	source := &sqlmigrate.FileMigrationSource{
		Dir: "migrations/",
	}

	db, err := sql.Open("pgx", globalConfig.DB.URL)
	if err != nil {
		logrus.Fatalf("Failed to connect to the database: %v", err.Error())
	}
	defer db.Close()

	// create migrations table for sql-migrate
	_, err = db.Exec(`create table if not exists migrations (
		id text, 
		applied_at timestamptz, 
		primary key (id)
	)`)
	if err != nil {
		logrus.Fatalln(err)
	}

	// check if schema_migrations table exists
	var exists bool
	err = db.QueryRow(
		"select exists(select from pg_tables where schemaname = 'auth' and tablename = 'schema_migrations')",
	).Scan(&exists)
	if err != nil {
		logrus.Fatalln(err)
	}

	migrationFiles, err := ioutil.ReadDir("./migrations/")
	if err != nil {
		logrus.Fatalln(err)
	}

	if exists {
		// get versions from schema_migrations
		res, err := db.Query("select version from schema_migrations")
		if err != nil {
			logrus.Fatalln(err)
		}
		defer res.Close()
		for res.Next() {
			var version string
			if err := res.Scan(&version); err != nil {
				logrus.Fatal(err)
			}
			stmt, err := db.Prepare("insert into migrations(id, applied_at) values($1, NOW()) on conflict do nothing")
			if err != nil {
				logrus.Fatalln(err)
			}
			defer stmt.Close()

			for _, file := range migrationFiles {
				filename := file.Name()
				if strings.HasPrefix(filename, version) {
					// insert into migrations table
					logrus.Infof("Adding %v to migrations table...", filename)
					if _, err := stmt.Exec(filename); err != nil {
						logrus.Fatalln(err)
					} else {
						logrus.Infof("Added %v", filename)
					}
				}
			}
		}
		if err = res.Err(); err != nil {
			log.Fatalln(err)
		}
	}

	sqlmigrate.SetTable("migrations")
	migrations, err := source.FindMigrations()
	if err != nil {
		logrus.Fatalf("Failed to find migrations: %v", err.Error())
	}

	n, err := sqlmigrate.Exec(db, globalConfig.DB.Driver, source, sqlmigrate.Up)
	if err != nil {
		logrus.Fatalf("Failed to run migrations: %v", err.Error())
	}
	logrus.Infof("Applied %d migrations!", n)

	// Inspired by https://github.com/rubenv/sql-migrate/blob/524fb2b1d791d5f4616590f1f54d576f01afa1ae/sql-migrate/command_status.go
	// Renders a table of all applied migrations
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Migration", "Applied"})
	table.SetColWidth(60)

	rows := make(map[string]*statusRow)
	for _, m := range migrations {
		rows[m.Id] = &statusRow{
			Id:       m.Id,
			Migrated: false,
		}
	}
	records, err := sqlmigrate.GetMigrationRecords(db, globalConfig.DB.Driver)
	if err != nil {
		logrus.Fatalf("Failed to retrieve migration records: %v", err.Error())
	}
	for _, r := range records {
		if rows[r.Id] == nil {
			logrus.Warnf("Could not find migration file: %v", r.Id)
			continue
		}

		rows[r.Id].Migrated = true
		rows[r.Id].AppliedAt = r.AppliedAt
	}
	for _, m := range migrations {
		if rows[m.Id] != nil && rows[m.Id].Migrated {
			table.Append([]string{
				m.Id,
				rows[m.Id].AppliedAt.String(),
			})
		} else {
			table.Append([]string{
				m.Id,
				"no",
			})
		}
	}
	table.Render()
}
