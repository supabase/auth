package cmd

import (
	"fmt"
	"net/url"
	"os"

	"github.com/gobuffalo/pop/v5"
	"github.com/gobuffalo/pop/v5/logging"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var migrateMultiTenantCmd = cobra.Command{
	Use:  "migrate-multi-tenant",
	Long: "Migrate command for the multi-tenant database.",
	Run:  migrateMultiTenant,
}

func migrateMultiTenant(cmd *cobra.Command, args []string) {
	config := loadMultiTenantConfig(cmd.Context())
	u, err := url.Parse(config.URL)
	if err != nil {
		logrus.Fatalf("%+v", errors.Wrap(err, "parsing db connection url"))
	}

	log := logrus.StandardLogger()

	pop.Debug = false
	if config.Logging.Level != "" {
		level, err := logrus.ParseLevel(config.Logging.Level)
		if err != nil {
			log.Fatalf("Failed to parse log level: %+v", err)
		}
		log.SetLevel(level)
		if level == logrus.DebugLevel {
			// Set to true to display query info
			pop.Debug = true
		}
		if level != logrus.DebugLevel {
			var noopLogger = func(lvl logging.Level, s string, args ...interface{}) {
			}
			// Hide pop migration logging
			pop.SetLogger(noopLogger)
		}
	}

	processedUrl := config.URL
	if len(u.Query()) != 0 {
		processedUrl = fmt.Sprintf("%s&application_name=gotrue_multi_tenant_migrations", processedUrl)
	} else {
		processedUrl = fmt.Sprintf("%s?application_name=gotrue_multi_tenant_migrations", processedUrl)
	}
	deets := &pop.ConnectionDetails{
		URL: processedUrl,
	}
	deets.Options = map[string]string{
		"migration_table_name": "schema_migrations",
		"Namespace":            "public",
	}

	db, err := pop.NewConnection(deets)
	if err != nil {
		log.Fatalf("%+v", errors.Wrap(err, "opening db connection"))
	}
	defer db.Close()

	if err := db.Open(); err != nil {
		log.Fatalf("%+v", errors.Wrap(err, "checking database connection"))
	}

	migrationPath := "./migrations/multitenant"
	log.Debugf("Reading migrations from %s", migrationPath)
	mig, err := pop.NewFileMigrator(migrationPath, db)
	if err != nil {
		log.Fatalf("%+v", errors.Wrap(err, "creating db migrator"))
	}
	log.Debugf("before status")

	if log.Level == logrus.DebugLevel {
		err = mig.Status(os.Stdout)
		if err != nil {
			log.Fatalf("%+v", errors.Wrap(err, "migration status"))
		}
	}

	// turn off schema dump
	mig.SchemaPath = ""

	err = mig.Up()
	if err != nil {
		log.Fatalf("%v", errors.Wrap(err, "running db migrations"))
	} else {
		log.Infof("GoTrue multi-tenant migrations applied successfully")
	}

	log.Debugf("after status")

	if log.Level == logrus.DebugLevel {
		err = mig.Status(os.Stdout)
		if err != nil {
			log.Fatalf("%+v", errors.Wrap(err, "migration status"))
		}
	}
}
