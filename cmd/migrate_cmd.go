package cmd

import (
	"embed"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/pop/v6/logging"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var EmbeddedMigrations embed.FS

var migrateCmd = cobra.Command{
	Use:  "migrate",
	Long: "Migrate database strucutures. This will create new tables and add missing columns and indexes.",
	Run:  migrate,
}

func migrate(cmd *cobra.Command, args []string) {
	globalConfig := loadGlobalConfig(cmd.Context())

	if globalConfig.DB.Driver == "" && globalConfig.DB.URL != "" {
		u, err := url.Parse(globalConfig.DB.URL)
		if err != nil {
			logrus.Fatalf("%+v", errors.Wrap(err, "parsing db connection url"))
		}
		globalConfig.DB.Driver = u.Scheme
	}

	log := logrus.StandardLogger()
	log.Infof("Starting migration with driver: %s", globalConfig.DB.Driver)

	// Set to true for more verbose debugging
	pop.Debug = true
	if globalConfig.Logging.Level != "" {
		level, err := logrus.ParseLevel(globalConfig.Logging.Level)
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

	// Log the DB URL (with password masked for security)
	maskedURL := maskPassword(globalConfig.DB.URL)
	log.Infof("Database URL: %s", maskedURL)

	// Log the namespace being used
	log.Infof("Using DB namespace: %s", globalConfig.DB.Namespace)

	u, _ := url.Parse(globalConfig.DB.URL)
	processedUrl := globalConfig.DB.URL
	if len(u.Query()) != 0 {
		processedUrl = fmt.Sprintf("%s&application_name=gotrue_migrations", processedUrl)
	} else {
		processedUrl = fmt.Sprintf("%s?application_name=gotrue_migrations", processedUrl)
	}

	// Add search_path explicitly if namespace is set
	if globalConfig.DB.Namespace != "" {
		if !strings.Contains(processedUrl, "search_path") {
			if strings.Contains(processedUrl, "?") {
				processedUrl = fmt.Sprintf("%s&search_path=%s", processedUrl, globalConfig.DB.Namespace)
			} else {
				processedUrl = fmt.Sprintf("%s?search_path=%s", processedUrl, globalConfig.DB.Namespace)
			}
		}
	}

	log.Infof("Processed DB URL: %s", maskPassword(processedUrl))

	deets := &pop.ConnectionDetails{
		Dialect: globalConfig.DB.Driver,
		URL:     processedUrl,
	}

	// Important: Set schema in connection options
	deets.Options = map[string]string{
		"migration_table_name": "schema_migrations",
		"schema":               globalConfig.DB.Namespace,
		"Namespace":            globalConfig.DB.Namespace,
	}

	log.Infof("Connection options: %v", deets.Options)

	db, err := pop.NewConnection(deets)
	if err != nil {
		log.Fatalf("%+v", errors.Wrap(err, "opening db connection"))
	}
	defer db.Close()

	if err := db.Open(); err != nil {
		log.Fatalf("%+v", errors.Wrap(err, "checking database connection"))
	}

	// Try to create schema if it doesn't exist
	if globalConfig.DB.Namespace != "" {
		log.Infof("Ensuring schema %s exists", globalConfig.DB.Namespace)
		_, err = db.Store.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", globalConfig.DB.Namespace))
		if err != nil {
			log.Warnf("Error creating schema: %v", err)
		}
	}

	log.Infof("Reading migrations from executable")
	box, err := pop.NewMigrationBox(EmbeddedMigrations, db)
	if err != nil {
		log.Fatalf("%+v", errors.Wrap(err, "creating db migrator"))
	}

	mig := box.Migrator

	// Explicitly set the schema for migrations
	if globalConfig.DB.Namespace != "" {
		_, err = db.Store.Exec(fmt.Sprintf("SET search_path TO %s", globalConfig.DB.Namespace))
		if err != nil {
			log.Warnf("Error setting search_path: %v", err)
		}
	}

	log.Infof("Before migration status")

	if log.Level == logrus.DebugLevel {
		err = mig.Status(os.Stdout)
		if err != nil {
			log.Fatalf("%+v", errors.Wrap(err, "migration status"))
		}
	}

	// turn off schema dump
	mig.SchemaPath = ""

	count, err := mig.UpTo(0)
	if err != nil {
		log.Fatalf("%v", errors.Wrap(err, "running db migrations"))
	} else {
		log.WithField("count", count).Infof("GoTrue migrations applied successfully")
	}

	log.Infof("After migration status")

	if log.Level == logrus.DebugLevel {
		err = mig.Status(os.Stdout)
		if err != nil {
			log.Fatalf("%+v", errors.Wrap(err, "migration status"))
		}
	}
}

// Helper function to mask password in database URLs for logging
func maskPassword(dbURL string) string {
	u, err := url.Parse(dbURL)
	if err != nil {
		return "[unparseable-url]"
	}

	if u.User != nil {
		userInfo := u.User.Username()
		if _, hasPassword := u.User.Password(); hasPassword {
			userInfo += ":********"
		}
		u.User = url.UserPassword(u.User.Username(), "********")
	}

	return u.String()
}
