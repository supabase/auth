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
	Long: "Migrate database structures. This will create new tables and add missing columns and indexes.",
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

	pop.Debug = true
	if globalConfig.Logging.Level != "" {
		level, err := logrus.ParseLevel(globalConfig.Logging.Level)
		if err != nil {
			log.Fatalf("Failed to parse log level: %+v", err)
		}
		log.SetLevel(level)
		if level == logrus.DebugLevel {
			pop.Debug = true
		}
		if level != logrus.DebugLevel {
			var noopLogger = func(lvl logging.Level, s string, args ...interface{}) {}
			pop.SetLogger(noopLogger)
		}
	}

	maskedURL := maskPassword(globalConfig.DB.URL)
	log.Infof("Database URL: %s", maskedURL)
	log.Infof("Using DB namespace: %s", globalConfig.DB.Namespace)

	u, _ := url.Parse(globalConfig.DB.URL)
	processedUrl := globalConfig.DB.URL
	if len(u.Query()) != 0 {
		processedUrl = fmt.Sprintf("%s&application_name=gotrue_migrations", processedUrl)
	} else {
		processedUrl = fmt.Sprintf("%s?application_name=gotrue_migrations", processedUrl)
	}

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
		Options: map[string]string{
			"migration_table_name": "schema_migrations",
			"schema":               globalConfig.DB.Namespace,
			"Namespace":            globalConfig.DB.Namespace,
		},
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

	if globalConfig.DB.Namespace != "" {
		log.Infof("Ensuring schema %s exists", globalConfig.DB.Namespace)
		_, err = db.Store.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", globalConfig.DB.Namespace))
		if err != nil {
			log.Errorf("❌ Error creating schema: %v", err)
		}
	}

	log.Infof("Reading migrations from executable")
	box, err := pop.NewMigrationBox(EmbeddedMigrations, db)
	if err != nil {
		log.Fatalf("%+v", errors.Wrap(err, "creating db migrator"))
	}

	mig := box.Migrator

	if globalConfig.DB.Namespace != "" {
		_, err = db.Store.Exec(fmt.Sprintf("SET search_path TO %s", globalConfig.DB.Namespace))
		if err != nil {
			log.Errorf("❌ Error setting search_path: %v", err)
		}
	}

	log.Infof("Before migration status")
	if log.Level == logrus.DebugLevel {
		err = mig.Status(os.Stdout)
		if err != nil {
			log.Warnf("%+v", errors.Wrap(err, "migration status"))
		}
	}

	mig.SchemaPath = ""

	// Custom migration execution to continue on errors with success and failure counts
	totalCount := 0  // Count of successfully applied migrations
	failedCount := 0 // Count of migrations that failed
	mtn := db.MigrationTableName()
	dialectName := db.Dialect.Name() // Get the dialect name (e.g., "postgres", "mysql", "sqlite3")
	for _, mi := range mig.UpMigrations.Migrations {
		// Filter migrations by dialect compatibility
		if mi.DBType != "all" && mi.DBType != dialectName {
			log.Infof("Skipping migration %s (incompatible dialect: %s, expected: %s)", mi.Version, mi.DBType, dialectName)
			continue
		}

		exists, err := db.Where("version = ?", mi.Version).Exists(mtn)
		if err != nil {
			log.Warnf("Error checking migration %s: %v", mi.Version, err)
			failedCount++ // Increment failed count for check errors
			continue
		}
		if exists {
			log.Infof("Migration %s already applied", mi.Version)
			continue
		}

		log.Infof("Applying migration: %s", mi.Version)
		err = db.Transaction(func(tx *pop.Connection) error {
			err := mi.Run(tx)
			if err != nil {
				return err
			}
			_, err = tx.Store.Exec(fmt.Sprintf("INSERT INTO %s (version) VALUES ('%s')", mtn, mi.Version))
			if err != nil {
				return fmt.Errorf("problem inserting migration version %s: %w", mi.Version, err)
			}
			return nil
		})
		if err != nil {
			log.Errorf("❌ Error applying migration %s: %v", mi.Version, err)
			failedCount++ // Increment failed count for application errors
			continue      // Continue to the next migration despite the error
		}
		totalCount++
		log.Infof("✅ Successfully applied migration: %s", mi.Version)
	}

	log.WithFields(logrus.Fields{
		"success_count": totalCount,
		"failed_count":  failedCount,
	}).Infof("GoTrue migrations completed (some may have been skipped due to errors)")

	log.Infof("After migration status")
	if log.Level == logrus.DebugLevel {
		err = mig.Status(os.Stdout)
		if err != nil {
			log.Warnf("%+v", errors.Wrap(err, "migration status"))
		}
	}
}

func maskPassword(dbURL string) string {
	u, err := url.Parse(dbURL)
	if err != nil {
		return "[unparseable-url]"
	}
	if u.User != nil {
		u.User = url.UserPassword(u.User.Username(), "********")
	}
	return u.String()
}
