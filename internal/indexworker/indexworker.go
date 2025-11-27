package indexworker

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	pkgerrors "github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
)

// ErrAdvisoryLockAlreadyAcquired is returned when another process already holds the advisory lock
var ErrAdvisoryLockAlreadyAcquired = errors.New("advisory lock already acquired by another process")
var ErrExtensionNotFound = errors.New("extension not found")

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeSkipped Outcome = "skipped"
)

// CreateIndexes ensures that the necessary indexes on the users table exist.
// If the indexes already exist and are valid, it skips creation.
// It uses a Postgres advisory lock to prevent concurrent index creation
// by multiple processes.
// Returns an error either from index creation failure (partial or complete) or if the advisory lock
// could not be acquired.
func CreateIndexes(ctx context.Context, config *conf.GlobalConfiguration, le *logrus.Entry) error {
	if config.DB.Driver == "" && config.DB.URL != "" {
		u, err := url.Parse(config.DB.URL)
		if err != nil {
			le.Fatalf("Error parsing db connection url: %+v", err)
		}
		config.DB.Driver = u.Scheme
	}

	u, _ := url.Parse(config.DB.URL)
	processedUrl := config.DB.URL
	if len(u.Query()) != 0 {
		processedUrl = fmt.Sprintf("%s&application_name=auth_index_worker", processedUrl)
	} else {
		processedUrl = fmt.Sprintf("%s?application_name=auth_index_worker", processedUrl)
	}
	deets := &pop.ConnectionDetails{
		Dialect: config.DB.Driver,
		URL:     processedUrl,
	}
	deets.Options = map[string]string{
		"Namespace": config.DB.Namespace,
	}

	db, err := pop.NewConnection(deets)
	if err != nil {
		log.Fatalf("Error opening db connection: %+v", err)
	}
	defer db.Close()

	if err := db.Open(); err != nil {
		log.Fatalf("Error checking database connection: %+v", err)
	}
	db = db.WithContext(ctx)

	// Try to obtain advisory lock to ensure only one index worker is creating indexes at a time
	lockName := "auth_index_worker"
	var lockAcquired bool
	lockQuery := fmt.Sprintf("SELECT pg_try_advisory_lock(hashtext('%s')::bigint)", lockName)

	if err := db.RawQuery(lockQuery).First(&lockAcquired); err != nil {
		le.WithFields(logrus.Fields{
			"outcome": OutcomeFailure,
			"code":    "advisory_lock_acquisition_failed",
		}).WithError(err).Error("Failed to attempt advisory lock acquisition")
		return err
	}

	if !lockAcquired {
		le.WithFields(logrus.Fields{
			"outcome": OutcomeSkipped,
			"code":    "advisory_lock_already_acquired",
		}).Info("Another process is currently holding the advisory lock, skipping index creation")
		return ErrAdvisoryLockAlreadyAcquired
	}

	le.Debug("Successfully acquired advisory lock for index creation")

	// Ensure lock is released on function exit
	defer func() {
		unlockQuery := fmt.Sprintf("SELECT pg_advisory_unlock(hashtext('%s')::bigint)", lockName)
		var unlocked bool
		if err := db.RawQuery(unlockQuery).First(&unlocked); err != nil {
			if ctx.Err() != nil {
				le.Debug("Context cancelled, advisory lock will be released upon session termination")
			} else {
				le.WithError(err).Error("Failed to release advisory lock")
			}
		} else if unlocked {
			le.Debug("Successfully released advisory lock")
		} else {
			le.Debug("Advisory lock was not held when attempting to release")
		}
	}()

	// Ensure either auth_trgm or pg_trgm extension is installed
	extName, err := ensureTrgmExtension(db, config.DB.Namespace, le)
	if err != nil {
		le.WithFields(logrus.Fields{
			"outcome": OutcomeFailure,
			"code":    "trgm_extension_unavailable",
		}).WithError(err).Error("Failed to ensure trgm extension is available")
		return err
	}

	// Look up which schema the trgm extension is installed in
	trgmSchema, err := getTrgmExtensionSchema(db, extName)
	if err != nil {
		le.WithFields(logrus.Fields{
			"outcome":   OutcomeFailure,
			"code":      "extension_schema_not_found",
			"extension": extName,
		}).WithError(err).Error("Failed to find extension schema")
		return ErrExtensionNotFound
	}

	indexes := getUsersIndexes(config.DB.Namespace, trgmSchema)
	indexNames := make([]string, len(indexes))
	for i, idx := range indexes {
		indexNames[i] = idx.name
	}

	// Check existing indexes and their statuses. If all exist and are valid, skip creation.
	existingIndexes, err := getIndexStatuses(db, config.DB.Namespace, indexNames)
	if err != nil {
		le.WithError(err).Warn("Failed to check existing index statuses, proceeding with index creation")
	} else {
		if len(existingIndexes) == len(indexes) {
			allHealthy := true
			for _, idx := range existingIndexes {
				if !idx.IsValid || !idx.IsReady {
					le.WithFields(logrus.Fields{
						"code":        "index_unhealthy",
						"index_name":  idx.IndexName,
						"index_valid": idx.IsValid,
						"index_ready": idx.IsReady,
					}).Info("Index exists but is not healthy")
					allHealthy = false
					break
				}
			}

			if allHealthy {
				le.WithFields(logrus.Fields{
					"outcome":     OutcomeSkipped,
					"code":        "indexes_already_exist",
					"index_count": len(indexes),
				}).Debug("All indexes on auth.users already exist and are ready, skipping index creation")
				return nil
			}
		} else {
			le.WithFields(logrus.Fields{
				"code":           "indexes_missing",
				"existing_count": len(existingIndexes),
				"expected_count": len(indexes),
			}).Info("Found fewer indexes than expected, proceeding with index creation")
		}
	}

	userCount, err := getApproximateUserCount(db, config.DB.Namespace)
	if err != nil {
		le.WithError(err).Warn("Failed to get approximate user count, proceeding with index creation")
	}
	le.WithFields(logrus.Fields{
		"code":       "index_creation_starting",
		"user_count": userCount,
	}).Info("Starting index creation")

	// First, clean up any invalid indexes from previous interrupted attempts
	dropInvalidIndexes(db, le, config.DB.Namespace, indexNames)

	// Create indexes one by one
	var failedIndexes []string
	var succeededIndexes []string
	totalStartTime := time.Now()

	for _, idx := range indexes {
		startTime := time.Now()
		le.WithFields(logrus.Fields{
			"code":       "index_creating",
			"index_name": idx.name,
		}).Info("Creating index")

		if err := db.RawQuery(idx.query).Exec(); err != nil {
			duration := time.Since(startTime).Milliseconds()
			le.WithFields(logrus.Fields{
				"code":        "index_creation_failed",
				"index_name":  idx.name,
				"duration_ms": duration,
			}).WithError(err).Error("Failed to create index")
			failedIndexes = append(failedIndexes, idx.name)
		} else {
			duration := time.Since(startTime).Milliseconds()
			le.WithFields(logrus.Fields{
				"code":        "index_created",
				"index_name":  idx.name,
				"duration_ms": duration,
			}).Info("Successfully created index")
			succeededIndexes = append(succeededIndexes, idx.name)
		}
	}

	totalDuration := time.Since(totalStartTime).Milliseconds()

	if len(failedIndexes) > 0 {
		le.WithFields(logrus.Fields{
			"outcome":           OutcomeFailure,
			"code":              "index_creation_partial_failure",
			"duration_ms":       totalDuration,
			"failed_indexes":    failedIndexes,
			"succeeded_indexes": succeededIndexes,
		}).Error("Index creation completed with some failures")

		return fmt.Errorf("failed to create indexes: %v", failedIndexes)
	}

	le.WithFields(logrus.Fields{
		"outcome":           OutcomeSuccess,
		"code":              "index_creation_completed",
		"duration_ms":       totalDuration,
		"succeeded_indexes": succeededIndexes,
	}).Info("All indexes created successfully")

	return nil
}

// getTrgmExtensionSchema looks up which schema the specified trgm extension is installed in
func getTrgmExtensionSchema(db *pop.Connection, extName string) (string, error) {
	var schema string
	query := `
		SELECT extnamespace::regnamespace::text AS schema_name
		FROM pg_extension
		WHERE extname = $1
		LIMIT 1
	`

	if err := db.RawQuery(query, extName).First(&schema); err != nil {
		return "", fmt.Errorf("failed to find %s extension schema: %w", extName, err)
	}

	return schema, nil
}

// extensionStatus represents the status of an extension from pg_available_extensions
type extensionStatus struct {
	Available bool
	Installed bool
}

// getExtensionStatus checks if an extension is available and/or installed
func getExtensionStatus(db *pop.Connection, extName string) (extensionStatus, error) {
	var result struct {
		Name             *string `db:"name"`
		InstalledVersion *string `db:"installed_version"`
	}

	query := `
		SELECT name, installed_version
		FROM pg_available_extensions
		WHERE name = $1
	`

	if err := db.RawQuery(query, extName).First(&result); err != nil {
		// If no rows returned, extension is not available
		if pkgerrors.Cause(err) == sql.ErrNoRows {
			return extensionStatus{Available: false, Installed: false}, nil
		}
		return extensionStatus{}, fmt.Errorf("failed to check extension status for %s: %w", extName, err)
	}

	return extensionStatus{
		Available: result.Name != nil,
		Installed: result.InstalledVersion != nil,
	}, nil
}

// installExtension installs the specified extension in the provided schema
func installExtension(db *pop.Connection, extName string, schema string) error {
	query := fmt.Sprintf("CREATE EXTENSION IF NOT EXISTS %s SCHEMA %s", extName, schema)
	if err := db.RawQuery(query).Exec(); err != nil {
		return fmt.Errorf("failed to install extension %s in schema %s: %w", extName, schema, err)
	}
	return nil
}

// ensureTrgmExtension ensures that either auth_trgm or pg_trgm extension is installed
// It prefers auth_trgm if available, otherwise falls back to pg_trgm
// Returns the name of the installed extension
func ensureTrgmExtension(db *pop.Connection, authSchema string, le *logrus.Entry) (string, error) {
	authTrgmStatus, err := getExtensionStatus(db, "auth_trgm")
	if err != nil {
		return "", fmt.Errorf("failed to check auth_trgm extension status: %w", err)
	}

	if authTrgmStatus.Available {
		if !authTrgmStatus.Installed {
			le.Debug("auth_trgm extension is available but not installed, installing")

			if err := installExtension(db, "auth_trgm", authSchema); err != nil {
				le.WithFields(logrus.Fields{
					"outcome":   OutcomeFailure,
					"code":      "extension_install_failed",
					"extension": "auth_trgm",
				}).WithError(err).Error("Failed to install auth_trgm extension")

				return "", fmt.Errorf("auth_trgm extension is available but failed to install: %w", err)
			}

			le.WithFields(logrus.Fields{
				"code":      "extension_installed",
				"extension": "auth_trgm",
			}).Info("Successfully installed auth_trgm extension")
		} else {
			le.Debug("auth_trgm extension is already installed")
		}

		return "auth_trgm", nil
	}

	le.Debug("auth_trgm extension is not available, checking pg_trgm")

	pgTrgmStatus, err := getExtensionStatus(db, "pg_trgm")
	if err != nil {
		return "", fmt.Errorf("failed to check pg_trgm extension status: %w", err)
	}

	if !pgTrgmStatus.Available {
		return "", fmt.Errorf("neither auth_trgm nor pg_trgm extensions are available")
	}

	if !pgTrgmStatus.Installed {
		le.Debug("pg_trgm extension is available but not installed, installing")

		if err := installExtension(db, "pg_trgm", "pg_catalog"); err != nil {
			le.WithFields(logrus.Fields{
				"code":      "extension_install_failed",
				"extension": "pg_trgm",
			}).WithError(err).Error("Failed to install pg_trgm extension")

			return "", fmt.Errorf("pg_trgm extension is available but failed to install: %w", err)
		}

		le.WithFields(logrus.Fields{
			"code":      "extension_installed",
			"extension": "pg_trgm",
		}).Info("Successfully installed pg_trgm extension")
	} else {
		le.Debug("pg_trgm extension is already installed")
	}

	return "pg_trgm", nil
}

// getUsersIndexes returns the list of indexes to create on the users table
func getUsersIndexes(namespace, trgmSchema string) []struct {
	name  string
	query string
} {
	// Define indexes to create
	// Note: CONCURRENTLY cannot be used inside a transaction block
	return []struct {
		name  string
		query string
	}{
		// for exact-match queries, sorting, and LIKE '%term%' (trigram) searches on email
		{
			name: "idx_users_email",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email
				ON %q.users USING btree (email);`, namespace),
		},
		{
			name: "idx_users_email_trgm",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_trgm
				ON %q.users USING gin (email %s.gin_trgm_ops);`, namespace, trgmSchema),
		},
		// for range queries and sorting on created_at and last_sign_in_at
		{
			name: "idx_users_created_at_desc",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_created_at_desc
				ON %q.users (created_at DESC);`, namespace),
		},
		{
			name: "idx_users_last_sign_in_at_desc",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_last_sign_in_at_desc
				ON %q.users (last_sign_in_at DESC);`, namespace),
		},
		// trigram indexes on name field in raw_user_meta_data JSONB - enables fast LIKE '%term%' searches
		{
			name: "idx_users_name_trgm",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_name_trgm
				ON %q.users USING gin ((raw_user_meta_data->>'name') %s.gin_trgm_ops)
				WHERE raw_user_meta_data->>'name' IS NOT NULL;`, namespace, trgmSchema),
		},
	}
}

type indexStatus struct {
	IndexName string `db:"index_name"`
	IsValid   bool   `db:"is_valid"`
	IsReady   bool   `db:"is_ready"`
}

// getIndexStatuses checks the status of the given indexes in the specified namespace
func getIndexStatuses(db *pop.Connection, namespace string, indexNames []string) ([]indexStatus, error) {
	indexNamesList := make([]string, len(indexNames))
	for i, idx := range indexNames {
		indexNamesList[i] = fmt.Sprintf("'%s'", idx)
	}
	indexNamesStr := strings.Join(indexNamesList, ",")

	query := fmt.Sprintf(`
		SELECT c.relname as index_name, i.indisvalid as is_valid, i.indisready as is_ready
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = '%s'
		AND c.relname IN (%s)
	`, namespace, indexNamesStr)

	var existingIndexes []indexStatus
	if err := db.RawQuery(query).All(&existingIndexes); err != nil {
		return nil, err
	}

	return existingIndexes, nil
}

// getApproximateUserCount returns an approximate count of users in the users table to avoid a full table scan
func getApproximateUserCount(db *pop.Connection, namespace string) (int64, error) {
	var userCount int64
	countQuery := fmt.Sprintf("SELECT reltuples::BIGINT FROM pg_class WHERE oid = '%q.users'::regclass;", namespace)

	if err := db.RawQuery(countQuery).First(&userCount); err != nil {
		return 0, err
	}

	return userCount, nil
}

// dropInvalidIndexes drops any invalid indexes from previous interrupted attempts
func dropInvalidIndexes(db *pop.Connection, le *logrus.Entry, namespace string, indexNames []string) {
	indexNamesList := make([]string, len(indexNames))
	for i, idx := range indexNames {
		indexNamesList[i] = fmt.Sprintf("'%s'", idx)
	}
	indexNamesStr := strings.Join(indexNamesList, ",")

	// Query the system catalog to find invalid indexes (from interrupted CONCURRENTLY operations)
	cleanupQuery := fmt.Sprintf(`
		SELECT c.relname as index_name
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = '%s'
		AND NOT i.indisvalid
		AND c.relname IN (%s)
	`, namespace, indexNamesStr)

	type invalidIndex struct {
		IndexName string `db:"index_name"`
	}
	var invalidIndexes []invalidIndex
	if err := db.RawQuery(cleanupQuery).All(&invalidIndexes); err == nil && len(invalidIndexes) > 0 {
		for _, idx := range invalidIndexes {
			le.WithFields(logrus.Fields{
				"code":       "dropping_invalid_index",
				"index_name": idx.IndexName,
			}).Info("Dropping invalid index from previous interrupted run")
			dropQuery := fmt.Sprintf("DROP INDEX CONCURRENTLY IF EXISTS %q.%s", namespace, idx.IndexName)
			if err := db.RawQuery(dropQuery).Exec(); err != nil {
				le.WithFields(logrus.Fields{
					"code":       "drop_invalid_index_failed",
					"index_name": idx.IndexName,
				}).WithError(err).Error("Failed to drop invalid index")
			}
		}
	}
}
