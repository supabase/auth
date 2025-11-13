package indexworker

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
)

// ErrAdvisoryLockAlreadyAcquired is returned when another process already holds the advisory lock
var ErrAdvisoryLockAlreadyAcquired = errors.New("advisory lock already acquired by another process")

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
		le.Errorf("Failed to attempt advisory lock acquisition: %+v", err)
		return err
	}

	if !lockAcquired {
		le.Infof("Another process is currently creating indexes. Skipping index creation.")
		return ErrAdvisoryLockAlreadyAcquired
	}

	le.Infof("Successfully acquired advisory lock for index creation.")

	// Ensure lock is released on function exit
	defer func() {
		unlockQuery := fmt.Sprintf("SELECT pg_advisory_unlock(hashtext('%s')::bigint)", lockName)
		var unlocked bool
		if err := db.RawQuery(unlockQuery).First(&unlocked); err != nil {
			if ctx.Err() != nil {
				le.Infof("Context cancelled. Advisory lock will be released upon session termination.")
			} else {
				le.Errorf("Failed to release advisory lock: %+v", err)
			}
		} else if unlocked {
			le.Infof("Successfully released advisory lock.")
		} else {
			le.Warnf("Advisory lock was not held when attempting to release.")
		}
	}()

	indexes := getUsersIndexes(config.DB.Namespace)
	indexNames := make([]string, len(indexes))
	for i, idx := range indexes {
		indexNames[i] = idx.name
	}

	// Check existing indexes and their statuses. If all exist and are valid, skip creation.
	existingIndexes, err := getIndexStatuses(db, config.DB.Namespace, indexNames)
	if err != nil {
		le.Warnf("Failed to check existing indexes: %+v. Proceeding with index creation.", err)
	} else {
		if len(existingIndexes) == len(indexes) {
			allHealthy := true
			for _, idx := range existingIndexes {
				if !idx.IsValid || !idx.IsReady {
					le.Infof("Index %s exists but is not healthy (valid: %v, ready: %v)", idx.IndexName, idx.IsValid, idx.IsReady)
					allHealthy = false
					break
				}
			}

			if allHealthy {
				le.Infof("All %d indexes on auth.users already exist and are ready. Skipping index creation.", len(indexes))
				return nil
			}
		} else {
			le.Infof("Found %d of %d expected indexes. Proceeding with index creation.", len(existingIndexes), len(indexes))
		}
	}

	userCount, err := getApproximateUserCount(db, config.DB.Namespace)
	if err != nil {
		le.Warnf("Failed to get approximate user count: %+v. Proceeding with index creation.", err)
	}
	le.Infof("User count: %d. Starting index creation...", userCount)

	// First, clean up any invalid indexes from previous interrupted attempts
	dropInvalidIndexes(db, le, config.DB.Namespace, indexNames)

	// Create indexes one by one
	var failedIndexes []string
	totalStartTime := time.Now()

	for _, idx := range indexes {
		startTime := time.Now()
		le.Infof("Creating index: %s", idx.name)

		if err := db.RawQuery(idx.query).Exec(); err != nil {
			duration := time.Since(startTime).Milliseconds()

			le.Errorf("Failed to create index %s after %d ms: %v", idx.name, duration, err)
			failedIndexes = append(failedIndexes, idx.name)
		} else {
			duration := time.Since(startTime).Milliseconds()
			le.Infof("Successfully created index %s in %d ms", idx.name, duration)
		}
	}

	totalDuration := time.Since(totalStartTime).Milliseconds()

	if len(failedIndexes) > 0 {
		le.Warnf("Index creation completed in %d ms with some failures: %v", totalDuration, failedIndexes)
		return fmt.Errorf("failed to create indexes: %v", failedIndexes)
	} else {
		le.Infof("All indexes created successfully in %d ms", totalDuration)
	}

	return nil
}

// getUsersIndexes returns the list of indexes to create on the users table
func getUsersIndexes(namespace string) []struct {
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
				ON %q.users USING gin (email gin_trgm_ops);`, namespace),
		},
		// enables exact-match and prefix searches and sorting by phone number
		{
			name: "idx_users_phone_pattern",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_phone_pattern
				ON %q.users USING btree (phone text_pattern_ops);`, namespace),
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
		// trigram indexes on name fields in raw_user_meta_data JSONB - enables fast LIKE '%term%' searches
		{
			name: "idx_users_display_name_trgm",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_display_name_trgm
				ON %q.users USING gin ((raw_user_meta_data->>'display_name') gin_trgm_ops)
				WHERE raw_user_meta_data->>'display_name' IS NOT NULL;`, namespace),
		},
		{
			name: "idx_users_first_name_trgm",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_first_name_trgm
				ON %q.users USING gin ((raw_user_meta_data->>'first_name') gin_trgm_ops)
				WHERE raw_user_meta_data->>'first_name' IS NOT NULL;`, namespace),
		},
		{
			name: "idx_users_last_name_trgm",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_last_name_trgm
				ON %q.users USING gin ((raw_user_meta_data->>'last_name') gin_trgm_ops)
				WHERE raw_user_meta_data->>'last_name' IS NOT NULL;`, namespace),
		},
		{
			name: "idx_users_full_name_trgm",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_full_name_trgm
				ON %q.users USING gin ((raw_user_meta_data->>'full_name') gin_trgm_ops)
				WHERE raw_user_meta_data->>'full_name' IS NOT NULL;`, namespace),
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
			le.Warnf("Dropping invalid index from previous interrupted run: %s", idx.IndexName)
			dropQuery := fmt.Sprintf("DROP INDEX CONCURRENTLY IF EXISTS %q.%s", namespace, idx.IndexName)
			if err := db.RawQuery(dropQuery).Exec(); err != nil {
				le.Errorf("Failed to drop invalid index %s: %v", idx.IndexName, err)
			}
		}
	}
}
