package cmd

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const userCountThreshold = 1000000 // 1 million users

var (
	forceIndexCreation bool
)

var createIndexesCmd = cobra.Command{
	Use:   "create-indexes",
	Short: "Conditionally create indexes based on user count",
	Long: `Check the number of users in the auth.users table and conditionally create indexes.
If user count exceeds the threshold (1,000,000), index creation is skipped.
Use --force to create indexes regardless of user count.`,
	Run: createIndexes,
}

func init() {
	createIndexesCmd.Flags().BoolVar(&forceIndexCreation, "force", false, "Force index creation even if user count exceeds threshold")
}

// default statement timeout for index creation queries
const defaultStatementTimeout = "8h"

func createIndexes(cmd *cobra.Command, args []string) {
	config := loadGlobalConfig(cmd.Context())

	if config.DB.Driver == "" && config.DB.URL != "" {
		u, err := url.Parse(config.DB.URL)
		if err != nil {
			logrus.Fatalf("parsing db connection url: %+v", err)
		}
		config.DB.Driver = u.Scheme
	}

	u, _ := url.Parse(config.DB.URL)
	processedUrl := config.DB.URL
	if len(u.Query()) != 0 {
		processedUrl = fmt.Sprintf("%s&application_name=auth_create_indexes", processedUrl)
	} else {
		processedUrl = fmt.Sprintf("%s?application_name=auth_create_indexes", processedUrl)
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
		log.Fatalf("opening db connection: %+v", err)
	}
	defer db.Close()

	if err := db.Open(); err != nil {
		log.Fatalf("checking database connection: %+v", err)
	}
	ctx := cmd.Context()
	db = db.WithContext(ctx)

	// Count users in auth.users table
	// we perform an approximate count here to avoid a full table scan
	var userCount int64
	countQuery := fmt.Sprintf("SELECT reltuples::BIGINT FROM pg_class WHERE oid = '%q.users'::regclass;", config.DB.Namespace)

	if err := db.RawQuery(countQuery).First(&userCount); err != nil {
		if ctx.Err() != nil {
			logrus.Warnf("Index creation cancelled during user count")
			return
		}
		logrus.Fatalf("Error counting users: %+v", err)
	}

	if userCount > userCountThreshold && !forceIndexCreation {
		logrus.Infof("User count (%d) exceeds threshold (%d). Skipping index creation. Use --force to override.", userCount, userCountThreshold)
		return
	}

	if userCount > userCountThreshold && forceIndexCreation {
		logrus.Warnf("User count (%d) exceeds threshold (%d), but forcing index creation as requested.", userCount, userCountThreshold)
	}

	logrus.Infof("User count: %d. Creating indexes...", userCount)

	// Define indexes to create
	// Note: CONCURRENTLY cannot be used inside a transaction block
	indexes := []struct {
		name  string
		query string
	}{
		// for exact-match queries, sorting, and LIKE '%term%' (trigram) searches on email
		{
			name: "idx_users_email",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email
				ON %q.users USING btree (email);`, config.DB.Namespace),
		},
		{
			name: "idx_users_email_trgm",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_trgm
				ON %q.users USING gin (email gin_trgm_ops);`, config.DB.Namespace),
		},
		// enables exact-match and prefix searches and sorting by phone number
		{
			name: "idx_users_phone_pattern",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_phone_pattern
				ON %q.users USING btree (phone text_pattern_ops);`, config.DB.Namespace),
		},
		// for range queries and sorting on created_at and last_sign_in_at
		{
			name: "idx_users_created_at_desc",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_created_at_desc
				ON %q.users (created_at DESC);`, config.DB.Namespace),
		},
		{
			name: "idx_users_last_sign_in_at_desc",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_last_sign_in_at_desc
				ON %q.users (last_sign_in_at DESC);`, config.DB.Namespace),
		},
		// trigram indexes on name fields in raw_user_meta_data JSONB - enables fast LIKE '%term%' searches
		{
			name: "idx_users_display_name_trgm",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_display_name_trgm
				ON %q.users USING gin ((raw_user_meta_data->>'display_name') gin_trgm_ops)
				WHERE raw_user_meta_data->>'display_name' IS NOT NULL;`, config.DB.Namespace),
		},
		{
			name: "idx_users_first_name_trgm",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_first_name_trgm
				ON %q.users USING gin ((raw_user_meta_data->>'first_name') gin_trgm_ops)
				WHERE raw_user_meta_data->>'first_name' IS NOT NULL;`, config.DB.Namespace),
		},
		{
			name: "idx_users_last_name_trgm",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_last_name_trgm
				ON %q.users USING gin ((raw_user_meta_data->>'last_name') gin_trgm_ops)
				WHERE raw_user_meta_data->>'last_name' IS NOT NULL;`, config.DB.Namespace),
		},
		{
			name: "idx_users_full_name_trgm",
			query: fmt.Sprintf(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_full_name_trgm
				ON %q.users USING gin ((raw_user_meta_data->>'full_name') gin_trgm_ops)
				WHERE raw_user_meta_data->>'full_name' IS NOT NULL;`, config.DB.Namespace),
		},
	}

	// Build list of index names for cleanup query
	indexNamesList := make([]string, len(indexes))
	for i, idx := range indexes {
		indexNamesList[i] = fmt.Sprintf("'%s'", idx.name)
	}
	indexNamesStr := strings.Join(indexNamesList, ",")

	// First, clean up any invalid indexes from previous interrupted attempts
	// Query the system catalog to find invalid indexes (from interrupted CONCURRENTLY operations)
	cleanupQuery := fmt.Sprintf(`
		SELECT c.relname as index_name
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = '%s'
		AND NOT i.indisvalid
		AND c.relname IN (%s)
	`, config.DB.Namespace, indexNamesStr)

	type invalidIndex struct {
		IndexName string `db:"index_name"`
	}
	var invalidIndexes []invalidIndex
	if err := db.RawQuery(cleanupQuery).All(&invalidIndexes); err == nil && len(invalidIndexes) > 0 {
		for _, idx := range invalidIndexes {
			// Check if context was cancelled before dropping each invalid index
			if ctx.Err() != nil {
				logrus.Warnf("Cleanup cancelled, stopping invalid index cleanup")
				return
			}

			logrus.Warnf("Dropping invalid index from previous interrupted run: %s", idx.IndexName)
			dropQuery := fmt.Sprintf("DROP INDEX CONCURRENTLY IF EXISTS %q.%s", config.DB.Namespace, idx.IndexName)
			if err := db.RawQuery(dropQuery).Exec(); err != nil {
				if ctx.Err() != nil {
					logrus.Warnf("Index drop cancelled for %s", idx.IndexName)
					return
				}
				logrus.Errorf("Failed to drop invalid index %s: %v", idx.IndexName, err)
			}
		}
	}

	// Set statement timeout for index creation queries
	setTimeoutQuery := fmt.Sprintf("SET statement_timeout = '%s';", defaultStatementTimeout)
	if err := db.RawQuery(setTimeoutQuery).Exec(); err != nil {
		logrus.Fatalf("Failed to set statement timeout: %v", err)
	}

	// Continue even if some indexes fail
	var failedIndexes []string
	var cancelledIndexes []string
	totalStartTime := time.Now()

	for _, idx := range indexes {
		// Check if context was cancelled before starting each index
		if ctx.Err() != nil {
			logrus.Warnf("Index creation cancelled, stopping at %s", idx.name)
			cancelledIndexes = append(cancelledIndexes, idx.name)
			break
		}

		startTime := time.Now()
		logrus.Infof("Creating index: %s", idx.name)

		if err := db.RawQuery(idx.query).Exec(); err != nil {
			duration := time.Since(startTime).Milliseconds()

			// Check if the error was due to context cancellation
			if ctx.Err() != nil {
				logrus.Warnf("Index creation cancelled for %s after %d ms", idx.name, duration)
				cancelledIndexes = append(cancelledIndexes, idx.name)
				break
			}

			logrus.Errorf("Failed to create index %s after %d ms: %v", idx.name, duration, err)
			failedIndexes = append(failedIndexes, idx.name)
			// Continue with other indexes
		} else {
			duration := time.Since(startTime).Milliseconds()
			logrus.Infof("Successfully created index %s in %d ms", idx.name, duration)
		}
	}

	totalDuration := time.Since(totalStartTime).Milliseconds()

	// reset statement timeout to default (usually 0 = no timeout)
	resetTimeoutQuery := "SET statement_timeout = DEFAULT;"
	if err := db.RawQuery(resetTimeoutQuery).Exec(); err != nil {
		logrus.Errorf("Failed to reset statement timeout: %v", err)
	}

	if len(cancelledIndexes) > 0 {
		// Collect remaining indexes that weren't attempted
		for i, idx := range indexes {
			found := false
			for _, name := range append(failedIndexes, cancelledIndexes...) {
				if name == idx.name {
					found = true
					break
				}
			}
			// Check if index was already successfully created
			if !found && i >= len(indexes)-len(cancelledIndexes) {
				cancelledIndexes = append(cancelledIndexes, idx.name)
			}
		}
		logrus.Warnf("Index creation interrupted after %d ms. Cancelled: %v", totalDuration, cancelledIndexes)
	} else if len(failedIndexes) > 0 {
		logrus.Warnf("Index creation completed in %d ms with some failures: %v", totalDuration, failedIndexes)
	} else {
		logrus.Infof("All indexes created successfully in %d ms", totalDuration)
	}
}
