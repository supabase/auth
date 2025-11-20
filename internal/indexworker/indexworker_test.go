package indexworker

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"testing"

	"github.com/gobuffalo/pop/v6"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
)

type IndexWorkerTestSuite struct {
	suite.Suite
	config    *conf.GlobalConfiguration
	db        *storage.Connection
	popDB     *pop.Connection
	namespace string
	logger    *logrus.Entry
}

func (ts *IndexWorkerTestSuite) SetupSuite() {
	// Load test configuration
	config, err := conf.LoadGlobal("../../hack/test.env")
	require.NoError(ts.T(), err)
	ts.config = config
	ts.namespace = config.DB.Namespace
	ts.logger = logrus.NewEntry(logrus.New())
	ts.logger.Logger.SetLevel(logrus.DebugLevel)

	// Setup database connection
	conn, err := storage.Dial(config)
	require.NoError(ts.T(), err)
	ts.db = conn

	// Setup pop connection for internal functions
	deets := &pop.ConnectionDetails{
		Dialect: config.DB.Driver,
		URL:     config.DB.URL,
	}
	deets.Options = map[string]string{
		"Namespace": config.DB.Namespace,
	}
	popConn, err := pop.NewConnection(deets)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), popConn.Open())
	ts.popDB = popConn

	// Ensure we have a clean state for testing
	ts.cleanupIndexes()

	// Ensure trigram extension is available
	err = ts.db.RawQuery("CREATE EXTENSION IF NOT EXISTS pg_trgm").Exec()
	require.NoError(ts.T(), err)
}

func (ts *IndexWorkerTestSuite) TearDownSuite() {
	if ts.db != nil {
		ts.cleanupIndexes()
		ts.db.Close()
	}
	if ts.popDB != nil {
		ts.popDB.Close()
	}
}

func (ts *IndexWorkerTestSuite) SetupTest() {
	// Clean up before each test
	ts.cleanupIndexes()
}

func (ts *IndexWorkerTestSuite) cleanupIndexes() {
	indexes := getUsersIndexes(ts.namespace, ts.namespace)
	for _, idx := range indexes {
		// Drop any existing indexes (valid or invalid)
		dropQuery := fmt.Sprintf("DROP INDEX IF EXISTS %q.%s", ts.namespace, idx.name)
		_ = ts.db.RawQuery(dropQuery).Exec()
	}
}

func (ts *IndexWorkerTestSuite) TestCreateIndexesHappyPath() {
	ctx := context.Background()

	err := CreateIndexes(ctx, ts.config, ts.logger)
	require.NoError(ts.T(), err)

	indexes := getUsersIndexes(ts.namespace, ts.namespace)
	existingIndexes, err := getIndexStatuses(ts.popDB, ts.namespace, getIndexNames(indexes))
	require.NoError(ts.T(), err)

	assert.Equal(ts.T(), len(indexes), len(existingIndexes), "All indexes should be created")
	for _, idx := range existingIndexes {
		assert.True(ts.T(), idx.IsValid, "Index %s should be valid", idx.IndexName)
		assert.True(ts.T(), idx.IsReady, "Index %s should be ready", idx.IndexName)
	}
}

func (ts *IndexWorkerTestSuite) TestGetIndexStatuses() {
	// Create a test index manually
	testIndexName := "test_idx_users_email"
	createQuery := fmt.Sprintf(`CREATE INDEX %s ON %q.users (email)`, testIndexName, ts.namespace)
	err := ts.db.RawQuery(createQuery).Exec()
	require.NoError(ts.T(), err)
	defer func() {
		dropQuery := fmt.Sprintf("DROP INDEX IF EXISTS %q.%s", ts.namespace, testIndexName)
		_ = ts.db.RawQuery(dropQuery).Exec()
	}()

	// existing index should be reported as valid and ready
	statuses, err := getIndexStatuses(ts.popDB, ts.namespace, []string{testIndexName})
	require.NoError(ts.T(), err)
	require.Len(ts.T(), statuses, 1)
	assert.Equal(ts.T(), testIndexName, statuses[0].IndexName)
	assert.True(ts.T(), statuses[0].IsValid)
	assert.True(ts.T(), statuses[0].IsReady)

	// non-existent index should return empty result
	statuses, err = getIndexStatuses(ts.popDB, ts.namespace, []string{"non_existent_index"})
	require.NoError(ts.T(), err)
	assert.Empty(ts.T(), statuses, "Non-existent index should return empty result")
}

func (ts *IndexWorkerTestSuite) TestIdempotency() {
	ctx := context.Background()

	// First run - create all indexes
	err := CreateIndexes(ctx, ts.config, ts.logger)
	require.NoError(ts.T(), err)

	// Get the state after first run
	indexes := getUsersIndexes(ts.namespace, ts.namespace)
	firstRunIndexes, err := getIndexStatuses(ts.popDB, ts.namespace, getIndexNames(indexes))
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), len(indexes), len(firstRunIndexes))

	// Record creation times (we'll use OID as a proxy for creation order/time)
	firstRunOIDs := make(map[string]string)
	for _, idx := range firstRunIndexes {
		var oid string
		query := fmt.Sprintf(`
			SELECT c.oid::text
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = '%s' AND c.relname = '%s'
		`, ts.namespace, idx.IndexName)
		err := ts.db.RawQuery(query).First(&oid)
		require.NoError(ts.T(), err)
		firstRunOIDs[idx.IndexName] = oid
	}

	// Second run - should skip creation (returns nil when indexes already exist)
	err = CreateIndexes(ctx, ts.config, ts.logger)
	require.NoError(ts.T(), err)

	// Get the state after second run
	secondRunIndexes, err := getIndexStatuses(ts.popDB, ts.namespace, getIndexNames(indexes))
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), len(indexes), len(secondRunIndexes))

	// Verify OIDs haven't changed (indexes weren't recreated)
	for _, idx := range secondRunIndexes {
		var oid string
		query := fmt.Sprintf(`
			SELECT c.oid::text
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = '%s' AND c.relname = '%s'
		`, ts.namespace, idx.IndexName)
		err := ts.db.RawQuery(query).First(&oid)
		require.NoError(ts.T(), err)

		originalOID, exists := firstRunOIDs[idx.IndexName]
		require.True(ts.T(), exists, "Index %s should have existed in first run", idx.IndexName)
		assert.Equal(ts.T(), originalOID, oid, "Index %s OID should not change (not recreated)", idx.IndexName)
	}
}

// If an index is removed out of band, it will be created when the method is called
func (ts *IndexWorkerTestSuite) TestOutOfBandIndexRemoval() {
	ctx := context.Background()

	// First, create all indexes
	err := CreateIndexes(ctx, ts.config, ts.logger)
	require.NoError(ts.T(), err)

	// Verify all indexes exist
	indexes := getUsersIndexes(ts.namespace, ts.namespace)
	existingIndexes, err := getIndexStatuses(ts.popDB, ts.namespace, getIndexNames(indexes))
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), len(indexes), len(existingIndexes))

	// Remove one index out of band
	indexToRemove := "idx_users_email"
	dropQuery := fmt.Sprintf("DROP INDEX IF EXISTS %q.%s", ts.namespace, indexToRemove)
	err = ts.db.RawQuery(dropQuery).Exec()
	require.NoError(ts.T(), err)

	// Verify index is gone
	statuses, err := getIndexStatuses(ts.popDB, ts.namespace, []string{indexToRemove})
	require.NoError(ts.T(), err)
	assert.Empty(ts.T(), statuses, "Index should have been dropped")

	// Run CreateIndexes again - should recreate the missing index
	err = CreateIndexes(ctx, ts.config, ts.logger)
	require.NoError(ts.T(), err)

	// Verify all indexes exist again
	existingIndexes, err = getIndexStatuses(ts.popDB, ts.namespace, getIndexNames(indexes))
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), len(indexes), len(existingIndexes), "All indexes should be recreated")

	// Specifically check that the removed index was recreated
	found := false
	for _, idx := range existingIndexes {
		if idx.IndexName == indexToRemove {
			found = true
			assert.True(ts.T(), idx.IsValid, "Recreated index should be valid")
			assert.True(ts.T(), idx.IsReady, "Recreated index should be ready")
			break
		}
	}
	assert.True(ts.T(), found, "The removed index should have been recreated")
}

// Test concurrent access - only one worker should create indexes
func (ts *IndexWorkerTestSuite) TestConcurrentWorkers() {
	ctx := context.Background()

	// Number of concurrent workers
	numWorkers := 3
	var wg sync.WaitGroup
	wg.Add(numWorkers)

	// Track which workers actually created indexes
	results := make(chan error, numWorkers)

	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()

			// Each worker needs its own logger to avoid race conditions
			logger := logrus.NewEntry(logrus.New())
			logger.Logger.SetLevel(logrus.DebugLevel)

			// CreateIndexes returns nil on success or ErrAdvisoryLockAlreadyAcquired
			err := CreateIndexes(ctx, ts.config, logger)
			results <- err
		}(i)
	}

	// Wait for all workers to complete
	wg.Wait()
	close(results)

	// Count how many workers acquired the lock
	lockCount := 0
	lockSkipCount := 0
	for err := range results {
		if err == nil {
			lockCount++
		} else if errors.Is(err, ErrAdvisoryLockAlreadyAcquired) {
			lockSkipCount++
		} else {
			ts.T().Errorf("Unexpected error from CreateIndexes: %v", err)
		}
	}

	// Only one worker should have acquired the lock and created indexes
	assert.Equal(ts.T(), 1, lockCount, "Only one worker should acquire the lock and create indexes")
	assert.Equal(ts.T(), numWorkers-1, lockSkipCount, "Other workers should skip due to lock")

	// Verify all indexes were created successfully
	indexes := getUsersIndexes(ts.namespace, ts.namespace)
	existingIndexes, err := getIndexStatuses(ts.popDB, ts.namespace, getIndexNames(indexes))
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), len(indexes), len(existingIndexes), "All indexes should be created")
}

// Helper function to get index names from index definitions
func getIndexNames(indexes []struct {
	name  string
	query string
}) []string {
	names := make([]string, len(indexes))
	for i, idx := range indexes {
		names[i] = idx.name
	}
	return names
}

// TestCreateIndexesWithInvalidIndexes tests that CreateIndexes can recover from invalid indexes
// This test simulates a scenario where indexes become invalid (e.g., from interrupted CONCURRENT creation)
// and verifies that CreateIndexes properly handles them by dropping and recreating.
func (ts *IndexWorkerTestSuite) TestCreateIndexesWithInvalidIndexes() {
	ctx := context.Background()

	// Step 1: Run CreateIndexes to create all indexes
	err := CreateIndexes(ctx, ts.config, ts.logger)
	require.NoError(ts.T(), err, "Initial CreateIndexes should succeed")

	// Verify all indexes were created and are valid
	indexes := getUsersIndexes(ts.namespace, ts.namespace)
	initialIndexes, err := getIndexStatuses(ts.popDB, ts.namespace, getIndexNames(indexes))
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), len(indexes), len(initialIndexes), "All indexes should be created initially")
	for _, idx := range initialIndexes {
		assert.True(ts.T(), idx.IsValid, "Index %s should be valid initially", idx.IndexName)
		assert.True(ts.T(), idx.IsReady, "Index %s should be ready initially", idx.IndexName)
	}

	// Step 2: Connect as the postgres superuser to manipulate pg_index
	// Parse the existing connection URL and replace credentials with postgres superuser
	manipulatorURL := ts.config.DB.URL
	if u, err := url.Parse(ts.config.DB.URL); err == nil {
		u.User = url.UserPassword("postgres", "root")
		manipulatorURL = u.String()
	}

	manipulatorDeets := &pop.ConnectionDetails{
		Dialect: ts.config.DB.Driver,
		URL:     manipulatorURL,
	}
	manipulatorDeets.Options = map[string]string{
		"Namespace": ts.config.DB.Namespace,
	}

	manipulatorDB, err := pop.NewConnection(manipulatorDeets)
	require.NoError(ts.T(), err, "Should be able to connect as postgres superuser")
	require.NoError(ts.T(), manipulatorDB.Open())
	defer manipulatorDB.Close()

	// Select the first 2 indexes to mark as invalid
	allIndexes := getUsersIndexes(ts.namespace, ts.namespace)
	indexesToInvalidate := []string{allIndexes[0].name, allIndexes[1].name}

	for _, indexName := range indexesToInvalidate {
		// Update pg_index to mark the index as invalid (indisvalid = false) and not ready (indisready = false)
		// This simulates what happens when CREATE INDEX CONCURRENTLY is interrupted
		updateQuery := fmt.Sprintf(`
			UPDATE pg_index
			SET indisvalid = false, indisready = false
			WHERE indexrelid = (
				SELECT c.oid
				FROM pg_class c
				JOIN pg_namespace n ON n.oid = c.relnamespace
				WHERE n.nspname = '%s' AND c.relname = '%s'
			)
		`, ts.namespace, indexName)

		err := manipulatorDB.RawQuery(updateQuery).Exec()
		require.NoError(ts.T(), err, "Should be able to mark index %s as invalid", indexName)

		ts.logger.Infof("Marked index %s as invalid for testing", indexName)
	}

	// Verify the indexes are now invalid
	invalidatedIndexes, err := getIndexStatuses(ts.popDB, ts.namespace, indexesToInvalidate)
	require.NoError(ts.T(), err)
	for _, idx := range invalidatedIndexes {
		assert.False(ts.T(), idx.IsValid, "Index %s should be marked as invalid", idx.IndexName)
		assert.False(ts.T(), idx.IsReady, "Index %s should be marked as not ready", idx.IndexName)
	}

	// Step 3: Re-run CreateIndexes - it should detect and fix the invalid indexes
	err = CreateIndexes(ctx, ts.config, ts.logger)
	require.NoError(ts.T(), err, "CreateIndexes should succeed even with invalid indexes present")

	// Step 4: Verify all indexes are now valid and ready
	finalIndexes, err := getIndexStatuses(ts.popDB, ts.namespace, getIndexNames(indexes))
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), len(indexes), len(finalIndexes), "All indexes should exist after recovery")

	for _, idx := range finalIndexes {
		assert.True(ts.T(), idx.IsValid, "Index %s should be valid after recovery", idx.IndexName)
		assert.True(ts.T(), idx.IsReady, "Index %s should be ready after recovery", idx.IndexName)
	}

	// Check that the previously invalid indexes were fixed
	recoveredIndexes, err := getIndexStatuses(ts.popDB, ts.namespace, indexesToInvalidate)
	require.NoError(ts.T(), err)
	for _, idx := range recoveredIndexes {
		assert.True(ts.T(), idx.IsValid, "Previously invalid index %s should now be valid", idx.IndexName)
		assert.True(ts.T(), idx.IsReady, "Previously invalid index %s should now be ready", idx.IndexName)
	}

	ts.logger.Infof("Successfully recovered from %d invalid indexes", len(indexesToInvalidate))
}

// TestCreateIndexesWithoutTrgmExtension tests that CreateIndexes installs pg_trgm extension
// when it's available but not installed, and then successfully creates indexes.
func (ts *IndexWorkerTestSuite) TestCreateIndexesWithoutTrgmExtension() {
	ctx := context.Background()

	// Drop the pg_trgm extension to simulate it not being installed
	dropExtQuery := "DROP EXTENSION IF EXISTS pg_trgm CASCADE"
	err := ts.db.RawQuery(dropExtQuery).Exec()
	require.NoError(ts.T(), err, "Should be able to drop pg_trgm extension")

	// Verify the extension is dropped
	var extensionExists bool
	checkExtQuery := "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm')"
	err = ts.db.RawQuery(checkExtQuery).First(&extensionExists)
	require.NoError(ts.T(), err)
	assert.False(ts.T(), extensionExists, "pg_trgm extension should not exist")

	// Verify no indexes exist initially
	indexes := getUsersIndexes(ts.namespace, ts.namespace)
	existingIndexes, err := getIndexStatuses(ts.popDB, ts.namespace, getIndexNames(indexes))
	require.NoError(ts.T(), err)
	assert.Empty(ts.T(), existingIndexes, "No indexes should exist initially")

	// Run CreateIndexes - it should install the pg_trgm extension and create indexes
	err = CreateIndexes(ctx, ts.config, ts.logger)
	require.NoError(ts.T(), err, "CreateIndexes should succeed by installing the pg_trgm extension")

	// Verify that pg_trgm is now installed
	err = ts.db.RawQuery(checkExtQuery).First(&extensionExists)
	require.NoError(ts.T(), err)
	assert.True(ts.T(), extensionExists, "pg_trgm extension should have been installed")

	// Verify all indexes were created successfully
	existingIndexes, err = getIndexStatuses(ts.popDB, ts.namespace, getIndexNames(indexes))
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), len(indexes), len(existingIndexes), "All indexes should have been created")

	for _, idx := range existingIndexes {
		assert.True(ts.T(), idx.IsValid, "Index %s should be valid", idx.IndexName)
		assert.True(ts.T(), idx.IsReady, "Index %s should be ready", idx.IndexName)
	}

	// Restore pg_trgm extension for other tests
	createExtQuery := "CREATE EXTENSION IF NOT EXISTS pg_trgm"
	err = ts.db.RawQuery(createExtQuery).Exec()
	require.NoError(ts.T(), err, "Should be able to restore pg_trgm extension")
}

// Run the test suite
func TestIndexWorker(t *testing.T) {
	suite.Run(t, new(IndexWorkerTestSuite))
}
