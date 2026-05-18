package migration

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----- Integration Test: Multi-Tenant Schema Consistency -----
// Verifies that creating multiple tenant databases produces identical schemas.

func TestIntegration_MultiTenant_SchemaConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	const masterDB = "test_consistency_master"
	const tenantDBOne = "test_consistency_tenant_one"
	const tenantDBTwo = "test_consistency_tenant_two"

	createTestDatabase(t, masterDB)
	createTestDatabase(t, tenantDBOne)
	createTestDatabase(t, tenantDBTwo)
	defer dropTestDatabase(t, masterDB)
	defer dropTestDatabase(t, tenantDBOne)
	defer dropTestDatabase(t, tenantDBTwo)

	masterConn := connectTestDB(t, masterDB)
	defer masterConn.Close()
	createMigrationLogsTable(t, masterConn)

	mDir := testMigrationsDir(t)
	tenantDir := filepath.Join(mDir, "tenant")

	// Create tenant one
	connOne := connectTestDB(t, tenantDBOne)
	defer connOne.Close()
	runnerOne := NewTenantMigrationRunner("tenant-one", connOne, tenantDir, masterConn)
	err := runnerOne.RunMigrations()
	require.NoError(t, err, "tenant one migrations should succeed")

	// Create tenant two
	connTwo := connectTestDB(t, tenantDBTwo)
	defer connTwo.Close()
	runnerTwo := NewTenantMigrationRunner("tenant-two", connTwo, tenantDir, masterConn)
	err = runnerTwo.RunMigrations()
	require.NoError(t, err, "tenant two migrations should succeed")

	t.Run("tables_match", func(t *testing.T) {
		tablesOne := getPublicTableNames(t, tenantDBOne)
		tablesTwo := getPublicTableNames(t, tenantDBTwo)
		assert.Equal(t, tablesOne, tablesTwo,
			"both tenant databases should have identical table sets")
		assert.Greater(t, len(tablesOne), 5, "should have meaningful number of tables")
	})

	t.Run("column_counts_match", func(t *testing.T) {
		for _, table := range []string{"users", "roles", "permissions", "role_bindings", "clients"} {
			colsOne := getPublicColumnCount(t, tenantDBOne, table)
			colsTwo := getPublicColumnCount(t, tenantDBTwo, table)
			assert.Equal(t, colsOne, colsTwo,
				"table %s should have same number of columns in both tenant DBs", table)
		}
	})
}

// ----- Integration Test: RunTenantMigrationsInProcess -----
// Tests the in-process tenant migration helper exposed in db_utils.go.

func TestIntegration_RunTenantMigrationsInProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	const masterDB = "test_inprocess_master"
	const tenantDB = "test_inprocess_tenant"

	createTestDatabase(t, masterDB)
	createTestDatabase(t, tenantDB)
	defer dropTestDatabase(t, masterDB)
	defer dropTestDatabase(t, tenantDB)

	masterConn := connectTestDB(t, masterDB)
	defer masterConn.Close()
	createMigrationLogsTable(t, masterConn)

	mDir := testMigrationsDir(t)
	tenantDir := filepath.Join(mDir, "tenant")

	err := RunTenantMigrationsInProcess(
		"test-inprocess-tenant",
		testDBHost, testDBPort, testDBUser, testDBPassword,
		tenantDB, masterConn, tenantDir,
	)
	require.NoError(t, err, "in-process migrations should succeed")

	// Verify schema
	conn := connectTestDB(t, tenantDB)
	defer conn.Close()

	for _, table := range []string{"users", "roles", "permissions", "role_bindings", "clients", "tenants", "migration_logs"} {
		var exists bool
		err := conn.QueryRow(
			"SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)",
			table,
		).Scan(&exists)
		require.NoError(t, err)
		assert.True(t, exists, "tenant DB should have table: %s", table)
	}
}

// ----- Schema comparison helpers -----

func getPublicTableNames(t *testing.T, dbName string) []string {
	t.Helper()
	db := connectTestDB(t, dbName)
	defer db.Close()
	return queryStringSlice(t, db, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema = 'public'
		ORDER BY table_name
	`)
}

func getPublicColumnCount(t *testing.T, dbName, tableName string) int {
	t.Helper()
	db := connectTestDB(t, dbName)
	defer db.Close()
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1
	`, tableName).Scan(&count)
	require.NoError(t, err)
	return count
}

func getPublicColumnDetails(t *testing.T, dbName, tableName string) []string {
	t.Helper()
	db := connectTestDB(t, dbName)
	defer db.Close()
	return queryStringSlice(t, db, `
		SELECT column_name || ':' || data_type || ':' || COALESCE(character_maximum_length::text, '') || ':' || is_nullable
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1
		ORDER BY column_name
	`, tableName)
}

func getPublicConstraintNames(t *testing.T, dbName string) []string {
	t.Helper()
	db := connectTestDB(t, dbName)
	defer db.Close()
	return queryStringSlice(t, db, `
		SELECT conname FROM pg_constraint
		JOIN pg_namespace ON pg_namespace.oid = connamespace
		WHERE nspname = 'public'
		ORDER BY conname
	`)
}

func getPublicIndexNames(t *testing.T, dbName string) []string {
	t.Helper()
	db := connectTestDB(t, dbName)
	defer db.Close()
	return queryStringSlice(t, db, `
		SELECT indexname FROM pg_indexes
		WHERE schemaname = 'public'
		ORDER BY indexname
	`)
}

func queryStringSlice(t *testing.T, db *sql.DB, query string, args ...interface{}) []string {
	t.Helper()
	rows, err := db.Query(query, args...)
	require.NoError(t, err)
	defer rows.Close()

	var result []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		result = append(result, s)
	}
	return result
}
