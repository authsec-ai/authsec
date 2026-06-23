//go:build integration || smoke

package config

import "sync"

// ResetForTest nullifies all process-global singletons so each test binary
// gets a guaranteed clean load. Called once at the start of TestMain,
// before setting env vars and calling LoadConfig.
//
// Lives in this package (not testsupport) to access unexported globals:
// AppConfig, redisClient, redisOnce.
func ResetForTest() {
	AppConfig = nil
	CacheManager = nil
	AuditLogger = nil
	TokenService = nil
	Database = nil
	DB = nil
	redisClient = nil
	redisOnce = sync.Once{}
}
