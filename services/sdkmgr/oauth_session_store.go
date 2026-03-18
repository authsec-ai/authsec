package sdkmgr

import (
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	authdb "github.com/authsec-ai/authsec/database"
	models "github.com/authsec-ai/authsec/models/sdkmgr"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// OAuthSessionStore manages oauth_sessions across the master and tenant databases.
// Pre-auth sessions live in the master DB; once a tenant_id is known the session
// migrates to the corresponding tenant DB and is removed from master.
type OAuthSessionStore struct{}

// NewOAuthSessionStore creates a new store instance.
func NewOAuthSessionStore() *OAuthSessionStore {
	return &OAuthSessionStore{}
}

// masterDB returns the global GORM instance (master "authsec" DB).
func (s *OAuthSessionStore) masterDB() *gorm.DB {
	return config.DB
}

// tenantDB returns a GORM instance for the given tenant.
func (s *OAuthSessionStore) tenantDB(tenantID string) (*gorm.DB, error) {
	return config.GetTenantGORMDB(tenantID)
}

// InvalidateAllSessions sets is_active=false for every session in the master DB.
// Called once at startup, matching the Python behaviour.
func (s *OAuthSessionStore) InvalidateAllSessions() {
	result := s.masterDB().Model(&models.OAuthSession{}).
		Where("is_active = true").
		Update("is_active", false)
	if result.Error != nil {
		logrus.WithError(result.Error).Error("failed to invalidate master sessions on startup")
	} else {
		logrus.WithField("affected", result.RowsAffected).Info("invalidated all previous master sessions on startup")
	}
}

// SaveSession persists the session. If the session has a tenant_id it goes
// to the tenant DB (and is removed from master if it was there before).
// Otherwise it goes to the master DB.
func (s *OAuthSessionStore) SaveSession(session *models.OAuthSession) error {
	session.Touch()

	if session.TenantID != nil && *session.TenantID != "" {
		return s.saveToTenant(session)
	}
	return s.saveToMaster(session)
}

func (s *OAuthSessionStore) saveToMaster(session *models.OAuthSession) error {
	db := s.masterDB()
	result := db.Save(session) // GORM Save does upsert on primary key
	if result.Error != nil {
		logrus.WithError(result.Error).Error("failed to save session to master DB")
		return result.Error
	}
	logrus.WithField("session_id", session.SessionID).Info("saved session to master DB")
	return nil
}

func (s *OAuthSessionStore) saveToTenant(session *models.OAuthSession) error {
	tenantID := *session.TenantID

	// Check if session exists in master (for migration).
	var existsInMaster bool
	masterDB := s.masterDB()
	var count int64
	masterDB.Model(&models.OAuthSession{}).
		Where("session_id = ?", session.SessionID).
		Count(&count)
	existsInMaster = count > 0

	// Save to tenant DB.
	tdb, err := s.tenantDB(tenantID)
	if err != nil {
		logrus.WithError(err).WithField("tenant_id", tenantID).Error("failed to get tenant DB")
		return err
	}

	if err := tdb.Save(session).Error; err != nil {
		if s.shouldRepairTenantSessionSchema(err) {
			logrus.WithError(err).WithField("tenant_id", tenantID).Warn("detected stale tenant oauth_sessions schema, running tenant migrations and retrying save once")
			if repairErr := s.repairTenantSchema(tenantID); repairErr != nil {
				logrus.WithError(repairErr).WithField("tenant_id", tenantID).Error("failed to repair tenant schema before retrying oauth session save")
				return err
			}

			tdb, err = s.tenantDB(tenantID)
			if err != nil {
				logrus.WithError(err).WithField("tenant_id", tenantID).Error("failed to reopen tenant DB after schema repair")
				return err
			}

			if retryErr := tdb.Save(session).Error; retryErr != nil {
				logrus.WithError(retryErr).WithField("tenant_id", tenantID).Error("failed to save session to tenant DB after schema repair")
				return retryErr
			}
		} else {
			logrus.WithError(err).Error("failed to save session to tenant DB")
			return err
		}
	}
	logrus.WithFields(logrus.Fields{
		"session_id": session.SessionID,
		"tenant_id":  tenantID,
	}).Info("saved session to tenant DB")

	// Upsert user record for dashboard queries.
	s.upsertTenantUser(tdb, session)

	// Migrate: remove from master if it was there.
	if existsInMaster {
		masterDB.Where("session_id = ?", session.SessionID).Delete(&models.OAuthSession{})
		logrus.WithField("session_id", session.SessionID).Info("migrated session from master to tenant DB")
	}

	return nil
}

// upsertTenantUser syncs the authenticated user into the tenant's users table
// so the dashboard has access to user data.
func (s *OAuthSessionStore) upsertTenantUser(tdb *gorm.DB, session *models.OAuthSession) {
	if session.UserID == nil || session.UserEmail == nil {
		return
	}

	userUUID, err := uuid.Parse(*session.UserID)
	if err != nil {
		logrus.WithError(err).WithField("user_id", *session.UserID).Warn("skipping tenant user upsert: invalid user UUID")
		return
	}

	var tenantUUID *uuid.UUID
	if session.TenantID != nil && *session.TenantID != "" {
		if parsed, err := uuid.Parse(*session.TenantID); err == nil {
			tenantUUID = &parsed
		}
	}

	var clientUUID *uuid.UUID
	info := session.GetUserInfoMap()
	if info != nil {
		if cid, ok := info["client_id"].(string); ok && cid != "" {
			if parsed, err := uuid.Parse(cid); err == nil {
				clientUUID = &parsed
			}
		}
	}

	var userName *string
	if info != nil {
		if n, ok := info["name"].(string); ok && n != "" {
			userName = &n
		} else if n, ok := info["full_name"].(string); ok && n != "" {
			userName = &n
		}
	}

	sql := `
		INSERT INTO users (id, client_id, tenant_id, name, email, provider, provider_id,
			active, last_login, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT (id) DO UPDATE SET
			last_login = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP,
			active = EXCLUDED.active,
			name = COALESCE(EXCLUDED.name, users.name),
			provider = COALESCE(EXCLUDED.provider, users.provider),
			provider_id = COALESCE(EXCLUDED.provider_id, users.provider_id)
	`
	result := tdb.Exec(sql,
		userUUID,
		clientUUID,
		tenantUUID,
		userName,
		*session.UserEmail,
		session.Provider,
		session.ProviderID,
		true,
	)
	if result.Error != nil {
		logrus.WithError(result.Error).WithField("user_id", userUUID.String()).Warn("failed to upsert tenant user for oauth session")
	}
}

func (s *OAuthSessionStore) shouldRepairTenantSessionSchema(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, `column "session_id"`) ||
		strings.Contains(msg, "column session_id") ||
		strings.Contains(msg, "created_at") && strings.Contains(msg, "timestamp with time zone")
}

func (s *OAuthSessionStore) repairTenantSchema(tenantID string) error {
	dbService, err := authdb.NewTenantDBService(config.GetDatabase(), config.AppConfig.DBHost, config.AppConfig.DBUser, config.AppConfig.DBPassword, config.AppConfig.DBPort)
	if err != nil {
		return err
	}
	defer dbService.Close()

	if _, err = dbService.CreateTenantDatabase(tenantID); err != nil {
		return err
	}

	tdb, err := s.tenantDB(tenantID)
	if err != nil {
		return err
	}

	return s.normalizeTenantOAuthSessionsSchema(tdb)
}

func (s *OAuthSessionStore) normalizeTenantOAuthSessionsSchema(db *gorm.DB) error {
	statements := []string{
		`ALTER TABLE oauth_sessions
			ADD COLUMN IF NOT EXISTS session_id VARCHAR(36),
			ADD COLUMN IF NOT EXISTS user_email VARCHAR(255),
			ADD COLUMN IF NOT EXISTS user_info JSONB,
			ADD COLUMN IF NOT EXISTS authorization_code TEXT,
			ADD COLUMN IF NOT EXISTS token_expires_at BIGINT,
			ADD COLUMN IF NOT EXISTS last_activity BIGINT,
			ADD COLUMN IF NOT EXISTS oauth_state VARCHAR(255),
			ADD COLUMN IF NOT EXISTS pkce_verifier TEXT,
			ADD COLUMN IF NOT EXISTS pkce_challenge TEXT,
			ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true,
			ADD COLUMN IF NOT EXISTS client_identifier VARCHAR(255),
			ADD COLUMN IF NOT EXISTS org_id VARCHAR(255),
			ADD COLUMN IF NOT EXISTS provider VARCHAR(100),
			ADD COLUMN IF NOT EXISTS provider_id VARCHAR(255),
			ADD COLUMN IF NOT EXISTS accessible_tools JSONB,
			ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255)`,
		`DO $$
		BEGIN
			IF EXISTS (
				SELECT 1
				FROM information_schema.columns
				WHERE table_schema = 'public'
				  AND table_name = 'oauth_sessions'
				  AND column_name = 'id'
			) THEN
				UPDATE oauth_sessions
				SET session_id = id::text
				WHERE session_id IS NULL
				  AND id IS NOT NULL;
			END IF;
		END $$;`,
		`DO $$
		BEGIN
			IF EXISTS (
				SELECT 1
				FROM information_schema.columns
				WHERE table_schema = 'public'
				  AND table_name = 'oauth_sessions'
				  AND column_name = 'created_at'
				  AND data_type = 'timestamp with time zone'
			) THEN
				ALTER TABLE oauth_sessions
					ALTER COLUMN created_at DROP DEFAULT,
					ALTER COLUMN created_at TYPE BIGINT
					USING COALESCE(
						CASE WHEN created_at IS NOT NULL THEN EXTRACT(EPOCH FROM created_at)::BIGINT END,
						last_activity,
						EXTRACT(EPOCH FROM now())::BIGINT
					);
			END IF;
		END $$;`,
		`UPDATE oauth_sessions
		SET last_activity = COALESCE(last_activity, created_at, EXTRACT(EPOCH FROM now())::BIGINT)
		WHERE last_activity IS NULL`,
		`UPDATE oauth_sessions
		SET token_expires_at = EXTRACT(EPOCH FROM expires_at)::BIGINT
		WHERE token_expires_at IS NULL
		  AND expires_at IS NOT NULL`,
		`ALTER TABLE oauth_sessions
			ALTER COLUMN session_id SET NOT NULL`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_sessions_session_id
			ON oauth_sessions(session_id)`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_sessions_client
			ON oauth_sessions(client_identifier) WHERE is_active = true`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_sessions_org_id
			ON oauth_sessions(org_id) WHERE is_active = true`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_sessions_state
			ON oauth_sessions(oauth_state) WHERE is_active = true`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_sessions_tenant
			ON oauth_sessions(tenant_id) WHERE is_active = true`,
	}

	for _, stmt := range statements {
		if err := db.Exec(stmt).Error; err != nil {
			return err
		}
	}

	return nil
}

// GetSession looks up an active session by ID, searching master first then
// all known tenant pools.
func (s *OAuthSessionStore) GetSession(sessionID string) *models.OAuthSession {
	// Search master first.
	var session models.OAuthSession
	result := s.masterDB().
		Where("session_id = ? AND is_active = true", sessionID).
		First(&session)
	if result.Error == nil {
		return &session
	}

	// Search tenant databases.
	return s.searchTenantDBs(func(db *gorm.DB) *models.OAuthSession {
		var ts models.OAuthSession
		if db.Where("session_id = ? AND is_active = true", sessionID).First(&ts).Error == nil {
			return &ts
		}
		return nil
	})
}

// GetSessionByState finds an active session by its oauth_state value.
func (s *OAuthSessionStore) GetSessionByState(oauthState string) *models.OAuthSession {
	var session models.OAuthSession
	result := s.masterDB().
		Where("oauth_state = ? AND is_active = true", oauthState).
		Order("last_activity DESC").
		First(&session)
	if result.Error == nil {
		return &session
	}

	return s.searchTenantDBs(func(db *gorm.DB) *models.OAuthSession {
		var ts models.OAuthSession
		if db.Where("oauth_state = ? AND is_active = true", oauthState).
			Order("last_activity DESC").
			First(&ts).Error == nil {
			return &ts
		}
		return nil
	})
}

// DeleteSession soft-deletes a session (sets is_active=false).
func (s *OAuthSessionStore) DeleteSession(sessionID string) {
	result := s.masterDB().Model(&models.OAuthSession{}).
		Where("session_id = ?", sessionID).
		Update("is_active", false)
	if result.RowsAffected > 0 {
		logrus.WithField("session_id", sessionID).Info("deleted session from master DB")
		return
	}

	// Try tenant databases.
	s.forEachTenantDB(func(db *gorm.DB, _ string) bool {
		r := db.Model(&models.OAuthSession{}).
			Where("session_id = ?", sessionID).
			Update("is_active", false)
		return r.RowsAffected > 0 // stop if found
	})
}

// GetActiveAuthenticatedSessionsCount returns the total count of active,
// authenticated sessions across master and all tenant databases.
func (s *OAuthSessionStore) GetActiveAuthenticatedSessionsCount() int64 {
	now := time.Now().Unix()
	var total int64

	// Clean up expired sessions in master.
	s.masterDB().Model(&models.OAuthSession{}).
		Where("token_expires_at < ?", now).
		Update("is_active", false)

	var masterCount int64
	s.masterDB().Model(&models.OAuthSession{}).
		Where("is_active = true AND access_token IS NOT NULL AND token_expires_at > ?", now).
		Count(&masterCount)
	total += masterCount

	s.forEachTenantDB(func(db *gorm.DB, _ string) bool {
		db.Model(&models.OAuthSession{}).
			Where("token_expires_at < ?", now).
			Update("is_active", false)

		var cnt int64
		db.Model(&models.OAuthSession{}).
			Where("is_active = true AND access_token IS NOT NULL AND token_expires_at > ?", now).
			Count(&cnt)
		total += cnt
		return false // continue iterating
	})

	return total
}

// CleanupClientSessions deactivates all sessions for a given client identifier
// across all databases. Returns total number of affected rows.
func (s *OAuthSessionStore) CleanupClientSessions(clientID string) int64 {
	var total int64

	result := s.masterDB().Model(&models.OAuthSession{}).
		Where("client_identifier = ? AND is_active = true", clientID).
		Update("is_active", false)
	total += result.RowsAffected

	s.forEachTenantDB(func(db *gorm.DB, _ string) bool {
		r := db.Model(&models.OAuthSession{}).
			Where("client_identifier = ? AND is_active = true", clientID).
			Update("is_active", false)
		total += r.RowsAffected
		return false
	})

	logrus.WithFields(logrus.Fields{
		"client_id": clientID,
		"total":     total,
	}).Info("cleaned up client sessions")
	return total
}

// GetActiveSessionsForClient returns all active, authenticated sessions for a
// specific client identifier.
func (s *OAuthSessionStore) GetActiveSessionsForClient(clientID string) []models.OAuthSession {
	now := time.Now().Unix()
	var sessions []models.OAuthSession

	s.masterDB().
		Where("client_identifier = ? AND is_active = true AND access_token IS NOT NULL AND token_expires_at > ?",
			clientID, now).
		Order("last_activity DESC").
		Find(&sessions)

	s.forEachTenantDB(func(db *gorm.DB, _ string) bool {
		var tenantSessions []models.OAuthSession
		db.Where("client_identifier = ? AND is_active = true AND access_token IS NOT NULL AND token_expires_at > ?",
			clientID, now).
			Order("last_activity DESC").
			Find(&tenantSessions)
		sessions = append(sessions, tenantSessions...)
		return false
	})

	return sessions
}

// ---------- helpers for iterating tenant databases ----------

// searchTenantDBs calls fn for each known tenant DB and returns the first
// non-nil result.
func (s *OAuthSessionStore) searchTenantDBs(fn func(*gorm.DB) *models.OAuthSession) *models.OAuthSession {
	tenantIDs, err := s.knownTenantIDs()
	if err != nil {
		logrus.WithError(err).Warn("failed to load tenant IDs during session search")
		return nil
	}

	for _, tid := range tenantIDs {
		tdb, err := s.tenantDB(tid)
		if err != nil {
			logrus.WithError(err).WithField("tenant_id", tid).Warn("skipping tenant DB during session search")
			continue
		}
		if result := fn(tdb); result != nil {
			return result
		}
	}
	return nil
}

// forEachTenantDB iterates known tenant databases. If fn returns true,
// iteration stops early.
func (s *OAuthSessionStore) forEachTenantDB(fn func(db *gorm.DB, tenantID string) bool) {
	tenantIDs, err := s.knownTenantIDs()
	if err != nil {
		logrus.WithError(err).Warn("failed to load tenant IDs for iteration")
		return
	}

	for _, tid := range tenantIDs {
		tdb, err := s.tenantDB(tid)
		if err != nil {
			logrus.WithError(err).WithField("tenant_id", tid).Warn("skipping tenant DB")
			continue
		}
		if fn(tdb, tid) {
			return
		}
	}
}

func (s *OAuthSessionStore) knownTenantIDs() ([]string, error) {
	rows, err := s.masterDB().Raw(`
		SELECT tenant_id::text
		FROM tenants
		WHERE tenant_db IS NOT NULL
		  AND tenant_db != ''
		  AND (status IS NULL OR status = 'active')
	`).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tenantIDs := make([]string, 0, 8)
	for rows.Next() {
		var tenantID string
		if scanErr := rows.Scan(&tenantID); scanErr != nil {
			return nil, scanErr
		}
		if tenantID != "" {
			tenantIDs = append(tenantIDs, tenantID)
		}
	}

	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, rowsErr
	}

	return tenantIDs, nil
}
