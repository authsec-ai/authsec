package admin

import (
	"errors"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/internal/directory/adguid"
	"github.com/authsec-ai/authsec/internal/testdb"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestSyncADUserToMainDBUpdatesLegacyGUIDWithChangedEmail(t *testing.T) {
	gormDB, err := testdb.Prepare("authsec_ad_admin_test", false)
	if errors.Is(err, testdb.ErrUnreachable) {
		t.Skipf("Postgres is not reachable (%v). CI sets DB_HOST, DB_PORT, DB_USER, and DB_PASSWORD; this test migrates authsec_ad_admin_test and must run there.", err)
	}
	require.NoError(t, err)
	sqlDB, err := gormDB.DB()
	require.NoError(t, err)
	config.Database = &database.DBConnection{DB: sqlDB}
	config.DB = gormDB

	raw := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	canonical, err := adguid.Format(raw)
	require.NoError(t, err)
	legacy, err := adguid.LegacyString(raw)
	require.NoError(t, err)
	require.NotEqual(t, canonical, legacy)

	workspaceID := uuid.New()
	userID := uuid.New()
	_, err = sqlDB.Exec(`INSERT INTO workspaces (id, name, email, password_hash, provider, source, status, workspace_domain)
		VALUES ($1, 'AD Admin', $2, '', 'local', 'ad', 'active', $3)`,
		workspaceID, "owner-"+workspaceID.String()+"@example.com", workspaceID.String()+".authsec.test")
	require.NoError(t, err)
	_, err = sqlDB.Exec(`INSERT INTO users (id, email, name, username, workspace_id, external_id, provider, active, is_synced_user)
		VALUES ($1, $2, 'Old Name', 'olduser', $3, $4, 'ad_sync', true, true)`,
		userID, "old-"+userID.String()+"@example.com", workspaceID, legacy)
	require.NoError(t, err)

	asc := &AdminSyncController{
		adminUserRepo: database.NewAdminUserRepository(config.Database),
		workspaceRepo: database.NewWorkspaceRepository(config.Database),
	}
	newEmail := "new-" + userID.String() + "@example.com"
	created, err := asc.syncADUserToMainDB(models.ADUser{
		ObjectGUID:        canonical,
		UserPrincipalName: newEmail,
		DisplayName:       "New Name",
		Email:             newEmail,
		Username:          "newuser",
		IsActive:          true,
	}, workspaceID, nil, nil)
	require.NoError(t, err)
	require.False(t, created, "legacy GUID row was inserted again")

	var count int
	require.NoError(t, sqlDB.QueryRow(`SELECT count(*) FROM users WHERE workspace_id = $1`, workspaceID).Scan(&count))
	require.Equal(t, 1, count)

	var email, externalID string
	require.NoError(t, sqlDB.QueryRow(`SELECT email, external_id FROM users WHERE id = $1`, userID).Scan(&email, &externalID))
	require.Equal(t, newEmail, email)
	require.Equal(t, canonical, externalID)
}
