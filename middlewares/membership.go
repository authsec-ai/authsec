package middlewares

import (
	"database/sql"
	"log"

	"github.com/authsec-ai/authsec/config"
	"github.com/google/uuid"
)

// principalActiveInWorkspace reports whether the token's user may still act
// in the token's workspace: an active, not deleted user of that workspace, or
// an active member of it. Checked on every request so that removing,
// suspending or deactivating someone takes effect immediately instead of when
// their token expires (AS-032, ADR-0001 §4.1).
//
// ok=true with checked=false means the check could not apply (no database,
// or a token without a user id, such as some service tokens).
func principalActiveInWorkspace(workspaceID, userID string) (ok bool, checked bool) {
	ws, err1 := uuid.Parse(workspaceID)
	uid, err2 := uuid.Parse(userID)
	if err1 != nil || err2 != nil {
		return true, false
	}
	conn := config.GetDatabase()
	if conn == nil || conn.DB == nil {
		return true, false
	}
	var active bool
	// The account itself must be active; then a membership row for this
	// workspace, if one exists, decides (so suspending works even in the
	// user's home workspace); otherwise only the home workspace is allowed.
	err := conn.DB.QueryRow(`
		SELECT EXISTS (
		  SELECT 1 FROM users u
		   WHERE u.id = $2 AND COALESCE(u.active, true) AND u.deleted_at IS NULL
		     AND CASE
		           WHEN EXISTS (SELECT 1 FROM workspace_memberships m
		                         WHERE m.workspace_id = $1 AND m.user_id = $2)
		           THEN EXISTS (SELECT 1 FROM workspace_memberships m
		                         WHERE m.workspace_id = $1 AND m.user_id = $2 AND m.status = 'active')
		           ELSE u.workspace_id = $1
		         END)`,
		ws, uid).Scan(&active)
	if err != nil && err != sql.ErrNoRows {
		// Fail closed: a database error must not let a revoked session through.
		log.Printf("auth: membership check failed: %v", err)
		return false, true
	}
	return active, true
}
