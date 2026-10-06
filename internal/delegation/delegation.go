// Package delegation enforces the server-side state of delegated JWT-SVIDs:
// tokens an admin issues to an AI agent on a user's behalf
// (POST /uflow/admin/agents/:id/delegate-token), recorded in
// delegation_tokens. A signature alone does not make such a token valid: it
// must still be the active, unexpired token stored for its agent, so that
// revoking it (or issuing a newer one) takes effect immediately (AS-069).
package delegation

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MaxTTL caps the lifetime of a delegated JWT-SVID.
const MaxTTL = 24 * time.Hour

// clockSkew tolerates small differences between issuer and verifier clocks
// when checking a token's lifetime.
const clockSkew = time.Minute

var (
	// ErrInactive means the token is not the active delegation token of its
	// agent: revoked, superseded by a newer one, expired, or never recorded.
	ErrInactive = errors.New("delegation: token is revoked, superseded or expired")
	// ErrLifetime means the token has no expiry or lives longer than MaxTTL.
	ErrLifetime = errors.New("delegation: token lifetime missing or above the maximum")
)

// CapTTL bounds a requested delegated-token lifetime to (0, MaxTTL].
func CapTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 || ttl > MaxTTL {
		return MaxTTL
	}
	return ttl
}

// Delegated reports whether claims are those of a delegated JWT-SVID, and
// returns the workspace and agent client it speaks for. Delegated tokens carry
// the delegated permissions together with the agent's client_id and
// agent_type (see controllers/admin/agent_controller.go DelegateToken).
func Delegated(claims map[string]interface{}) (workspaceID, clientID string, ok bool) {
	if _, has := claims["permissions"]; !has {
		return "", "", false
	}
	if _, has := claims["agent_type"]; !has {
		return "", "", false
	}
	clientID, _ = claims["client_id"].(string)
	workspaceID, _ = claims["workspace_id"].(string)
	return strings.TrimSpace(workspaceID), strings.TrimSpace(clientID), true
}

// CheckLifetime requires an expiry no further than MaxTTL after issuance.
func CheckLifetime(claims map[string]interface{}) error {
	exp, okExp := numericClaim(claims["exp"])
	iat, okIat := numericClaim(claims["iat"])
	if !okExp || !okIat {
		return ErrLifetime
	}
	if time.Duration(exp-iat)*time.Second > MaxTTL+clockSkew {
		return ErrLifetime
	}
	return nil
}

func numericClaim(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case interface{ Int64() (int64, error) }:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

// CheckActive returns nil only when token is the active, unexpired
// delegation token stored for (workspaceID, clientID). Any lookup failure is
// an error, so callers fail closed.
func CheckActive(ctx context.Context, db *sql.DB, workspaceID, clientID, token string) error {
	if db == nil {
		return fmt.Errorf("delegation: no database to check revocation")
	}
	if workspaceID == "" || clientID == "" || token == "" {
		return ErrInactive
	}
	var stored string
	err := db.QueryRowContext(ctx, `
		SELECT token FROM delegation_tokens -- TENANT-EXEMPT: scoped by workspace_id on the next line
		WHERE workspace_id::text = $1 AND client_id::text = $2
		  AND status = 'active' AND expires_at > now()`,
		workspaceID, clientID).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInactive
	}
	if err != nil {
		return fmt.Errorf("delegation: check revocation: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(token)) != 1 {
		return ErrInactive
	}
	return nil
}

// Verify applies both checks to a verified delegated token.
func Verify(ctx context.Context, db *sql.DB, claims map[string]interface{}, token string) error {
	ws, client, ok := Delegated(claims)
	if !ok {
		return nil
	}
	if err := CheckLifetime(claims); err != nil {
		return err
	}
	return CheckActive(ctx, db, ws, client, token)
}
