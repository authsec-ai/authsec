// Package logintickets binds the steps of an interactive sign-in together on
// the server.
//
// A ticket is issued only after a first factor (password, OIDC, SAML) has been
// verified, and names exactly one (workspace, user). The anonymous MFA
// endpoints accept a request only for the subject its ticket names; a
// successful second-factor verification marks the ticket; and the callback
// that mints the session token consumes it once. Nothing the client asserts
// (email, workspace_id, mfa_verified) is trusted on its own.
//
// Only a SHA-256 hash of the ticket is stored (table login_tickets, 043).
package logintickets

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// RealmAdmin is a sign-in to the admin console.
	RealmAdmin = "admin"
	// RealmEndUser is a sign-in through hosted (end-user) login.
	RealmEndUser = "enduser"

	// HeaderName carries the ticket on the MFA and callback requests.
	HeaderName = "X-Login-Ticket"
	// ResponseField is the JSON field (and URL query parameter) a first-factor
	// response uses to hand the ticket to the client.
	ResponseField = "login_ticket"

	// TTL bounds the whole MFA step, including first-time passkey enrollment.
	TTL = 15 * time.Minute
)

// ErrInvalid covers unknown, expired, consumed and wrong-realm tickets alike,
// so callers cannot tell them apart.
var ErrInvalid = errors.New("invalid or expired login ticket")

// Ticket is the server-side view of an issued ticket.
type Ticket struct {
	ID            uuid.UUID
	Realm         string
	WorkspaceID   uuid.UUID
	UserID        uuid.UUID
	Email         string
	FirstFactor   string
	MFAVerifiedAt *time.Time
	ExpiresAt     time.Time
}

// MFAVerified reports whether a second factor was verified for this ticket.
func (t *Ticket) MFAVerified() bool { return t.MFAVerifiedAt != nil }

// Issue creates a ticket for a subject whose first factor was just verified
// and returns the opaque value to hand to the client.
func Issue(db *sql.DB, realm string, workspaceID, userID uuid.UUID, email, firstFactor string) (string, error) {
	if realm != RealmAdmin && realm != RealmEndUser {
		return "", errors.New("logintickets: unknown realm")
	}
	if workspaceID == uuid.Nil || userID == uuid.Nil || email == "" {
		return "", errors.New("logintickets: subject is incomplete")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	// TENANT-EXEMPT: pre-session; the ticket records the workspace the first factor verified
	_, err := db.Exec(`
		INSERT INTO login_tickets (ticket_hash, realm, workspace_id, user_id, email, first_factor, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		hash(value), realm, workspaceID, userID, strings.ToLower(email), firstFactor, time.Now().Add(TTL))
	if err != nil {
		return "", err
	}
	return value, nil
}

// Lookup returns a live (unexpired, unconsumed) ticket.
func Lookup(db *sql.DB, value string) (*Ticket, error) {
	if value == "" {
		return nil, ErrInvalid
	}
	t := &Ticket{}
	var mfa sql.NullTime
	err := db.QueryRow(`
		SELECT id, realm, workspace_id, user_id, email, first_factor, mfa_verified_at, expires_at
		  FROM login_tickets
		 WHERE ticket_hash = $1 AND consumed_at IS NULL AND expires_at > now()`,
		hash(value)).Scan(&t.ID, &t.Realm, &t.WorkspaceID, &t.UserID, &t.Email, &t.FirstFactor, &mfa, &t.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	if mfa.Valid {
		t.MFAVerifiedAt = &mfa.Time
	}
	return t, nil
}

// MarkMFAVerified records that a second factor was verified for the ticket.
func MarkMFAVerified(db *sql.DB, value string) error {
	// TENANT-EXEMPT: pre-session lookup by the random ticket's hash
	res, err := db.Exec(`
		UPDATE login_tickets SET mfa_verified_at = now()
		 WHERE ticket_hash = $1 AND consumed_at IS NULL AND expires_at > now()`, hash(value))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrInvalid
	}
	return nil
}

// ConsumeVerified atomically consumes a live, MFA-verified ticket of the given
// realm. A ticket can be consumed once; a second call returns ErrInvalid.
func ConsumeVerified(db *sql.DB, value, realm string) (*Ticket, error) {
	if value == "" {
		return nil, ErrInvalid
	}
	t := &Ticket{}
	var mfa sql.NullTime
	// TENANT-EXEMPT: pre-session lookup by the random ticket's hash
	err := db.QueryRow(`
		UPDATE login_tickets SET consumed_at = now()
		 WHERE ticket_hash = $1 AND realm = $2 AND consumed_at IS NULL
		   AND expires_at > now() AND mfa_verified_at IS NOT NULL
		RETURNING id, realm, workspace_id, user_id, email, first_factor, mfa_verified_at, expires_at`,
		hash(value), realm).Scan(&t.ID, &t.Realm, &t.WorkspaceID, &t.UserID, &t.Email, &t.FirstFactor, &mfa, &t.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	if mfa.Valid {
		t.MFAVerifiedAt = &mfa.Time
	}
	return t, nil
}

func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
