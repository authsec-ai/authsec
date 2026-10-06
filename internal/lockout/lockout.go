// Package lockout counts failed sign-in and second-factor attempts per
// account in the database and locks the account for a while after too many
// (AS-034, AS-004).
//
// Counters live in auth_lockouts (migration 065), keyed by (workspace_id,
// kind, subject), and are updated with one atomic INSERT ... ON CONFLICT ...
// RETURNING, so concurrent attempts on several replicas cannot race past the
// threshold. There is deliberately no Redis: rate state stays in the
// database (standing project rule).
//
// Rule: an account is locked for AUTH_LOCKOUT_DURATION (default 15m) once it
// has AUTH_LOCKOUT_MAX_FAILURES (default 5) failures within
// AUTH_LOCKOUT_WINDOW (default 15m). While locked every attempt is refused
// before the credential is checked, so a correct guess during the lock does
// not succeed. A success resets the counter. A lock expires on its own.
package lockout

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/google/uuid"
)

// Kind separates counters for different credentials of one account.
type Kind string

const (
	AdminPassword   Kind = "admin_password"
	EndUserPassword Kind = "enduser_password"
	TOTP            Kind = "totp"
	SMS             Kind = "sms"
	OTP             Kind = "otp"
)

// Policy holds the thresholds.
type Policy struct {
	MaxFailures int
	Window      time.Duration
	Duration    time.Duration
}

// CurrentPolicy reads the thresholds from the environment.
func CurrentPolicy() Policy {
	p := Policy{MaxFailures: 5, Window: 15 * time.Minute, Duration: 15 * time.Minute}
	if v, err := strconv.Atoi(os.Getenv("AUTH_LOCKOUT_MAX_FAILURES")); err == nil && v > 0 {
		p.MaxFailures = v
	}
	if v, err := time.ParseDuration(os.Getenv("AUTH_LOCKOUT_WINDOW")); err == nil && v > 0 {
		p.Window = v
	}
	if v, err := time.ParseDuration(os.Getenv("AUTH_LOCKOUT_DURATION")); err == nil && v > 0 {
		p.Duration = v
	}
	return p
}

// Subject normalises an account key (an email or a user id).
func Subject(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func scoped(ctx context.Context, ws uuid.UUID) context.Context {
	return tenancy.WithContext(ctx, tenancy.Context{WorkspaceID: ws, PrincipalKind: "lockout"})
}

// Locked reports whether the account is locked now, and until when.
// A database error is reported as locked (fail closed).
func Locked(ctx context.Context, db *sql.DB, ws uuid.UUID, kind Kind, subject string) (bool, time.Time, error) {
	if db == nil || ws == uuid.Nil || subject == "" {
		return false, time.Time{}, nil
	}
	var until sql.NullTime
	err := tenancy.QueryRowContext(scoped(ctx, ws), db, `
		SELECT locked_until FROM auth_lockouts
		 WHERE workspace_id = $1 AND kind = $2 AND subject = $3 AND locked_until > now()`,
		[]interface{}{string(kind), Subject(subject)}, &until)
	if err == tenancy.ErrNotFound {
		return false, time.Time{}, nil
	}
	if err != nil {
		return true, time.Now().Add(time.Minute), err
	}
	return until.Valid, until.Time, nil
}

// Fail records one failed attempt and reports whether the account is now
// locked, and until when.
func Fail(ctx context.Context, db *sql.DB, ws uuid.UUID, kind Kind, subject string) (bool, time.Time, error) {
	if db == nil || ws == uuid.Nil || subject == "" {
		return false, time.Time{}, nil
	}
	p := CurrentPolicy()
	var failures int
	var until sql.NullTime
	// A counter restarts when its window has passed or its lock has expired.
	err := tenancy.QueryRowContext(scoped(ctx, ws), db, `
		INSERT INTO auth_lockouts AS l (workspace_id, kind, subject, failures, window_started_at, locked_until, updated_at)
		VALUES ($1, $2, $3, 1, now(),
		        CASE WHEN 1 >= $4 THEN now() + make_interval(secs => $5) END, now())
		ON CONFLICT (workspace_id, kind, subject) DO UPDATE SET
		  failures = CASE WHEN l.window_started_at < now() - make_interval(secs => $6)
		                    OR (l.locked_until IS NOT NULL AND l.locked_until <= now())
		                  THEN 1 ELSE l.failures + 1 END,
		  window_started_at = CASE WHEN l.window_started_at < now() - make_interval(secs => $6)
		                             OR (l.locked_until IS NOT NULL AND l.locked_until <= now())
		                           THEN now() ELSE l.window_started_at END,
		  locked_until = CASE
		      WHEN (CASE WHEN l.window_started_at < now() - make_interval(secs => $6)
		                   OR (l.locked_until IS NOT NULL AND l.locked_until <= now())
		                 THEN 1 ELSE l.failures + 1 END) >= $4
		        THEN now() + make_interval(secs => $5)
		      WHEN l.locked_until IS NOT NULL AND l.locked_until <= now() THEN NULL
		      ELSE l.locked_until END,
		  updated_at = now()
		WHERE l.workspace_id = $1
		RETURNING failures, locked_until`,
		[]interface{}{string(kind), Subject(subject), p.MaxFailures, p.Duration.Seconds(), p.Window.Seconds()},
		&failures, &until)
	if err != nil {
		return false, time.Time{}, err
	}
	if until.Valid && until.Time.After(time.Now()) {
		return true, until.Time, nil
	}
	return false, time.Time{}, nil
}

// Succeed clears the account's counter.
func Succeed(ctx context.Context, db *sql.DB, ws uuid.UUID, kind Kind, subject string) error {
	if db == nil || ws == uuid.Nil || subject == "" {
		return nil
	}
	_, err := tenancy.ExecContext(scoped(ctx, ws), db,
		`DELETE FROM auth_lockouts WHERE workspace_id = $1 AND kind = $2 AND subject = $3`,
		string(kind), Subject(subject))
	return err
}

// RetryAfterSeconds is the Retry-After value for a lock that ends at until.
func RetryAfterSeconds(until time.Time) string {
	s := int(time.Until(until).Seconds()) + 1
	if s < 1 {
		s = 1
	}
	return strconv.Itoa(s)
}

// Message is the client-facing refusal for a locked account.
const Message = "too many failed attempts; this account is temporarily locked, try again later"
