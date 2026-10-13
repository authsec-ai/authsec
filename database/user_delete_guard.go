package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// UserHasAuditHistoryCode is the error code returned when a user cannot be
// hard-deleted because audit or approval records still name them.
//
// DECISION (review P0-1, SPEC-iga-phase3-policy.md §6.2 "existing tables are
// referenced only by FK"): the Phase 3 records that name a user as the actor
// -- iga_gov_policy / _version / _validation / _finding_rule / _owner_rule /
// _owner.created_by, iga_gov_approval.decided_by, iga_gov_acceptance.accepted_by,
// iga_gov_owner_review.exception_by, iga_gov_owner_response.user_id,
// iga_gov_deployment.emergency_by, iga_gov_health_report.reported_by,
// iga_gov_settings.updated_by, iga_gov_iac_source.created_by,
// cloud_enforcement_binding.consented_by, workspace_slack_integration.installed_by
// (and the older role_assignment_requests.reviewed_by) -- are ON DELETE NO
// ACTION on purpose: who approved, accepted or consented must survive the
// user. Deleting such a user OUTSIDE a workspace purge is therefore refused,
// and the refusal is this explicit error (HTTP 409, code
// user_has_audit_history) instead of a raw foreign-key violation. The user
// can be deactivated instead. A workspace purge (WorkspaceRepository.
// DeleteTenant) removes the workspace's records first, so its own users are
// no longer named when they are deleted.
const UserHasAuditHistoryCode = "user_has_audit_history"

// UserAuditHistoryError is a refused user delete: Table (via Constraint)
// still names the user.
type UserAuditHistoryError struct {
	Table      string
	Constraint string
	Err        error
}

func (e *UserAuditHistoryError) Error() string {
	return fmt.Sprintf("%s: the user is named by audit records in %s (%s) and cannot be deleted; deactivate the user instead",
		UserHasAuditHistoryCode, e.Table, e.Constraint)
}

func (e *UserAuditHistoryError) Unwrap() error { return e.Err }

// Message is the client-facing explanation.
func (e *UserAuditHistoryError) Message() string {
	return "This user is named in audit records (" + e.Table + ") that must be kept, so the user cannot be deleted. Deactivate the user instead."
}

// usersFKViolation matches PostgreSQL's 23503 message for a DELETE on users
// refused by a referencing row (lib/pq and pgx render the same text).
var usersFKViolation = regexp.MustCompile(`update or delete on table "users" violates foreign key constraint "([^"]+)" on table "([^"]+)"`)

// ClassifyUserDeleteError turns a foreign-key refusal of a DELETE on users
// into *UserAuditHistoryError; any other error (or nil) is returned as is.
// Every NO ACTION / RESTRICT key into users is an actor reference kept for
// audit (the user's own rows cascade), so any such refusal is this case.
func ClassifyUserDeleteError(err error) error {
	if err == nil {
		return nil
	}
	var st interface{ SQLState() string }
	if !errors.As(err, &st) || st.SQLState() != "23503" {
		return err
	}
	m := usersFKViolation.FindStringSubmatch(err.Error())
	if m == nil {
		return err
	}
	return &UserAuditHistoryError{Constraint: m[1], Table: m[2], Err: err}
}

// AsUserAuditHistory reports whether err is (or wraps) a refused user delete.
func AsUserAuditHistory(err error) (*UserAuditHistoryError, bool) {
	var e *UserAuditHistoryError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// UserInAnotherWorkspaceCode is the error code of a refused delete of a user
// that another workspace still refers to (a membership, or one of its rows).
const UserInAnotherWorkspaceCode = "user_in_another_workspace"

// ErrUserInAnotherWorkspace is a refused user delete (or workspace purge):
// a row of another workspace refers to the user. Deleting the user would
// silently change that workspace's data (ON DELETE CASCADE / SET NULL keys
// remove its owners and Slack links, or null its policy owners), or leave
// its membership dangling. The other workspace and its table are not named.
var ErrUserInAnotherWorkspace = errors.New(UserInAnotherWorkspaceCode +
	": another workspace still refers to this user; remove the user there first")

// UsersReferencedByOtherWorkspaces reports whether a row of a workspace other
// than ws refers to any of userIDs: a workspace_memberships row, or a
// single-column foreign key to users(id) from a table with workspace_id.
// (A composite (workspace_id, user_id) key cannot cross workspaces.) It is
// read on the owner connection on purpose: row-level security would hide
// exactly the rows it looks for.
func UsersReferencedByOtherWorkspaces(ctx context.Context, db *sql.DB, ws uuid.UUID, userIDs []uuid.UUID) (bool, error) {
	if len(userIDs) == 0 {
		return false, nil
	}
	ids := make([]string, len(userIDs))
	for i, u := range userIDs {
		ids[i] = u.String()
	}
	// TENANT-EXEMPT: catalog read of the foreign keys into users.
	rows, err := db.QueryContext(ctx, `
		SELECT format('%I.%I', n.nspname, cl.relname), a.attname
		  FROM pg_constraint c
		  JOIN pg_class cl ON cl.oid = c.conrelid
		  JOIN pg_namespace n ON n.oid = cl.relnamespace
		  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
		 WHERE c.contype = 'f' AND c.confrelid = 'public.users'::regclass
		   AND array_length(c.conkey, 1) = 1
		   AND EXISTS (SELECT 1 FROM pg_attribute w
		                WHERE w.attrelid = c.conrelid AND w.attname = 'workspace_id' AND NOT w.attisdropped)`)
	if err != nil {
		return false, fmt.Errorf("list user references: %w", err)
	}
	type ref struct{ table, column string }
	refs := []ref{{"public.workspace_memberships", "user_id"}}
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.table, &r.column); err != nil {
			rows.Close()
			return false, err
		}
		refs = append(refs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	for _, r := range refs {
		var found bool
		// TENANT-EXEMPT: looks for other workspaces' rows naming these users
		// Table and column come from the catalog query above, quoted there.
		q := fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM %s WHERE %s::text = ANY($1::text[]) AND workspace_id::text <> $2::text)`,
			r.table, pq.QuoteIdentifier(r.column))
		if err := db.QueryRowContext(ctx, q, pq.Array(ids), ws.String()).Scan(&found); err != nil {
			return false, fmt.Errorf("check %s.%s: %w", r.table, r.column, err)
		}
		if found {
			return true, nil
		}
	}
	return false, nil
}

// WorkspaceUserIDs lists the users homed in ws.
func WorkspaceUserIDs(ctx context.Context, db *sql.DB, ws uuid.UUID) ([]uuid.UUID, error) {
	// TENANT-EXEMPT: owner-connection read of one workspace's user ids, for
	// UsersReferencedByOtherWorkspaces before a purge.
	rows, err := db.QueryContext(ctx, `SELECT id FROM users WHERE workspace_id = $1`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CheckUsersDeletable is ErrUserInAnotherWorkspace when another workspace
// refers to one of userIDs, nil when they may be deleted from ws.
func CheckUsersDeletable(ctx context.Context, db *sql.DB, ws uuid.UUID, userIDs []uuid.UUID) error {
	refd, err := UsersReferencedByOtherWorkspaces(ctx, db, ws, userIDs)
	if err != nil {
		return err
	}
	if refd {
		return ErrUserInAnotherWorkspace
	}
	return nil
}
