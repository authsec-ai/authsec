package database

import (
	"errors"
	"fmt"
	"regexp"
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
