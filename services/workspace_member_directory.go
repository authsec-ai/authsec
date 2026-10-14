package services

import (
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// WorkspaceMemberDirectory answers who the ACTIVE members of a workspace are:
// by user id, and by email. It is the declared seam between Phase 3 ownership
// (SPEC-iga-phase3-policy.md §2.9: "iga_gov_owner_rule maps an AWS tag key to
// a workspace member by email") and the platform's users and memberships.
//
// DECISION (T3.07): it lives in a file of its own, outside the IGA files that
// scripts/ci-iga-isolation-check.sh scans, rather than as an ad-hoc join from
// iga_gov_ownership_service.go into `users`. Matching an owner tag needs the
// email, which only `users` holds; reading it here keeps that coupling to
// one named, read-only lookup that the ownership service depends on through
// this type -- the same reasoning as the isolation check's
// workspace_memberships entry (an authz-adjacent read, never cached).
//
// Active means: a workspace_memberships row of THIS workspace with status
// 'active', and a user row that is not soft-deleted and not deactivated.
type WorkspaceMemberDirectory struct{}

// WorkspaceMember is one active member.
type WorkspaceMember struct {
	UserID uuid.UUID
	Email  string
	Name   string
}

const activeMemberSQL = `
	SELECT u.id AS user_id, u.email, COALESCE(u.name, '') AS name
	  FROM workspace_memberships wm
	  JOIN users u ON u.id = wm.user_id
	 WHERE wm.workspace_id = ? AND wm.status = 'active'
	   AND u.deleted_at IS NULL AND COALESCE(u.active, true)`

// ActiveMembers returns the active members among userIDs, by user id.
func (WorkspaceMemberDirectory) ActiveMembers(db *gorm.DB, ws uuid.UUID, userIDs []uuid.UUID) (map[uuid.UUID]WorkspaceMember, error) {
	out := map[uuid.UUID]WorkspaceMember{}
	if len(userIDs) == 0 {
		return out, nil
	}
	var rows []WorkspaceMember
	if err := db.Raw(activeMemberSQL+` AND u.id IN ?`, ws, userIDs).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.UserID] = r
	}
	return out, nil
}

// MembersByEmail resolves emails (case-insensitive, trimmed) to active
// members. An email that names no active member, or more than one (DECISION:
// ambiguous is unmatched, never a guess), is absent from the result.
func (WorkspaceMemberDirectory) MembersByEmail(db *gorm.DB, ws uuid.UUID, emails []string) (map[string]WorkspaceMember, error) {
	out := map[string]WorkspaceMember{}
	norm := make([]string, 0, len(emails))
	for _, e := range emails {
		if e = NormalizeMemberEmail(e); e != "" {
			norm = append(norm, e)
		}
	}
	if len(norm) == 0 {
		return out, nil
	}
	var rows []WorkspaceMember
	if err := db.Raw(activeMemberSQL+` AND lower(btrim(u.email)) IN ?`, ws, norm).Scan(&rows).Error; err != nil {
		return nil, err
	}
	count := map[string]int{}
	for _, r := range rows {
		k := NormalizeMemberEmail(r.Email)
		count[k]++
		out[k] = r
	}
	for k, n := range count {
		if n > 1 {
			delete(out, k)
		}
	}
	return out, nil
}

// NormalizeMemberEmail is the comparison form of an email: trimmed, lower case.
func NormalizeMemberEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }
