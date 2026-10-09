package services

import (
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// The ENTITLEMENT arm of policy enforcement — phase 2 of
// ENFORCEMENT-ARCHITECTURE.md §7.
//
// Everything here changes scopes and bindings in the control plane. Nothing
// reaches a cluster, nothing can be reverted by a reconciler, and every effect is
// instantly reversible by editing the policy. That is why this arm goes live first
// while the cluster arm is still computing plans.

/* ------------------------------ role ceiling ----------------------------- */

// applyRoleCeiling narrows an agent's bindings to the policy's ceiling role.
//
// "Narrowing scope" cannot be done by editing a list: role_bindings carries a
// role_id, and scopes are derived from role -> role_permissions -> permissions.
// (scope_type/scope_id on a binding is the resource server it applies to, not an
// OAuth scope.) So narrowing means REBINDING to a role that grants strictly less.
//
// Which makes the subset check the whole safety property. A policy naming a WIDER
// role would otherwise be a grant, and PG-5 is absolute: governance can narrow,
// never widen. A ceiling that is not a subset is refused and recorded, not applied.
func (m *agentPolicyManager) applyRoleCeiling(tx *gorm.DB, workspaceID uuid.UUID,
	agent *models.DiscoveredAgent, ceilingRoleID uuid.UUID) (changed int, detail string, err error) {

	// The agent's live bindings, read through the enforcement chain rather than a
	// copy of it (PG-7).
	type binding struct {
		ID       uuid.UUID
		RoleID   uuid.UUID
		RoleName string
	}
	var bindings []binding
	err = tx.Raw(`
		SELECT rb.id, rb.role_id, ro.name AS role_name
		  FROM role_bindings rb
		  JOIN roles ro ON ro.id = rb.role_id
		  JOIN service_accounts sa ON sa.id = rb.service_account_id
		 WHERE sa.workspace_id = ?
		   AND sa.oauth_client_id = ?`,
		workspaceID, agent.MatchedClientID).Scan(&bindings).Error
	if err != nil {
		return 0, "", fmt.Errorf("read bindings for agent %s: %w", agent.ID, err)
	}
	if len(bindings) == 0 {
		return 0, "agent holds no role bindings", nil
	}

	ceiling, err := rolePermissionIDs(tx, ceilingRoleID)
	if err != nil {
		return 0, "", err
	}

	var refusals []string
	for _, b := range bindings {
		if b.RoleID == ceilingRoleID {
			continue // already at the ceiling
		}
		current, perr := rolePermissionIDs(tx, b.RoleID)
		if perr != nil {
			return changed, "", perr
		}
		// The ceiling must grant a SUBSET of what is held. Anything else is a widen
		// wearing a ceiling's clothes.
		if extra := notSubset(ceiling, current); len(extra) > 0 {
			refusals = append(refusals, fmt.Sprintf(
				"role %s would ADD %d permission(s) not held via %s: refusing to widen",
				ceilingRoleID, len(extra), b.RoleName))
			continue
		}
		if err := tx.Exec(`UPDATE role_bindings SET role_id = ?, updated_at = now() WHERE id = ?`,
			ceilingRoleID, b.ID).Error; err != nil {
			return changed, "", fmt.Errorf("narrow binding %s: %w", b.ID, err)
		}
		changed++
	}
	return changed, strings.Join(refusals, "; "), nil
}

// rolePermissionIDs reads a role's permission set from the live chain.
func rolePermissionIDs(tx *gorm.DB, roleID uuid.UUID) (map[uuid.UUID]bool, error) {
	var ids []uuid.UUID
	if err := tx.Raw(`SELECT permission_id FROM role_permissions WHERE role_id = ?`,
		roleID).Scan(&ids).Error; err != nil {
		return nil, fmt.Errorf("read permissions for role %s: %w", roleID, err)
	}
	out := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// notSubset returns the members of `candidate` absent from `held`. Empty means the
// candidate grants nothing new, so binding to it can only narrow.
func notSubset(candidate, held map[uuid.UUID]bool) []uuid.UUID {
	var extra []uuid.UUID
	for id := range candidate {
		if !held[id] {
			extra = append(extra, id)
		}
	}
	return extra
}

/* ------------------------------ expiry: revoke --------------------------- */

// revokeGrantsForAgent makes an agent's grants lapse NOW.
//
// It deliberately does NOT revoke anything itself. PG-6 says revocation has exactly
// one implementation, and that implementation is the expiry worker: close the
// provenance, kill live tokens, delete the binding, in one transaction. Writing a
// second one here would mean two places that must stay in step forever, and the
// second would inevitably drift.
//
// So this shortens the grant and lets the existing sweeper do the work on its next
// pass (1m). Shortening is itself a narrowing, which PG-5 explicitly permits.
//
// is_standing is cleared too: FindLapsedGrants skips standing grants by design, so a
// policy revoking one would otherwise be silently ignored — the worst outcome, since
// the operator would believe it was handled.
func revokeGrantsForAgent(tx *gorm.DB, workspaceID, agentID uuid.UUID,
	reason string) (int64, error) {

	res := tx.Exec(`
		UPDATE entitlement_provenance
		   SET expires_at  = now(),
		       is_standing = false,
		       updated_at  = now()
		 WHERE workspace_id = ?
		   AND discovered_agent_id = ?
		   AND revoked_at IS NULL
		   AND (expires_at IS NULL OR expires_at > now())`,
		workspaceID, agentID)
	if res.Error != nil {
		return 0, fmt.Errorf("lapse grants for agent %s: %w", agentID, res.Error)
	}
	return res.RowsAffected, nil
}

/* ------------------------------- the arm --------------------------------- */

// entitlementOutcome is what applying the entitlement arm to one agent did.
type entitlementOutcome struct {
	Narrowed int
	Lapsed   int64
	Refusal  string
}

// applyEntitlementArm executes the control-plane half of a policy for one agent.
//
// One transaction per agent, not per pass: an agent must never end up narrowed but
// not recorded, and one agent's failure must not roll back every other agent's
// correctly applied change.
func (m *agentPolicyManager) applyEntitlementArm(workspaceID uuid.UUID,
	agent *models.DiscoveredAgent, eff *EffectivePolicy,
	expiredRevoke []*models.AgentPolicy) (entitlementOutcome, error) {

	var out entitlementOutcome
	err := m.db.Transaction(func(tx *gorm.DB) error {
		// Narrowing first: if a grant is about to lapse anyway, narrowing it in the
		// same pass is harmless, and doing it in the other order would narrow a
		// binding the sweeper is about to delete.
		if eff != nil && eff.RoleCeilingID != nil && agent.MatchedClientID != nil {
			n, detail, err := m.applyRoleCeiling(tx, workspaceID, agent, *eff.RoleCeilingID)
			if err != nil {
				return err
			}
			out.Narrowed = n
			out.Refusal = detail
		}
		for _, p := range expiredRevoke {
			n, err := revokeGrantsForAgent(tx, workspaceID, agent.ID,
				"agent policy "+p.Name+" expired: "+p.Reason)
			if err != nil {
				return err
			}
			out.Lapsed += n
		}
		return nil
	})
	return out, err
}

/* --------------------------- scope ceiling: report ----------------------- */

// evaluateScopeCeiling reports scopes an agent holds that a policy's ceiling does
// not allow.
//
// It does NOT narrow, and that is a limitation worth stating rather than hiding.
// Scopes are derived from a role's permissions, so honouring an arbitrary scope
// ceiling would mean synthesising a role that grants exactly those scopes — the
// system would be inventing entitlements to satisfy a restriction, which is exactly
// the widen PG-5 forbids, arrived at from the other direction.
//
// So a scope ceiling is evaluated and surfaced. Acting on it is a human decision:
// bind a narrower role (role_ceiling_id), or revoke.
func (m *agentPolicyManager) evaluateScopeCeiling(workspaceID uuid.UUID,
	agent *models.DiscoveredAgent, allowed []string) ([]string, error) {

	if len(allowed) == 0 || agent.MatchedClientID == nil {
		return nil, nil
	}
	permitted := map[string]bool{}
	for _, s := range allowed {
		permitted[strings.TrimSpace(s)] = true
	}

	// The live chain: binding -> role -> permissions -> the scopes that carry them.
	var held []string
	err := m.db.Raw(`
		SELECT DISTINCT os.scope_string
		  FROM role_bindings rb
		  JOIN service_accounts sa ON sa.id = rb.service_account_id
		  JOIN role_permissions rp ON rp.role_id = rb.role_id
		  JOIN oauth_scope_permissions osp ON osp.permission_id = rp.permission_id
		  JOIN oauth_scopes os ON os.id = osp.scope_id
		 WHERE sa.workspace_id = ? AND sa.oauth_client_id = ?`,
		workspaceID, agent.MatchedClientID).Scan(&held).Error
	if err != nil {
		return nil, fmt.Errorf("resolve held scopes for agent %s: %w", agent.ID, err)
	}

	var over []string
	for _, s := range held {
		if !permitted[s] {
			over = append(over, s)
		}
	}
	return over, nil
}

// policyReason builds the audit string a lapsed grant carries.
func policyReason(p *models.AgentPolicy, at time.Time) string {
	r := fmt.Sprintf("agent policy %q expired at %s", p.Name, at.UTC().Format(time.RFC3339))
	if p.Reason != "" {
		r += ": " + p.Reason
	}
	return r
}
