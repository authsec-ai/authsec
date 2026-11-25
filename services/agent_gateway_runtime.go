package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/internal/agentgateway"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// Gateway revocation (AS-174). Three things keep a stopped agent from being
// served by a gateway:
//
//  1. The stop list. Every live containment (agent_containment in a live
//     state: previewed, containing, contained, partially_contained,
//     releasing) names a cloud identity and, at workload level, workloads.
//     A gateway names its agents by the same AuthSec ids
//     (subject.properties identity_id / workload_id), so a containment
//     becomes stops on those ids: identity level stops the identity and
//     every workload running as it; model level the same for model calls
//     only; workload level the selected workloads. Deny policies that block
//     every target for a named agent are stops too (PolicyStops). The PDP
//     refuses these agents itself (reason agent_stopped, never cached) and
//     the hints hand the list to the gateway, which refuses them before its
//     cache and whatever its fail mode.
//  2. The fail mode and cache cap are AuthSec's, per gateway
//     (agent_gateway.fail_mode, cache_ttl_seconds): the gateway takes the
//     stricter of AuthSec's and its own. Tightening applies at once;
//     loosening is tier 3 (pending_change, a second person approves).
//  3. The hints carry a version (ETag) and are refreshed every 5 s.
//
// Worst case: a containment committed at T is refused by the PDP in this
// process at once (the policy cache is dropped) and in other processes by
// T + agentGatewayPolicyCacheTTL (5 s); a gateway that already cached an
// allow for the agent refuses it locally from its next hints refresh,
// T + hints interval (5 s by default, at most 60 s) + one request
// (<= 5 s timeout), so about 10 s; a gateway that cannot reach AuthSec at
// all stops using its cache 30 s after its last confirmed hints and then
// applies its fail mode.

// gatewayCacheTTL is the cache lifetime handed out: the workspace setting,
// capped by the gateway's own cap.
func gatewayCacheTTL(workspaceTTL, gatewayCap int) int {
	if gatewayCap < workspaceTTL {
		return gatewayCap
	}
	return workspaceTTL
}

type containmentStopRow struct {
	ID          uuid.UUID
	IdentityID  uuid.UUID
	Level       string
	WorkloadIDs pq.StringArray `gorm:"column:workload_ids"`
}

// readContainmentStops lists the stops of the workspace's live containments
// (tx is under RLS for ws).
func readContainmentStops(tx *gorm.DB, ws uuid.UUID) ([]agentgateway.StoppedSubject, error) {
	var rows []containmentStopRow
	if err := tx.Raw(`SELECT id, identity_id, level, workload_ids FROM agent_containment
		WHERE workspace_id = ? AND state IN ? ORDER BY id`, ws, agentcontain.LiveStates).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	var identities []uuid.UUID
	for _, r := range rows {
		if r.Level != agentcontain.LevelWorkload {
			identities = append(identities, r.IdentityID)
		}
	}
	workloadsOf := map[uuid.UUID][]string{}
	if len(identities) > 0 {
		var wls []struct {
			ID         uuid.UUID
			IdentityID uuid.UUID
		}
		if err := tx.Raw(`SELECT id, identity_id FROM cloud_workload WHERE workspace_id = ? AND identity_id IN ?
			ORDER BY id`, ws, identities).Scan(&wls).Error; err != nil {
			return nil, err
		}
		for _, w := range wls {
			workloadsOf[w.IdentityID] = append(workloadsOf[w.IdentityID], w.ID.String())
		}
	}
	var out []agentgateway.StoppedSubject
	for _, r := range rows {
		ref := "containment:" + r.ID.String()
		kind := ""
		if r.Level == agentcontain.LevelModel {
			kind = agentgateway.KindModel
		}
		switch r.Level {
		case agentcontain.LevelWorkload:
			for _, w := range r.WorkloadIDs {
				out = append(out, agentgateway.StoppedSubject{Selector: agentgateway.Selector{WorkloadID: strings.ToLower(w)}, Ref: ref})
			}
		default:
			out = append(out, agentgateway.StoppedSubject{Selector: agentgateway.Selector{IdentityID: r.IdentityID.String()}, Kind: kind, Ref: ref})
			for _, w := range workloadsOf[r.IdentityID] {
				out = append(out, agentgateway.StoppedSubject{Selector: agentgateway.Selector{WorkloadID: w}, Kind: kind, Ref: ref})
			}
		}
	}
	return out, nil
}

func digestJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

// policySetVersion digests what a decision depends on besides stops.
func policySetVersion(policies []agentgateway.Policy, settings AgentGatewaySettings) string {
	return digestJSON(map[string]any{"policies": policies, "mode": settings.Mode, "ttl": settings.CacheTTLSeconds})
}

// hintsVersion digests a hints body (without its time and version).
func hintsVersion(h AgentGatewayPolicyHints) string {
	h.Version, h.AsOf = "", time.Time{}
	return digestJSON(h)
}

/* --------------------------- fail mode and cache --------------------------- */

// PendingChangeKindGatewayRuntime is the pending change that loosens a
// gateway's fail mode or cache cap.
const PendingChangeKindGatewayRuntime = "agent_gateway.runtime"

// AgentGatewayRuntimeUpdate changes a gateway's fail mode and/or cache cap
// (omitted fields keep their value) at the expected version.
type AgentGatewayRuntimeUpdate struct {
	FailMode        *string `json:"fail_mode"`
	CacheTTLSeconds *int    `json:"cache_ttl_seconds"`
	Reason          string  `json:"reason"`
	Version         *int    `json:"version"`
}

// AgentGatewayRuntimeResult is the outcome: applied at once (tightening, no
// change, or break-glass), or a pending change awaiting a second person.
type AgentGatewayRuntimeResult struct {
	Gateway       AgentGatewayView   `json:"gateway"`
	Applied       bool               `json:"applied"`
	BreakGlass    bool               `json:"break_glass,omitempty"`
	PendingChange *PendingChangeView `json:"pending_change,omitempty"`
}

type gatewayRuntimeValues struct {
	FailMode        string `json:"fail_mode"`
	CacheTTLSeconds int    `json:"cache_ttl_seconds"`
}

// loosens reports whether going from v to to loosens anything.
func (v gatewayRuntimeValues) loosens(to gatewayRuntimeValues) bool {
	return agentgateway.LoosensFailMode(v.FailMode, to.FailMode) || to.CacheTTLSeconds > v.CacheTTLSeconds
}

type gatewayRuntimePayload struct {
	GatewayID uuid.UUID            `json:"gateway_id"`
	From      gatewayRuntimeValues `json:"from"`
	To        gatewayRuntimeValues `json:"to"`
}

func writeGatewayRuntime(tx *gorm.DB, ws, id uuid.UUID, v gatewayRuntimeValues) error {
	return tx.Exec(`UPDATE agent_gateway SET fail_mode = ?, cache_ttl_seconds = ?, updated_at = now(), version = version + 1
		WHERE workspace_id = ? AND id = ? AND revoked_at IS NULL`, v.FailMode, v.CacheTTLSeconds, ws, id).Error
}

func validateGatewayRuntime(u AgentGatewayRuntimeUpdate) error {
	if u.Version == nil {
		return govErr(http.StatusUnprocessableEntity, "validation_failed", "version is required.", map[string]any{"field": "version"})
	}
	if u.FailMode == nil && u.CacheTTLSeconds == nil {
		return govErr(http.StatusUnprocessableEntity, "validation_failed", "fail_mode or cache_ttl_seconds is required.", nil)
	}
	if u.FailMode != nil && !agentgateway.ValidFailMode(*u.FailMode) {
		return govErr(http.StatusUnprocessableEntity, "validation_failed", "fail_mode must be closed, auto or open.",
			map[string]any{"field": "fail_mode"})
	}
	if u.CacheTTLSeconds != nil && (*u.CacheTTLSeconds < 0 || *u.CacheTTLSeconds > AgentGatewayMaxCacheTTL) {
		return govErr(http.StatusUnprocessableEntity, "validation_failed",
			fmt.Sprintf("cache_ttl_seconds must be between 0 and %d.", AgentGatewayMaxCacheTTL), map[string]any{"field": "cache_ttl_seconds"})
	}
	if len(u.Reason) > MaxPendingChangeReason {
		return govErr(http.StatusUnprocessableEntity, "validation_failed", "reason is too long.", map[string]any{"field": "reason"})
	}
	return nil
}

// UpdateGatewayRuntime changes a gateway's fail mode and cache cap.
// Tightening (or no change) applies at once. Loosening (closed -> auto/open,
// auto -> open, a longer cache) is tier 3: it becomes a pending change that
// another member holding governance:approve must approve -- unless no other
// member holds it, when it applies alone as break-glass, flagged for review
// within 24 h (decision 4). Another workspace's gateway is 404.
func (s *AgentGatewayService) UpdateGatewayRuntime(ctx context.Context, ws, id, actor uuid.UUID, u AgentGatewayRuntimeUpdate) (AgentGatewayView, AgentGatewayRuntimeResult, error) {
	if err := validateGatewayRuntime(u); err != nil {
		return AgentGatewayView{}, AgentGatewayRuntimeResult{}, err
	}
	now := s.now().UTC()
	var before, after *agentGatewayRow
	var res AgentGatewayRuntimeResult
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		if before, err = readAgentGateway(tx, ws, id); err != nil {
			return err
		}
		approvers, err := WorkspaceUsersHoldingPermission(tx, ws, "governance", "approve")
		if err != nil {
			return err
		}
		second := false
		for _, a := range approvers {
			if a != actor {
				second = true
				break
			}
		}
		if before.RevokedAt != nil {
			return govConflict("gateway_revoked", "A revoked gateway cannot be changed.", nil)
		}
		if before.Version != *u.Version {
			return govConflict(GovCodeVersionConflict, "The gateway changed since you opened it.", map[string]any{"version": before.Version})
		}
		from := gatewayRuntimeValues{FailMode: before.FailMode, CacheTTLSeconds: before.CacheTTLSeconds}
		to := from
		if u.FailMode != nil {
			to.FailMode = *u.FailMode
		}
		if u.CacheTTLSeconds != nil {
			to.CacheTTLSeconds = *u.CacheTTLSeconds
		}
		if to == from {
			after, res.Applied = before, true
			return nil
		}
		payload := gatewayRuntimePayload{GatewayID: id, From: from, To: to}
		if from.loosens(to) && second {
			pc, err := insertPendingChangeTx(tx, ws, PendingChangeKindGatewayRuntime, "agent_gateway:"+id.String(),
				payload, strings.TrimSpace(u.Reason), actor, now)
			if err != nil {
				return err
			}
			v := pc.view()
			res.PendingChange = &v
			after = before
			return nil
		}
		if err := writeGatewayRuntime(tx, ws, id, to); err != nil {
			return err
		}
		if from.loosens(to) {
			// Nobody else could approve: break-glass, recorded for review.
			pc, err := insertBreakGlassChangeTx(tx, ws, PendingChangeKindGatewayRuntime, "agent_gateway:"+id.String(),
				payload, strings.TrimSpace(u.Reason), actor, now)
			if err != nil {
				return err
			}
			v := pc.view()
			res.PendingChange, res.BreakGlass = &v, true
		}
		res.Applied = true
		after, err = readAgentGateway(tx, ws, id)
		return err
	})
	if err != nil {
		return AgentGatewayView{}, AgentGatewayRuntimeResult{}, err
	}
	if res.Applied {
		InvalidateAgentGatewayWorkspace(ws, id)
	}
	res.Gateway = after.view()
	return before.view(), res, nil
}

// applyGatewayRuntimeChange applies an approved runtime change: the
// gateway must still have the values the request was made against
// (409 change_stale otherwise; the change stays pending to be rejected).
func applyGatewayRuntimeChange(tx *gorm.DB, ws uuid.UUID, pc *pendingChangeRow) (func(), error) {
	var p gatewayRuntimePayload
	if err := json.Unmarshal([]byte(pc.Payload), &p); err != nil {
		return nil, fmt.Errorf("pending change %s: payload: %w", pc.ID, err)
	}
	if !agentgateway.ValidFailMode(p.To.FailMode) || p.To.CacheTTLSeconds < 0 || p.To.CacheTTLSeconds > AgentGatewayMaxCacheTTL {
		return nil, govConflict("change_invalid", "The requested values are no longer valid.", nil)
	}
	var cur agentGatewayRow
	res := tx.Raw(`SELECT `+agentGatewayCols+` FROM agent_gateway WHERE workspace_id = ? AND id = ? FOR UPDATE`, ws, p.GatewayID).Scan(&cur)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, GovNotFound()
	}
	if cur.RevokedAt != nil {
		return nil, govConflict("gateway_revoked", "The gateway was revoked; reject this change.", nil)
	}
	if (gatewayRuntimeValues{FailMode: cur.FailMode, CacheTTLSeconds: cur.CacheTTLSeconds}) != p.From {
		return nil, govConflict("change_stale", "The gateway changed since this was requested; reject it and request again.",
			map[string]any{"fail_mode": cur.FailMode, "cache_ttl_seconds": cur.CacheTTLSeconds})
	}
	if err := writeGatewayRuntime(tx, ws, p.GatewayID, p.To); err != nil {
		return nil, err
	}
	gid := p.GatewayID
	return func() { InvalidateAgentGatewayWorkspace(ws, gid) }, nil
}

func init() {
	registerPendingChangeKind(PendingChangeKindGatewayRuntime, applyGatewayRuntimeChange)
}
