package services

import (
	"fmt"
	"sort"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
)

// R1b's part of POST /proposals (SPEC-iga-phase3-policy.md §7.3, §12.1):
// recommending action removals within the services each role keeps. Runs
// only while PolicyActionsOn(); with R1b off no role has actions and the
// proposal is exactly R1a's.

// proposalActions are the role's removable actions at the evaluated revision
// (the preliminary bundle's): justified by frozen evidence (removableActions)
// and, for a proposal from findings, limited to the selected unused_action
// findings.
func (a *GovAuthoring) proposalActions(db *gorm.DB, ws uuid.UUID, r *proposalRole, removedSvc []string) ([]govActionEvidence, error) {
	if len(r.prelim.Facts.Sources) == 0 || r.basis == nil {
		return nil, nil
	}
	rows, err := actionEvidenceAt(db, ws, r.prelim.Facts.Sources[0].Rev, r.target.Identity.ID)
	if err != nil {
		return nil, fmt.Errorf("action evidence of %s: %w", r.target.Identity.RoleID, err)
	}
	rm := map[string]bool{}
	for _, s := range removedSvc {
		rm[s] = true
	}
	acts := removableActions(rows, dependencyContexts(r.basis.Consumers), rm)
	if r.findings == nil {
		return acts, nil
	}
	var out []govActionEvidence
	for _, x := range acts {
		if _, ok := r.actionFindings[x.ActionKey]; ok {
			out = append(out, x)
		}
	}
	return out, nil
}

// commonActions is DECISION A6 at action level: a version has one action
// removal list for all its subjects, so a multi-role proposal removes the
// actions every role can remove; the rest are warnings. An action whose
// namespace is removed whole is dropped (the service exclusion covers it).
func commonActions(roles []*proposalRole, remove []string, warnings *[]string) []string {
	if len(roles) == 0 {
		return nil
	}
	display := map[string]string{}
	sets := make([][]string, 0, len(roles))
	for _, r := range roles {
		var ks []string
		for _, x := range r.actions {
			ks = append(ks, x.ActionKey)
			if cur, ok := display[x.ActionKey]; !ok || x.Action < cur {
				display[x.ActionKey] = x.Action
			}
		}
		sets = append(sets, ks)
	}
	common := map[string]bool{}
	for _, k := range intersect(sets) {
		common[k] = true
	}
	rm := map[string]bool{}
	for _, s := range remove {
		rm[s] = true
	}
	var out []string
	for k := range common {
		if ns, _, ok := igagov.SplitAction(k); ok && rm[ns] {
			continue
		}
		out = append(out, display[k])
	}
	for _, r := range roles {
		for _, x := range r.actions {
			if !common[x.ActionKey] {
				*warnings = append(*warnings, fmt.Sprintf("not_common:%s:%s", r.target.Identity.RoleID, x.Action))
			}
		}
	}
	sort.Strings(out)
	return out
}

// recommendActions adds the action removals to the recommended intent: one
// no_event entry per action with the shortest qualified window of the roles
// and predates_observation when any role's grant predates observation
// (owners are then asked to confirm, as for services), and the unused_action
// findings the proposal addresses.
//
// db is the caller's transaction under row-level security for ws.
func (a *GovAuthoring) recommendActions(db *gorm.DB, ws uuid.UUID, roles []*proposalRole, removeActs []string, in *igagov.RightSizeIntent, rec *ProposalRecommendation) error {
	want := map[string]bool{}
	for _, x := range removeActs {
		want[igagov.ActionKey(x)] = true
	}
	type agg struct {
		days     int
		predates bool
		seen     bool
	}
	byKey := map[string]*agg{}
	for _, r := range roles {
		for _, x := range r.actions {
			if !want[x.ActionKey] {
				continue
			}
			g := byKey[x.ActionKey]
			if g == nil {
				g = &agg{}
				byKey[x.ActionKey] = g
			}
			if !g.seen || x.QualifiedDays < g.days {
				g.days, g.seen = x.QualifiedDays, true
			}
			g.predates = g.predates || x.GrantAgeBasis == igagov.GrantAgePredatesObservation
		}
	}
	for _, x := range removeActs {
		g := byKey[igagov.ActionKey(x)]
		if g == nil {
			continue
		}
		ns, _, _ := igagov.SplitAction(x)
		e := igagov.RemoveActionEntry{Action: x, Service: ns, Basis: igagov.RemoveActionNoEvent, QualifiedDays: g.days,
			GrantAgeBasis: igagov.GrantAgeObservedSinceChange}
		if g.predates {
			e.GrantAgeBasis = igagov.GrantAgePredatesObservation
			rec.Warnings = append(rec.Warnings, "age_unverified: "+x+" was granted before AuthSec's first scan; owners will be asked to confirm")
		}
		in.RemoveActions = append(in.RemoveActions, e)
	}
	ids := map[string]bool{}
	for _, f := range in.FindingIDs {
		ids[f] = true
	}
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, r := range roles {
		if r.findings != nil {
			for k, fid := range r.actionFindings {
				if want[k] {
					ids[fid.String()] = true
				}
			}
			continue
		}
		var fids []uuid.UUID
		if err := db.Raw(`SELECT id FROM iga_gov_finding WHERE workspace_id = ? AND identity_account_id = ? AND kind = ?
		               AND detail_key IN ? AND status IN ('open','reopened')`,
			ws, r.target.Identity.ID, igagov.KindUnusedAction, keys).Scan(&fids).Error; err != nil {
			return fmt.Errorf("action findings addressed by the proposal for %s: %w", r.target.Identity.RoleID, err)
		}
		for _, f := range fids {
			ids[f.String()] = true
		}
	}
	in.FindingIDs = in.FindingIDs[:0]
	for f := range ids {
		in.FindingIDs = append(in.FindingIDs, f)
	}
	sort.Strings(in.FindingIDs)
	if in.Remove == nil {
		in.Remove = []igagov.RemoveEntry{}
	}
	rec.Remove, rec.RemoveActions = in.Remove, in.RemoveActions
	return nil
}
