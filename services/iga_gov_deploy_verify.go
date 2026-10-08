package services

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Verification (SPEC-iga-phase3-policy.md §8.7; T3.16). The verify job
// records four dimensions per deployment (iga_gov_verification, one row per
// dimension, rewritten on each run):
//
//	artifact            a discovery read classified by igagov.Classify
//	                    against the plan: passed only on `after` (both
//	                    outcomes: attachment AND disposition).
//	graph               a publication of the control's connector whose scan
//	                    started after applied_at agrees (boundary assignment,
//	                    document version, disposition); awaiting_evidence
//	                    until then, overdue after verify_deadline_at.
//	application_health  igagov.EvaluateCanary's three health gates over the
//	                    window (CloudTrail management events of the role's
//	                    sessions, declared validations, owner reports).
//	restriction         boundary-attributed denials on removed services or a
//	                    matched expected=denied validation; not_applicable for
//	                    absent / split plans; never `passed` from absence.
//
// A deployment is VERIFIED only when artifact AND graph pass (§8.4). Time
// alone never verifies: an overdue graph keeps it applied_unverified (A55).
// Verification is an enforcement observer: the posture, history, findings
// and supersession / undo / retirement are written in one compare-and-swap
// transaction (iga_gov_deploy_observer.go).

// VerifyHandler is the verify job.
func (s *GovDeployments) VerifyHandler(ctx context.Context, run *PolicyJobRun) error {
	if run.Job.SubjectID == nil {
		return PolicyJobAbandon("verify needs a deployment subject")
	}
	ws := run.Job.WorkspaceID
	db := run.DB().WithContext(ctx)
	d, err := s.loadDeployment(db, ws, *run.Job.SubjectID)
	if err != nil {
		var ge *GovError
		if errors.As(err, &ge) {
			return PolicyJobAbandon("deployment not found")
		}
		return err
	}
	plan, err := loadGovPlan(run.DB(), ws, d.PlanID)
	if err != nil {
		return err
	}
	switch d.State {
	case models.GovDeployAppliedUnverified, models.GovDeployVerified:
	case models.GovDeployAwaitingApply:
		if h := govDeliveryHandler(d.Delivery); h != nil {
			return h.Verify(ctx, run, *d, plan)
		}
		return nil
	default:
		return nil
	}
	if d.AppliedAt == nil {
		return PolicyJobAbandon("an applied deployment without applied_at")
	}
	ctl, err := s.loadControl(db, ws, d.ControlID)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	live, cl, err := s.readPlan(ctx, run, *d, plan, *ctl)
	if err != nil {
		return err
	}
	artifact := igagov.OutcomeFailed
	if cl.Class == igagov.ClassAfter {
		artifact = igagov.OutcomePassed
	}
	graph, graphEv, published, err := s.graphDimension(db, *d, plan, *ctl, now)
	if err != nil {
		return err
	}
	cr, err := s.canary(db, *d, plan, *ctl, now, artifact, published)
	if err != nil {
		return err
	}
	if err := run.InTx(ctx, func(tx *gorm.DB) error {
		if err := upsertVerificationTx(tx, *d, "artifact", artifact, igagov.AttributionNotApplicable,
			map[string]any{"classification": cl, "reason": cl.Reason}); err != nil {
			return err
		}
		if err := upsertVerificationTx(tx, *d, "graph", graph, igagov.AttributionNotApplicable, graphEv); err != nil {
			return err
		}
		if err := upsertVerificationTx(tx, *d, "application_health", cr.ApplicationHealth.Outcome, igagov.AttributionNotApplicable,
			map[string]any{"canary": cr, "reason": cr.ApplicationHealth.Reason}); err != nil {
			return err
		}
		if err := upsertVerificationTx(tx, *d, "restriction", cr.Restriction.Outcome, cr.Restriction.Attribution,
			map[string]any{"reason": cr.Restriction.Reason, "service_restriction": cr.ServiceRestriction}); err != nil {
			return err
		}
		if err := s.writeValidationResultsTx(tx, *d, cr.Validations); err != nil {
			return err
		}
		return s.event(tx, *d, GovEventVerificationRecorded, map[string]any{"artifact": artifact, "graph": graph,
			"application_health": cr.ApplicationHealth.Outcome, "restriction": cr.Restriction.Outcome})
	}); err != nil {
		return err
	}
	if d.State == models.GovDeployAppliedUnverified {
		switch {
		case artifact == igagov.OutcomeFailed:
			// The readback had passed; the artifact changed since (§8.8).
			return s.recordDrift(ctx, run, *d, plan, *ctl, driftReason(plan, live, cl), live)
		case artifact == igagov.OutcomePassed && graph == igagov.OutcomePassed:
			if err := s.markVerified(ctx, run, *d, plan, cr); err != nil {
				return err
			}
		}
	} else if err := s.restrictionUpdate(ctx, run, *d, plan, *ctl, cr); err != nil {
		return err
	}
	cur, err := s.loadDeployment(run.DB().WithContext(ctx), ws, d.ID)
	if err != nil {
		return err
	}
	hours := s.canaryHours(db, ws)
	if cur.State == models.GovDeployAppliedUnverified ||
		(cur.State == models.GovDeployVerified && now.Before(cur.AppliedAt.Add(time.Duration(hours)*time.Hour))) {
		return PolicyJobRetryLater(DefaultVerifyEvery, "verification continues")
	}
	return nil
}

func (s *GovDeployments) canaryHours(db *gorm.DB, ws uuid.UUID) int {
	st, err := repositories.NewIGAGovSettingsRepository(db).Get(ws)
	if err != nil || st == nil || st.CanaryHours <= 0 {
		return 48
	}
	return st.CanaryHours
}

func upsertVerificationTx(tx *gorm.DB, d models.IGAGovDeployment, dim, outcome, attribution string, evidence any) error {
	raw, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	return tx.Exec(`INSERT INTO iga_gov_verification (workspace_id, deployment_id, dimension, outcome, attribution, evidence, checked_at)
		VALUES (?, ?, ?, ?, ?, ?::jsonb, now())
		ON CONFLICT (deployment_id, dimension) DO UPDATE SET outcome = EXCLUDED.outcome, attribution = EXCLUDED.attribution,
		  evidence = EXCLUDED.evidence, checked_at = now()`, d.WorkspaceID, d.ID, dim, outcome, attribution, string(raw)).Error
}

// readPlan is one fenced discovery read of the deployment's plan, classified.
func (s *GovDeployments) readPlan(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment, plan igagov.Plan, ctl models.IGAGovControl) (igagov.LiveRead, igagov.Classification, error) {
	env := s.envNow()
	if env.AWS == nil {
		return igagov.LiveRead{}, igagov.Classification{}, PolicyJobRetryLater(5*time.Minute, "AWS access is not configured")
	}
	var live igagov.LiveRead
	err := run.External(ctx, 0, func(ctx context.Context) error {
		disc, err := env.AWS.DiscoveryIAM(ctx, d.WorkspaceID, ctl.ConnectorID)
		if err != nil {
			return err
		}
		live, _, err = awsenforce.ReadForPlan(ctx, disc, roleNameOfARN(ctl.RoleARN), plan, s.now())
		return err
	})
	if err != nil {
		if isLeaseErr(err) {
			return live, igagov.Classification{}, err
		}
		return live, igagov.Classification{}, PolicyJobRetryLater(time.Minute, "discovery read failed: "+err.Error())
	}
	cl, err := igagov.Classify(plan, live)
	return live, cl, err
}

// inForce is the role's boundary in a live read (nil: none, or unreadable).
func inForce(live igagov.LiveRead) *govBoundaryInForce {
	if live.Role == nil || live.Role.BoundaryARN == "" {
		return nil
	}
	p := live.Policies[live.Role.BoundaryARN]
	if p == nil {
		return nil
	}
	h, err := p.DocumentHash()
	if err != nil {
		return nil
	}
	return &govBoundaryInForce{ARN: live.Role.BoundaryARN, DocHash: h, DocText: p.DefaultDocument}
}

/* ---------------------------------- graph ---------------------------------- */

// graphDimension is §8.7's graph dimension. DECISION (T3.16): "a
// publication after applied_at" is a publication whose own scan run belongs
// to the control's connector and STARTED after applied_at (a scan that
// started before could have read IAM before the change). The graph's
// iga_policy.document_hash is the raw sha256 of AWS's text, not the
// canonical hash, so the document is matched by the ledger's default
// version id (aws_version_id, written at readback) or by the canonical
// archived document's raw hash.
func (s *GovDeployments) graphDimension(db *gorm.DB, d models.IGAGovDeployment, p igagov.Plan, ctl models.IGAGovControl, now time.Time) (string, map[string]any, bool, error) {
	var revs []int64
	if err := db.Raw(`SELECT p.rev FROM iga_publication p
		JOIN cloud_scan_run r ON r.workspace_id = p.workspace_id AND r.id = p.scan_run_id
		WHERE p.workspace_id = ? AND r.connector_id = ? AND COALESCE(r.started_at, r.requested_at) > ?
		ORDER BY p.rev DESC LIMIT 1`, d.WorkspaceID, ctl.ConnectorID, *d.AppliedAt).Scan(&revs).Error; err != nil {
		return "", nil, false, err
	}
	if len(revs) == 0 {
		ev := map[string]any{"reason": "no publication of the account after the change yet"}
		if d.VerifyDeadlineAt != nil && now.After(*d.VerifyDeadlineAt) {
			ev["reason"] = "no publication of the account since the change; verification is overdue (never verified by elapsed time)"
			return GovOutcomeOverdue, ev, false, nil
		}
		return igagov.OutcomeAwaitingEvidence, ev, false, nil
	}
	var asg []struct {
		NativeRef    string
		DocumentHash string
		VersionID    string
	}
	if err := db.Raw(`SELECT pol.native_ref, pol.document_hash, pol.version_id FROM iga_policy_assignment a
		JOIN iga_policy pol ON pol.workspace_id = a.workspace_id AND pol.id = a.policy_id
		WHERE a.workspace_id = ? AND a.holder_identity_account_id = ? AND a.assignment_kind = 'boundary' AND a.state = 'current'`,
		d.WorkspaceID, ctl.IdentityAccountID).Scan(&asg).Error; err != nil {
		return "", nil, false, err
	}
	ev := map[string]any{"rev": revs[0], "boundary_assignments": asg}
	fail := func(why string) (string, map[string]any, bool, error) {
		ev["reason"] = why
		return igagov.OutcomeFailed, ev, true, nil
	}
	switch p.DesiredAttachment {
	case igagov.AttachmentPresent:
		if len(asg) != 1 || asg[0].NativeRef != *p.DesiredBoundaryARN {
			return fail("the graph does not show the desired boundary assigned to the role")
		}
		var ver []string
		_ = db.Raw(`SELECT aws_version_id FROM iga_gov_artifact WHERE workspace_id = ? AND control_id = ? AND kind = 'boundary_policy'
			AND native_arn = ? AND state IN ('present','released') ORDER BY updated_at DESC LIMIT 1`,
			d.WorkspaceID, ctl.ID, *p.DesiredBoundaryARN).Scan(&ver)
		docOK := len(ver) == 1 && ver[0] != "" && ver[0] == asg[0].VersionID
		if !docOK && p.DesiredDocumentHash != nil {
			var canon []string
			_ = db.Raw(`SELECT canonical FROM iga_gov_document WHERE workspace_id = ? AND document_hash = ?`, d.WorkspaceID, *p.DesiredDocumentHash).Scan(&canon)
			docOK = len(canon) == 1 && rawSHA256(canon[0]) == asg[0].DocumentHash
		}
		if !docOK {
			return fail("the graph's boundary document is not the desired one")
		}
	case igagov.AttachmentAbsent:
		if len(asg) != 0 {
			return fail("the graph still shows a boundary assigned to the role")
		}
	}
	if p.ReplacedBoundaryARN != nil && p.ArtifactDisposition != igagov.DispositionKeep {
		var active int64
		if err := db.Raw(`SELECT count(*) FROM iga_policy WHERE workspace_id = ? AND native_ref = ? AND lifecycle = 'active'`,
			d.WorkspaceID, *p.ReplacedBoundaryARN).Scan(&active).Error; err != nil {
			return "", nil, false, err
		}
		if p.ArtifactDisposition == igagov.DispositionDelete && active > 0 {
			return fail("the replaced policy is still live in the graph")
		}
		if p.ArtifactDisposition == igagov.DispositionRetainShared && active == 0 {
			return fail("the retained shared policy is not live in the graph")
		}
	}
	return igagov.OutcomePassed, ev, true, nil
}

/* --------------------------------- health ---------------------------------- */

// canary builds igagov.EvaluateCanary's input for the deployment.
//
// DECISION (T3.16): a retained service is "active in the qualified
// interval" when its basis is `observed`; data-event-only services are not
// known in R1a's evidence, so none is marked (a validation or a working
// report still counts for any service). CloudTrail coverage is one read
// per published scan of the connector whose coverage has a
// cloudtrail-events surface: [scan start - 48 h, scan start], capped when
// that surface is partial or counted >= 10,000 events.
func (s *GovDeployments) canary(db *gorm.DB, d models.IGAGovDeployment, p igagov.Plan, ctl models.IGAGovControl, now time.Time, artifact string, published bool) (igagov.CanaryResult, error) {
	in := igagov.CanaryInput{RoleID: ctl.RoleID, AppliedAt: d.AppliedAt.UTC(), Now: now, CanaryHours: s.canaryHours(db, d.WorkspaceID),
		PublishedAfterApply: published, ArtifactOutcome: artifact}
	in.RemovesServices = d.Kind == igagov.PlanApply && p.DesiredAttachment == igagov.AttachmentPresent && len(p.Impact.Removed) > 0
	for _, r := range p.Impact.Removed {
		in.Removed = append(in.Removed, r.Service)
	}
	for _, r := range p.Impact.Retained {
		in.Retained = append(in.Retained, igagov.RetainedService{Service: r.Service, ActiveInQualifiedInterval: r.Basis == "observed"})
	}
	var obs []struct {
		ObservedAt     time.Time
		SanitizedFacts json.RawMessage
	}
	if err := db.Raw(`SELECT observed_at, sanitized_facts FROM cloud_observation
		WHERE workspace_id = ? AND source_api = 'cloudtrail:LookupEvents' AND sanitized_facts->>'session_issuer_principal_id' = ?
		  AND observed_at >= ? ORDER BY observed_at`, d.WorkspaceID, ctl.RoleID, d.AppliedAt.Add(-time.Hour)).Scan(&obs).Error; err != nil {
		return igagov.CanaryResult{}, err
	}
	for _, o := range obs {
		var f map[string]any
		_ = json.Unmarshal(o.SanitizedFacts, &f)
		str := func(k string) string { v, _ := f[k].(string); return v }
		in.Events = append(in.Events, igagov.TrailEvent{EventTime: o.ObservedAt.UTC(), PrincipalID: str("session_issuer_principal_id"),
			SessionName: str("session_name"), EventSource: str("event_source"), EventName: str("event_name"),
			ErrorCode: str("error_code"), DenialPolicyType: str("denial_policy_type")})
	}
	vs, items, err := loadValidations(db, d)
	if err != nil {
		return igagov.CanaryResult{}, err
	}
	for _, v := range vs {
		iv := igagov.Validation{ID: v.ID.String(), RoleID: v.RoleID, SessionName: v.SessionName, WindowStart: v.WindowStart.UTC(), WindowEnd: v.WindowEnd.UTC()}
		for _, it := range items[v.ID] {
			iv.Items = append(iv.Items, igagov.ValidationItem{Action: it.Action, Expected: it.Expected})
		}
		in.Validations = append(in.Validations, iv)
	}
	var reps []models.IGAGovHealthReport
	if err := db.Where("workspace_id = ? AND deployment_id = ?", d.WorkspaceID, d.ID).Find(&reps).Error; err != nil {
		return igagov.CanaryResult{}, err
	}
	for _, r := range reps {
		in.Reports = append(in.Reports, igagov.HealthReport{Kind: r.Kind, Service: r.Service, CreatedAt: r.CreatedAt.UTC()})
	}
	var runs []struct {
		StartedAt   *time.Time
		RequestedAt time.Time
		Coverage    json.RawMessage
	}
	if err := db.Raw(`SELECT started_at, requested_at, coverage FROM cloud_scan_run
		WHERE workspace_id = ? AND connector_id = ? AND status = 'published' AND COALESCE(started_at, requested_at) >= ?`,
		d.WorkspaceID, ctl.ConnectorID, d.AppliedAt.Add(-igagov.MaxTrailScanGap)).Scan(&runs).Error; err != nil {
		return igagov.CanaryResult{}, err
	}
	for _, r := range runs {
		var cov struct {
			Surfaces map[string]struct {
				State string `json:"state"`
				Count int    `json:"count"`
			} `json:"surfaces"`
		}
		_ = json.Unmarshal(r.Coverage, &cov)
		at := r.RequestedAt
		if r.StartedAt != nil {
			at = *r.StartedAt
		}
		for k, sc := range cov.Surfaces {
			if !strings.HasPrefix(k, models.SurfaceCloudTrailEventsPrefix+":") {
				continue
			}
			if sc.State != models.CloudCoverageReached && sc.State != "partial" {
				continue
			}
			in.Trail = append(in.Trail, igagov.TrailRead{From: at.Add(-igagov.MaxTrailScanGap).UTC(), To: at.UTC(),
				CapHit: sc.State == "partial" || sc.Count >= 10000})
		}
	}
	return igagov.EvaluateCanary(in), nil
}

func loadValidations(db *gorm.DB, d models.IGAGovDeployment) ([]models.IGAGovValidation, map[uuid.UUID][]models.IGAGovValidationItem, error) {
	var vs []models.IGAGovValidation
	if err := db.Where("workspace_id = ? AND deployment_id = ?", d.WorkspaceID, d.ID).Order("created_at, id").Find(&vs).Error; err != nil {
		return nil, nil, err
	}
	items := map[uuid.UUID][]models.IGAGovValidationItem{}
	if len(vs) == 0 {
		return vs, items, nil
	}
	ids := make([]uuid.UUID, len(vs))
	for i, v := range vs {
		ids[i] = v.ID
	}
	var its []models.IGAGovValidationItem
	if err := db.Where("workspace_id = ? AND validation_id IN ?", d.WorkspaceID, ids).Order("action").Find(&its).Error; err != nil {
		return nil, nil, err
	}
	for _, it := range its {
		items[it.ValidationID] = append(items[it.ValidationID], it)
	}
	return vs, items, nil
}

func (s *GovDeployments) writeValidationResultsTx(tx *gorm.DB, d models.IGAGovDeployment, vrs []igagov.ValidationResult) error {
	for _, vr := range vrs {
		id, err := uuid.Parse(vr.ID)
		if err != nil {
			continue
		}
		if err := tx.Exec(`UPDATE iga_gov_validation SET result = ? WHERE workspace_id = ? AND id = ?`, vr.Result, d.WorkspaceID, id).Error; err != nil {
			return err
		}
		for _, it := range vr.Items {
			if err := tx.Exec(`UPDATE iga_gov_validation_item SET result = ?, matched_events = ?, opposite_events = ?,
				evidence = jsonb_build_object('boundary_attributed', ?::boolean)
				WHERE workspace_id = ? AND validation_id = ? AND action = ?`, it.Result, it.MatchedEvents, it.OppositeEvents,
				it.BoundaryAttested, d.WorkspaceID, id, it.Action).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

/* --------------------------------- verified -------------------------------- */

// markVerified is applied_unverified -> verified, as an enforcement observer
// (§8.7): supersession of the control's earlier deployment (apply), the undone
// deployment (undo), retirement of the control (remove_control), history,
// posture and findings, in one compare-and-swap transaction.
func (s *GovDeployments) markVerified(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment, p igagov.Plan, cr igagov.CanaryResult) error {
	ws := d.WorkspaceID
	restr := map[string]string{}
	if d.Kind == igagov.PlanApply {
		for k, v := range cr.ServiceRestriction {
			if v != igagov.RestrictionNotObserved {
				restr[k] = v
			}
		}
	}
	_, err := s.observe(ctx, run, func(ctx context.Context) (*govObservation, error) {
		db := run.DB().WithContext(ctx)
		seen, cstate, err := controlSeen(db, ws, d.ControlID)
		if err != nil {
			return nil, err
		}
		if cstate == "removed" {
			return nil, PolicyJobAbandon("the control is retired")
		}
		ctl, err := s.loadControl(db, ws, d.ControlID)
		if err != nil {
			return nil, err
		}
		if err := s.hook("before_read", d.ControlID, nil); err != nil {
			return nil, err
		}
		live, cl, err := s.readPlan(ctx, run, d, p, *ctl)
		if err != nil {
			return nil, err
		}
		if cl.Class != igagov.ClassAfter {
			return nil, nil // the next verify run sees it (artifact failed -> drift)
		}
		o := &govObservation{Dep: d, ControlID: d.ControlID, Seen: seen, InForce: inForce(live), Restriction: restr,
			Writer: "verify", Retire: d.Kind == igagov.PlanRemoveControl}
		dep := d.ID
		o.CurrentDeployment = &dep
		o.ResolvedBy = &dep
		if d.Kind == igagov.PlanApply {
			o.Seeds = seedsFor(p)
		}
		o.Step2 = func(tx *gorm.DB, newSeq int64) error {
			now := s.now().UTC()
			// Deployments of the control, by id (lock order 2).
			var others []models.IGAGovDeployment
			if err := tx.Where("workspace_id = ? AND control_id = ?", ws, d.ControlID).Order("id").Clauses(lockForUpdate()).Find(&others).Error; err != nil {
				return err
			}
			var undone *models.IGAGovDeployment
			if d.Kind == igagov.PlanUndo {
				undone = undoneBy(others, d)
			}
			for i := range others {
				o2 := others[i]
				switch {
				case o2.ID == d.ID:
					if err := setStateTx(tx, o2, []string{models.GovDeployAppliedUnverified}, map[string]any{
						"state": models.GovDeployVerified, "verified_at": now, "state_reason": ""}); err != nil {
						return err
					}
				case undone != nil && o2.ID == undone.ID:
					if err := setStateTx(tx, o2, []string{o2.State}, map[string]any{"state": models.GovDeployUndone,
						"state_reason": "undone by deployment " + d.ID.String()}); err != nil {
						return err
					}
					if err := s.event(tx, o2, GovEventDeploymentUndone, map[string]any{"undo_deployment_id": d.ID,
						"message": "AuthSec's change was undone; other controls may still restrict this role."}); err != nil {
						return err
					}
				case o2.State == models.GovDeployVerified || o2.State == models.GovDeployDrifted:
					if err := setStateTx(tx, o2, []string{o2.State}, map[string]any{"state": models.GovDeploySuperseded,
						"state_reason": "superseded by deployment " + d.ID.String()}); err != nil {
						return err
					}
					if err := s.event(tx, o2, GovEventDeploymentSuperseded, map[string]any{"by": d.ID}); err != nil {
						return err
					}
				}
			}
			if d.Kind == igagov.PlanRemoveControl {
				if err := tx.Exec(`UPDATE iga_gov_artifact SET state = 'removed', last_deployment_id = ?, updated_at = now()
					WHERE workspace_id = ? AND control_id = ? AND state IN ('intended','present','drifted')`, d.ID, ws, d.ControlID).Error; err != nil {
					return err
				}
				if err := s.event(tx, d, GovEventControlRemoved, map[string]any{"control_id": d.ControlID, "enforcement_seq": newSeq,
					"message": "AuthSec no longer controls this role; other controls may still restrict it."}); err != nil {
					return err
				}
			}
			if d.Kind == igagov.PlanUndo && p.DesiredAttachment == igagov.AttachmentAbsent && p.ArtifactDisposition == igagov.DispositionDelete {
				// §8.9: no artifact in AWS any more; Re-apply possible.
				if err := tx.Exec(`UPDATE iga_gov_control SET state = 'planned', updated_at = now() WHERE id = ? AND state = 'active'`, d.ControlID).Error; err != nil {
					return err
				}
			}
			if err := historyTx(tx, d, p, restr); err != nil {
				return err
			}
			return s.event(tx, d, GovEventDeploymentVerified, map[string]any{"kind": d.Kind, "enforcement_seq": newSeq,
				"boundary": inForce(live), "summary": verifiedSummary(d, cr)})
		}
		return o, nil
	})
	return err
}

func verifiedSummary(d models.IGAGovDeployment, cr igagov.CanaryResult) string {
	parts := []string{"Boundary verified", "application health " + cr.ApplicationHealth.Outcome}
	if cr.Restriction.Outcome == igagov.OutcomeNotApplicable {
		parts = append(parts, "restriction not applicable")
	} else if cr.Restriction.Outcome == igagov.OutcomePassed {
		parts = append(parts, "restriction observed ("+cr.Restriction.Attribution+")")
	} else {
		parts = append(parts, "restriction not observed")
	}
	if d.Kind == igagov.PlanUndo || d.Kind == igagov.PlanRemoveControl {
		parts = append(parts, "other controls may still restrict this role")
	}
	return strings.Join(parts, " · ")
}

// undoneBy is the apply deployment an undo deployment undoes: the latest
// applied apply deployment of the undo's version on the same control.
func undoneBy(deps []models.IGAGovDeployment, undo models.IGAGovDeployment) *models.IGAGovDeployment {
	var best *models.IGAGovDeployment
	for i := range deps {
		x := &deps[i]
		if x.Kind != igagov.PlanApply || x.VersionID != undo.VersionID || x.AppliedAt == nil {
			continue
		}
		switch x.State {
		case models.GovDeployVerified, models.GovDeployAppliedUnverified, models.GovDeployDrifted, models.GovDeploySuperseded:
		default:
			continue
		}
		if best == nil || x.AppliedAt.After(*best.AppliedAt) {
			best = x
		}
	}
	return best
}

// restrictionUpdate writes restriction observed / contradicted on posture
// rows when a verified deployment's evidence moves it (§8.7 table).
func (s *GovDeployments) restrictionUpdate(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment, p igagov.Plan, ctl models.IGAGovControl, cr igagov.CanaryResult) error {
	if d.Kind != igagov.PlanApply || len(cr.ServiceRestriction) == 0 {
		return nil
	}
	var rows []struct {
		Service             string
		Restriction         string
		CurrentDeploymentID *uuid.UUID
	}
	if err := run.DB().WithContext(ctx).Raw(`SELECT service, restriction, current_deployment_id FROM iga_gov_service_posture
		WHERE workspace_id = ? AND account_id = ? AND role_id = ?`, d.WorkspaceID, ctl.AccountID, ctl.RoleID).Scan(&rows).Error; err != nil {
		return err
	}
	want := map[string]string{}
	for _, r := range rows {
		v, ok := cr.ServiceRestriction[r.Service]
		if ok && v != igagov.RestrictionNotObserved && v != r.Restriction && r.CurrentDeploymentID != nil && *r.CurrentDeploymentID == d.ID {
			want[r.Service] = v
		}
	}
	if len(want) == 0 {
		return nil
	}
	_, err := s.observe(ctx, run, func(ctx context.Context) (*govObservation, error) {
		seen, cstate, err := controlSeen(run.DB().WithContext(ctx), d.WorkspaceID, d.ControlID)
		if err != nil || cstate == "removed" {
			return nil, err
		}
		live, cl, err := s.readPlan(ctx, run, d, p, ctl)
		if err != nil || cl.Class != igagov.ClassAfter {
			return nil, err
		}
		return &govObservation{Dep: d, ControlID: d.ControlID, Seen: seen, InForce: inForce(live), Restriction: want, Writer: "verify"}, nil
	})
	return err
}
