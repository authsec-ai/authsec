package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// The evaluation snapshot (SPEC-iga-phase3-policy.md §2.5 step 2, §8.2): what
// igagov.Evaluate reads for revision N, gathered from the graph, the scan
// tables and the Phase 3 configuration in ONE repeatable-read, read-only
// transaction while the pipeline barrier is held -- so every connector's
// cloud_usage rows still belong to the run rev N's manifest names for it.
//
// Every role is judged on the evidence of ITS OWN connector's run (A47): the
// role's partition key is its live identity support row's, and the run is
// manifest[partition_key]. The loader never picks "the scan that triggered
// this publication".
//
// The bundle builder and the target resolver (T3.06b) reuse the same reads
// for one role, outside the barrier, against frozen or immutable evidence.

// govRunMeta is what the services need about one manifest run beyond the
// pure RunEvidence.
type govRunMeta struct {
	ID          uuid.UUID
	ConnectorID uuid.UUID
	Generation  int
	Coverage    models.ScanCoverage
	AccountID   string
	Regions     []string
	PublishedAt *time.Time
}

// govRoleMeta is what the services need about one role beyond RoleSnapshot.
type govRoleMeta struct {
	IdentityAccountID uuid.UUID
	ConnectorID       uuid.UUID
	PartitionKey      string
	Continuity        string
	BoundaryARN       string
}

// govSnapshot is a loaded evaluation snapshot.
type govSnapshot struct {
	Snap  igagov.Snapshot
	Runs  map[string]govRunMeta
	Roles map[string]govRoleMeta // by RoleId
	// Excluded are active AWS roles left out of Snap.Roles with the reason
	// (no RoleId: continuity recognition_only, §2.2).
	Excluded map[uuid.UUID]string
}

// cloudReads is the collected model's read interface (declared once, read-only).
var cloudReads repositories.CloudEvidenceReads

// repeatableRead is the snapshot transaction's isolation: one consistent
// view across every read.
var repeatableRead = &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}

// loadGovSnapshot reads revision rev's snapshot for the whole workspace
// (roleFilter nil) or one identity.
func loadGovSnapshot(ctx context.Context, db *gorm.DB, ws uuid.UUID, rev int64, roleFilter *uuid.UUID) (*govSnapshot, error) {
	var out *govSnapshot
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		out, err = readGovSnapshot(tx, ws, rev, roleFilter)
		return err
	}, repeatableRead)
	return out, err
}

func readGovSnapshot(tx *gorm.DB, ws uuid.UUID, rev int64, roleFilter *uuid.UUID) (*govSnapshot, error) {
	var pub models.IGAPublication
	if err := tx.Where("workspace_id = ? AND rev = ?", ws, rev).Take(&pub).Error; err != nil {
		return nil, fmt.Errorf("publication rev %d: %w", rev, err)
	}
	manifest := map[string]string{}
	if len(pub.Manifest) > 0 {
		if err := json.Unmarshal(pub.Manifest, &manifest); err != nil {
			return nil, fmt.Errorf("rev %d manifest: %w", rev, err)
		}
	}
	gs := &govSnapshot{
		Snap: igagov.Snapshot{Rev: rev, EvaluatedAt: pub.PublishedAt.UTC(), Manifest: manifest,
			Runs: map[string]igagov.RunEvidence{}},
		Runs: map[string]govRunMeta{}, Roles: map[string]govRoleMeta{}, Excluded: map[uuid.UUID]string{},
	}
	runIDs := map[uuid.UUID]bool{}
	for _, v := range manifest {
		if id, err := uuid.Parse(v); err == nil {
			runIDs[id] = true
		}
	}
	runs, metas, err := loadRunEvidence(tx, ws, keysOf(runIDs), rev)
	if err != nil {
		return nil, err
	}
	gs.Snap.Runs, gs.Runs = runs, metas

	if err := loadRoles(tx, ws, gs, roleFilter); err != nil {
		return nil, err
	}

	// Workloads consuming any loaded role, owners, rules, settings.
	wlIDs := map[string]bool{}
	for _, r := range gs.Snap.Roles {
		for _, c := range r.Consumers {
			wlIDs[c.WorkloadID] = true
		}
	}
	if len(wlIDs) > 0 {
		var wls []struct {
			ID             uuid.UUID
			DisplayName    string
			RuntimeKind    string
			Stage          string
			Classification string
		}
		if err := tx.Raw(`SELECT id, display_name, runtime_kind, stage, classification FROM iga_workload
		                   WHERE workspace_id = ? AND id IN ?`, ws, stringKeys(wlIDs)).Scan(&wls).Error; err != nil {
			return nil, fmt.Errorf("workloads: %w", err)
		}
		for _, w := range wls {
			gs.Snap.Workloads = append(gs.Snap.Workloads, igagov.WorkloadSnapshot{ID: w.ID.String(), Name: w.DisplayName,
				RuntimeKind: w.RuntimeKind, Stage: w.Stage, Classification: w.Classification})
		}
	}
	var owners []models.IGAGovOwner
	if err := tx.Where("workspace_id = ?", ws).Order("id").Find(&owners).Error; err != nil {
		return nil, fmt.Errorf("owners: %w", err)
	}
	for _, o := range owners {
		rec := igagov.OwnerRecord{ID: o.ID.String(), ObjectKind: o.ObjectKind, UserID: o.UserID.String(),
			Role: o.Role, ReviewDueAt: o.ReviewDueAt}
		if o.WorkloadID != nil {
			rec.WorkloadID = o.WorkloadID.String()
		}
		if o.IdentityAccountID != nil {
			rec.IdentityAccountID = o.IdentityAccountID.String()
		}
		gs.Snap.Owners = append(gs.Snap.Owners, rec)
	}
	var rules []models.IGAGovFindingRule
	if err := tx.Where("workspace_id = ? AND enabled", ws).Order("id").Find(&rules).Error; err != nil {
		return nil, fmt.Errorf("finding rules: %w", err)
	}
	for _, r := range rules {
		fr, err := igagov.ParseFindingRule(r.ID.String(), r.Kind, r.Enabled, r.Scope, r.Params)
		if err != nil {
			// A rule the evaluator cannot read is not applied, never guessed.
			log.Printf("[policy] workspace %s: finding rule %s skipped: %v", ws, r.ID, err)
			continue
		}
		gs.Snap.Rules = append(gs.Snap.Rules, fr)
	}
	var window []int
	if err := tx.Raw(`SELECT default_window_days FROM iga_gov_settings WHERE workspace_id = ?`, ws).Scan(&window).Error; err != nil {
		return nil, fmt.Errorf("settings: %w", err)
	}
	if len(window) == 1 {
		gs.Snap.DefaultWindowDays = window[0]
	}
	return gs, nil
}

// loadRunEvidence reads the runs a manifest names: connector, generation,
// coverage, the connector's first publication (at or before rev), regions,
// and the run's immutable resource-policy evidence (§3.9).
func loadRunEvidence(tx *gorm.DB, ws uuid.UUID, ids []uuid.UUID, rev int64) (map[string]igagov.RunEvidence, map[string]govRunMeta, error) {
	runs, metas := map[string]igagov.RunEvidence{}, map[string]govRunMeta{}
	if len(ids) == 0 {
		return runs, metas, nil
	}
	rows, err := cloudReads.Runs(tx, ws, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("manifest runs: %w", err)
	}
	var firsts []struct {
		ConnectorID uuid.UUID
		First       time.Time
	}
	if err := tx.Raw(`SELECT r.connector_id, min(p.published_at) AS first
	                    FROM iga_publication p
	                    JOIN cloud_scan_run r ON r.workspace_id = p.workspace_id AND r.id = p.scan_run_id
	                   WHERE p.workspace_id = ? AND p.rev <= ?
	                   GROUP BY r.connector_id`, ws, rev).Scan(&firsts).Error; err != nil {
		return nil, nil, fmt.Errorf("first publications: %w", err)
	}
	first := map[uuid.UUID]time.Time{}
	for _, f := range firsts {
		first[f.ConnectorID] = f.First.UTC()
	}
	ev, err := loadResourcePolicyEvidence(tx, ws, ids)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range rows {
		cc := models.CloudConnector{Attrs: r.Attrs}
		regions := append([]string{}, cc.AWSAttrs().Regions...)
		sort.Strings(regions)
		fp := first[r.ConnectorID]
		if fp.IsZero() && r.PublishedAt != nil {
			fp = r.PublishedAt.UTC()
		}
		runs[r.ID.String()] = igagov.RunEvidence{RunID: r.ID.String(), ConnectorID: r.ConnectorID.String(),
			AccountID: r.ScopeID, ConnectorFirstPublishedAt: fp, EnabledRegions: regions,
			ResourcePolicy: ev[r.ID]}
		metas[r.ID.String()] = govRunMeta{ID: r.ID, ConnectorID: r.ConnectorID, Generation: r.Generation,
			Coverage: models.DecodeScanCoverage(r.Coverage), AccountID: r.ScopeID, Regions: regions,
			PublishedAt: r.PublishedAt}
	}
	return runs, metas, nil
}

// loadResourcePolicyEvidence reads each run's coverage and observations,
// decoding stored documents. A run with no coverage rows collected none
// (nil). A stored document that no longer decodes is treated as unparseable.
func loadResourcePolicyEvidence(tx *gorm.DB, ws uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]*igagov.ResourcePolicyEvidence, error) {
	out := map[uuid.UUID]*igagov.ResourcePolicyEvidence{}
	cov, err := cloudReads.ResourcePolicyCoverage(tx, ws, ids)
	if err != nil {
		return nil, fmt.Errorf("resource-policy coverage: %w", err)
	}
	for _, c := range cov {
		e := out[c.ScanRunID]
		if e == nil {
			e = &igagov.ResourcePolicyEvidence{}
			out[c.ScanRunID] = e
		}
		e.Coverage = append(e.Coverage, igagov.CoverageRow{Form: c.ResourceForm, Region: c.Region, State: c.State, Reason: c.Reason})
	}
	if len(out) == 0 {
		return out, nil
	}
	obs, err := cloudReads.ResourcePolicyObservations(tx, ws, ids)
	if err != nil {
		return nil, fmt.Errorf("resource-policy observations: %w", err)
	}
	for _, o := range obs {
		e := out[o.ScanRunID]
		if e == nil {
			continue // FK: an observation always has its coverage row
		}
		ob := igagov.ResourcePolicyObservation{Form: o.ResourceForm, Region: o.Region, ResourceARN: o.ResourceARN,
			PolicyPresent: o.PolicyPresent, ParseState: o.ParseState}
		if o.DocumentHash != nil {
			ob.DocumentHash = *o.DocumentHash
		}
		if o.PolicyPresent && o.ParseState == igagov.ParseParsed && o.Canonical != nil {
			if doc, err := igagov.DecodePolicyDocument(*o.Canonical); err == nil {
				ob.Document = &doc
			} else {
				ob.ParseState = igagov.ParseUnparseable
			}
		}
		e.Observations = append(e.Observations, ob)
	}
	return out, nil
}

// loadRoles reads every active AWS IAM role (or one identity) with its
// support partition, CreateDate, grant history, activity report and
// consumers.
func loadRoles(tx *gorm.DB, ws uuid.UUID, gs *govSnapshot, roleFilter *uuid.UUID) error {
	filter, args := "", []any{ws}
	if roleFilter != nil {
		filter, args = " AND i.id = ?", append(args, *roleFilter)
	}
	var idents []struct {
		ID            uuid.UUID
		DisplayName   string
		SourceKey     string
		ImmutableKey  string
		Continuity    string
		ProviderAttrs json.RawMessage
	}
	if err := tx.Raw(`SELECT i.id, i.display_name, i.source_key, i.immutable_key, i.continuity, i.provider_attrs
	                    FROM iga_identity_accounts i
	                   WHERE i.workspace_id = ? AND i.provider = 'aws' AND i.account_kind = 'iam_role'
	                     AND i.lifecycle = 'active'`+filter+`
	                   ORDER BY i.id`, args...).Scan(&idents).Error; err != nil {
		return fmt.Errorf("roles: %w", err)
	}
	if len(idents) == 0 {
		return nil
	}
	roleScope := `SELECT i.id FROM iga_identity_accounts i
	               WHERE i.workspace_id = ? AND i.provider = 'aws' AND i.account_kind = 'iam_role'
	                 AND i.lifecycle = 'active'` + filter

	// The live support row names the role's connector and partition;
	// current is preferred over stale (§2.5 step 2).
	var support []struct {
		IdentityAccountID uuid.UUID
		ConnectorID       uuid.UUID
		PartitionKey      string
	}
	if err := tx.Raw(`SELECT DISTINCT ON (s.identity_account_id) s.identity_account_id, s.connector_id, s.partition_key
	                    FROM iga_object_support s
	                   WHERE s.workspace_id = ? AND s.state <> 'ended' AND s.identity_account_id IN (`+roleScope+`)
	                   ORDER BY s.identity_account_id, (s.state = 'current') DESC, s.last_confirmed_at DESC NULLS LAST, s.id`,
		append([]any{ws}, args...)...).Scan(&support).Error; err != nil {
		return fmt.Errorf("role support: %w", err)
	}
	sup := map[uuid.UUID]int{}
	for i, s := range support {
		sup[s.IdentityAccountID] = i
	}

	// IAM CreateDate, from the inventory row of the same principal.
	cis, err := cloudReads.Roles(tx, ws)
	if err != nil {
		return fmt.Errorf("cloud identities: %w", err)
	}
	type ciKey struct {
		conn uuid.UUID
		arn  string
	}
	ciByKey := map[ciKey][]int{}
	for i, c := range cis {
		k := ciKey{c.ConnectorID, c.NativeID}
		ciByKey[k] = append(ciByKey[k], i)
	}

	assigns, statements, err := loadGrantHistory(tx, ws, roleScope, args)
	if err != nil {
		return err
	}
	consumers, err := loadConsumers(tx, ws, roleScope, args)
	if err != nil {
		return err
	}
	usage, err := loadUsage(tx, ws, gs)
	if err != nil {
		return err
	}

	seen := map[string]bool{}
	for _, id := range idents {
		if id.ImmutableKey == "" {
			// §2.2: a role is bound by RoleId; without one it is ineligible
			// and outside findings.
			gs.Excluded[id.ID] = "no_role_id"
			continue
		}
		if seen[id.ImmutableKey] {
			gs.Excluded[id.ID] = "duplicate_role_id"
			continue
		}
		seen[id.ImmutableKey] = true
		arn := nativeOfSourceKey(id.SourceKey)
		var attrs struct {
			Path     string            `json:"path"`
			Tags     map[string]string `json:"tags"`
			Boundary string            `json:"permissions_boundary_arn"`
		}
		_ = json.Unmarshal(id.ProviderAttrs, &attrs)
		r := igagov.RoleSnapshot{
			IdentityAccountID: id.ID.String(), RoleID: id.ImmutableKey, ARN: arn, Name: id.DisplayName,
			Path: attrs.Path, AccountID: govARNField(arn, 4), Partition: govARNField(arn, 1), Tags: attrs.Tags,
		}
		meta := govRoleMeta{IdentityAccountID: id.ID, Continuity: id.Continuity, BoundaryARN: attrs.Boundary}
		if i, ok := sup[id.ID]; ok {
			s := support[i]
			r.ConnectorID, r.PartitionKey = s.ConnectorID.String(), s.PartitionKey
			meta.ConnectorID, meta.PartitionKey = s.ConnectorID, s.PartitionKey
			for _, ci := range ciByKey[ciKey{s.ConnectorID, arn}] {
				c := cis[ci]
				if c.UniqueID == "" || c.UniqueID == id.ImmutableKey {
					if c.CreatedAt != nil {
						r.CreatedAt = c.CreatedAt.UTC()
					}
					r.Activity = activityFor(gs, r, c.ID, usage)
					break
				}
			}
			if r.Activity == nil {
				r.Activity = activityNoInventory(gs, r)
			}
		}
		r.Assignments = assigns[id.ID]
		for _, a := range r.Assignments {
			r.Statements = append(r.Statements, statements[a.PolicyKey]...)
		}
		r.Statements = dedupeStatements(r.Statements)
		r.Consumers = consumers[id.ID]
		gs.Snap.Roles = append(gs.Snap.Roles, r)
		gs.Roles[r.RoleID] = meta
	}
	return nil
}

func dedupeStatements(in []igagov.StatementRevision) []igagov.StatementRevision {
	seen := map[string]bool{}
	var out []igagov.StatementRevision
	for _, s := range in {
		k := s.PolicyKey + "\x1f" + s.StatementKey + "\x1f" + s.Hash + "\x1f" + s.From.String()
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

// loadGrantHistory reads every policy assignment of the scoped roles (all
// states: ended rows are history) and every statement of those policies with
// its content history. Sid-keyed statements have iga_statement_revision
// rows; a statement without a Sid is keyed by its content, so the
// entitlement's own lifetime is its one revision (DECISION E1: a retired one
// ends at last_seen_at, the last pass that saw it).
func loadGrantHistory(tx *gorm.DB, ws uuid.UUID, roleScope string, args []any) (map[uuid.UUID][]igagov.PolicyAssignment, map[string][]igagov.StatementRevision, error) {
	var rows []struct {
		Holder    uuid.UUID
		PolicyID  uuid.UUID
		NativeRef string
		Kind      string
		ValidFrom time.Time
		ValidTo   *time.Time
	}
	if err := tx.Raw(`SELECT a.holder_identity_account_id AS holder, a.policy_id, p.native_ref, a.assignment_kind AS kind,
	                         a.valid_from, a.valid_to
	                    FROM iga_policy_assignment a
	                    JOIN iga_policy p ON p.workspace_id = a.workspace_id AND p.id = a.policy_id
	                   WHERE a.workspace_id = ? AND a.holder_identity_account_id IN (`+roleScope+`)
	                   ORDER BY a.holder_identity_account_id, a.policy_id, a.assignment_kind, a.valid_from`,
		append([]any{ws}, args...)...).Scan(&rows).Error; err != nil {
		return nil, nil, fmt.Errorf("assignments: %w", err)
	}
	assigns := map[uuid.UUID][]igagov.PolicyAssignment{}
	policies := map[uuid.UUID]bool{}
	for _, r := range rows {
		policies[r.PolicyID] = true
		list := assigns[r.Holder]
		key := r.PolicyID.String()
		iv := igagov.TimeRange{From: r.ValidFrom.UTC(), To: utcPtr(r.ValidTo)}
		if n := len(list); n > 0 && list[n-1].PolicyKey == key && list[n-1].Kind == r.Kind {
			list[n-1].Intervals = append(list[n-1].Intervals, iv)
		} else {
			list = append(list, igagov.PolicyAssignment{PolicyKey: key, PolicyARN: r.NativeRef, Kind: r.Kind,
				Intervals: []igagov.TimeRange{iv}})
		}
		assigns[r.Holder] = list
	}
	statements := map[string][]igagov.StatementRevision{}
	if len(policies) == 0 {
		return assigns, statements, nil
	}
	pids := keysOf(policies)
	var ents []struct {
		ID           uuid.UUID
		PolicyID     uuid.UUID
		StatementKey string
		ContentHash  string
		NativeRights json.RawMessage
		Lifecycle    string
		FirstSeenAt  time.Time
		LastSeenAt   time.Time
	}
	if err := tx.Raw(`SELECT id, policy_id, statement_key, content_hash, native_rights, lifecycle, first_seen_at, last_seen_at
	                    FROM iga_entitlements
	                   WHERE workspace_id = ? AND provider = 'aws' AND policy_id IN ?
	                   ORDER BY policy_id, statement_key`, ws, pids).Scan(&ents).Error; err != nil {
		return nil, nil, fmt.Errorf("statements: %w", err)
	}
	var revs []struct {
		EntitlementID uuid.UUID
		ContentHash   string
		Statement     json.RawMessage
		ValidFrom     time.Time
		ValidTo       *time.Time
	}
	if err := tx.Raw(`SELECT sr.entitlement_id, sr.content_hash, sr.statement, sr.valid_from, sr.valid_to
	                    FROM iga_statement_revision sr
	                    JOIN iga_entitlements e ON e.workspace_id = sr.workspace_id AND e.id = sr.entitlement_id
	                   WHERE sr.workspace_id = ? AND e.policy_id IN ?
	                   ORDER BY sr.entitlement_id, sr.valid_from`, ws, pids).Scan(&revs).Error; err != nil {
		return nil, nil, fmt.Errorf("statement revisions: %w", err)
	}
	revsOf := map[uuid.UUID][]int{}
	for i, r := range revs {
		revsOf[r.EntitlementID] = append(revsOf[r.EntitlementID], i)
	}
	for _, e := range ents {
		pk := e.PolicyID.String()
		if idx := revsOf[e.ID]; len(idx) > 0 {
			for _, i := range idx {
				r := revs[i]
				st, ok := decodeGraphStatement(r.Statement)
				if !ok {
					continue // not reconstructable: the service stays unreviewed (§2.6)
				}
				statements[pk] = append(statements[pk], igagov.StatementRevision{PolicyKey: pk, StatementKey: e.StatementKey,
					Hash: r.ContentHash, Statement: st, From: r.ValidFrom.UTC(), To: utcPtr(r.ValidTo)})
			}
			continue
		}
		st, ok := decodeGraphStatement(e.NativeRights)
		if !ok {
			continue
		}
		sr := igagov.StatementRevision{PolicyKey: pk, StatementKey: e.StatementKey, Hash: e.ContentHash,
			Statement: st, From: e.FirstSeenAt.UTC()}
		if e.Lifecycle != models.IGALifecycleActive {
			to := e.LastSeenAt.UTC()
			sr.To = &to
		}
		statements[pk] = append(statements[pk], sr)
	}
	return assigns, statements, nil
}

// decodeGraphStatement decodes one stored statement (verbatim, as AWS
// returned it) with the policy-document decoder.
func decodeGraphStatement(raw json.RawMessage) (igagov.Statement, bool) {
	if len(raw) == 0 {
		return igagov.Statement{}, false
	}
	doc, err := igagov.DecodePolicyDocument(`{"Version":"2012-10-17","Statement":[` + string(raw) + `]}`)
	if err != nil || len(doc.Statements) != 1 {
		return igagov.Statement{}, false
	}
	return doc.Statements[0], true
}

// loadConsumers reads the live executes_as / task_execution_role
// relationships into the scoped roles.
func loadConsumers(tx *gorm.DB, ws uuid.UUID, roleScope string, args []any) (map[uuid.UUID][]igagov.Consumer, error) {
	var rows []struct {
		Target           uuid.UUID
		SourceWorkloadID uuid.UUID
		RelationshipType string
	}
	if err := tx.Raw(`SELECT target_identity_account_id AS target, source_workload_id, relationship_type
	                    FROM iga_relationship
	                   WHERE workspace_id = ? AND relationship_type IN ('executes_as','task_execution_role')
	                     AND state <> 'ended' AND source_workload_id IS NOT NULL
	                     AND target_identity_account_id IN (`+roleScope+`)
	                   ORDER BY target_identity_account_id, source_workload_id, relationship_type`,
		append([]any{ws}, args...)...).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("consumers: %w", err)
	}
	out := map[uuid.UUID][]igagov.Consumer{}
	for _, r := range rows {
		out[r.Target] = append(out[r.Target], igagov.Consumer{WorkloadID: r.SourceWorkloadID.String(), Relationship: r.RelationshipType})
	}
	return out, nil
}

// govUsage is the activity read for the manifest runs.
type govUsage struct {
	// rows by (cloud identity id, generation)
	rows map[uuid.UUID][]usageRow
	// newer[connector] = a generation newer than some manifest run touched
	// the connector's activity: its max generation.
	maxGen map[uuid.UUID]int
}

type usageRow struct {
	Service     string
	LastUsedAt  *time.Time
	GeneratedAt *time.Time
	Generation  int
}

func loadUsage(tx *gorm.DB, ws uuid.UUID, gs *govSnapshot) (*govUsage, error) {
	u := &govUsage{rows: map[uuid.UUID][]usageRow{}, maxGen: map[uuid.UUID]int{}}
	conns := map[uuid.UUID]bool{}
	for _, m := range gs.Runs {
		conns[m.ConnectorID] = true
	}
	if len(conns) == 0 {
		return u, nil
	}
	cids := keysOf(conns)
	rows, err := cloudReads.Usage(tx, ws, models.UsageSourceServiceLastAccessed, cids)
	if err != nil {
		return nil, fmt.Errorf("activity rows: %w", err)
	}
	for _, r := range rows {
		u.rows[r.IdentityID] = append(u.rows[r.IdentityID], usageRow{Service: r.Service, LastUsedAt: r.LastUsedAt,
			GeneratedAt: r.GeneratedAt, Generation: r.LastSeenGeneration})
	}
	// The newest generation that touched each connector's activity
	// (idetailActivity's rule).
	if u.maxGen, err = cloudReads.ActivityGenerations(tx, ws, models.UsageSourceServiceLastAccessed, cids); err != nil {
		return nil, fmt.Errorf("activity generations: %w", err)
	}
	return u, nil
}

// Reasons an activity report is not collected for a role (they extend
// Evaluate's own: partition_not_in_manifest, run_evidence_missing,
// not_in_activity_sample, report_run_mismatch, report_time_missing).
const (
	ActivityReasonNotRead        = "activity_not_read_by_run"
	ActivityReasonSurfaceFailed  = "activity_surface_not_reached"
	ActivityReasonNotInScan      = "not_in_scan"
	ActivityReasonReportNotRead  = "report_not_read"
	ActivityReasonNewerScanState = "newer_scan_not_published"
)

// activityFor is the role's Access Advisor report as of its manifest run,
// by idetailActivity's rules (D-86, T3.03): the run's activity surface
// decides whether the role was read; SurfaceCoverage.ActivitySampled names
// the capped sample (nil: outside it); rows must carry exactly the run's
// generation, and none may be newer.
func activityFor(gs *govSnapshot, r igagov.RoleSnapshot, cloudID uuid.UUID, u *govUsage) *igagov.ActivityReport {
	runID, ok := gs.Snap.Manifest[r.PartitionKey]
	if !ok {
		return nil // Evaluate: partition_not_in_manifest
	}
	meta, ok := gs.Runs[runID]
	if !ok {
		return nil // Evaluate: run_evidence_missing
	}
	notCollected := func(reason string) *igagov.ActivityReport {
		return &igagov.ActivityReport{ScanRunID: runID, State: igagov.EvidenceNotCollected, Reason: reason}
	}
	surf, read := meta.Coverage.Surfaces[models.SurfaceActivity]
	switch {
	case !read:
		return notCollected(ActivityReasonNotRead)
	case surf.State != models.CloudCoverageReached && surf.State != models.CloudCoveragePartial:
		return notCollected(ActivityReasonSurfaceFailed)
	case surf.State == models.CloudCoveragePartial && !surf.ActivitySampled(r.ARN):
		return nil // Evaluate: not_in_activity_sample
	}
	if u.maxGen[meta.ConnectorID] > meta.Generation {
		return notCollected(ActivityReasonNewerScanState)
	}
	rep := &igagov.ActivityReport{ScanRunID: runID, State: igagov.EvidenceCollected}
	for _, row := range u.rows[cloudID] {
		if row.Generation != meta.Generation {
			continue
		}
		rep.Services = append(rep.Services, igagov.ServiceActivity{Service: row.Service, LastAuthenticatedAt: utcPtr(row.LastUsedAt)})
		if row.GeneratedAt != nil && row.GeneratedAt.UTC().After(rep.GeneratedAt) {
			rep.GeneratedAt = row.GeneratedAt.UTC()
		}
	}
	if surf.State == models.CloudCoveragePartial && len(rep.Services) == 0 {
		// A partial read cannot tell "no services" from "report failed".
		return notCollected(ActivityReasonReportNotRead)
	}
	return rep
}

// activityNoInventory is the answer for a role whose inventory row is not in
// its connector's tables: not collected, when the run read activity at all.
func activityNoInventory(gs *govSnapshot, r igagov.RoleSnapshot) *igagov.ActivityReport {
	runID, ok := gs.Snap.Manifest[r.PartitionKey]
	if !ok {
		return nil
	}
	if _, ok := gs.Runs[runID]; !ok {
		return nil
	}
	return &igagov.ActivityReport{ScanRunID: runID, State: igagov.EvidenceNotCollected, Reason: ActivityReasonNotInScan}
}

/* ---------------------------------- helpers -------------------------------- */

func keysOf(m map[uuid.UUID]bool) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func stringKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// nativeOfSourceKey is the native id (ARN) of an AWS graph source key.
func nativeOfSourceKey(key string) string {
	parts := strings.Split(key, igagraph.Sep)
	if len(parts) < 2 || parts[0] != "aws" {
		return ""
	}
	return parts[len(parts)-1]
}

// govARNField is field i of an ARN ("" when absent).
func govARNField(arn string, i int) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || i >= len(parts) {
		return ""
	}
	return parts[i]
}
