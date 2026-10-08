package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Dedicated-identity isolation (SPEC-iga-phase3-policy.md §11; T3.17):
// proposing a dedicated_identity version (split + split_revert plans,
// compiled by igagov.CompileSplit, delivered only as iac_pr or export), the
// migration subjects (iga_gov_workload_migration, one row per subject and
// plan), and the per-subject migration evidence read by the discovery role
// (T3.03b's readers, internal/awsdiscovery/migration_evidence.go) that decides
// `moved` and `remaining_old_refs`.
//
// A row is `moved` only on complete evidence (every list returned all its
// pages, every describe succeeded, the subject's region read), nothing left
// on the old role, and the new workload published in the graph -- the same
// rule 051's iga_gov_wm_moved_chk enforces. Anything less is `incomplete`
// (evidence) or `moving` / `pending`. The split's binding fact (§2.8) is
// observed at its after value only when its row is moved, so `artifact`
// (applied_unverified) is reached only when every row is moved.

// GovMigrationClients builds one region's migration-evidence clients for a
// connector (the discovery role).
type GovMigrationClients func(ctx context.Context, ws, connectorID uuid.UUID, region string) (awsdiscovery.MigrationClients, error)

var (
	govMigMu      sync.RWMutex
	govMigClients GovMigrationClients
)

// SetGovMigrationClients installs the process-wide factory.
func SetGovMigrationClients(f GovMigrationClients) {
	govMigMu.Lock()
	govMigClients = f
	govMigMu.Unlock()
}

// DefaultGovMigrationClients is the process-wide factory, or nil.
func DefaultGovMigrationClients() GovMigrationClients {
	govMigMu.RLock()
	defer govMigMu.RUnlock()
	return govMigClients
}

/* ----------------------------- graph lookups ------------------------------ */

// workloadsExecutingAsARN are the graph workload keys with a current
// executes_as relationship to the role with this ARN.
func workloadsExecutingAsARN(db *gorm.DB, ws uuid.UUID, roleARN string) ([]string, error) {
	var keys []string
	err := db.Raw(`SELECT DISTINCT w.source_key FROM iga_workload w
		JOIN iga_relationship r ON r.workspace_id = w.workspace_id AND r.source_workload_id = w.id
		 AND r.relationship_type = ? AND r.state = 'current'
		JOIN iga_identity_accounts i ON i.workspace_id = r.workspace_id AND i.id = r.target_identity_account_id
		WHERE w.workspace_id = ? AND i.source_key = ? ORDER BY w.source_key`,
		models.RelTypeExecutesAs, ws, igagraph.IdentityARNKey(roleARN)).Scan(&keys).Error
	return keys, err
}

// keyARN is the ARN inside a graph source key ("aws<US>arn").
func keyARN(k string) string {
	if i := strings.LastIndex(k, igagraph.Sep); i >= 0 {
		return k[i+len(igagraph.Sep):]
	}
	return k
}

// ecsFamily is "family" of a task-definition ARN (".../task-definition/family:rev").
func ecsFamily(tdARN string) string {
	i := strings.Index(tdARN, ":task-definition/")
	if i < 0 {
		return ""
	}
	f := tdARN[i+len(":task-definition/"):]
	if j := strings.LastIndex(f, ":"); j >= 0 {
		f = f[:j]
	}
	return f
}

// subjectPredicate says whether a graph workload key belongs to a subject:
// ECS, any revision of the subject's family; Lambda, the function; EC2,
// one of the instances.
func subjectPredicate(kind, subjectARN string, fromKeys, instances []string) func(string) bool {
	switch kind {
	case igagov.SubjectECSService:
		fams := map[string]bool{}
		for _, k := range fromKeys {
			if f := ecsFamily(keyARN(k)); f != "" {
				fams[f] = true
			}
		}
		return func(k string) bool { return fams[ecsFamily(keyARN(k))] }
	case igagov.SubjectLambdaFunction:
		return func(k string) bool {
			a := keyARN(k)
			return a == subjectARN || strings.HasPrefix(a, subjectARN+":")
		}
	default:
		set := map[string]bool{}
		for _, i := range instances {
			set[i] = true
		}
		if kind == igagov.SubjectEC2Instance {
			set[subjectARN[strings.LastIndex(subjectARN, "/")+1:]] = true
		}
		return func(k string) bool {
			a := keyARN(k)
			return set[a[strings.LastIndexAny(a, "/:")+1:]]
		}
	}
}

/* --------------------------- migration decisions --------------------------- */

// GovMigrationDecision is what one subject's evidence shows.
type GovMigrationDecision struct {
	Moved     bool           `json:"moved"`
	Remaining int            `json:"remaining_old_refs"`
	AnyOnNew  bool           `json:"any_on_new"`
	Observed  map[string]any `json:"observed"`
}

func hasKeyFor(keys []string, arn string) bool {
	for _, k := range keys {
		if keyARN(k) == arn {
			return true
		}
	}
	return false
}

// DecideECSService is §11's ECS rule: moved when the service has one
// deployment, PRIMARY, COMPLETED, on a new-role revision, running = desired,
// and every running task of the service runs a new-role revision; remaining
// counts running tasks of the service and of the family on an old-role
// revision.
func DecideECSService(st awsdiscovery.ECSServiceState, family []awsdiscovery.ECSTask, fromKeys, toKeys []string) GovMigrationDecision {
	d := GovMigrationDecision{Observed: map[string]any{"found": st.Found, "deployments": st.Deployments,
		"running": st.RunningCount, "desired": st.DesiredCount}}
	seen := map[string]bool{}
	onNew, total := 0, 0
	for _, t := range append(append([]awsdiscovery.ECSTask{}, st.RunningTasks...), family...) {
		if seen[t.TaskARN] {
			continue
		}
		seen[t.TaskARN] = true
		if hasKeyFor(fromKeys, t.TaskDefinitionARN) {
			d.Remaining++
		}
		if hasKeyFor(toKeys, t.TaskDefinitionARN) {
			d.AnyOnNew = true
		}
	}
	for _, t := range st.RunningTasks {
		total++
		if hasKeyFor(toKeys, t.TaskDefinitionARN) {
			onNew++
		}
	}
	d.Observed["service_tasks"], d.Observed["service_tasks_on_new"] = total, onNew
	if !st.Found || len(st.Deployments) != 1 {
		return d
	}
	dep := st.Deployments[0]
	d.Moved = dep.Status == "PRIMARY" && dep.RolloutState == "COMPLETED" && hasKeyFor(toKeys, dep.TaskDefinition) &&
		st.RunningCount == st.DesiredCount && onNew == total && d.Remaining == 0
	return d
}

// DecideLambdaFunction is §11's Lambda rule: moved when $LATEST, every
// alias's version and every weighted version run as the new role and no
// event-source mapping targets a version on the old role; remaining counts
// aliases, weighted versions and mappings (and $LATEST) on the old role.
func DecideLambdaFunction(st awsdiscovery.LambdaFunctionState, fromRole, toRole string) GovMigrationDecision {
	role := map[string]string{"$LATEST": st.LatestRole, "": st.LatestRole}
	for _, v := range st.Versions {
		role[v.Version] = v.Role
	}
	d := GovMigrationDecision{Observed: map[string]any{"latest_role": st.LatestRole, "aliases": st.Aliases,
		"event_source_mappings": len(st.EventSourceMappings)}}
	allNew := st.LatestRole == toRole
	if st.LatestRole == fromRole {
		d.Remaining++
	}
	var old []string
	for _, a := range st.Aliases {
		if role[a.FunctionVersion] == fromRole {
			d.Remaining++
			old = append(old, a.Name+"@"+a.FunctionVersion)
		}
		allNew = allNew && role[a.FunctionVersion] == toRole
		for v := range a.AdditionalWeight {
			if role[v] == fromRole {
				d.Remaining++
				old = append(old, a.Name+"~"+v)
			}
			allNew = allNew && role[v] == toRole
		}
	}
	for _, m := range st.EventSourceMappings {
		q := ""
		if parts := strings.Split(m.FunctionARN, ":"); len(parts) == 8 {
			q = parts[7]
		}
		if role[q] == fromRole {
			d.Remaining++
			old = append(old, "esm:"+m.UUID)
		}
	}
	d.AnyOnNew = st.LatestRole == toRole
	d.Observed["old_references"] = old
	d.Moved = allNew && d.Remaining == 0
	return d
}

func profileName(arn string) string { return arn[strings.LastIndex(arn, "/")+1:] }

// DecideAutoScalingGroup is §11's EC2 rule: moved when the group's launch
// template version names the new profile and every InService instance has
// an `associated` association to it; remaining counts InService instances
// not on it. DECISION (T3.17): the new instance profile carries the new
// role's name (iacpr renders it so); for a revert the "new" profile is any
// profile other than the split's.
func DecideAutoScalingGroup(st awsdiscovery.AutoScalingGroupState, isTarget func(profileARN, profileName string) bool) GovMigrationDecision {
	d := GovMigrationDecision{Observed: map[string]any{"found": st.Found, "launch_template_profile": st.LaunchTemplateProfileARN,
		"in_service": st.InServiceInstances}}
	assoc := map[string]awsdiscovery.InstanceProfileAssociation{}
	for _, a := range st.Associations {
		if a.State == "associated" {
			assoc[a.InstanceID] = a
		}
	}
	var old []string
	for _, i := range st.InServiceInstances {
		a, ok := assoc[i]
		if ok && isTarget(a.ProfileARN, profileName(a.ProfileARN)) {
			d.AnyOnNew = true
			continue
		}
		d.Remaining++
		old = append(old, i)
	}
	d.Observed["instances_on_old_profile"] = old
	ltOK := isTarget(st.LaunchTemplateProfileARN, st.LaunchTemplateProfile) ||
		(st.LaunchTemplateProfileARN == "" && st.LaunchTemplateProfile != "" && isTarget("", st.LaunchTemplateProfile))
	d.Moved = st.Found && ltOK && d.Remaining == 0
	return d
}

/* ------------------------------ migration rows ----------------------------- */

func subjectRegion(arn string) string {
	p := strings.Split(arn, ":")
	if len(p) > 3 {
		return p[3]
	}
	return ""
}

// ensureMigrationRows inserts the plan's migration subject (state pending)
// when a split / split_revert deployment starts.
func (d *GovIaCDelivery) ensureMigrationRows(tx *gorm.DB, ws uuid.UUID, x *iacDep) error {
	if (x.plan.Kind != igagov.PlanSplit && x.plan.Kind != igagov.PlanSplitRevert) || x.plan.Diff.Split == nil {
		return nil
	}
	s := x.plan.Diff.Split
	from, to, keys := s.SourceRoleARN, s.NewRoleARN, s.FromWorkloadKeys
	if x.plan.Kind == igagov.PlanSplitRevert {
		from, to = s.NewRoleARN, s.SourceRoleARN
		var prev []models.IGAGovWorkloadMigration
		if err := tx.Where("workspace_id = ? AND control_id = ? AND subject_arn = ? AND to_role_arn = ? AND state = 'moved'",
			ws, x.control.ID, s.SubjectARN, s.NewRoleARN).Order("checked_at DESC").Limit(1).Find(&prev).Error; err != nil {
			return err
		}
		keys = []string{}
		if len(prev) == 1 {
			keys = prev[0].ToWorkloadKeys
		}
	}
	if keys == nil {
		keys = []string{}
	}
	return tx.Exec(`INSERT INTO iga_gov_workload_migration (workspace_id, plan_id, control_id, subject_kind, subject_arn,
		from_role_arn, to_role_arn, from_workload_keys) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (plan_id, subject_kind, subject_arn) DO NOTHING`,
		ws, x.planRow.ID, x.control.ID, s.SubjectKind, s.SubjectARN, from, to, pq.StringArray(keys)).Error
}

// GovMigrationCheck is one subject's check.
type GovMigrationCheck struct {
	RowID     uuid.UUID            `json:"row_id"`
	Subject   string               `json:"subject_arn"`
	Kind      string               `json:"subject_kind"`
	State     string               `json:"state"`
	Complete  bool                 `json:"evidence_complete"`
	Remaining *int                 `json:"remaining_old_refs"`
	ToKeys    []string             `json:"to_workload_keys"`
	Decision  GovMigrationDecision `json:"decision"`
}

// checkMigrations reads every migration subject of the deployment's plan,
// updates its row, and returns the binding each subject shows (the new role
// only when moved).
func (d *GovIaCDelivery) checkMigrations(ctx context.Context, run *PolicyJobRun, ws uuid.UUID, x *iacDep, newRoleID string) ([]GovMigrationCheck, map[string]string, error) {
	db := d.db.WithContext(ctx)
	var rows []models.IGAGovWorkloadMigration
	if err := db.Where("workspace_id = ? AND plan_id = ?", ws, x.planRow.ID).Order("subject_arn").Find(&rows).Error; err != nil {
		return nil, nil, err
	}
	if len(rows) == 0 {
		if err := run.InTx(ctx, func(tx *gorm.DB) error { return d.ensureMigrationRows(tx, ws, x) }); err != nil {
			return nil, nil, err
		}
		if err := db.Where("workspace_id = ? AND plan_id = ?", ws, x.planRow.ID).Find(&rows).Error; err != nil {
			return nil, nil, err
		}
	}
	bindings := map[string]string{}
	var checks []GovMigrationCheck
	now := d.now().UTC()
	for _, row := range rows {
		region := subjectRegion(row.SubjectARN)
		ev := &awsdiscovery.MigrationEvidence{APIs: map[string]*awsdiscovery.APIStats{}, Regions: []string{}}
		var dec GovMigrationDecision
		var instances []string
		mf := d.migrationClients()
		var clients awsdiscovery.MigrationClients
		var cerr error
		if mf == nil {
			cerr = errors.New("migration evidence reads are not configured")
		} else {
			cerr = run.External(ctx, 0, func(ctx context.Context) error {
				var err error
				clients, err = mf(ctx, ws, x.control.ConnectorID, region)
				return err
			})
			if errors.Is(cerr, repositories.ErrPolicyJobLeaseLost) {
				return nil, nil, cerr
			}
		}
		toKeys, err := workloadsExecutingAsARN(db, ws, row.ToRoleARN)
		if err != nil {
			return nil, nil, err
		}
		if cerr != nil {
			ev.APIs["session"] = &awsdiscovery.APIStats{Failures: 1, Errors: []string{"session_unavailable"}}
		} else {
			r := awsdiscovery.NewMigrationEvidenceReader(region, clients)
			if err := run.External(ctx, 0, func(ctx context.Context) error {
				switch row.SubjectKind {
				case igagov.SubjectECSService:
					cl := row.SubjectARN
					// arn:aws:ecs:r:acct:service/<cluster>/<name>
					parts := strings.Split(cl[strings.Index(cl, ":service/")+len(":service/"):], "/")
					clusterARN := cl[:strings.Index(cl, ":service/")] + ":cluster/" + parts[0]
					st, sev := r.ECSService(ctx, awsdiscovery.ECSServiceRef{ClusterARN: clusterARN, ServiceARN: row.SubjectARN})
					ev = sev
					fam := ""
					for _, k := range row.FromWorkloadKeys {
						if f := ecsFamily(keyARN(k)); f != "" {
							fam = f
						}
					}
					var famTasks []awsdiscovery.ECSTask
					if fam != "" {
						var fev *awsdiscovery.MigrationEvidence
						famTasks, fev = r.ECSFamilyRunningTasks(ctx, fam)
						ev.Merge(fev)
					}
					pred := subjectPredicate(row.SubjectKind, row.SubjectARN, row.FromWorkloadKeys, nil)
					var tk []string
					for _, k := range toKeys {
						if pred(k) {
							tk = append(tk, k)
						}
					}
					toKeys = tk
					dec = DecideECSService(st, famTasks, row.FromWorkloadKeys, toKeys)
				case igagov.SubjectLambdaFunction:
					name := row.SubjectARN[strings.LastIndex(row.SubjectARN, ":")+1:]
					st, sev := r.LambdaFunction(ctx, name)
					ev = sev
					dec = DecideLambdaFunction(st, row.FromRoleARN, row.ToRoleARN)
				case igagov.SubjectEC2ASG:
					name := row.SubjectARN[strings.LastIndex(row.SubjectARN, "/")+1:]
					st, sev := r.AutoScalingGroup(ctx, name)
					ev = sev
					instances = st.InServiceInstances
					toName, fromName := profileName(row.ToRoleARN), profileName(row.FromRoleARN)
					split := x.plan.Kind == igagov.PlanSplit
					dec = DecideAutoScalingGroup(st, func(arn, name string) bool {
						if name == "" {
							name = profileName(arn)
						}
						if split {
							return name == toName
						}
						return name != "" && name != fromName
					})
				case igagov.SubjectEC2Instance:
					id := row.SubjectARN[strings.LastIndex(row.SubjectARN, "/")+1:]
					as, sev := r.InstanceAssociations(ctx, []string{id})
					ev = sev
					instances = []string{id}
					st := awsdiscovery.AutoScalingGroupState{Found: true, InServiceInstances: []string{id}, Associations: as}
					if len(as) > 0 {
						st.LaunchTemplateProfileARN = as[0].ProfileARN
					}
					toName, fromName := profileName(row.ToRoleARN), profileName(row.FromRoleARN)
					split := x.plan.Kind == igagov.PlanSplit
					dec = DecideAutoScalingGroup(st, func(arn, name string) bool {
						name = profileName(arn)
						if split {
							return name == toName
						}
						return name != "" && name != fromName
					})
				}
				return nil
			}); err != nil {
				return nil, nil, err
			}
		}
		if row.SubjectKind != igagov.SubjectECSService {
			pred := subjectPredicate(row.SubjectKind, row.SubjectARN, row.FromWorkloadKeys, instances)
			var tk []string
			for _, k := range toKeys {
				if pred(k) {
					tk = append(tk, k)
				}
			}
			toKeys = tk
		}
		regionRead := false
		for _, rg := range ev.Regions {
			regionRead = regionRead || rg == region
		}
		complete := ev.Complete() && regionRead
		state := "pending"
		var remaining *int
		switch {
		case !complete:
			state = "incomplete"
		case dec.Moved && len(toKeys) > 0:
			state = "moved"
			z := 0
			remaining = &z
		default:
			n := dec.Remaining
			remaining = &n
			if dec.AnyOnNew || dec.Moved {
				state = "moving"
			}
		}
		if toKeys == nil {
			toKeys = []string{}
		}
		evRaw, _ := json.Marshal(map[string]any{"apis": ev.APIs, "regions": ev.Regions, "decision": dec, "new_role_id": newRoleID})
		err = run.InTx(ctx, func(tx *gorm.DB) error {
			return tx.Model(&models.IGAGovWorkloadMigration{}).Where("workspace_id = ? AND id = ?", ws, row.ID).
				Updates(map[string]any{"state": state, "evidence": json.RawMessage(evRaw), "evidence_complete": complete,
					"remaining_old_refs": remaining, "checked_at": now, "to_workload_keys": pq.StringArray(toKeys)}).Error
		})
		if err != nil {
			return nil, nil, err
		}
		bindings[row.SubjectARN] = row.FromRoleARN
		if state == "moved" {
			bindings[row.SubjectARN] = row.ToRoleARN
		}
		checks = append(checks, GovMigrationCheck{RowID: row.ID, Subject: row.SubjectARN, Kind: row.SubjectKind, State: state,
			Complete: complete, Remaining: remaining, ToKeys: toKeys, Decision: dec})
	}
	return checks, bindings, nil
}

/* --------------------------- proposing isolation --------------------------- */

// subjectKindFor maps a binding to §11's migration subject.
func subjectKindFor(binding, ref string) string {
	switch binding {
	case igagov.BindingECSTaskRole:
		return igagov.SubjectECSService
	case igagov.BindingLambdaRole:
		return igagov.SubjectLambdaFunction
	case igagov.BindingEC2InstanceProfile:
		if strings.Contains(ref, ":autoScalingGroup:") {
			return igagov.SubjectEC2ASG
		}
		return igagov.SubjectEC2Instance
	}
	return ""
}

// GovIsolationInput is what proposing a dedicated identity reads beyond the
// version: the graph keys and compute facts the compiler needs (§11).
type GovIsolationInput struct {
	FromWorkloadKeys  []string
	TaskFamily        string
	Aliases           []string
	UnaliasedVersions []string
}

// isolationInput derives the subject's graph keys and compute facts: the
// intent's workload names the graph workload; for ECS every revision of its
// family bound to the source role is a from key (§11 "the family's
// revisions bound to the source role"); for Lambda the aliases and the
// versions behind none are read through the migration evidence reader.
func (a *GovAuthoring) isolationInput(ctx context.Context, ws uuid.UUID, c models.IGAGovControl, di igagov.DedicatedIdentityIntent) (GovIsolationInput, error) {
	db := a.db.WithContext(ctx)
	out := GovIsolationInput{}
	wid, err := uuid.Parse(di.Workload.WorkloadID)
	if err != nil {
		return out, err
	}
	var keys []string
	if err := db.Raw(`SELECT source_key FROM iga_workload WHERE workspace_id = ? AND id = ?`, ws, wid).Scan(&keys).Error; err != nil {
		return out, err
	}
	if len(keys) != 1 {
		return out, govUnprocessable("workload_not_found", "The intent's workload is not in the graph.", map[string]any{"workload_id": wid})
	}
	bound, err := workloadsExecutingAsARN(db, ws, c.RoleARN)
	if err != nil {
		return out, err
	}
	kind := subjectKindFor(di.Workload.BindingKind, di.Workload.BindingRef)
	if kind == igagov.SubjectECSService {
		out.TaskFamily = ecsFamily(keyARN(keys[0]))
		pred := subjectPredicate(kind, di.Workload.BindingRef, keys, nil)
		for _, k := range bound {
			if pred(k) {
				out.FromWorkloadKeys = append(out.FromWorkloadKeys, k)
			}
		}
	}
	if len(out.FromWorkloadKeys) == 0 {
		out.FromWorkloadKeys = keys
	}
	if kind == igagov.SubjectLambdaFunction {
		if mf := DefaultGovMigrationClients(); mf != nil {
			region := subjectRegion(di.Workload.BindingRef)
			if cl, err := mf(ctx, ws, c.ConnectorID, region); err == nil {
				name := di.Workload.BindingRef[strings.LastIndex(di.Workload.BindingRef, ":")+1:]
				st, _ := awsdiscovery.NewMigrationEvidenceReader(region, cl).LambdaFunction(ctx, name)
				ref := map[string]bool{}
				for _, al := range st.Aliases {
					out.Aliases = append(out.Aliases, al.Name)
					ref[al.FunctionVersion] = true
					for v := range al.AdditionalWeight {
						ref[v] = true
					}
				}
				for _, v := range st.Versions {
					if !ref[v.Version] {
						out.UnaliasedVersions = append(out.UnaliasedVersions, v.Version)
					}
				}
			}
		}
	}
	return out, nil
}

// proposeIsolation is Propose for a dedicated_identity version (§7.3, §11):
// a fresh bundle and live reads of the source role and the new role's ARN,
// igagov.CompileSplit, the compile-time IaC form decision, and the split and
// split_revert plans persisted with their documents.
func (a *GovAuthoring) proposeIsolation(ctx context.Context, ws, actor, policyID uuid.UUID, no int, v *models.IGAGovPolicyVersion,
	di igagov.DedicatedIdentityIntent) (*ProposeResult, error) {
	db := a.db.WithContext(ctx)
	ts, cs, err := a.versionTargets(db, ws, v.ID)
	if err != nil {
		return nil, err
	}
	if len(ts) != 1 {
		return nil, govUnprocessable(GovCodeInvalidIntent, "A dedicated identity version has exactly one target: the source role's control.",
			map[string]any{"targets": len(ts)})
	}
	t, c := ts[0], cs[ts[0].ID]
	// fix/p3-appr (P0-2): a re-proposed version never rewrites the plans of
	// a target that already carries one of its deployments.
	if dep, err := deployedTargets(db, ws, v.ID, uuid.Nil); err != nil {
		return nil, err
	} else if dep[t.ID] {
		return nil, govConflict(GovCodeTargetDeployed, "This target already carries a deployment of this version; its plans are not recompiled.",
			map[string]any{"target_id": t.ID, "role_id": c.RoleID})
	}
	ct, blk, err := a.compileIsolationOne(ctx, ws, di, t, c, directCall)
	if err != nil {
		return nil, err
	}
	if blk != nil {
		return nil, blk.Err
	}
	if !ct.Plans.Apply.Eligible() {
		sp := ct.Plans.Apply
		return nil, govUnprocessable(GovCodeTargetIneligible, "The dedicated identity cannot be proposed.", map[string]any{"targets": []any{
			map[string]any{"target_id": t.ID, "role_id": c.RoleID, "reasons": sp.Refusals, "ineligible_reason": sp.IneligibleReason}}})
	}
	k, aid := userActor(actor)
	if err := a.storeCompiled(ctx, ws, []*compiledTarget{ct}, k, aid); err != nil {
		return nil, err
	}
	return a.persistIsolationProposal(ctx, ws, actor, policyID, no, v, c, ct)
}

// compileIsolationOne is the in-memory compile of a dedicated_identity
// target (§11): a fresh bundle and live reads of the source role and the new
// role's ARN, igagov.CompileSplit, and the compile-time IaC form decision.
// Nothing is written. Propose and revalidation (fix/p3-appr P1-10: a stale
// split must be revalidatable, §2.8) share it, so the recompiled
// material_hash is comparable with the approved one. A refusal that a
// revalidation records as `blocked` (untrusted evidence, a failed live
// read, a compiler refusal, the workload gone from the graph) is a
// compileBlock whose Err is what propose answers. An ineligible split is
// returned as compiled (the caller decides) and skips the IaC decision.
func (a *GovAuthoring) compileIsolationOne(ctx context.Context, ws uuid.UUID, di igagov.DedicatedIdentityIntent, t models.IGAGovTarget,
	c models.IGAGovControl, call liveCaller) (*compiledTarget, *compileBlock, error) {
	db := a.db.WithContext(ctx)
	facts, err := LoadIaCConnectorFacts(db, ws, c.ConnectorID)
	if err != nil {
		return nil, nil, err
	}
	b, src, basis, err := a.targets.buildBasis(ctx, ws, c.IdentityAccountID, nil)
	if err != nil {
		if ge := bundleBuildError(err, c.RoleID); ge != nil {
			return nil, &compileBlock{Err: ge, Reason: "evidence_unavailable: " + reasonOf(err)}, nil
		}
		return nil, nil, err
	}
	if b.Trust == igagov.TrustUntrusted {
		return nil, &compileBlock{Bundle: &b, Reason: "evidence_untrusted: " + strings.Join(b.TrustReasons, "; "),
			Err: StoredBundle{Hash: b.Hash, Trust: b.Trust, TrustReasons: b.TrustReasons, Facts: b.Facts}.UntrustedError()}, nil
	}
	if a.live == nil {
		return nil, &compileBlock{Bundle: &b, Reason: "discovery_unavailable: live reads are not configured",
			Err: govErr(http.StatusServiceUnavailable, GovCodeDiscoveryUnavail, "AWS cannot be read through the discovery role right now.", nil)}, nil
	}
	newARN := "arn:" + arnPartition(c.RoleARN) + ":iam::" + c.AccountID + ":role" + di.NewRole.Path + di.NewRole.Name
	var live, nl igagov.LiveRead
	if err := call(ctx, func(ctx context.Context) error {
		var e error
		if live, e = a.live.ReadRole(ctx, LiveReadRequest{WorkspaceID: ws, ConnectorID: c.ConnectorID, AccountID: c.AccountID,
			RoleARN: c.RoleARN, RoleID: c.RoleID}); e != nil {
			return e
		}
		nl, e = a.live.ReadRole(ctx, LiveReadRequest{WorkspaceID: ws, ConnectorID: c.ConnectorID, AccountID: c.AccountID, RoleARN: newARN})
		return e
	}); err != nil {
		if errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
			return nil, nil, err
		}
		return nil, &compileBlock{Bundle: &b, Reason: "discovery_unavailable: " + err.Error(),
			Err: govErr(http.StatusServiceUnavailable, GovCodeDiscoveryUnavail, "AWS cannot be read through the discovery role right now.",
				map[string]any{"reason": err.Error()})}, nil
	}
	live.Roles = map[string]*igagov.LiveRole{newARN: nl.Role}
	if live.ReadAt.IsZero() {
		live.ReadAt = a.now()
	}
	iso, err := a.isolationInput(ctx, ws, c, di)
	if err != nil {
		var ge *GovError
		if errors.As(err, &ge) {
			return nil, &compileBlock{Bundle: &b, Reason: ge.Code + ": " + ge.Message, Err: ge}, nil
		}
		return nil, nil, err
	}
	in := igagov.SplitInput{
		Control: igagov.ControlRef{ID: c.ID.String(), PolicyID: c.PolicyID.String(), AccountID: c.AccountID, RoleID: c.RoleID,
			WorkspaceRef: GovWorkspaceRef(ws)},
		Intent: di, Live: live, Evidence: igagov.EvidenceRef{Bundle: b, EvidenceRev: src.Rev, ScanRunID: src.ConnectorRun},
		SubjectKind: subjectKindFor(di.Workload.BindingKind, di.Workload.BindingRef), SubjectARN: di.Workload.BindingRef,
		FromWorkloadKeys: iso.FromWorkloadKeys, TaskFamily: iso.TaskFamily, Aliases: iso.Aliases, UnaliasedVersions: iso.UnaliasedVersions,
		AccountServices: accountServicesOf(b.Facts),
		// DECISION (T3.17, D55): R1a's PR does not edit resource or trust
		// policies, so no compatibility item is "in the mapped source": each
		// is owner confirmation (route_confirmations) as §11 requires when
		// the PR cannot add the new role.
		MappedResources:            map[string]bool{},
		MigrationEvidenceAvailable: facts.MigrationEvidence,
	}
	if basis.HasRun {
		in.ScanEvidence = basis.Run.ResourcePolicy
	}
	blocked := func(err error) (*compiledTarget, *compileBlock, error) {
		var ce *igagov.CompileError
		if !errors.As(err, &ce) {
			return nil, nil, err
		}
		ge, _ := compileErrorAsGov(err, c.RoleID).(*GovError)
		return nil, &compileBlock{Bundle: &b, Reason: ce.Code + ": " + strings.Join(ce.Reasons, "; "), Err: ge}, nil
	}
	sp, err := igagov.CompileSplit(in)
	if err != nil {
		return blocked(err)
	}
	if sp.Split.Eligible() && di.Delivery == igagov.DeliveryIaCPR {
		f, err := DecideIaCForm(ctx, db, a.iacGitHub(), ws, c, sp.Split, map[string]string{}, "", false)
		if err != nil {
			if errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
				return nil, nil, err
			}
			var ge *GovError
			if errors.As(err, &ge) {
				return nil, &compileBlock{Bundle: &b, Reason: ge.Code + ": " + ge.Message, Err: ge}, nil
			}
			return nil, &compileBlock{Bundle: &b, Reason: GovCodeIaCUnavailable + ": " + err.Error(),
				Err: govErr(http.StatusServiceUnavailable, GovCodeIaCUnavailable, "The mapped IaC source could not be read.",
					map[string]any{"reason": err.Error(), "role_id": c.RoleID})}, nil
		}
		if f.Fallback != nil {
			in.Intent.Delivery = igagov.DeliveryExport
			if sp, err = igagov.CompileSplit(in); err != nil {
				return blocked(err)
			}
			note := iacFallbackNote(f.Fallback)
			sp.Split.Diff.Notes = append(sp.Split.Diff.Notes, note)
			if sp.Revert != nil {
				sp.Revert.Diff.Notes = append(sp.Revert.Diff.Notes, note)
			}
		}
	}
	return &compiledTarget{Target: t, Control: c, Bundle: b, Plans: igagov.TargetPlans{Apply: sp.Split, Undo: sp.Revert}, ReadAt: live.ReadAt}, nil, nil
}

// persistIsolationProposal stores a compiled dedicated-identity target as
// the version's current plans and moves the version to in_review.
func (a *GovAuthoring) persistIsolationProposal(ctx context.Context, ws, actor, policyID uuid.UUID, no int, v *models.IGAGovPolicyVersion,
	c models.IGAGovControl, ct *compiledTarget) (*ProposeResult, error) {
	db := a.db.WithContext(ctx)
	k, aid := userActor(actor)
	var out ProposeResult
	err := db.Transaction(func(tx *gorm.DB) error {
		cur, err := a.loadVersion(tx, ws, policyID, no, true)
		if err != nil {
			return err
		}
		if cur.Status != v.Status {
			return govConflict(GovCodeVersionConflict, "The version changed while it was being compiled.", map[string]any{"status": cur.Status})
		}
		sp, rp, err := a.persistTargetTx(tx, ws, v.ID, ct)
		if err != nil {
			return err
		}
		ids := []uuid.UUID{sp.ID}
		if rp != nil {
			ids = append(ids, rp.ID)
		}
		reproposed := cur.Status == "in_review"
		if !reproposed {
			if err := tx.Model(&models.IGAGovPolicyVersion{}).Where("workspace_id = ? AND id = ?", ws, v.ID).
				Updates(map[string]any{"status": "in_review", "status_changed_at": a.now()}).Error; err != nil {
				return err
			}
		}
		if err := a.event(tx, ws, "version_proposed", k, aid, &policyID, &v.ID, map[string]any{"version_no": no,
			"plan_ids": ids, "reproposed": reproposed, "kind": igagov.IntentDedicatedIdentity}); err != nil {
			return err
		}
		if h := a.hooks().OnProposed; h != nil {
			if err := h(tx, GovProposedVersion{WorkspaceID: ws, PolicyID: policyID, VersionID: v.ID, VersionNo: no, ActorID: actor,
				ApplyPlans: []GovPlanSummary{summary(*sp, c)}, Reproposed: reproposed}); err != nil {
				return err
			}
		}
		nv, err := a.loadVersion(tx, ws, policyID, no, false)
		if err != nil {
			return err
		}
		vv, err := a.versionView(tx, *nv)
		if err != nil {
			return err
		}
		out.Version = vv
		pv, err := a.plansView(tx, ws, *nv)
		out.Plans = pv
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// compileErrorAsGov maps a compiler error to the §7.12 envelope.
func compileErrorAsGov(err error, roleID string) error {
	var ce *igagov.CompileError
	if !errors.As(err, &ce) {
		return err
	}
	detail := map[string]any{"role_id": roleID, "reasons": ce.Reasons, "compile_code": ce.Code}
	switch ce.Code {
	case igagov.ErrCodeEvidenceUntrusted:
		return govUnprocessable(GovCodeEvidenceUntrusted, "The evidence for this role is not trustworthy enough to compile a change.", detail)
	case igagov.ErrCodeLiveIncomplete:
		return govErr(http.StatusServiceUnavailable, GovCodeDiscoveryUnavail, "The live read of this role was incomplete.", detail)
	case igagov.ErrCodeInvalidIntent:
		return govUnprocessable(GovCodeInvalidIntent, "The intent is not valid for this role.", detail)
	}
	return govUnprocessable(GovCodeTargetIneligible, fmt.Sprintf("This target cannot be compiled (%s).", ce.Code), detail)
}

// createIsolationVersion is POST /policies/:id/versions for a
// dedicated_identity intent (§7.3, §11 "Propose dedicated identity"): the
// next version of the policy that controls the source role, with one target
// (the source role's control). T3.11's route creates right_size_services
// versions; this is the "own flow" its parser points dedicated identities to.
//
// DECISION (T3.17): the version's evidence_rev is the latest complete
// evaluation's (a dedicated_identity intent carries none, and 049 requires
// one); the plan's evidence is the bundle compiled at propose time.
func (a *GovAuthoring) createIsolationVersion(ctx context.Context, ws, actor, policyID uuid.UUID, baseNo int, in *igagov.Intent) (*GovVersionView, error) {
	canon, hash, err := igagov.CanonicalIntent(*in)
	if err != nil {
		return nil, intentProblems(err)
	}
	di := in.DedicatedIdentity
	var out *GovVersionView
	err = a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		pol, err := a.loadPolicy(tx, ws, policyID, true)
		if err != nil {
			return err
		}
		if pol.Lifecycle == "archived" {
			return govConflict(GovCodePolicyArchived, "The policy is archived and read-only.", nil)
		}
		var latest models.IGAGovPolicyVersion
		if err := tx.Where("workspace_id = ? AND policy_id = ?", ws, policyID).Order("version_no DESC").Limit(1).Take(&latest).Error; err != nil {
			return err
		}
		if baseNo != latest.VersionNo {
			return govConflict(GovCodeVersionConflict, "The policy has a newer version; re-read it and edit that.",
				map[string]any{"base_version_no": baseNo, "current_version_no": latest.VersionNo, "current_status": latest.Status})
		}
		lc, err := a.targets.repo.LatestComplete(tx, ws)
		if err != nil {
			return err
		}
		if lc == nil {
			return ErrNoCompleteEvaluation
		}
		controls, err := a.bindSubjectsTx(tx, ws, policyID, []igagov.Subject{di.Source})
		if err != nil {
			return err
		}
		shim := &igagov.RightSizeIntent{EvidenceRev: lc.Rev}
		v, _, err := a.insertVersionTx(tx, ws, policyID, actor, latest.VersionNo+1, shim, canon, hash, controls)
		if err != nil {
			return err
		}
		if latest.Status == "draft" || latest.Status == "in_review" {
			if err := a.closeVersionTx(tx, actor, latest, "withdrawn", fmt.Sprintf("replaced by version %d", latest.VersionNo+1), nil); err != nil {
				return err
			}
		}
		k, aid := userActor(actor)
		if err := a.event(tx, ws, "version_created", k, aid, &policyID, &v.ID, map[string]any{"version_no": v.VersionNo,
			"base_version_no": baseNo, "intent_hash": hash, "kind": igagov.IntentDedicatedIdentity}); err != nil {
			return err
		}
		vv, err := a.versionView(tx, *v)
		out = &vv
		return err
	})
	return out, err
}
