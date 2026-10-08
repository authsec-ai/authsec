package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// dLab is the T3.16 fixture: T3.10's x3Lab (a verified binding over the fake
// AWS account, compiled and stored plans) plus an approver who holds
// governance:approve, the deployment state machine over the lab's AWS
// access with a controllable clock, and helpers to run one job of a kind the
// way the worker does. CloudTrail is the fake account's own (review P1-7):
// every enforcement-session call is recorded there and read back through
// the access's LookupEvents path; tests edit it with d.fake.EditTrail and
// make it unreadable with d.fake.TrailErr. The per-dispatch binding check is
// the production one over the lab's binding (review P1-8); beforeDispatch,
// when set, runs first.
type dLab struct {
	*x3Lab
	approver       uuid.UUID
	dep            *services.GovDeployments
	env            services.GovDeployEnv
	mu             sync.Mutex
	offset         time.Duration
	bindErr        error
	beforeDispatch func() error
	scanGen        int
	rev            int64
}

func newDLab(t *testing.T) *dLab {
	t.Helper()
	d := &dLab{x3Lab: newX3Lab(t), scanGen: 1, rev: 1}
	d.approver = d.memberWith("governance:approve")
	d.fake.Now = d.now
	dispatch := services.NewEnforcementBindingDispatchCheck(d.enf.svc)
	d.env = services.GovDeployEnv{AWS: d.access,
		Binding: func(context.Context, uuid.UUID, uuid.UUID) error { return d.bindErr },
		BindingState: func(ctx context.Context, ws, conn uuid.UUID) error {
			if d.beforeDispatch != nil {
				if err := d.beforeDispatch(); err != nil {
					return err
				}
			}
			return dispatch(ctx, ws, conn)
		}}
	env := d.env
	d.dep = services.NewGovDeployments(d.db, &env).WithClock(d.now).WithSleep(noSleep)
	d.dep.Executor = func(e *services.IGAGovAWSExecutor) { e.WithSleep(noSleep) }
	return d
}

func (d *dLab) now() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return time.Now().Add(d.offset)
}

func (d *dLab) advance(by time.Duration) {
	d.mu.Lock()
	d.offset += by
	d.mu.Unlock()
}

// memberWith adds an active member of the lab's workspace whose role holds
// the given permissions (full permission strings seeded by 055).
func (d *dLab) memberWith(perms ...string) uuid.UUID {
	d.t.Helper()
	user, role, mem := uuid.New(), uuid.New(), uuid.New()
	p3exec(d.t, d.db, `INSERT INTO users (id, email, name, workspace_id) VALUES (?, ?, 'Dee Approver', ?)`, user, user.String()+"@p3dep.test", d.ws)
	p3exec(d.t, d.db, `INSERT INTO roles (id, name, workspace_id) VALUES (?, ?, ?)`, role, "p3dep-"+role.String()[:8], d.ws)
	p3exec(d.t, d.db, `INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status) VALUES (?, ?, ?, ?, 'active')`,
		mem, d.ws, user, role)
	for _, p := range perms {
		p3exec(d.t, d.db, `INSERT INTO role_permissions (role_id, permission_id)
			SELECT ?, id FROM permissions WHERE full_permission_string = ? AND workspace_id IS NULL`, role, p)
	}
	d.t.Cleanup(func() {
		d.db.Exec(`DELETE FROM role_permissions WHERE role_id = ?`, role)
		d.db.Exec(`DELETE FROM workspace_memberships WHERE id = ?`, mem)
		d.db.Exec(`DELETE FROM roles WHERE id = ?`, role)
	})
	return user
}

// storeApproved stores plans under a new version, approved by the approver
// (the version approved, any earlier approved version superseded).
func (d *dLab) storeApproved(x *x3Role, plans ...igagov.Plan) x3Stored {
	d.t.Helper()
	p3exec(d.t, d.db, `UPDATE iga_gov_policy_version SET status = 'superseded' WHERE policy_id = ? AND status = 'approved'`, x.policy)
	s := d.store(x, plans...)
	p3exec(d.t, d.db, `UPDATE iga_gov_policy_version SET status = 'approved' WHERE id = ?`, s.version)
	p3exec(d.t, d.db, `UPDATE iga_gov_approval SET decided_by = ? WHERE id = ?`, d.approver, s.approval)
	return s
}

// queue inserts a queued deployment of a stored plan (as T3.15 does).
func (d *dLab) queue(x *x3Role, s x3Stored, kind string) uuid.UUID {
	d.t.Helper()
	id := uuid.New()
	p3exec(d.t, d.db, `INSERT INTO iga_gov_deployment (id, workspace_id, version_id, plan_id, control_id, approval_id, kind, delivery, state)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'direct', 'queued')`, id, d.ws, s.version, s.plans[kind], x.control, s.approval, kind)
	return id
}

// runJob runs one job of kind for the deployment as the worker would claim
// it (other open jobs of that kind in the workspace are closed first) and
// closes it; it returns the handler's error.
func (d *dLab) runJob(kind string, dep uuid.UUID) error {
	d.t.Helper()
	repo := repositories.NewIGAGovJobRepository(d.db)
	if _, err := repo.EnqueueTx(d.db, &models.IGAGovJob{WorkspaceID: d.ws, Kind: kind, SubjectID: &dep,
		DedupeKey: "deployment:" + dep.String(), RunAfter: d.now().Add(-time.Hour)}); err != nil {
		d.t.Fatal(err)
	}
	p3exec(d.t, d.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now(), lease_owner = '', lease_expires_at = NULL
		WHERE workspace_id = ? AND kind = ? AND status IN ('queued','running') AND subject_id IS DISTINCT FROM ?`, d.ws, kind, dep)
	p3exec(d.t, d.db, `UPDATE iga_gov_job SET run_after = ?, status = 'queued', lease_owner = '', lease_expires_at = NULL
		WHERE workspace_id = ? AND kind = ? AND subject_id = ? AND status IN ('queued','running')`, d.now().Add(-time.Hour), d.ws, kind, dep)
	j := p3ClaimOwn(d.t, d.db, d.ws, "worker-t", 2*time.Minute, d.now(), kind)
	if j == nil {
		d.t.Fatalf("no %s job to claim for %s", kind, dep)
	}
	run := services.NewPolicyJobRun(d.db, *j, "worker-t")
	var h services.PolicyJobHandler
	switch kind {
	case repositories.GovJobDeploy:
		h = d.dep.DeployHandler
	case repositories.GovJobVerify:
		h = d.dep.VerifyHandler
	case repositories.GovJobDriftCheck:
		h = d.dep.DriftHandler
	case repositories.GovJobResolveUnknown:
		h = d.dep.ResolveUnknownHandler
	}
	err := h(context.Background(), run)
	p3exec(d.t, d.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now(), lease_owner = '', lease_expires_at = NULL
		WHERE id = ? AND status = 'running'`, j.ID)
	return err
}

// mustRun runs a job and fails on any error that is not "retry later".
func (d *dLab) mustRun(kind string, dep uuid.UUID) {
	d.t.Helper()
	if err := d.runJob(kind, dep); err != nil && !isRetryLater(err) {
		d.t.Fatalf("%s %s: %v", kind, dep, err)
	}
}

func isRetryLater(err error) bool {
	return err != nil && len(err.Error()) >= 11 && err.Error()[:11] == "retry later"
}

// publish publishes a scan of the lab's connector started at `started`,
// showing boundaryARN (version) as the role's live boundary assignment in
// the graph ("" = none); it returns the new revision.
func (d *dLab) publish(x *x3Role, started time.Time, boundaryARN, version string) int64 {
	d.t.Helper()
	d.scanGen++
	d.rev++
	run := uuid.New()
	p3exec(d.t, d.db, `INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status, started_at, published_at, coverage)
		VALUES (?, ?, ?, ?, 'published', ?, ?, '{"surfaces":{"cloudtrail-events:us-east-1":{"state":"reached","count":3}}}'::jsonb)`,
		run, d.ws, d.conn.ID, d.scanGen, started, started.Add(time.Minute))
	p3exec(d.t, d.db, `INSERT INTO iga_publication (workspace_id, rev, published_at, scan_run_id, manifest)
		VALUES (?, ?, ?, ?, jsonb_build_object(?::text, ?::text))`, d.ws, d.rev, started.Add(time.Minute), run, "aws:"+testAccount, run.String())
	p3exec(d.t, d.db, `UPDATE iga_policy_assignment SET state = 'ended', valid_to = now(), ended_reason = 'replaced'
		WHERE workspace_id = ? AND holder_identity_account_id = ? AND assignment_kind = 'boundary' AND state <> 'ended'`, d.ws, x.identity)
	if boundaryARN != "" {
		pol := uuid.New()
		p3exec(d.t, d.db, `INSERT INTO iga_policy (id, workspace_id, provider, policy_kind, display_name, native_ref, source_key, continuity,
			immutable_key, version_id, document_hash) VALUES (?, ?, 'aws', 'customer_managed', 'boundary', ?, ?, 'immutable', ?, ?, 'x')`,
			pol, d.ws, boundaryARN, "aws:policy:"+pol.String(), "ANPA"+pol.String()[:8], version)
		p3exec(d.t, d.db, `INSERT INTO iga_policy_assignment (workspace_id, policy_id, holder_identity_account_id, assignment_kind, source_key, partition_key, connector_id)
			VALUES (?, ?, ?, 'boundary', ?, ?, ?)`, d.ws, pol, x.identity, "asg:"+pol.String(), "aws:"+testAccount, d.conn.ID)
	}
	d.scanRun = run
	return d.rev
}

// retirePolicy marks every graph policy row for arn retired.
func (d *dLab) retirePolicy(arn string) {
	p3exec(d.t, d.db, `UPDATE iga_policy SET lifecycle = 'retired', retired_reason = 'deleted' WHERE workspace_id = ? AND native_ref = ? AND lifecycle = 'active'`, d.ws, arn)
}

// finding inserts an open unused_service finding for the role's service.
func (d *dLab) finding(x *x3Role, svc string) uuid.UUID {
	d.t.Helper()
	id := uuid.New()
	p3exec(d.t, d.db, `INSERT INTO iga_gov_finding (id, workspace_id, fingerprint, kind, family, severity, confidence, identity_account_id,
		role_id, detail_key, status, first_seen_rev, last_evaluated_rev) VALUES (?, ?, ?, 'unused_service', 'cloud_access', 'medium',
		'qualified', ?, ?, ?, 'open', 1, 1)`, id, d.ws, "fp-"+x.role.RoleID+"-"+svc, x.identity, x.role.RoleID, svc)
	return id
}

func (d *dLab) findingStatus(id uuid.UUID) string {
	var s string
	d.db.Raw(`SELECT status FROM iga_gov_finding WHERE id = ?`, id).Scan(&s)
	return s
}

// posture is the role's posture: service -> "exclusion/outcome".
func (d *dLab) posture(x *x3Role) map[string]string {
	d.t.Helper()
	var rows []models.IGAGovServicePosture
	if err := d.db.Raw(`SELECT * FROM iga_gov_service_posture WHERE workspace_id = ? AND role_id = ?`, d.ws, x.role.RoleID).Scan(&rows).Error; err != nil {
		d.t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.Service] = r.Exclusion + "/" + r.Outcome
	}
	return out
}

func (d *dLab) state(dep uuid.UUID) string { return d.deployment(dep).State }

func (d *dLab) controlState(x *x3Role) (string, int64) {
	var row struct {
		State          string
		EnforcementSeq int64
	}
	d.db.Raw(`SELECT state, enforcement_seq FROM iga_gov_control WHERE id = ?`, x.control).Scan(&row)
	return row.State, row.EnforcementSeq
}

func (d *dLab) dimension(dep uuid.UUID, dim string) string {
	var s string
	d.db.Raw(`SELECT outcome FROM iga_gov_verification WHERE deployment_id = ? AND dimension = ?`, dep, dim).Scan(&s)
	return s
}

// ledgerVersion is the present boundary_policy's aws_version_id.
func (d *dLab) ledgerVersion(x *x3Role, arn string) string {
	var v string
	d.db.Raw(`SELECT aws_version_id FROM iga_gov_artifact WHERE control_id = ? AND kind = 'boundary_policy' AND native_arn = ?
		ORDER BY updated_at DESC LIMIT 1`, x.control, arn).Scan(&v)
	return v
}

// applyAndVerify takes a stored, approved apply through deploy, readback,
// publication and verification; it returns the deployment.
func (d *dLab) applyAndVerify(x *x3Role, s x3Stored) uuid.UUID {
	d.t.Helper()
	dep := d.queue(x, s, igagov.PlanApply)
	d.mustRun("deploy", dep)
	if st := d.state(dep); st != "applied_unverified" {
		d.t.Fatalf("after deploy: %s (%s)", st, d.deployment(dep).StateReason)
	}
	arn := *d.planOf(dep).DesiredBoundaryARN
	d.publish(x, d.now().Add(time.Second), arn, d.ledgerVersion(x, arn))
	d.mustRun("verify", dep)
	if st := d.state(dep); st != "verified" {
		d.t.Fatalf("after verify: %s; artifact %s graph %s", st, d.dimension(dep, "artifact"), d.dimension(dep, "graph"))
	}
	return dep
}

func (d *dLab) planOf(dep uuid.UUID) igagov.Plan {
	d.t.Helper()
	p, err := services.LoadIGAGovPlan(d.db, d.ws, d.deployment(dep).PlanID)
	if err != nil {
		d.t.Fatal(err)
	}
	return p
}

func govCode(err error) string {
	var ge *services.GovError
	if errors.As(err, &ge) {
		return ge.Code
	}
	return ""
}

// role is x3Lab.role with the production workspace tag value
// (services.GovWorkspaceRef), which every T3.16 compile (role-only
// recovery, control removal) uses.
func (d *dLab) role(name, path string, tags map[string]string) *x3Role {
	x := d.x3Lab.role(name, path, tags)
	x.ref.WorkspaceRef = services.GovWorkspaceRef(d.ws)
	return x
}
