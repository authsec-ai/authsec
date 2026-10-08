package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// x3Lab is the T3.10 executor fixture against real PostgreSQL: a workspace
// with an onboarded AWS connector and a VERIFIED enforcement binding (T3.09's
// lab: Vault-held ExternalId, a fake account whose every write is authorised
// by the enforcement template's policy), a published revision and scan run,
// and per role a control under its own policy. Plans are compiled by the
// real compiler from the fake account's discovery read and stored with their
// documents; deployments are inserted `applying`, as T3.16 will leave them.
type x3Lab struct {
	t        *testing.T
	db       *gorm.DB
	enf      *enfLab
	ws       uuid.UUID
	user     uuid.UUID
	conn     *models.CloudConnector
	fake     *enforcetest.FakeAWS
	access   *services.AWSEnforcementAccess
	attempts *services.IGAGovAttemptLog
	exec     *services.IGAGovAWSExecutor
	scanRun  uuid.UUID
	extID    string
	bundles  map[string]igagov.Bundle
}

type x3Role struct {
	name     string
	role     *enforcetest.Role
	identity uuid.UUID
	policy   uuid.UUID
	control  uuid.UUID
	arn      string
	ref      igagov.ControlRef
	versions int
}

// x3Stored is a group of plans stored under one version and target.
type x3Stored struct {
	version  uuid.UUID
	approval uuid.UUID
	plans    map[string]uuid.UUID // by kind (apply, undo, remove_control)
}

func noSleep(context.Context, time.Duration) error { return nil }

func newX3Lab(t *testing.T) *x3Lab {
	t.Helper()
	enf := newEnfLab(t)
	ctx := context.Background()
	sess := enf.start(t, enf.a)
	f := enf.aws.deploy(t, sess.AccountID, sess.Suffix, sess.ExternalID)
	roleARN := func(name string) string { return "arn:aws:iam::" + testAccount + ":role/" + name }
	if v, err := enf.svc.BindManual(ctx, enf.a.ws, enf.a.connector.ID, enf.a.user, roleARN(sess.RoleName), roleARN(sess.SelfTestRoleName), ""); err != nil ||
		v.State != models.EnforcementBindingVerified {
		t.Fatalf("bind: %+v %v", v, err)
	}
	l := &x3Lab{t: t, db: enf.db, enf: enf, ws: enf.a.ws, user: enf.a.user, conn: enf.a.connector, fake: f,
		scanRun: uuid.New(), extID: sess.ExternalID, bundles: map[string]igagov.Bundle{}}
	p3exec(t, l.db, `INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status, published_at)
		VALUES (?, ?, ?, 1, 'published', now())`, l.scanRun, l.ws, l.conn.ID)
	p3exec(t, l.db, `INSERT INTO iga_publication (workspace_id, rev, published_at, scan_run_id, manifest)
		VALUES (?, 1, now(), ?, jsonb_build_object(?::text, ?::text))`, l.ws, l.scanRun, "aws:"+testAccount, l.scanRun.String())
	l.access = services.NewAWSEnforcementAccess(repositories.NewCloudConnectorRepository(l.db), nil, enf.svc).
		WithDiscovery(func(context.Context, *models.CloudConnector) (awsenforce.DiscoveryIAM, error) {
			return f.Discovery(), nil
		}).
		WithTrail(func(context.Context, *models.CloudConnector) (awsenforce.TrailAPI, error) { return f, nil })
	l.attempts = services.NewIGAGovAttemptLog(l.db)
	l.exec = services.NewIGAGovAWSExecutor(l.db, l.attempts, l.access).WithSleep(noSleep)
	return l
}

const x3AppDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","sqs:*","sns:*","ec2:*"],"Resource":"*"}]}`

// role adds a role to the fake account (with a permissions policy and an
// inline policy) and its identity, policy and control rows.
func (l *x3Lab) role(name, path string, tags map[string]string) *x3Role {
	l.t.Helper()
	r := l.fake.AddRole(name, path, tags)
	r.Inline["app-inline"] = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"logs:PutLogEvents","Resource":"*"}]}`
	cust := l.fake.AddPolicy("/", name+"Access", nil, x3AppDoc)
	l.fake.AttachPermissions(name, cust.ARN)
	x := &x3Role{name: name, role: r, identity: uuid.New(), policy: uuid.New(), control: uuid.New(), arn: l.fake.RoleARNOf(r)}
	p3exec(l.t, l.db, `INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, provider, source_key, continuity, immutable_key, display_name, provider_attrs)
		VALUES (?, ?, 'role', 'aws', ?, 'immutable', ?, ?, '{}'::jsonb)`,
		x.identity, l.ws, "aws:iam:role:"+testAccount+":"+name, r.RoleID, name)
	p3exec(l.t, l.db, `INSERT INTO iga_gov_policy (id, workspace_id, name, family, provider, created_by) VALUES (?, ?, ?, 'cloud_access', 'aws', ?)`,
		x.policy, l.ws, name+" right-size", l.user)
	authsec := igagov.AuthSecBoundaryARN("aws", testAccount, r.RoleID)
	p3exec(l.t, l.db, `INSERT INTO iga_gov_control (id, workspace_id, connector_id, account_id, role_id, role_arn, identity_account_id, policy_id, boundary_policy_arn)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, x.control, l.ws, l.conn.ID, testAccount, r.RoleID, x.arn, x.identity, x.policy, authsec)
	// The production ControlRef (p3-wire item 2): the authsec:workspace tag
	// is services.GovWorkspaceRef(ws), exactly what the compile service uses.
	var ctl models.IGAGovControl
	if err := l.db.Where("workspace_id = ? AND id = ?", l.ws, x.control).Take(&ctl).Error; err != nil {
		l.t.Fatal(err)
	}
	x.ref = services.GovControlRef(l.ws, ctl, []string{authsec})
	return x
}

func (x *x3Role) authsecARN() string { return x.ref.OwnedPolicyARNs[0] }

// live is a discovery read of the role (and its boundary, its AuthSec
// boundary ARN and extra ARNs) for the compiler, through the same reader the
// executor uses.
func (l *x3Lab) live(disc awsenforce.DiscoveryIAM, x *x3Role, extra ...string) igagov.LiveRead {
	l.t.Helper()
	ctx := context.Background()
	role, err := awsenforce.ReadRole(ctx, disc, x.name)
	if err != nil {
		l.t.Fatal(err)
	}
	live := igagov.LiveRead{ReadAt: time.Now().UTC(), Role: role, Policies: map[string]*igagov.LivePolicy{}}
	arns := append([]string{x.authsecARN()}, extra...)
	if role != nil && role.BoundaryARN != "" {
		arns = append(arns, role.BoundaryARN)
	}
	for _, a := range arns {
		p, _, err := awsenforce.ReadPolicy(ctx, disc, a)
		if err != nil {
			l.t.Fatal(err)
		}
		live.Policies[a] = p
	}
	return live
}

func (l *x3Lab) evidence(x *x3Role, remove []string) igagov.EvidenceRef {
	l.t.Helper()
	at := time.Now().UTC().Add(-3 * time.Hour)
	cov := &igagov.ResourcePolicyEvidence{Coverage: x3Coverage()}
	role := igagov.RoleRef{RoleID: x.role.RoleID, ARN: x.arn, Name: x.name, AccountID: testAccount}
	act := []igagov.BundleActivity{}
	var routes []igagov.RouteAnalysis
	for _, s := range remove {
		act = append(act, igagov.BundleActivity{Service: s, State: igagov.EvidenceCollected, Outcome: igagov.QualNoAttempt,
			GrantAgeBasis: igagov.GrantAgePredatesObservation, QualifiedDays: 112})
		routes = append(routes, igagov.AnalyzeRoutes(s, role, cov, []string{"us-east-1"}))
	}
	b, err := igagov.BuildBundle(igagov.BundleInput{BuiltAt: time.Now().UTC(),
		Sources: []igagov.BundleSourceInput{{Kind: igagov.SourceAWSPublication, Rev: 1, PublishedAt: at, ConnectorID: l.conn.ID.String(),
			ConnectorRun: l.scanRun.String(), Authenticated: true, Ordered: true, ActivityReportGeneratedAt: &at,
			ResourcePolicyCoverage: igagov.CoverageComplete, ResourcePolicyRun: l.scanRun.String()}},
		Target:          igagov.BundleTarget{AccountID: testAccount, RoleID: x.role.RoleID, RoleARN: x.arn},
		RemovedServices: remove, Consumers: []igagov.ImpactConsumer{{WorkloadID: uuid.NewString(), Relationship: "executes_as"}},
		Owners: []string{l.user.String()}, Activity: act, RouteAnalyses: routes}, igagov.DefaultTrustRules())
	if err != nil {
		l.t.Fatal(err)
	}
	l.bundles[b.Hash] = b
	return igagov.EvidenceRef{Bundle: b, EvidenceRev: 1, ScanRunID: l.scanRun.String()}
}

func x3Coverage() []igagov.CoverageRow {
	var rows []igagov.CoverageRow
	for _, f := range igagov.AllForms() {
		if f.State != igagov.FormCollected {
			continue
		}
		rows = append(rows, igagov.CoverageRow{Form: f.Name, Region: "us-east-1", State: igagov.CoverageComplete})
	}
	return rows
}

func (l *x3Lab) intent(x *x3Role, remove ...string) igagov.RightSizeIntent {
	in := igagov.RightSizeIntent{Kind: igagov.IntentRightSizeServices,
		Subjects:        []igagov.Subject{{IdentityAccountID: x.identity.String(), RoleID: x.role.RoleID, AccountID: testAccount}},
		ObservationDays: 7, Delivery: igagov.DeliveryDirect, EvidenceRev: 1}
	for _, s := range remove {
		in.Remove = append(in.Remove, igagov.RemoveEntry{Service: s, Basis: igagov.RemoveNoAttempt, QualifiedDays: 112,
			GrantAgeBasis: igagov.GrantAgePredatesObservation})
	}
	return in
}

// compile compiles the role's apply and undo from a discovery read.
func (l *x3Lab) compile(disc awsenforce.DiscoveryIAM, x *x3Role, remove ...string) igagov.TargetPlans {
	l.t.Helper()
	tp, err := igagov.CompileTarget(igagov.TargetInput{Control: x.ref, Intent: l.intent(x, remove...), Live: l.live(disc, x),
		Evidence: l.evidence(x, remove), ScanEvidence: &igagov.ResourcePolicyEvidence{Coverage: x3Coverage()},
		EnabledRegions: []string{"us-east-1"}, AccountServices: []string{"ecr", "sqs"}})
	if err != nil {
		l.t.Fatalf("compile %s: %v", x.name, err)
	}
	return tp
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// store inserts plans under a new version and target of the role, with their
// documents, bundle and an approval naming them.
func (l *x3Lab) store(x *x3Role, plans ...igagov.Plan) x3Stored {
	l.t.Helper()
	x.versions++
	s := x3Stored{version: uuid.New(), approval: uuid.New(), plans: map[string]uuid.UUID{}}
	target := uuid.New()
	p3exec(l.t, l.db, `INSERT INTO iga_gov_policy_version (id, workspace_id, policy_id, version_no, intent, intent_hash, catalog_version, evidence_rev, created_by)
		VALUES (?, ?, ?, ?, '{"kind":"right_size_services"}', ?, 1, 1, ?)`, s.version, l.ws, x.policy, x.versions, "ih-"+s.version.String(), l.user)
	p3exec(l.t, l.db, `INSERT INTO iga_gov_target (id, workspace_id, version_id, policy_id, control_id, is_canary) VALUES (?, ?, ?, ?, ?, true)`,
		target, l.ws, s.version, x.policy, x.control)
	var hashes, materials []string
	for _, p := range plans {
		hashes, materials = append(hashes, p.PlanHash), append(materials, p.MaterialHash)
	}
	p3exec(l.t, l.db, `INSERT INTO iga_gov_approval (id, workspace_id, version_id, decision, decided_by, channel, intent_hash, impact_hashes, plan_hashes, material_hashes, evidence_rev, expires_at)
		VALUES (?, ?, ?, 'approve', ?, 'ui', ?, ARRAY[?], string_to_array(?, ','), string_to_array(?, ','), 1, now() + interval '7 days')`,
		s.approval, l.ws, s.version, l.user, "ih-"+s.version.String(), plans[0].ImpactHash, strings.Join(hashes, ","), strings.Join(materials, ","))
	for _, p := range plans {
		if !p.Eligible() {
			l.t.Fatalf("storing an ineligible %s plan: %s", p.Kind, p.IneligibleReason)
		}
		for _, d := range p.Documents {
			p3exec(l.t, l.db, `INSERT INTO iga_gov_document (workspace_id, document_hash, canonical, document) VALUES (?, ?, ?, ?::jsonb)
				ON CONFLICT (workspace_id, document_hash) DO NOTHING`, l.ws, d.Hash, d.Canonical, d.Canonical)
		}
		b := l.bundles[p.BundleHash]
		var bundleID uuid.UUID
		p3exec(l.t, l.db, `INSERT INTO iga_gov_evidence_bundle (workspace_id, provider, trust, bundle_hash, canonical, facts)
			VALUES (?, 'aws', ?, ?, ?, ?::jsonb) ON CONFLICT (workspace_id, bundle_hash) DO NOTHING`,
			l.ws, b.Trust, b.Hash, string(b.Canonical), string(b.Canonical))
		var row struct{ ID uuid.UUID }
		if err := l.db.Raw(`SELECT id FROM iga_gov_evidence_bundle WHERE workspace_id = ? AND bundle_hash = ?`, l.ws, b.Hash).Scan(&row).Error; err != nil {
			l.t.Fatal(err)
		}
		bundleID = row.ID
		if bundleID == uuid.Nil {
			l.t.Fatalf("no bundle row for %s", p.BundleHash)
		}
		id := uuid.New()
		p3exec(l.t, l.db, `INSERT INTO iga_gov_plan (id, workspace_id, version_id, target_id, control_id, kind, delivery, eligibility,
			ineligible_reason, basis, basis_read_at, precondition, precondition_hash, before_document_hash, desired_attachment,
			desired_boundary_arn, desired_document_hash, replaced_boundary_arn, artifact_disposition, evidence_bundle_id,
			evidence_rev, resource_policy_scan_run_id, first_attachment, unanalysed, impact, impact_hash, operations, diff,
			plan_hash, material_hash)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, ?::jsonb, ?::jsonb, ?, ?)`,
			id, l.ws, s.version, target, x.control, p.Kind, p.Delivery, p.Eligibility, p.IneligibleReason, p.Basis, p.BasisReadAt,
			string(p.Precondition), p.PreconditionHash, p.BeforeDocumentHash, p.DesiredAttachment, p.DesiredBoundaryARN,
			p.DesiredDocumentHash, p.ReplacedBoundaryARN, p.ArtifactDisposition, bundleID, p.EvidenceRev, p.ResourcePolicyScanRunID,
			p.FirstAttachment, jsonOf(l.t, p.Unanalysed), jsonOf(l.t, p.Impact), p.ImpactHash, jsonOf(l.t, p.Ops), jsonOf(l.t, p.Diff),
			p.PlanHash, p.MaterialHash)
		s.plans[p.Kind] = id
	}
	return s
}

// deploy inserts a direct deployment of a stored plan in `applying`.
func (l *x3Lab) deploy(x *x3Role, s x3Stored, kind string) uuid.UUID {
	l.t.Helper()
	id := uuid.New()
	p3exec(l.t, l.db, `INSERT INTO iga_gov_deployment (id, workspace_id, version_id, plan_id, control_id, approval_id, kind, delivery, state)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'direct', 'applying')`, id, l.ws, s.version, s.plans[kind], x.control, s.approval, kind)
	return id
}

// settle marks a deployment as T3.16 would after it (so the control is free
// for the next deployment).
func (l *x3Lab) settle(dep uuid.UUID, state string) {
	p3exec(l.t, l.db, `UPDATE iga_gov_deployment SET state = ?, updated_at = now() WHERE id = ?`, state, dep)
}

// claim enqueues (once) and claims the deployment's deploy job as owner at
// time at (a later time reclaims a lapsed lease: a replacement worker).
func (l *x3Lab) claim(dep uuid.UUID, owner string, at time.Time) *services.PolicyJobRun {
	l.t.Helper()
	repo := repositories.NewIGAGovJobRepository(l.db)
	j := &models.IGAGovJob{WorkspaceID: l.ws, Kind: repositories.GovJobDeploy, DedupeKey: "deployment:" + dep.String(), SubjectID: &dep,
		RunAfter: at.Add(-time.Hour)}
	if _, err := repo.EnqueueTx(l.db, j); err != nil {
		l.t.Fatal(err)
	}
	// Earlier deployments' jobs of this workspace are done (T3.16 would
	// complete them); finish them so the claim below takes this one.
	p3exec(l.t, l.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now(), lease_owner = '', lease_expires_at = NULL
		WHERE workspace_id = ? AND kind = 'deploy' AND status IN ('queued','running') AND subject_id IS DISTINCT FROM ?`, l.ws, dep)
	c := p3ClaimOwn(l.t, l.db, l.ws, owner, 2*time.Minute, at, repositories.GovJobDeploy)
	if c == nil || c.SubjectID == nil || *c.SubjectID != dep {
		l.t.Fatalf("%s could not claim the deploy job of %s: %+v", owner, dep, c)
	}
	return services.NewPolicyJobRun(l.db, *c, owner)
}

func (l *x3Lab) deployment(id uuid.UUID) models.IGAGovDeployment {
	l.t.Helper()
	var d models.IGAGovDeployment
	if err := l.db.First(&d, "id = ?", id).Error; err != nil {
		l.t.Fatal(err)
	}
	return d
}

// execute loads the deployment and its stored plan and runs ExecutePlan with
// exec.
func (l *x3Lab) execute(exec *services.IGAGovAWSExecutor, run *services.PolicyJobRun, dep uuid.UUID) (*services.DeployOutcome, error) {
	l.t.Helper()
	d := l.deployment(dep)
	p, err := services.LoadIGAGovPlan(l.db, l.ws, d.PlanID)
	if err != nil {
		l.t.Fatal(err)
	}
	return exec.ExecutePlan(context.Background(), run, d, p)
}

func (l *x3Lab) mustApply(exec *services.IGAGovAWSExecutor, run *services.PolicyJobRun, dep uuid.UUID) *services.DeployOutcome {
	l.t.Helper()
	out, err := l.execute(exec, run, dep)
	if err != nil {
		l.t.Fatalf("execute: %v", err)
	}
	if out.Result != services.DeployApplied {
		l.t.Fatalf("execute: %s %s %s (ops %+v)", out.Result, out.Reason, out.Detail, out.Ops)
	}
	return out
}

func (l *x3Lab) attemptRows(dep uuid.UUID) []models.IGAGovAttempt {
	l.t.Helper()
	var out []models.IGAGovAttempt
	if err := l.db.Where("deployment_id = ?", dep).Order("op_seq, attempt_no").Find(&out).Error; err != nil {
		l.t.Fatal(err)
	}
	return out
}

func (l *x3Lab) artifacts(x *x3Role) []models.IGAGovArtifact {
	l.t.Helper()
	var out []models.IGAGovArtifact
	if err := l.db.Where("control_id = ?", x.control).Order("kind, updated_at").Find(&out).Error; err != nil {
		l.t.Fatal(err)
	}
	return out
}

// ledger summarises the control's artifact rows as "kind native_arn state".
func (l *x3Lab) ledger(x *x3Role) []string {
	var out []string
	for _, a := range l.artifacts(x) {
		out = append(out, a.Kind+" "+a.NativeARN+" "+a.State)
	}
	return out
}

func (l *x3Lab) completedOps(dep uuid.UUID) []map[string]any {
	l.t.Helper()
	var ops []map[string]any
	if err := json.Unmarshal(l.deployment(dep).CompletedOps, &ops); err != nil {
		l.t.Fatal(err)
	}
	return ops
}

func (l *x3Lab) eventNames(dep uuid.UUID) []string {
	l.t.Helper()
	var out []string
	if err := l.db.Raw(`SELECT event FROM iga_gov_event WHERE workspace_id = ? AND deployment_id = ? ORDER BY id`, l.ws, dep).Scan(&out).Error; err != nil {
		l.t.Fatal(err)
	}
	return out
}

func x3Has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// killAfterApply makes the fake apply action and then "lose" the worker: a
// replacement claims the job (the dispatching worker's fence is gone, so it
// can record neither the answer nor `unknown`) and the caller gets no answer.
// It returns the replacement's run (set once the hook fired).
func (l *x3Lab) killAfterApply(action string, dep uuid.UUID, at time.Time) **services.PolicyJobRun {
	var runB *services.PolicyJobRun
	l.fake.AfterApply[action] = func(context.Context) error {
		delete(l.fake.AfterApply, action)
		runB = l.claim(dep, "worker-b", at.Add(3*time.Minute))
		return fmt.Errorf("connection reset by peer")
	}
	return &runB
}

// document returns an archived document's canonical text.
func (l *x3Lab) document(hash string) string {
	l.t.Helper()
	var docs []models.IGAGovDocument
	if err := l.db.Where("workspace_id = ? AND document_hash = ?", l.ws, hash).Find(&docs).Error; err != nil || len(docs) != 1 {
		l.t.Fatalf("document %s: %v", hash, err)
	}
	return docs[0].Canonical
}

// x3Liar is a discovery read that hides what makes a role ineligible (its
// protection tags, its service-linked path) for the roles named: the
// "forced attempt" of A11, where AuthSec's own checks were bypassed.
type x3Liar struct {
	awsenforce.DiscoveryIAM
	hide map[string]bool
}

func (d x3Liar) GetRole(ctx context.Context, name string) (*awsenforce.RoleInfo, error) {
	r, err := d.DiscoveryIAM.GetRole(ctx, name)
	if err != nil || !d.hide[name] {
		return r, err
	}
	tags := map[string]string{}
	for k, v := range r.Tags {
		if k != "ManagedBy" && k != "authsec:protected" {
			tags[k] = v
		}
	}
	r.Tags = tags
	if strings.HasPrefix(r.Path, "/aws-") {
		r.ARN = strings.Replace(r.ARN, ":role"+r.Path, ":role/", 1)
		r.Path = "/"
	}
	return r, nil
}

// x3Lag is a discovery read that, while frozen, still reports a policy's
// old default version (IAM's eventual consistency after a write).
type x3Lag struct {
	awsenforce.DiscoveryIAM
	frozen map[string]string
}

func (d *x3Lag) GetPolicy(ctx context.Context, arn string) (*awsenforce.PolicyInfo, error) {
	p, err := d.DiscoveryIAM.GetPolicy(ctx, arn)
	if err == nil {
		if v, ok := d.frozen[arn]; ok {
			p.DefaultVersionID = v
		}
	}
	return p, err
}

// x3Access gives an executor another discovery view of the same account.
type x3Access struct {
	disc awsenforce.DiscoveryIAM
	real services.IGAGovAWS
}

func (a x3Access) DiscoveryIAM(context.Context, uuid.UUID, uuid.UUID) (awsenforce.DiscoveryIAM, error) {
	return a.disc, nil
}

func (a x3Access) EnforcementIAM(ctx context.Context, ws, connector, dep uuid.UUID) (awsenforce.IAM, error) {
	return a.real.EnforcementIAM(ctx, ws, connector, dep)
}

func (l *x3Lab) executorWith(disc awsenforce.DiscoveryIAM) *services.IGAGovAWSExecutor {
	return services.NewIGAGovAWSExecutor(l.db, l.attempts, x3Access{disc: disc, real: l.access}).WithSleep(noSleep)
}

// calls counts the fake account's write calls of action on a resource
// containing sub (the self-test's own calls are not the deployment's).
func (l *x3Lab) calls(action, sub string) int {
	n := 0
	for _, c := range l.fake.Calls {
		if strings.HasPrefix(c, action+" ") && strings.Contains(c, sub) {
			n++
		}
	}
	return n
}
