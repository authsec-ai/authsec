package integration

// Remediation (SPEC-secops-backend-upgrade.md W8) against a real database
// and a fake AWS account whose writes are authorised by simulating the
// remediation template's own policy (remediatetest): each writer's happy
// path, an AWS refusal and a readback mismatch; prepared mode without the
// remediation role; the IaC pull request and a closed one reopening the
// decision; proof needing both the change event and a read; apply needing
// governance:remediate and a second person (break-glass alone); no secret
// value in any row; another workspace's remediation is 404.
//
// Needs IGA_TEST_DSN (skipped otherwise).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/awsremediate"
	"github.com/authsec-ai/authsec/internal/awsremediate/remediatetest"
	"github.com/authsec-ai/authsec/internal/iacpr"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/services"
)

// remFakeAccess is the fake AWS of one test: every connector is the fake
// account.
type remFakeAccess struct{ a *remediatetest.Account }

func (f remFakeAccess) Open(_ context.Context, _, _, id uuid.UUID) (awsremediate.Account, error) {
	return f.a.Session(awsremediate.SessionName(id.String())), nil
}
func (f remFakeAccess) Reader(context.Context, uuid.UUID, uuid.UUID) (awsremediate.Reader, error) {
	return f.a, nil
}

type remWorld struct {
	ws, conn                   uuid.UUID
	account                    string
	fake                       *remediatetest.Account
	requester, requesterM      uuid.UUID // governance:remediate
	approver, approverM        uuid.UUID // governance:approve
	bystander, bystanderM      uuid.UUID // neither
	roleARN, userARN           string
	roleIdentity, userIdentity uuid.UUID
}

var remPermOnce sync.Once

func remGrant(t *testing.T, db *gorm.DB, membership uuid.UUID, action string) {
	t.Helper()
	arExec(t, db, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT m.role_id, p.id FROM workspace_memberships m, permissions p
		 WHERE m.id = ? AND p.resource = 'governance' AND p.action = ? AND p.workspace_id IS NULL
		ON CONFLICT DO NOTHING`, membership, action)
}

func remSeed(t *testing.T, db *gorm.DB, name string, binding bool) *remWorld {
	t.Helper()
	// W5 owns governance:remediate; insert it when its migration has not run.
	remPermOnce.Do(func() {
		arExec(t, db, `INSERT INTO permissions (resource, action, description)
			SELECT 'governance', 'remediate', 'Tier 4: remediation writes to the customer'
			 WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE resource = 'governance' AND action = 'remediate' AND workspace_id IS NULL)`)
	})
	w := &remWorld{ws: newWorkspace(t, db, name), conn: uuid.New(), account: fmt.Sprintf("%012d", rand.Int63n(1e12))}
	fake, err := remediatetest.New(w.account)
	if err != nil {
		t.Fatal(err)
	}
	w.fake = fake
	t.Cleanup(func() {
		for _, tbl := range []string{"agent_remediation_step", "agent_remediation", "cloud_remediation_binding", "pending_change",
			"agent_evidence_event", "iga_snapshot", "cloud_policy", "cloud_workload", "agent", "model_provider_connection",
			"iga_gov_event", "cloud_identity", "cloud_connector"} {
			db.Exec(`DELETE FROM `+tbl+` WHERE workspace_id = ?`, w.ws)
		}
	})
	arExec(t, db, `INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, status, auth_ref)
		VALUES (?, ?, 'aws', 'account', ?, 'active', 'vault://aws/test')`, w.conn, w.ws, w.account)
	w.roleARN, w.userARN = fake.RoleARN("agent-role-"+name), fake.UserARN("bot-"+name)
	w.roleIdentity, w.userIdentity = uuid.New(), uuid.New()
	arExec(t, db, `INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, attrs)
		VALUES (?, ?, ?, 'iam_role', ?, ?, '{"unique_id":"AROAEXAMPLE1"}'::jsonb)`, w.roleIdentity, w.ws, w.conn, w.roleARN, "agent-role-"+name)
	arExec(t, db, `INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, attrs)
		VALUES (?, ?, ?, 'iam_user', ?, ?, '{"unique_id":"AIDAEXAMPLE1"}'::jsonb)`, w.userIdentity, w.ws, w.conn, w.userARN, "bot-"+name)
	arExec(t, db, `INSERT INTO cloud_workload (workspace_id, connector_id, identity_id, runtime_kind, native_id, name, region)
		VALUES (?, ?, ?, 'lambda_function', ?, ?, 'us-east-1')`, w.ws, w.conn, w.roleIdentity,
		"arn:aws:lambda:us-east-1:"+w.account+":function:agent-"+name, "agent-"+name)
	n1, n2, n3 := "Rita "+name, "Arun "+name, "Bea "+name
	w.requester, w.requesterM = classMember(t, db, w.ws, &n1, "rita-"+name+"@test.local", "active")
	w.approver, w.approverM = classMember(t, db, w.ws, &n2, "arun-"+name+"@test.local", "active")
	w.bystander, w.bystanderM = classMember(t, db, w.ws, &n3, "bea-"+name+"@test.local", "active")
	remGrant(t, db, w.requesterM, "remediate")
	remGrant(t, db, w.approverM, "approve")
	if binding {
		arExec(t, db, `INSERT INTO cloud_remediation_binding (workspace_id, connector_id, account_ref, role_arn, auth_ref, template_version,
			    state, consented_by, verified_at)
			VALUES (?, ?, ?, ?, 'kv/test', '2026-11-25', 'verified', ?, now())`, w.ws, w.conn, w.account,
			"arn:aws:iam::"+w.account+":role/AuthSecRemediation-abcd1234", w.requester)
	}
	return w
}

// remAPI is the route table with the token's workspace and claims set.
type remAPI struct {
	t      *testing.T
	eng    *gin.Engine
	ws     uuid.UUID
	claims map[string]string
}

func newRemAPI(t *testing.T, db *gorm.DB) *remAPI {
	gin.SetMode(gin.TestMode)
	a := &remAPI{t: t, claims: map[string]string{}}
	eng := gin.New()
	g := eng.Group("/api/iga/v1")
	g.Use(func(c *gin.Context) {
		if a.ws != uuid.Nil {
			tenancy.Set(c, tenancy.Context{WorkspaceID: a.ws, PrincipalKind: "user"})
		}
		for k, v := range a.claims {
			c.Set(k, v)
		}
		c.Next()
	})
	platform.RegisterRemediationRoutes(g, platform.NewRemediationControllerWith(db), func(string, string) gin.HandlerFunc {
		return func(c *gin.Context) { c.Next() }
	})
	a.eng = eng
	return a
}

func (a *remAPI) as(ws, user, membership uuid.UUID) *remAPI {
	a.ws = ws
	a.claims = map[string]string{"user_id": user.String(), "workspace_membership_id": membership.String(), "client_id": "console"}
	return a
}

func (a *remAPI) do(method, path string, body any) (int, map[string]any) {
	a.t.Helper()
	rd := bytes.NewReader(nil)
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "/api/iga/v1"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	a.eng.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			a.t.Fatalf("%s %s: %d, not JSON: %s", method, path, rec.Code, rec.Body.String())
		}
	}
	return rec.Code, out
}

func remData(b map[string]any) map[string]any { m, _ := b["data"].(map[string]any); return m }

func remErrCode(b map[string]any) string {
	e, _ := b["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

// remInstall installs the fake account and a synchronous run.
func remInstall(t *testing.T, db *gorm.DB, fake *remediatetest.Account, now *time.Time) {
	t.Helper()
	t.Cleanup(services.SetRemediationAccess(remFakeAccess{a: fake}))
	t.Cleanup(services.SetRemediationKick(func(ws, id uuid.UUID) {
		svc := services.NewRemediationService(db)
		if now != nil {
			svc.WithClock(func() time.Time { return *now })
		}
		if err := svc.Execute(context.Background(), ws, id); err != nil {
			t.Errorf("execute: %v", err)
		}
	}))
}

// remFeedTrail writes the fake account's successful calls into the
// evidence store, as the CloudTrail poller would (the change events).
func remFeedTrail(t *testing.T, db *gorm.DB, w *remWorld, principal string) {
	t.Helper()
	for i, c := range w.fake.Succeeded() {
		src, name, _ := strings.Cut(c.Action, ":")
		detail := "arn:aws:sts::" + w.account + ":assumed-role/AuthSecRemediation-abcd1234/" + c.Session
		if principal != "" {
			detail = principal
		}
		sum := sha256.Sum256([]byte(fmt.Sprint(c, i)))
		arExec(t, db, `INSERT INTO agent_evidence_event (workspace_id, provider, source, event_id, connector_id, event_time, principal,
			    principal_detail, account_id, event_source, event_name, outcome, raw_hash)
			VALUES (?, 'aws', 'cloudtrail_poll', ?, ?, ?, ?, ?, ?, ?, ?, 'success', ?) ON CONFLICT DO NOTHING`,
			w.ws, uuid.NewString(), w.conn, c.At.Add(time.Second), "arn:aws:iam::"+w.account+":role/AuthSecRemediation-abcd1234", detail,
			w.account, src+".amazonaws.com", name, hex.EncodeToString(sum[:]))
	}
}

const remS3Doc = `{"Version":"2012-10-17","Statement":[{"Sid":"Read","Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Sid":"Wipe","Effect":"Allow","Action":["s3:DeleteObject","s3:DeleteBucket"],"Resource":"*"}]}`

func TestRemediationRemoveGrantWriteSecondPersonProofAndIsolation(t *testing.T) {
	db := igaDB(t)
	w := remSeed(t, db, "rgw", true)
	b := remSeed(t, db, "rgwb", true)
	remInstall(t, db, w.fake, nil)
	pol := w.fake.PolicyARN("/", "S3Wide")
	w.fake.AddPolicy(pol, remS3Doc, nil)
	role := w.fake.AddRole(strings.TrimPrefix(w.roleARN, "arn:aws:iam::"+w.account+":role/"), nil)
	role.Attached = []string{pol}
	api := newRemAPI(t, db)

	code, body := api.as(w.ws, w.bystander, w.bystanderM).do("POST", "/remediations", map[string]any{
		"kind": "remove_grant", "reason": "agent can delete buckets",
		"target": map[string]any{"provider": "aws", "ref": w.roleARN, "detail": map[string]any{"policy_arn": pol}}})
	if code != 200 {
		t.Fatalf("create: %d %v", code, body)
	}
	rem := remData(body)
	id := rem["id"].(string)
	if rem["mode"] != "write" || rem["state"] != "draft" {
		t.Fatalf("mode/state %v %v (%v)", rem["mode"], rem["state"], rem["mode_reason"])
	}
	coll, _ := rem["collateral"].(map[string]any)
	if wl, _ := coll["workloads"].([]any); len(wl) != 1 {
		t.Fatalf("collateral workloads %v", coll)
	}
	if loses, _ := coll["loses"].([]any); len(loses) != 3 {
		t.Fatalf("collateral loses %v", coll["loses"])
	}
	// Another workspace sees nothing.
	for _, r := range [][2]string{{"GET", "/remediations/" + id}, {"POST", "/remediations/" + id + "/apply"},
		{"GET", "/remediations/" + id + "/proof"}, {"POST", "/remediations/" + id + "/cancel"}} {
		if code, _ := api.as(b.ws, b.requester, b.requesterM).do(r[0], r[1], nil); code != 404 {
			t.Fatalf("B %s %s: %d, want 404", r[0], r[1], code)
		}
	}
	// Tier 4: governance:remediate is required.
	if code, body := api.as(w.ws, w.bystander, w.bystanderM).do("POST", "/remediations/"+id+"/apply", nil); code != 403 ||
		remErrCode(body) != services.RemCodeRemediateRequired {
		t.Fatalf("apply without remediate: %d %v", code, body)
	}
	// With it: a second person must approve.
	code, body = api.as(w.ws, w.requester, w.requesterM).do("POST", "/remediations/"+id+"/apply", map[string]any{"reason": "approved by SOC"})
	if code != 200 {
		t.Fatalf("apply: %d %v", code, body)
	}
	res := remData(body)
	pcv, _ := res["pending_change"].(map[string]any)
	if r := res["remediation"].(map[string]any); r["state"] != "awaiting_approval" || pcv == nil || res["break_glass"] == true {
		t.Fatalf("apply result %v", res)
	}
	if w.fake.Count("iam:DetachRolePolicy") != 0 {
		t.Fatal("wrote before the second person")
	}
	pcID := uuid.MustParse(pcv["id"].(string))
	pcs := services.NewPendingChangeService(db)
	if _, _, err := pcs.Approve(context.Background(), w.ws, pcID, w.requester); err == nil {
		t.Fatal("the requester approved their own write")
	}
	if _, _, err := pcs.Approve(context.Background(), w.ws, pcID, w.approver); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if len(role.Attached) != 0 {
		t.Fatalf("not detached: %v", role.Attached)
	}
	_, body = api.as(w.ws, w.bystander, w.bystanderM).do("GET", "/remediations/"+id, nil)
	got := remData(body)
	if got["state"] != "applied" || got["approved_by"] != w.approver.String() {
		t.Fatalf("after approval: %v %v %v", got["state"], got["approved_by"], got["error"])
	}
	// Proof: the read alone is not enough.
	_, body = api.do("GET", "/remediations/"+id+"/proof", nil)
	if p := remData(body); p["proven"] == true || !strings.Contains(fmt.Sprint(p["missing"]), "change event") {
		t.Fatalf("proof without event: %v", p)
	}
	// An event from another session does not count in write mode.
	remFeedTrail(t, db, w, "arn:aws:sts::"+w.account+":assumed-role/Someone/else")
	_, body = api.do("GET", "/remediations/"+id+"/proof", nil)
	if p := remData(body); p["proven"] == true {
		t.Fatalf("proven by someone else's event: %v", p)
	}
	// The remediation's own session's event: proven.
	remFeedTrail(t, db, w, "")
	_, body = api.do("GET", "/remediations/"+id+"/proof", nil)
	if p := remData(body); p["proven"] != true || p["state"] != "proven" {
		t.Fatalf("proof with event and read: %v", p)
	}
	// The write was made by the remediation's session.
	for _, c := range w.fake.Succeeded() {
		if c.Session != awsremediate.SessionName(id) {
			t.Fatalf("call %s by session %q", c.Action, c.Session)
		}
	}
	if n := len(aiEvents(t, db, w.ws, services.GovEventRemediationProven)); n != 1 {
		t.Fatalf("%d proven events", n)
	}
	if n := len(aiEvents(t, db, b.ws, services.GovEventRemediationRequested)); n != 0 {
		t.Fatal("B got A's events")
	}
}

func TestRemediationPreparedWithoutRole(t *testing.T) {
	db := igaDB(t)
	w := remSeed(t, db, "prep", false)
	remInstall(t, db, w.fake, nil)
	r := w.fake.AddRole(strings.TrimPrefix(w.roleARN, "arn:aws:iam::"+w.account+":role/"), nil)
	r.Inline["inline-s3"] = remS3Doc
	api := newRemAPI(t, db)
	code, body := api.as(w.ws, w.requester, w.requesterM).do("POST", "/remediations", map[string]any{
		"kind": "remove_grant", "reason": "drop the wipe statement",
		"target": map[string]any{"ref": w.roleARN, "detail": map[string]any{"inline_policy": "inline-s3", "statement_sid": "Wipe"}}})
	if code != 200 {
		t.Fatalf("create: %d %v", code, body)
	}
	rem := remData(body)
	id := rem["id"].(string)
	if rem["mode"] != "prepared" || rem["state"] != "prepared" || rem["mode_reason"] != services.RemReasonNoRole {
		t.Fatalf("mode %v state %v reason %v", rem["mode"], rem["state"], rem["mode_reason"])
	}
	prep, _ := json.Marshal(rem["prepared"])
	if !strings.Contains(string(prep), "aws iam put-role-policy") || strings.Contains(string(prep), "DeleteBucket") {
		t.Fatalf("prepared change %s", prep)
	}
	if code, body := api.do("POST", "/remediations/"+id+"/apply", nil); code != 409 || remErrCode(body) != services.RemCodePrepared {
		t.Fatalf("apply prepared: %d %v", code, body)
	}
	if len(w.fake.Calls) != 0 {
		t.Fatalf("AuthSec wrote without a role: %v", w.fake.Calls)
	}
	// The customer runs the prepared change; the proof follows the account.
	newDoc, _, _ := awsremediate.RemoveStatement(remS3Doc, "Wipe", -1)
	r.Inline["inline-s3"] = newDoc
	_, body = api.do("GET", "/remediations/"+id+"/proof", nil)
	if p := remData(body); p["proven"] == true {
		t.Fatalf("proven without an event: %v", p)
	}
	sum := sha256.Sum256([]byte(id))
	arExec(t, db, `INSERT INTO agent_evidence_event (workspace_id, provider, source, event_id, event_time, principal, principal_detail,
		    account_id, event_source, event_name, outcome, raw_hash)
		VALUES (?, 'aws', 'cloudtrail_poll', ?, now(), 'arn:aws:iam::x:user/ops', 'arn:aws:iam::x:user/ops', ?, 'iam.amazonaws.com', 'PutRolePolicy', 'success', ?)`,
		w.ws, uuid.NewString(), w.account, hex.EncodeToString(sum[:]))
	_, body = api.do("GET", "/remediations/"+id+"/proof", nil)
	if p := remData(body); p["proven"] != true {
		t.Fatalf("customer-run prepared change not proven: %v", p)
	}
}

func TestRemediationRefusalReadbackAndBreakGlass(t *testing.T) {
	db := igaDB(t)
	w := remSeed(t, db, "rrb", true)
	// No second approver: the approver loses approve.
	arExec(t, db, `DELETE FROM role_permissions WHERE role_id = (SELECT role_id FROM workspace_memberships WHERE id = ?)`, w.approverM)
	remInstall(t, db, w.fake, nil)
	api := newRemAPI(t, db).as(w.ws, w.requester, w.requesterM)
	name := strings.TrimPrefix(w.roleARN, "arn:aws:iam::"+w.account+":role/")
	pol := w.fake.PolicyARN("/", "S3Wide")
	w.fake.AddPolicy(pol, remS3Doc, nil)
	r := w.fake.AddRole(name, map[string]string{"authsec:protected": "true"})
	r.Attached = []string{pol}
	_, body := api.do("POST", "/remediations", map[string]any{"kind": "remove_grant", "reason": "x",
		"target": map[string]any{"ref": w.roleARN, "detail": map[string]any{"policy_arn": pol}}})
	id := remData(body)["id"].(string)
	code, body := api.do("POST", "/remediations/"+id+"/apply", nil)
	if code != 200 || remData(body)["break_glass"] != true {
		t.Fatalf("break-glass apply: %d %v", code, body)
	}
	var pc struct {
		BreakGlass  bool
		ReviewDueAt *time.Time
	}
	db.Raw(`SELECT break_glass, review_due_at FROM pending_change WHERE workspace_id = ? AND target_ref = ?`, w.ws, "agent_remediation:"+id).Scan(&pc)
	if !pc.BreakGlass || pc.ReviewDueAt == nil {
		t.Fatalf("break-glass row %+v", pc)
	}
	_, body = api.do("GET", "/remediations/"+id, nil)
	got := remData(body)
	if got["state"] != "failed" || !strings.Contains(got["error"].(string), awsremediate.CodeDenied) {
		t.Fatalf("protected role: %v %v", got["state"], got["error"])
	}
	if len(r.Attached) != 1 {
		t.Fatal("protected role changed")
	}
	// A read that does not show the change: applied, not proven.
	w2 := remSeed(t, db, "rrb2", true)
	arExec(t, db, `DELETE FROM role_permissions WHERE role_id = (SELECT role_id FROM workspace_memberships WHERE id = ?)`, w2.approverM)
	remInstall(t, db, w2.fake, nil)
	pol2 := w2.fake.PolicyARN("/", "S3Wide")
	w2.fake.AddPolicy(pol2, remS3Doc, nil)
	r2 := w2.fake.AddRole(strings.TrimPrefix(w2.roleARN, "arn:aws:iam::"+w2.account+":role/"), nil)
	r2.Attached = []string{pol2}
	w2.fake.LieOnRead[w2.roleARN] = true
	api2 := newRemAPI(t, db).as(w2.ws, w2.requester, w2.requesterM)
	_, body = api2.do("POST", "/remediations", map[string]any{"kind": "remove_grant", "reason": "x",
		"target": map[string]any{"ref": w2.roleARN, "detail": map[string]any{"policy_arn": pol2}}})
	id2 := remData(body)["id"].(string)
	api2.do("POST", "/remediations/"+id2+"/apply", nil)
	remFeedTrail(t, db, w2, "")
	_, body = api2.do("GET", "/remediations/"+id2+"/proof", nil)
	p := remData(body)
	if p["proven"] == true || p["state"] != "applied" || !strings.Contains(fmt.Sprint(p["missing"]), "end state") {
		t.Fatalf("readback mismatch proof: %v", p)
	}
}

func TestRemediationRotateIAMKeyNoSecretAnywhere(t *testing.T) {
	db := igaDB(t)
	w := remSeed(t, db, "rik", true)
	arExec(t, db, `DELETE FROM role_permissions WHERE role_id = (SELECT role_id FROM workspace_memberships WHERE id = ?)`, w.approverM)
	now := time.Now().UTC()
	remInstall(t, db, w.fake, &now)
	user := strings.TrimPrefix(w.userARN, "arn:aws:iam::"+w.account+":user/")
	u := w.fake.AddUser(user, nil, awsremediate.AccessKey{ID: "AKIAOLDKEY0000000001", Active: true})
	sec := w.fake.AddSecret("bot-key", map[string]string{"authsec:key-handover": "true"}, false)
	api := newRemAPI(t, db).as(w.ws, w.requester, w.requesterM)
	// Without a handover secret: prepared.
	_, body := api.do("POST", "/remediations", map[string]any{"kind": "rotate_iam_key", "reason": "key leaked",
		"target": map[string]any{"ref": w.userARN, "detail": map[string]any{"access_key_id": "AKIAOLDKEY0000000001"}}})
	if r := remData(body); r["mode"] != "prepared" || r["mode_reason"] != services.RemReasonNoHandover {
		t.Fatalf("no handover: %v", r)
	}
	api.do("POST", "/remediations/"+remData(body)["id"].(string)+"/cancel", nil)
	_, body = api.do("POST", "/remediations", map[string]any{"kind": "rotate_iam_key", "reason": "key leaked",
		"target": map[string]any{"ref": w.userARN, "detail": map[string]any{"access_key_id": "AKIAOLDKEY0000000001",
			"handover_secret_arn": sec.ARN, "grace_hours": 2}}})
	r := remData(body)
	if r["mode"] != "write" {
		t.Fatalf("rotate mode %v %v", r["mode"], r["mode_reason"])
	}
	id := r["id"].(string)
	if code, body := api.do("POST", "/remediations/"+id+"/apply", nil); code != 200 {
		t.Fatalf("apply: %d %v", code, body)
	}
	_, body = api.do("GET", "/remediations/"+id, nil)
	r = remData(body)
	steps := r["steps"].([]any)
	if r["state"] != "applied" || steps[0].(map[string]any)["state"] != "applied" || steps[1].(map[string]any)["state"] != "waiting" {
		t.Fatalf("after rotation: %v %v", r["state"], steps)
	}
	if len(u.Keys) != 2 || !u.Keys[0].Active {
		t.Fatalf("old key deactivated before its grace: %v", u.Keys)
	}
	// After the grace: the old key is deactivated.
	now = now.Add(3 * time.Hour)
	svc := services.NewRemediationService(db).WithClock(func() time.Time { return now })
	if err := svc.RemediationSweep(context.Background(), w.ws); err != nil {
		t.Fatal(err)
	}
	if u.Keys[0].Active {
		t.Fatalf("old key still active after the grace: %v", u.Keys)
	}
	remFeedTrail(t, db, w, "")
	p, err := svc.Proof(context.Background(), w.ws, uuid.MustParse(id))
	if err != nil || !p.Proven {
		t.Fatalf("rotation proof: %+v %v", p, err)
	}
	// No generated secret is in any row of the workspace.
	var dump []string
	for _, q := range []string{
		`SELECT row_to_json(r)::text FROM agent_remediation r WHERE workspace_id = ?`,
		`SELECT row_to_json(s)::text FROM agent_remediation_step s WHERE workspace_id = ?`,
		`SELECT payload::text FROM iga_gov_event WHERE workspace_id = ?`,
		`SELECT row_to_json(p)::text FROM pending_change p WHERE workspace_id = ?`,
	} {
		var rows []string
		db.Raw(q, w.ws).Scan(&rows)
		dump = append(dump, rows...)
	}
	all := strings.Join(dump, "\n")
	for _, s := range remediatetest.GeneratedSecrets() {
		if strings.Contains(all, s) {
			t.Fatal("a generated key secret is stored in a row")
		}
	}
	if !strings.Contains(sec.Values[sec.Current], "SecretAccessKey") {
		t.Fatal("the key was not handed over through the secret")
	}
	if w.fake.Count("secretsmanager:GetSecretValue") != 0 {
		t.Fatal("a secret value was read")
	}
}

func TestRemediationRotateSecret(t *testing.T) {
	db := igaDB(t)
	w := remSeed(t, db, "rsec", true)
	arExec(t, db, `DELETE FROM role_permissions WHERE role_id = (SELECT role_id FROM workspace_memberships WHERE id = ?)`, w.approverM)
	remInstall(t, db, w.fake, nil)
	on := w.fake.AddSecret("db-pass", nil, true)
	off := w.fake.AddSecret("api-token", nil, false)
	api := newRemAPI(t, db).as(w.ws, w.requester, w.requesterM)
	_, body := api.do("POST", "/remediations", map[string]any{"kind": "rotate_secret", "reason": "exposed",
		"target": map[string]any{"ref": off.ARN}})
	if r := remData(body); r["mode"] != "prepared" || r["mode_reason"] != services.RemReasonRotationOff {
		t.Fatalf("rotation off: %v", r)
	}
	_, body = api.do("POST", "/remediations", map[string]any{"kind": "rotate_secret", "reason": "exposed",
		"target": map[string]any{"ref": on.ARN}})
	id := remData(body)["id"].(string)
	before := on.Current
	api.do("POST", "/remediations/"+id+"/apply", nil)
	if on.Current == before {
		t.Fatal("not rotated")
	}
	remFeedTrail(t, db, w, "")
	_, body = api.do("GET", "/remediations/"+id+"/proof", nil)
	if p := remData(body); p["proven"] != true {
		t.Fatalf("rotate proof: %v", p)
	}
}

func TestRemediationIaCPullRequestClosedReopens(t *testing.T) {
	db := igaDB(t)
	w := remSeed(t, db, "iac", true)
	remInstall(t, db, w.fake, nil)
	arExec(t, db, `UPDATE cloud_identity SET attrs = '{"tags":{"aws:cloudformation:stack-name":"agents-prod"}}'::jsonb WHERE id = ?`, w.roleIdentity)
	gh := iacpr.NewFake()
	gh.Seed("acme/infra", "main", map[string]string{"stacks/agents.yaml": "Resources: {}\n"})
	t.Cleanup(func() { services.SetGovIaCGitHub(services.DefaultGovIaCGitHub()) })
	prev := services.DefaultGovIaCGitHub()
	services.SetGovIaCGitHub(gh)
	t.Cleanup(func() { services.SetGovIaCGitHub(prev) })
	src := uuid.New()
	t.Cleanup(services.SetRemediationIaCResolver(func(_ context.Context, _ *gorm.DB, ws, conn uuid.UUID, format string) (*services.RemediationIaCTarget, error) {
		if ws != w.ws || format != "cloudformation" {
			return nil, nil
		}
		return &services.RemediationIaCTarget{SourceID: src, Repo: iacpr.RepoRef{FullName: "acme/infra", WorkspaceID: ws.String()},
			BaseBranch: "main", Directory: "stacks", Format: format}, nil
	}))
	pol := w.fake.PolicyARN("/", "S3Wide")
	w.fake.AddPolicy(pol, remS3Doc, nil)
	r := w.fake.AddRole(strings.TrimPrefix(w.roleARN, "arn:aws:iam::"+w.account+":role/"), nil)
	r.Attached = []string{pol}
	api := newRemAPI(t, db).as(w.ws, w.requester, w.requesterM)
	_, body := api.do("POST", "/remediations", map[string]any{"kind": "remove_grant", "reason": "x",
		"target": map[string]any{"ref": w.roleARN, "detail": map[string]any{"policy_arn": pol}}})
	rem := remData(body)
	id := rem["id"].(string)
	if rem["mode"] != "iac_pr" {
		t.Fatalf("CloudFormation-managed role: mode %v %v", rem["mode"], rem["mode_reason"])
	}
	code, body := api.do("POST", "/remediations/"+id+"/apply", nil)
	if code != 200 {
		t.Fatalf("apply: %d %v", code, body)
	}
	got := remData(body)["remediation"].(map[string]any)
	pr, _ := got["pull_request"].(map[string]any)
	if got["state"] != "pr_open" || pr == nil || pr["number"].(float64) != 1 {
		t.Fatalf("pr: %v", got)
	}
	if f, ok := gh.PRFile("acme/infra", 1, "stacks/authsec-remediation-"+strings.ReplaceAll(id, "-", "")[:8]+".json"); !ok || !strings.Contains(f, "detach-role-policy") {
		t.Fatalf("pr file %v %q", ok, f)
	}
	if w.fake.Count("iam:DetachRolePolicy") != 0 {
		t.Fatal("an IaC-managed role was written")
	}
	asks := len(aiEvents(t, db, w.ws, services.GovEventRemediationAskNeeded))
	if asks != 1 {
		t.Fatalf("%d asks after the pr, want 1 (code owners)", asks)
	}
	// Closed unmerged: the decision reopens (not failed).
	gh.Close("acme/infra", 1)
	_, body = api.do("GET", "/remediations/"+id+"/proof", nil)
	_, body = api.do("GET", "/remediations/"+id, nil)
	got = remData(body)
	if got["state"] != "pr_closed" {
		t.Fatalf("closed pr: state %v", got["state"])
	}
	if n := len(aiEvents(t, db, w.ws, services.GovEventRemediationAskNeeded)); n != 2 {
		t.Fatalf("%d asks after close, want 2", n)
	}
	// Decide again: a new pull request; merged: pr_merged.
	code, body = api.do("POST", "/remediations/"+id+"/apply", nil)
	if code != 200 || remData(body)["remediation"].(map[string]any)["pull_request"].(map[string]any)["number"].(float64) != 2 {
		t.Fatalf("reapply: %d %v", code, body)
	}
	gh.Merge("acme/infra", 2, time.Now())
	_, body = api.do("GET", "/remediations/"+id+"/proof", nil)
	if p := remData(body); p["state"] != "pr_merged" || p["proven"] == true {
		t.Fatalf("merged, not yet changed in the account: %v", p)
	}
	// The code owners' deploy detaches it; its event and the read prove it.
	r.Attached = nil
	sum := sha256.Sum256([]byte(id + "deploy"))
	arExec(t, db, `INSERT INTO agent_evidence_event (workspace_id, provider, source, event_id, event_time, principal, principal_detail,
		    account_id, event_source, event_name, outcome, raw_hash)
		VALUES (?, 'aws', 'cloudtrail_poll', ?, now(), 'cfn', 'cloudformation.amazonaws.com', ?, 'iam.amazonaws.com', 'DetachRolePolicy', 'success', ?)`,
		w.ws, uuid.NewString(), w.account, hex.EncodeToString(sum[:]))
	_, body = api.do("GET", "/remediations/"+id+"/proof", nil)
	if p := remData(body); p["proven"] != true {
		t.Fatalf("merged and deployed: %v", p)
	}
}

func TestRemediationRetireAgent(t *testing.T) {
	db := igaDB(t)
	w := remSeed(t, db, "ret", true)
	arExec(t, db, `DELETE FROM role_permissions WHERE role_id = (SELECT role_id FROM workspace_memberships WHERE id = ?)`, w.approverM)
	remInstall(t, db, w.fake, nil)
	w.fake.AddRole(strings.TrimPrefix(w.roleARN, "arn:aws:iam::"+w.account+":role/"), nil)
	u := w.fake.AddUser(strings.TrimPrefix(w.userARN, "arn:aws:iam::"+w.account+":user/"), nil, awsremediate.AccessKey{ID: "AKIARETIRE0000000001", Active: true})
	agent := uuid.New()
	arExec(t, db, `INSERT INTO agent (id, workspace_id, display_name, kind) VALUES (?, ?, 'old bot', 'iga')`, agent, w.ws)
	api := newRemAPI(t, db).as(w.ws, w.requester, w.requesterM)
	code, body := api.do("POST", "/remediations", map[string]any{"kind": "retire_agent", "reason": "decommissioned",
		"target": map[string]any{"provider": "authsec", "ref": agent.String(), "detail": map[string]any{"identity_arns": []string{w.roleARN, w.userARN}}}})
	if code != 200 {
		t.Fatalf("create: %d %v", code, body)
	}
	id := remData(body)["id"].(string)
	if code, body := api.do("POST", "/remediations/"+id+"/apply", nil); code != 200 {
		t.Fatalf("apply: %d %v", code, body)
	}
	_, body = api.do("GET", "/remediations/"+id, nil)
	r := remData(body)
	if r["state"] != "applied" {
		t.Fatalf("retire: %v %v", r["state"], r["error"])
	}
	if u.Keys[0].Active {
		t.Fatal("key still active")
	}
	if w.fake.Count("iam:AttachRolePolicy") != 1 || w.fake.Count("iam:AttachUserPolicy") != 1 {
		t.Fatalf("deny not attached to both identities: %v", w.fake.Calls)
	}
	var state string
	db.Raw(`SELECT state FROM agent WHERE workspace_id = ? AND id = ?`, w.ws, agent).Scan(&state)
	if state != "retired" {
		t.Fatalf("agent state %s", state)
	}
	steps := r["steps"].([]any)
	if gw := steps[len(steps)-2].(map[string]any); gw["op"] != services.RemOpGatewayRulesRemove || gw["state"] != "skipped" {
		t.Fatalf("gateway step %v", gw)
	}
	remFeedTrail(t, db, w, "")
	_, body = api.do("GET", "/remediations/"+id+"/proof", nil)
	if p := remData(body); p["proven"] != true {
		t.Fatalf("retire proof: %v", p)
	}
}

func TestRemediationRotateProviderKeyIsAnAsk(t *testing.T) {
	db := igaDB(t)
	w := remSeed(t, db, "prov", false)
	conn := uuid.New()
	arExec(t, db, `INSERT INTO model_provider_connection (id, workspace_id, provider, secret_ref, key_fingerprint, org_id, created_by)
		VALUES (?, ?, 'anthropic', 'kv/x', '...abcd sha256:0123456789ab', 'org-1', ?)`, conn, w.ws, w.requester)
	api := newRemAPI(t, db).as(w.ws, w.requester, w.requesterM)
	code, body := api.do("POST", "/remediations", map[string]any{"kind": "rotate_provider_key", "reason": "admin key in a log",
		"target": map[string]any{"provider": "model_provider", "ref": conn.String()}})
	if code != 200 {
		t.Fatalf("create: %d %v", code, body)
	}
	r := remData(body)
	id := r["id"].(string)
	if r["mode"] != "prepared" || r["mode_reason"] != services.RemReasonProviderNoWrite {
		t.Fatalf("provider key mode %v %v", r["mode"], r["mode_reason"])
	}
	if n := len(aiEvents(t, db, w.ws, services.GovEventRemediationAskNeeded)); n != 2 {
		t.Fatalf("%d asks, want 2 (create, revoke old)", n)
	}
	// The admin rotates through AuthSec: fingerprint and audit row.
	arExec(t, db, `UPDATE model_provider_connection SET key_fingerprint = '...wxyz sha256:ffffffffffff' WHERE id = ?`, conn)
	arExec(t, db, `INSERT INTO audit_events (workspace_id, action, resource, resource_id, "timestamp", created_at)
		VALUES (?, 'model_provider.rotate', 'model_provider_connection', ?, now(), now())`, w.ws.String(), conn.String())
	t.Cleanup(func() { db.Exec(`DELETE FROM audit_events WHERE workspace_id = ?`, w.ws.String()) })
	_, body = api.do("GET", "/remediations/"+id+"/proof", nil)
	p := remData(body)
	if p["proven"] != true || len(p["cannot_verify"].([]any)) != 1 {
		t.Fatalf("provider proof: %v", p)
	}
}

func TestRemediationRevertSnapshot(t *testing.T) {
	db := igaDB(t)
	w := remSeed(t, db, "rev", true)
	arExec(t, db, `DELETE FROM role_permissions WHERE role_id = (SELECT role_id FROM workspace_memberships WHERE id = ?)`, w.approverM)
	remInstall(t, db, w.fake, nil)
	name := strings.TrimPrefix(w.roleARN, "arn:aws:iam::"+w.account+":role/")
	role := w.fake.AddRole(name, nil)
	role.Inline["inline-s3"] = remS3Doc // widened since the snapshot
	old := `{"Version":"2012-10-17","Statement":[{"Sid":"Read","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	pid := uuid.New()
	stable := "cloud_policy:" + pid.String()
	snapBody, _ := json.Marshal(map[string]any{"type": "cloud_policy", "id": pid, "connector_id": w.conn, "policy_kind": "inline",
		"native_id": "inline:" + w.roleARN + ":inline-s3", "name": "inline-s3", "holder_arn": w.roleARN, "document": json.RawMessage(old)})
	h := sha256.Sum256(snapBody)
	arExec(t, db, `INSERT INTO iga_snapshot (workspace_id, snapshot_date, kind, stable_id, hash, body, chain_hash)
		VALUES (?, '2026-11-01', 'policy_text', ?, ?, ?::jsonb, ?)`, w.ws, stable, hex.EncodeToString(h[:]), string(snapBody), hex.EncodeToString(h[:]))
	api := newRemAPI(t, db).as(w.ws, w.requester, w.requesterM)
	code, body := api.do("POST", "/remediations", map[string]any{"kind": "revert_snapshot", "reason": "undo the widening",
		"target": map[string]any{"ref": stable, "detail": map[string]any{"as_of": "2026-11-10"}}})
	if code != 200 {
		t.Fatalf("create: %d %v", code, body)
	}
	r := remData(body)
	if loses := fmt.Sprint(r["collateral"].(map[string]any)["loses"]); !strings.Contains(loses, "s3:DeleteBucket") {
		t.Fatalf("collateral %v", loses)
	}
	id := r["id"].(string)
	api.do("POST", "/remediations/"+id+"/apply", nil)
	if !awsremediate.SameDocument(role.Inline["inline-s3"], old) {
		t.Fatalf("not reverted: %s", role.Inline["inline-s3"])
	}
	_, body = api.do("GET", "/remediations/"+id, nil)
	step := remData(body)["steps"].([]any)[0].(map[string]any)
	before, _ := json.Marshal(step["before"])
	if !strings.Contains(string(before), "DeleteBucket") {
		t.Fatalf("the before-state does not keep the replaced document: %s", before)
	}
	// Before the snapshot existed: 404.
	if code, _ := api.do("POST", "/remediations", map[string]any{"kind": "revert_snapshot", "reason": "x",
		"target": map[string]any{"ref": stable, "detail": map[string]any{"as_of": "2026-10-01"}}}); code != 404 {
		t.Fatalf("as of before the snapshot: %d", code)
	}
}
