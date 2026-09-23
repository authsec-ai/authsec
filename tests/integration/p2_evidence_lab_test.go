package integration

// Fixtures for GET /evidence (T6.5, §5.3 Evidence, E4): the P2-0 lab's REAL
// scan worker and projector over faked AWS, with the collector fakes each
// limitation needs -- a bucket policy to read, a credential report for a user,
// Access Advisor services -- wired through the scanner hook the lab already
// uses.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"
	"time"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// evidenceAccountC is a partner account that is NEVER connected.
const evidenceAccountC = "300000000003"

// evidenceFakes are the collector answers a lab's scans get beyond the lab's
// own hook: bucket policies by bucket name, a credential report CSV, and the
// Access Advisor services every sampled identity reports.
type evidenceFakes struct {
	bucketPolicies map[string]string
	credentialCSV  string
	activity       []iamtypes.ServiceLastAccessed
}

// evidenceHook is the account's lab hook with the fakes' answers layered on.
func evidenceHook(a *p2Account, f evidenceFakes) services.ScannerHook {
	base := a.hook()
	return func(iamS *services.AWSIAMScanner, perm *services.AWSPermissionScanner, wl *services.AWSWorkloadScanner) {
		base(iamS, perm, wl)
		noSleep := func(context.Context, time.Duration) error { return nil }
		if f.credentialCSV != "" {
			iamS.WithCredentialReportAPI(&fakeCredentialReport{csv: f.credentialCSV}, noSleep)
		}
		if f.bucketPolicies != nil {
			perm.WithResourcePolicyAPIs(&fakeS3Policy{policyByBucket: f.bucketPolicies}, &fakeKMSPolicy{})
		}
		if f.activity != nil {
			wl.WithActivityAPI(&fakeActivity{services: f.activity}, noSleep)
		}
	}
}

var evidenceSeq int

// evidenceCycle is one scan through the REAL worker with the evidence fakes,
// then one projection pass.
func evidenceCycle(l *p2Lab, a *p2Account, f evidenceFakes) models.CloudScanRun {
	l.t.Helper()
	evidenceSeq++
	queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		l.t.Fatalf("enqueue: %v", err)
	}
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner(fmt.Sprintf("evidence-scan-%d", evidenceSeq)).
		WithGraphProjection(l.gate).WithScannerHook(evidenceHook(a, f))
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		l.t.Fatalf("scan worker: worked=%v err=%v", worked, err)
	}
	var run models.CloudScanRun
	if err := l.db.First(&run, "id = ?", queued.ID).Error; err != nil {
		l.t.Fatalf("read run: %v", err)
	}
	if run.Status != models.CloudScanRunPublished {
		l.t.Fatalf("run %s is %s (%s), want published", run.ID, run.Status, run.LastError)
	}
	l.project(fmt.Sprintf("evidence-projector-%d", evidenceSeq))
	return run
}

// evidenceDoc wraps statements in a policy document.
func evidenceDoc(statements ...string) string {
	out := `{"Version":"2012-10-17","Statement":[`
	for i, s := range statements {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out + `]}`
}

// evidenceE4 is the E4 lab: account A connected, partner account C never.
//
//	SharedToolRole  (Lambda ticket-tools runs as it; Lambda trust)
//	  TicketRead    ReadTickets  s3:GetObject  support-tickets/*        selector
//	                ListTickets  s3:ListBucket support-tickets  + Condition s3:prefix;
//	                             the bucket's policy is READ (not projected)
//	  ToolboxRead   ToolboxGet   s3:GetObject  support-tickets/*        same group key as ReadTickets
//	  FinanceAll    AllButFinance s3:*  NotResource finance/*           B19
//	                AllButIAM    NotAction iam:*  scratch/*
//	  ExternalKey   Decrypt      kms:Decrypt on a key in account C      not connected
//	  GuardRails    Deny s3:DeleteObject *                              a Deny restriction
//	PlainRole       PlainRead    s3:GetObject  plain-bucket/report.csv  exact; nothing else
//	priya (user)    boundary PowerUserAccess; member of ops; PriyaOwn priya-scratch/*
//	ops (group)     OpsRead ops-bucket/*; inline OpsDeny (Deny)
//	sam (user)      member of devs
//	devs (group)    DevRead dev-bucket/*
//	AssumerRole     trusts SharedToolRole with Condition sts:ExternalId
//	PartnerRole     trusts account C's root; and ec2 through NotAction sts:TagSession
//	GuardedRole     Deny NotPrincipal; Allow lambda
//
// priya's credential report is collected, so the junction links it to her
// grants -- and /evidence must not show it (D-24).
type evidenceE4 struct {
	l   *p2Lab
	a   *p2Account
	api *readAPI
	run models.CloudScanRun
}

func evidenceE4Lab(t *testing.T, name string) *evidenceE4 {
	t.Helper()
	l := newP2Lab(t, name, true)
	a := l.account(accountA)

	shared := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.lambda("us-east-1", "ticket-tools", shared)
	a.attach("SharedToolRole", a.managed("TicketRead", evidenceDoc(
		`{"Sid":"ReadTickets","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::support-tickets/*"}`,
		`{"Sid":"ListTickets","Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::support-tickets",`+
			`"Condition":{"StringLike":{"s3:prefix":["tickets/*"]}}}`)))
	a.attach("SharedToolRole", a.managed("ToolboxRead", evidenceDoc(
		`{"Sid":"ToolboxGet","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::support-tickets/*"}`)))
	a.attach("SharedToolRole", a.managed("FinanceAll", evidenceDoc(
		`{"Sid":"AllButFinance","Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::finance/*"}`,
		`{"Sid":"AllButIAM","Effect":"Allow","NotAction":"iam:*","Resource":"arn:aws:s3:::scratch/*"}`)))
	a.attach("SharedToolRole", a.managed("ExternalKey", evidenceDoc(
		`{"Sid":"Decrypt","Effect":"Allow","Action":"kms:Decrypt","Resource":"arn:aws:kms:us-east-1:`+evidenceAccountC+`:key/abcd"}`)))
	a.attach("SharedToolRole", a.managed("GuardRails", evidenceDoc(
		`{"Sid":"NoDeletes","Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}`)))

	a.role("PlainRole", "AROAPLAINROLEPLAIN01")
	a.attach("PlainRole", a.managed("PlainRead", evidenceDoc(
		`{"Sid":"PlainGet","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::plain-bucket/report.csv"}`)))

	boundary := s3aAWSManaged(a, "PowerUserAccess", evidenceDoc(
		`{"Effect":"Allow","NotAction":["iam:*","organizations:*"],"Resource":"*"}`))
	s3aGroup(a, "ops", "AGPAOPSOPSOPSOPSOPS1")
	s3aGroupAttach(t, a, "ops", a.managed("OpsRead", evidenceDoc(
		`{"Sid":"ReadOps","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::ops-bucket/*"}`)))
	s3aGroupInline(t, a, "ops", "OpsDeny", evidenceDoc(
		`{"Sid":"NoBucketDeletes","Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}`))
	priyaARN := s3aUser(a, "priya", "AIDAPRIYAPRIYAPRIYA1")
	s3aEditUser(t, a, "priya", func(u *iamtypes.User) { u.PermissionsBoundary = s3aBoundary(boundary) })
	s3aJoin(a, "priya", "ops")
	a.iam.inlineUserPolicies["priya"] = map[string]string{
		"PriyaOwn": evidenceDoc(`{"Sid":"OwnRead","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::priya-scratch/*"}`),
	}
	s3aGroup(a, "devs", "AGPADEVSDEVSDEVSDEV1")
	s3aGroupAttach(t, a, "devs", a.managed("DevRead", evidenceDoc(
		`{"Sid":"ReadDev","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::dev-bucket/*"}`)))
	s3aUser(a, "sam", "AIDASAMSAMSAMSAMSAM1")
	s3aJoin(a, "sam", "devs")

	trustRole(a, "AssumerRole", "AROAASSUMERROLEASSU1", trustDoc(
		`{"Sid":"FromTools","Effect":"Allow","Principal":{"AWS":"`+shared+`"},"Action":"sts:AssumeRole",`+
			`"Condition":{"StringEquals":{"sts:ExternalId":"ticket-42"}}}`))
	trustRole(a, "PartnerRole", "AROAPARTNERROLEPART1", trustDoc(
		trustAllow(`{"AWS":"arn:aws:iam::`+evidenceAccountC+`:root"}`, "sts:AssumeRole"),
		`{"Sid":"AllButTagging","Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"NotAction":"sts:TagSession"}`))
	trustRole(a, "GuardedRole", "AROAGUARDEDROLEGUAR1", trustDoc(
		`{"Effect":"Deny","NotPrincipal":{"AWS":"`+shared+`"},"Action":"sts:AssumeRole"}`,
		trustAllow(`{"Service":"lambda.amazonaws.com"}`, "sts:AssumeRole")))

	header := "user,arn,password_enabled,password_last_used,mfa_active," +
		"access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date," +
		"access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\n"
	csv := header + "priya," + priyaARN + ",true,N/A,true,false,N/A,N/A,false,N/A,N/A\n"

	run := evidenceCycle(l, a, evidenceFakes{
		bucketPolicies: map[string]string{"support-tickets": evidenceDoc(
			`{"Effect":"Deny","Principal":"*","Action":"s3:DeleteBucket","Resource":"arn:aws:s3:::support-tickets"}`)},
		credentialCSV: csv,
	})
	if n := l.count(`SELECT count(*) FROM cloud_observation WHERE workspace_id = ? AND source_api = 'iam:GetCredentialReport'`, l.ws); n == 0 {
		t.Fatal("fixture: priya's credential report was not collected")
	}
	if n := l.count(`SELECT count(*) FROM cloud_observation WHERE workspace_id = ? AND surface = ?
	                  AND subject_native_id = 'arn:aws:s3:::support-tickets'`, l.ws, models.SurfaceResourcePolicies); n == 0 {
		t.Fatal("fixture: the support-tickets bucket policy was not read")
	}
	return &evidenceE4{l: l, a: a, api: l.api(), run: run}
}

/* ------------------------------- lookups ---------------------------------- */

// evidenceGrant is the grant of holder through policy's statement sid.
func evidenceGrant(t *testing.T, l *p2Lab, holder, policy, sid string) string {
	t.Helper()
	var ids []uuid.UUID
	l.db.Raw(`SELECT g.id FROM iga_access_edges g
	            JOIN iga_identity_accounts ia ON ia.workspace_id = g.workspace_id AND ia.id = g.subject_identity_account_id
	            JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
	            JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	           WHERE g.workspace_id = ? AND ia.display_name = ? AND p.display_name = ? AND e.sid = ?
	           ORDER BY g.valid_from DESC`, l.ws, holder, policy, sid).Scan(&ids)
	if len(ids) == 0 {
		t.Fatalf("fixture: no grant of %s through %s/%s", holder, policy, sid)
	}
	return refOf("grant", ids[0])
}

// evidenceRelationship is the relationship of relType from source (an
// identity or workload display name, or an external principal's subject) to
// target.
func evidenceRelationship(t *testing.T, l *p2Lab, relType, source, target string) string {
	t.Helper()
	var ids []uuid.UUID
	l.db.Raw(`SELECT r.id FROM iga_relationship r
	            JOIN iga_identity_accounts t ON t.workspace_id = r.workspace_id AND t.id = r.target_identity_account_id
	            LEFT JOIN iga_identity_accounts si ON si.workspace_id = r.workspace_id AND si.id = r.source_identity_account_id
	            LEFT JOIN iga_workload sw ON sw.workspace_id = r.workspace_id AND sw.id = r.source_workload_id
	            LEFT JOIN iga_external_principal ep ON ep.workspace_id = r.workspace_id AND ep.id = r.source_external_principal_id
	           WHERE r.workspace_id = ? AND r.relationship_type = ? AND t.display_name = ?
	             AND ? IN (si.display_name, sw.display_name, ep.subject_claim)
	           ORDER BY r.valid_from DESC`, l.ws, relType, target, source).Scan(&ids)
	if len(ids) == 0 {
		t.Fatalf("fixture: no %s from %s to %s", relType, source, target)
	}
	return refOf("relationship", ids[0])
}

// evidenceAssignment is the assignment of policy to holder.
func evidenceAssignment(t *testing.T, l *p2Lab, policy, holder string) string {
	t.Helper()
	var ids []uuid.UUID
	l.db.Raw(`SELECT pa.id FROM iga_policy_assignment pa
	            JOIN iga_policy p ON p.workspace_id = pa.workspace_id AND p.id = pa.policy_id
	            JOIN iga_identity_accounts ia ON ia.workspace_id = pa.workspace_id AND ia.id = pa.holder_identity_account_id
	           WHERE pa.workspace_id = ? AND p.display_name = ? AND ia.display_name = ?`, l.ws, policy, holder).Scan(&ids)
	if len(ids) == 0 {
		t.Fatalf("fixture: no assignment of %s to %s", policy, holder)
	}
	return refOf("assignment", ids[0])
}

// evidenceTarget is the target of policy's statement sid naming resource.
func evidenceTarget(t *testing.T, l *p2Lab, policy, sid, resource string) string {
	t.Helper()
	var ids []uuid.UUID
	l.db.Raw(`SELECT t.id FROM iga_entitlement_target t
	            JOIN iga_entitlements e ON e.workspace_id = t.workspace_id AND e.id = t.entitlement_id
	            JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	            JOIN iga_resources r ON r.workspace_id = t.workspace_id AND r.id = t.resource_id
	           WHERE t.workspace_id = ? AND p.display_name = ? AND e.sid = ? AND r.display_name = ?`,
		l.ws, policy, sid, resource).Scan(&ids)
	if len(ids) == 0 {
		t.Fatalf("fixture: no target of %s/%s on %s", policy, sid, resource)
	}
	return refOf("target", ids[0])
}

// evidenceNode is an object ref by its table and display name.
func evidenceNode(t *testing.T, l *p2Lab, refType, table, name string) string {
	t.Helper()
	var ids []uuid.UUID
	l.db.Raw(`SELECT id FROM `+table+` WHERE workspace_id = ? AND display_name = ? ORDER BY first_seen_at DESC`,
		l.ws, name).Scan(&ids)
	if len(ids) == 0 {
		t.Fatalf("fixture: no %s %q", table, name)
	}
	return refOf(refType, ids[0])
}

// evidenceExternal is an external principal ref by its subject.
func evidenceExternal(t *testing.T, l *p2Lab, subject string) string {
	t.Helper()
	var ids []uuid.UUID
	l.db.Raw(`SELECT id FROM iga_external_principal WHERE workspace_id = ? AND subject_claim = ?`, l.ws, subject).Scan(&ids)
	if len(ids) == 0 {
		t.Fatalf("fixture: no external principal %q", subject)
	}
	return refOf("external_principal", ids[0])
}

/* ------------------------------ assertions -------------------------------- */

// evidenceGet calls /evidence for one claim (plus extra query pairs) and
// requires 200.
func evidenceGet(t *testing.T, api *readAPI, claim string, extra ...string) map[string]any {
	t.Helper()
	code, body := api.get("/evidence" + qs(append([]string{"claim", claim}, extra...)...))
	mustStatus(t, "evidence "+claim, code, body, http.StatusOK)
	return body
}

// evidenceCodes lists a response's limitation codes, in order.
func evidenceCodes(body map[string]any) []string {
	var out []string
	for _, l := range digl(body, "data", "limitations") {
		out = append(out, digs(l, "code"))
	}
	return out
}

// evidenceLim returns the first limitation with code, or nil.
func evidenceLim(body map[string]any, code string) map[string]any {
	for _, l := range digl(body, "data", "limitations") {
		if digs(l, "code") == code {
			m, _ := l.(map[string]any)
			return m
		}
	}
	return nil
}

// evidenceStrings reads a JSON string list, sorted.
func evidenceStrings(v any) []string {
	var out []string
	for _, x := range digl(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// evidenceJSON renders a body for failure messages.
func evidenceJSON(v any) string {
	raw, _ := json.MarshalIndent(v, "", "  ")
	return string(raw)
}
