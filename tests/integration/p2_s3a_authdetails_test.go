package integration

// S3a (SPEC-iga-phase2-graph.md T3.1, T3.3, T3.5): the IAM configuration read
// through GetAccountAuthorizationDetails, one call per filter (P2-DECISIONS
// D-48); per-document isolation (T3.3, D-49); policy versions as evidence
// subjects (T3.5). Every test runs the REAL worker and projector over the P2-0
// lab (p2_0_lab_test.go), with the AWS boundary answered by fakeIAM, which
// serves each authorization-details listing from its own state.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

/* ------------------------------ lab helpers -------------------------------- */

// s3aAWSManaged defines an AWS-managed policy document (served by GetPolicy /
// GetPolicyVersion only, never by the LocalManagedPolicy listing).
func s3aAWSManaged(a *p2Account, name, doc string) string {
	arn := "arn:aws:iam::aws:policy/" + name
	a.iam.managedPolicies[arn] = doc
	return arn
}

// s3aUser adds an IAM user.
func s3aUser(a *p2Account, name, userID string) string {
	arn := "arn:aws:iam::" + a.id + ":user/" + name
	a.iam.users = append(a.iam.users, iamtypes.User{
		Arn: aws.String(arn), UserName: aws.String(name), UserId: aws.String(userID),
		Path: aws.String("/"), CreateDate: ago(60 * 24 * time.Hour),
	})
	return arn
}

// s3aEditUser changes one user in place.
func s3aEditUser(t *testing.T, a *p2Account, name string, edit func(*iamtypes.User)) {
	t.Helper()
	for i := range a.iam.users {
		if aws.ToString(a.iam.users[i].UserName) == name {
			edit(&a.iam.users[i])
			return
		}
	}
	t.Fatalf("no user %q in the fixture", name)
}

// s3aEditRole changes one role in place.
func s3aEditRole(t *testing.T, a *p2Account, name string, edit func(*iamtypes.Role)) {
	t.Helper()
	for i := range a.iam.roles {
		if aws.ToString(a.iam.roles[i].RoleName) == name {
			edit(&a.iam.roles[i])
			return
		}
	}
	t.Fatalf("no role %q in the fixture", name)
}

func s3aBoundary(arn string) *iamtypes.AttachedPermissionsBoundary {
	return &iamtypes.AttachedPermissionsBoundary{
		PermissionsBoundaryArn:  aws.String(arn),
		PermissionsBoundaryType: iamtypes.PermissionsBoundaryAttachmentTypePolicy,
	}
}

// s3aGroup adds an IAM group.
func s3aGroup(a *p2Account, name, groupID string) string {
	arn := "arn:aws:iam::" + a.id + ":group/" + name
	a.iam.groups = append(a.iam.groups, iamtypes.GroupDetail{
		Arn: aws.String(arn), GroupName: aws.String(name), GroupId: aws.String(groupID),
		Path: aws.String("/"), CreateDate: ago(90 * 24 * time.Hour),
	})
	return arn
}

func s3aEditGroup(t *testing.T, a *p2Account, name string, edit func(*iamtypes.GroupDetail)) {
	t.Helper()
	for i := range a.iam.groups {
		if aws.ToString(a.iam.groups[i].GroupName) == name {
			edit(&a.iam.groups[i])
			return
		}
	}
	t.Fatalf("no group %q in the fixture", name)
}

// s3aGroupAttach attaches a managed policy to a group.
func s3aGroupAttach(t *testing.T, a *p2Account, group, policyARN string) {
	s3aEditGroup(t, a, group, func(g *iamtypes.GroupDetail) {
		g.AttachedManagedPolicies = append(g.AttachedManagedPolicies, iamtypes.AttachedPolicy{
			PolicyArn: aws.String(policyARN), PolicyName: aws.String(lastSegment(policyARN)),
		})
	})
}

// s3aGroupInline embeds an inline policy in a group, URL-encoded as IAM
// returns it.
func s3aGroupInline(t *testing.T, a *p2Account, group, name, doc string) {
	s3aEditGroup(t, a, group, func(g *iamtypes.GroupDetail) {
		g.GroupPolicyList = append(g.GroupPolicyList, iamtypes.PolicyDetail{
			PolicyName: aws.String(name), PolicyDocument: aws.String(url.QueryEscape(doc)),
		})
	})
}

// s3aJoin makes a user a member of a group.
func s3aJoin(a *p2Account, user, group string) {
	a.iam.userGroups[user] = append(a.iam.userGroups[user], group)
}

// s3aDoc is a one-statement Allow document.
func s3aDoc(sid, action, resource string) string {
	sidPart := ""
	if sid != "" {
		sidPart = `"Sid":"` + sid + `",`
	}
	return `{"Version":"2012-10-17","Statement":[{` + sidPart + `"Effect":"Allow","Action":"` +
		action + `","Resource":"` + resource + `"}]}`
}

type s3aAssignment struct {
	Policy      string
	Holder      string
	Kind        string
	State       string
	EndedReason string
}

func s3aAssignments(l *p2Lab) []s3aAssignment {
	var out []s3aAssignment
	l.db.Raw(`SELECT p.display_name AS policy, i.display_name AS holder, a.assignment_kind AS kind,
	                 a.state, a.ended_reason
	            FROM iga_policy_assignment a
	            JOIN iga_policy p ON p.id = a.policy_id
	            JOIN iga_identity_accounts i ON i.id = a.holder_identity_account_id
	           WHERE a.workspace_id = ? ORDER BY p.display_name, i.display_name, a.valid_from`, l.ws).Scan(&out)
	return out
}

func s3aFindAssignment(rows []s3aAssignment, policy, holder, kind string) *s3aAssignment {
	for i := range rows {
		if rows[i].Policy == policy && rows[i].Holder == holder && rows[i].Kind == kind {
			return &rows[i]
		}
	}
	return nil
}

type s3aGrant struct {
	Policy string
	Holder string
	State  string
}

// s3aGrantsByHolder lists grants with the holder they run from.
func s3aGrantsByHolder(l *p2Lab) []s3aGrant {
	var out []s3aGrant
	l.db.Raw(`SELECT p.display_name AS policy, i.display_name AS holder, g.state
	            FROM iga_access_edges g
	            JOIN iga_entitlements e ON e.id = g.entitlement_id
	            JOIN iga_policy p ON p.id = e.policy_id
	            JOIN iga_identity_accounts i ON i.id = g.subject_identity_account_id
	           WHERE g.workspace_id = ? AND g.provider = 'aws'
	           ORDER BY p.display_name, i.display_name`, l.ws).Scan(&out)
	return out
}

// s3aStatementSupport is each statement's lifecycle and its support state for
// one connector, keyed "policy/sid-or-index".
func s3aStatementSupport(l *p2Lab, conn uuid.UUID) map[string]string {
	var rows []struct {
		Policy    string
		Sid       string
		Idx       int
		Lifecycle string
		Support   string
	}
	l.db.Raw(`SELECT p.display_name AS policy, e.sid, e.statement_index AS idx, e.lifecycle,
	                 COALESCE(s.state, '') AS support
	            FROM iga_entitlements e
	            JOIN iga_policy p ON p.id = e.policy_id
	            LEFT JOIN iga_object_support s ON s.entitlement_id = e.id AND s.connector_id = ?
	           WHERE e.workspace_id = ? AND e.provider = 'aws'`, conn, l.ws).Scan(&rows)
	out := map[string]string{}
	for _, r := range rows {
		k := r.Sid
		if k == "" {
			k = fmt.Sprint(r.Idx)
		}
		out[r.Policy+"/"+k] = r.Lifecycle + ":" + r.Support
	}
	return out
}

type s3aPolicyRow struct {
	NativeID      string
	Name          string
	AWSManaged    bool
	PolicyID      string
	VersionID     string
	HasDocument   bool
	DocumentError string
	Holder        *uuid.UUID
	Generation    int
}

// s3aCloudPolicies is the connector's cloud_policy rows at one generation, by
// name.
func s3aCloudPolicies(l *p2Lab, conn uuid.UUID, generation int) map[string]s3aPolicyRow {
	var rows []s3aPolicyRow
	l.db.Raw(`SELECT native_id, name, aws_managed, policy_id, version_id, document IS NOT NULL AS has_document,
	                 document_error, holder_identity_id AS holder, last_seen_generation AS generation
	            FROM cloud_policy WHERE workspace_id = ? AND connector_id = ? AND last_seen_generation = ?`,
		l.ws, conn, generation).Scan(&rows)
	out := map[string]s3aPolicyRow{}
	for _, r := range rows {
		out[r.Name] = r
	}
	return out
}

// s3aFacts decodes the sanitized_facts a query selects, one map per row.
func s3aFacts(l *p2Lab, q string, args ...any) []map[string]any {
	l.t.Helper()
	var raws []json.RawMessage
	if err := l.db.Raw(q, args...).Scan(&raws).Error; err != nil {
		l.t.Fatalf("facts: %v", err)
	}
	out := make([]map[string]any, 0, len(raws))
	for _, r := range raws {
		var m map[string]any
		if err := json.Unmarshal(r, &m); err != nil {
			l.t.Fatalf("facts %s: %v", r, err)
		}
		out = append(out, m)
	}
	return out
}

func s3aCoverage(run models.CloudScanRun) map[string]models.SurfaceCoverage {
	return models.DecodeScanCoverage(run.Coverage).Surfaces
}

/* ---------------------------------- tests --------------------------------- */

// E3/E4 (T3.1 gate): user priya, a member of group ops, with a permissions
// boundary, appears with her membership, her boundary assignment, and the
// group's policies AS THE GROUP'S -- inherited by traversal, never copied
// onto her (§2.6).
func TestP2S3aUserInGroupWithBoundary(t *testing.T) {
	l := newP2Lab(t, "p2-s3a-priya", true)
	a := l.account(accountA)

	opsRead := a.managed("OpsRead", s3aDoc("ReadOps", "s3:GetObject", "arn:aws:s3:::ops-bucket/*"))
	// An AWS-managed boundary: fetched like an attached policy (D-50).
	boundary := s3aAWSManaged(a, "PowerUserAccess", `{"Version":"2012-10-17","Statement":[`+
		`{"Effect":"Allow","NotAction":["iam:*","organizations:*"],"Resource":"*"}]}`)
	s3aGroup(a, "ops", "AGPAOPSOPSOPSOPSOPS1")
	s3aGroupAttach(t, a, "ops", opsRead)
	s3aGroupInline(t, a, "ops", "OpsInline", s3aDoc("ListOps", "s3:ListBucket", "arn:aws:s3:::ops-bucket"))
	priyaARN := s3aUser(a, "priya", "AIDAPRIYAPRIYAPRIYA1")
	s3aEditUser(t, a, "priya", func(u *iamtypes.User) {
		u.PermissionsBoundary = s3aBoundary(boundary)
		u.Tags = []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String("ops")}}
	})
	s3aJoin(a, "priya", "ops")
	run := l.scanAndProject(a)

	// ---- collected -------------------------------------------------------
	for _, surf := range []string{models.SurfaceIAMRoles, models.SurfaceIAMUsers,
		models.SurfaceIAMGroups, models.SurfaceIAMPolicies} {
		if s := s3aCoverage(run)[surf]; s.State != models.CloudCoverageReached {
			t.Errorf("%s = %+v, want reached", surf, s)
		}
	}
	var priya models.CloudIdentity
	if err := l.db.Where("workspace_id = ? AND native_id = ?", l.ws, priyaARN).First(&priya).Error; err != nil {
		t.Fatalf("priya was not recorded: %v", err)
	}
	if at := priya.AWSAttrs(); at.PermissionsBoundaryARN != boundary || at.Tags["team"] != "ops" ||
		at.UniqueID != "AIDAPRIYAPRIYAPRIYA1" {
		t.Errorf("priya's attrs = %+v, want her boundary, her tags and her UserId", at)
	}
	if n := l.count(`SELECT count(*) FROM cloud_group_membership m
	                  JOIN cloud_identity u ON u.id = m.user_identity_id
	                  JOIN cloud_identity g ON g.id = m.group_identity_id
	                 WHERE m.workspace_id = ? AND u.name = 'priya' AND g.name = 'ops'
	                   AND m.last_seen_generation = ?`, l.ws, run.Generation); n != 1 {
		t.Errorf("priya -> ops memberships at this run = %d, want 1", n)
	}
	pols := s3aCloudPolicies(l, a.conn, run.Generation)
	if b := pols["PowerUserAccess"]; !b.AWSManaged || !b.HasDocument || b.DocumentError != "" || b.PolicyID == "" {
		t.Errorf("boundary policy row = %+v, want an AWS-managed row with its document and PolicyId", b)
	}
	if n := a.iam.calls["GetPolicyVersion:"+boundary]; n != 1 {
		t.Errorf("GetPolicyVersion for the AWS-managed boundary = %d calls, want 1 (D-50)", n)
	}
	if n := l.count(`SELECT count(*) FROM cloud_policy_attachment x
	                  JOIN cloud_policy p ON p.id = x.policy_row_id
	                  JOIN cloud_identity i ON i.id = x.principal_identity_id
	                 WHERE x.workspace_id = ? AND i.name = 'priya' AND p.name = 'PowerUserAccess'
	                   AND x.attachment_kind = 'boundary'`, l.ws); n != 1 {
		t.Errorf("boundary attachments on priya = %d, want 1", n)
	}
	// Cloud Inventory: priya's own statements are read in the light of her
	// boundary now (§1.3) -- the boundary's statements are written as a
	// ceiling, never as granted access.
	if n := l.count(`SELECT count(*) FROM cloud_permission p JOIN cloud_identity i ON i.id = p.identity_id
	                  WHERE p.workspace_id = ? AND i.name = 'priya' AND p.derivation <> ?`,
		l.ws, models.PermissionDerivationBoundary); n != 0 {
		t.Errorf("priya has %d non-boundary cloud_permission rows: the group's grants were copied onto her", n)
	}

	// ---- projected -------------------------------------------------------
	var member []struct {
		Source string
		Target string
		State  string
	}
	l.db.Raw(`SELECT s.display_name AS source, g.display_name AS target, r.state
	            FROM iga_relationship r
	            JOIN iga_identity_accounts s ON s.id = r.source_identity_account_id
	            JOIN iga_identity_accounts g ON g.id = r.target_identity_account_id
	           WHERE r.workspace_id = ? AND r.relationship_type = ?`, l.ws, models.RelTypeMemberOf).Scan(&member)
	if len(member) != 1 || member[0].Source != "priya" || member[0].Target != "ops" || member[0].State != models.RelCurrent {
		t.Errorf("member_of = %+v, want priya -> ops, current", member)
	}
	asg := s3aAssignments(l)
	if b := s3aFindAssignment(asg, "PowerUserAccess", "priya", models.CloudAttachmentBoundary); b == nil || b.State != models.RelCurrent {
		t.Errorf("priya's boundary assignment = %+v in %+v, want current", b, asg)
	}
	if g := s3aFindAssignment(asg, "OpsRead", "ops", models.CloudAttachmentAttached); g == nil || g.State != models.RelCurrent {
		t.Errorf("ops' OpsRead assignment = %+v, want current", g)
	}
	if g := s3aFindAssignment(asg, "OpsInline", "ops", models.CloudAttachmentInline); g == nil || g.State != models.RelCurrent {
		t.Errorf("ops' inline assignment = %+v, want current", g)
	}
	grants := s3aGrantsByHolder(l)
	var groupGrants, priyaGrants int
	for _, g := range grants {
		switch g.Holder {
		case "ops":
			if g.State == models.RelCurrent && (g.Policy == "OpsRead" || g.Policy == "OpsInline") {
				groupGrants++
			}
		case "priya":
			priyaGrants++
		}
	}
	if groupGrants != 2 {
		t.Errorf("grants held by ops = %+v, want OpsRead's and OpsInline's, current", grants)
	}
	if priyaGrants != 0 {
		t.Errorf("priya holds %d grants: a boundary never grants, and group access is by traversal, not copied (%+v)",
			priyaGrants, grants)
	}
	// Every edge this adds has evidence (§4.8): member_of from priya's own
	// observation (it lists the group), the boundary assignment from hers and
	// the policy version's.
	if n := l.count(`SELECT count(*) FROM iga_relationship r WHERE r.workspace_id = ?
	                  AND NOT EXISTS (SELECT 1 FROM iga_relationship_evidence e WHERE e.relationship_id = r.id)`,
		l.ws); n != 0 {
		t.Errorf("%d relationships without evidence", n)
	}
	if n := l.count(`SELECT count(*) FROM iga_policy_assignment a WHERE a.workspace_id = ?
	                  AND NOT EXISTS (SELECT 1 FROM iga_assignment_evidence e WHERE e.assignment_id = a.id)`,
		l.ws); n != 0 {
		t.Errorf("%d assignments without evidence", n)
	}
}

// T3.2 via T3.1: an AWS-managed policy attached in two accounts is TWO
// cloud_policy rows (per-connector keys) and ONE graph policy with a support
// row per account.
func TestP2S3aAWSManagedPolicyInTwoAccounts(t *testing.T) {
	l := newP2Lab(t, "p2-s3a-two-accounts", true)
	const doc = `{"Version":"2012-10-17","Statement":[{"Sid":"ReadOnly","Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}`
	a := l.account(accountA)
	a.role("ReaderA", "AROAREADERAREADERA01")
	b := l.account(accountB)
	b.role("ReaderB", "AROAREADERBREADERB01")
	ro := s3aAWSManaged(a, "ReadOnlyAccess", doc)
	s3aAWSManaged(b, "ReadOnlyAccess", doc)
	a.attach("ReaderA", ro)
	b.attach("ReaderB", ro)
	l.scanAndProject(a)
	l.scanAndProject(b)

	var rows []struct {
		ConnectorID uuid.UUID
		AWSManaged  bool
	}
	l.db.Raw(`SELECT connector_id, aws_managed FROM cloud_policy WHERE workspace_id = ? AND native_id = ?`,
		l.ws, ro).Scan(&rows)
	byConn := map[uuid.UUID]bool{}
	for _, r := range rows {
		byConn[r.ConnectorID] = r.AWSManaged
	}
	if len(rows) != 2 || !byConn[a.conn] || !byConn[b.conn] {
		t.Fatalf("cloud_policy rows for %s = %+v, want one AWS-managed row per connector", ro, rows)
	}
	var policyIDs []uuid.UUID
	l.db.Raw(`SELECT id FROM iga_policy WHERE workspace_id = ? AND native_ref = ? AND lifecycle = 'active'`,
		l.ws, ro).Scan(&policyIDs)
	if len(policyIDs) != 1 {
		t.Fatalf("graph policies for %s = %v, want exactly one", ro, policyIDs)
	}
	sup := l.supportOf("policy_id", policyIDs[0])
	if sup[a.conn] != models.RelCurrent || sup[b.conn] != models.RelCurrent {
		t.Errorf("policy support = %v, want both accounts current", sup)
	}
}

// T3.3 gate: ONE unreadable document -- every other policy's statements are
// written, and the unreadable one's statements and grants go STALE, never
// ended. Covers the collection side end to end: the reader records the fetch
// failure on the one policy, the permission scanner writes every other policy
// and every attachment, and the projector protects what the unreadable one
// declared.
func TestP2S3aOneUnreadableDocumentIsolated(t *testing.T) {
	l := newP2Lab(t, "p2-s3a-isolation", true)
	a := l.account(accountA)
	a.role("WorkerRole", "AROAWORKERROLEWORKER")
	s3aGroup(a, "builders", "AGPABUILDERSBUILDERS")
	s3aUser(a, "sam", "AIDASAMSAMSAMSAMSAM1")
	s3aJoin(a, "sam", "builders")

	blocked := s3aAWSManaged(a, "AAABlockedAccess", s3aDoc("Blocked", "dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:"+a.id+":table/blocked"))
	alpha := a.managed("Alpha", s3aDoc("AlphaRead", "s3:GetObject", "arn:aws:s3:::alpha/*"))
	zeta := s3aAWSManaged(a, "ZetaAccess", s3aDoc("ZetaRead", "s3:GetObject", "arn:aws:s3:::zeta/*"))
	// Detached in the SAME run as the denial (E9(b)): its assignment must end,
	// and its cloud_policy_attachment must be reconciled away, one unreadable
	// document notwithstanding.
	detached := a.managed("DetachedLater", s3aDoc("Later", "s3:GetObject", "arn:aws:s3:::later/*"))
	a.attach("WorkerRole", blocked)
	a.attach("WorkerRole", alpha)
	a.attach("WorkerRole", zeta)
	a.attach("WorkerRole", detached)
	a.iam.inlineRolePolicies["WorkerRole"] = map[string]string{"Gamma": s3aDoc("GammaRead", "s3:GetObject", "arn:aws:s3:::gamma/*")}
	s3aGroupAttach(t, a, "builders", blocked)
	s3aGroupAttach(t, a, "builders", alpha)
	s3aEditUser(t, a, "sam", func(u *iamtypes.User) { u.PermissionsBoundary = s3aBoundary(zeta) })
	l.scanAndProject(a)

	a.iam.failPolicyVersion[blocked] = denied("iam:GetPolicyVersion")
	a.detach("WorkerRole", detached)
	run := l.scanAndProject(a)

	// The unreadable document, named with its call; the listing stays reached.
	cov := s3aCoverage(run)
	if pd := cov[models.SurfacePolicyDocuments]; pd.State != models.CloudCoveragePartial ||
		!strings.Contains(pd.Error, "1 policy could not be read") || !strings.Contains(pd.Error, "AAABlockedAccess") ||
		strings.Contains(pd.Error, "Alpha") || strings.Contains(pd.Error, "Zeta") {
		t.Errorf("policy_documents = %+v, want partial naming exactly AAABlockedAccess", pd)
	}
	for _, surf := range []string{models.SurfaceIAMPolicies, models.SurfaceIAMRoles, models.SurfaceIAMUsers, models.SurfaceIAMGroups} {
		if s := cov[surf].State; s != models.CloudCoverageReached {
			t.Errorf("%s = %q, want reached: one document must not veto a listing", surf, s)
		}
	}
	if _, bad := cov[models.SurfacePermissionScan]; bad {
		t.Errorf("permission_scan = %+v: the permission scan aborted over one document", cov[models.SurfacePermissionScan])
	}
	pols := s3aCloudPolicies(l, a.conn, run.Generation)
	if b := pols["AAABlockedAccess"]; b.HasDocument || !strings.HasPrefix(b.DocumentError, "fetch: ") ||
		!strings.Contains(b.DocumentError, "iam:GetPolicyVersion") || !strings.Contains(b.DocumentError, "AccessDenied") {
		t.Errorf("unreadable row = %+v, want no document and a fetch error naming the call and code", b)
	}
	for _, name := range []string{"Alpha", "ZetaAccess", "Gamma"} {
		if p, ok := pols[name]; !ok || !p.HasDocument || p.DocumentError != "" {
			t.Errorf("%s at this run = %+v (present %v), want readable with its document", name, p, ok)
		}
	}

	// Every OTHER policy's statements: confirmed by this run.
	sup := s3aStatementSupport(l, a.conn)
	for _, k := range []string{"Alpha/AlphaRead", "ZetaAccess/ZetaRead", "Gamma/GammaRead"} {
		if sup[k] != models.IGALifecycleActive+":"+models.RelCurrent {
			t.Errorf("statement %s = %q, want active:current (%v)", k, sup[k], sup)
		}
	}
	if s := sup["AAABlockedAccess/Blocked"]; s != models.IGALifecycleActive+":"+models.RelStale {
		t.Errorf("unreadable statement = %q, want active:stale", s)
	}
	// Cloud Inventory rows for every readable document, at this generation.
	for _, src := range []string{alpha + "#s0", "inline:Gamma#s0", "boundary:" + zeta + "#s0"} {
		if n := l.count(`SELECT count(*) FROM cloud_permission WHERE workspace_id = ? AND native_id = ?
		                  AND last_seen_generation = ?`, l.ws, src, run.Generation); n == 0 {
			t.Errorf("cloud_permission %s not written this run", src)
		}
	}
	// Grants: the unreadable policy's stale (both holders), the detached
	// policy's ended, everything else current. Nothing else ends.
	for _, g := range s3aGrantsByHolder(l) {
		want := models.RelCurrent
		switch g.Policy {
		case "AAABlockedAccess":
			want = models.RelStale
		case "DetachedLater":
			want = models.RelEnded
		}
		if g.State != want {
			t.Errorf("grant %s on %s = %s, want %s", g.Policy, g.Holder, g.State, want)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND state = 'ended'`, l.ws); n != 1 {
		t.Errorf("%d grants ended, want exactly the detached policy's", n)
	}
	// cloud_policy reconciles on the listings, not on every document being
	// readable: the detached attachment is gone, the policy row (still listed)
	// stays.
	if n := l.count(`SELECT count(*) FROM cloud_policy_attachment x JOIN cloud_policy p ON p.id = x.policy_row_id
	                  WHERE x.workspace_id = ? AND p.name = 'DetachedLater'`, l.ws); n != 0 {
		t.Errorf("DetachedLater attachments = %d, want 0: one unreadable document vetoed the account's policy cleanup", n)
	}
	if _, ok := pols["DetachedLater"]; !ok {
		t.Error("DetachedLater's row is gone: a detached customer-managed policy is still listed")
	}
	// Its assignments stay current: attachment lists are read independently.
	for _, holder := range []string{"WorkerRole", "builders"} {
		if x := s3aFindAssignment(s3aAssignments(l), "AAABlockedAccess", holder, models.CloudAttachmentAttached); x == nil || x.State != models.RelCurrent {
			t.Errorf("unreadable policy's assignment on %s = %+v, want current", holder, x)
		}
	}
}

// D-49: a document with ONE unusable statement is unreadable as a whole --
// document_error set, named under policy_documents -- so what it declared goes
// stale instead of its unusable statement silently retiring and its grant
// ending.
func TestP2S3aUnusableStatementMarksDocumentUnreadable(t *testing.T) {
	l := newP2Lab(t, "p2-s3a-unusable", true)
	a := l.account(accountA)
	a.role("MixedRole", "AROAMIXEDROLEMIXEDRO")
	mixed := a.managed("Mixed", `{"Version":"2012-10-17","Statement":[`+
		`{"Sid":"KeepA","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::a/*"},`+
		`{"Sid":"LoseB","Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*"}]}`)
	a.attach("MixedRole", mixed)
	l.scanAndProject(a)

	// LoseB loses its Effect in AWS: the document still parses; one statement
	// cannot be used.
	a.iam.managedPolicies[mixed] = `{"Version":"2012-10-17","Statement":[` +
		`{"Sid":"KeepA","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::a/*"},` +
		`{"Sid":"LoseB","Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*"}]}`
	run := l.scanAndProject(a)

	row := s3aCloudPolicies(l, a.conn, run.Generation)["Mixed"]
	if row.DocumentError != "parse: 1 statement(s) unusable" || !row.HasDocument {
		t.Errorf("Mixed row = %+v, want document stored and document_error 'parse: 1 statement(s) unusable'", row)
	}
	if pd := s3aCoverage(run)[models.SurfacePolicyDocuments]; pd.State != models.CloudCoveragePartial ||
		!strings.Contains(pd.Error, "Mixed v3 (parse: 1 statement(s) unusable)") {
		t.Errorf("policy_documents = %+v, want partial naming Mixed and the skipped statement", pd)
	}
	sup := s3aStatementSupport(l, a.conn)
	for _, k := range []string{"Mixed/KeepA", "Mixed/LoseB"} {
		if sup[k] != models.IGALifecycleActive+":"+models.RelStale {
			t.Errorf("statement %s = %q, want active:stale -- neither may be confirmed from an unreadable document, nor end", k, sup[k])
		}
	}
	for _, g := range s3aGrantsByHolder(l) {
		if g.State != models.RelStale {
			t.Errorf("grant %s = %s, want stale (never ended)", g.Policy, g.State)
		}
	}
	// The policy's observation counts the skipped statement (§1.4: "counted
	// per document").
	facts := s3aFacts(l, `SELECT o.sanitized_facts FROM cloud_observation o JOIN cloud_policy p ON p.id = o.policy_id
	           WHERE o.workspace_id = ? AND p.name = 'Mixed' AND o.last_confirmed_run_id = ?`, l.ws, run.ID)
	if len(facts) != 1 || facts[0]["statements_skipped"] != float64(1) {
		t.Errorf("Mixed's observation this run = %v, want one, counting 1 skipped statement", facts)
	}
}

// D-48: one call per filter, so each surface has its OWN state. A failed Group
// listing makes iam_groups denied, naming the call and the filter, while roles,
// users and policies stay reached; then a failed LocalManagedPolicy listing
// makes iam_policies denied and the customer-managed documents unreadable,
// naming that listing. Nothing ends in either.
func TestP2S3aPerFilterSurfaceStates(t *testing.T) {
	l := newP2Lab(t, "p2-s3a-per-filter", true)
	a := l.account(accountA)
	a.role("SoloRole", "AROASOLOROLESOLOROLE")
	solo := a.managed("SoloRead", s3aDoc("Solo", "s3:GetObject", "arn:aws:s3:::solo/*"))
	a.attach("SoloRole", solo)
	s3aGroup(a, "crew", "AGPACREWCREWCREWCREW")
	s3aGroupAttach(t, a, "crew", a.managed("CrewRead", s3aDoc("Crew", "s3:GetObject", "arn:aws:s3:::crew/*")))
	s3aUser(a, "kim", "AIDAKIMKIMKIMKIMKIM1")
	s3aJoin(a, "kim", "crew")
	l.scanAndProject(a)

	a.iam.fail["GetAccountAuthorizationDetails:Group"] = denied("iam:GetAccountAuthorizationDetails")
	run := l.scanAndProject(a)
	cov := s3aCoverage(run)
	if g := cov[models.SurfaceIAMGroups]; g.State != models.CloudCoverageDenied ||
		!strings.Contains(g.Error, "AccessDenied") ||
		!strings.Contains(g.Error, "iam:GetAccountAuthorizationDetails (Groups)") {
		t.Errorf("iam_groups = %+v, want denied naming AccessDenied and iam:GetAccountAuthorizationDetails (Groups)", g)
	}
	for _, surf := range []string{models.SurfaceIAMRoles, models.SurfaceIAMUsers, models.SurfaceIAMPolicies} {
		if s := cov[surf]; s.State != models.CloudCoverageReached {
			t.Errorf("%s = %+v, want reached: another filter's failure is not this listing's", surf, s)
		}
	}
	// The group's collected attachments are not reconciled away by a run that
	// could not list groups.
	if n := l.count(`SELECT count(*) FROM cloud_policy_attachment x JOIN cloud_identity g ON g.id = x.principal_identity_id
	                  WHERE x.workspace_id = ? AND g.name = 'crew'`, l.ws); n != 1 {
		t.Errorf("crew's attachments = %d, want its 1 kept: absence is only inferred from reached", n)
	}
	var memberState string
	l.db.Raw(`SELECT state FROM iga_relationship WHERE workspace_id = ? AND relationship_type = ?`,
		l.ws, models.RelTypeMemberOf).Scan(&memberState)
	if memberState != models.RelStale {
		t.Errorf("member_of = %q, want stale: groups could not be read", memberState)
	}
	for _, g := range s3aGrantsByHolder(l) {
		want := models.RelCurrent
		if g.Holder == "crew" {
			want = models.RelStale
		}
		if g.State != want {
			t.Errorf("grant %s on %s = %s, want %s", g.Policy, g.Holder, g.State, want)
		}
	}

	delete(a.iam.fail, "GetAccountAuthorizationDetails:Group")
	a.iam.fail["GetAccountAuthorizationDetails:LocalManagedPolicy"] = throttled("iam:GetAccountAuthorizationDetails")
	run = l.scanAndProject(a)
	cov = s3aCoverage(run)
	if p := cov[models.SurfaceIAMPolicies]; p.State != models.CloudCoverageThrottled ||
		!strings.Contains(p.Error, "iam:GetAccountAuthorizationDetails (LocalManagedPolicy)") {
		t.Errorf("iam_policies = %+v, want throttled naming the LocalManagedPolicy listing", p)
	}
	for _, surf := range []string{models.SurfaceIAMRoles, models.SurfaceIAMUsers, models.SurfaceIAMGroups} {
		if s := cov[surf]; s.State != models.CloudCoverageReached {
			t.Errorf("%s = %+v, want reached", surf, s)
		}
	}
	row := s3aCloudPolicies(l, a.conn, run.Generation)["SoloRead"]
	if row.HasDocument || !strings.Contains(row.DocumentError, "(LocalManagedPolicy)") || row.PolicyID != "" {
		t.Errorf("SoloRead row = %+v, want unreadable, naming the failed listing, and no guessed PolicyId", row)
	}
	if n := l.count(`SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND state = 'ended'`, l.ws); n != 0 {
		t.Errorf("%d grants ended while a listing failed", n)
	}
	if n := l.count(`SELECT count(*) FROM iga_policy_assignment WHERE workspace_id = ? AND state = 'ended'`, l.ws); n != 0 {
		t.Errorf("%d assignments ended while a listing failed", n)
	}
}

// Pagination runs to completion for EVERY filter: roles, users, groups and
// customer-managed policies over several pages each, memberships resolved
// across pages, and the policy listing's pages all written.
func TestP2S3aPaginationAcrossPages(t *testing.T) {
	l := newP2Lab(t, "p2-s3a-pages", true)
	a := l.account(accountA)
	a.iam.pageSize = 2
	for i := 0; i < 5; i++ {
		role := fmt.Sprintf("PageRole%d", i)
		a.role(role, fmt.Sprintf("AROAPAGEROLE%08d", i))
		a.attach(role, a.managed(fmt.Sprintf("PagePolicy%d", i),
			s3aDoc("", "s3:GetObject", fmt.Sprintf("arn:aws:s3:::page-%d/*", i))))
		s3aUser(a, fmt.Sprintf("pageuser%d", i), fmt.Sprintf("AIDAPAGEUSER%08d", i))
	}
	a.managed("NeverAttached", s3aDoc("Loose", "s3:ListBucket", "arn:aws:s3:::loose"))
	for i := 0; i < 3; i++ {
		s3aGroup(a, fmt.Sprintf("pagegroup%d", i), fmt.Sprintf("AGPAPAGEGROUP%07d", i))
	}
	for i := 0; i < 5; i++ {
		s3aJoin(a, fmt.Sprintf("pageuser%d", i), fmt.Sprintf("pagegroup%d", i%3))
	}
	run := l.scanAndProject(a)

	cov := s3aCoverage(run)
	for surf, want := range map[string]int{models.SurfaceIAMRoles: 5, models.SurfaceIAMUsers: 5, models.SurfaceIAMGroups: 3} {
		if s := cov[surf]; s.State != models.CloudCoverageReached || s.Count != want {
			t.Errorf("%s = %+v, want reached with %d", surf, s, want)
		}
	}
	for filter, pages := range map[string]int{"Role": 3, "User": 3, "Group": 2, "LocalManagedPolicy": 3} {
		if got := a.iam.calls["GetAccountAuthorizationDetails:"+filter]; got != pages {
			t.Errorf("%s listing calls = %d, want %d pages at size 2", filter, got, pages)
		}
	}
	if n := l.count(`SELECT count(*) FROM cloud_identity WHERE workspace_id = ? AND last_seen_generation = ?`,
		l.ws, run.Generation); n != 13 {
		t.Errorf("identities = %d, want 13 across every page", n)
	}
	if n := l.count(`SELECT count(*) FROM cloud_group_membership WHERE workspace_id = ? AND last_seen_generation = ?`,
		l.ws, run.Generation); n != 5 {
		t.Errorf("memberships = %d, want 5 (users and groups on different pages)", n)
	}
	if pols := s3aCloudPolicies(l, a.conn, run.Generation); len(pols) != 6 {
		t.Errorf("cloud_policy rows = %d, want the 6 customer-managed policies on every page", len(pols))
	}
	if n := l.count(`SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND state = 'current'`, l.ws); n != 5 {
		t.Errorf("current grants = %d, want 5", n)
	}
}

// D-48: attrs merge, never blank -- for the fields the listing does NOT
// return. A role's tags and boundary are in the listing, so their removal is
// observed; its description and max session duration are not, so what an
// earlier GetRole-based read stored is kept.
func TestP2S3aRescanReplacesListedAttrsKeepsUnlisted(t *testing.T) {
	l := newP2Lab(t, "p2-s3a-attrs", true)
	a := l.account(accountA)
	roleARN := a.role("TaggedRole", "AROATAGGEDROLETAGGED")
	bound := a.managed("RoleBoundary", s3aDoc("Cap", "s3:*", "*"))
	s3aEditRole(t, a, "TaggedRole", func(r *iamtypes.Role) {
		r.Tags = []iamtypes.Tag{{Key: aws.String("owner"), Value: aws.String("platform")}}
		r.PermissionsBoundary = s3aBoundary(bound)
	})
	userARN := s3aUser(a, "tagged-user", "AIDATAGGEDUSERTAGGED")
	s3aEditUser(t, a, "tagged-user", func(u *iamtypes.User) {
		u.Tags = []iamtypes.Tag{{Key: aws.String("cost"), Value: aws.String("ops")}}
		u.PermissionsBoundary = s3aBoundary(bound)
	})
	l.scanAndProject(a)

	// The role row as an earlier, GetRole-based read left it: description
	// and max session duration are in attrs.
	if err := l.db.Exec(`UPDATE cloud_identity SET attrs = attrs ||
	        '{"description":"runs the summariser","max_session_duration":7200}'::jsonb
	        WHERE workspace_id = ? AND native_id = ?`, l.ws, roleARN).Error; err != nil {
		t.Fatalf("seed legacy attrs: %v", err)
	}

	// In AWS: tags and boundary removed from both.
	s3aEditRole(t, a, "TaggedRole", func(r *iamtypes.Role) { r.Tags, r.PermissionsBoundary = nil, nil })
	s3aEditUser(t, a, "tagged-user", func(u *iamtypes.User) { u.Tags, u.PermissionsBoundary = nil, nil })
	l.scanAndProject(a)

	var role, user models.CloudIdentity
	l.db.Where("workspace_id = ? AND native_id = ?", l.ws, roleARN).First(&role)
	l.db.Where("workspace_id = ? AND native_id = ?", l.ws, userARN).First(&user)
	ra, ua := role.AWSAttrs(), user.AWSAttrs()
	if len(ra.Tags) != 0 || ra.PermissionsBoundaryARN != "" {
		t.Errorf("role attrs = %+v, want tags and boundary GONE: the listing said so", ra)
	}
	if ra.Description != "runs the summariser" || ra.MaxSessionDuration != 7200 {
		t.Errorf("role attrs = %+v, want description and max session KEPT: the listing does not carry them", ra)
	}
	if ra.UniqueID != "AROATAGGEDROLETAGGED" {
		t.Errorf("role unique id = %q, want it rewritten from the listing", ra.UniqueID)
	}
	if len(ua.Tags) != 0 || ua.PermissionsBoundaryARN != "" {
		t.Errorf("user attrs = %+v, want tags and boundary gone", ua)
	}
	// The boundary assignments end: the listing that carries boundaries
	// reached, and no longer lists them.
	for _, holder := range []string{"TaggedRole", "tagged-user"} {
		if x := s3aFindAssignment(s3aAssignments(l), "RoleBoundary", holder, models.CloudAttachmentBoundary); x == nil ||
			x.State != models.RelEnded {
			t.Errorf("%s's boundary assignment = %+v, want ended", holder, x)
		}
	}
}

// T3.5: one observation per policy version, subject policy_id, citing the call
// the document came from -- and the dedupe path takes it on an unchanged
// rescan: still ONE row per policy, confirmed by the second run. The dedupe
// target names policy_id (035's widened index); a writer whose ON CONFLICT
// did not would fail every policy observation.
func TestP2S3aPolicyObservationPerVersion(t *testing.T) {
	l := newP2Lab(t, "p2-s3a-policy-evidence", true)
	a := l.account(accountA)
	a.role("EvRole", "AROAEVROLEEVROLEEVRO")
	aws1 := s3aAWSManaged(a, "EvAWSManaged", s3aDoc("A", "s3:GetObject", "arn:aws:s3:::ev-a/*"))
	cust := a.managed("EvCustomer", s3aDoc("C", "s3:GetObject", "arn:aws:s3:::ev-c/*"))
	a.attach("EvRole", aws1)
	a.attach("EvRole", cust)
	a.iam.inlineRolePolicies["EvRole"] = map[string]string{"EvInline": s3aDoc("I", "s3:GetObject", "arn:aws:s3:::ev-i/*")}
	l.scanAndProject(a)
	second := l.scanAndProject(a)

	type obsRow struct {
		Name       string
		SourceAPI  string
		Surface    string
		NativeID   string
		Count      int
		Confirmed  int
		LastRun    uuid.UUID
		PolicyNat  string
		HasSubject bool
	}
	var rows []obsRow
	l.db.Raw(`SELECT p.name, o.source_api, o.surface, o.subject_native_id AS native_id,
	                 count(*) OVER (PARTITION BY o.policy_id) AS count,
	                 o.confirmation_count AS confirmed, o.last_confirmed_run_id AS last_run,
	                 p.native_id AS policy_nat, o.policy_id IS NOT NULL AS has_subject
	            FROM cloud_observation o JOIN cloud_policy p ON p.id = o.policy_id
	           WHERE o.workspace_id = ?`, l.ws).Scan(&rows)
	want := map[string]string{
		"EvAWSManaged": "iam:GetPolicyVersion",
		"EvCustomer":   "iam:GetAccountAuthorizationDetails",
		"EvInline":     "iam:GetAccountAuthorizationDetails",
	}
	got := map[string]obsRow{}
	for _, r := range rows {
		got[r.Name] = r
	}
	if len(rows) != len(want) {
		t.Fatalf("policy observations = %+v, want exactly one per policy", rows)
	}
	for name, api := range want {
		r, ok := got[name]
		switch {
		case !ok:
			t.Errorf("%s has no observation", name)
		case r.SourceAPI != api || r.Surface != models.SurfaceIAMPolicies || r.NativeID != r.PolicyNat:
			t.Errorf("%s observation = %+v, want source_api %s, surface iam_policies, subject_native_id its native id", name, r, api)
		case r.Count != 1 || r.Confirmed != 2 || r.LastRun != second.ID:
			t.Errorf("%s observation = %+v, want ONE row confirmed twice, last by run %s", name, r, second.ID)
		}
	}
	// And every principal's observation cites the listing it came from.
	var apis []string
	l.db.Raw(`SELECT DISTINCT o.source_api FROM cloud_observation o JOIN cloud_identity i ON i.id = o.identity_id
	           WHERE o.workspace_id = ? AND o.surface IN ('iam_roles','iam_users','iam_groups')`, l.ws).Scan(&apis)
	if len(apis) != 1 || apis[0] != "iam:GetAccountAuthorizationDetails" {
		t.Errorf("identity observation source_api = %v, want only iam:GetAccountAuthorizationDetails", apis)
	}
}

// T3.1/T3.3: the role's trust document is stored verbatim with its hash, and
// judged by the trust parser's readability check. An unparseable one is
// NULL in the jsonb column, carries trust_parse_error, is named under
// policy_documents, and is travelled by the role's observation; fixing it in
// AWS clears the error on the next scan.
func TestP2S3aTrustDocumentStoredAndJudged(t *testing.T) {
	l := newP2Lab(t, "p2-s3a-trust", true)
	a := l.account(accountA)
	roleARN := a.role("TrustRole", "AROATRUSTROLETRUSTRO")
	read := func() (doc []byte, hash, perr string) {
		var row struct {
			TrustDocument     []byte
			TrustDocumentHash string
			TrustParseError   string
		}
		l.db.Raw(`SELECT trust_document, trust_document_hash, trust_parse_error FROM cloud_identity
		           WHERE workspace_id = ? AND native_id = ?`, l.ws, roleARN).Scan(&row)
		return row.TrustDocument, row.TrustDocumentHash, row.TrustParseError
	}
	sha := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

	l.scanAndProject(a)
	doc, hash, perr := read()
	if len(doc) == 0 || !strings.Contains(string(doc), "lambda.amazonaws.com") || hash != sha(lambdaTrust) || perr != "" {
		t.Fatalf("readable trust = doc %q hash %q error %q, want the document, sha256 of its text, no error", doc, hash, perr)
	}

	const broken = `{"Version":"2012-10-17","Statement":[{"Effect":`
	s3aEditRole(t, a, "TrustRole", func(r *iamtypes.Role) { r.AssumeRolePolicyDocument = aws.String(url.QueryEscape(broken)) })
	run := l.scanAndProject(a)
	doc, hash, perr = read()
	if len(doc) != 0 || hash != sha(broken) || !strings.HasPrefix(perr, "parse: ") {
		t.Errorf("broken trust = doc %q hash %q error %q, want NULL document, the text's hash, a parse error", doc, hash, perr)
	}
	if pd := s3aCoverage(run)[models.SurfacePolicyDocuments]; pd.State != models.CloudCoveragePartial ||
		!strings.Contains(pd.Error, "trust policy of TrustRole (parse: ") {
		t.Errorf("policy_documents = %+v, want partial naming TrustRole's trust policy", pd)
	}
	roleFacts := func() []map[string]any {
		return s3aFacts(l, `SELECT o.sanitized_facts FROM cloud_observation o JOIN cloud_identity i ON i.id = o.identity_id
		           WHERE o.workspace_id = ? AND i.native_id = ? AND o.surface = 'iam_roles'
		             AND o.last_confirmed_run_id = ?`, l.ws, roleARN, run.ID)
	}
	facts := roleFacts()
	if len(facts) != 1 || facts[0]["trust_document"] != broken ||
		!strings.HasPrefix(fmt.Sprint(facts[0]["trust_parse_error"]), "parse: ") {
		t.Errorf("role observation = %v, want one carrying the unparseable trust text and its error", facts)
	}

	s3aEditRole(t, a, "TrustRole", func(r *iamtypes.Role) { r.AssumeRolePolicyDocument = aws.String(url.QueryEscape(lambdaTrust)) })
	run = l.scanAndProject(a)
	if doc, _, perr = read(); len(doc) == 0 || perr != "" {
		t.Errorf("fixed trust = doc %q error %q, want the document back and the error cleared", doc, perr)
	}
	if _, ok := s3aCoverage(run)[models.SurfacePolicyDocuments]; ok {
		t.Errorf("policy_documents still reported after the trust document was fixed: %+v", s3aCoverage(run)[models.SurfacePolicyDocuments])
	}
	facts = roleFacts()
	if len(facts) != 1 || !strings.Contains(fmt.Sprint(facts[0]["trust_document"]), "lambda.amazonaws.com") ||
		facts[0]["trust_parse_error"] != "" {
		t.Errorf("role observation = %v, want one carrying the trust document (§4.8)", facts)
	}
}

// A customer-managed policy is read from the LocalManagedPolicy listing,
// ATTACHED OR NOT: never with GetPolicy/GetPolicyVersion. Unattached, it is
// still a policy in the account (§2.15) -- a cloud_policy row with no holder
// and no attachment, a graph policy with its statements. Detached from its
// last holder it KEEPS its row and statements; only the assignment ends.
func TestP2S3aCustomerPoliciesFromTheListing(t *testing.T) {
	l := newP2Lab(t, "p2-s3a-local-policies", true)
	a := l.account(accountA)
	a.role("HolderRole", "AROAHOLDERROLEHOLDER")
	loose := a.managed("Loose", s3aDoc("LooseRead", "s3:GetObject", "arn:aws:s3:::loose/*"))
	held := a.managed("Held", s3aDoc("HeldRead", "s3:GetObject", "arn:aws:s3:::held/*"))
	a.attach("HolderRole", held)
	run := l.scanAndProject(a)

	pols := s3aCloudPolicies(l, a.conn, run.Generation)
	if p, ok := pols["Loose"]; !ok || p.Holder != nil || !p.HasDocument || p.PolicyID == "" || p.VersionID != "v3" {
		t.Fatalf("unattached Loose = %+v (present %v), want a holderless row with its default-version document and PolicyId", p, ok)
	}
	for _, arn := range []string{loose, held} {
		if n := a.iam.calls["GetPolicy:"+arn] + a.iam.calls["GetPolicyVersion:"+arn]; n != 0 {
			t.Errorf("%s fetched %d times with GetPolicy/GetPolicyVersion; it is in the listing", arn, n)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_entitlements e JOIN iga_policy p ON p.id = e.policy_id
	                  WHERE e.workspace_id = ? AND e.sid = 'SupersededVersion'`, l.ws); n != 0 {
		t.Errorf("%d statements from a NON-default version were projected (§2.6: only the default is read)", n)
	}
	sup := s3aStatementSupport(l, a.conn)
	if sup["Loose/LooseRead"] != models.IGALifecycleActive+":"+models.RelCurrent {
		t.Errorf("Loose's statement = %q, want active:current", sup["Loose/LooseRead"])
	}

	a.detach("HolderRole", held)
	run = l.scanAndProject(a)
	if _, ok := s3aCloudPolicies(l, a.conn, run.Generation)["Held"]; !ok {
		t.Error("Held lost its cloud_policy row on being detached: it is still a policy in the account")
	}
	if x := s3aFindAssignment(s3aAssignments(l), "Held", "HolderRole", models.CloudAttachmentAttached); x == nil ||
		x.State != models.RelEnded || x.EndedReason != models.EndedNotSeen {
		t.Errorf("Held's assignment = %+v, want ended not_seen", x)
	}
	if s := s3aStatementSupport(l, a.conn)["Held/HeldRead"]; s != models.IGALifecycleActive+":"+models.RelCurrent {
		t.Errorf("Held's statement after detach = %q, want active:current (§2.15)", s)
	}
}

// A customer-managed policy a principal attaches but the (completed)
// LocalManagedPolicy listing did not return -- two calls are not a
// transaction -- is recorded UNREADABLE with the reason and its attachment
// kept, never guessed at and never fetched another way.
func TestP2S3aAttachedPolicyAbsentFromListing(t *testing.T) {
	l := newP2Lab(t, "p2-s3a-absent", true)
	a := l.account(accountA)
	a.role("GhostRole", "AROAGHOSTROLEGHOSTRO")
	ghost := a.policyARN("Ghost") // attached, never defined
	a.attach("GhostRole", ghost)
	run := l.scanAndProject(a)

	row := s3aCloudPolicies(l, a.conn, run.Generation)["Ghost"]
	if row.HasDocument || !strings.Contains(row.DocumentError,
		"absent from the iam:GetAccountAuthorizationDetails (LocalManagedPolicy) listing") {
		t.Errorf("Ghost = %+v, want unreadable, saying it was absent from the listing", row)
	}
	if n := a.iam.calls["GetPolicy:"+ghost]; n != 0 {
		t.Errorf("GetPolicy called %d times for a customer-managed policy", n)
	}
	if n := l.count(`SELECT count(*) FROM cloud_policy_attachment x JOIN cloud_policy p ON p.id = x.policy_row_id
	                  WHERE x.workspace_id = ? AND p.name = 'Ghost' AND x.last_seen_generation = ?`,
		l.ws, run.Generation); n != 1 {
		t.Errorf("Ghost attachments = %d, want 1: the role's own entry lists it", n)
	}
	cov := s3aCoverage(run)
	if cov[models.SurfaceIAMPolicies].State != models.CloudCoverageReached ||
		!strings.Contains(cov[models.SurfacePolicyDocuments].Error, "Ghost") {
		t.Errorf("coverage = iam_policies %+v, policy_documents %+v; want reached, and Ghost named",
			cov[models.SurfaceIAMPolicies], cov[models.SurfacePolicyDocuments])
	}
}
