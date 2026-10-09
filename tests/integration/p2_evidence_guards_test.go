package integration

// Safeguards of GET /evidence that the E4 lab's ordinary fixtures cannot tell
// apart from their absence. Where the fakes cannot produce the state -- a
// GitHub row with support, a Deny statement as a grant, a non-supports
// junction link, a revoked connector, a claim whose connector was deleted --
// the row is written directly, and each test says so.

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// D-6: only rows the projector owns are graph rows. A GitHub identity is 404
// even WITH a support row (the provider decides), and an AWS identity no
// support row stands behind is 404 too (support decides) -- each condition
// alone is enough. Both rows are inserted directly: no fake produces them.
func TestP2EvidenceOnlyProjectorRows(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-readable")
	gh, bare := uuid.New(), uuid.New()
	for _, row := range []struct {
		id       uuid.UUID
		provider string
	}{{gh, "github"}, {bare, "aws"}} {
		if err := e.l.db.Exec(`INSERT INTO iga_identity_accounts (id, workspace_id, display_name, account_kind, provider, source_key)
		                        VALUES (?, ?, 'octocat', 'iam_user', ?, ?)`,
			row.id, e.l.ws, row.provider, row.provider+"\x1foctocat-"+row.id.String()).Error; err != nil {
			t.Fatalf("insert identity: %v", err)
		}
	}
	if err := e.l.db.Exec(`INSERT INTO iga_object_support (workspace_id, identity_account_id, connector_id, partition_key, state)
	                        VALUES (?, ?, ?, 'github-partition', 'current')`, e.l.ws, gh, e.a.conn).Error; err != nil {
		t.Fatalf("insert support: %v", err)
	}
	for name, id := range map[string]uuid.UUID{"github row with support": gh, "aws row without support": bare} {
		if code, body := e.api.get("/evidence" + qs("claim", refOf("identity", id))); code != http.StatusNotFound {
			t.Errorf("%s = %d %v, want 404", name, code, body)
		}
	}
}

// §3 rule 7: a grant row whose statement is a Deny is never readable as a
// grant -- 404, not a grant with an Allow sentence. The projector refuses to
// write one (UpsertGrant), so it is inserted directly.
func TestP2EvidenceDenyIsNeverAGrant(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-deny-grant")
	var row struct {
		Holder, Statement, Assignment uuid.UUID
	}
	if err := e.l.db.Raw(`SELECT pa.holder_identity_account_id AS holder, e.id AS statement, pa.id AS assignment
	                        FROM iga_policy_assignment pa
	                        JOIN iga_policy p ON p.id = pa.policy_id
	                        JOIN iga_entitlements e ON e.policy_id = p.id
	                       WHERE pa.workspace_id = ? AND p.display_name = 'GuardRails' AND e.effect = 'deny'`, e.l.ws).
		Row().Scan(&row.Holder, &row.Statement, &row.Assignment); err != nil {
		t.Fatalf("fixture: GuardRails' Deny: %v", err)
	}
	id := uuid.New()
	if err := e.l.db.Exec(`INSERT INTO iga_access_edges (id, workspace_id, subject_kind, subject_id, subject_identity_account_id,
	                              entitlement_id, assignment_id, direction, provider, source_key, calculation_state)
	                        VALUES (?, ?, 'identity_account', ?, ?, ?, ?, 'outbound', 'aws', ?, 'partial')`,
		id, e.l.ws, row.Holder, row.Holder, row.Statement, row.Assignment, "deny-as-grant-"+id.String()).Error; err != nil {
		t.Fatalf("insert deny grant: %v", err)
	}
	if code, body := e.api.get("/evidence" + qs("claim", refOf("grant", id))); code != http.StatusNotFound {
		t.Fatalf("a Deny statement as a grant = %d %v, want 404", code, body)
	}
}

// A junction link that is not 'supports' is never a supporting fact. The
// projector writes only 'supports' today, so the link is inserted directly.
func TestP2EvidenceOnlySupportingLinks(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-relation")
	claim := evidenceGrant(t, e.l, "PlainRole", "PlainRead", "PlainGet")
	var obs uuid.UUID
	if err := e.l.db.Raw(`SELECT id FROM cloud_observation WHERE workspace_id = ? AND source_api = 'iam:GetAccountAuthorizationDetails'
	                        AND surface = ? AND subject_native_id = ?`, e.l.ws, models.SurfaceIAMRoles, e.a.roleARN("SharedToolRole")).
		Row().Scan(&obs); err != nil {
		t.Fatalf("fixture: SharedToolRole's entry: %v", err)
	}
	for _, rel := range []string{"contradicts", "supersedes", "previously_supported"} {
		if err := e.l.db.Exec(`INSERT INTO iga_access_edge_evidence (workspace_id, access_edge_id, observation_id, relation)
		                        VALUES (?, ?, ?, ?)`, e.l.ws, refUUID(t, claim), obs, rel).Error; err != nil {
			t.Fatalf("insert %s link: %v", rel, err)
		}
	}
	for _, f := range digl(evidenceGet(t, e.api, claim), "data", "facts") {
		if digs(f, "fact") == "PlainRole has PlainRead attached" {
			continue
		}
		if digs(f, "fact") != "Statement PlainGet allows s3:GetObject on arn:aws:s3:::plain-bucket/report.csv" {
			t.Errorf("fact %q: a non-supports link (SharedToolRole's entry) was shown as support", digs(f, "fact"))
		}
	}
	if n := len(digl(evidenceGet(t, e.api, claim), "data", "facts")); n != 2 {
		t.Errorf("facts = %d, want PlainRole's entry and the policy version only", n)
	}
}

// D-89: a claim collected by a REVOKED connector is from an account that is no
// longer connected. Nothing in the lab revokes a connector, so the status is
// set directly.
func TestP2EvidenceRevokedConnector(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-revoked")
	claim := evidenceGrant(t, e.l, "PlainRole", "PlainRead", "PlainGet")
	if lim := evidenceLim(evidenceGet(t, e.api, claim), "account_not_connected"); lim != nil {
		t.Fatalf("a live connector's grant carries %v", lim)
	}
	if err := e.l.db.Exec(`UPDATE cloud_connector SET status = ? WHERE id = ?`, models.CloudConnectorRevoked, e.a.conn).Error; err != nil {
		t.Fatalf("revoke: %v", err)
	}
	lim := evidenceLim(evidenceGet(t, e.api, claim), "account_not_connected")
	if lim == nil || !reflect.DeepEqual(evidenceStrings(lim["accounts"]), []string{accountA}) {
		t.Fatalf("revoked connector's grant: account_not_connected = %v, want [%s]", lim, accountA)
	}
	body := evidenceGet(t, e.api, "coverage:"+e.run.ID.String()+":"+models.SurfaceIAMRoles)
	if evidenceLim(body, "account_not_connected") == nil {
		t.Errorf("a revoked connector's coverage claim: limitations %v, want account_not_connected", evidenceCodes(body))
	}
}

// A claim whose partition cannot be named (its connector was deleted: the FK
// SETs NULL) is not known to be complete. Deleting a connector is not a lab
// operation, so the column is cleared directly.
func TestP2EvidenceUnrecordedPartitionIsNotComplete(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-unrecorded")
	claim := evidenceGrant(t, e.l, "PlainRole", "PlainRead", "PlainGet")
	if got := digs(evidenceGet(t, e.api, claim), "data", "status", "collection"); got != "complete" {
		t.Fatalf("fixture: collection = %q, want complete before", got)
	}
	if err := e.l.db.Exec(`UPDATE iga_access_edges SET connector_id = NULL WHERE id = ?`, refUUID(t, claim)).Error; err != nil {
		t.Fatalf("clear connector: %v", err)
	}
	if got := digs(evidenceGet(t, e.api, claim), "data", "status", "collection"); got != "stale" {
		t.Errorf("collection = %q with no nameable partition, want stale (never complete)", got)
	}
}

// D-19: a resource policy counts only when a run that PUBLISHED at or below the
// current revision first recorded it. A run that collected a bucket policy
// but was never projected says nothing the revision holds.
func TestP2EvidenceResourcePolicyOfAnUnpublishedRun(t *testing.T) {
	l := newP2Lab(t, "p2-evidence-unpublished-policy", true)
	a := l.account(accountA)
	a.role("ListRole", "AROALISTROLELISTROL1")
	a.attach("ListRole", a.managed("ListBucket", s3aDoc("List", "s3:ListBucket", "arn:aws:s3:::support-tickets")))
	evidenceCycle(l, a, evidenceFakes{}) // the bucket's policy read is denied: nothing recorded
	claim := evidenceGrant(t, l, "ListRole", "ListBucket", "List")
	if lim := evidenceLim(evidenceGet(t, l.api(), claim), "resource_policy_not_projected"); lim != nil {
		t.Fatalf("no policy was read: %v", lim)
	}

	// Collected, never projected: the policy observation exists, its run has
	// no publication.
	queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner("evidence-unprojected").WithGraphProjection(l.gate).
		WithScannerHook(evidenceHook(a, evidenceFakes{bucketPolicies: map[string]string{
			"support-tickets": evidenceDoc(`{"Effect":"Deny","Principal":"*","Action":"s3:DeleteBucket","Resource":"*"}`)}}))
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("scan: worked=%v err=%v", worked, err)
	}
	if n := l.count(`SELECT count(*) FROM cloud_observation WHERE workspace_id = ? AND scan_run_id = ? AND surface = ?`,
		l.ws, queued.ID, models.SurfaceResourcePolicies); n == 0 {
		t.Fatal("fixture: the unprojected run recorded no bucket policy")
	}
	body := evidenceGet(t, l.api(), claim)
	if lim := evidenceLim(body, "resource_policy_not_projected"); lim != nil {
		t.Errorf("a policy only an unpublished run read counts: %v", lim)
	}

	l.project(fmt.Sprintf("evidence-projector-late-%d", evidenceSeq))
	if lim := evidenceLim(evidenceGet(t, l.api(), claim), "resource_policy_not_projected"); lim == nil {
		t.Errorf("once that run published, the read policy is a limitation: %v", evidenceCodes(evidenceGet(t, l.api(), claim)))
	}
}
