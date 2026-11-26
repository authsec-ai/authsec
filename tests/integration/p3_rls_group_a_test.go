package integration

// AS-108 (group A: findings, evaluation, reads, evidence, metrics): the
// governance reads and the prune_evidence job run in transactions under
// row-level security for ONE workspace. These tests show that the database,
// not only each statement's own workspace_id filter, keeps workspace B's
// transaction away from A's rows: a statement that names A's workspace,
// run in B's transaction, sees nothing; a handle bound to A is refused for
// B; and A's daily prune leaves B's evidence alone.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// inWS runs fn in a read-only transaction under row-level security for ws.
func inWS(t *testing.T, db *gorm.DB, ws uuid.UUID, fn func(tx *gorm.DB) error) {
	t.Helper()
	if err := tenancy.InWorkspaceRead(context.Background(), db, ws, fn); err != nil {
		t.Fatalf("workspace %s transaction: %v", ws, err)
	}
}

// Resource-policy coverage, observations and documents: the repository
// reads B's workspace only; the evaluation's typed reads (CloudEvidenceReads)
// asked for A's rows inside B's transaction get none; a repository built on
// B's transaction refuses A's workspace.
func TestP3RLSResourcePolicyReadsAreWorkspaceScoped(t *testing.T) {
	a := newRPEnv(t, "p3-rls-rp-a")
	b := newRPEnv(t, "p3-rls-rp-b")
	runA := a.run(t)
	a.collect(t, newRPWorld(), runA)
	runB := b.run(t)

	repo := repositories.NewCloudResourcePolicyRepository(a.db)
	covA, err := repo.CoverageForScan(a.ws, runA)
	if err != nil || len(covA) == 0 {
		t.Fatalf("A's own coverage: %d rows, %v", len(covA), err)
	}
	obsA, err := repo.ObservationsForScan(a.ws, runA)
	if err != nil || len(obsA) == 0 {
		t.Fatalf("A's own observations: %d rows, %v", len(obsA), err)
	}
	var hashes []string
	for _, o := range obsA {
		if o.DocumentHash != nil {
			hashes = append(hashes, *o.DocumentHash)
		}
	}
	if docs, err := repo.Documents(a.ws, hashes); err != nil || len(docs) == 0 {
		t.Fatalf("A's own documents: %d, %v", len(docs), err)
	}
	// B asking for A's scan by id: nothing.
	if rows, err := repo.CoverageForScan(b.ws, runA); err != nil || len(rows) != 0 {
		t.Fatalf("B reads A's coverage: %d rows, %v", len(rows), err)
	}
	if rows, err := repo.ObservationsForScan(b.ws, runA); err != nil || len(rows) != 0 {
		t.Fatalf("B reads A's observations: %d rows, %v", len(rows), err)
	}
	if docs, err := repo.Documents(b.ws, hashes); err != nil || len(docs) != 0 {
		t.Fatalf("B reads A's documents: %d, %v", len(docs), err)
	}

	// The typed evaluation reads in B's transaction, SQL naming A: RLS
	// returns nothing; the same reads in A's transaction return A's rows.
	reads := repositories.CloudEvidenceReads{}
	count := func(ws uuid.UUID) (cov, obs, runs int) {
		inWS(t, a.db, ws, func(tx *gorm.DB) error {
			c, err := reads.ResourcePolicyCoverage(tx, a.ws, []uuid.UUID{runA})
			if err != nil {
				return err
			}
			o, err := reads.ResourcePolicyObservations(tx, a.ws, []uuid.UUID{runA})
			if err != nil {
				return err
			}
			r, err := reads.Runs(tx, a.ws, []uuid.UUID{runA, runB})
			cov, obs, runs = len(c), len(o), len(r)
			return err
		})
		return
	}
	if cov, obs, runs := count(a.ws); cov != len(covA) || obs != len(obsA) || runs != 1 {
		t.Fatalf("A's transaction: %d coverage, %d observations, %d runs; want %d, %d, 1", cov, obs, runs, len(covA), len(obsA))
	}
	if cov, obs, runs := count(b.ws); cov != 0 || obs != 0 || runs != 0 {
		t.Fatalf("B's transaction reads A's evidence: %d coverage, %d observations, %d runs", cov, obs, runs)
	}

	// A repository built on B's transaction is refused A's workspace.
	err = tenancy.InWorkspaceRead(context.Background(), a.db, b.ws, func(tx *gorm.DB) error {
		_, err := repositories.NewCloudResourcePolicyRepository(tx).CoverageForScan(a.ws, runA)
		return err
	})
	if err == nil {
		t.Fatal("a repository on B's transaction read A's workspace")
	}
}

// ActivityEvidence, findings and the CloudTrail attribution read: another
// workspace's identity or finding is 404 through the reader, the frozen
// evidence and the inventory are invisible to B's transaction even by A's
// workspace id, and a reader bound to A's context is refused B's workspace.
func TestP3RLSActivityEvidenceAndAttributionReads(t *testing.T) {
	l := newP3eLab(t, "p3-rls-evidence")
	acct := l.account(accountA)
	arn := p3eOldRole(acct, "RlsRole", "AROARLSROLE0001", 200*24*time.Hour, "RlsWork", p3eSQSS3)
	acct.lambda("us-east-1", "rls", arn)
	l.activity(acct).set(arn, map[string]*time.Time{"sqs": nil})
	l.cycle(acct, nil)
	ident := bdbIdentity(t, l.p2Lab, "RlsRole")
	rev := l.latestRev()
	other := newWorkspace(t, l.db, "p3-rls-evidence-other")

	rd := services.NewGovReader(l.db, []byte("p3-rls-cursor-key"))
	own, err := rd.ActivityEvidence(l.ws, ident, rev)
	if err != nil || len(own) == 0 {
		t.Fatalf("own activity evidence: %d rows, %v", len(own), err)
	}
	var ge *services.GovError
	if _, err := rd.ActivityEvidence(other, ident, rev); !errors.As(err, &ge) || ge.Code != "not_found" {
		t.Fatalf("other workspace's activity evidence: %v, want 404 not_found", err)
	}
	var finding uuid.UUID
	if err := l.db.Raw(`SELECT id FROM iga_gov_finding WHERE workspace_id = ? LIMIT 1`, l.ws).Row().Scan(&finding); err != nil {
		t.Fatal(err)
	}
	if _, err := rd.Finding(other, finding, rev); !errors.As(err, &ge) || ge.Code != "not_found" {
		t.Fatalf("other workspace's finding: %v, want 404 not_found", err)
	}

	// B's transaction, statements naming A's workspace: nothing.
	evidenceSeen := func(ws uuid.UUID) (evidence int, evaluated bool, candidates int) {
		inWS(t, l.db, ws, func(tx *gorm.DB) error {
			var rows []models.IGAGovActivityEvidence
			if err := tx.Where("workspace_id = ? AND identity_account_id = ?", l.ws, ident).Find(&rows).Error; err != nil {
				return err
			}
			lc, err := repositories.NewIGAGovEvaluationRepository().LatestComplete(tx, l.ws)
			if err != nil {
				return err
			}
			// The CloudTrail attribution read (T3.04) by the role's ARN.
			found, err := repositories.NewCloudIdentityRepository(tx).FindForAttribution(l.ws, acct.conn, []string{arn}, nil)
			evidence, evaluated, candidates = len(rows), lc != nil, len(found)
			return err
		})
		return
	}
	if n, ok, c := evidenceSeen(l.ws); n == 0 || !ok || c != 1 {
		t.Fatalf("own transaction: %d evidence rows, evaluated %v, %d attribution candidates", n, ok, c)
	}
	if n, ok, c := evidenceSeen(other); n != 0 || ok || c != 0 {
		t.Fatalf("other workspace's transaction sees A: %d evidence rows, evaluated %v, %d attribution candidates", n, ok, c)
	}

	// A reader whose handle carries A's request context is refused B.
	actx := tenancy.WithContext(context.Background(), tenancy.Context{WorkspaceID: l.ws})
	bound := services.NewGovReader(l.db.WithContext(actx), []byte("k"))
	if _, err := bound.ActivityEvidence(other, ident, rev); err == nil || errors.As(err, &ge) {
		t.Fatalf("a reader bound to A answered for B: %v", err)
	}
	if _, err := bound.ActivityEvidence(l.ws, ident, rev); err != nil {
		t.Fatalf("a reader bound to A, for A: %v", err)
	}
}

// A's prune_evidence job prunes A's evaluation and resource-policy evidence
// and leaves B's -- old scans' coverage, complete evaluations, unreferenced
// documents, all of which A's rules would prune -- untouched.
func TestP3RLSPruneEvidenceJobLeavesOtherWorkspace(t *testing.T) {
	a := newP3aLab(t, "p3-rls-prune-a")
	a.role("PruneRole", "AROARLSPRUNEA01", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	world := newP3covWorld(accountA, "us-east-1")
	for i := 0; i < 6; i++ {
		a.publishCollected(world)
	}
	p3exec(t, a.db, `INSERT INTO iga_gov_settings (workspace_id, evidence_retention_revs) VALUES (?, 5)
	                 ON CONFLICT (workspace_id) DO UPDATE SET evidence_retention_revs = 5`, a.ws)

	// B: six old published scans with coverage, a document nothing
	// references and six complete evaluations, retention 5.
	db := a.db
	wsB := newWorkspace(t, db, "p3-rls-prune-b")
	connB := connectorFor(t, db, wsB)
	t.Cleanup(func() { p3ePurge(t, db, wsB); db.Exec(`DELETE FROM cloud_scan_run WHERE workspace_id = ?`, wsB) })
	var runsB []uuid.UUID
	for i := 1; i <= 6; i++ {
		id := uuid.New()
		runsB = append(runsB, id)
		p3exec(t, db, `INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status, requested_at, published_at)
		               VALUES (?, ?, ?, ?, 'published', now() - interval '10 days', now() - interval '10 days')`, id, wsB, connB, i)
		p3exec(t, db, `INSERT INTO cloud_resource_policy_coverage (workspace_id, connector_id, scan_run_id, resource_form, region, state, enumerated, read_ok)
		               VALUES (?, ?, ?, 'sqs_queue', 'us-east-1', 'complete', 0, 0)`, wsB, connB, id)
		p3exec(t, db, `INSERT INTO iga_publication (workspace_id, rev, published_at, scan_run_id, manifest)
		               VALUES (?, ?, now() - interval '10 days', ?, '{}'::jsonb)`, wsB, i, id)
		p3exec(t, db, `INSERT INTO iga_gov_evaluation (workspace_id, rev, status, attempts, finished_at) VALUES (?, ?, 'complete', 1, now())`, wsB, i)
	}
	doc := `{"Statement":[{"Action":"sns:Publish","Effect":"Allow","Principal":"*","Resource":"*"}],"Version":"2012-10-17"}`
	hash, err := igagov.DocumentHash(doc)
	if err != nil {
		t.Fatal(err)
	}
	p3exec(t, db, `INSERT INTO cloud_policy_document (workspace_id, document_hash, canonical, document) VALUES (?, ?, ?, ?::jsonb)`,
		wsB, hash, doc, doc)
	p3exec(t, db, `INSERT INTO iga_gov_settings (workspace_id, evidence_retention_revs) VALUES (?, 5)
	               ON CONFLICT (workspace_id) DO UPDATE SET evidence_retention_revs = 5`, wsB)

	heldA := func() (revs, scans int64) {
		return a.count(`SELECT count(DISTINCT rev) FROM iga_gov_activity_evidence WHERE workspace_id = ?`, a.ws),
			a.count(`SELECT count(DISTINCT scan_run_id) FROM cloud_resource_policy_coverage WHERE workspace_id = ?`, a.ws)
	}
	heldB := func() (scans, docs, evals, pruned int64) {
		return a.count(`SELECT count(DISTINCT scan_run_id) FROM cloud_resource_policy_coverage WHERE workspace_id = ?`, wsB),
			a.count(`SELECT count(*) FROM cloud_policy_document WHERE workspace_id = ?`, wsB),
			a.count(`SELECT count(*) FROM iga_gov_evaluation WHERE workspace_id = ? AND status = 'complete'`, wsB),
			a.count(`SELECT count(*) FROM iga_gov_evaluation_pruned WHERE workspace_id = ?`, wsB)
	}
	if revs, scans := heldA(); revs != 6 || scans != 6 {
		t.Fatalf("A before: %d revisions, %d scans; want 6 and 6", revs, scans)
	}

	// Only A's job is queued; the worker runs it.
	key := services.PruneEvidenceDedupeKey(a.ws, time.Now())
	p3exec(t, db, `INSERT INTO iga_gov_job (workspace_id, kind, dedupe_key) VALUES (?, ?, ?)`,
		a.ws, repositories.GovJobPruneEvidence, key)
	w := services.NewPolicyJobWorker(db, "p3-rls-prune").WithGate(func() bool { return true })
	services.RegisterPruneEvidenceJob(w)
	for i := 0; i < 20; i++ {
		ok, err := w.RunOnce(context.Background())
		if err != nil {
			t.Fatalf("worker: %v", err)
		}
		if !ok {
			break
		}
	}
	var status string
	db.Raw(`SELECT status FROM iga_gov_job WHERE workspace_id = ? AND kind = ? AND dedupe_key = ?`,
		a.ws, repositories.GovJobPruneEvidence, key).Scan(&status)
	if status != "complete" {
		t.Fatalf("A's prune_evidence job %q, want complete", status)
	}
	if revs, scans := heldA(); revs != 5 || scans != 5 {
		t.Fatalf("A after its prune: %d revisions, %d scans; want 5 and 5", revs, scans)
	}
	if scans, docs, evals, pruned := heldB(); scans != 6 || docs != 1 || evals != 6 || pruned != 0 {
		t.Fatalf("B after A's prune: %d scans with coverage, %d documents, %d evaluations, %d pruned records; want 6, 1, 6, 0",
			scans, docs, evals, pruned)
	}
	for _, id := range runsB {
		if n := a.count(`SELECT count(*) FROM cloud_resource_policy_coverage WHERE workspace_id = ? AND scan_run_id = ?`, wsB, id); n != 1 {
			t.Fatalf("B's scan %s: %d coverage rows, want 1", id, n)
		}
	}
}
