package igagovschema_test

// T3.03b (§3.9 "Retention") against real Postgres, over the probe world's
// plans, approvals and deployments: PruneEvidence deletes the coverage and
// observations of scans older than the newest keepRevs publications, keeps
// every scan a current, approved or deployed plan names and every scan the
// retained publications name, never touches a live run, and then deletes
// only the documents no remaining observation references.

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

func TestP3RPCRetentionPrunesOnlyUnprotectedScans(t *testing.T) {
	_, g := testDB(t)
	tx := g.Begin()
	defer tx.Rollback()
	sqlTx, ok := tx.Statement.ConnPool.(*sql.Tx)
	if !ok {
		t.Fatal("no sql.Tx under the gorm transaction")
	}
	w := probeWorld(t, sqlTx)
	w.id("oFree", "oCurrent", "oApproved", "oDeployed", "oSuperseded", "oManifest", "oLive", "rNew",
		"tB2", "plCur", "plApp", "plDep", "plSup", "dDep")
	w.doc("dShared", `{"Statement":[{"Action":"sqs:SendMessage","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/RefundTaskRole"},"Resource":"*"}],"Version":"2012-10-17"}`)
	w.doc("dOnlyFree", `{"Statement":[{"Action":"sns:Publish","Effect":"Allow","Principal":"*","Resource":"*"}],"Version":"2012-10-17"}`)

	s := &step{t: t, x: sqlTx, w: w}
	old := "now() - interval '10 days'"
	for _, q := range []string{
		// Seven scans older than every publication.
		`INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status, requested_at, published_at) VALUES
		   ({oFree}, {ws1}, {conn}, 11, 'published', ` + old + `, ` + old + `),
		   ({oCurrent}, {ws1}, {conn}, 12, 'published', ` + old + `, ` + old + `),
		   ({oApproved}, {ws1}, {conn}, 13, 'published', ` + old + `, ` + old + `),
		   ({oDeployed}, {ws1}, {conn}, 14, 'failed', ` + old + `, NULL),
		   ({oSuperseded}, {ws1}, {conn}, 15, 'published', ` + old + `, ` + old + `),
		   ({oManifest}, {ws1}, {conn}, 16, 'published', ` + old + `, ` + old + `),
		   ({rNew}, {ws1}, {conn}, 18, 'published', now(), now())`,
		`INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status, requested_at, lease_owner, lease_expires_at)
		 VALUES ({oLive}, {ws1}, {conn}, 17, 'running', ` + old + `, 'worker-x', now() + interval '5 minutes')`,
		// Rev 6 names oManifest for another partition.
		`INSERT INTO iga_publication (workspace_id, rev, published_at, scan_run_id, manifest)
		 VALUES ({ws1}, 6, now(), {rNew}, jsonb_build_object('aws:111111111111', {rNew}::text, 'aws:222222222222', {oManifest}::text))`,
		`INSERT INTO cloud_policy_document (workspace_id, document_hash, canonical, document) VALUES
		   ({ws1}, {dShared}, {dShared.c}, {dShared.c}::jsonb), ({ws1}, {dOnlyFree}, {dOnlyFree.c}, {dOnlyFree.c}::jsonb)`,
		`INSERT INTO cloud_resource_policy_coverage (workspace_id, connector_id, scan_run_id, resource_form, region, state, enumerated, read_ok)
		 SELECT {ws1}, {conn}, r, 'sqs_queue', 'us-east-1', 'complete', 1, 1
		   FROM unnest(ARRAY[{oFree}, {oCurrent}, {oApproved}, {oDeployed}, {oSuperseded}, {oManifest}, {oLive}]) r`,
		`INSERT INTO cloud_resource_policy_observation (workspace_id, scan_run_id, resource_form, region, resource_arn, policy_present, document_hash, read_at)
		 SELECT {ws1}, r, 'sqs_queue', 'us-east-1', 'arn:aws:sqs:us-east-1:111111111111:refunds', true, {dShared}, now()
		   FROM unnest(ARRAY[{oCurrent}, {oApproved}, {oDeployed}, {oSuperseded}, {oManifest}, {oLive}]) r`,
		`INSERT INTO cloud_resource_policy_observation (workspace_id, scan_run_id, resource_form, region, resource_arn, policy_present, document_hash, read_at)
		 VALUES ({ws1}, {oFree}, 'sqs_queue', 'us-east-1', 'arn:aws:sqs:us-east-1:111111111111:refunds', true, {dOnlyFree}, now())`,
		// A current plan (not superseded) on a new target.
		`INSERT INTO iga_gov_target (id, workspace_id, version_id, policy_id, control_id, is_canary) VALUES ({tB2}, {ws1}, {p1v2}, {p1}, {ctlB}, false)`,
		plan("plCur", "p1v2", "tB2", "ctlB", "resource_policy_scan_run_id", "{oCurrent}"),
		// A superseded plan whose hash the live approval apA2 binds.
		plan("plApp", "p1v2", "tA2", "ctlA", "resource_policy_scan_run_id", "{oApproved}", "plan_hash", "'plh-plA2'",
			"superseded_at", "now()"),
		// A superseded plan a deployment references.
		plan("plDep", "p1v1", "tB1", "ctlB", "resource_policy_scan_run_id", "{oDeployed}", "superseded_at", "now()"),
		deployment("dDep", "p1v1", "plDep", "ctlB", "apA1", "state", "'blocked'"),
		// A superseded plan nobody approved or deployed.
		plan("plSup", "p1v1", "tA1", "ctlA", "resource_policy_scan_run_id", "{oSuperseded}", "superseded_at", "now()"),
	} {
		s.exec(q)
		if s.err != nil {
			t.Fatalf("fixture: %s\n%s", describe(s.err), w.sql(q))
		}
	}
	id := func(name string) uuid.UUID {
		v := w.vals[name]
		return uuid.MustParse(v[1 : len(v)-len("'::uuid")])
	}
	ws := id("ws1")
	repo := repositories.NewCloudResourcePolicyRepository(tx)

	// Fewer publications than the window: no scan is pruned. The probe
	// world's pdoc2 is referenced by no observation at all, so it goes (the
	// document sweep is not windowed: an unreferenced document is evidence of
	// nothing).
	if res, err := repo.PruneEvidence(ws, 100); err != nil || len(res.Scans) != 0 || res.Documents != 1 {
		t.Fatalf("prune with a window wider than history = %+v, %v", res, err)
	}

	res, err := repo.PruneEvidence(ws, 2) // retained: revs 5 and 6
	if err != nil {
		t.Fatal(err)
	}
	pruned := map[uuid.UUID]bool{}
	for _, sc := range res.Scans {
		pruned[sc] = true
	}
	if len(pruned) != 2 || !pruned[id("oFree")] || !pruned[id("oSuperseded")] {
		t.Fatalf("pruned %v, want exactly oFree and oSuperseded", res.Scans)
	}
	for _, kept := range []string{"oCurrent", "oApproved", "oDeployed", "oManifest", "oLive", "r1"} {
		var n int64
		tx.Model(&models.CloudResourcePolicyCoverage{}).Where("workspace_id = ? AND scan_run_id = ?", ws, id(kept)).Count(&n)
		if n == 0 {
			t.Errorf("%s's coverage was pruned; it must be kept", kept)
		}
	}
	var obs int64
	tx.Model(&models.CloudResourcePolicyObservation{}).Where("workspace_id = ? AND scan_run_id IN ?", ws,
		[]uuid.UUID{id("oFree"), id("oSuperseded")}).Count(&obs)
	if obs != 0 {
		t.Errorf("pruned scans kept %d observations", obs)
	}
	// The document only oFree referenced is gone; the shared one stays.
	docs, err := repo.Documents(ws, []string{hashOf(`{"Statement":[{"Action":"sns:Publish","Effect":"Allow","Principal":"*","Resource":"*"}],"Version":"2012-10-17"}`),
		hashOf(`{"Statement":[{"Action":"sqs:SendMessage","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/RefundTaskRole"},"Resource":"*"}],"Version":"2012-10-17"}`)})
	if err != nil || len(docs) != 1 || res.Documents != 1 {
		t.Fatalf("documents after prune = %d (deleted %d), err %v; want only the shared one kept", len(docs), res.Documents, err)
	}
	// The probe world's own s3_bucket observation (r1, named by rev 1 ...) is
	// outside the window but r1 is not older than it, so it stays, and so
	// does its document.

	// The service entry point reads evidence_retention_revs (default 30).
	if res, err := services.PruneResourcePolicyEvidence(tx, ws); err != nil || len(res.Scans) != 0 {
		t.Fatalf("PruneResourcePolicyEvidence with the default window = %+v, %v", res, err)
	}
}
