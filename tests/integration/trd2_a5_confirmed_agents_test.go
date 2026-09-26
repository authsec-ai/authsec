package integration

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

func TestTRD2ITA5MigrationIndependentOf041(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "migrations", "master", "042_trd2_agent_instance_link.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sqlText := string(body)
	for _, forbidden := range []string{"iga_runtime_instances", "iga_observed_access", "041_"} {
		if strings.Contains(sqlText, forbidden) {
			t.Fatalf("042 references %s; it must apply with or without 041 and 045", forbidden)
		}
	}
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set")
	}
	db := openFreshDB(t, dsn, "authsec_it_a5fresh")
	applyMaster(t, db, false)
	mig := filepath.Join("..", "..", "migrations", "master", "042_trd2_agent_instance_link.sql")
	applyFile(t, db, mig)
	if n := scalarDB(t, db, `SELECT count(*) FROM information_schema.tables WHERE table_name = 'discovered_agent_workloads'`); n != 1 {
		t.Fatalf("discovered_agent_workloads count = %d", n)
	}
	if constraintValidated(t, db, "iga_agent_instances_workload_authority_chk") {
		t.Fatal("042 validated the authority check inside the deploy transaction")
	}
	applyFile(t, db, mig)
	if n := scalarDB(t, db, `SELECT count(*) FROM pg_constraint WHERE conname = 'iga_agent_instances_workload_authority_chk'`); n != 1 {
		t.Fatalf("authority check count after a second apply = %d", n)
	}
	applyFile(t, db, filepath.Join("..", "..", "scripts", "validate-042-agent-instance-link.sql"))
	if !constraintValidated(t, db, "iga_agent_instances_workload_authority_chk") ||
		!constraintValidated(t, db, "iga_agent_instances_workload_fkey") {
		t.Fatal("validate script left a 042 constraint NOT VALID")
	}
}

func TestTRD2ITA5MigrationProdShapedWeakLinks(t *testing.T) {
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set")
	}
	db := openFreshDB(t, dsn, "authsec_it_a5prod")
	applyMaster(t, db, false)
	ws := uuid.New()
	agent, inst, dagent := uuid.New(), uuid.New(), uuid.New()
	execDB(t, db, `INSERT INTO workspaces (id, name) VALUES ($1, 'a5-prod')`, ws)
	execDB(t, db, `INSERT INTO iga_agents (id, workspace_id, display_name) VALUES ($1, $2, 'legacy')`, agent, ws)
	execDB(t, db, `INSERT INTO iga_agent_instances (id, workspace_id, agent_id) VALUES ($1, $2, $3)`, inst, ws, agent)
	execDB(t, db, `INSERT INTO discovered_agents (id, workspace_id, source, fingerprint, display_name)
		VALUES ($1, $2, 'k8s_webhook', $3, 'legacy')`, dagent, ws, "fp-"+dagent.String())
	execDB(t, db, `INSERT INTO discovered_agent_iga_links
		(workspace_id, discovered_agent_id, iga_agent_id, strength, state, join_key)
		VALUES ($1, $2, $3, 'weak', 'proposed', 'display_name:legacy')`, ws, dagent, agent)
	before := a5LinkDigest(t, db, ws, dagent, inst)

	mig := filepath.Join("..", "..", "migrations", "master", "042_trd2_agent_instance_link.sql")
	applyFile(t, db, mig)
	if got := a5LinkDigest(t, db, ws, dagent, inst); got != before {
		t.Fatalf("weak link changed across 042:\n before %s\n after  %s", before, got)
	}
	applyFile(t, db, mig)
	if got := a5LinkDigest(t, db, ws, dagent, inst); got != before {
		t.Fatalf("second 042 apply changed the weak link:\n before %s\n after  %s", before, got)
	}
	if n := scalarDB(t, db, `SELECT count(*) FROM discovered_agent_workloads WHERE workspace_id = $1`, ws); n != 0 {
		t.Fatalf("042 created %d discovered_agent_workloads rows", n)
	}
	if n := scalarDB(t, db, `SELECT count(*) FROM iga_agent_instances WHERE id = $1 AND workload_id IS NULL`, inst); n != 1 {
		t.Fatal("042 backfilled workload_id on a legacy instance")
	}

	wl := uuid.New()
	execDB(t, db, `INSERT INTO iga_workload (id, workspace_id, runtime_kind, source_key)
		VALUES ($1, $2, 'lambda_function', $3)`, wl, ws, "wl-"+wl.String())
	if _, err := db.Exec(`UPDATE iga_agent_instances
		SET workload_id = $1, workload_link_basis = 'weak', linked_by = $2, owner_user_id = $2, classification_version = 0
		WHERE id = $3`, wl, uuid.New(), inst); err == nil {
		t.Fatal("a weak basis set workload_id")
	}
	if _, err := db.Exec(`INSERT INTO discovered_agent_workloads
		(workspace_id, discovered_agent_id, workload_id, link_strength, link_state)
		VALUES ($1, $2, $3, 'strong', 'accepted')`, ws, dagent, wl); err == nil {
		t.Fatal("discovered_agent_workloads accepted strength strong")
	}
}

func a5LinkDigest(t *testing.T, db *sql.DB, ws, dagent, inst uuid.UUID) string {
	t.Helper()
	var strength, state string
	var decided sql.NullString
	err := db.QueryRow(`SELECT l.strength, l.state, l.decided_by::text
		FROM discovered_agent_iga_links l
		WHERE l.workspace_id = $1 AND l.discovered_agent_id = $2
		  AND EXISTS (SELECT 1 FROM iga_agent_instances i
		              WHERE i.workspace_id = l.workspace_id AND i.id = $3)`, ws, dagent, inst).
		Scan(&strength, &state, &decided)
	if err != nil {
		t.Fatal(err)
	}
	return strength + "|" + state + "|" + decided.String
}

func TestTRD2ITA5RegistrationIdempotency(t *testing.T) {
	f := newA3(t)
	owner, mem := a5Human(t, f)
	wl, obs := a5IGAEvidence(f)
	api := newA5HTTP(t, f.g, f.ws)
	api.claims["user_id"] = owner.String()
	api.claims["workspace_membership_id"] = mem.String()

	raw := a5RegBody(t, 0, "invoice processing", owner, "", "invoice-worker", obs, uuid.Nil)
	key := "a5-reg-1"
	code, first, body := api.post("/workloads/"+wl.String()+"/agent-registration", key, raw)
	if code != http.StatusOK {
		t.Fatalf("register = %d %s", code, first)
	}
	if digs(body, "data", "link_basis") != models.WorkloadLinkBasisHuman ||
		!a5Flag(body, "data", "created_agent") ||
		!a5Flag(body, "data", "created_instance") ||
		digs(body, "data", "purpose") != "invoice processing" {
		t.Fatalf("registration = %s", first)
	}
	instanceID := digs(body, "data", "instance_id")
	agentID := digs(body, "data", "agent_id")
	if f.scalar(`SELECT count(*) FROM iga_agents WHERE id = $1 AND rollup_state = 'confirmed'`, agentID) != 1 {
		t.Fatal("creating an agent did not set rollup_state confirmed")
	}

	code, again, _ := api.post("/workloads/"+wl.String()+"/agent-registration", key, raw)
	if code != http.StatusOK || !bytes.Equal(first, again) {
		t.Fatalf("replay = %d %s, want the stored bytes %s", code, again, first)
	}
	if f.scalar(`SELECT count(*) FROM iga_agent_instances WHERE workspace_id = $1 AND workload_id = $2`, f.ws, wl) != 1 {
		t.Fatal("replay inserted another instance")
	}

	other := a5RegBody(t, 0, "a different purpose", owner, "", "invoice-worker", obs, uuid.Nil)
	code, conflict, cbody := api.post("/workloads/"+wl.String()+"/agent-registration", key, other)
	if code != http.StatusConflict || errCode(cbody) != "idempotency_key_reused" {
		t.Fatalf("conflicting body = %d %s", code, conflict)
	}
	code, third, _ := api.post("/workloads/"+wl.String()+"/agent-registration", key, raw)
	if code != http.StatusOK || !bytes.Equal(first, third) {
		t.Fatalf("replay after the 409 = %d %s, want the original stored bytes", code, third)
	}

	relink := a5RegBody(t, 0, "invoice processing", owner, agentID, "", obs, uuid.Nil)
	code, relinked, rbody := api.post("/workloads/"+wl.String()+"/agent-registration", "a5-reg-2", relink)
	if code != http.StatusOK || a5Flag(rbody, "data", "created_instance") ||
		digs(rbody, "data", "instance_id") != instanceID {
		t.Fatalf("relink = %d %s", code, relinked)
	}
	if f.scalar(`SELECT count(*) FROM iga_agent_instances WHERE workspace_id = $1 AND workload_id = $2`, f.ws, wl) != 1 {
		t.Fatal("relink inserted another instance")
	}

	otherAgent := uuid.New()
	f.exec(`INSERT INTO iga_agents (id, workspace_id, display_name, rollup_state) VALUES ($1, $2, 'other', 'unknown')`, otherAgent, f.ws)
	taken := a5RegBody(t, 0, "invoice processing", owner, otherAgent.String(), "", obs, uuid.Nil)
	code, takenBody, tbody := api.post("/workloads/"+wl.String()+"/agent-registration", "a5-reg-3", taken)
	if code != http.StatusConflict || errCode(tbody) != "instance_evidence_taken" {
		t.Fatalf("second agent on the same evidence = %d %s", code, takenBody)
	}

	staleWL, staleObs := a5IGAEvidence(f)
	f.exec(`UPDATE iga_workload SET classification_version = 2 WHERE id = $1`, staleWL)
	stale := a5RegBody(t, 0, "invoice processing", owner, "", "stale", staleObs, uuid.Nil)
	code, staleBody, sbody := api.post("/workloads/"+staleWL.String()+"/agent-registration", "a5-reg-4", stale)
	if code != http.StatusConflict || errCode(sbody) != "classification_conflict" {
		t.Fatalf("stale version = %d %s", code, staleBody)
	}

	bare := uuid.New()
	f.exec(`INSERT INTO iga_workload (id, workspace_id, runtime_kind, source_key, classification) VALUES ($1, $2, 'lambda_function', $3, 'classified_agent')`,
		bare, f.ws, "bare-"+bare.String())
	noEv := a5RegBody(t, 0, "invoice processing", owner, "", "no-evidence", staleObs, uuid.Nil)
	code, noEvBody, ebody := api.post("/workloads/"+bare.String()+"/agent-registration", "a5-reg-5", noEv)
	if code != http.StatusUnprocessableEntity || errCode(ebody) != "workload_evidence" {
		t.Fatalf("missing evidence = %d %s", code, noEvBody)
	}

	badOwner := a5RegBody(t, 0, "invoice processing", uuid.New(), "", "bad-owner", obs, uuid.Nil)
	code, _, obody := api.post("/workloads/"+wl.String()+"/agent-registration", "a5-reg-6", badOwner)
	if code != http.StatusUnprocessableEntity || errCode(obody) != "invalid_owner" {
		t.Fatalf("invalid owner = %d %v", code, obody)
	}

	// Linking an existing agent does not rewrite its rollup, and the cloud
	// observation arm is accepted when it shares the confirming run.
	linked := uuid.New()
	f.exec(`INSERT INTO iga_agents (id, workspace_id, display_name, rollup_state) VALUES ($1, $2, 'kept', 'unknown')`, linked, f.ws)
	cwl, cobs := a5CloudEvidence(f)
	cloudRaw := a5RegBody(t, 0, "cloud evidence", owner, linked.String(), "", uuid.Nil, cobs)
	code, cloudResp, cloudBody := api.post("/workloads/"+cwl.String()+"/agent-registration", "a5-reg-cloud", cloudRaw)
	if code != http.StatusOK || a5Flag(cloudBody, "data", "created_agent") ||
		digs(cloudBody, "data", "agent_id") != linked.String() {
		t.Fatalf("cloud registration = %d %s", code, cloudResp)
	}
	if f.scalar(`SELECT count(*) FROM iga_agents WHERE id = $1 AND rollup_state = 'unknown'`, linked) != 1 {
		t.Fatal("linking an agent changed its rollup_state")
	}
	if f.scalar(`SELECT count(*) FROM iga_agent_instances WHERE workload_id = $1 AND cloud_observation_id = $2 AND workload_link_basis = 'human_registration'`, cwl, cobs) != 1 {
		t.Fatal("cloud arm did not land as human_registration")
	}
}

func TestTRD2ITA5RegistrationCrossWorkspace(t *testing.T) {
	f := newA3(t)
	wl, obs := a5IGAEvidence(f)
	other := newWorkspace(t, f.g, "a5-other-"+uuid.NewString()[:8])
	owner := uuid.New()
	seedUser(t, f.g, other, owner, owner.String()+"@a5.test")
	mem := seedMembership(t, f.g, other, owner, "active")
	api := newA5HTTP(t, f.g, other)
	api.claims["user_id"] = owner.String()
	api.claims["workspace_membership_id"] = mem.String()
	raw := a5RegBody(t, 0, "probe", owner, "", "probe", obs, uuid.Nil)
	code, resp, body := api.post("/workloads/"+wl.String()+"/agent-registration", "", raw)
	if code != http.StatusNotFound || errCode(body) != "not_found" {
		t.Fatalf("cross-workspace = %d %s", code, resp)
	}
	if strings.Contains(string(resp), obs.String()) {
		t.Fatalf("cross-workspace response leaked the observation: %s", resp)
	}
	if f.scalar(`SELECT count(*) FROM iga_agent_instances WHERE workload_id = $1`, wl) != 0 {
		t.Fatal("cross-workspace registration wrote an instance")
	}
}

func TestTRD2ITA5CandidateCannotGovern(t *testing.T) {
	f := newA3(t)
	wl, _ := a5IGAEvidence(f)
	dagent := uuid.New()
	f.exec(`INSERT INTO discovered_agents (id, workspace_id, source, fingerprint, display_name, metadata)
		VALUES ($1, $2, 'k8s_webhook', $3, 'candidate-pod', '{"process":"invoice-worker"}')`,
		dagent, f.ws, "fp-"+dagent.String())
	if err := services.NewAgentRegistrationService(f.g).RecordCandidateLink(t.Context(), f.ws, dagent, wl, nil, nil); err != nil {
		t.Fatal(err)
	}
	if f.scalar(`SELECT count(*) FROM discovered_agent_workloads
		WHERE workspace_id = $1 AND discovered_agent_id = $2 AND workload_id = $3
		  AND link_strength = 'candidate' AND link_state = 'proposed'`, f.ws, dagent, wl) != 1 {
		t.Fatal("candidate join was not recorded")
	}
	if f.scalar(`SELECT count(*) FROM iga_agent_instances WHERE workspace_id = $1 AND workload_id IS NOT NULL`, f.ws) != 0 {
		t.Fatal("a candidate link set workload_id")
	}
	agent := uuid.New()
	f.exec(`INSERT INTO iga_agents (id, workspace_id, display_name) VALUES ($1, $2, 'cand')`, agent, f.ws)
	if _, err := f.db.Exec(`INSERT INTO iga_agent_instances
		(workspace_id, agent_id, workload_id, workload_link_basis, linked_by, owner_user_id, classification_version)
		VALUES ($1, $2, $3, 'candidate', $4, $4, 0)`, f.ws, agent, wl, uuid.New()); err == nil {
		t.Fatal("candidate basis was stored on an authoritative instance")
	}
}

func TestTRD2ITA5WeakNameNeverGoverns(t *testing.T) {
	f := newA3(t)
	agent := uuid.New()
	f.exec(`INSERT INTO iga_agents (id, workspace_id, display_name, lifecycle) VALUES ($1, $2, 'Invoice Worker', 'active')`, agent, f.ws)
	bridge := services.NewIGABridgeManager(f.g)

	marker := uuid.New()
	f.exec(`INSERT INTO discovered_agents (id, workspace_id, source, fingerprint, display_name, metadata)
		VALUES ($1, $2, 'k8s_webhook', $3, 'unrelated-pod', $4::jsonb)`,
		marker, f.ws, "fp-"+marker.String(),
		`{"process":"Invoice Worker","workload_name":"invoice-worker","env":{"AGENT_NAME":"invoice-worker"}}`)
	link, err := bridge.ProposeForAgent(f.ws, marker)
	if err != nil {
		t.Fatal(err)
	}
	if link != nil {
		t.Fatalf("process, workload name or env marker proposed a link: %+v", link)
	}
	if f.scalar(`SELECT count(*) FROM iga_agent_instances WHERE agent_id = $1`, agent) != 0 {
		t.Fatal("a name marker created an agent instance")
	}

	named := uuid.New()
	f.exec(`INSERT INTO discovered_agents (id, workspace_id, source, fingerprint, display_name)
		VALUES ($1, $2, 'k8s_webhook', $3, 'invoice-worker')`, named, f.ws, "fp-"+named.String())
	link, err = bridge.ProposeForAgent(f.ws, named)
	if err != nil || link == nil {
		t.Fatalf("display-name proposal = %v %v", link, err)
	}
	if link.Strength != models.IGALinkWeak || link.State != models.IGALinkProposed {
		t.Fatalf("proposal = %s/%s, want weak/proposed", link.Strength, link.State)
	}
	decider := uuid.New()
	accepted, err := bridge.Decide(f.ws, named, models.IGALinkAccepted, &decider, link.Version)
	if err != nil || accepted.State != models.IGALinkAccepted {
		t.Fatalf("decide = %+v %v", accepted, err)
	}
	var status string
	f.scan(`SELECT status FROM discovered_agents WHERE id = $1`, []any{named}, &status)
	if status != "unregistered" {
		t.Fatalf("accepted name match set discovered_agents.status = %s", status)
	}
	if f.scalar(`SELECT count(*) FROM iga_agent_instances WHERE workspace_id = $1 AND workload_id IS NOT NULL`, f.ws) != 0 {
		t.Fatal("an accepted weak name match set workload_id")
	}
}

func TestTRD2ITA5StuckSnapshots(t *testing.T) {
	f := newA3(t)
	api := newA5HTTP(t, f.g, f.ws)
	integ, collector, _ := f.seedCollector("linux")
	run := f.seedRun(integ, "full", false)

	stuckRow, stuckSnap := uuid.New(), uuid.New()
	a5Snapshot(f, stuckRow, collector, stuckSnap, "ns/app", "workload", 2, false, false)
	f.exec(`INSERT INTO collector_snapshot_chunks (workspace_id, snapshot_row_id, chunk_no, payload_hash, validated)
		VALUES ($1, $2, 1, 'h', true)`, f.ws, stuckRow)
	a5Batch(f, integ, collector, run, stuckSnap, 1, 4, false)

	hiddenRow, hiddenSnap := uuid.New(), uuid.New()
	a5Snapshot(f, hiddenRow, collector, hiddenSnap, "ns/hidden", "workload", 1, false, false)
	f.exec(`INSERT INTO collector_snapshot_chunks (workspace_id, snapshot_row_id, chunk_no, payload_hash, validated)
		VALUES ($1, $2, 1, 'h', true)`, f.ws, hiddenRow)
	a5Batch(f, integ, collector, run, hiddenSnap, 2, 3, false)

	gapRow, gapSnap := uuid.New(), uuid.New()
	a5Snapshot(f, gapRow, collector, gapSnap, "ns/gap", "workload", 1, false, true)
	f.exec(`INSERT INTO collector_snapshot_chunks (workspace_id, snapshot_row_id, chunk_no, payload_hash, validated)
		VALUES ($1, $2, 1, 'h', true)`, f.ws, gapRow)
	a5Batch(f, integ, collector, run, gapSnap, 3, 5, false)

	superSnap := uuid.New()
	superRow := uuid.New()
	a5Snapshot(f, superRow, collector, superSnap, "ns/old", "workload", 1, true, false)
	a5Batch(f, integ, collector, run, superSnap, 4, 0, true)

	code, raw, body := api.get("/pipeline")
	if code != http.StatusOK {
		t.Fatalf("GET /pipeline = %d %s", code, raw)
	}
	data, _ := body["data"].(map[string]any)
	if _, ok := data["collector_deferrals"]; ok {
		t.Fatalf("default /pipeline included collector_deferrals: %s", raw)
	}
	for _, key := range []string{"barrier", "accounts", "current_rev", "current_published_at"} {
		if _, ok := data[key]; !ok {
			t.Fatalf("default /pipeline missing %s: %s", key, raw)
		}
	}

	code, raw, body = api.get("/pipeline?include=stuck_snapshots")
	if code != http.StatusOK {
		t.Fatalf("opt-in /pipeline = %d %s", code, raw)
	}
	block, _ := dig(body, "data", "collector_deferrals").(map[string]any)
	if block == nil {
		t.Fatalf("opt-in omitted collector_deferrals: %s", raw)
	}
	if num(block, "deferral_threshold") != 3 {
		t.Fatalf("threshold = %v", block["deferral_threshold"])
	}
	stuck := a5Stuck(t, block, stuckSnap)
	if num(stuck, "expected_chunks") != 2 || num(stuck, "received_chunks") != 1 ||
		digs(stuck, "reason") != "missing_chunk" || num(stuck, "deferrals") != 4 {
		t.Fatalf("missing chunk snapshot = %v", stuck)
	}
	if strings.Contains(string(raw), hiddenSnap.String()) {
		t.Fatalf("attempt_count 3 was reported as stuck: %s", raw)
	}
	gap := a5Stuck(t, block, gapSnap)
	if digs(gap, "reason") != "gap_blocked" || num(gap, "received_chunks") != 1 || num(gap, "expected_chunks") != 1 {
		t.Fatalf("gap_blocked snapshot = %v", gap)
	}
	var superCount int64
	for _, row := range digl(block, "superseded_batches") {
		if digs(row, "collector_id") == collector.String() {
			superCount += num(row, "count")
		}
	}
	if superCount != 1 {
		t.Fatalf("superseded count = %v, block %v", superCount, block["superseded_batches"])
	}

	code, raw, body = api.get("/pipeline?include=nope")
	if code != http.StatusBadRequest || errCode(body) != "invalid_parameter" {
		t.Fatalf("bad include = %d %s", code, raw)
	}
}

func a5Flag(v any, path ...any) bool {
	b, _ := dig(v, path...).(bool)
	return b
}

func a5Stuck(t *testing.T, block map[string]any, snap uuid.UUID) map[string]any {
	t.Helper()
	for _, row := range digl(block, "stuck_snapshots") {
		m, _ := row.(map[string]any)
		if digs(m, "snapshot_id") == snap.String() {
			return m
		}
	}
	t.Fatalf("snapshot %s not in stuck_snapshots: %v", snap, block["stuck_snapshots"])
	return nil
}

func a5Snapshot(f *a3, row, collector, snap uuid.UUID, scope, class string, expected int, complete, gap bool) {
	f.t.Helper()
	f.exec(`INSERT INTO collector_snapshots
		(id, workspace_id, collector_id, snapshot_id, epoch, scope_key, object_class, generation, expected_chunks, complete, gap_blocked)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, $9, $10)`,
		row, f.ws, collector, snap, uuid.New(), scope, class, expected, complete, gap)
}

func a5Batch(f *a3, integ, collector, run, snap uuid.UUID, sequence int64, attempts int, superseded bool) {
	f.t.Helper()
	batch := uuid.New()
	var superAt any
	if superseded {
		superAt = time.Date(2026, 9, 26, 11, 0, 0, 0, time.UTC)
	}
	f.exec(`INSERT INTO collector_batches
		(id, workspace_id, collector_id, epoch, sequence, batch_id, payload_hash, receipt_id,
		 receipt_state, projection_state, iga_scan_run_id, snapshot_id, superseded_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'h', $7, 'accepted', 'queued', $8, $9, $10)`,
		batch, f.ws, collector, uuid.New(), sequence, uuid.New(), uuid.New(), run, snap, superAt)
	f.exec(`INSERT INTO collector_outbox
		(id, workspace_id, integration_id, collector_id, batch_row_id, job_kind, dedupe_key,
		 state, attempt_count, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, 'collector_project', $6, 'ready', $7, $8, $9)`,
		uuid.New(), f.ws, integ, collector, batch, "batch:"+batch.String(), attempts,
		time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 9, 26, 12, 5, 0, 0, time.UTC))
}

func a5Human(t *testing.T, f *a3) (user, membership uuid.UUID) {
	t.Helper()
	user = uuid.New()
	seedUser(t, f.g, f.ws, user, user.String()+"@a5.test")
	membership = seedMembership(t, f.g, f.ws, user, "active")
	return user, membership
}

func a5IGAEvidence(f *a3) (workload, observation uuid.UUID) {
	f.t.Helper()
	integ, _, _ := f.seedCollector("linux")
	run := f.seedRun(integ, "full", true)
	workload = uuid.New()
	f.exec(`INSERT INTO iga_workload (id, workspace_id, runtime_kind, source_key, display_name, classification)
		VALUES ($1, $2, 'lambda_function', $3, 'invoice', 'classified_agent')`, workload, f.ws, "wl-"+workload.String())
	obj := uuid.New()
	f.exec(`INSERT INTO iga_source_objects (id, workspace_id, integration_id, object_type, recognition_key)
		VALUES ($1, $2, $3, 'workload', $4)`, obj, f.ws, integ, "obj-"+obj.String())
	observation = uuid.New()
	f.exec(`INSERT INTO iga_observations
		(id, workspace_id, source_object_id, scan_run_id, mode, observed_at, dedupe_key)
		VALUES ($1, $2, $3, $4, 'platform_declared', now(), $5)`,
		observation, f.ws, obj, run, observation.String())
	f.exec(`INSERT INTO iga_object_support
		(id, workspace_id, workload_id, integration_id, confirming_iga_scan_run_id, partition_key)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		uuid.New(), f.ws, workload, integ, run, "reg-"+workload.String())
	return workload, observation
}

func a5CloudEvidence(f *a3) (workload, observation uuid.UUID) {
	f.t.Helper()
	workload = uuid.New()
	f.exec(`INSERT INTO iga_workload (id, workspace_id, runtime_kind, source_key, display_name, classification)
		VALUES ($1, $2, 'lambda_function', $3, 'cloud-fn', 'classified_agent')`, workload, f.ws, "cwl-"+workload.String())
	run := f.publishedRun(f.connector, 1)
	cloudWL := uuid.New()
	f.exec(`INSERT INTO cloud_workload (id, workspace_id, connector_id, runtime_kind, native_id, name)
		VALUES ($1, $2, $3, 'lambda_function', $4, 'fn')`, cloudWL, f.ws, f.connector, "arn:aws:lambda:eu-central-1:111111111111:function:"+cloudWL.String())
	observation = uuid.New()
	f.exec(`INSERT INTO cloud_observation
		(id, workspace_id, connector_id, scan_run_id, generation, source_api, observed_at, content_hash, subject_native_id, workload_id)
		VALUES ($1, $2, $3, $4, 1, 'lambda:ListFunctions', now(), $5, $6, $7)`,
		observation, f.ws, f.connector, run, "h-"+observation.String(), "arn:aws:lambda:fn:"+observation.String(), cloudWL)
	f.exec(`INSERT INTO iga_object_support
		(id, workspace_id, workload_id, connector_id, last_confirmed_run_id, partition_key)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		uuid.New(), f.ws, workload, f.connector, run, "cloud-"+workload.String())
	return workload, observation
}

func a5RegBody(t *testing.T, version int, purpose string, owner uuid.UUID, agentID, displayName string, observation, cloudObservation uuid.UUID) []byte {
	t.Helper()
	body := map[string]any{
		"expected_version": version,
		"purpose":          purpose,
		"owner_user_id":    owner.String(),
	}
	if agentID != "" {
		body["agent_id"] = agentID
	} else {
		body["create_agent"] = map[string]any{"display_name": displayName}
	}
	if cloudObservation != uuid.Nil {
		body["cloud_observation_id"] = cloudObservation.String()
	} else {
		body["observation_id"] = observation.String()
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type a5HTTP struct {
	t      *testing.T
	eng    *gin.Engine
	ws     uuid.UUID
	claims map[string]string
}

func newA5HTTP(t *testing.T, g *gorm.DB, ws uuid.UUID) *a5HTTP {
	t.Helper()
	gate := services.NewGraphProjectionGate(true, "")
	if err := gate.Verify(g); err != nil {
		t.Fatalf("graph gate: %v", err)
	}
	gin.SetMode(gin.TestMode)
	h := &a5HTTP{t: t, eng: gin.New(), ws: ws, claims: map[string]string{}}
	group := h.eng.Group("/api/iga/v1")
	group.Use(func(c *gin.Context) {
		c.Set("workspace_id", h.ws.String())
		for k, v := range h.claims {
			c.Set(k, v)
		}
		c.Next()
	})
	platform.RegisterIGAGraphReadRoutes(group, platform.NewIGAGraphReadControllerWith(g, gate, []byte("a5-test-cursor")),
		func(string, string) gin.HandlerFunc {
			return func(c *gin.Context) { c.Next() }
		})
	return h
}

func (h *a5HTTP) post(path, key string, raw []byte) (int, []byte, map[string]any) {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/iga/v1"+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	return h.do(req)
}

func (h *a5HTTP) get(path string) (int, []byte, map[string]any) {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/iga/v1"+path, nil)
	return h.do(req)
}

func (h *a5HTTP) do(req *http.Request) (int, []byte, map[string]any) {
	h.t.Helper()
	w := httptest.NewRecorder()
	h.eng.ServeHTTP(w, req)
	var body map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			h.t.Fatalf("%s %s: status %d, body is not JSON: %s", req.Method, req.URL.Path, w.Code, w.Body.Bytes())
		}
	}
	return w.Code, w.Body.Bytes(), body
}
