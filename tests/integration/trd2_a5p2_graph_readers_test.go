package integration

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestTRD2ITA5P2Readers covers the v2 opt-in, runtime reads, declared versus
// observed labels, and the two Part 1 carry-overs. Default AWS responses stay
// free of graph_revision and of linux rows.
func TestTRD2ITA5P2Readers(t *testing.T) {
	f := newA3(t)
	api := newA5HTTP(t, f.g, f.ws)

	code, raw, body := api.get("/capabilities")
	if code != http.StatusOK {
		t.Fatalf("capabilities %d %s", code, raw)
	}
	available, _ := dig(body, "data", "graph_v2", "available").(bool)
	if digs(body, "data", "graph_v2", "opt_in") != "graph=v2" || !available {
		t.Fatalf("graph_v2 = %v", body["data"])
	}
	feats, _ := body["data"].(map[string]any)["features"].(map[string]any)
	if len(feats) != 8 {
		t.Fatalf("features = %d, want 8", len(feats))
	}

	linux, lcol, _ := f.seedCollector("linux")
	lrun := f.seedRun(linux, "runtime_batch", false)
	f.seedFact(linux, lrun, "linux.systemd_workload", "unit", "o_workload",
		map[string]any{"native": map[string]any{"unit": "invoice-worker.service"}}, nil)
	f.seedFact(linux, lrun, "linux.local_account", "uid", "o_identity",
		map[string]any{"native": map[string]any{"uid": 995, "user_namespace": "host"}, "attributes": map[string]any{"name": "svc-invoice"}}, nil)
	f.seedFact(linux, lrun, "network.endpoint", "db", "o_db",
		map[string]any{"native": map[string]any{"address": "10.20.0.15", "port": 5432, "protocol": "tcp", "address_family": "ipv4"}},
		map[string]any{"kind": "runtime.network_connect", "subject_ref": "o_workload", "identity_ref": "o_identity", "resource_ref": "o_db",
			"runtime": map[string]any{"boot_id": "boot-a", "pid_namespace": "host", "pid": 824, "start_ticks": 93401},
			"outcome": "success", "attribution": "kernel_process_credentials"})
	f.seedBatch(linux, lcol, uuid.New(), lrun, 1, uuid.Nil)
	f.projectDefault()

	k8s, kcol, _ := f.seedCollector("kubernetes")
	krun := f.seedRun(k8s, "runtime_batch", false)
	f.seedFact(k8s, krun, "k8s.service_account", "sa", "sa",
		map[string]any{"native": map[string]any{"namespace": "pay", "name": "invoice", "uid": "sa-uid-1"}}, nil)
	f.seedFact(k8s, krun, "k8s.cluster_role", "view", "role",
		map[string]any{"native": map[string]any{"name": "view", "uid": "role-1", "rules": []any{map[string]any{
			"verbs": []any{"get"}, "resources": []any{"pods"},
		}}}}, nil)
	f.seedFact(k8s, krun, "k8s.role_binding", "bind", "bind",
		map[string]any{"native": map[string]any{
			"name": "view-pay", "namespace": "pay", "namespace_uid": "ns-pay", "uid": "bind-1",
			"roleRef":  map[string]any{"kind": "ClusterRole", "name": "view"},
			"subjects": []any{map[string]any{"kind": "ServiceAccount", "name": "invoice", "namespace": "pay"}},
		}}, nil)
	f.seedFact(k8s, krun, "k8s.workload", "dep", "dep",
		map[string]any{"native": map[string]any{
			"apiGroup": "apps", "kind": "Deployment", "namespace": "pay", "name": "invoice", "uid": "dep-1", "slot": "0",
			"serviceAccountName": "invoice",
		}}, nil)
	f.seedBatch(k8s, kcol, uuid.New(), krun, 1, uuid.Nil)
	f.projectDefault()

	ad, acol, _ := f.seedCollector("ad")
	arun := f.seedRun(ad, "runtime_batch", false)
	f.seedFact(ad, arun, "user", "ada", "", map[string]any{
		"account_kind": "ad_user", "object_guid": "11111111-1111-1111-1111-111111111111",
		"object_sid": "S-1-5-21-1", "distinguished_name": "CN=ada,DC=test", "sam_account_name": "ada",
		"forest_id": "DC=authsec,DC=test",
	}, nil)
	f.seedBatch(ad, acol, uuid.New(), arun, 1, uuid.Nil)
	f.projectDefault()

	var wl, ident, resource uuid.UUID
	f.scan(`SELECT id FROM iga_workload WHERE workspace_id = $1 AND provider = 'linux'`, []any{f.ws}, &wl)
	f.scan(`SELECT id FROM iga_identity_accounts WHERE workspace_id = $1 AND provider = 'linux'`, []any{f.ws}, &ident)
	f.scan(`SELECT id FROM iga_resources WHERE workspace_id = $1 AND provider = 'linux' LIMIT 1`, []any{f.ws}, &resource)
	var adIdent, k8sIdent, k8sWorkload uuid.UUID
	f.scan(`SELECT id FROM iga_identity_accounts WHERE workspace_id = $1 AND provider = 'ad'`, []any{f.ws}, &adIdent)
	f.scan(`SELECT subject_identity_account_id FROM iga_access_edges
		WHERE workspace_id = $1 AND provider = 'kubernetes' AND calculation_state = 'partial' AND effective_conclusion = 'unknown'
		LIMIT 1`, []any{f.ws}, &k8sIdent)
	f.scan(`SELECT id FROM iga_workload WHERE workspace_id = $1 AND provider = 'kubernetes' LIMIT 1`, []any{f.ws}, &k8sWorkload)

	rel := uuid.New()
	f.exec(`INSERT INTO iga_relationship
		(id, workspace_id, relationship_type, source_identity_account_id, target_identity_account_id, basis, state, source_key)
		VALUES ($1,$2,'backed_by_directory',$3,$4,'asserted','current',$5)`,
		rel, f.ws, ident, adIdent, "backed-"+rel.String())

	var obs, runtime uuid.UUID
	f.scan(`SELECT observation_id, runtime_instance_id FROM iga_observed_access WHERE workspace_id = $1 LIMIT 1`,
		[]any{f.ws}, &obs, &runtime)
	sqlObs, dbObs := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{sqlObs, dbObs} {
		f.exec(`INSERT INTO iga_observations
			(id, workspace_id, source_object_id, scan_run_id, mode, observed_at, dedupe_key)
			SELECT $1, workspace_id, source_object_id, scan_run_id, mode, now(), $2
			FROM iga_observations WHERE id = $3`, id, id.String(), obs)
	}
	f.exec(`INSERT INTO iga_observed_access
		(id, workspace_id, workload_id, runtime_instance_id, identity_account_id, resource_id, observation_id, action, outcome, observed_at, attribution)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'sql','success', now(), '')`,
		uuid.New(), f.ws, wl, runtime, ident, resource, sqlObs)
	f.exec(`INSERT INTO iga_observed_access
		(id, workspace_id, workload_id, runtime_instance_id, identity_account_id, resource_id, observation_id, action, outcome, observed_at, attribution)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'sql','success', now(), 'database')`,
		uuid.New(), f.ws, wl, runtime, ident, resource, dbObs)

	code, raw, body = api.get("/workloads")
	if code != 200 || strings.Contains(string(raw), wl.String()) || strings.Contains(string(raw), "graph_revision") {
		t.Fatalf("default workloads leaked v2 data: %d %s", code, raw)
	}
	code, raw, body = api.get("/workloads?provider=linux")
	if code != 400 || errCode(body) != "invalid_parameter" || !strings.Contains(string(raw), "provider must be aws") {
		t.Fatalf("provider=linux without v2 = %d %s", code, raw)
	}
	code, raw, _ = api.get("/workloads?graph=v2")
	if code != 200 || !strings.Contains(string(raw), wl.String()) || !strings.Contains(string(raw), "graph_revision") {
		t.Fatalf("v2 workloads = %d %s", code, raw)
	}
	code, raw, _ = api.get("/workloads?graph=v2&provider=linux")
	if code != 200 || !strings.Contains(string(raw), wl.String()) || strings.Contains(string(raw), k8sWorkload.String()) {
		t.Fatalf("provider=linux = %d %s", code, raw)
	}
	code, raw, body = api.get("/workloads?graph=later")
	if code != 400 || errCode(body) != "invalid_parameter" {
		t.Fatalf("graph=later = %d %s", code, raw)
	}

	code, raw, _ = api.get("/graph/expand?node=workload:" + wl.String() + "&edge=observed_access&direction=forward")
	if code != 400 || strings.Contains(string(raw), "observed_access") {
		t.Fatalf("default expand listed observed_access: %d %s", code, raw)
	}
	code, raw, body = api.get("/graph?root=workload:" + wl.String() + "&direction=forward&graph=v2")
	if code != 200 || !strings.Contains(string(raw), "graph_revision") {
		t.Fatalf("v2 graph = %d %s", code, raw)
	}
	if !strings.Contains(string(raw), "effective_access_not_evaluated") {
		t.Fatalf("v2 graph dropped the effective-access limitation: %s", raw)
	}
	if strings.Count(string(raw), `"access_class":"observed"`) != 2 || !strings.Contains(string(raw), `"outcome":"success"`) {
		t.Fatalf("observed edges = %d, want the network connect and the database sql only\n%s", strings.Count(string(raw), `"access_class":"observed"`), raw)
	}

	code, raw, _ = api.get("/graph?root=identity:" + ident.String() + "&direction=forward&graph=v2")
	if code != 200 || !strings.Contains(string(raw), "directory_backing") || strings.Contains(string(raw), "kerberos") {
		t.Fatalf("backed_by_directory = %d %s", code, raw)
	}

	code, raw, _ = api.get("/graph?root=identity:" + k8sIdent.String() + "&direction=forward&graph=v2")
	if code != 200 || !strings.Contains(string(raw), `"calculation_state":"partial"`) || !strings.Contains(string(raw), `"effective_conclusion":"unknown"`) {
		t.Fatalf("k8s grant honesty = %d %s", code, raw)
	}

	code, raw, _ = api.get("/resources/" + resource.String())
	if code != 404 || strings.Contains(string(raw), "reference_status") {
		t.Fatalf("default resource detail returned a linux resource: %d %s", code, raw)
	}
	code, raw, _ = api.get("/resources/" + resource.String() + "?graph=v2")
	if code != 200 || !strings.Contains(string(raw), `"reference_status"`) {
		t.Fatalf("v2 resource detail = %d %s", code, raw)
	}

	var grant uuid.UUID
	f.scan(`SELECT id FROM iga_access_edges WHERE workspace_id = $1 AND provider = 'kubernetes' LIMIT 1`, []any{f.ws}, &grant)
	code, raw, _ = api.get("/evidence?claim=grant:" + grant.String())
	if code != 404 {
		t.Fatalf("default evidence returned a kubernetes grant: %d %s", code, raw)
	}
	code, raw, _ = api.get("/evidence?claim=grant:" + grant.String() + "&graph=v2")
	if code != 200 || !strings.Contains(string(raw), `"manifest"`) || !strings.Contains(string(raw), `"graph_revision"`) {
		t.Fatalf("v2 evidence provenance = %d %s", code, raw)
	}

	code, raw, _ = api.get("/pipeline")
	if code != 200 || strings.Contains(string(raw), linux.String()) || strings.Contains(string(raw), "graph_revision") {
		t.Fatalf("default pipeline = %d %s", code, raw)
	}
	code, raw, _ = api.get("/pipeline?graph=v2")
	if code != 200 || !strings.Contains(string(raw), linux.String()) || !strings.Contains(string(raw), "graph_revision") {
		t.Fatalf("v2 pipeline = %d %s", code, raw)
	}
	code, raw, _ = api.get("/coverage?graph=v2&provider=linux")
	if code != 200 || !strings.Contains(string(raw), linux.String()) {
		t.Fatalf("v2 coverage = %d %s", code, raw)
	}

	code, raw, _ = api.get("/workloads/" + wl.String() + "/runtime-instances")
	if code != 200 || !strings.Contains(string(raw), runtime.String()) || !strings.Contains(string(raw), `"ttl_basis":null`) {
		t.Fatalf("runtime instances = %d %s", code, raw)
	}
	f.exec(`UPDATE iga_runtime_instances SET ended_at = now() WHERE id = $1`, runtime)
	code, raw, _ = api.get("/workloads/" + wl.String() + "/runtime-instances")
	if code != 200 || !strings.Contains(string(raw), `"ttl_basis":"runtime_unobserved"`) || !strings.Contains(string(raw), `"ended_at":"`) {
		t.Fatalf("ended runtime = %d %s", code, raw)
	}
	code, raw, body = api.get("/workloads/" + wl.String() + "/runtime-policy-status")
	if code != 200 || digs(body, "data", "status") != "not_configured" {
		t.Fatalf("policy status = %d %s", code, raw)
	}
	code, raw, _ = api.get("/workloads/" + wl.String() + "/observed-access")
	if code != 200 || strings.Contains(string(raw), `"attribution":""`) || !strings.Contains(string(raw), `"attribution":"database"`) {
		t.Fatalf("observed-access aggregate = %d %s", code, raw)
	}
	code, raw, _ = api.get("/workloads/" + wl.String() + "/observed-access?view=events&limit=10")
	if code != 200 || strings.Contains(string(raw), `"action":"sql","outcome":"success","attribution":""`) {
		t.Fatalf("observed-access events leaked bare sql: %d %s", code, raw)
	}
	code, raw, _ = api.get("/identities/" + ident.String() + "/observed-use")
	if code != 200 || !strings.Contains(string(raw), `"binding_kind":"uid"`) || !strings.Contains(string(raw), `"basis":"observed"`) {
		t.Fatalf("observed-use = %d %s", code, raw)
	}

}

func TestTRD2ITA5P2ClassificationAndRescan(t *testing.T) {
	f := newA3(t)
	owner, mem := a5Human(t, f)
	api := newA5HTTP(t, f.g, f.ws)
	api.claims["user_id"] = owner.String()
	api.claims["workspace_membership_id"] = mem.String()

	wl, obs := a5IGAEvidence(f)
	f.exec(`UPDATE iga_workload SET classification = 'unclassified', classification_version = 4 WHERE id = $1`, wl)
	raw := a5RegBody(t, 0, "invoice", owner, "", "stale-first", obs, uuid.Nil)
	code, resp, body := api.post("/workloads/"+wl.String()+"/agent-registration", "a5p2-stale", raw)
	if code != http.StatusConflict || errCode(body) != "classification_conflict" {
		t.Fatalf("stale version before class gate = %d %s", code, resp)
	}

	wl, obs = a5IGAEvidence(f)
	f.exec(`UPDATE iga_workload SET classification = 'unclassified' WHERE id = $1`, wl)
	raw = a5RegBody(t, 0, "invoice", owner, "", "not-agent", obs, uuid.Nil)
	code, resp, body = api.post("/workloads/"+wl.String()+"/agent-registration", "a5p2-unclass", raw)
	if code != http.StatusConflict || errCode(body) != "classification_not_agent" {
		t.Fatalf("unclassified = %d %s", code, resp)
	}
	if f.scalar(`SELECT count(*) FROM iga_agent_instances WHERE workload_id = $1`, wl) != 0 {
		t.Fatal("rejected registration wrote an instance")
	}

	wl, obs = a5IGAEvidence(f)
	f.exec(`UPDATE iga_workload SET classification = 'provider_native_agent' WHERE id = $1`, wl)
	raw = a5RegBody(t, 0, "invoice", owner, "", "native", obs, uuid.Nil)
	code, resp, body = api.post("/workloads/"+wl.String()+"/agent-registration", "a5p2-native", raw)
	if code != http.StatusOK || digs(body, "data", "workload_id") != wl.String() {
		t.Fatalf("provider_native_agent = %d %s", code, resp)
	}

	wl, obs = a5IGAEvidence(f)
	raw = a5RegBody(t, 0, "invoice", owner, "", "rescan", obs, uuid.Nil)
	code, resp, body = api.post("/workloads/"+wl.String()+"/agent-registration", "a5p2-rescan", raw)
	if code != http.StatusOK {
		t.Fatalf("register = %d %s", code, resp)
	}
	inst := digs(body, "data", "instance_id")
	again := uuid.New()
	f.exec(`INSERT INTO iga_observations
		(id, workspace_id, source_object_id, scan_run_id, mode, observed_at, dedupe_key)
		SELECT $1, workspace_id, source_object_id, scan_run_id, mode, now(), $2
		FROM iga_observations WHERE id = $3`, again, again.String(), obs)
	if f.scalar(`SELECT count(*) FROM iga_agent_instances WHERE id = $1 AND workload_id = $2 AND observation_id = $3`,
		uuid.MustParse(inst), wl, obs) != 1 {
		t.Fatal("a later observation deleted or rewrote the confirmed instance")
	}
}
