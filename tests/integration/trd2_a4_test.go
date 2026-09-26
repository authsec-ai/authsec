package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	igraph "github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

func (f *a3) projectDefault() {
	f.t.Helper()
	f.t.Setenv("IGA_V2_PROJECTION", "on")
	svc := services.NewProjectionService(f.g,
		repositories.NewIGAProjectionJobRepository(f.g),
		repositories.NewIGAPipelineLeaseRepository(f.g),
		f.graph, "proj", time.Minute)
	if _, err := svc.RunOnce(context.Background()); err != nil {
		f.t.Fatalf("project: %v", err)
	}
}

func (f *a3) seedFact(integ, run uuid.UUID, objectType, recognition, ref string, payload, fact any) {
	f.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		f.t.Fatal(err)
	}
	loc, _ := json.Marshal(map[string]string{"ref": ref})
	factBody := []byte(`{}`)
	if fact != nil {
		factBody, err = json.Marshal(fact)
		if err != nil {
			f.t.Fatal(err)
		}
	}
	var obj uuid.UUID
	err = f.db.QueryRow(`SELECT id FROM iga_source_objects
		WHERE workspace_id = $1 AND integration_id = $2 AND object_type = $3 AND recognition_key = $4`,
		f.ws, integ, objectType, recognition).Scan(&obj)
	if err != nil {
		obj = uuid.New()
		f.exec(`INSERT INTO iga_source_objects
			(id, workspace_id, integration_id, object_type, recognition_key, normalized_payload, locator)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, obj, f.ws, integ, objectType, recognition, body, loc)
	} else {
		f.exec(`UPDATE iga_source_objects SET normalized_payload = $1, locator = $2 WHERE workspace_id = $3 AND id = $4`,
			body, loc, f.ws, obj)
	}
	obs := uuid.New()
	f.exec(`INSERT INTO iga_observations
		(id, workspace_id, source_object_id, scan_run_id, mode, fact_payload, observed_at, dedupe_key)
		VALUES ($1,$2,$3,$4,'platform_declared',$5, now(), $6)`,
		obs, f.ws, obj, run, factBody, obs.String())
}

func TestTRD2ITM3RejectsInvalidPairs(t *testing.T) {
	f := newA3(t)
	_, err := f.db.Exec(`INSERT INTO iga_identity_accounts
		(id, workspace_id, display_name, account_kind, provider, source_key, first_seen_at, last_seen_at)
		VALUES ($1,$2,'bad','iam_role','linux','linux-bad', now(), now())`, uuid.New(), f.ws)
	if err == nil {
		t.Fatal("linux/iam_role was accepted")
	}
	_, err = f.db.Exec(`INSERT INTO iga_identity_accounts
		(id, workspace_id, display_name, account_kind, provider, source_key, first_seen_at, last_seen_at)
		VALUES ($1,$2,'bad','user','kubernetes','k8s-bad', now(), now())`, uuid.New(), f.ws)
	if err == nil {
		t.Fatal("kubernetes/user was accepted")
	}
	id := uuid.New()
	f.exec(`INSERT INTO iga_identity_accounts
		(id, workspace_id, display_name, account_kind, provider, source_key, first_seen_at, last_seen_at)
		VALUES ($1,$2,'sa','k8s_service_account','kubernetes','k8s-ok', now(), now())`, id, f.ws)

	other := uuid.New()
	f.exec(`INSERT INTO workspaces (id, name, slug) VALUES ($1,$2,$3)`, other, "other-"+other.String()[:8], "o"+other.String()[:8])
	foreignIdent := uuid.New()
	f.exec(`INSERT INTO iga_identity_accounts
		(id, workspace_id, display_name, account_kind, provider, source_key, first_seen_at, last_seen_at)
		VALUES ($1,$2,'foreign','k8s_service_account','kubernetes','k8s-foreign', now(), now())`, foreignIdent, other)
	wl := uuid.New()
	f.exec(`INSERT INTO iga_workload (id, workspace_id, runtime_kind, source_key, provider) VALUES ($1,$2,'pod',$3,'kubernetes')`, wl, f.ws, "wl-"+wl.String())
	wl2 := uuid.New()
	f.exec(`INSERT INTO iga_workload (id, workspace_id, runtime_kind, source_key, provider) VALUES ($1,$2,'pod',$3,'kubernetes')`, wl2, f.ws, "wl2-"+wl2.String())
	rt := uuid.New()
	f.exec(`INSERT INTO iga_runtime_instances (id, workspace_id, workload_id, runtime_key, runtime_kind, last_observed_at)
		VALUES ($1,$2,$3,'rt-a','container', now())`, rt, f.ws, wl)
	res := uuid.New()
	f.exec(`INSERT INTO iga_resources (id, workspace_id, resource_kind, source_key, provider) VALUES ($1,$2,'file',$3,'linux')`, res, f.ws, "res-"+res.String())
	obs := uuid.New()
	// observation needs a source object in this workspace
	obj := uuid.New()
	integ := uuid.New()
	f.exec(`INSERT INTO iga_integrations (id, workspace_id, provider, provider_host, app_registration_id, status)
		VALUES ($1,$2,'linux','local',$3,'active')`, integ, f.ws, integ.String())
	f.exec(`INSERT INTO iga_source_objects (id, workspace_id, integration_id, object_type, recognition_key) VALUES ($1,$2,$3,'linux.file','f')`, obj, f.ws, integ)
	scan := f.seedRun(integ, "runtime_batch", false)
	f.exec(`INSERT INTO iga_observations (id, workspace_id, source_object_id, scan_run_id, mode, observed_at, dedupe_key)
		VALUES ($1,$2,$3,$4,'platform_declared', now(), $5)`, obs, f.ws, obj, scan, obs.String())

	_, err = f.db.Exec(`INSERT INTO iga_observed_access
		(workspace_id, workload_id, runtime_instance_id, identity_account_id, resource_id, observation_id, action, outcome, observed_at)
		VALUES ($1,$2,$3,$4,$5,$6,'connect','success', now())`,
		f.ws, wl, rt, foreignIdent, res, obs)
	if err == nil {
		t.Fatal("cross-workspace identity was accepted")
	}
	_, err = f.db.Exec(`INSERT INTO iga_observed_access
		(workspace_id, workload_id, runtime_instance_id, resource_id, observation_id, action, outcome, observed_at)
		VALUES ($1,$2,$3,$4,$5,'connect','success', now())`,
		f.ws, wl2, rt, res, obs)
	if err == nil {
		t.Fatal("runtime instance of another workload was accepted")
	}
	f.exec(`INSERT INTO iga_observed_access
		(workspace_id, workload_id, runtime_instance_id, resource_id, observation_id, action, outcome, observed_at)
		VALUES ($1,$2,$3,$4,$5,'connect','success', now())`,
		f.ws, wl, rt, res, obs)
	_ = id
}

func TestTRD2ITLinuxAndK8sNormalizers(t *testing.T) {
	f := newA3(t)
	integ, collector, _ := f.seedCollector("linux")
	run := f.seedRun(integ, "runtime_batch", false)
	f.seedFact(integ, run, "linux.systemd_workload", "unit", "o_workload",
		map[string]any{"native": map[string]any{"unit": "invoice-worker.service"}, "attributes": map[string]any{"nftables": map[string]any{"chain": "output"}}},
		nil)
	f.seedFact(integ, run, "linux.local_account", "uid", "o_identity",
		map[string]any{"native": map[string]any{"uid": 995, "user_namespace": "host"}, "attributes": map[string]any{"name": "svc-invoice"}},
		nil)
	f.seedFact(integ, run, "network.endpoint", "db", "o_db",
		map[string]any{"native": map[string]any{"address": "10.20.0.15", "port": 5432, "protocol": "tcp", "address_family": "ipv4"}},
		map[string]any{"kind": "runtime.network_connect", "subject_ref": "o_workload", "identity_ref": "o_identity", "resource_ref": "o_db",
			"runtime": map[string]any{"boot_id": "boot-a", "pid_namespace": "host", "pid": 824, "start_ticks": 93401},
			"outcome": "success", "attribution": "kernel_process_credentials"})
	f.seedBatch(integ, collector, uuid.New(), run, 1, uuid.Nil)
	f.projectDefault()
	if f.scalar(`SELECT count(*) FROM iga_workload WHERE workspace_id = $1 AND provider = 'linux'`, f.ws) != 1 {
		t.Fatal("linux workload missing")
	}
	if f.scalar(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = $1 AND account_kind = 'local_user'`, f.ws) != 1 {
		t.Fatal("local user missing")
	}
	if f.scalar(`SELECT count(*) FROM iga_policy WHERE workspace_id = $1 AND policy_kind = 'linux_nftables'`, f.ws) != 1 {
		t.Fatal("nftables policy missing")
	}
	if f.scalar(`SELECT count(*) FROM iga_runtime_instances WHERE workspace_id = $1`, f.ws) != 1 {
		t.Fatal("runtime missing")
	}
	if f.scalar(`SELECT count(*) FROM iga_observed_access WHERE workspace_id = $1 AND outcome = 'success'`, f.ws) != 1 {
		t.Fatal("observed access missing")
	}
	if f.scalar(`SELECT count(*) FROM iga_runtime_identity_bindings WHERE workspace_id = $1 AND binding_kind = 'uid'`, f.ws) != 1 {
		t.Fatal("uid binding missing")
	}

	k8s, kcol, _ := f.seedCollector("kubernetes")
	krun := f.seedRun(k8s, "runtime_batch", false)
	f.seedFact(k8s, krun, "k8s.service_account", "sa", "sa",
		map[string]any{"native": map[string]any{"namespace": "pay", "name": "invoice", "uid": "sa-uid-1"}}, nil)
	f.seedFact(k8s, krun, "k8s.cluster_role", "view", "role",
		map[string]any{"native": map[string]any{"name": "view", "uid": "role-1", "rules": []any{map[string]any{
			"verbs": []any{"get"}, "resources": []any{"pods"}, "resourceNames": []any{"invoice"}, "nonResourceURLs": []any{"/healthz"},
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
			"annotations":        map[string]any{"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/invoice"},
		}}, nil)
	roleARN := "arn:aws:iam::123456789012:role/invoice"
	f.exec(`INSERT INTO iga_identity_accounts
		(id, workspace_id, display_name, account_kind, provider, source_key, first_seen_at, last_seen_at)
		VALUES ($1,$2,'invoice','iam_role','aws',$3, now(), now())`,
		uuid.New(), f.ws, igraph.IdentityARNKey(roleARN))
	f.seedBatch(k8s, kcol, uuid.New(), krun, 1, uuid.Nil)
	f.projectDefault()
	if f.scalar(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = $1 AND provider = 'aws'`, f.ws) != 1 {
		t.Fatal("role annotation fabricated an AWS identity")
	}
	if f.scalar(`SELECT count(*) FROM iga_relationship WHERE workspace_id = $1 AND relationship_type = 'can_assume'`, f.ws) != 0 {
		t.Fatal("annotation became can_assume")
	}
	if f.scalar(`SELECT count(*) FROM iga_relationship r
		JOIN iga_identity_accounts i ON i.workspace_id = r.workspace_id AND i.id = r.target_identity_account_id
		WHERE r.workspace_id = $1 AND r.relationship_type = 'executes_as' AND r.basis = 'declared' AND i.provider = 'aws'`, f.ws) != 1 {
		t.Fatal("existing AWS role was not joined by a declared executes_as")
	}
	if f.scalar(`SELECT count(*) FROM iga_relationship WHERE workspace_id = $1 AND relationship_type = 'executes_as' AND basis = 'declared'`, f.ws) != 2 {
		t.Fatal("declared executes_as missing")
	}
	var scope, ns string
	f.scan(`SELECT assignment_scope_kind, namespace_uid FROM iga_policy_assignment WHERE workspace_id = $1`, []any{f.ws}, &scope, &ns)
	if scope != "namespace" || ns != "ns-pay" {
		t.Fatalf("binding scope %s namespace %s", scope, ns)
	}
	if f.scalar(`SELECT count(*) FROM iga_access_edges WHERE workspace_id = $1 AND provider = 'kubernetes' AND calculation_state = 'partial' AND effective_conclusion = 'unknown'`, f.ws) != 1 {
		t.Fatal("k8s grant was not partial/unknown")
	}
}

func TestTRD2ITADRenameDisabledAndNoSecret(t *testing.T) {
	f := newA3(t)
	integ, collector, _ := f.seedCollector("ad")
	run := f.seedRun(integ, "runtime_batch", false)
	forest := "DC=authsec,DC=test"
	f.seedFact(integ, run, "user", "ada", "", map[string]any{
		"account_kind": "ad_user", "object_guid": "11111111-1111-1111-1111-111111111111",
		"object_sid": "S-1-5-21-1", "distinguished_name": "CN=ada,DC=test", "sam_account_name": "ada",
		"forest_id": forest, "msDS-ManagedPassword": "CANARY-SECRET-DO-NOT-LEAK-3",
	}, nil)
	f.seedFact(integ, run, "user", "off", "", map[string]any{
		"account_kind": "ad_user", "object_guid": "22222222-2222-2222-2222-222222222222",
		"distinguished_name": "CN=off,DC=test", "sam_account_name": "off", "forest_id": forest,
		"account_flags": map[string]any{"account_disabled": true},
	}, nil)
	f.seedFact(integ, run, "group", "eng", "", map[string]any{
		"account_kind": "ad_group", "object_guid": "33333333-3333-3333-3333-333333333333",
		"distinguished_name": "CN=eng,DC=test", "sam_account_name": "eng", "forest_id": forest,
		"member": []string{"CN=ada,DC=test"},
	}, nil)
	f.seedFact(integ, run, "computer", "host", "", map[string]any{
		"account_kind": "ad_computer", "object_guid": "55555555-5555-5555-5555-555555555555",
		"distinguished_name": "CN=host,DC=test", "forest_id": forest,
	}, nil)
	f.seedFact(integ, run, "msDS-GroupManagedServiceAccount", "msa", "", map[string]any{
		"account_kind": "ad_managed_service_account", "object_guid": "66666666-6666-6666-6666-666666666666",
		"distinguished_name": "CN=msa,DC=test", "forest_id": forest,
	}, nil)
	f.seedBatch(integ, collector, uuid.New(), run, 1, uuid.Nil)
	f.projectDefault()
	if f.scalar(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = $1 AND provider = 'ad'`, f.ws) != 5 {
		t.Fatalf("ad identities %d", f.scalar(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = $1 AND provider = 'ad'`, f.ws))
	}
	if f.scalar(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = $1 AND account_state = 'disabled' AND lifecycle = 'active'`, f.ws) != 1 {
		t.Fatal("disabled account was retired or not marked")
	}
	var attrs string
	f.scan(`SELECT coalesce(string_agg(provider_attrs::text, ''), '') FROM iga_identity_accounts WHERE workspace_id = $1`, []any{f.ws}, &attrs)
	if strings.Contains(attrs, "CANARY-SECRET-DO-NOT-LEAK") {
		t.Fatal("secret attribute reached a canonical row")
	}
	var key string
	f.scan(`SELECT source_key FROM iga_identity_accounts WHERE workspace_id = $1 AND display_name = 'ada'`, []any{f.ws}, &key)
	run2 := f.seedRun(integ, "runtime_batch", false)
	f.seedFact(integ, run2, "user", "ada", "", map[string]any{
		"account_kind": "ad_user", "object_guid": "11111111-1111-1111-1111-111111111111",
		"distinguished_name": "CN=ada-renamed,DC=test", "sam_account_name": "ada2", "display_name": "ada2",
		"forest_id": forest,
	}, nil)
	f.seedBatch(integ, collector, uuid.New(), run2, 2, uuid.Nil)
	f.projectDefault()
	var key2, name string
	f.scan(`SELECT source_key, display_name FROM iga_identity_accounts WHERE workspace_id = $1 AND immutable_key = '11111111-1111-1111-1111-111111111111' AND lifecycle = 'active'`,
		[]any{f.ws}, &key2, &name)
	if key2 != key || name != "ada2" {
		t.Fatalf("rename key %s->%s name %s", key, key2, name)
	}
}

func TestTRD2ITT08SharedSupportAndPartial(t *testing.T) {
	f := newA3(t)
	aInteg, aCol, aScope := f.seedCollector("linux")
	bInteg, bCol, _ := f.seedCollector("linux")
	f.exec(`UPDATE collector_instances SET estate_scope_id = $1 WHERE id = $2`, aScope, bCol)
	unit := map[string]any{"native": map[string]any{"unit": "invoice-worker.service"}}
	projectSnap := func(integ, col uuid.UUID, class string, complete bool, payload map[string]any) {
		f.t.Helper()
		epoch := uuid.New()
		snap := f.seedSnapshot(col, epoch, "host", class, complete, 1)
		run := f.seedRun(integ, "configuration_snapshot", complete)
		if payload != nil {
			f.seedFact(integ, run, class, "obj", "o", payload, nil)
		}
		f.seedBatch(integ, col, epoch, run, 1, snap)
		f.projectDefault()
	}
	projectSnap(aInteg, aCol, "linux.systemd_workload", true, unit)
	projectSnap(bInteg, bCol, "linux.systemd_workload", true, unit)
	if f.scalar(`SELECT count(*) FROM iga_workload WHERE workspace_id = $1 AND lifecycle = 'active'`, f.ws) != 1 {
		t.Fatal("shared unit became two workloads")
	}
	if f.scalar(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND state = 'current'`, f.ws) != 2 {
		t.Fatal("both sources should vouch")
	}
	projectSnap(aInteg, aCol, "linux.systemd_workload", true, nil)
	if f.scalar(`SELECT count(*) FROM iga_workload WHERE workspace_id = $1 AND lifecycle = 'active'`, f.ws) != 1 {
		t.Fatal("one remaining source retired the workload")
	}
	projectSnap(bInteg, bCol, "linux.systemd_workload", true, nil)
	if f.scalar(`SELECT count(*) FROM iga_workload WHERE workspace_id = $1 AND lifecycle = 'retired' AND retired_reason = 'unsupported'`, f.ws) != 1 {
		t.Fatal("last source did not retire the workload")
	}

	cInteg, cCol, _ := f.seedCollector("linux")
	f.exec(`UPDATE collector_instances SET estate_scope_id = $1 WHERE id = $2`, aScope, cCol)
	projectSnap(cInteg, cCol, "linux.systemd_workload", true, map[string]any{"native": map[string]any{"unit": "keep.service"}})
	projectSnap(cInteg, cCol, "linux.systemd_workload", false, map[string]any{"native": map[string]any{"unit": "other.service"}})
	if f.scalar(`SELECT count(*) FROM iga_workload WHERE workspace_id = $1 AND display_name = 'keep.service' AND lifecycle = 'active'`, f.ws) != 1 {
		t.Fatal("partial snapshot retired an omitted workload")
	}
}

func TestTRD2ITRuntimeTTLDoesNotCrossPartitions(t *testing.T) {
	f := newA3(t)
	f.t.Setenv("IGA_V2_RUNTIME_SUPPORT_TTL", "1h")
	integ, collector, _ := f.seedCollector("linux")
	run := f.seedRun(integ, "runtime_batch", false)
	f.seedFact(integ, run, "linux.process_group", "g1", "g",
		map[string]any{"native": map[string]any{"boot_id": "boot", "root_pid": "10", "start_ticks": "1"}}, nil)
	f.seedBatch(integ, collector, uuid.New(), run, 1, uuid.Nil)
	f.projectDefault()
	f.exec(`UPDATE iga_object_support SET last_confirmed_at = now() - interval '2 hours' WHERE workspace_id = $1`, f.ws)
	f.exec(`UPDATE iga_runtime_instances SET last_observed_at = now() - interval '2 hours' WHERE workspace_id = $1`, f.ws)
	run2 := f.seedRun(integ, "runtime_batch", false)
	f.seedFact(integ, run2, "linux.process_group", "g2", "g2",
		map[string]any{"native": map[string]any{"boot_id": "boot", "root_pid": "11", "start_ticks": "2"}}, nil)
	f.seedBatch(integ, collector, uuid.New(), run2, 2, uuid.Nil)
	f.projectDefault()
	if f.scalar(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND ended_reason = 'runtime_unobserved'`, f.ws) != 1 {
		t.Fatal("stale runtime support did not age out")
	}
	if f.scalar(`SELECT count(*) FROM iga_workload WHERE workspace_id = $1 AND display_name = '10' AND lifecycle = 'retired'`, f.ws) != 1 {
		t.Fatal("runtime-only workload was not retired")
	}

	snapInteg, snapCol, scope := f.seedCollector("linux")
	f.exec(`UPDATE collector_instances SET estate_scope_id = $1 WHERE id = $2`, scope, collector)
	epoch := uuid.New()
	snap := f.seedSnapshot(snapCol, epoch, "host", "linux.systemd_workload", true, 1)
	srun := f.seedRun(snapInteg, "configuration_snapshot", true)
	f.seedFact(snapInteg, srun, "linux.systemd_workload", "unit", "o",
		map[string]any{"native": map[string]any{"unit": "both.service"}}, nil)
	f.seedBatch(snapInteg, snapCol, epoch, srun, 1, snap)
	rrun := f.seedRun(integ, "runtime_batch", false)
	f.seedFact(integ, rrun, "linux.process_group", "child", "c",
		map[string]any{"native": map[string]any{"boot_id": "boot", "root_pid": "12", "start_ticks": "3"}}, nil)
	f.seedBatch(integ, collector, uuid.New(), rrun, 3, uuid.Nil)
	f.projectDefault()
	// Snapshot absence of the unit must not end the process-group runtime support,
	// and a runtime pass must not end the snapshot support.
	epoch2 := uuid.New()
	snap2 := f.seedSnapshot(snapCol, epoch2, "host", "linux.systemd_workload", true, 2)
	srun2 := f.seedRun(snapInteg, "configuration_snapshot", true)
	f.seedBatch(snapInteg, snapCol, epoch2, srun2, 1, snap2)
	f.projectDefault()
	if f.scalar(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND partition_key = 'collector/object' AND state = 'current'`, f.ws) == 0 {
		t.Fatal("snapshot absence ended runtime support")
	}
	if f.scalar(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND ended_reason = 'absent' AND partition_key = 'collector/object'`, f.ws) != 0 {
		t.Fatal("runtime partition ended with snapshot absence")
	}
}

func TestTRD2ITSnapshotCollectorsStayIsolated(t *testing.T) {
	f := newA3(t)
	aInteg, aCol, scope := f.seedCollector("linux")
	bInteg, bCol, _ := f.seedCollector("linux")
	f.exec(`UPDATE collector_instances SET estate_scope_id = $1 WHERE id = $2`, scope, bCol)
	snap := uuid.New()
	epoch := uuid.New()
	for _, side := range []struct {
		integ, col uuid.UUID
		unit       string
	}{
		{aInteg, aCol, "a.service"},
		{bInteg, bCol, "b.service"},
	} {
		f.exec(`INSERT INTO collector_snapshots
			(id, workspace_id, collector_id, snapshot_id, epoch, scope_key, object_class, generation, expected_chunks, complete, gap_blocked)
			VALUES ($1,$2,$3,$4,$5,'host','linux.systemd_workload',1,1,true,false)`,
			uuid.New(), f.ws, side.col, snap, epoch)
		run := f.seedRun(side.integ, "configuration_snapshot", true)
		f.seedFact(side.integ, run, "linux.systemd_workload", side.unit, "o",
			map[string]any{"native": map[string]any{"unit": side.unit}}, nil)
		f.seedBatch(side.integ, side.col, epoch, run, 1, snap)
	}
	f.projectDefault()
	var aSupport, bSupport int
	f.scan(`SELECT
		(SELECT count(*) FROM iga_object_support s JOIN iga_workload w ON w.id = s.workload_id
		  WHERE s.integration_id = $1 AND w.display_name = 'b.service'),
		(SELECT count(*) FROM iga_object_support s JOIN iga_workload w ON w.id = s.workload_id
		  WHERE s.integration_id = $2 AND w.display_name = 'a.service')`,
		[]any{aInteg, bInteg}, &aSupport, &bSupport)
	if aSupport != 0 || bSupport != 0 {
		t.Fatalf("colliding snapshot_id crossed collectors: a saw b=%d b saw a=%d", aSupport, bSupport)
	}
}

func TestTRD2ITT07RecreateCloneAndPID(t *testing.T) {
	f := newA3(t)
	k8s, col, scope := f.seedCollector("kubernetes")
	run := f.seedRun(k8s, "runtime_batch", false)
	f.seedFact(k8s, run, "k8s.service_account", "sa", "sa",
		map[string]any{"native": map[string]any{"namespace": "pay", "name": "invoice", "uid": "uid-old"}}, nil)
	f.seedBatch(k8s, col, uuid.New(), run, 1, uuid.Nil)
	f.projectDefault()
	var oldID uuid.UUID
	f.scan(`SELECT id FROM iga_identity_accounts WHERE workspace_id = $1 AND immutable_key = 'uid-old'`, []any{f.ws}, &oldID)
	run2 := f.seedRun(k8s, "runtime_batch", false)
	f.seedFact(k8s, run2, "k8s.service_account", "sa", "sa",
		map[string]any{"native": map[string]any{"namespace": "pay", "name": "invoice", "uid": "uid-new"}}, nil)
	f.seedBatch(k8s, col, uuid.New(), run2, 2, uuid.Nil)
	f.projectDefault()
	var newID uuid.UUID
	var reason string
	f.scan(`SELECT id FROM iga_identity_accounts WHERE workspace_id = $1 AND immutable_key = 'uid-new' AND lifecycle = 'active'`, []any{f.ws}, &newID)
	f.scan(`SELECT retired_reason FROM iga_identity_accounts WHERE id = $1`, []any{oldID}, &reason)
	if newID == oldID || reason != models.RetiredRecreated {
		t.Fatalf("recreate id old %s new %s reason %s", oldID, newID, reason)
	}

	linux, lcol, _ := f.seedCollector("linux")
	f.exec(`UPDATE collector_instances SET estate_scope_id = $1 WHERE id = $2`, scope, lcol)
	otherScope := uuid.New()
	f.exec(`INSERT INTO iga_estate_scopes (id, workspace_id, scope_kind, source_key, display_name) VALUES ($1,$2,'host',$3,'clone')`,
		otherScope, f.ws, "clone-"+otherScope.String())
	_, lcol2, _ := f.seedCollector("linux")
	f.exec(`UPDATE collector_instances SET estate_scope_id = $1 WHERE id = $2`, otherScope, lcol2)
	var integ2 uuid.UUID
	f.scan(`SELECT integration_id FROM collector_instances WHERE id = $1`, []any{lcol2}, &integ2)
	for _, side := range []struct {
		col, integ uuid.UUID
	}{{lcol, linux}, {lcol2, integ2}} {
		run := f.seedRun(side.integ, "runtime_batch", false)
		f.seedFact(side.integ, run, "linux.local_account", "u", "u",
			map[string]any{"native": map[string]any{"uid": 1000, "user_namespace": "host", "machine_id": "cloned"}, "attributes": map[string]any{"name": "svc"}}, nil)
		f.seedBatch(side.integ, side.col, uuid.New(), run, 1, uuid.Nil)
		f.projectDefault()
	}
	if f.scalar(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = $1 AND provider = 'linux' AND account_kind = 'local_user'`, f.ws) != 2 {
		t.Fatal("cloned machine-id collapsed two estates")
	}

	prun := f.seedRun(linux, "runtime_batch", false)
	for _, ticks := range []string{"100", "200"} {
		f.seedFact(linux, prun, "linux.process_group", "pid-"+ticks, "p"+ticks,
			map[string]any{"native": map[string]any{"boot_id": "boot", "root_pid": "9", "start_ticks": ticks}}, nil)
	}
	f.seedBatch(linux, lcol, uuid.New(), prun, 2, uuid.Nil)
	f.projectDefault()
	if f.scalar(`SELECT count(*) FROM iga_workload WHERE workspace_id = $1 AND provider = 'linux' AND runtime_kind = 'process_group'`, f.ws) != 2 {
		t.Fatal("PID reuse with different start ticks collapsed")
	}
}

func TestTRD2ITMigration041Rehearsal(t *testing.T) {
	dsn := "postgres://postgres:postgres@localhost:5432/authsec?sslmode=disable"
	if v := getenvIGA(); v != "" {
		dsn = v
	}
	db := openFreshDB(t, dsn, "authsec_it_a4mig")
	applyMaster(t, db, false)
	applyFile(t, db, "../../migrations/master/041_trd2_runtime_graph.sql")
	execDB(t, db, `CREATE TABLE IF NOT EXISTS runtime_policies (id uuid primary key)`)
	execDB(t, db, `CREATE TABLE IF NOT EXISTS discovered_agent_workloads (id uuid primary key)`)
	applyFile(t, db, "../../migrations/master/041_trd2_runtime_graph.sql")
	applyFile(t, db, "../../scripts/validate-041-runtime-graph.sql")
	if !constraintValidated(t, db, "iga_identity_accounts_provider_kind_chk") {
		t.Fatal("041 check was not validated")
	}
	if !constraintValidated(t, db, "iga_pa_estate_scope_fkey") {
		t.Fatal("041 foreign key was not validated")
	}
}

func getenvIGA() string {
	return ""
}
