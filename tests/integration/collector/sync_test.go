package collector

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/pkg/collectorcontract"
	"github.com/google/uuid"
)

const canary = "CANARY-SECRET-DO-NOT-LEAK-1"

func TestSync_HeartbeatReceiptAndEvidence(t *testing.T) {
	resetSync(t)
	ws := newWorkspace(t)
	en := enrollCollector(t, ws, "linux_collector", "", nil)
	epoch := uuid.NewString()
	body := syncBody(t, 1, epoch, uuid.NewString(),
		[]collectorcontract.Object{{
			Ref: "o_unit", Kind: "linux.systemd_workload",
			Native: map[string]any{"unit": "invoice-worker.service"},
		}},
		[]collectorcontract.Observation{{
			EventID: "e-1", Kind: "runtime.process_exec", SubjectRef: "o_unit",
			ObservedAt: "2026-09-25T07:59:58Z", Outcome: "success",
		}},
		nil,
		[]collectorcontract.AppliedReceipt{{
			WorkloadID: uuid.NewString(), DeliveryRevision: 1, RuntimeGeneration: "run-1",
			State: "verified", ObservedAt: "2026-09-25T08:00:00Z",
			Controls: []collectorcontract.ControlReceipt{{
				Kind: "linux.netns_egress", State: "verified",
				ArtifactSHA256: strings.Repeat("ab", 32), Test: "allow_and_deny_endpoints_verified",
			}},
		}},
		nil,
	)
	res := postSync(en.Credential, body, nil)
	resp := mustSyncOK(t, res)
	if string(resp.Desired) != "null" || resp.ReceiptState != "accepted" || resp.ProjectionState != "queued" {
		t.Fatalf("receipt = %+v desired %s", resp, resp.Desired)
	}
	if resp.NextSyncSeconds != 15 || resp.PublishedGraphRevision != 0 {
		t.Fatalf("revision/next = %d %d", resp.PublishedGraphRevision, resp.NextSyncSeconds)
	}
	if resp.MappingURL != "/api/iga/v2/receipts/"+resp.ReceiptID {
		t.Fatalf("mapping url %s", resp.MappingURL)
	}
	if countRows(t, "collector_batches", ws) != 1 || countRows(t, "collector_outbox", ws) != 1 {
		t.Fatalf("batch=%d outbox=%d", countRows(t, "collector_batches", ws), countRows(t, "collector_outbox", ws))
	}
	assertNoCanonical(t, ws)

	var trust, schema, norm, mode string
	if err := db.Raw(`SELECT evidence_trust, schema_version, normalizer_version, mode
		FROM iga_observations WHERE workspace_id = ? AND evidence_ref = 'e-1'`, ws).
		Row().Scan(&trust, &schema, &norm, &mode); err != nil {
		t.Fatal(err)
	}
	if trust != "authenticated_collector" || schema != "2.0" ||
		norm != collectorcontract.NormalizerVersion || mode != "runtime_batch" {
		t.Fatalf("evidence trust=%s schema=%s norm=%s mode=%s", trust, schema, norm, mode)
	}
	var nativeID, recKey string
	if err := db.Raw(`SELECT native_id, recognition_key FROM iga_source_objects
		WHERE workspace_id = ? AND object_type = 'linux.systemd_workload'`, ws).Row().Scan(&nativeID, &recKey); err != nil {
		t.Fatal(err)
	}
	if nativeID == "o_unit" || !strings.HasPrefix(recKey, "linux.systemd_workload:") {
		t.Fatalf("recognition leaked a client id: %s %s", nativeID, recKey)
	}
	var applied int64
	if err := db.Raw(`SELECT count(*) FROM iga_source_objects WHERE workspace_id = ? AND object_type = 'applied_receipt'`, ws).Scan(&applied).Error; err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("applied source objects = %d", applied)
	}

	got := do(http.MethodGet, "/api/iga/v2/receipts/"+resp.ReceiptID, en.Credential, "", "", nil)
	if got.code != http.StatusOK {
		t.Fatalf("get receipt: %d %s", got.code, got.body)
	}
	var view collectorcontract.ReceiptView
	if err := json.Unmarshal(got.body, &view); err != nil {
		t.Fatal(err)
	}
	if view.State != "accepted" || view.ProjectionState != "queued" || view.Mappings == nil || len(view.Mappings) != 0 {
		t.Fatalf("view = %+v", view)
	}

	empty := syncBody(t, 2, epoch, uuid.NewString(), nil, nil, nil, nil, nil)
	emptyRes := postSync(en.Credential, empty, nil)
	mustSyncOK(t, emptyRes)
	if countRows(t, "iga_observations", ws) != 2 { // one runtime fact + one applied receipt
		t.Fatalf("heartbeat created observations: %d", countRows(t, "iga_observations", ws))
	}
}

func TestT03_ReplayAndConflict(t *testing.T) {
	resetSync(t)
	ws := newWorkspace(t)
	en := enrollCollector(t, ws, "linux_collector", "", nil)
	epoch := uuid.NewString()
	body := syncBody(t, 1, epoch, uuid.NewString(), nil, nil, nil, nil, nil)
	first := mustSyncOK(t, postSync(en.Credential, body, nil))
	second := mustSyncOK(t, postSync(en.Credential, body, nil))
	if first.ReceiptID != second.ReceiptID || first.AcceptedSequence != second.AcceptedSequence {
		t.Fatalf("replay changed receipt %s %s", first.ReceiptID, second.ReceiptID)
	}
	if countRows(t, "collector_batches", ws) != 1 {
		t.Fatalf("replay stored a second batch: %d", countRows(t, "collector_batches", ws))
	}
	var altered map[string]any
	if err := json.Unmarshal(body, &altered); err != nil {
		t.Fatal(err)
	}
	altered["sent_at"] = "2026-09-25T08:00:01Z"
	changed, _ := json.Marshal(altered)
	got := postSync(en.Credential, changed, nil)
	if got.code != http.StatusConflict {
		t.Fatalf("changed payload: %d %s persist=%v", got.code, got.body, syncSvc.LastPersistErr)
	}
	if countRows(t, "collector_batches", ws) != 1 {
		t.Fatalf("conflict stored a batch: %d", countRows(t, "collector_batches", ws))
	}
}

func TestT04_IncompleteSnapshotDoesNotEndSupport(t *testing.T) {
	resetSync(t)
	ws := newWorkspace(t)
	en := enrollCollector(t, ws, "linux_collector", "", nil)
	epoch := uuid.NewString()
	objects := []collectorcontract.Object{{
		Ref: "o_unit", Kind: "linux.systemd_workload", Native: map[string]any{"unit": "invoice-worker.service"},
	}}
	snapID := uuid.NewString()
	// Chunk 1 is never sent. The terminal chunk claims complete.
	snap := digestSnap(t, objects, collectorcontract.Snapshot{
		SnapshotID: snapID, CollectorEpoch: epoch, ScopeKey: "host", ObjectClass: "linux.systemd_workload",
		Generation: 1, ChunkNo: 2, TerminalChunkCount: 2, Complete: true,
	})
	body := syncBody(t, 1, epoch, uuid.NewString(), objects, nil, snap, nil, nil)
	mustSyncOK(t, postSync(en.Credential, body, nil))
	complete, blocked := snapshotFlags(t, ws, snapID)
	if complete || blocked {
		t.Fatalf("dropped chunk marked complete=%v gap=%v", complete, blocked)
	}
	assertNoCanonical(t, ws)
	if countRows(t, "iga_object_support", ws) != 0 {
		t.Fatal("incomplete snapshot wrote object support")
	}
}

func TestSync_SnapshotCompletesWithoutGraphWrites(t *testing.T) {
	resetSync(t)
	ws := newWorkspace(t)
	en := enrollCollector(t, ws, "linux_collector", "", nil)
	epoch := uuid.NewString()
	objects := []collectorcontract.Object{{
		Ref: "o_unit", Kind: "linux.systemd_workload", Native: map[string]any{"unit": "invoice-worker.service"},
	}}
	snapID := uuid.NewString()
	base := collectorcontract.Snapshot{
		SnapshotID: snapID, CollectorEpoch: epoch, ScopeKey: "host", ObjectClass: "linux.systemd_workload",
		Generation: 1, TerminalChunkCount: 2,
	}
	chunk := func(n int, seq int64, complete bool) {
		t.Helper()
		s := base
		s.ChunkNo = n
		s.Complete = complete
		body := syncBody(t, seq, epoch, uuid.NewString(), objects, nil, digestSnap(t, objects, s), nil, nil)
		mustSyncOK(t, postSync(en.Credential, body, nil))
	}
	chunk(1, 1, false)
	complete, _ := snapshotFlags(t, ws, snapID)
	if complete {
		t.Fatal("snapshot complete after one of two chunks")
	}
	chunk(2, 2, true)
	complete, blocked := snapshotFlags(t, ws, snapID)
	if !complete || blocked {
		t.Fatalf("full snapshot complete=%v gap=%v", complete, blocked)
	}
	assertNoCanonical(t, ws)

	// Same chunk bytes are a replay of the chunk, not a new generation.
	chunk(1, 3, true)
	var chunks int64
	if err := db.Raw(`SELECT count(*) FROM collector_snapshot_chunks c
		JOIN collector_snapshots s ON s.workspace_id = c.workspace_id AND s.id = c.snapshot_row_id
		WHERE s.workspace_id = ? AND s.snapshot_id = ?`, ws, snapID).Scan(&chunks).Error; err != nil {
		t.Fatal(err)
	}
	if chunks != 2 {
		t.Fatalf("duplicate chunk stored again: %d", chunks)
	}

	changed := objects
	changed[0].Native = map[string]any{"unit": "other.service"}
	s := base
	s.ChunkNo = 1
	s.Complete = true
	bad := syncBody(t, 4, epoch, uuid.NewString(), changed, nil, digestSnap(t, changed, s), nil, nil)
	got := postSync(en.Credential, bad, nil)
	if got.code != http.StatusConflict {
		t.Fatalf("changed chunk: %d %s persist=%v", got.code, got.body, syncSvc.LastPersistErr)
	}

	wrong := digestSnap(t, objects, base)
	wrong.ChunkNo = 1
	wrong.Digest = strings.Repeat("0", 64)
	mismatch := syncBody(t, 5, epoch, uuid.NewString(), objects, nil, wrong, nil, nil)
	got = postSync(en.Credential, mismatch, nil)
	if got.code != http.StatusUnprocessableEntity || !strings.Contains(string(got.body), "snapshot.digest") {
		t.Fatalf("digest mismatch: %d %s", got.code, got.body)
	}
}

func TestSync_SequenceGapDoesNotDelete(t *testing.T) {
	resetSync(t)
	ws := newWorkspace(t)
	en := enrollCollector(t, ws, "linux_collector", "", nil)
	epoch := uuid.NewString()
	objects := []collectorcontract.Object{{
		Ref: "o_unit", Kind: "linux.systemd_workload", Native: map[string]any{"unit": "invoice-worker.service"},
	}}
	snapID := uuid.NewString()
	snap := digestSnap(t, objects, collectorcontract.Snapshot{
		SnapshotID: snapID, CollectorEpoch: epoch, ScopeKey: "host", ObjectClass: "linux.systemd_workload",
		Generation: 1, ChunkNo: 1, TerminalChunkCount: 1, Complete: true,
	})
	mustSyncOK(t, postSync(en.Credential, syncBody(t, 1, epoch, uuid.NewString(), objects, nil, snap, nil, nil), nil))
	before := countRows(t, "iga_source_objects", ws)
	if before < 1 {
		t.Fatal("expected source objects")
	}
	complete, _ := snapshotFlags(t, ws, snapID)
	if !complete {
		t.Fatal("single chunk snapshot should be complete before the gap")
	}
	// Sequence 3 leaves 2 missing. The gap is recorded and the snapshot is
	// incomplete, but earlier objects stay.
	mustSyncOK(t, postSync(en.Credential, syncBody(t, 3, epoch, uuid.NewString(), nil, nil, nil, nil, nil), nil))
	complete, blocked := snapshotFlags(t, ws, snapID)
	if complete || !blocked {
		t.Fatalf("after gap complete=%v blocked=%v", complete, blocked)
	}
	var gaps int64
	if err := db.Raw(`SELECT count(*) FROM collector_sequence_gaps WHERE workspace_id = ? AND expected_sequence = 2 AND received_sequence = 3`, ws).Scan(&gaps).Error; err != nil {
		t.Fatal(err)
	}
	if gaps != 1 {
		t.Fatalf("gaps = %d", gaps)
	}
	if countRows(t, "iga_source_objects", ws) < before {
		t.Fatalf("gap deleted source objects: before %d now %d", before, countRows(t, "iga_source_objects", ws))
	}
	assertNoCanonical(t, ws)
}

func TestSync_ObservationDedup(t *testing.T) {
	resetSync(t)
	ws := newWorkspace(t)
	en := enrollCollector(t, ws, "linux_collector", "", nil)
	epoch := uuid.NewString()
	obs := []collectorcontract.Observation{{
		EventID: "e-same", Kind: "collector.health", ObservedAt: "2026-09-25T08:00:00Z", Outcome: "unknown",
	}}
	mustSyncOK(t, postSync(en.Credential, syncBody(t, 1, epoch, uuid.NewString(), nil, obs, nil, nil, nil), nil))
	mustSyncOK(t, postSync(en.Credential, syncBody(t, 2, epoch, uuid.NewString(), nil, obs, nil, nil, nil), nil))
	var n int64
	if err := db.Raw(`SELECT count(*) FROM iga_observations WHERE workspace_id = ? AND evidence_ref = 'e-same'`, ws).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("duplicate event stored %d times", n)
	}
}

func TestSync_PayloadLimitsAndSchema(t *testing.T) {
	resetSync(t)
	ws := newWorkspace(t)
	en := enrollCollector(t, ws, "linux_collector", "", nil)
	epoch := uuid.NewString()

	huge := bytes.Repeat([]byte("a"), int(collectorcontract.DecompressedMaxBytes)+1)
	got := postSync(en.Credential, huge, nil)
	if got.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: %d %s", got.code, got.body)
	}

	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(bytes.Repeat([]byte{0}, int(collectorcontract.DecompressedMaxBytes)+1)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	got = postSync(en.Credential, compressed.Bytes(), map[string]string{"Content-Encoding": "gzip"})
	if got.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("gzip bomb: %d %s", got.code, got.body)
	}
	over := bytes.Repeat([]byte("z"), int(collectorcontract.CompressedMaxBytes)+1)
	got = postSync(en.Credential, over, map[string]string{"Content-Encoding": "gzip"})
	if got.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("gzip cap: %d %s", got.code, got.body)
	}

	plain := syncBody(t, 1, epoch, uuid.NewString(), nil, nil, nil, nil, nil)
	var gz bytes.Buffer
	zw = gzip.NewWriter(&gz)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	mustSyncOK(t, postSync(en.Credential, gz.Bytes(), map[string]string{"Content-Encoding": "gzip"}))

	old := syncBody(t, 2, epoch, uuid.NewString(), nil, nil, nil, nil, map[string]any{"schema_version": "1.0"})
	got = postSync(en.Credential, old, nil)
	if got.code != http.StatusUpgradeRequired || !strings.Contains(string(got.body), `"2.0"`) {
		t.Fatalf("426: %d %s", got.code, got.body)
	}

	badKind := syncBody(t, 3, epoch, uuid.NewString(), []collectorcontract.Object{{
		Ref: "o_x", Kind: "linux.not_a_kind", Native: map[string]any{"name": "x"},
	}}, nil, nil, nil, nil)
	got = postSync(en.Credential, badKind, nil)
	if got.code != http.StatusUnprocessableEntity || !strings.Contains(string(got.body), "unknown object kind") {
		t.Fatalf("422: %d %s", got.code, got.body)
	}
	if countRows(t, "collector_batches", ws) != 1 {
		t.Fatalf("rejected bodies stored batches: %d", countRows(t, "collector_batches", ws))
	}
}

func TestSync_QuotaReplayAndStorageFailure(t *testing.T) {
	resetSync(t)
	ws := newWorkspace(t)
	en := enrollCollector(t, ws, "linux_collector", "", nil)
	epoch := uuid.NewString()
	syncSvc.QuotaPerMinute = 1
	body := syncBody(t, 1, epoch, uuid.NewString(), nil, nil, nil, nil, nil)
	first := mustSyncOK(t, postSync(en.Credential, body, nil))
	replay := mustSyncOK(t, postSync(en.Credential, body, nil))
	if replay.ReceiptID != first.ReceiptID {
		t.Fatal("quota blocked an identical replay")
	}
	again := syncBody(t, 2, epoch, uuid.NewString(), nil, nil, nil, nil, nil)
	got := postSync(en.Credential, again, nil)
	if got.code != http.StatusTooManyRequests || got.hdr.Get("Retry-After") == "" {
		t.Fatalf("429: %d retry=%q %s", got.code, got.hdr.Get("Retry-After"), got.body)
	}

	syncSvc.QuotaPerMinute = 120
	syncSvc.FailBeforeCommit = func() error { return errors.New("disk unavailable") }
	ws2 := newWorkspace(t)
	en2 := enrollCollector(t, ws2, "linux_collector", "", nil)
	got = postSync(en2.Credential, syncBody(t, 1, uuid.NewString(), uuid.NewString(), nil, nil, nil, nil, nil), nil)
	if got.code != http.StatusServiceUnavailable {
		t.Fatalf("503: %d %s persist=%v", got.code, got.body, syncSvc.LastPersistErr)
	}
	if strings.Contains(string(got.body), "disk") {
		t.Fatalf("503 echoed the storage error: %s", got.body)
	}
	if countRows(t, "collector_batches", ws2) != 0 || countRows(t, "collector_outbox", ws2) != 0 {
		t.Fatal("failed commit left a receipt")
	}
}

func TestT01_SyncTenantBoundary(t *testing.T) {
	resetSync(t)
	ws := newWorkspace(t)
	other := newWorkspace(t)
	en := enrollCollector(t, ws, "linux_collector", "", nil)
	epoch := uuid.NewString()
	base := func(extra map[string]any) []byte {
		return syncBody(t, 1, epoch, uuid.NewString(), nil, nil, nil, nil, extra)
	}
	for _, extra := range []map[string]any{
		{"workspace_id": other.String()},
		{"estate_id": uuid.NewString()},
		{"host_id": "machine-1"},
		{"host_id": "machine-1", "password": canary},
	} {
		got := postSync(en.Credential, base(extra), nil)
		if got.code != http.StatusForbidden {
			t.Fatalf("spoof %v: %d %s", extra, got.code, got.body)
		}
		if strings.Contains(string(got.body), canary) {
			t.Fatalf("403 echoed canary: %s", got.body)
		}
	}
	if countRows(t, "collector_batches", ws) != 0 || countRows(t, "collector_batches", other) != 0 {
		t.Fatal("spoof stored a batch")
	}
	okBody := syncBody(t, 1, epoch, uuid.NewString(), nil, nil, nil, nil, map[string]any{
		"workspace_id": ws.String(),
		"estate_id":    en.EstateID.String(),
	})
	mustSyncOK(t, postSync(en.Credential, okBody, nil))
	assertNoCanary(t, ws, canary)
}

func TestT23_CanaryRejectedAndNotStored(t *testing.T) {
	resetSync(t)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(io.Discard) })

	ws := newWorkspace(t)
	en := enrollCollector(t, ws, "linux_collector", "", nil)
	body := syncBody(t, 1, uuid.NewString(), uuid.NewString(), []collectorcontract.Object{{
		Ref: "o_unit", Kind: "linux.systemd_workload",
		Native: map[string]any{"unit": "invoice-worker.service", "password": canary},
	}}, nil, nil, nil, nil)
	got := postSync(en.Credential, body, nil)
	if got.code != http.StatusUnprocessableEntity {
		t.Fatalf("canary: %d %s persist=%v", got.code, got.body, syncSvc.LastPersistErr)
	}
	if strings.Contains(string(got.body), canary) || strings.Contains(logs.String(), canary) {
		t.Fatalf("canary leaked response=%s logs=%s", got.body, logs.String())
	}
	if countRows(t, "collector_batches", ws) != 0 {
		t.Fatal("canary batch was stored")
	}
	assertNoCanary(t, ws, canary)
}

func TestSync_ScopeEnforcement(t *testing.T) {
	resetSync(t)
	ws := newWorkspace(t)
	k8s := enrollNamespaced(t, ws, "k8s_collector", "", []string{"payments"}, nil)
	epoch := uuid.NewString()
	pod := func(ns string, seq int64) []byte {
		return syncBody(t, seq, epoch, uuid.NewString(), []collectorcontract.Object{{
			Ref: "o_pod", Kind: "k8s.pod", Native: map[string]any{"namespace": ns, "name": "api"},
		}}, nil, nil, nil, nil)
	}
	mustSyncOK(t, postSync(k8s.Credential, pod("payments", 1), nil))
	got := postSync(k8s.Credential, pod("kube-system", 2), nil)
	if got.code != http.StatusForbidden {
		t.Fatalf("namespace: %d %s", got.code, got.body)
	}
	cluster := syncBody(t, 3, epoch, uuid.NewString(), []collectorcontract.Object{
		{Ref: "o_cr", Kind: "k8s.cluster_role", Native: map[string]any{"name": "view"}},
		{Ref: "o_crb", Kind: "k8s.cluster_role_binding", Native: map[string]any{"name": "view-bind"}},
		{Ref: "o_ns", Kind: "k8s.namespace", Native: map[string]any{"name": "payments"}},
		{Ref: "o_node", Kind: "k8s.node", Native: map[string]any{"name": "node-a"}},
	}, []collectorcontract.Observation{{
		EventID: "e-admit", Kind: "admission.actor", SubjectRef: "o_ns",
		ObservedAt: "2026-09-25T08:00:00Z", Outcome: "success", Preview: true,
	}}, nil, nil, map[string]any{
		"health": map[string]any{
			"events_lost": 0, "queue_depth": 1,
			"partitions_partial": 1, "partitions_forbidden": 2,
			"poison_isolated": 3, "idempotency_conflicts": 4,
		},
	})
	mustSyncOK(t, postSync(k8s.Credential, cluster, nil))
	var payload string
	if err := db.Raw(`SELECT fact_payload::text FROM iga_observations WHERE workspace_id = ? AND evidence_ref = 'e-admit'`, ws).Scan(&payload).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, "admission.actor") || !strings.Contains(payload, `"preview": true`) {
		t.Fatalf("admission preview was not stored as telemetry: %s", payload)
	}
	pv := syncBody(t, 4, epoch, uuid.NewString(), []collectorcontract.Object{{
		Ref: "o_pv", Kind: "k8s.pv", Native: map[string]any{"name": "data"},
	}}, nil, nil, nil, nil)
	mustSyncOK(t, postSync(k8s.Credential, pv, nil))
	linuxObj := syncBody(t, 5, epoch, uuid.NewString(), []collectorcontract.Object{{
		Ref: "o_unit", Kind: "linux.systemd_workload", Native: map[string]any{"unit": "x.service"},
	}}, nil, nil, nil, nil)
	got = postSync(k8s.Credential, linuxObj, nil)
	if got.code != http.StatusForbidden {
		t.Fatalf("k8s collector linux object: %d %s", got.code, got.body)
	}

	star := enrollNamespaced(t, ws, "k8s_collector", "", []string{"*"}, nil)
	starEpoch := uuid.NewString()
	mustSyncOK(t, postSync(star.Credential, syncBody(t, 1, starEpoch, uuid.NewString(), []collectorcontract.Object{{
		Ref: "o_cr", Kind: "k8s.cluster_role", Native: map[string]any{"name": "view"},
	}}, nil, nil, nil, nil), nil))
	mustSyncOK(t, postSync(star.Credential, syncBody(t, 2, starEpoch, uuid.NewString(), []collectorcontract.Object{{
		Ref: "o_pv", Kind: "k8s.pv", Native: map[string]any{"name": "data"},
	}}, nil, nil, nil, nil), nil))

	linux := enrollCollector(t, ws, "linux_collector", "", nil)
	got = postSync(linux.Credential, syncBody(t, 1, uuid.NewString(), uuid.NewString(), []collectorcontract.Object{{
		Ref: "o_pod", Kind: "k8s.pod", Native: map[string]any{"namespace": "payments", "name": "api"},
	}}, nil, nil, nil, nil), nil)
	if got.code != http.StatusForbidden {
		t.Fatalf("linux collector k8s object: %d %s", got.code, got.body)
	}

	node := enrollCollector(t, ws, "node_sensor", "", map[string]any{"node_name": "node-a"})
	nodeEpoch := uuid.NewString()
	mustSyncOK(t, postSync(node.Credential, syncBody(t, 1, nodeEpoch, uuid.NewString(), []collectorcontract.Object{{
		Ref: "o_unit", Kind: "linux.systemd_workload", Native: map[string]any{"unit": "x.service", "node_name": "node-a"},
	}}, []collectorcontract.Observation{{
		EventID: "e-node", Kind: "runtime.process_exec", SubjectRef: "o_unit",
		ObservedAt: "2026-09-25T08:00:00Z", Outcome: "success",
	}}, nil, nil, nil), nil))
	got = postSync(node.Credential, syncBody(t, 2, nodeEpoch, uuid.NewString(), []collectorcontract.Object{{
		Ref: "o_role", Kind: "k8s.role", Native: map[string]any{"namespace": "payments", "name": "edit"},
	}}, nil, nil, nil, nil), nil)
	if got.code != http.StatusForbidden {
		t.Fatalf("node sensor role: %d %s", got.code, got.body)
	}
	got = postSync(node.Credential, syncBody(t, 3, nodeEpoch, uuid.NewString(), []collectorcontract.Object{{
		Ref: "o_unit", Kind: "linux.systemd_workload", Native: map[string]any{"unit": "x.service", "node_name": "node-b"},
	}}, nil, nil, nil, nil), nil)
	if got.code != http.StatusForbidden {
		t.Fatalf("node sensor wrong node: %d %s", got.code, got.body)
	}
	priv := syncBody(t, 4, nodeEpoch, uuid.NewString(), []collectorcontract.Object{{
		Ref: "o_own", Kind: "ownership.record", Native: map[string]any{"name": "x"},
	}}, nil, nil, nil, nil)
	got = postSync(node.Credential, priv, nil)
	if got.code != http.StatusForbidden {
		t.Fatalf("privileged kind: %d %s", got.code, got.body)
	}
	got = postSync(node.Credential, syncBody(t, 5, nodeEpoch, uuid.NewString(), nil, []collectorcontract.Observation{{
		EventID: "e-admit-node", Kind: "admission.actor", ObservedAt: "2026-09-25T08:00:00Z", Outcome: "success", Preview: true,
	}}, nil, nil, nil), nil)
	if got.code != http.StatusForbidden {
		t.Fatalf("node sensor admission: %d %s", got.code, got.body)
	}
}

func TestSync_WrongCredentialDoesNotReadBody(t *testing.T) {
	resetSync(t)
	ws := newWorkspace(t)
	en := enrollNamespaced(t, ws, "linux_collector", `{"scopes":["actuation"]}`, nil, nil)
	body := &countingBody{}
	req := httptest.NewRequest(http.MethodPost, "/api/iga/v2/agent-sync", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+en.Credential)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || body.reads != 0 {
		t.Fatalf("actuation credential: %d reads=%d %s", w.Code, body.reads, w.Body.Bytes())
	}

	body = &countingBody{}
	req = httptest.NewRequest(http.MethodPost, "/api/iga/v2/agent-sync", body)
	req.Header.Set("Authorization", "Bearer authsec_act_not-a-real-token")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized || body.reads != 0 {
		t.Fatalf("v1 token: %d reads=%d %s", w.Code, body.reads, w.Body.Bytes())
	}
}

func TestSync_EpochChangeRequiresAuthorization(t *testing.T) {
	resetSync(t)
	ws := newWorkspace(t)
	en := enrollCollector(t, ws, "linux_collector", "", nil)
	first := uuid.NewString()
	next := uuid.New()
	mustSyncOK(t, postSync(en.Credential, syncBody(t, 1, first, uuid.NewString(), nil, nil, nil, nil, nil), nil))
	got := postSync(en.Credential, syncBody(t, 1, next.String(), uuid.NewString(), nil, nil, nil, nil, nil), nil)
	if got.code != http.StatusConflict {
		t.Fatalf("unauthorized epoch: %d %s persist=%v", got.code, got.body, syncSvc.LastPersistErr)
	}
	raw, _ := json.Marshal(map[string]any{
		"authorized_next_epoch": next.String(),
		"expected_version":      en.RowVersion,
	})
	authz := do(http.MethodPost, "/api/iga/v2/collectors/"+en.CollectorID.String()+"/epoch", "", "discovery:admin", ws.String(), raw)
	if authz.code != http.StatusOK {
		t.Fatalf("authorize epoch: %d %s", authz.code, authz.body)
	}
	mustSyncOK(t, postSync(en.Credential, syncBody(t, 1, next.String(), uuid.NewString(), nil, nil, nil, nil, nil), nil))
	got = postSync(en.Credential, syncBody(t, 2, first, uuid.NewString(), nil, nil, nil, nil, nil), nil)
	if got.code != http.StatusConflict {
		t.Fatalf("old epoch after switch: %d %s", got.code, got.body)
	}
	var bound string
	if err := db.Raw(`SELECT epoch::text FROM collector_instances WHERE workspace_id = ? AND id = ?`, ws, en.CollectorID).Scan(&bound).Error; err != nil {
		t.Fatal(err)
	}
	if bound != next.String() {
		t.Fatalf("bound epoch = %s", bound)
	}
}

func TestSync_CrashBetweenCommitAndWorker(t *testing.T) {
	resetSync(t)
	drainOutbox(t)
	ws := newWorkspace(t)
	en := enrollCollector(t, ws, "linux_collector", "", nil)
	resp := mustSyncOK(t, postSync(en.Credential, syncBody(t, 1, uuid.NewString(), uuid.NewString(), nil, nil, nil, nil, nil), nil))
	view := getReceipt(t, en.Credential, resp.ReceiptID)
	if view.State != "accepted" {
		t.Fatalf("before worker: %+v", view)
	}
	if countRows(t, "collector_batches", ws) != 1 || countRows(t, "collector_outbox", ws) != 1 {
		t.Fatal("commit did not leave a batch and outbox row")
	}

	syncSvc.ProcessFail = func() error { return errors.New("worker crashed") }
	if err := syncSvc.RunWorkerOnce("crash"); err == nil {
		t.Fatal("expected the worker crash hook to surface")
	}
	view = getReceipt(t, en.Credential, resp.ReceiptID)
	if view.State != "projecting" {
		t.Fatalf("after crash: %+v", view)
	}
	if countRows(t, "collector_batches", ws) != 1 {
		t.Fatal("crash lost the batch")
	}
	assertNoCanonical(t, ws)

	if err := db.Exec(`UPDATE collector_outbox SET leased_until = ? WHERE workspace_id = ?`, current.Add(-time.Minute), ws).Error; err != nil {
		t.Fatal(err)
	}
	syncSvc.ProcessFail = nil
	if err := syncSvc.RunWorkerOnce("restart"); err != nil {
		t.Fatalf("restart: %v", err)
	}
	view = getReceipt(t, en.Credential, resp.ReceiptID)
	if view.State != "published" || view.ProjectionState != "published" {
		t.Fatalf("after restart: %+v", view)
	}
	assertNoCanonical(t, ws)
	var rev int64
	if err := db.Raw(`SELECT COALESCE(MAX(rev), 0) FROM iga_publication WHERE workspace_id = ?`, ws).Scan(&rev).Error; err != nil {
		t.Fatal(err)
	}
	if rev != 0 {
		t.Fatalf("worker bumped the graph publication to %d", rev)
	}
}

func resetSync(t *testing.T) {
	t.Helper()
	if syncSvc == nil {
		t.Fatal("sync service was not mounted")
	}
	syncSvc.QuotaPerMinute = 120
	syncSvc.FailBeforeCommit = nil
	syncSvc.ProcessFail = nil
	syncSvc.LastPersistErr = nil
	t.Cleanup(func() {
		syncSvc.QuotaPerMinute = 120
		syncSvc.FailBeforeCommit = nil
		syncSvc.ProcessFail = nil
	})
}

func drainOutbox(t *testing.T) {
	t.Helper()
	syncSvc.ProcessFail = nil
	for i := 0; i < 200; i++ {
		var n int64
		if err := db.Raw(`SELECT count(*) FROM collector_outbox
			WHERE state = 'ready' OR (state = 'leased' AND leased_until IS NOT NULL AND leased_until < ?)`, current).Scan(&n).Error; err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return
		}
		if err := syncSvc.RunWorkerOnce("drain"); err != nil {
			t.Fatalf("drain: %v last=%v", err, syncSvc.LastPersistErr)
		}
	}
	t.Fatal("outbox did not drain")
}

func enrollNamespaced(t *testing.T, ws uuid.UUID, kind, ceiling string, namespaces []string, hints map[string]any) enrolled {
	t.Helper()
	resetClock(t)
	payload := map[string]any{"kind": kind}
	if ceiling != "" {
		payload["capability_ceiling"] = json.RawMessage(ceiling)
	}
	if namespaces != nil {
		payload["namespace_allowlist"] = namespaces
	}
	raw, _ := json.Marshal(payload)
	issued := do(http.MethodPost, "/api/iga/v2/collector-enrollments", "", "discovery:admin", ws.String(), raw)
	if issued.code != http.StatusCreated {
		t.Fatalf("issue enrollment: %d %s", issued.code, issued.body)
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(issued.body, &tok); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"installation_public_key": b64(pub),
		"installation_nonce":      uuid.NewString(),
		"kind":                    kind,
		"version":                 "0.1.0",
		"native_hints":            hints,
	}
	braw, _ := json.Marshal(body)
	got := do(http.MethodPost, "/api/iga/v2/collectors/enroll", tok.Token, "", "", braw)
	if got.code != http.StatusOK {
		t.Fatalf("enroll: %d %s", got.code, got.body)
	}
	var out struct {
		CollectorID       uuid.UUID `json:"collector_id"`
		DiscoverySourceID uuid.UUID `json:"discovery_source_id"`
		IntegrationID     uuid.UUID `json:"integration_id"`
		EstateID          uuid.UUID `json:"estate_id"`
		Credential        string    `json:"credential"`
		Scopes            []string  `json:"scopes"`
	}
	if err := json.Unmarshal(got.body, &out); err != nil {
		t.Fatal(err)
	}
	view := do(http.MethodGet, "/api/iga/v2/collectors/"+out.CollectorID.String(), "", "discovery:read", ws.String(), nil)
	var v struct {
		RowVersion int64 `json:"row_version"`
	}
	_ = json.Unmarshal(view.body, &v)
	return enrolled{
		CollectorID: out.CollectorID, DiscoverySourceID: out.DiscoverySourceID,
		IntegrationID: out.IntegrationID, EstateID: out.EstateID,
		Credential: out.Credential, Scopes: out.Scopes,
		Public: pub, Private: priv, RowVersion: v.RowVersion,
	}
}

func syncBody(t *testing.T, seq int64, epoch, batch string, objects []collectorcontract.Object, obs []collectorcontract.Observation, snap *collectorcontract.Snapshot, applied []collectorcontract.AppliedReceipt, extra map[string]any) []byte {
	t.Helper()
	if objects == nil {
		objects = []collectorcontract.Object{}
	}
	if obs == nil {
		obs = []collectorcontract.Observation{}
	}
	if applied == nil {
		applied = []collectorcontract.AppliedReceipt{}
	}
	req := collectorcontract.SyncRequest{
		SchemaVersion: collectorcontract.SchemaVersion, BatchID: batch, CollectorEpoch: epoch,
		Sequence: seq, SentAt: "2026-09-25T08:00:00Z",
		Objects: objects, Observations: obs, Applied: applied,
		Health: collectorcontract.Health{}, Snapshot: snap,
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(extra) == 0 {
		return raw
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for k, v := range extra {
		doc[k] = v
	}
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func digestSnap(t *testing.T, objects []collectorcontract.Object, snap collectorcontract.Snapshot) *collectorcontract.Snapshot {
	t.Helper()
	sum, err := collectorcontract.ObjectsDigest(objects)
	if err != nil {
		t.Fatal(err)
	}
	snap.Digest = sum
	return &snap
}

func postSync(cred string, body []byte, hdr map[string]string) apiResp {
	req := httptest.NewRequest(http.MethodPost, "/api/iga/v2/agent-sync", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return apiResp{code: w.Code, body: w.Body.Bytes(), hdr: w.Header()}
}

func mustSyncOK(t *testing.T, res apiResp) collectorcontract.SyncResponse {
	t.Helper()
	if res.code != http.StatusOK {
		t.Fatalf("sync: %d %s persist=%v", res.code, res.body, syncSvc.LastPersistErr)
	}
	var resp collectorcontract.SyncResponse
	if err := json.Unmarshal(res.body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ReceiptID == "" {
		t.Fatalf("empty receipt: %s", res.body)
	}
	return resp
}

func snapshotFlags(t *testing.T, ws uuid.UUID, snapID string) (complete, blocked bool) {
	t.Helper()
	if err := db.Raw(`SELECT complete, gap_blocked FROM collector_snapshots WHERE workspace_id = ? AND snapshot_id = ?`, ws, snapID).Row().Scan(&complete, &blocked); err != nil {
		t.Fatal(err)
	}
	return complete, blocked
}

func assertNoCanonical(t *testing.T, ws uuid.UUID) {
	t.Helper()
	for _, table := range []string{"iga_agents", "iga_relationship", "iga_object_support", "iga_workload"} {
		if n := countRows(t, table, ws); n != 0 {
			t.Fatalf("%s = %d, ingest wrote canonical graph state", table, n)
		}
	}
}

func assertNoCanary(t *testing.T, ws uuid.UUID, secret string) {
	t.Helper()
	var n int64
	err := db.Raw(`SELECT
		(SELECT count(*) FROM collector_batches WHERE workspace_id = ? AND position(? in receipt_body::text) > 0) +
		(SELECT count(*) FROM iga_observations WHERE workspace_id = ? AND position(? in fact_payload::text) > 0) +
		(SELECT count(*) FROM iga_source_objects WHERE workspace_id = ? AND (
			position(? in normalized_payload::text) > 0 OR position(? in locator::text) > 0 OR position(? in native_id) > 0))`,
		ws, secret, ws, secret, ws, secret, secret, secret).Scan(&n).Error
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("canary stored in %d rows", n)
	}
}

func getReceipt(t *testing.T, cred, id string) collectorcontract.ReceiptView {
	t.Helper()
	got := do(http.MethodGet, "/api/iga/v2/receipts/"+id, cred, "", "", nil)
	if got.code != http.StatusOK {
		t.Fatalf("receipt: %d %s", got.code, got.body)
	}
	var view collectorcontract.ReceiptView
	if err := json.Unmarshal(got.body, &view); err != nil {
		t.Fatal(err)
	}
	return view
}
