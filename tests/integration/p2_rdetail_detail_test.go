package integration

// T6.3 -- GET /resources/:id (§5.3 Resources): the list row plus existence,
// resource_policy (D-19) and sources, through the REAL route table over the
// P2-0 lab. Gates: B3/E10 (a reference two accounts name has two sources; one
// ends, the reference stays and Access keeps the other's grant), D-19
// (resource_policy from the revision's resource-policy observations only),
// E14 (a foreign id is 404), E8 (a retired reference is readable), and the
// §5.1 revision and optional-work contracts.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// rdetailSourceLines renders sources as integration|account|state|ended_reason?.
func rdetailSourceLines(body map[string]any) []string {
	out := []string{}
	for _, s := range digl(body, "data", "sources") {
		reason := "-"
		if dig(s, "ended_reason") != nil {
			reason = "ended_reason"
		}
		out = append(out, strings.Join([]string{digs(s, "integration"), digs(s, "account", "id"), digs(s, "state"), reason}, "|"))
	}
	return out
}

// B3 / E10, read side. Two accounts' policies name support-tickets/*: ONE
// reference with two sources, both current. B's policy is then removed: B's
// source ends (listed, with its reason), A's stays current, the reference stays
// active, and Access still shows A's grant and not B's ended one. The detail's
// list fields are the list row's, value for value (§2.14.11).
func TestP2RDetailSourcesTwoAccounts(t *testing.T) {
	l := newP2Lab(t, "p2-rdetail-sources", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	b := l.account(accountB)
	b.role("data-reader", "AROADATAREADERDATARE")
	bPolicy := b.managed("SandboxTickets", docToolboxRead)
	b.attach("data-reader", bPolicy)
	l.scanAndProject(a)
	l.scanAndProject(b)
	api := l.api()
	res := rdetailResource(t, l, "arn:aws:s3:::support-tickets/*")
	if perm := api.requiredPermission("GET", "/resources/"+res); perm != "iga:read" {
		t.Errorf("/resources/:id demands %q, want iga:read", perm)
	}

	body := rdetailGet(t, api, "/resources/"+res)
	srcA, srcB := refOf("cloud_connector", a.conn), refOf("cloud_connector", b.conn)
	want := []string{srcA + "|" + accountA + "|current|-", srcB + "|" + accountB + "|current|-"}
	if got := rdetailSourceLines(body); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("sources = %v, want both connectors, current, by account", got)
	}
	src := dig(body, "data", "sources", 0)
	if !strings.HasPrefix(digs(src, "presence"), "presence:") || digs(src, "account", "label") != "acct-"+accountA ||
		digs(src, "first_seen_at") == "" || digs(src, "last_confirmed_at") == "" {
		t.Errorf("source = %v, want a presence ref, the connector's labelled account and its times", src)
	}
	d := dig(body, "data")
	if digs(d, "ref") != res || digs(d, "existence") != "not_verified" || digs(d, "lifecycle") != "active" ||
		digs(d, "state") != "current" || num(d, "named_by_count", "value") != 2 {
		t.Errorf("detail = %v, want the active reference, existence not_verified, named by 2 statements", d)
	}
	if _, has := d.(map[string]any)["provider_attrs"]; has {
		t.Error("the resource detail carries provider_attrs; D-85 allows none for resources")
	}
	m := dig(body, "meta")
	if num(m, "rev") != 2 || digs(m, "graph_state") != "published" || digs(m, "published_at") == "" {
		t.Errorf("meta = %v, want rev 2, published", m)
	}
	if cov, ok := dig(m, "coverage").([]any); !ok || len(cov) != 0 {
		t.Errorf("meta.coverage = %v, want []", dig(m, "coverage"))
	}
	if _, paged := m.(map[string]any)["next_cursor"]; paged {
		t.Error("the detail meta carries next_cursor: a detail is never a one-row list (§5.2)")
	}

	// The graph and the lists agree: every list field, value for value.
	row := listsRowBy(t, digl(rdetailGet(t, api, "/resources"), "data"), "ref", res)
	for _, f := range []string{"text", "kind", "type", "service", "account", "region", "named_by_count",
		"excluded_by_count", "lifecycle", "state", "last_confirmed_at"} {
		if got, want := rdetailJSON(t, dig(d, f)), rdetailJSON(t, row[f]); got != want {
			t.Errorf("detail %s = %s, list row %s", f, got, want)
		}
	}

	// E10: B's policy naming the bucket is removed.
	b.detach("data-reader", bPolicy)
	delete(b.iam.managedPolicies, bPolicy)
	l.scanAndProject(b)
	body = rdetailGet(t, api, "/resources/"+res)
	want = []string{srcA + "|" + accountA + "|current|-", srcB + "|" + accountB + "|ended|ended_reason"}
	if got := rdetailSourceLines(body); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("sources after B dropped it = %v, want A current and B ended (listed, never dropped)", got)
	}
	if digs(body, "data", "lifecycle") != "active" || digs(body, "data", "state") != "current" {
		t.Errorf("reference = %v / %v, want active and current: A still names it", dig(body, "data", "lifecycle"), dig(body, "data", "state"))
	}
	acc := rdetailGet(t, api, "/resources/"+res+"/access")
	if got := rdetailLines(digl(acc, "data", "access")); strings.Join(got, ",") != "SharedToolRole|TicketRead|ReadTickets|-|current" {
		t.Errorf("access after B dropped it = %v, want A's grant only", got)
	}
}

// rdetailJSON is v as compact JSON, for field-by-field comparison.
func rdetailJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode %v: %v", v, err)
	}
	return string(raw)
}

// D-19. Buckets named exactly by a statement: guarded (a policy with a Deny),
// open (a policy with none), nopolicy (no policy: nothing is recorded), garbled
// (a policy that does not parse). A selector over guarded never borrows its
// bucket's policy. Then guarded's policy loses its Deny: the latest
// observation decides. Finally, observations that do not belong to the
// revision -- from a run that never published, or recorded after the
// revision's publication -- change nothing.
func TestP2RDetailResourcePolicy(t *testing.T) {
	l := newP2Lab(t, "p2-rdetail-resource-policy", true)
	a := l.account(accountA)
	a.role("BucketRole", "AROABUCKETROLEBUCKET")
	a.iam.inlineRolePolicies["BucketRole"] = map[string]string{"Buckets": `{"Version":"2012-10-17","Statement":[` +
		`{"Sid":"Buckets","Effect":"Allow","Action":"s3:ListBucket","Resource":[` +
		`"arn:aws:s3:::guarded","arn:aws:s3:::open","arn:aws:s3:::nopolicy","arn:aws:s3:::garbled","arn:aws:s3:::guarded/*"]}]}`}
	withDeny := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::guarded/*"}]}`
	allowOnly := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::open/*"}]}`
	s3p := &s3bS3Policy{docs: map[string]string{"guarded": withDeny, "open": allowOnly, "garbled": "not a policy {"}}
	f := &s3bFakes{s3: s3p, kms: &fakeKMSPolicy{}}
	s3bScanAndProject(l, a, f)
	api := l.api()

	policyOf := func(text string) string {
		t.Helper()
		body := rdetailGet(t, api, "/resources/"+rdetailResource(t, l, text))
		return rdetailJSON(t, dig(body, "data", "resource_policy"))
	}
	for text, want := range map[string]string{
		"arn:aws:s3:::guarded":   `{"has_deny":true,"read":true}`,
		"arn:aws:s3:::open":      `{"has_deny":false,"read":true}`,
		"arn:aws:s3:::nopolicy":  `{"has_deny":null,"read":false}`,
		"arn:aws:s3:::garbled":   `{"has_deny":null,"read":true}`,  // read, but nothing parsed proves a Deny or its absence
		"arn:aws:s3:::guarded/*": `{"has_deny":null,"read":false}`, // a selector is not the bucket
	} {
		if got := policyOf(text); got != want {
			t.Errorf("%s resource_policy = %s, want %s", text, got, want)
		}
	}

	// The Deny is removed: a new observation, and the latest decides.
	s3p.docs["guarded"] = allowOnly
	run2 := s3bScanAndProject(l, a, f)
	if got := policyOf("arn:aws:s3:::guarded"); got != `{"has_deny":false,"read":true}` {
		t.Errorf("guarded after its Deny was removed = %s, want read, no Deny", got)
	}

	// Observations the scanner cannot be made to write on cue are inserted
	// directly, first and last recorded by the same run as the writer does: a
	// Deny for nopolicy (1) from a run that has not published, recorded before
	// the revision's publication, and (2) from the published run, but recorded
	// after the publication. Neither belongs to the revision; (3) belongs to it
	// but is not a resource-policy read.
	pending, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	for i, o := range []struct {
		run uuid.UUID
		api string
		at  time.Time
	}{
		{pending.ID, "s3:GetBucketPolicy", run2.PublishedAt.Add(-time.Minute)},
		{run2.ID, "s3:GetBucketPolicy", time.Now().Add(time.Hour)},
		// (3) in the revision, about the same ARN, but not a resource-policy read.
		{run2.ID, "iam:GetAccountAuthorizationDetails", run2.PublishedAt.Add(-time.Minute)},
	} {
		rdetailSeedPolicyObservation(t, l.db, l.ws, a.conn, o.run, o.api, o.at, "rdetail-outside-"+string(rune('a'+i)))
	}
	if got := policyOf("arn:aws:s3:::nopolicy"); got != `{"has_deny":null,"read":false}` {
		t.Errorf("nopolicy with observations outside the revision = %s, want not read (D-19)", got)
	}

	// E14: another tenant scanned the same ARN. Its Deny for nopolicy was
	// recorded before THIS revision's publication, by a run that published
	// there at a rev below this one's -- every condition but the workspace
	// holds -- and must never answer here. Last, because the foreign
	// workspace's seeded run is queued, and a lab worker would claim it.
	other := newWorkspace(t, l.db, "p2-rdetail-resource-policy-other")
	classPublish(t, l.db, other)
	var foreign struct {
		ScanRunID   uuid.UUID
		ConnectorID uuid.UUID
	}
	if err := l.db.Raw(`SELECT pb.scan_run_id, sr.connector_id FROM iga_publication pb
	                      JOIN cloud_scan_run sr ON sr.id = pb.scan_run_id WHERE pb.workspace_id = ?`, other).
		Scan(&foreign).Error; err != nil || foreign.ScanRunID == uuid.Nil {
		t.Fatalf("setup: the foreign publication's run: %v", err)
	}
	rdetailSeedPolicyObservation(t, l.db, other, foreign.ConnectorID, foreign.ScanRunID, "s3:GetBucketPolicy",
		run2.PublishedAt.Add(-time.Minute), "rdetail-foreign")
	if got := policyOf("arn:aws:s3:::nopolicy"); got != `{"has_deny":null,"read":false}` {
		t.Errorf("nopolicy beside another workspace's read of it = %s, want not read: foreign data (E14)", got)
	}
}

// rdetailSeedPolicyObservation inserts a Deny resource-policy observation of
// arn:aws:s3:::nopolicy, first and last recorded by run at `at` (as
// ObservationWriter.Record writes a new row), and deletes it at cleanup --
// before the runs and workspaces it references.
func rdetailSeedPolicyObservation(t *testing.T, db *gorm.DB, ws, conn, run uuid.UUID, api string, at time.Time, hash string) {
	t.Helper()
	var id uuid.UUID
	if err := db.Raw(`INSERT INTO cloud_observation (workspace_id, connector_id, scan_run_id, generation,
	                      subject_native_id, source_api, surface, surface_state, observed_at, ingested_at,
	                      sanitized_facts, content_hash, last_confirmed_run_id, last_confirmed_at)
	                  VALUES (?, ?, ?, 1, 'arn:aws:s3:::nopolicy', ?, 'resource_policies', '',
	                          ?, ?, '{"kind":"s3_bucket","has_deny":true,"parse_failed":false,"statements":1}', ?, ?, ?)
	                  RETURNING id`,
		ws, conn, run, api, at, at, hash, run, at).Row().Scan(&id); err != nil {
		t.Fatalf("seed observation %s: %v", hash, err)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM cloud_observation WHERE id = ?`, id) })
}

// rdetailPhase1Scan runs ONE scan through the REAL worker with
// IGA_GRAPH_PROJECTION off: the run collects and publishes its Phase 1
// results, and no projection job or publication ever exists for it -- the
// run that first read a policy in a workspace upgraded to Phase 2.
func rdetailPhase1Scan(l *p2Lab, a *p2Account, f *s3bFakes) models.CloudScanRun {
	l.t.Helper()
	queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		l.t.Fatalf("enqueue: %v", err)
	}
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner("scan-worker-rdetail-phase1").
		WithGraphProjection(services.NewGraphProjectionGate(false, "")).WithScannerHook(f.hook(a))
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		l.t.Fatalf("phase 1 scan: worked=%v err=%v", worked, err)
	}
	var run models.CloudScanRun
	if err := l.db.First(&run, "id = ?", queued.ID).Error; err != nil || run.Status != models.CloudScanRunPublished {
		l.t.Fatalf("phase 1 run = %s (%v), want published", run.Status, err)
	}
	if n := l.count(`SELECT count(*) FROM iga_publication WHERE workspace_id = ?`, l.ws); n != 0 {
		l.t.Fatalf("setup: %d publications after a Phase 1 scan, want none", n)
	}
	return run
}

// rdetailPolicyRows is every resource-policy observation of a reference, as
// "first-recorder|confirmations", oldest first.
func rdetailPolicyRows(t *testing.T, l *p2Lab, text string) []string {
	t.Helper()
	var rows []struct {
		ScanRunID         uuid.UUID
		ConfirmationCount int
	}
	l.db.Raw(`SELECT scan_run_id, confirmation_count FROM cloud_observation
	           WHERE workspace_id = ? AND subject_native_id = ? AND source_api IN ?
	           ORDER BY ingested_at, id`, l.ws, text, igaread.ResourcePolicySourceAPIs).Scan(&rows)
	out := []string{}
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%s|%d", r.ScanRunID, r.ConfirmationCount))
	}
	return out
}

// D-19 over deduplicated reads, through the REAL worker and projector. An
// unchanged re-read writes no new row: it moves the existing row's
// last_confirmed_run_id. So a row names only its first and latest readers.
//
//  1. guarded's Deny is first read while projection is off (a run that never
//     publishes); the first projected run re-reads it unchanged, onto that
//     row. The revision's run DID read it: read, has_deny true -- keyed on the
//     first reader alone it read "not read" at every revision.
//  2. A collection in flight moves the row's latest reader past the revision
//     while its first reader never published: the proof is gone, so "not
//     read", never a has_deny from a run the revision was not built from
//     (D-19's Raise: no per-run confirmation record). Once it publishes, read.
//  3. The Deny is removed (a new row): has_deny false, unchanged while the
//     next collection is in flight -- that row's first reader published.
//  4. The Deny is restored: the re-read dedupes onto the OLD row, whose first
//     recording is older than the no-Deny row's. The latest READ decides:
//     has_deny true, never the latest first-recorded's false.
//  5. In flight again, the old row's latest reader is past the revision and
//     its first never published: it may or may not have been read after the
//     no-Deny row, so has_deny is null -- read, and never a guessed false.
func TestP2RDetailResourcePolicyConfirmations(t *testing.T) {
	l := newP2Lab(t, "p2-rdetail-policy-confirmations", true)
	a := l.account(accountA)
	a.role("BucketRole", "AROABUCKETROLEBUCKET")
	a.iam.inlineRolePolicies["BucketRole"] = map[string]string{"Buckets": `{"Version":"2012-10-17","Statement":[` +
		`{"Sid":"Buckets","Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::guarded"}]}`}
	withDeny := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::guarded/*"}]}`
	allowOnly := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::guarded/*"}]}`
	s3p := &s3bS3Policy{docs: map[string]string{"guarded": withDeny}}
	f := &s3bFakes{s3: s3p, kms: &fakeKMSPolicy{}}
	api := l.api()
	const guarded = "arn:aws:s3:::guarded"
	check := func(step, want string) {
		t.Helper()
		body := rdetailGet(t, api, "/resources/"+rdetailResource(t, l, guarded))
		if got := rdetailJSON(t, dig(body, "data", "resource_policy")); got != want {
			t.Errorf("%s (rev %v): resource_policy = %s, want %s", step, dig(body, "meta", "rev"), got, want)
		}
	}
	inFlight := func() {
		t.Helper()
		scanSeq++
		s3bScan(l, a, f, fmt.Sprintf("scan-worker-rdetail-inflight-%d", scanSeq))
	}
	project := func() {
		t.Helper()
		l.project(fmt.Sprintf("projector-rdetail-inflight-%d", scanSeq))
	}

	// 1.
	first := rdetailPhase1Scan(l, a, f)
	s3bScanAndProject(l, a, f)
	if got := strings.Join(rdetailPolicyRows(t, l, guarded), ","); got != first.ID.String()+"|2" {
		t.Fatalf("setup: guarded's rows = %s, want ONE row first recorded by the Phase 1 run, read twice", got)
	}
	check("first read by an unpublished run, confirmed by a published one", `{"has_deny":true,"read":true}`)

	// 2.
	inFlight()
	check("its latest reader in flight, its first never published", `{"has_deny":null,"read":false}`)
	project()
	check("that reader published", `{"has_deny":true,"read":true}`)

	// 3.
	s3p.docs["guarded"] = allowOnly
	s3bScanAndProject(l, a, f)
	check("the Deny removed", `{"has_deny":false,"read":true}`)
	inFlight()
	check("the Deny removed, the next collection in flight", `{"has_deny":false,"read":true}`)
	project()

	// 4.
	s3p.docs["guarded"] = withDeny
	s3bScanAndProject(l, a, f)
	if rows := rdetailPolicyRows(t, l, guarded); len(rows) != 2 || !strings.HasPrefix(rows[0], first.ID.String()+"|") {
		t.Fatalf("setup: guarded's rows = %v, want the restored Deny deduplicated onto the Phase 1 run's row", rows)
	}
	check("the Deny restored onto its old row", `{"has_deny":true,"read":true}`)

	// 5.
	inFlight()
	check("the restored row's latest reader in flight", `{"has_deny":null,"read":true}`)
	project()
	check("that reader published", `{"has_deny":true,"read":true}`)
}

// E14, D-4, D-5, D-6, E8 and the parameter contract. A foreign id, another
// type's ref, a malformed id, a GitHub row and an unsupported AWS row are all
// 404 with no hint; bare UUID and resource:<uuid> both open the object. A
// retired reference is readable with its lifecycle, reason and ended source,
// and its ended grant is history include_ended shows. A stale rev is 409 on
// both routes; unknown or malformed parameters are 400.
func TestP2RDetailNotFoundRetiredAndParameters(t *testing.T) {
	l := newP2Lab(t, "p2-rdetail-404", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	gone := a.managed("GoneRead", `{"Version":"2012-10-17","Statement":[{"Sid":"Gone",`+
		`"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::gone-bucket/*"}]}`)
	a.attach("SharedToolRole", gone)
	l.scanAndProject(a)
	api := l.api()
	res := rdetailResource(t, l, "arn:aws:s3:::support-tickets/*")
	id := refUUID(t, res)

	// A GitHub resource with a support row, and an AWS row no pass supports.
	var gh, orphan uuid.UUID
	if err := l.db.Raw(`WITH gh AS (
	                        INSERT INTO iga_resources (workspace_id, resource_kind, display_name, provider, source_key)
	                        VALUES (?, 'repository', 'acme/support-tickets', 'github', 'github' || chr(31) || 'repo' || chr(31) || 'rdetail')
	                        RETURNING workspace_id, id),
	                    s AS (INSERT INTO iga_object_support (workspace_id, resource_id, connector_id, partition_key, state)
	                        SELECT workspace_id, id, ?, 'rdetail-test|github', 'current' FROM gh)
	                    SELECT id FROM gh`, l.ws, a.conn).Row().Scan(&gh); err != nil {
		t.Fatalf("seed github resource: %v", err)
	}
	if err := l.db.Raw(`INSERT INTO iga_resources (workspace_id, resource_kind, display_name, provider, source_key)
	                    VALUES (?, 's3_bucket', 'arn:aws:s3:::orphan', 'aws', 'aws' || chr(31) || 'ref' || chr(31) || 'arn:aws:s3:::orphan')
	                    RETURNING id`, l.ws).Row().Scan(&orphan); err != nil {
		t.Fatalf("seed unsupported resource: %v", err)
	}
	if gh == uuid.Nil || orphan == uuid.Nil {
		t.Fatal("setup: seeding the non-graph rows failed")
	}

	for _, path := range []string{"/resources/" + res, "/resources/" + res + "/access"} {
		if code, b := api.get(strings.Replace(path, res, id.String(), 1)); code != 200 {
			t.Errorf("GET %s by bare UUID = %d %v, want 200 (D-5)", path, code, b)
		}
	}
	for name, ref := range map[string]string{
		"another type's ref":     "identity:" + id.String(),
		"a malformed id":         "not-a-uuid",
		"an unknown id":          uuid.NewString(),
		"a GitHub resource":      refOf("resource", gh),
		"an unsupported AWS row": refOf("resource", orphan),
	} {
		for _, suffix := range []string{"", "/access"} {
			if code, b := api.get("/resources/" + ref + suffix); code != 404 || errCode(b) != "not_found" {
				t.Errorf("%s%s = %d %v, want 404 not_found", name, suffix, code, b)
			}
		}
	}

	// Parameters (before the snapshot).
	for _, tc := range []struct{ path, param string }{
		{"/resources/" + res + qs("limit", "5"), "limit"},
		{"/resources/" + res + qs("rev", "zero"), "rev"},
		{"/resources/" + res + "/access" + qs("limit", "0"), "limit"},
		{"/resources/" + res + "/access" + qs("limit", "201"), "limit"},
		{"/resources/" + res + "/access" + qs("include_ended", "yes"), "include_ended"},
		{"/resources/" + res + "/access" + qs("sort", "name"), "sort"},
	} {
		if code, b := api.get(tc.path); code != 400 || errCode(b) != "invalid_parameter" || digs(b, "error", "parameter") != tc.param {
			t.Errorf("GET %s = %d %v, want 400 invalid_parameter naming %s", tc.path, code, b, tc.param)
		}
	}
	if code, b := api.get("/resources/" + res + "/access" + qs("cursor", "garbage")); code != 400 || errCode(b) != "cursor_invalid" {
		t.Errorf("a garbage cursor = %d %v, want 400 cursor_invalid", code, b)
	}

	// E8: GoneRead is removed, so gone-bucket/* loses its only source and retires.
	a.detach("SharedToolRole", gone)
	delete(a.iam.managedPolicies, gone)
	l.scanAndProject(a)
	goneRes := rdetailResource(t, l, "arn:aws:s3:::gone-bucket/*")
	body := rdetailGet(t, api, "/resources/"+goneRes)
	d := dig(body, "data")
	if digs(d, "lifecycle") != "retired" || digs(d, "retired_reason") == "" || digs(d, "state") != "ended" ||
		digs(d, "last_confirmed_at") == "" {
		t.Errorf("retired reference = lifecycle %v reason %v state %v last_confirmed %v, want readable, retired, with its reason",
			d.(map[string]any)["lifecycle"], d.(map[string]any)["retired_reason"], d.(map[string]any)["state"], d.(map[string]any)["last_confirmed_at"])
	}
	if got := rdetailSourceLines(body); strings.Join(got, ",") != refOf("cloud_connector", a.conn)+"|"+accountA+"|ended|ended_reason" {
		t.Errorf("retired sources = %v, want A's, ended", got)
	}
	if rows := digl(rdetailGet(t, api, "/resources/"+goneRes+"/access"), "data", "access"); len(rows) != 0 {
		t.Errorf("retired access = %v, want no live row", rdetailLines(rows))
	}
	if got := rdetailLines(digl(rdetailGet(t, api, "/resources/"+goneRes+"/access"+qs("include_ended", "true")), "data", "access")); strings.Join(got, ",") != "SharedToolRole|GoneRead|Gone|-|ended" {
		t.Errorf("retired access with include_ended = %v, want the ended grant", got)
	}

	// §5.1: rev 1 is no longer current.
	for _, suffix := range []string{"", "/access"} {
		code, b := api.get("/resources/" + res + suffix + qs("rev", "1"))
		if code != 409 || errCode(b) != "revision_stale" || num(b, "error", "requested_rev") != 1 || num(b, "error", "current_rev") != 2 {
			t.Errorf("rev=1%s = %d %v, want 409 revision_stale 1 -> 2", suffix, code, b)
		}
		if code, b := api.get("/resources/" + res + suffix + qs("rev", "2")); code != 200 || num(b, "meta", "rev") != 2 {
			t.Errorf("rev=2%s = %d, want 200 at rev 2", suffix, code)
		}
	}
	// A cursor issued at rev 2 is stale after rev 3.
	a.role("SecondRole", "AROASECONDROLESECOND")
	a.attach("SecondRole", a.policyARN("TicketRead"))
	l.scanAndProject(a)
	p1 := rdetailGet(t, api, "/resources/"+res+"/access"+qs("limit", "1"))
	next, _ := dig(p1, "meta", "next_cursor").(string)
	if next == "" {
		t.Fatalf("setup: page 1 of two holders has no cursor")
	}
	a.detach("SecondRole", a.policyARN("TicketRead"))
	l.scanAndProject(a)
	if code, b := api.get("/resources/" + res + "/access" + qs("limit", "1", "cursor", next)); code != 409 || errCode(b) != "revision_stale" {
		t.Errorf("a cursor from rev 3 at rev 4 = %d %v, want 409 revision_stale", code, b)
	}

	// E14: the same id from another workspace's token. That workspace HAS a
	// publication: otherwise the 404 would be D-4's "nothing published" and
	// would prove nothing about the workspace scoping. Last, because its seeded
	// run is queued, and the lab's worker would claim it.
	other := newWorkspace(t, l.db, "p2-rdetail-404-other")
	classPublish(t, l.db, other)
	api.asWorkspace(other)
	for _, suffix := range []string{"", "/access"} {
		if code, b := api.get("/resources/" + res + suffix); code != 404 || errCode(b) != "not_found" {
			t.Errorf("foreign workspace %s = %d %v, want 404 not_found with no hint", suffix, code, b)
		}
	}
	api.asWorkspace(l.ws)

	// D-4: before a workspace's first publication no object exists, so every
	// id is 404 -- even a graph row seeded without one (a state the projector
	// cannot leave: a publication commits with its graph).
	unpublished := newWorkspace(t, l.db, "p2-rdetail-404-unpublished")
	conn := connectorFor(t, l.db, unpublished)
	var early uuid.UUID
	if err := l.db.Raw(`WITH r AS (
	                        INSERT INTO iga_resources (workspace_id, resource_kind, display_name, provider, source_key)
	                        VALUES (?, 's3_bucket', 'arn:aws:s3:::early', 'aws', 'aws' || chr(31) || 'ref' || chr(31) || 'arn:aws:s3:::early')
	                        RETURNING workspace_id, id),
	                    s AS (INSERT INTO iga_object_support (workspace_id, resource_id, connector_id, partition_key, state)
	                        SELECT workspace_id, id, ?, 'rdetail-test|early', 'current' FROM r)
	                    SELECT id FROM r`, unpublished, conn).Row().Scan(&early); err != nil {
		t.Fatalf("seed an unpublished resource: %v", err)
	}
	t.Cleanup(func() {
		l.db.Exec(`DELETE FROM iga_object_support WHERE workspace_id = ?`, unpublished)
		l.db.Exec(`DELETE FROM iga_resources WHERE workspace_id = ?`, unpublished)
		l.db.Exec(`DELETE FROM cloud_connector WHERE workspace_id = ?`, unpublished)
	})
	api.asWorkspace(unpublished)
	for _, suffix := range []string{"", "/access"} {
		if code, b := api.get("/resources/" + refOf("resource", early) + suffix); code != 404 || errCode(b) != "not_found" {
			t.Errorf("nothing published%s = %d %v, want 404 not_found (D-4)", suffix, code, b)
		}
	}
	api.asWorkspace(l.ws)
}

// The only reference an unreadable document names goes stale: the detail
// says stale with D-74's stale_reason, meta.coverage names the gap exactly
// as the resources list does, and Access marks the grant stale -- never
// ended, never dropped.
func TestP2RDetailStaleReferenceAndCoverage(t *testing.T) {
	l := newP2Lab(t, "p2-rdetail-stale", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	// AWS-managed (D-51): only an AWS-managed document can fail to FETCH.
	archive := s3aAWSManaged(a, "ArchiveRead", `{"Version":"2012-10-17","Statement":[{"Sid":"Archive",`+
		`"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::ticket-archive/*"}]}`)
	a.attach("SharedToolRole", archive)
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	l.scanAndProject(a)
	a.iam.failPolicyVersion[archive] = denied("iam:GetPolicyVersion")
	run := l.scanAndProject(a)
	api := l.api()

	res := rdetailResource(t, l, "arn:aws:s3:::ticket-archive/*")
	body := rdetailGet(t, api, "/resources/"+res)
	d := dig(body, "data")
	if digs(d, "state") != "stale" || digs(d, "lifecycle") != "active" {
		t.Fatalf("setup: ticket-archive/* = %v / %v, want stale and active", dig(d, "state"), dig(d, "lifecycle"))
	}
	since := run.PublishedAt.UTC().Format(time.RFC3339)
	if got := strings.Join(listsRowStaleReasons(d), ","); got != accountA+"|policy_documents|partial|"+since {
		t.Errorf("stale_reason = %q, want A's policy_documents partial since %s (D-74)", got, since)
	}
	docsA := listsNote(accountA, "policy_documents", "partial", "resources named by unreadable policy documents")
	list := rdetailGet(t, api, "/resources")
	if got, want := strings.Join(listsNotes(body), ","), strings.Join(listsNotes(list), ","); got != docsA || got != want {
		t.Errorf("detail meta.coverage = %q, list %q, want both exactly %q", got, want, docsA)
	}
	acc := rdetailGet(t, api, "/resources/"+res+"/access")
	if got := rdetailLines(digl(acc, "data", "access")); strings.Join(got, ",") != "SharedToolRole|ArchiveRead|Archive|-|stale" {
		t.Errorf("access = %v, want the grant, marked stale", got)
	}
	if got := strings.Join(listsNotes(acc), ","); got != docsA {
		t.Errorf("access meta.coverage = %q, want %q", got, docsA)
	}
	// A current reference carries no stale_reason.
	cur := rdetailGet(t, api, "/resources/"+rdetailResource(t, l, "arn:aws:s3:::support-tickets/*"))
	if _, has := dig(cur, "data").(map[string]any)["stale_reason"]; has {
		t.Errorf("a current reference carries stale_reason %v", dig(cur, "data", "stale_reason"))
	}
}

// §2.14.14, D-73, D-93: a detail and its tab carry every gap that bears on
// THEM. Account A names the bucket locked (and locked/*), and its crew group
// holds a grant on locked/*; account B names b-locked, and at first locked
// too, until a clean scan drops it (B's support for locked ENDS). Then A's
// scan cannot read locked's bucket policy or the groups listing, nor B's
// b-locked's policy or its groups listing.
//
//   - locked's Overview names A's resource_policies gap -- the only thing that
//     explains its resource_policy read = false -- and BOTH accounts' iam_groups
//     gaps: groups' inline policies arrive with the groups listing, and an
//     unread one in either account may name locked. Not B's resource_policies
//     gap: B's run no longer names locked, so it never tried to read its
//     policy; that gap is about b-locked.
//   - locked/*'s Overview has no resource_policies gap: no policy is read for
//     an object selector.
//   - locked/* > Access names both iam_groups gaps, which its member rows
//     (D-18) depend on, and keeps kim's member row, stale, never dropped.
//   - The resources list carries neither: D-73's list table has no
//     resource_policies or iam_groups for resources.
func TestP2RDetailCoverageEveryGapThatBears(t *testing.T) {
	l := newP2Lab(t, "p2-rdetail-own-coverage", true)
	a := l.account(accountA)
	a.role("LockedRole", "AROALOCKEDROLELOCKED")
	a.iam.inlineRolePolicies["LockedRole"] = map[string]string{"Locked": `{"Version":"2012-10-17","Statement":[` +
		`{"Sid":"Locked","Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::locked","arn:aws:s3:::locked/*"]}]}`}
	s3aGroup(a, "crew", "AGPACREWCREWCREWCREW")
	s3aGroupAttach(t, a, "crew", a.managed("CrewRead", `{"Version":"2012-10-17","Statement":[{"Sid":"Crew",`+
		`"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::locked/*"}]}`))
	s3aUser(a, "kim", "AIDAKIMKIMKIMKIMKIM1")
	s3aJoin(a, "kim", "crew")
	b := l.account(accountB)
	b.role("BRole", "AROABROLEBROLEBROLE1")
	bNames := func(resources string) {
		b.iam.inlineRolePolicies["BRole"] = map[string]string{"B": `{"Version":"2012-10-17","Statement":[` +
			`{"Sid":"B","Effect":"Allow","Action":"s3:ListBucket","Resource":[` + resources + `]}]}`}
	}
	bNames(`"arn:aws:s3:::b-locked","arn:aws:s3:::locked"`)
	fa := &s3bFakes{s3: &s3bS3Policy{docs: map[string]string{}, errs: map[string]error{}}, kms: &fakeKMSPolicy{}}
	fb := &s3bFakes{s3: &s3bS3Policy{docs: map[string]string{}, errs: map[string]error{}}, kms: &fakeKMSPolicy{}}
	s3bScanAndProject(l, a, fa)
	s3bScanAndProject(l, b, fb)
	bNames(`"arn:aws:s3:::b-locked"`)
	s3bScanAndProject(l, b, fb)
	api := l.api()
	locked := rdetailResource(t, l, "arn:aws:s3:::locked")
	lockedObjects := rdetailResource(t, l, "arn:aws:s3:::locked/*")
	if got := listsNotes(rdetailGet(t, api, "/resources/"+locked)); len(got) != 0 {
		t.Fatalf("setup: locked's coverage after clean scans = %v, want none", got)
	}
	if got := l.supportOf("resource_id", refUUID(t, locked)); got[a.conn] != "current" || got[b.conn] != "ended" {
		t.Fatalf("setup: locked's supports = %v, want A current and B ended", got)
	}

	fa.s3.(*s3bS3Policy).errs["locked"] = denied("s3:GetBucketPolicy")
	a.iam.fail["GetAccountAuthorizationDetails:Group"] = denied("iam:GetAccountAuthorizationDetails")
	s3bScanAndProject(l, a, fa)
	fb.s3.(*s3bS3Policy).errs["b-locked"] = denied("s3:GetBucketPolicy")
	b.iam.fail["GetAccountAuthorizationDetails:Group"] = denied("iam:GetAccountAuthorizationDetails")
	s3bScanAndProject(l, b, fb)

	named := "resources named by groups' inline policies"
	policy := "whether this resource's policy was read"
	groupsA, groupsB := listsNote(accountA, "iam_groups", "denied", named), listsNote(accountB, "iam_groups", "denied", named)
	body := rdetailGet(t, api, "/resources/"+locked)
	if got, want := strings.Join(listsNotes(body), ","),
		strings.Join([]string{groupsA, listsNote(accountA, "resource_policies", "denied", policy), groupsB}, ","); got != want {
		t.Errorf("locked meta.coverage = %q,\nwant both accounts' iam_groups and A's resource_policies %q", got, want)
	}
	if got := rdetailJSON(t, dig(body, "data", "resource_policy")); got != `{"has_deny":null,"read":false}` {
		t.Errorf("locked resource_policy = %s, want not read", got)
	}
	if got, want := strings.Join(listsNotes(rdetailGet(t, api, "/resources/"+lockedObjects)), ","), groupsA+","+groupsB; got != want {
		t.Errorf("locked/* meta.coverage = %q, want only %q: no policy is read for an object selector", got, want)
	}
	acc := rdetailGet(t, api, "/resources/"+lockedObjects+"/access")
	held := "access held by groups and their members"
	if got, want := strings.Join(listsNotes(acc), ","),
		listsNote(accountA, "iam_groups", "denied", held)+","+listsNote(accountB, "iam_groups", "denied", held); got != want {
		t.Errorf("locked/* access meta.coverage = %q, want both accounts' iam_groups gaps %q", got, want)
	}
	if got := strings.Join(rdetailLines(digl(acc, "data", "access")), ","); !strings.Contains(got, "kim|CrewRead|Crew|via crew|stale") {
		t.Errorf("locked/* access = %s, want kim's member row kept, stale, while the groups read failed", got)
	}
	bLocked := rdetailGet(t, api, "/resources/"+rdetailResource(t, l, "arn:aws:s3:::b-locked"))
	if got, want := strings.Join(listsNotes(bLocked), ","),
		strings.Join([]string{groupsA, groupsB, listsNote(accountB, "resource_policies", "denied", policy)}, ","); got != want {
		t.Errorf("b-locked meta.coverage = %q,\nwant both accounts' iam_groups and B's resource_policies %q", got, want)
	}
	if got := listsNotes(rdetailGet(t, api, "/resources")); len(got) != 0 {
		t.Errorf("resources list meta.coverage = %v, want none (D-73's list table)", got)
	}
}

// §5.1 optional work. With iga_entitlement_target locked, only the detail's
// counts wait: they time out inside their savepoint and read {value: null,
// exact: false}, and the detail is still served. With a budget too small for
// any optional work, Access still serves its page and its restrictions and
// says its total is not known.
func TestP2RDetailOptionalWork(t *testing.T) {
	l := newP2Lab(t, "p2-rdetail-optional", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	l.scanAndProject(a)
	api := l.api()
	res := rdetailResource(t, l, "arn:aws:s3:::support-tickets/*")

	listsWithTableLocked(t, l.db, "iga_entitlement_target", func() {
		body := rdetailGet(t, api, "/resources/"+res)
		for _, c := range []string{"named_by_count", "excluded_by_count"} {
			if dig(body, "data", c, "value") != nil || dig(body, "data", c, "exact") != false {
				t.Errorf("%s = %v, want {value: null, exact: false}", c, dig(body, "data", c))
			}
		}
		if digs(body, "data", "text") != "arn:aws:s3:::support-tickets/*" || len(digl(body, "data", "sources")) != 1 {
			t.Errorf("detail = %v, want it served despite the timed-out counts", body["data"])
		}
	})
	if num(rdetailGet(t, api, "/resources/"+res), "data", "named_by_count", "value") != 1 {
		t.Error("named_by_count without the lock is not 1")
	}

	r := igaread.NewReader(l.db, readTestCursorKey).WithBudget(39 * time.Millisecond)
	var out any
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		out, err = r.ResourceAccess(context.Background(), l.ws, res, url.Values{})
		if e := igaread.AsError(err); e == nil || e.Code != "query_timeout" {
			break
		}
	}
	if err != nil {
		t.Fatalf("access under a tiny budget: %v", err)
	}
	env := out.(igaread.Envelope)
	meta := env.Meta.(igaread.ListMeta)
	view := env.Data.(igaread.ResourceAccessView)
	if len(view.Access) != 1 || view.ExcludedBy == nil || view.DenyStatementsNaming == nil {
		t.Errorf("view = %+v, want the one row and both (empty) restriction lists", view)
	}
	if meta.TotalKnown || meta.Total != nil || meta.TotalAtLeast != nil {
		t.Errorf("total = known %v %v %v, want unknown, never guessed", meta.TotalKnown, meta.Total, meta.TotalAtLeast)
	}
}
