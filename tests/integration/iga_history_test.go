package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/services"
)

// W9 history and metrics (SPEC-secops-backend-upgrade.md P9): snapshots are
// deduplicated by hash and chained; as-of reads answer the latest row at or
// before a day; a legal hold keeps rows from retention; redaction keeps the
// hash; tier-3 changes need a second person holding governance:approve
// (break-glass only with one approver); metrics report live values from
// seeded data and "unavailable" for sources not merged yet; everything is
// isolated per workspace.

type histClock struct{ t time.Time }

func (c *histClock) now() time.Time { return c.t }

func histSvc(db *gorm.DB, c *histClock) *services.HistoryService {
	return services.NewHistoryService(db).WithClock(c.now)
}

// histGrantApprove gives the role of g.users[i] governance:approve.
func histGrantApprove(t *testing.T, g *p3Gov, i int) {
	t.Helper()
	p3exec(t, g.db, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE workspace_id IS NULL AND resource = 'governance' AND action = 'approve'`, g.roles[i])
	t.Cleanup(func() { g.db.Exec(`DELETE FROM role_permissions WHERE role_id = ?`, g.roles[i]) })
}

func histWorkload(t *testing.T, g *p3Gov, name, class string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	p3exec(t, g.db, `INSERT INTO iga_workload (id, workspace_id, runtime_kind, display_name, region, source_key, classification)
		VALUES (?, ?, 'lambda_function', ?, 'us-east-1', ?, ?)`, id, g.ws, name, "aws\x1fhist\x1f"+id.String(), class)
	return id
}

func histInventory(t *testing.T, db *gorm.DB, ws uuid.UUID, stable string) []services.HistorySnapshot {
	t.Helper()
	var rows []services.HistorySnapshot
	if err := db.Raw(`SELECT id, snapshot_date, kind, stable_id, hash, body, absent, legal_hold, redacted, prev_chain_hash, chain_hash
	                    FROM iga_snapshot WHERE workspace_id = ? AND kind = 'inventory' AND stable_id = ? ORDER BY snapshot_date`, ws, stable).
		Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func histGovCode(err error) (int, string) {
	var ge *services.GovError
	if errors.As(err, &ge) {
		return ge.Status, ge.Code
	}
	return 0, ""
}

func TestHistorySnapshotDedupeChainAndAsOf(t *testing.T) {
	db := igaDB(t)
	ctx := context.Background()
	a := p3NewGov(t, db, "hist-snap-a")
	b := p3NewGov(t, db, "hist-snap-b")
	clk := &histClock{t: time.Now().UTC().AddDate(0, 0, -10)}
	svc := histSvc(db, clk)
	w := histWorkload(t, a, "book-flight", "classified_agent")
	stable := "iga_workload:" + w.String()
	d1 := clk.t

	r1, err := svc.TakeDaily(ctx, a.ws)
	if err != nil || r1.Skipped || r1.RowsWritten == 0 {
		t.Fatalf("day 1: %+v %v", r1, err)
	}
	if again, err := svc.TakeDaily(ctx, a.ws); err != nil || !again.Skipped {
		t.Fatalf("a second run the same day must skip: %+v %v", again, err)
	}
	// Day 2, nothing changed: the day is recorded, no new inventory row.
	clk.t = d1.AddDate(0, 0, 1)
	if r, err := svc.TakeDaily(ctx, a.ws); err != nil || r.Skipped {
		t.Fatalf("day 2: %+v %v", r, err)
	}
	if rows := histInventory(t, db, a.ws, stable); len(rows) != 1 {
		t.Fatalf("unchanged object must not be written again: %d rows", len(rows))
	}
	// Day 3: changed -> a new row chained to the first.
	p3exec(t, db, `UPDATE iga_workload SET display_name = 'book-flight-v2' WHERE id = ?`, w)
	clk.t = d1.AddDate(0, 0, 2)
	if _, err := svc.TakeDaily(ctx, a.ws); err != nil {
		t.Fatal(err)
	}
	// Day 4: gone -> an absent row.
	p3exec(t, db, `DELETE FROM iga_workload WHERE id = ?`, w)
	clk.t = d1.AddDate(0, 0, 3)
	if _, err := svc.TakeDaily(ctx, a.ws); err != nil {
		t.Fatal(err)
	}
	rows := histInventory(t, db, a.ws, stable)
	if len(rows) != 3 || rows[1].PrevChainHash != rows[0].ChainHash || rows[2].PrevChainHash != rows[1].ChainHash || !rows[2].Absent {
		t.Fatalf("rows: %+v", rows)
	}
	if rows[0].Hash == rows[1].Hash {
		t.Fatal("a changed body must have a new hash")
	}
	var days int64
	db.Raw(`SELECT count(*) FROM iga_snapshot_day WHERE workspace_id = ?`, a.ws).Scan(&days)
	if days != 4 {
		t.Fatalf("every day is recorded: %d", days)
	}

	// As-of reads.
	read := func(asOf time.Time) *services.HistorySnapshot {
		p, err := svc.SnapshotsAsOf(ctx, a.ws, services.SnapshotKindInventory, stable, asOf, "", 0)
		if err != nil {
			if st, _ := histGovCode(err); st == http.StatusNotFound {
				return nil
			}
			t.Fatal(err)
		}
		return &p.Items[0]
	}
	if r := read(d1.AddDate(0, 0, 1)); r == nil || r.ID != rows[0].ID {
		t.Fatalf("as of day 2 must be day 1's row: %+v", r)
	}
	if r := read(d1.AddDate(0, 0, 2)); r == nil || r.ID != rows[1].ID || !strings.Contains(string(r.Body), "book-flight-v2") {
		t.Fatalf("as of day 3: %+v", r)
	}
	if r := read(d1.AddDate(0, 0, 3)); r == nil || !r.Absent {
		t.Fatalf("as of day 4 the object is absent: %+v", r)
	}
	if r := read(d1.AddDate(0, 0, -1)); r != nil {
		t.Fatalf("nothing before the first day: %+v", r)
	}
	// Listing a kind at a day leaves absent objects out.
	page, err := svc.SnapshotsAsOf(ctx, a.ws, services.SnapshotKindInventory, "", d1.AddDate(0, 0, 3), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range page.Items {
		if it.StableID == stable {
			t.Fatal("an absent object must not be listed")
		}
	}
	// Metric values and definitions are snapshotted too.
	var metricRows int64
	db.Raw(`SELECT count(*) FROM iga_snapshot WHERE workspace_id = ? AND kind IN ('metric_value', 'metric_definition')`, a.ws).Scan(&metricRows)
	if metricRows == 0 {
		t.Fatal("metric values and definitions must be snapshotted")
	}

	// Chains verify; rows cannot be rewritten.
	v, err := svc.VerifyChain(ctx, a.ws, d1.AddDate(0, 0, -1), d1.AddDate(0, 0, 4))
	if err != nil || !v.OK || v.DaysChecked != 4 {
		t.Fatalf("verify: %+v %v", v, err)
	}
	if err := db.Exec(`UPDATE iga_snapshot SET hash = repeat('0', 64) WHERE id = ?`, rows[0].ID).Error; err == nil {
		t.Fatal("a snapshot's hash must be immutable")
	}
	if err := db.Exec(`DELETE FROM iga_snapshot WHERE id = ?`, rows[0].ID).Error; err == nil {
		t.Fatal("a snapshot must not be deleted outside retention")
	}

	// Isolation: workspace B sees none of A's history.
	if _, err := svc.SnapshotsAsOf(ctx, b.ws, services.SnapshotKindInventory, stable, d1.AddDate(0, 0, 2), "", 0); err == nil {
		t.Fatal("B must not read A's snapshot")
	} else if st, _ := histGovCode(err); st != http.StatusNotFound {
		t.Fatalf("cross-workspace read must be 404: %v", err)
	}
	if ds, err := svc.SnapshotDays(ctx, b.ws, d1.AddDate(0, 0, -1), d1.AddDate(0, 0, 5)); err != nil || len(ds) != 0 {
		t.Fatalf("B's days: %v %v", ds, err)
	}

	// Posture as of a past day reads the snapshot taken then.
	clk.t = d1.AddDate(0, 0, 9)
	pa := d1.AddDate(0, 0, 1)
	post, err := svc.Posture(ctx, a.ws, &pa)
	if err != nil || post.Source != "snapshot" {
		t.Fatalf("posture as of: %+v %v", post, err)
	}
	for _, m := range post.Metrics {
		if m.ID == services.PostureAgentsLabelled && (m.Status != services.MetricAvailable || m.Value == nil || *m.Value != 1 || m.Source != "snapshot") {
			t.Fatalf("labelled agents as of day 2: %+v", m)
		}
	}
}

func TestHistoryHoldBlocksPurgeAndSecondPersonRelease(t *testing.T) {
	db := igaDB(t)
	ctx := context.Background()
	g := p3NewGov(t, db, "hist-hold")
	other := p3NewGov(t, db, "hist-hold-other")
	now := time.Now().UTC()
	clk := &histClock{}
	svc := histSvc(db, clk)
	p3exec(t, db, `INSERT INTO iga_snapshot_setting (workspace_id, retention_days) VALUES (?, 30)`, g.ws)
	w := histWorkload(t, g, "v0", "classified_agent")
	stable := "iga_workload:" + w.String()
	day0 := now.AddDate(0, 0, -100)
	for i, name := range []string{"", "v1", "v2"} {
		if name != "" {
			p3exec(t, db, `UPDATE iga_workload SET display_name = ? WHERE id = ?`, name, w)
		}
		clk.t = day0.AddDate(0, 0, 10*i)
		if _, err := svc.TakeDaily(ctx, g.ws); err != nil {
			t.Fatal(err)
		}
	}
	if rows := histInventory(t, db, g.ws, stable); len(rows) != 3 {
		t.Fatalf("seed rows: %d", len(rows))
	}
	clk.t = now
	hold, err := svc.PlaceHold(ctx, g.ws, g.author, day0, day0, []string{services.SnapshotKindInventory}, "litigation L-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Purge(ctx, g.ws); err != nil {
		t.Fatal(err)
	}
	rows := histInventory(t, db, g.ws, stable)
	if len(rows) != 2 || !rows[0].LegalHold || !strings.Contains(string(rows[1].Body), "v2") {
		t.Fatalf("held day-0 row kept, unheld superseded day-10 row purged, latest kept: %+v", rows)
	}
	var purged int64
	db.Raw(`SELECT count(*) FROM iga_snapshot_day WHERE workspace_id = ? AND purged`, g.ws).Scan(&purged)
	if purged < 1 {
		t.Fatalf("the purged day is marked: %d", purged)
	}
	if v, err := svc.VerifyChain(ctx, g.ws, day0, now); err != nil || !v.OK {
		t.Fatalf("chain must verify after retention: %+v %v", v, err)
	}

	// Releasing is tier 3: the requester cannot apply it, a member without
	// governance:approve cannot, another workspace cannot see it.
	req, err := svc.RequestChange(ctx, g.ws, g.author, services.HistoryChangeRequest{Action: services.HistoryActionHoldRelease,
		SubjectID: &hold.ID, Reason: "matter closed"})
	if err != nil || req.State != "pending" {
		t.Fatalf("request: %+v %v", req, err)
	}
	histGrantApprove(t, g, 0) // the requester holds approve too: still not enough
	if _, err := svc.Approve(ctx, g.ws, g.author, req.ID, ""); err == nil {
		t.Fatal("the requester must not approve")
	} else if _, code := histGovCode(err); code != "self_approval" {
		t.Fatalf("self approval: %v", err)
	}
	if _, err := svc.Approve(ctx, g.ws, g.approver, req.ID, ""); err == nil {
		t.Fatal("an approver without governance:approve must be refused")
	} else if st, _ := histGovCode(err); st != http.StatusForbidden {
		t.Fatalf("no permission: %v", err)
	}
	histGrantApprove(t, other, 1)
	if _, err := svc.Approve(ctx, other.ws, other.approver, req.ID, ""); err == nil {
		t.Fatal("another workspace's approver must not see the request")
	} else if st, _ := histGovCode(err); st != http.StatusNotFound {
		t.Fatalf("cross-workspace approve: %v", err)
	}
	if _, err := svc.Purge(ctx, g.ws); err != nil {
		t.Fatal(err)
	}
	if rows := histInventory(t, db, g.ws, stable); len(rows) != 2 {
		t.Fatal("a pending release must keep the hold")
	}
	histGrantApprove(t, g, 1)
	done, err := svc.Approve(ctx, g.ws, g.approver, req.ID, "ok")
	if err != nil || done.State != "applied" || done.DecidedBy == nil || *done.DecidedBy != g.approver {
		t.Fatalf("approve: %+v %v", done, err)
	}
	if _, err := svc.Purge(ctx, g.ws); err != nil {
		t.Fatal(err)
	}
	if rows := histInventory(t, db, g.ws, stable); len(rows) != 1 {
		t.Fatalf("after release the old row is purged: %d", len(rows))
	}
	// Break-glass is refused while another approver exists.
	if _, err := svc.RequestChange(ctx, g.ws, g.author, services.HistoryChangeRequest{Action: services.HistoryActionHoldRelease,
		SubjectID: &hold.ID, Reason: "again", BreakGlass: true}); err == nil {
		t.Fatal("released hold / break-glass must be refused")
	}
}

func TestHistoryRedactionKeepsHashAndBreakGlass(t *testing.T) {
	db := igaDB(t)
	ctx := context.Background()
	g := p3NewGov(t, db, "hist-redact")
	clk := &histClock{t: time.Now().UTC().AddDate(0, 0, -2)}
	svc := histSvc(db, clk)
	w := histWorkload(t, g, "pii-agent", "classified_agent")
	if _, err := svc.TakeDaily(ctx, g.ws); err != nil {
		t.Fatal(err)
	}
	clk.t = time.Now().UTC()
	row := histInventory(t, db, g.ws, "iga_workload:"+w.String())[0]

	// One approver (the author): break-glass applies alone, review due.
	histGrantApprove(t, g, 0)
	a, err := svc.RequestChange(ctx, g.ws, g.author, services.HistoryChangeRequest{Action: services.HistoryActionSnapshotRedact,
		SubjectID: &row.ID, Reason: "erasure request E-7", BreakGlass: true})
	if err != nil || a.State != "applied" || !a.BreakGlass || a.ReviewDueAt == nil {
		t.Fatalf("break-glass: %+v %v", a, err)
	}
	after := histInventory(t, db, g.ws, "iga_workload:"+w.String())[0]
	if !after.Redacted || after.Hash != row.Hash || strings.Contains(string(after.Body), "pii-agent") {
		t.Fatalf("redaction keeps the hash and drops the body: %+v", after)
	}
	if v, err := svc.VerifyChain(ctx, g.ws, clk.t.AddDate(0, 0, -5), clk.t); err != nil || !v.OK {
		t.Fatalf("chain verifies after redaction: %+v %v", v, err)
	}
	if err := db.Exec(`UPDATE iga_snapshot SET redacted = false, redacted_at = NULL WHERE id = ?`, row.ID).Error; err == nil {
		t.Fatal("a redaction must be final")
	}
	// The review is by another member holding approve.
	if _, err := svc.Review(ctx, g.ws, g.author, a.ID, "self"); err == nil {
		t.Fatal("self review must be refused")
	}
	histGrantApprove(t, g, 1)
	if r, err := svc.Review(ctx, g.ws, g.approver, a.ID, "checked"); err != nil || r.ReviewedBy == nil {
		t.Fatalf("review: %+v %v", r, err)
	}
	// Now two approvers: break-glass is refused.
	w2 := histWorkload(t, g, "other", "unclassified")
	_ = w2
	if _, err := svc.RequestChange(ctx, g.ws, g.author, services.HistoryChangeRequest{Action: services.HistoryActionSnapshotRedact,
		SubjectID: &row.ID, Reason: "x", BreakGlass: true}); err == nil {
		t.Fatal("already redacted")
	}
	var anyRow services.HistorySnapshot
	db.Raw(`SELECT id FROM iga_snapshot WHERE workspace_id = ? AND NOT redacted LIMIT 1`, g.ws).Scan(&anyRow)
	if _, err := svc.RequestChange(ctx, g.ws, g.author, services.HistoryChangeRequest{Action: services.HistoryActionSnapshotRedact,
		SubjectID: &anyRow.ID, Reason: "x", BreakGlass: true}); err == nil {
		t.Fatal("break-glass with two approvers must be refused")
	} else if _, code := histGovCode(err); code != "break_glass_not_allowed" {
		t.Fatalf("break-glass refusal: %v", err)
	}
	// A held snapshot cannot be redacted.
	if _, err := svc.PlaceHold(ctx, g.ws, g.author, clk.t.AddDate(0, 0, -30), clk.t, nil, "hold all"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RequestChange(ctx, g.ws, g.author, services.HistoryChangeRequest{Action: services.HistoryActionSnapshotRedact,
		SubjectID: &anyRow.ID, Reason: "x"}); err == nil {
		t.Fatal("a held snapshot must not be redacted")
	} else if _, code := histGovCode(err); code != "snapshot_held" {
		t.Fatalf("held: %v", err)
	}
}

func histSeedRuntime(t *testing.T, g *p3Gov, t0 time.Time) (identity uuid.UUID) {
	t.Helper()
	identity = uuid.New()
	other := uuid.New()
	alert := func(id uuid.UUID, at time.Time, state string, changed *time.Time) {
		p3exec(t, g.db, `INSERT INTO agent_alert (workspace_id, connector_id, identity_id, subject_label, detection, severity, title, dedupe_key,
			first_seen, last_seen, created_at, state, state_changed_at)
			VALUES (?, ?, ?, 'agent', 'D1', 'high', 't', ?, ?, ?, ?, ?, ?)`, g.ws, g.conn, id, uuid.NewString(), at, at, at, state, changed)
	}
	ack := t0.Add(30 * time.Second)
	alert(identity, t0, "acknowledged", &ack)
	alert(other, t0.Add(time.Minute), "open", nil)
	contain := func(id uuid.UUID, level string, created, contained time.Time) {
		p3exec(t, g.db, `INSERT INTO agent_containment (workspace_id, connector_id, identity_id, identity_kind, identity_arn, level, state, reason,
			created_by, contained_at, created_at)
			VALUES (?, ?, ?, 'iam_role', 'arn:aws:iam::111111111111:role/x', ?, 'contained', 'stop', ?, ?, ?)`,
			g.ws, g.conn, id, level, g.author, contained, created)
	}
	contain(identity, "identity", t0.Add(60*time.Second), t0.Add(120*time.Second))
	contain(other, "model", t0.Add(2*time.Minute), t0.Add(3*time.Minute))
	return identity
}

func histMetric(t *testing.T, ms []services.MetricResult, id string) services.MetricResult {
	t.Helper()
	for _, m := range ms {
		if m.ID == id {
			return m
		}
	}
	t.Fatalf("metric %s missing", id)
	return services.MetricResult{}
}

func TestHistoryMetricsSeededAndUnavailable(t *testing.T) {
	db := igaDB(t)
	ctx := context.Background()
	services.ResetHistorySchemaCache()
	a := p3NewGov(t, db, "hist-metrics-a")
	b := p3NewGov(t, db, "hist-metrics-b")
	now := time.Now().UTC()
	clk := &histClock{t: now}
	svc := histSvc(db, clk)
	histSeedRuntime(t, a, now.Add(-2*time.Hour))
	histWorkload(t, a, "agent-1", "provider_native_agent")

	soc, err := svc.SOC(ctx, a.ws, "7d")
	if err != nil {
		t.Fatal(err)
	}
	ttc := histMetric(t, soc.Metrics, services.SOCTimeToContain)
	if ttc.Status != services.MetricAvailable || ttc.Median == nil || *ttc.Median != 120 ||
		ttc.Breakdown["contained_not_covering"] != 1 || ttc.Breakdown["contained_covering"] != 1 {
		t.Fatalf("time to contain (model level does not cover): %+v", ttc)
	}
	tfa := histMetric(t, soc.Metrics, services.SOCTimeToFirstAction)
	// Alert 1: acknowledged at +30 s (before its stop at +60 s); alert 2:
	// its (non-covering) stop was started a minute after it.
	// With F8's acknowledged_at/resolved_at present the metric runs under
	// definition version 2; both versions see the same two alerts acted on.
	if *tfa.N != 2 || tfa.Breakdown["acted_on"] != 2 || tfa.Definition.Version != 2 {
		t.Fatalf("time to first action: %+v", tfa)
	}
	up := histMetric(t, soc.Metrics, services.SOCUnprovenStops)
	if *up.Value != 2 || up.Breakdown["1h_to_24h"] != 2 {
		t.Fatalf("unproven stops: %+v", up)
	}
	mix := histMetric(t, soc.Metrics, services.SOCOutcomeMix)
	// W3's cases and F8's outcome codes are merged: the outcome mix is live.
	if mix.Status != services.MetricAvailable {
		t.Fatalf("outcome mix is available once W3/F8 are merged: %+v", mix)
	}
	if tfa.Previous == nil || tfa.Previous.Definition.Version != tfa.Definition.Version {
		t.Fatalf("previous period under the same definition: %+v", tfa.Previous)
	}
	// Workspace B: nothing of A's.
	socB, err := svc.SOC(ctx, b.ws, "7d")
	if err != nil {
		t.Fatal(err)
	}
	if m := histMetric(t, socB.Metrics, services.SOCTimeToContain); m.Breakdown["alerts"] != 0 {
		t.Fatalf("B sees A's alerts: %+v", m)
	}

	post, err := svc.Posture(ctx, a.ws, nil)
	if err != nil || post.Source != "live" {
		t.Fatalf("posture: %+v %v", post, err)
	}
	if m := histMetric(t, post.Metrics, services.PostureAgentsLabelled); *m.Value != 1 {
		t.Fatalf("labelled: %+v", m)
	}
	if m := histMetric(t, post.Metrics, services.PostureNoResponder); m.Status != services.MetricUnavailable {
		t.Fatalf("responder groups are W7: %+v", m)
	}
	if m := histMetric(t, post.Metrics, services.PostureCrownJewelReach); m.Status != services.MetricUnavailable {
		t.Fatalf("crown jewels are W7: %+v", m)
	}
	postB, _ := svc.Posture(ctx, b.ws, nil)
	if m := histMetric(t, postB.Metrics, services.PostureAgentsLabelled); *m.Value != 0 {
		t.Fatalf("B posture: %+v", m)
	}

	ciso, err := svc.CISO(ctx, a.ws, now.Format("2006-01"))
	if err != nil || len(ciso.Headlines) != 7 {
		t.Fatalf("ciso: %+v %v", ciso, err)
	}
	// W3 is merged: incidents and the outcome mix read agent_case. Two closed
	// cases in A (one true positive) and one in B, which A must never count.
	p3exec(t, db, `INSERT INTO agent_case (workspace_id, number, title, severity, state, outcome, opened_by, closed_at, closed_by)
		VALUES (?, 901, 'hist case 1', 'high', 'closed', 'true_positive', 'system', now() - interval '1 minute', gen_random_uuid()),
		       (?, 902, 'hist case 2', 'medium', 'closed', 'benign', 'system', now() - interval '1 minute', gen_random_uuid()),
		       (?, 901, 'hist case B', 'high', 'closed', 'true_positive', 'system', now() - interval '1 minute', gen_random_uuid())`,
		a.ws, a.ws, b.ws)
	services.ResetHistorySchemaCache()
	soc, err = svc.SOC(ctx, a.ws, "7d")
	if err != nil {
		t.Fatal(err)
	}
	mix = histMetric(t, soc.Metrics, services.SOCOutcomeMix)
	if mix.Status != services.MetricAvailable || mix.Breakdown["true_positive"] != 1 || mix.Breakdown["benign"] != 1 {
		t.Fatalf("outcome mix from cases (A only): %+v", mix)
	}
	ciso, _ = svc.CISO(ctx, a.ws, now.Format("2006-01"))
	if m := histMetric(t, ciso.Headlines, services.CISOIncidents); m.Status != services.MetricAvailable || *m.Value != 1 {
		t.Fatalf("incidents from cases: %+v", m)
	}

	// Population: A's alerts and containments, paged, with hashes; B none.
	pop, err := svc.Population(ctx, a.ws, now.Add(-24*time.Hour), now.Add(time.Minute), []string{"alert", "containment"}, "", 3)
	if err != nil || len(pop.Items) != 3 || pop.NextCursor == nil {
		t.Fatalf("population page 1: %+v %v", pop, err)
	}
	rest, err := svc.Population(ctx, a.ws, now.Add(-24*time.Hour), now.Add(time.Minute), []string{"alert", "containment"}, *pop.NextCursor, 3)
	if err != nil || len(rest.Items) != 1 || rest.NextCursor != nil {
		t.Fatalf("population page 2: %+v %v", rest, err)
	}
	for _, it := range append(pop.Items, rest.Items...) {
		if len(it.Hash) != 64 || it.ID == "" {
			t.Fatalf("item: %+v", it)
		}
	}
	popB, _ := svc.Population(ctx, b.ws, now.Add(-24*time.Hour), now.Add(time.Minute), []string{"alert", "containment"}, "", 10)
	if len(popB.Items) != 0 {
		t.Fatalf("B's population has A's records: %+v", popB.Items)
	}
}

func histCall(t *testing.T, api *p3OwnersAPI, method, path, tok string, body any) (int, map[string]any, *httptest.ResponseRecorder) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/api/iga/v1"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	api.eng.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, w
}

func TestHistoryExportRoutesSecondPerson(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "hist-export-a")
	b := p3NewGov(t, db, "hist-export-b")
	p3Audit(t, db, a.ws, b.ws)
	api := p3NewOwnersAPI(t, db)
	histSeedRuntime(t, a, time.Now().UTC().Add(-time.Hour))
	histGrantApprove(t, a, 1)
	histGrantApprove(t, b, 1)
	scope := "governance:read governance:author governance:approve"
	author := api.token(a.ws, a.author, a.authorMember, scope)
	member := func(ws, user uuid.UUID) uuid.UUID {
		var id string
		if err := db.Raw(`SELECT id::text FROM workspace_memberships WHERE workspace_id = ? AND user_id = ?`, ws, user).Scan(&id).Error; err != nil {
			t.Fatal(err)
		}
		return uuid.MustParse(id)
	}
	approver := api.token(a.ws, a.approver, member(a.ws, a.approver), scope)
	approverB := api.token(b.ws, b.approver, member(b.ws, b.approver), scope)
	readerOnly := api.token(a.ws, a.author, a.authorMember, "governance:read")

	from := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	to := time.Now().UTC().AddDate(0, 0, 1).Format("2006-01-02")
	if code, _, _ := histCall(t, api, "POST", "/exports", readerOnly, map[string]any{"from": from, "to": to, "reason": "audit"}); code != http.StatusForbidden {
		t.Fatalf("export needs governance:author: %d", code)
	}
	code, out, _ := histCall(t, api, "POST", "/exports", author, map[string]any{"from": from, "to": to, "reason": "SOC 2 sample", "kinds": []string{"alert", "containment"}})
	if code != http.StatusAccepted {
		t.Fatalf("export request: %d %v", code, out)
	}
	id := out["data"].(map[string]any)["id"].(string)
	if code, out, _ := histCall(t, api, "POST", "/history-approvals/"+id+"/approve", author, nil); code != http.StatusForbidden {
		t.Fatalf("requester approving: %d %v", code, out)
	}
	if code, out, _ := histCall(t, api, "POST", "/history-approvals/"+id+"/approve", approverB, nil); code != http.StatusNotFound {
		t.Fatalf("another workspace approving: %d %v", code, out)
	}
	code, out, _ = histCall(t, api, "POST", "/history-approvals/"+id+"/approve", approver, map[string]any{"reason": "ok"})
	if code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, out)
	}
	res := out["data"].(map[string]any)["result"].(map[string]any)
	exportID, sum := res["export_id"].(string), res["sha256"].(string)
	if res["item_count"].(float64) != 4 {
		t.Fatalf("export items: %v", res)
	}
	code, _, rec := histCall(t, api, "GET", "/exports/"+exportID+"/download", author, nil)
	if code != http.StatusOK || rec.Header().Get("X-Content-SHA256") != sum {
		t.Fatalf("download: %d", code)
	}
	got := sha256.Sum256(rec.Body.Bytes())
	if hex.EncodeToString(got[:]) != sum {
		t.Fatal("the bundle's bytes must match its sha256")
	}
	if code, _, _ := histCall(t, api, "GET", "/exports/"+exportID+"/download", approverB, nil); code != http.StatusNotFound {
		t.Fatalf("another workspace downloading: %d", code)
	}
	// Reads over HTTP.
	if code, out, _ := histCall(t, api, "GET", "/metrics/soc?period=30d", readerOnly, nil); code != http.StatusOK {
		t.Fatalf("soc: %d %v", code, out)
	}
	if code, _, _ := histCall(t, api, "GET", "/metrics/soc?period=1y", readerOnly, nil); code != http.StatusBadRequest {
		t.Fatalf("bad period: %d", code)
	}
	if code, out, _ := histCall(t, api, "GET", "/reports/population?from="+from+"&to="+to+"&kind=alert", readerOnly, nil); code != http.StatusOK ||
		len(out["data"].([]any)) != 2 {
		t.Fatalf("population: %d %v", code, out)
	}
	if code, _, _ := histCall(t, api, "GET", "/reports/ciso?month=2026-13", readerOnly, nil); code != http.StatusBadRequest {
		t.Fatalf("bad month: %d", code)
	}
}
