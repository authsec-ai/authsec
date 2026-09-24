package integration

// B13 (SPEC-iga-phase2-graph.md §7.3; §7.5 S2 -> S1: the switch turned off
// after an 'on' period) and E1 (§7.1: the first publication), through the
// REAL scan worker and projector.

import (
	"strings"
	"testing"
	"time"

	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// bdbLease is the workspace's barrier row, every column.
type bdbLease struct {
	State     string
	Holder    string
	ScanRunID *uuid.UUID
	ExpiresAt *time.Time
	Version   int64
	UpdatedAt time.Time
}

func bdbBarrier(t *testing.T, l *p2Lab) (bdbLease, bool) {
	t.Helper()
	var rows []bdbLease
	if err := l.db.Raw(`SELECT state, holder, scan_run_id, expires_at, version, updated_at
	                      FROM iga_pipeline_lease WHERE workspace_id = ?`, l.ws).Scan(&rows).Error; err != nil {
		t.Fatalf("read barrier: %v", err)
	}
	if len(rows) == 0 {
		return bdbLease{}, false
	}
	return rows[0], true
}

// B13 hardening: the switch is turned OFF in a workspace that already ran
// with it ON -- an idle barrier row, a projection job and a publication left
// from that period. Two consecutive off-mode scans both publish, and neither
// touches the barrier (state, holder, run, expiry, version and updated_at all
// byte-identical), queues a job, or publishes a revision. The existing
// TestP2SwitchOffTwoScans covers only a workspace with NO barrier row, where a
// Phase 1 worker has nothing to disturb.
//
// Safeguard (mutation-checked): the scan worker's switch -- a worker that
// takes the pipeline path while the switch is off acquires the barrier (the
// table-probing enablement §7.3 names).
func TestP2BdbSwitchOffLeavesTheIdleBarrier(t *testing.T) {
	l := newP2Lab(t, "p2-bdb-b13", true)
	a := oneLambda(l)
	l.scanAndProject(a) // the 'on' period: barrier row idle, one job, one publication
	before, ok := bdbBarrier(t, l)
	if !ok || before.State != models.PipelineIdle || before.Version == 0 {
		t.Fatalf("setup: barrier after the 'on' period = %+v (present %v), want an idle row that has moved", before, ok)
	}
	jobs := l.count(`SELECT count(*) FROM iga_projection_job WHERE workspace_id = ?`, l.ws)
	pubs := l.count(`SELECT count(*) FROM iga_publication WHERE workspace_id = ?`, l.ws)

	l.gate = services.NewGraphProjectionGate(false, "") // S2 -> S1: the switch turned off
	time.Sleep(10 * time.Millisecond)
	for _, owner := range []string{"scan-worker-off-a", "scan-worker-off-b"} {
		if run := l.scan(a, owner); run.Status != models.CloudScanRunPublished {
			t.Fatalf("%s: run %s, want published", owner, run.Status)
		}
	}

	after, ok := bdbBarrier(t, l)
	if !ok || after.State != before.State || after.Holder != before.Holder || !sameRun(after.ScanRunID, before.ScanRunID) ||
		after.Version != before.Version || !after.UpdatedAt.Equal(before.UpdatedAt) ||
		(after.ExpiresAt == nil) != (before.ExpiresAt == nil) ||
		(after.ExpiresAt != nil && !after.ExpiresAt.Equal(*before.ExpiresAt)) {
		t.Errorf("barrier %+v -> %+v: a Phase 1 scan must not touch it", before, after)
	}
	if n := l.count(`SELECT count(*) FROM iga_projection_job WHERE workspace_id = ?`, l.ws); n != jobs {
		t.Errorf("projection jobs %d -> %d with the switch off", jobs, n)
	}
	if n := l.count(`SELECT count(*) FROM iga_publication WHERE workspace_id = ?`, l.ws); n != pubs {
		t.Errorf("publications %d -> %d with the switch off", pubs, n)
	}
	if n := l.count(`SELECT count(*) FROM cloud_scan_run WHERE workspace_id = ? AND status = 'published'`, l.ws); n != 3 {
		t.Errorf("published runs = %d, want 3 (one on, two off)", n)
	}
}

// E1 (§7.1): a clean workspace connects account A with two regions and scans
// once. The database says: one published run, one job complete, the barrier
// idle, ONE publication at rev 1 for that run, and no AWS row in iga_agents or
// iga_agent_instances -- although the account runs a Bedrock agent, which the
// graph holds as a WORKLOAD classified provider_native_agent (§2.2: no AWS row
// is ever an agent row). The API lists the account's workloads at rev 1. And
// the second scan starts and publishes rev 2.
//
// Safeguards (mutation-checked): the first revision is 1 (NextRevision), and
// no projection pass writes iga_agents (the graph branch's projectAgents).
func TestP2BdbFirstPublication(t *testing.T) {
	l := newP2Lab(t, "p2-bdb-e1", true)
	a := l.account(accountA, "eu-central-1", "us-east-1")
	role := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	agentRole := a.role("SupportAgentRole", "AROASUPPORTAGENTROL1")
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	listsFunctions(a, "us-east-1", "ticket-tools", role)
	fakes := bdbFakes{agents: []bedrockagenttypes.Agent{bdbAgent(a, "eu-central-1", "AGENTE1SUPPORT", "support-bot", agentRole)}}
	run := bdbCycle(l, a, fakes)

	if n := l.count(`SELECT count(*) FROM cloud_scan_run WHERE workspace_id = ? AND status = 'published'`, l.ws); n != 1 {
		t.Errorf("published runs = %d, want 1", n)
	}
	if n := l.count(`SELECT count(*) FROM iga_projection_job WHERE workspace_id = ? AND status = 'complete'`, l.ws); n != 1 ||
		l.count(`SELECT count(*) FROM iga_projection_job WHERE workspace_id = ?`, l.ws) != 1 {
		t.Errorf("projection jobs complete = %d, want exactly one job, complete", n)
	}
	if b, ok := bdbBarrier(t, l); !ok || b.State != models.PipelineIdle {
		t.Errorf("barrier = %+v (present %v), want idle", b, ok)
	}
	var pubs []struct {
		Rev       int64
		ScanRunID uuid.UUID
	}
	l.db.Raw(`SELECT rev, scan_run_id FROM iga_publication WHERE workspace_id = ?`, l.ws).Scan(&pubs)
	if len(pubs) != 1 || pubs[0].Rev != 1 || pubs[0].ScanRunID != run.ID {
		t.Errorf("publications = %+v, want exactly one, rev 1, for run %s", pubs, run.ID)
	}

	// The Bedrock agent is a workload, provider_native_agent -- never an agent row.
	var agent struct {
		Classification string
		Region         string
	}
	l.db.Raw(`SELECT classification, region FROM iga_workload WHERE workspace_id = ? AND display_name = 'support-bot'`,
		l.ws).Scan(&agent)
	if agent.Classification != models.ClassificationProviderAgent || agent.Region != "eu-central-1" {
		t.Fatalf("support-bot = %+v, want a workload in eu-central-1 classified provider_native_agent", agent)
	}
	for _, table := range []string{"iga_agents", "iga_agent_instances"} {
		if n := l.count(`SELECT count(*) FROM `+table+` WHERE workspace_id = ?`, l.ws); n != 0 {
			t.Errorf("%s has %d rows after an AWS scan: no AWS row is ever an agent row (§2.2)", table, n)
		}
	}

	// /workloads lists A's workloads at rev 1.
	body := listsGet(t, l.api(), "/workloads")
	if num(body, "meta", "rev") != 1 {
		t.Errorf("/workloads meta.rev = %v, want 1", dig(body, "meta", "rev"))
	}
	names := listsField(digl(body, "data"), "name")
	if strings.Join(names, ",") != "support-bot,ticket-tools" {
		t.Errorf("/workloads names = %v, want support-bot and ticket-tools", names)
	}
	for _, row := range digl(body, "data") {
		if digs(row, "account", "id") != accountA {
			t.Errorf("workload row %v: account %q, want %s", dig(row, "name"), digs(row, "account", "id"), accountA)
		}
	}

	// The second scan starts, and publishes rev 2.
	second := bdbCycle(l, a, fakes)
	if rev := bdbRevOf(t, l, second.ID); rev != 2 {
		t.Errorf("second publication rev = %d, want 2", rev)
	}
}
