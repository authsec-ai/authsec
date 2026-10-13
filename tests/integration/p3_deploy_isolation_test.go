package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// AS-108: the deployment routes, the stuck-deployment sweeper and the
// attempt log run under row-level security for one workspace. Workspace A
// can neither see nor move workspace B's deployments (404, B unchanged), the
// sweeper settles each deployment in its own workspace, and the attempt log
// refuses a request naming another workspace than its job's.

type p3DepSnapshot struct {
	State     string
	UpdatedAt time.Time
	Events    int
	Jobs      int
	Attempts  int
}

func p3DepSnap(t *testing.T, g *p3Gov, dep uuid.UUID) p3DepSnapshot {
	t.Helper()
	var s p3DepSnapshot
	if err := g.db.Raw(`SELECT state, updated_at FROM iga_gov_deployment WHERE id = ?`, dep).Row().Scan(&s.State, &s.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	s.Events = len(g.events())
	for q, dst := range map[string]*int{
		`SELECT count(*) FROM iga_gov_job WHERE workspace_id = ?`:     &s.Jobs,
		`SELECT count(*) FROM iga_gov_attempt WHERE workspace_id = ?`: &s.Attempts,
	} {
		var n int64
		if err := g.db.Raw(q, g.ws).Scan(&n).Error; err != nil {
			t.Fatal(err)
		}
		*dst = int(n)
	}
	return s
}

func TestP3AS108DeploymentIDsOfAnotherWorkspace404(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "p3own-as108-dep-a")
	b := p3NewGov(t, db, "p3own-as108-dep-b")
	laneB := b.lane()
	depB := b.deployment(laneB, models.GovDeployApplying)
	b.deployment(b.lane(), models.GovDeployQueued)
	before := p3DepSnap(t, b, depB)

	ctx := context.Background()
	s := services.NewGovDeployments(db, nil)
	actor := a.author
	notFound := func(what string, err error) {
		t.Helper()
		if govCode(err) != "not_found" {
			t.Errorf("%s of workspace B's deployment from A: %v, want 404 not_found", what, err)
		}
	}
	_, err := s.GetDeployment(ctx, a.ws, depB)
	notFound("get", err)
	_, err = s.DeploymentGateFacts(ctx, a.ws, depB)
	notFound("gate facts", err)
	_, err = s.Resolve(ctx, a.ws, actor, depB, services.GovResolveRequest{Action: "reread", Reason: "probe"})
	notFound("resolve reread", err)
	_, err = s.Resolve(ctx, a.ws, actor, depB, services.GovResolveRequest{Action: "emergency_undo", Reason: "probe"})
	notFound("resolve emergency_undo", err)
	_, err = s.Undo(ctx, a.ws, actor, depB, services.GovUndoRequest{Reason: "probe"}, true)
	notFound("emergency undo", err)
	_, err = s.Undo(ctx, a.ws, actor, depB, services.GovUndoRequest{}, false)
	notFound("undo", err)
	_, err = s.DeclareValidation(ctx, a.ws, actor, depB, services.GovValidationRequest{Correlation: "assumed_session",
		Items:       []services.GovValidationItemInput{{Action: "sqs:SendMessage", Expected: "denied"}},
		WindowStart: time.Now(), WindowEnd: time.Now().Add(time.Hour)})
	notFound("declare validation", err)
	_, err = s.ListValidations(ctx, a.ws, depB)
	notFound("list validations", err)
	_, err = s.CreateHealthReport(ctx, a.ws, actor, depB, services.GovHealthReportRequest{Kind: "problem", Detail: "probe"}, true)
	notFound("health report", err)
	_, err = s.ListHealthReports(ctx, a.ws, depB)
	notFound("list health reports", err)
	_, err = s.RemoveControl(ctx, a.ws, actor, laneB.policy, services.GovRemoveControlRequest{
		ControlIDs: []string{laneB.control.String()}, Reason: "probe"}, true)
	notFound("emergency remove control of B's policy", err)
	_, err = s.StartRemoveControlDeployments(ctx, a.ws, actor, laneB.policy, 1)
	notFound("start remove control of B's version", err)
	list, _, err := s.ListDeployments(ctx, a.ws, services.GovDeploymentFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range list {
		if d.WorkspaceID != a.ws {
			t.Fatalf("A's deployment list shows %s of workspace %s", d.ID, d.WorkspaceID)
		}
	}

	if after := p3DepSnap(t, b, depB); after != before {
		t.Fatalf("workspace B changed: %+v -> %+v", before, after)
	}
	// B itself still sees its deployment.
	if d, err := s.GetDeployment(ctx, b.ws, depB); err != nil || d.Deployment.ID != depB {
		t.Fatalf("B reads its own deployment: %v", err)
	}
}

func TestP3AS108StuckSweepSettlesEachInItsWorkspace(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "p3own-as108-sweep-a")
	b := p3NewGov(t, db, "p3own-as108-sweep-b")
	depA := a.deployment(a.lane(), models.GovDeployQueued)
	depB := b.deployment(b.lane(), models.GovDeployQueued)
	p3exec(t, db, `UPDATE iga_gov_deployment SET updated_at = now() - interval '10 minutes' WHERE id = ?`, depA)
	// B's deployment is in flight but fresh (inside the sweep grace): the
	// sweep acting on A's stuck deployment must leave B's rows untouched.
	before := p3DepSnap(t, b, depB)

	out, err := services.NewGovDeployments(db, nil).SweepStuckDeployments(context.Background())
	if err != nil {
		t.Logf("sweep (other workspaces' rows may fail): %v", err)
	}
	if out[depA] != services.StuckRequeued {
		t.Fatalf("A's stuck deployment: %q, want %q", out[depA], services.StuckRequeued)
	}
	if _, ok := out[depB]; ok {
		t.Fatalf("B's fresh deployment was swept: %q", out[depB])
	}
	var jobs []models.IGAGovJob
	if err := db.Where("dedupe_key = ?", "deployment:"+depA.String()).Find(&jobs).Error; err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].WorkspaceID != a.ws || jobs[0].Kind != "deploy" {
		t.Fatalf("A's re-enqueued job: %+v", jobs)
	}
	if evs := a.events(); len(evs) == 0 || evs[len(evs)-1] != services.GovEventDeploymentRequeued {
		t.Fatalf("A's events: %v", evs)
	}
	if after := p3DepSnap(t, b, depB); after != before {
		t.Fatalf("workspace B changed: %+v -> %+v", before, after)
	}

	// Both stuck: each is settled in its own workspace (its job and event
	// carry its workspace, never the other's).
	p3exec(t, db, `UPDATE iga_gov_deployment SET updated_at = now() - interval '10 minutes' WHERE id = ?`, depB)
	if out, _ = services.NewGovDeployments(db, nil).SweepStuckDeployments(context.Background()); out[depB] != services.StuckRequeued {
		t.Fatalf("B's stuck deployment: %q", out[depB])
	}
	var ws []uuid.UUID
	if err := db.Raw(`SELECT workspace_id FROM iga_gov_job WHERE dedupe_key = ?`, "deployment:"+depB.String()).Scan(&ws).Error; err != nil {
		t.Fatal(err)
	}
	if len(ws) != 1 || ws[0] != b.ws {
		t.Fatalf("B's job workspaces: %v", ws)
	}
	var n int64
	if err := db.Raw(`SELECT count(*) FROM iga_gov_event WHERE deployment_id = ? AND workspace_id <> ?`, depB, b.ws).Scan(&n).Error; err != nil || n != 0 {
		t.Fatalf("events of B's deployment outside B: %d %v", n, err)
	}
}

func TestP3AS108AttemptLogRefusesAnotherWorkspace(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "p3own-as108-attempt-a")
	b := p3NewGov(t, db, "p3own-as108-attempt-b")
	depA := a.deployment(a.lane(), "applying")
	depB := b.deployment(b.lane(), "applying")
	runA := p3DeployRun(t, db, a, depA, "worker-a", 2*time.Minute, time.Now())
	log := services.NewIGAGovAttemptLog(db)
	before := p3DepSnap(t, b, depB)

	// A's job names B's workspace and deployment: refused before anything is
	// written.
	if _, err := log.Prepare(context.Background(), runA, p3Req(b, depB, 0, "CreatePolicy")); !errors.Is(err, services.ErrAttemptWorkspace) {
		t.Fatalf("prepare for B under A's job: %v, want ErrAttemptWorkspace", err)
	}
	// A's workspace but B's deployment id: RLS hides B's rows, so nothing of
	// B's moves (the attempt row cannot reference B's deployment).
	req := p3Req(a, depB, 0, "CreatePolicy")
	req.DocumentHash = ""
	if _, err := log.Prepare(context.Background(), runA, req); err == nil {
		t.Fatal("an attempt of A's job on B's deployment was recorded")
	}
	if _, err := log.Recover(context.Background(), runA, b.ws, depB); !errors.Is(err, services.ErrAttemptWorkspace) {
		t.Fatalf("recover of B's deployment under A's job: %v", err)
	}
	if after := p3DepSnap(t, b, depB); after != before {
		t.Fatalf("workspace B changed: %+v -> %+v", before, after)
	}
	// A's own attempt still works.
	if _, err := log.Prepare(context.Background(), runA, p3Req(a, depA, 0, "CreatePolicy")); err != nil {
		t.Fatalf("A's own attempt: %v", err)
	}
}
