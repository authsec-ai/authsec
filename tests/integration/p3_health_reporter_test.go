package integration

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/slackapp"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// Review fix R1a P2: SetGovHealthReporter had no production caller, so every
// Slack "Report a problem" / "It's working" answered 503
// health_reports_unavailable in production. The startup wiring
// (InstallGovPolicyRuntime -> InstallGovHealthReporter) now installs T3.16's
// health-report path: through the Slack interactions endpoint, an owner's
// click on a deployment notice records an iga_gov_health_report (channel
// slack) and its health.reported event; a member who is neither an owner of
// a consumer nor an author is refused by the same rule as the UI route; a
// canary_gate notice records on the rollout's canary deployment.
func TestP3SlackHealthReportsUseTheProductionReporter(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3misc-health-reporter")
	app := newP3sApp(t, db, p3sGate(t, db))
	const team = "TMISCHR"
	app.connectDirect(g.ws, team, "CMISCHR", g.author)
	lane := g.lane()
	dep := g.deployment(lane, "applied_unverified")
	owner, _ := g.member("hr-owner@p3misc.test", "Hana Owner", "active")
	stranger, _ := g.member("hr-stranger@p3misc.test", "Sam Stranger", "active")
	p3Manual(t, db, g, models.GovObjectIdentityAccount, lane.identity, owner, models.GovOwnerAccountable)
	app.link(g.ws, "UHROWNER", owner)
	app.link(g.ws, "UHRSTRANGER", stranger)

	notice := func(kind string, subject uuid.UUID, user uuid.UUID, ts string) string {
		n := uuid.New()
		p3exec(t, db, `INSERT INTO iga_gov_notification (id, workspace_id, subject_kind, subject_id, channel, recipient, state, sent_at, slack_ts)
			VALUES (?, ?, ?, ?, 'slack', ?, 'sent', now(), ?)`, n, g.ws, kind, subject, "user:"+user.String(), ts)
		return slackapp.ButtonValue{Notification: n.String()}.Encode()
	}
	click := func(slackUser, ts, value, action string, state map[string]any) (int, map[string]any) {
		return app.click(p3sClick{team: team, user: slackUser, messageTS: ts, action: action, value: value, state: state})
	}

	// The startup wiring is what installs it (no reporter before).
	t.Cleanup(services.SetGovHealthReporter(nil))
	v := notice(services.GovNoticeDeployment, dep, owner, "1700000000.111111")
	if code, out := click("UHROWNER", "1700000000.111111", v, slackapp.ActionWorking, nil); code != http.StatusServiceUnavailable {
		t.Fatalf("no reporter installed: %d %v, want 503", code, out)
	}
	restore := services.InstallGovHealthReporter(db)
	defer restore()

	if code, out := click("UHROWNER", "1700000000.111111", v, slackapp.ActionReportProblem, p3sNote("refunds time out after the change")); code != http.StatusOK {
		t.Fatalf("owner's problem report: %d %v", code, out)
	}
	var rows []models.IGAGovHealthReport
	db.Where("workspace_id = ? AND deployment_id = ?", g.ws, dep).Find(&rows)
	if len(rows) != 1 || rows[0].Kind != "problem" || rows[0].Channel != "slack" || rows[0].ReportedBy != owner ||
		rows[0].Detail != "refunds time out after the change" {
		t.Fatalf("stored reports %+v", rows)
	}
	var events int64
	db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = ? AND deployment_id = ?`,
		g.ws, services.GovEventHealthReported, dep).Scan(&events)
	if events != 1 {
		t.Fatalf("health.reported events: %d", events)
	}

	// Not an owner of a consumer, not an author: refused like the UI route.
	vs := notice(services.GovNoticeDeployment, dep, stranger, "1700000000.222222")
	if code, out := click("UHRSTRANGER", "1700000000.222222", vs, slackapp.ActionWorking, nil); code != http.StatusForbidden ||
		p3eErr(out) != services.GovCodeNotConsumerOwner {
		t.Fatalf("stranger: %d %v, want 403 %s", code, out, services.GovCodeNotConsumerOwner)
	}

	// A canary_gate notice (subject: the rollout) records on its canary.
	rollout := uuid.New()
	p3exec(t, db, `INSERT INTO iga_gov_rollout (id, workspace_id, version_id, stage) VALUES (?, ?, ?, 'canary')`,
		rollout, g.ws, lane.version)
	vc := notice(services.GovNoticeCanaryGate, rollout, owner, "1700000000.333333")
	if code, out := click("UHROWNER", "1700000000.333333", vc, slackapp.ActionWorking, nil); code != http.StatusOK {
		t.Fatalf("canary notice: %d %v", code, out)
	}
	var n int64
	db.Raw(`SELECT count(*) FROM iga_gov_health_report WHERE workspace_id = ? AND deployment_id = ? AND kind = 'working'`, g.ws, dep).Scan(&n)
	if n != 1 {
		t.Fatalf("canary working reports on the canary deployment: %d", n)
	}
	_ = context.Background()
}

// The production startup path installs the reporter: InstallGovPolicyRuntime
// (called by cmd/main.go once the Phase 3 schema verifies) calls
// InstallGovHealthReporter.
func TestP3PolicyRuntimeInstallsTheHealthReporter(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join("..", "..", "services", "iga_gov_wiring.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "InstallGovPolicyRuntime" {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "InstallGovHealthReporter" {
					found = true
				}
			}
			return true
		})
	}
	if !found {
		t.Fatal("InstallGovPolicyRuntime does not install the health reporter")
	}
}
