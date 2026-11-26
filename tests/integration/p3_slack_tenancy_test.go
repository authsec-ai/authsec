package integration

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/slackapp"
	"github.com/authsec-ai/authsec/services"
)

// AS-108: a Slack interaction finds its workspace from the notification it
// names, then runs under row-level security for that workspace only if the
// signed request's Slack team is that workspace's installation. A click
// signed for team T2 (installed in workspace B, its user linked there) on a
// notification of workspace A, whose installation is team T1, is refused
// with team_not_connected and changes nothing in either workspace.
func TestP3SlackTenancyForeignTeamClick(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "p3-slack-ten-a")
	b := p3NewGov(t, db, "p3-slack-ten-b")
	app := newP3sApp(t, db, p3sGate(t, db))
	app.connectDirect(a.ws, "TTENA1", "CTENA1", a.author)
	app.connectDirect(b.ws, "TTENB2", "CTENB2", b.author)
	lane := a.lane()
	dep := a.deployment(lane, "applied_unverified")
	userB, _ := b.member("ten-b@p3sx.test", "Bea B", "active")
	app.link(b.ws, "UTENB", userB)
	t.Cleanup(services.InstallGovHealthReporter(db))

	n := uuid.New()
	p3exec(t, db, `INSERT INTO iga_gov_notification (id, workspace_id, subject_kind, subject_id, channel, recipient, state, sent_at, slack_ts)
		VALUES (?, ?, 'deployment', ?, 'slack', 'approvals_channel', 'sent', now(), '1700000000.777777')`, n, a.ws, dep)
	value := slackapp.ButtonValue{Notification: n.String()}.Encode()

	events := func() int64 {
		return p3sCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id IN (?, ?) AND event = ?`,
			a.ws, b.ws, services.GovEventSlackActionReceived)
	}
	lastTS := func() string {
		var s string
		db.Raw(`SELECT last_action_ts FROM iga_gov_notification WHERE id = ?`, n).Row().Scan(&s)
		return s
	}
	reports := func() int64 {
		return p3sCount(t, db, `SELECT count(*) FROM iga_gov_health_report WHERE deployment_id = ?`, dep)
	}

	code, out := app.click(p3sClick{team: "TTENB2", user: "UTENB", messageTS: "1700000000.777777", action: slackapp.ActionWorking, value: value})
	if code != http.StatusForbidden || p3sDetail(out, "reason") != "team_not_connected" {
		t.Fatalf("T2's click on A's notification: %d %v, want 403 team_not_connected", code, out)
	}
	if lastTS() != "" || events() != 0 || reports() != 0 {
		t.Fatalf("the refused click changed something: last_action_ts %q, %d events, %d reports", lastTS(), events(), reports())
	}
	if st := p3sCount(t, db, `SELECT count(*) FROM iga_gov_deployment WHERE workspace_id = ? AND id = ? AND state = 'applied_unverified'`, a.ws, dep); st != 1 {
		t.Fatal("A's deployment changed")
	}
}
