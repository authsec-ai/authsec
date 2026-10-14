package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/slackapp"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

func p3sGate(t *testing.T, db *gorm.DB) *services.PolicyGate {
	t.Helper()
	g := services.NewPolicyGate(true, "", p3GraphOn(t, db))
	if err := g.Verify(db); err != nil {
		t.Fatal(err)
	}
	return g
}

// T3.14 owner review through Slack (§7.4, §7.11, §9.3 S4): the owner review
// reaches a linked owner's Slack DM through the T3.12 notify job (with the
// age and route confirmations as checkboxes); Looks fine / Keep a service /
// This will break something call the review's Respond with Via slack; a
// DM's buttons act only for its recipient; Report a problem / It's working
// go to the (T3.15) health reporter; delivery failures follow the notify
// job's retry and dead rules.
func TestP3T314SlackOwnerReview(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3-t314-review")
	app := newP3sApp(t, db, p3sGate(t, db))
	ctx := context.Background()
	const team = "T314REV"
	app.connectDirect(g.ws, team, "C314REV", g.author)

	refund, refundRoleID := g.identity("RefundTaskRole", nil)
	wl := g.workload("refund-agent", &refund, models.RelTypeExecutesAs)
	u1, _ := g.member("u1-slack@p3slack.test", "Una Owner", "active")
	u2, _ := g.member("u2-slack@p3slack.test", "Ugo Other", "active")
	p3Manual(t, db, g, models.GovObjectWorkload, wl, u1, models.GovOwnerAccountable)
	app.link(g.ws, "UOWNER1", u1)
	app.link(g.ws, "UOTHER2", u2)
	route := igagov.Route{Service: "sqs", Resource: "arn:aws:sqs:us-east-1:111111111111:refunds", Principal: igagov.PrincipalRoleSession,
		Effect: igagov.RouteEffectBypassKnown}
	rev := g.reviewVersion(nil, 1, map[string]string{"sqs": igagov.GrantAgePredatesObservation, "dynamodb": igagov.GrantAgeObservedSinceChange},
		p3RevTarget{identity: refund, roleID: refundRoleID, name: "RefundTaskRole", removed: []string{"sqs", "dynamodb"}, retained: []string{"s3"},
			routes: []igagov.Route{route}})
	reviews := services.NewIGAGovOwnerReviewService(db)
	sync, err := reviews.OpenReview(ctx, g.ws, rev.version, g.author)
	if err != nil {
		t.Fatal(err)
	}
	var chans []string
	db.Raw(`SELECT channel FROM iga_gov_notification WHERE workspace_id = ? AND subject_id = ? AND recipient = ? ORDER BY channel`,
		g.ws, sync.ReviewID, "user:"+u1.String()).Scan(&chans)
	if strings.Join(chans, ",") != "email,slack" {
		t.Fatalf("owner notices on %v, want email and slack (Reaches)", chans)
	}
	email := &p3Outbox{}
	p3Drain(t, p3NotifyWorker(db, email, &p3Outbox{}))
	dms := app.fake.PostsTo("UOWNER1")
	if len(dms) != 1 || len(email.sent) != 1 {
		t.Fatalf("%d Slack DMs, %d emails", len(dms), len(email.sent))
	}
	dm := dms[0]
	var slackTS string
	var delivered []string
	db.Raw(`SELECT slack_ts FROM iga_gov_notification WHERE workspace_id = ? AND subject_id = ? AND channel = 'slack'`, g.ws, sync.ReviewID).Row().Scan(&slackTS)
	db.Raw(`SELECT unnest(delivery_channels) FROM iga_gov_owner_response WHERE workspace_id = ? AND review_id = ? AND user_id = ?`,
		g.ws, sync.ReviewID, u1).Scan(&delivered)
	if slackTS != dm.TS || !strings.Contains(strings.Join(delivered, ","), "slack") {
		t.Fatalf("slack_ts %q (post %q), delivery channels %v", slackTS, dm.TS, delivered)
	}
	btn := p3sButtons(dm)
	text := p3sText(dm.Message)
	ageVal := slackapp.ConfirmationValue("a", "sqs", "")
	routeVal := slackapp.ConfirmationValue("r", "sqs", services.GovRouteKey(route))
	for _, want := range []string{"Looks fine", "Keep a service", "This will break something", "sqs was not added recently", "sqs is not used through"} {
		if !strings.Contains(text, want) {
			t.Fatalf("DM lacks %q:\n%s", want, text)
		}
	}
	if btn[slackapp.ActionAcknowledge] == "" || btn[slackapp.ActionRetain] == "" || btn[slackapp.ActionObject] == "" {
		t.Fatalf("DM buttons %v", btn)
	}
	val := btn[slackapp.ActionAcknowledge]
	confirm := func(vals ...string) map[string]any {
		var opts []any
		for _, v := range vals {
			opts = append(opts, map[string]any{"value": v})
		}
		return map[string]any{slackapp.BlockConfirmations: map[string]any{"value": map[string]any{"type": "checkboxes", "selected_options": opts}}}
	}
	click := func(user, action string, state map[string]any) (int, map[string]any) {
		return app.click(p3sClick{team: team, user: user, messageTS: dm.TS, action: action, value: val, state: state})
	}

	// Another linked member cannot answer u1's DM.
	if code, out := click("UOTHER2", slackapp.ActionAcknowledge, confirm(ageVal, routeVal)); code != http.StatusForbidden || p3sDetail(out, "reason") != "not_recipient" {
		t.Fatalf("other member: %d %v", code, out)
	}
	// An objection needs a comment.
	if code, out := click("UOWNER1", slackapp.ActionObject, nil); code != http.StatusBadRequest {
		t.Fatalf("object without a comment: %d %v", code, out)
	}
	// Acknowledge with only the age confirmation: recorded; the gate still
	// wants the route confirmation.
	if code, out := click("UOWNER1", slackapp.ActionAcknowledge, confirm(ageVal)); code != http.StatusOK {
		t.Fatalf("acknowledge: %d %v", code, out)
	}
	wantGov(t, reviews.CheckGate(db, g.ws, rev.version), "route_unconfirmed")
	// Again with both: the review completes.
	if code, out := click("UOWNER1", slackapp.ActionAcknowledge, confirm(ageVal, routeVal)); code != http.StatusOK {
		t.Fatalf("acknowledge with confirmations: %d %v", code, out)
	}
	wantGov(t, reviews.CheckGate(db, g.ws, rev.version), "")
	var via, resp string
	db.Raw(`SELECT responded_via, response FROM iga_gov_owner_response WHERE workspace_id = ? AND review_id = ? AND user_id = ?`,
		g.ws, sync.ReviewID, u1).Row().Scan(&via, &resp)
	if via != "slack" || resp != "acknowledge" {
		t.Fatalf("response %s via %s", resp, via)
	}
	if n := p3sCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'review.responded' AND actor_kind = 'slack_user' AND actor_id = ?`,
		g.ws, u1.String()); n != 2 {
		t.Fatalf("%d review.responded events by the slack user", n)
	}
	if n := p3sCountEventually(t, db, 2, `SELECT count(*) FROM audit_events WHERE workspace_id = ? AND action = 'respond' AND user_id = ?`, g.ws.String(), u1.String()); n != 2 {
		t.Fatalf("%d respond audit rows", n)
	}
	if r := app.fake.LastResponse().Message; !r.ReplaceOriginal || !strings.Contains(r.Text, "looks fine") {
		t.Fatalf("outcome %+v", r)
	}

	// Keep a service: service, reason and review date from the message.
	retain := map[string]any{
		slackapp.BlockRetainService: map[string]any{"value": map[string]any{"type": "multi_static_select", "selected_options": []any{map[string]any{"value": "sqs"}}}},
		slackapp.BlockReviewBy:      map[string]any{"value": map[string]any{"type": "datepicker", "selected_date": "2099-01-31"}},
		slackapp.BlockNote:          map[string]any{"value": map[string]any{"type": "plain_text_input", "value": "monthly alert job"}},
	}
	if code, out := click("UOWNER1", slackapp.ActionRetain, retain); code != http.StatusOK {
		t.Fatalf("retain: %d %v", code, out)
	}
	var items string
	db.Raw(`SELECT retain_items::text FROM iga_gov_owner_response WHERE workspace_id = ? AND review_id = ? AND user_id = ?`,
		g.ws, sync.ReviewID, u1).Row().Scan(&items)
	if !strings.Contains(items, `"service": "sqs"`) || !strings.Contains(items, "monthly alert job") || !strings.Contains(items, "2099-01-31") {
		t.Fatalf("retain items %s", items)
	}

	t.Run("health reports", func(t *testing.T) {
		dep := uuid.New()
		n := uuid.New()
		p3exec(t, db, `INSERT INTO iga_gov_notification (id, workspace_id, subject_kind, subject_id, channel, recipient, state, sent_at, slack_ts)
			VALUES (?, ?, 'deployment', ?, 'slack', ?, 'sent', now(), '1700000000.999999')`, n, g.ws, dep, "user:"+u1.String())
		v := slackapp.ButtonValue{Notification: n.String()}.Encode()
		hc := func(action string, state map[string]any) (int, map[string]any) {
			return app.click(p3sClick{team: team, user: "UOWNER1", messageTS: "1700000000.999999", action: action, value: v, state: state})
		}
		if code, out := hc(slackapp.ActionWorking, nil); code != http.StatusServiceUnavailable || p3eErr(out) != "health_reports_unavailable" {
			t.Fatalf("no reporter: %d %v", code, out)
		}
		h := &p3sHealth{}
		t.Cleanup(services.SetGovHealthReporter(h))
		if code, out := hc(slackapp.ActionReportProblem, nil); code != http.StatusBadRequest {
			t.Fatalf("problem without detail: %d %v", code, out)
		}
		if code, out := hc(slackapp.ActionReportProblem, p3sNote("refunds time out")); code != http.StatusOK {
			t.Fatalf("problem: %d %v", code, out)
		}
		if code, out := hc(slackapp.ActionWorking, nil); code != http.StatusOK {
			t.Fatalf("working: %d %v", code, out)
		}
		if len(h.got) != 2 || h.got[0].Kind != "problem" || h.got[0].Detail != "refunds time out" || h.got[0].SubjectID != dep ||
			h.got[0].ActorID != u1 || h.got[0].Channel != "slack" || h.got[1].Kind != "working" {
			t.Fatalf("reports %+v", h.got)
		}
	})

	t.Run("delivery failures", func(t *testing.T) {
		resend := func() uuid.UUID {
			var nid uuid.UUID
			if err := db.Transaction(func(tx *gorm.DB) error {
				nn, err := services.EnqueueGovNotificationTx(tx, g.ws, services.GovNoticeOwnerReview, sync.ReviewID, services.GovChannelSlack,
					services.GovUserRecipient(u1), true)
				if nn != nil {
					nid = nn.ID
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return nid
		}
		state := func(id uuid.UUID) string {
			var s string
			db.Raw(`SELECT state FROM iga_gov_notification WHERE id = ?`, id).Row().Scan(&s)
			return s
		}
		w := p3NotifyWorker(db, &p3Outbox{}, &p3Outbox{})
		app.fake.SetPostErr(&slackapp.APIError{Method: "chat.postMessage", Code: "ratelimited"})
		id := resend()
		w.RunOnce(ctx)
		if state(id) != "failed" {
			t.Fatalf("transient failure: state %s, want failed (retried)", state(id))
		}
		app.fake.SetPostErr(&slackapp.APIError{Method: "chat.postMessage", Code: "channel_not_found"})
		p3exec(t, db, `UPDATE iga_gov_job SET run_after = now() WHERE workspace_id = ? AND dedupe_key = ?`, g.ws, "notification:"+id.String())
		p3exec(t, db, `UPDATE iga_gov_notification SET available_at = now() WHERE id = ?`, id)
		w.RunOnce(ctx)
		if state(id) != "dead" {
			t.Fatalf("permanent failure: state %s, want dead", state(id))
		}
		app.fake.SetPostErr(nil)
	})

}
