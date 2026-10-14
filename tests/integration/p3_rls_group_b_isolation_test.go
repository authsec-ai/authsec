package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// AS-108 cross-workspace isolation of the authoring, approval, settings and
// notification code once it runs under row-level security.

// An approver of another workspace, holding every scope, cannot approve,
// reject or withdraw this workspace's version: every route answers 404 and
// nothing changes -- the version stays in review, no approval, acceptance or
// event is written in either workspace -- and this workspace's own approver
// still approves afterwards.
func TestP3RLSApprovalFromAnotherWorkspaceChangesNothing(t *testing.T) {
	l := newP3aLab(t, "p3-rls-b-approval")
	l.role("IsoRole", "AROAISOLATION001", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	policy, _ := l.proposeTemplate("AROAISOLATION001")
	plans := l.compile(policy, 1)
	if l.status(policy, 1) != "in_review" {
		t.Fatalf("status %s", l.status(policy, 1))
	}

	ows := newWorkspace(t, l.db, "p3-rls-b-approval-other")
	om := p3aMember{user: uuid.New(), membership: uuid.New(), role: uuid.New()}
	p3exec(t, l.db, `INSERT INTO users (id, email, name, workspace_id) VALUES (?, ?, 'other', ?)`, om.user, om.user.String()+"@p3a.test", ows)
	p3exec(t, l.db, `INSERT INTO roles (id, name, workspace_id) VALUES (?, 'p3-rls-b-other', ?)`, om.role, ows)
	p3exec(t, l.db, `INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status) VALUES (?, ?, ?, ?, 'active')`, om.membership, ows, om.user, om.role)
	t.Cleanup(func() {
		l.db.Exec(`DELETE FROM audit_events WHERE workspace_id = ?`, ows.String())
		l.db.Exec(`DELETE FROM workspace_memberships WHERE id = ?`, om.membership)
		l.db.Exec(`DELETE FROM users WHERE id = ?`, om.user)
		l.db.Exec(`DELETE FROM roles WHERE id = ?`, om.role)
	})
	ot := l.token(ows, om, p3aAllScopes)

	eventsBefore := l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ?`, l.ws)
	for _, r := range []struct {
		path string
		body map[string]any
	}{
		// A well-formed approval: the hashes are the current ones.
		{"/versions/1/approve", p3aApproveBody(plans, nil)},
		{"/versions/1/reject", map[string]any{"reason": "not mine to decide"}},
		{"/versions/1/withdraw", map[string]any{"reason": "not mine either"}},
	} {
		if code, body := l.callAs(ot, http.MethodPost, "/policies/"+policy+r.path, r.body); code != http.StatusNotFound {
			t.Fatalf("other workspace POST %s: %d %v, want 404", r.path, code, body)
		}
	}
	if s := l.status(policy, 1); s != "in_review" {
		t.Fatalf("status after cross-workspace decisions: %s", s)
	}
	for _, q := range []string{
		`SELECT count(*) FROM iga_gov_approval WHERE workspace_id IN (?, ?)`,
		`SELECT count(*) FROM iga_gov_acceptance WHERE workspace_id IN (?, ?)`,
	} {
		if n := l.count(q, l.ws, ows); n != 0 {
			t.Fatalf("%s: %d rows", q, n)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ?`, ows); n != 0 {
		t.Fatalf("%d events written in the other workspace", n)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ?`, l.ws); n != eventsBefore {
		t.Fatalf("events in this workspace %d -> %d", eventsBefore, n)
	}
	// The service, called with the other workspace (as a token of it would),
	// does not find the version either.
	vid := l.versionID(policy, 1)
	if _, err := l.authoring().UsableApproval(context.Background(), ows, vid, nil); !isGovStatus(err, http.StatusNotFound) {
		t.Fatalf("UsableApproval from the other workspace: %v, want 404", err)
	}

	l.approveAll(policy, 1)
	if s := l.status(policy, 1); s != "approved" {
		t.Fatalf("status after this workspace's approval: %s", s)
	}
}

func isGovStatus(err error, status int) bool {
	ge, ok := err.(*services.GovError)
	return ok && ge.Status == status
}

// Each workspace's settings and notification channels are its own: A's
// channel change is not seen by B, and B's later change leaves A's row and
// webhook secret as they were.
func TestP3RLSSettingsAndChannelsPerWorkspace(t *testing.T) {
	db := igaDB(t)
	api := p3NewOwnersAPI(t, db)
	vault := newMemVault()
	t.Cleanup(services.SetGovNotificationChannelStore(services.NewGovDBChannelStore(vault)))
	a := p3NewGov(t, db, "p3-rls-b-settings-a")
	b := p3NewGov(t, db, "p3-rls-b-settings-b")
	p3Audit(t, db, a.ws, b.ws)
	ta := api.token(a.ws, a.author, a.authorMember, "governance:read governance:enforce")
	tb := api.token(b.ws, b.author, b.authorMember, "governance:read governance:enforce")

	code, body := api.call(http.MethodPut, "/settings", ta, map[string]any{"canary_hours": 30,
		"notifications": map[string]any{"email_enabled": false, "webhook_url": "https://hooks.a.test/x", "webhook_secret": "secret-of-a"}})
	if code != http.StatusOK {
		t.Fatalf("A PUT: %d %v", code, body)
	}
	var refA string
	db.Raw(`SELECT notify_webhook_secret_ref FROM iga_gov_settings WHERE workspace_id = ?`, a.ws).Scan(&refA)
	if refA == "" {
		t.Fatal("A's secret was not stored")
	}
	code, body = api.call(http.MethodGet, "/settings", tb, nil)
	if code != http.StatusOK || dig(body, "data", "canary_hours") == float64(30) || dig(body, "data", "saved") != false ||
		digs(body, "data", "notifications", "webhook_url") != "" || dig(body, "data", "notifications", "email_enabled") != true ||
		dig(body, "data", "notifications", "webhook_secret_set") != false {
		t.Fatalf("B sees A's settings: %d %v", code, body)
	}

	code, body = api.call(http.MethodPut, "/settings", tb, map[string]any{"canary_hours": 12,
		"notifications": map[string]any{"webhook_url": "https://hooks.b.test/y", "webhook_secret": "secret-of-b"}})
	if code != http.StatusOK {
		t.Fatalf("B PUT: %d %v", code, body)
	}
	code, body = api.call(http.MethodGet, "/settings", ta, nil)
	if code != http.StatusOK || dig(body, "data", "canary_hours") != float64(30) ||
		digs(body, "data", "notifications", "webhook_url") != "https://hooks.a.test/x" ||
		dig(body, "data", "notifications", "email_enabled") != false {
		t.Fatalf("A after B's change: %d %v", code, body)
	}
	var refA2, refB string
	db.Raw(`SELECT notify_webhook_secret_ref FROM iga_gov_settings WHERE workspace_id = ?`, a.ws).Scan(&refA2)
	db.Raw(`SELECT notify_webhook_secret_ref FROM iga_gov_settings WHERE workspace_id = ?`, b.ws).Scan(&refB)
	if refA2 != refA || refB == refA {
		t.Fatalf("secret refs: A %q -> %q, B %q", refA, refA2, refB)
	}
	if sec, err := vault.ReadSecret(refA); err != nil || sec["secret"] != "secret-of-a" {
		t.Fatalf("A's secret after B's change: %v %v", sec, err)
	}
	// The webhook target each workspace's notices resolve is its own.
	for _, c := range []struct {
		ws  uuid.UUID
		url string
	}{{a.ws, "https://hooks.a.test/x"}, {b.ws, "https://hooks.b.test/y"}} {
		var got *services.GovWebhookTarget
		if err := tenancy.InWorkspaceRead(context.Background(), db, c.ws, func(tx *gorm.DB) error {
			var err error
			got, err = services.GovWorkspaceWebhookTarget(tx, c.ws)
			return err
		}); err != nil || got == nil || got.URL != c.url {
			t.Fatalf("webhook target of %s: %+v %v", c.ws, got, err)
		}
	}
	if n := len(b.eventsNamed("settings.updated")); n != 1 {
		t.Fatalf("B's settings events: %d", n)
	}
	if n := len(a.eventsNamed("settings.updated")); n != 1 {
		t.Fatalf("A's settings events: %d", n)
	}
}

// Migration 132: a notice's natural key is per workspace. The same subject,
// channel and recipient in two workspaces are two notices; enqueueing again
// in one workspace returns its own row; and neither workspace's transaction
// sees the other's.
func TestP3RLSNotificationUniquePerWorkspace(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "p3-rls-b-notify-a")
	b := p3NewGov(t, db, "p3-rls-b-notify-b")
	subject, recipient := uuid.New(), services.GovUserRecipient(uuid.New())
	enqueue := func(ws uuid.UUID) *models.IGAGovNotification {
		t.Helper()
		var n *models.IGAGovNotification
		if err := tenancy.InWorkspace(context.Background(), db, ws, func(tx *gorm.DB) error {
			var err error
			n, err = services.EnqueueGovNotificationTx(tx, ws, services.GovNoticeOwnerReview, subject, services.GovChannelEmail, recipient, false)
			return err
		}); err != nil {
			t.Fatalf("enqueue in %s: %v", ws, err)
		}
		return n
	}
	na, nb := enqueue(a.ws), enqueue(b.ws)
	if na.ID == nb.ID || na.WorkspaceID != a.ws || nb.WorkspaceID != b.ws {
		t.Fatalf("notices %+v / %+v", na, nb)
	}
	if again := enqueue(a.ws); again.ID != na.ID {
		t.Fatalf("re-enqueue in A returned %s, want %s", again.ID, na.ID)
	}
	for _, c := range []struct{ ws, foreign uuid.UUID }{{a.ws, nb.ID}, {b.ws, na.ID}} {
		var seen int64
		if err := tenancy.InWorkspaceRead(context.Background(), db, c.ws, func(tx *gorm.DB) error {
			return tx.Raw(`SELECT count(*) FROM iga_gov_notification WHERE id = ?`, c.foreign).Scan(&seen).Error
		}); err != nil || seen != 0 {
			t.Fatalf("workspace %s sees the other's notice: %d %v", c.ws, seen, err)
		}
	}
	var total int64
	db.Raw(`SELECT count(*) FROM iga_gov_notification WHERE subject_id = ?`, subject).Scan(&total)
	if total != 2 {
		t.Fatalf("%d notices, want one per workspace", total)
	}
}
