package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// Review fix R1a P2 "Events: redact before insert". iga_gov_event is
// append-only, so a raw e-mail or webhook URL stored there stays forever.
// Through the REAL writers -- PUT /settings (webhook URL, an enforce reason
// naming a person's e-mail) and the repository's AppendTx -- the STORED row
// holds neither; the read side still redacts a row written before the fix
// (inserted here by raw SQL, bypassing the model).
func TestP3EventsRedactedBeforeInsert(t *testing.T) {
	db := igaDB(t)
	api := p3NewOwnersAPI(t, db)
	g := p3NewGov(t, db, "p3misc-event-redaction")
	p3Audit(t, db, g.ws)
	t.Cleanup(services.SetGovNotificationChannelStore(services.NewGovDBChannelStore(newMemVault())))
	enforcer := api.token(g.ws, g.author, g.authorMember, "governance:read governance:enforce")

	const hook = "https://hooks.slack.com/services/T000/B000/XXXXSECRETXXXX"
	const email = "ops.lead@customer-corp.example"
	if code, body := api.call(http.MethodPut, "/settings", enforcer, map[string]any{
		"notifications": map[string]any{"webhook_url": hook, "webhook_secret": "whsec-very-secret"}}); code != http.StatusOK {
		t.Fatalf("PUT webhook: %d %v", code, body)
	}
	if code, body := api.call(http.MethodPut, "/settings", enforcer, map[string]any{"enforcement_mode": "enforce",
		"reason": "approved by " + email + " in CAB-7"}); code != http.StatusOK {
		t.Fatalf("PUT enforce: %d %v", code, body)
	}
	// A writer through the repository (every writer goes through the model).
	if err := repositories.NewIGAGovEventRepository(db).AppendTx(db, &models.IGAGovEvent{WorkspaceID: g.ws,
		Event: services.GovEventSettingsUpdated, ActorKind: models.GovActorSystem, ActorID: "test",
		Payload: json.RawMessage(`{"slack_email":"` + email + `","note":"ping ` + email + `","response_url":"https://x.example/cb?sig=abc",
		  "token_hint":"xoxb-1234567890-abcdefghij","pr_url":"https://github.com/acme/infra/pull/42","rev":9007199254740993,
		  "webhook_signed":true}`)}); err != nil {
		t.Fatal(err)
	}

	var rows []string
	if err := db.Raw(`SELECT payload::text FROM iga_gov_event WHERE workspace_id = ? ORDER BY id`, g.ws).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) < 3 {
		t.Fatalf("%d events", len(rows))
	}
	all := strings.Join(rows, "\n")
	for _, raw := range []string{"hooks.slack.com", "XXXXSECRETXXXX", email, "@customer-corp", "whsec-very-secret", "sig=abc", "xoxb-"} {
		if strings.Contains(all, raw) {
			t.Errorf("a stored iga_gov_event payload contains %q:\n%s", raw, all)
		}
	}
	// Correlation data is kept: the PR link, exact numbers, booleans, the
	// redaction marker in place of the webhook URL.
	for _, kept := range []string{"https://github.com/acme/infra/pull/42", "9007199254740993", `"webhook_signed": true`,
		`"webhook_url": "[redacted]"`, "approved by [redacted] in CAB-7"} {
		if !strings.Contains(all, kept) {
			t.Errorf("stored payloads lost %q:\n%s", kept, all)
		}
	}

	// A row written before the fix (raw SQL bypasses the model) is still
	// redacted on read.
	p3exec(t, db, `INSERT INTO iga_gov_event (workspace_id, event, actor_kind, actor_id, payload)
		VALUES (?, 'settings.updated', 'system', 'legacy', ?::jsonb)`, g.ws,
		`{"webhook_url":"`+hook+`","owner_email":"`+email+`","keep":"visible"}`)
	reader := api.token(g.ws, g.author, g.authorMember, "governance:read")
	code, body := api.call(http.MethodGet, "/events?kind=settings.updated", reader, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /events: %d %v", code, body)
	}
	out, _ := json.Marshal(body)
	if strings.Contains(string(out), "hooks.slack.com") || strings.Contains(string(out), email) || !strings.Contains(string(out), "visible") {
		t.Fatalf("read-side redaction of an old row: %s", out)
	}
	_ = uuid.Nil
}
