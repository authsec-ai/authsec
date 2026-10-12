// The two legacy governance mutations that wrote no audit_events row
// (disposition plan §5 step 1): the force-delete escalation and the warning
// channel settings. Both are now recorded through auditAdminMutation, as their
// sibling handlers are -- and the settings record never carries the webhook
// secret.
package ownership

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/monitoring"
	"github.com/gin-gonic/gin"
)

var initMonitoringOnce sync.Once

// withAuditLogger installs the process audit logger over the test database
// for the test's duration, as main does over the platform database (after
// monitoring.InitMetrics, which builds the logger the audit logger writes to;
// once per binary, because it registers process-wide metrics).
func withAuditLogger(t *testing.T, raw *sql.DB) {
	t.Helper()
	initMonitoringOnce.Do(func() {
		if monitoring.GetLogger() == nil {
			monitoring.InitMetrics()
		}
	})
	prev := config.AuditLogger
	config.AuditLogger = monitoring.NewAuditLogger(gormFor(t, raw))
	t.Cleanup(func() { config.AuditLogger = prev })
}

// auditRow is one audit_events row, as text.
type auditRow struct {
	WorkspaceID, UserID, Action, Resource, ResourceID, Method, Path string
	StatusCode                                                      int
	OldValues, NewValues                                            sql.NullString
}

// waitAudit waits for the audit row a handler wrote (the logger writes it on a
// goroutine) and returns every row matching action+resource+resource_id.
func waitAudit(t *testing.T, raw *sql.DB, action, resource, resourceID string) []auditRow {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rows := auditRows(t, raw, action, resource, resourceID)
		if len(rows) > 0 || time.Now().After(deadline) {
			return rows
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func auditRows(t *testing.T, raw *sql.DB, action, resource, resourceID string) []auditRow {
	t.Helper()
	rs, err := raw.Query(`SELECT coalesce(workspace_id,''), coalesce(user_id,''), action, resource,
	                             coalesce(resource_id,''), coalesce(method,''), coalesce(path,''),
	                             coalesce(status_code,0), old_values::text, new_values::text
	                        FROM audit_events
	                       WHERE action = $1 AND resource = $2 AND resource_id = $3
	                       ORDER BY id`, action, resource, resourceID)
	if err != nil {
		t.Fatalf("read audit_events: %v", err)
	}
	defer rs.Close()
	var out []auditRow
	for rs.Next() {
		var r auditRow
		if err := rs.Scan(&r.WorkspaceID, &r.UserID, &r.Action, &r.Resource, &r.ResourceID,
			&r.Method, &r.Path, &r.StatusCode, &r.OldValues, &r.NewValues); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
		out = append(out, r)
	}
	return out
}

// countAudit is the number of audit rows of any kind, after a moment for an
// in-flight write to land -- for asserting that a refused request wrote none.
func countAudit(t *testing.T, raw *sql.DB) int {
	t.Helper()
	time.Sleep(300 * time.Millisecond)
	var n int
	if err := raw.QueryRow(`SELECT count(*) FROM audit_events`).Scan(&n); err != nil {
		t.Fatalf("count audit_events: %v", err)
	}
	return n
}

// governanceRouter mounts the two handlers as routes.go does, behind a
// stand-in for AuthMiddleware that sets the token's workspace and user.
func governanceRouter(t *testing.T, f provFixture) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctl := platform.NewGovernanceController(gormFor(t, f.raw))
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("workspace_id", f.ws.String())
		c.Set("user_id", claimOwner.String())
		c.Set("email", "u@a.com")
	})
	r.POST("/authsec/governance/agents/:id/force-evict", ctl.ForceEvictAgent)
	r.PUT("/authsec/governance/notification-settings", ctl.UpdateNotificationSettings)
	r.GET("/authsec/governance/notification-settings", ctl.GetNotificationSettings)
	return r
}

func send(t *testing.T, r *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestForceEvictIsAudited(t *testing.T) {
	f := newActFixture(t)
	withAuditLogger(t, f.raw)
	r := governanceRouter(t, f.provFixture)
	capable(t, f, true, true, true)
	path := "/authsec/governance/agents/" + f.agent.String() + "/force-evict"

	// Refused (the agent is not quarantined): nothing happened, nothing audited.
	before := countAudit(t, f.raw)
	if rec := send(t, r, http.MethodPost, path, map[string]string{"reason": "compromised"}); rec.Code != http.StatusConflict {
		t.Fatalf("an unquarantined agent must be refused 409, got %d: %s", rec.Code, rec.Body.String())
	}
	if after := countAudit(t, f.raw); after != before {
		t.Errorf("a refused force-delete must not be audited as if it happened (%d -> %d)", before, after)
	}

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "hold", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	recordPDBRefusal(t, f, `["research-agent-7d9fbc4d8f-x2k9"]`)
	rec := send(t, r, http.MethodPost, path, map[string]string{"reason": "compromised, budget overruled"})
	if rec.Code != http.StatusOK {
		t.Fatalf("force-evict: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		InstructionID string `json:"instruction_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)

	rows := waitAudit(t, f.raw, "force_evict", "discovered_agent", f.agent.String())
	if len(rows) != 1 {
		t.Fatalf("want exactly one force_evict audit row, got %d", len(rows))
	}
	a := rows[0]
	if a.WorkspaceID != f.ws.String() || a.UserID != claimOwner.String() || a.StatusCode != http.StatusOK ||
		a.Method != http.MethodPost || a.Path != path {
		t.Errorf("audit row does not attribute the act: %+v", a)
	}
	var nv map[string]any
	if err := json.Unmarshal([]byte(a.NewValues.String), &nv); err != nil {
		t.Fatalf("new_values: %v (%q)", err, a.NewValues.String)
	}
	if nv["reason"] != "compromised, budget overruled" || nv["instruction_id"] != out.InstructionID ||
		out.InstructionID == "" {
		t.Errorf("the audit record must carry the reason and what was queued, got %v", nv)
	}
}

func TestNotificationSettingsUpdateIsAuditedWithoutTheSecret(t *testing.T) {
	f := newProvFixture(t)
	withAuditLogger(t, f.raw)
	r := governanceRouter(t, f)
	const secret = "whsec-do-not-log-7f3a9c"

	rec := send(t, r, http.MethodPut, "/authsec/governance/notification-settings", map[string]any{
		"warning_lead":   "48h",
		"webhook_url":    "https://hooks.example.com/authsec",
		"webhook_secret": secret,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	// The response is the console's view, unchanged in shape.
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	for _, k := range []string{"workspace_id", "warning_lead_seconds", "webhook_url",
		"webhook_secret_set", "email_enabled"} {
		if _, ok := body[k]; !ok {
			t.Errorf("response lost %q: %s", k, rec.Body.String())
		}
	}
	if len(body) != 5 || strings.Contains(rec.Body.String(), secret) {
		t.Errorf("response shape changed or leaks the secret: %s", rec.Body.String())
	}

	rows := waitAudit(t, f.raw, "update", "governance_notification_settings", f.ws.String())
	if len(rows) != 1 {
		t.Fatalf("want exactly one settings audit row, got %d", len(rows))
	}
	a := rows[0]
	if a.WorkspaceID != f.ws.String() || a.UserID != claimOwner.String() || a.StatusCode != http.StatusOK {
		t.Errorf("audit row does not attribute the change: %+v", a)
	}
	if strings.Contains(a.OldValues.String+a.NewValues.String, secret) {
		t.Fatal("the webhook secret must never be written to the audit log")
	}
	var oldV, newV map[string]any
	if err := json.Unmarshal([]byte(a.OldValues.String), &oldV); err != nil {
		t.Fatalf("old_values: %v (%q)", err, a.OldValues.String)
	}
	if err := json.Unmarshal([]byte(a.NewValues.String), &newV); err != nil {
		t.Fatalf("new_values: %v (%q)", err, a.NewValues.String)
	}
	if oldV["webhook_url"] != "" || oldV["email_enabled"] != true || oldV["webhook_secret_set"] != false {
		t.Errorf("old values must be the defaults the workspace had, got %v", oldV)
	}
	if newV["webhook_url"] != "https://hooks.example.com/authsec" ||
		newV["webhook_secret_set"] != true || newV["warning_lead_seconds"] != float64(48*3600) {
		t.Errorf("new values must be the redacted settings now in force, got %v", newV)
	}
	// Exactly what the response reported as in force.
	if nb, _ := json.Marshal(newV); string(nb) != string(mustJSON(t, body)) {
		t.Errorf("audit new values %s differ from the response %s", nb, mustJSON(t, body))
	}

	// A refused update (http webhook) is not audited.
	before := countAudit(t, f.raw)
	if rec := send(t, r, http.MethodPut, "/authsec/governance/notification-settings",
		map[string]any{"webhook_url": "http://plain.example.com"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("an http webhook must be refused, got %d", rec.Code)
	}
	if after := countAudit(t, f.raw); after != before {
		t.Errorf("a refused update must not be audited (%d -> %d)", before, after)
	}
}
