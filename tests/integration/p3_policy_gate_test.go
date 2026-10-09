package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/iacpr"
	"github.com/authsec-ai/authsec/routes"
	"github.com/authsec-ai/authsec/services"
)

// T3.02 (SPEC-iga-phase3-policy.md §4.3, §7, §7.12): the IGA_POLICY gate.
//
// On requires IGA_GRAPH_PROJECTION=on (verified) and the Phase 3 schema
// verified by relation; every other combination is unavailable, and every
// /api/iga/v1/policy route then answers 503 policy_unavailable with the
// reason /capabilities reports. These tests run against the integration
// database with 047-056 applied.

// p3GraphOn is a verified graph gate over the integration database.
func p3GraphOn(t *testing.T, db *gorm.DB) func() *services.GraphProjectionGate {
	t.Helper()
	g := services.NewGraphProjectionGate(true, "")
	if err := g.Verify(db); err != nil {
		t.Fatalf("the integration database must be at 036+ for the graph gate: %v", err)
	}
	return func() *services.GraphProjectionGate { return g }
}

// The switch is read like IGA_GRAPH_PROJECTION's: a typo is misconfigured,
// never silently on or off.
func TestP3T302PolicyEnvParsing(t *testing.T) {
	graphOff := func() *services.GraphProjectionGate { return services.NewGraphProjectionGate(false, "") }
	for v, want := range map[string]string{
		"": services.PolicyOff, "off": services.PolicyOff, "FALSE": services.PolicyOff, "0": services.PolicyOff,
		"on": services.PolicyMisconfigured, "true": services.PolicyMisconfigured, " 1 ": services.PolicyMisconfigured,
		"maybe": services.PolicyMisconfigured,
	} {
		t.Setenv(services.PolicyEnv, v)
		g := services.PolicyGateFromEnv(graphOff)
		state, reason, _ := g.Status()
		if state != want || reason == "" || g.Available() {
			t.Errorf("%s=%q: state %q reason %q available %v, want %q with a reason, unavailable", services.PolicyEnv, v, state, reason, g.Available(), want)
		}
		if v == "maybe" && !strings.Contains(reason, "is not on or off") {
			t.Errorf("a bad value's reason = %q", reason)
		}
	}
}

// Fail closed, every way: the graph gate off or misconfigured, the schema not
// yet verified, a Phase 3 relation missing, a bad switch value. Only the
// complete combination is on, and a verified schema follows the graph gate
// LIVE (it verifies asynchronously at startup).
//
// Safeguards (mutation-checked): the graph dependency and the verified check
// in PolicyGate.Status; Verify recording a failure as unverified.
func TestP3T302PolicyGateFailsClosed(t *testing.T) {
	db := igaDB(t)
	graphOn := p3GraphOn(t, db)
	graphGate := services.NewGraphProjectionGate(false, "")
	graphNow := func() *services.GraphProjectionGate { return graphGate }

	// Graph off: unavailable, naming IGA_GRAPH_PROJECTION, even once verified.
	g := services.NewPolicyGate(true, "", graphNow)
	if err := g.Verify(db); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if state, reason, _ := g.Status(); state != services.PolicyMisconfigured || !strings.Contains(reason, services.GraphProjectionEnv) {
		t.Fatalf("graph off: %q %q, want misconfigured naming %s", state, reason, services.GraphProjectionEnv)
	}
	// Graph switched on but its schema unverified: still unavailable.
	graphGate = services.NewGraphProjectionGate(true, "")
	if state, reason, _ := g.Status(); state != services.PolicyMisconfigured || !strings.Contains(reason, "misconfigured") {
		t.Fatalf("graph unverified: %q %q, want misconfigured", state, reason)
	}
	// The graph verifies: the SAME policy gate is now on (read live).
	graphGate = graphOn()
	if state, reason, head := g.Status(); state != services.PolicyOn || reason != "" || head != services.PolicySchemaHead || !g.Available() {
		t.Fatalf("all verified: %q %q %q, want on with schema head %s", state, reason, head, services.PolicySchemaHead)
	}

	// Graph on, Phase 3 schema never verified: unavailable.
	fresh := services.NewPolicyGate(true, "", graphOn)
	if state, reason, _ := fresh.Status(); state != services.PolicyMisconfigured || !strings.Contains(reason, "not been verified") {
		t.Fatalf("unverified: %q %q, want misconfigured, not verified", state, reason)
	}

	// A Phase 3 relation missing: verification fails naming it, the gate
	// stays unavailable, and a later successful verification opens it. The
	// drop is inside a transaction that is rolled back.
	rollback := errors.New("rollback")
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`DROP INDEX uq_iga_gov_control_live`).Error; err != nil {
			return err
		}
		verr := fresh.Verify(tx)
		if verr == nil || !strings.Contains(verr.Error(), "uq_iga_gov_control_live") {
			t.Errorf("verify with a missing relation = %v, want it named", verr)
		}
		if state, reason, _ := fresh.Status(); state != services.PolicyMisconfigured || !strings.Contains(reason, "uq_iga_gov_control_live") {
			t.Errorf("after a failed verification: %q %q, want misconfigured naming the relation", state, reason)
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("the probe transaction: %v", err)
	}
	if err := fresh.Verify(db); err != nil || !fresh.Available() {
		t.Fatalf("re-verify against the full schema: %v, available %v", err, fresh.Available())
	}

	// A bad switch value never verifies, whatever the graph and schema say.
	bad := services.NewPolicyGate(true, `IGA_POLICY="maybe" is not on or off`, graphOn)
	if err := bad.Verify(db); err == nil || bad.Available() {
		t.Fatalf("a bad switch value verified (%v) or is available (%v)", err, bad.Available())
	}
	// Off is off, verified or not.
	off := services.NewPolicyGate(false, "", graphOn)
	_ = off.Verify(db)
	if state, reason, _ := off.Status(); state != services.PolicyOff || reason != services.PolicyEnv+" is off" {
		t.Fatalf("off: %q %q", state, reason)
	}
	var nilGate *services.PolicyGate
	if nilGate.Available() {
		t.Fatal("a nil gate is available")
	}
}

// p3PolicyEngine mounts the PRODUCTION /api/iga/v1 surface
// (routes.SetupIGARoutes, with the production AuthMiddleware and permission
// middleware) over the integration database, with the given policy gate.
func p3PolicyEngine(t *testing.T, db *gorm.DB, gate *services.PolicyGate) (call func(path, bearer string) (int, map[string]any), token func(scope string) string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	const secret = "p3-t302-jwt-secret"
	t.Setenv("JWT_SDK_SECRET", secret)
	t.Setenv("JWT_DEF_SECRET", secret+"-default")
	t.Setenv("AUTH_EXPECT_ISS", "authsec-ai/auth-manager")
	t.Setenv("REQUIRE_SERVER_AUTH", "true")
	ws := newWorkspace(t, db, "p3-t302-policy-gate")
	eng := gin.New()
	ctl := platform.NewIGAGraphReadControllerWith(db, services.NewGraphProjectionGate(false, ""), readTestCursorKey).WithPolicyGate(gate)
	routes.SetupIGARoutes(eng, platform.NewIGAController(db), ctl)
	token = func(scope string) string {
		claims := jwt.MapClaims{"iss": "authsec-ai/auth-manager", "exp": time.Now().Add(time.Hour).Unix(),
			"workspace_id": ws.String(), "user_id": uuid.NewString()}
		if scope != "" {
			claims["scope"] = scope
		}
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	call = func(path, bearer string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodGet, "/api/iga/v1"+path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		eng.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	return call, token
}

// The routes, through the production chain: off or unverified, every policy
// route is 503 policy_unavailable with /capabilities' reason, before the
// permission check; on, the route is reached and its permission enforced;
// authentication comes first either way, in the graph group's envelope.
//
// Safeguards (mutation-checked): the gate middleware's fail-closed check;
// the subgroup being behind the gate.
func TestP3T302PolicyRoutesAreGated(t *testing.T) {
	db := igaDB(t)
	graphOn := p3GraphOn(t, db)
	unverified := services.NewPolicyGate(true, "", graphOn)
	verified := services.NewPolicyGate(true, "", graphOn)
	if err := verified.Verify(db); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		gate *services.PolicyGate
	}{
		{"off", services.NewPolicyGate(false, "", graphOn)},
		{"switch on, graph off", services.NewPolicyGate(true, "", func() *services.GraphProjectionGate { return nil })},
		{"schema unverified", unverified},
		{"bad value", services.NewPolicyGate(true, `IGA_POLICY="yes please" is not on or off`, graphOn)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			call, token := p3PolicyEngine(t, db, tc.gate)
			_, want, _ := tc.gate.Status()
			for _, scope := range []string{"governance:read", "", "iga:read"} {
				code, body := call("/policy/status", token(scope))
				if code != http.StatusServiceUnavailable || errCode(body) != "policy_unavailable" ||
					digs(body, "error", "detail", "reason") != want || digs(body, "error", "message") == "" {
					t.Fatalf("scope %q: %d %v, want 503 policy_unavailable with reason %q", scope, code, body, want)
				}
			}
			// The same reason /capabilities reports.
			code, caps := call("/capabilities", token(""))
			if code != http.StatusOK || digs(caps, "data", "policy", "reason") != want {
				t.Fatalf("/capabilities = %d %v, want policy.reason %q", code, caps, want)
			}
			// Authentication is still first: no token is 401 in the envelope.
			if code, body := call("/policy/status", ""); code != http.StatusUnauthorized || errCode(body) != "unauthenticated" {
				t.Fatalf("no token: %d %v, want 401 unauthenticated", code, body)
			}
		})
	}

	t.Run("on", func(t *testing.T) {
		call, token := p3PolicyEngine(t, db, verified)
		code, body := call("/policy/status", token("governance:read"))
		if code != http.StatusOK || digs(body, "data", "state") != services.PolicyOn ||
			digs(body, "data", "schema_head") != services.PolicySchemaHead {
			t.Fatalf("on: %d %v, want 200 state on", code, body)
		}
		// The route's permission is enforced once the gate is open.
		if code, body := call("/policy/status", token("iga:read")); code != http.StatusForbidden || errCode(body) != "forbidden" {
			t.Fatalf("without governance:read: %d %v, want 403 forbidden", code, body)
		}
	})
}

// The /capabilities policy block (§4.3): the gate's state and reason, the six
// feature flags with a reason for every false one, provider support; and the
// existing fields unchanged.
//
// Safeguard (mutation-checked): no feature reported available before its
// routes exist; every false flag carries a reason.
func TestP3T302CapabilitiesPolicyBlock(t *testing.T) {
	db := igaDB(t)
	graphOn := p3GraphOn(t, db)
	verified := services.NewPolicyGate(true, "", graphOn)
	if err := verified.Verify(db); err != nil {
		t.Fatal(err)
	}
	features := []string{"findings", "proposals", "export", "iac", "enforcement", "slack"}
	for _, tc := range []struct {
		name   string
		gate   *services.PolicyGate
		state  string
		reason any
	}{
		{"off", services.NewPolicyGate(false, "", graphOn), services.PolicyOff, services.PolicyEnv + " is off"},
		{"on", verified, services.PolicyOn, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newP2Lab(t, "p3-t302-caps-"+tc.name, true)
			a := l.api()
			a.ctl.WithPolicyGate(tc.gate)
			code, body := a.get("/capabilities")
			mustStatus(t, "/capabilities", code, body, http.StatusOK)
			contractCheck(t, "/capabilities", body, contractCapabilities)
			if digs(body, "data", "graph_projection") != services.GraphProjectionOn || dig(body, "data", "features", "workloads") != true {
				t.Fatalf("existing fields changed: %v", body["data"])
			}
			p, _ := dig(body, "data", "policy").(map[string]any)
			if p["state"] != tc.state || p["reason"] != tc.reason {
				t.Fatalf("policy state %v reason %v, want %s %v", p["state"], p["reason"], tc.state, tc.reason)
			}
			if tc.state == services.PolicyOn && p["schema_head"] != services.PolicySchemaHead {
				t.Fatalf("policy schema_head %v, want %s", p["schema_head"], services.PolicySchemaHead)
			}
			reasons, _ := p["reasons"].(map[string]any)
			for _, f := range features {
				// T3.06b mounted the findings routes, T3.11/T3.13 the
				// proposal routes, T3.17 export and IaC delivery and T3.10/T3.15/T3.16
				// direct enforcement: served,
				// so true exactly when the gate is on, with no reason.
				if (f == "findings" || f == "proposals" || f == "export") && tc.state == services.PolicyOn {
					if p[f] != true || reasons[f] != nil {
						t.Errorf("on: policy.%s = %v (reason %v), want true with no reason: its routes are in this build", f, p[f], reasons[f])
					}
					continue
				}
				if p[f] != false {
					t.Errorf("policy.%s = %v: this feature's routes are not in this build", f, p[f])
				}
				r, _ := reasons[f].(string)
				if r == "" {
					t.Errorf("policy.%s is false with no reason", f)
				}
				if tc.state == services.PolicyOff && r != services.PolicyEnv+" is off" {
					t.Errorf("off: reasons.%s = %q, want the gate's reason", f, r)
				}
				if tc.state == services.PolicyOn && r == services.PolicyEnv+" is off" {
					t.Errorf("on: reasons.%s still the gate's reason", f)
				}
			}
			// Review fix R1a P2: iac and enforcement are true only while this
			// process can deliver them (the GitHub PR adapter; the deployment
			// environment), each false with its own reason otherwise.
			if tc.state == services.PolicyOn {
				for f, want := range map[string]string{"iac": "GitHub App adapter", "enforcement": "deployment environment"} {
					if r, _ := reasons[f].(string); !strings.Contains(r, want) {
						t.Errorf("on, not installed: reasons.%s = %q, want the %s reason", f, r, want)
					}
				}
				services.SetGovIaCGitHub(iacpr.NewFake())
				services.SetGovDeployEnv(services.GovDeployEnv{AWS: p3CapsAWS{},
					Binding: func(context.Context, uuid.UUID, uuid.UUID) error { return nil }})
				code, body := a.get("/capabilities")
				services.SetGovIaCGitHub(nil)
				services.SetGovDeployEnv(services.GovDeployEnv{})
				mustStatus(t, "/capabilities", code, body, http.StatusOK)
				for _, f := range []string{"iac", "enforcement"} {
					if dig(body, "data", "policy", f) != true || dig(body, "data", "policy", "reasons", f) != nil {
						t.Errorf("installed: policy.%s = %v (reason %v), want true", f, dig(body, "data", "policy", f),
							dig(body, "data", "policy", "reasons", f))
					}
				}
			}
			// T3.14: Slack's routes are in this build; the flag follows the
			// app's configuration on this server (not installed here).
			if r, _ := reasons["slack"].(string); tc.state == services.PolicyOn && !strings.Contains(r, "not configured on this server") {
				t.Errorf("on: reasons.slack = %q, want the configuration reason", r)
			}
			if tc.state == services.PolicyOn {
				restore := services.InstallSlackApp(services.NewSlackIntegrationService(db, newMemVault(), nil, services.SlackConfig{SigningSecret: "x"}))
				code, body := a.get("/capabilities")
				restore()
				mustStatus(t, "/capabilities", code, body, http.StatusOK)
				if dig(body, "data", "policy", "slack") != true || dig(body, "data", "policy", "reasons", "slack") != nil {
					t.Errorf("slack installed: policy.slack = %v (reason %v), want true", dig(body, "data", "policy", "slack"),
						dig(body, "data", "policy", "reasons", "slack"))
				}
			}
			if dig(p, "providers", "aws") != "supported" || dig(p, "providers", "k8s") != "not_supported" ||
				digs(p, "provider_reasons", "k8s") == "" {
				t.Fatalf("providers = %v / %v", p["providers"], p["provider_reasons"])
			}
		})
	}
}

// Review fix R1a P2 "gate leaks": VerifyPolicySchema checks the triggers and
// key CHECK / UNIQUE constraints of 047-056 by name, not only relations. A
// dropped trigger, a DISABLED trigger and a dropped CHECK each leave the gate
// unavailable naming the object; every probe runs in a transaction that is
// rolled back, after which the same gate verifies.
func TestP3PolicyGateVerifiesTriggersAndConstraints(t *testing.T) {
	db := igaDB(t)
	graphOn := p3GraphOn(t, db)
	rollback := errors.New("rollback")
	for _, tc := range []struct {
		name, ddl, want string
	}{
		{"dropped trigger", `DROP TRIGGER iga_gov_event_no_update ON iga_gov_event`, "trigger iga_gov_event.iga_gov_event_no_update"},
		{"disabled trigger", `ALTER TABLE iga_gov_attempt DISABLE TRIGGER iga_gov_attempt_transition`, "trigger iga_gov_attempt.iga_gov_attempt_transition"},
		{"dropped check", `ALTER TABLE iga_gov_finding DROP CONSTRAINT iga_gov_finding_exception_chk`, "constraint iga_gov_finding.iga_gov_finding_exception_chk"},
		{"dropped unique", `ALTER TABLE iga_gov_finding DROP CONSTRAINT iga_gov_finding_workspace_id_fingerprint_key`, "constraint iga_gov_finding.iga_gov_finding_workspace_id_fingerprint_key"},
		{"056 trigger", `DROP TRIGGER cloud_rpo_immutable ON cloud_resource_policy_observation`, "trigger cloud_resource_policy_observation.cloud_rpo_immutable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := services.NewPolicyGate(true, "", graphOn)
			err := db.Transaction(func(tx *gorm.DB) error {
				if err := tx.Exec(tc.ddl).Error; err != nil {
					return err
				}
				verr := gate.Verify(tx)
				if verr == nil || !strings.Contains(verr.Error(), tc.want) {
					t.Errorf("verify = %v, want it to name %s", verr, tc.want)
				}
				if state, reason, _ := gate.Status(); state != services.PolicyMisconfigured || !strings.Contains(reason, tc.want) || gate.Available() {
					t.Errorf("gate %q %q, want unavailable naming %s", state, reason, tc.want)
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatalf("probe transaction: %v", err)
			}
			if err := gate.Verify(db); err != nil || !gate.Available() {
				t.Fatalf("after the rollback the gate must verify: %v", err)
			}
		})
	}

	// The lists are the schema: every trigger and every named CHECK / UNIQUE
	// constraint on a table 047-056 create is listed, and every listed name
	// exists, so a new invariant cannot be added without the gate checking it.
	var tables []string
	for _, r := range services.PolicySchemaRelations() {
		var kind string
		db.Raw(`SELECT c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		         WHERE n.nspname = 'public' AND c.relname = ?`, r).Scan(&kind)
		if kind == "r" {
			tables = append(tables, r)
		}
	}
	var triggers, constraints []string
	db.Raw(`SELECT c.relname || '.' || t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
	         WHERE NOT t.tgisinternal AND c.relname IN ? ORDER BY 1`, tables).Scan(&triggers)
	db.Raw(`SELECT c.relname || '.' || k.conname FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
	         WHERE c.relname IN ? AND (k.contype = 'u' OR (k.contype = 'c' AND k.conname LIKE '%\_chk'))
	         ORDER BY 1`, tables).Scan(&constraints)
	listed := map[string]bool{}
	for _, n := range append(services.PolicySchemaTriggers(), services.PolicySchemaConstraints()...) {
		listed[n] = true
	}
	for _, n := range append(triggers, constraints...) {
		if !listed[n] {
			t.Errorf("%s is on a Phase 3 table but VerifyPolicySchema does not check it", n)
		}
	}
	if len(triggers) != len(services.PolicySchemaTriggers()) {
		t.Errorf("%d triggers on Phase 3 tables, %d listed", len(triggers), len(services.PolicySchemaTriggers()))
	}
}

// p3CapsAWS stands in for the deployment environment's AWS access in the
// capabilities test: the flag reads only whether one is installed.
type p3CapsAWS struct{ services.IGAGovAWS }
