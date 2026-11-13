package integration

// AuthSec Agent Kit control plane (migration 162): machine events and policy
// pull on the discovery ingress, console logs and the policy editor, and the
// machine branch of quarantine. Every route is checked across two
// workspaces: neither reads, lists or writes the other's rows.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

type agentKitLab struct {
	*ingestLab
	// mA and mB are machines (vm_sensor sources) of workspaces A and B.
	mA, mB     uuid.UUID
	tokA, tokB string
	adminA     string
	adminB     string
	readA      string
}

func newAgentKitLab(t *testing.T) *agentKitLab {
	t.Helper()
	l := &agentKitLab{ingestLab: newIngestLab(t)}
	ctl := platform.NewDiscoveryController(l.db)
	platform.MountAgentKitMachineRoutes(l.eng.Group("/authsec/discovery"), ctl)
	console := l.eng.Group("/authsec/discovery")
	console.Use(middlewares.AuthMiddleware())
	platform.MountAgentKitConsoleRoutes(console, ctl, middlewares.Require)

	l.mA = l.registerMachine(l.wsA, "host:aaaa")
	l.mB = l.registerMachine(l.wsB, "host:bbbb")
	l.tokA, _ = l.mint(l.wsA, nil)
	l.tokB, _ = l.mint(l.wsB, nil)
	l.adminA = l.jwtFor(l.wsA, "discovery:admin discovery:read")
	l.adminB = l.jwtFor(l.wsB, "discovery:admin discovery:read")
	l.readA = l.jwtFor(l.wsA, "discovery:read")
	return l
}

func (l *agentKitLab) registerMachine(ws uuid.UUID, instance string) uuid.UUID {
	l.t.Helper()
	code, body := l.post("/agent-registration", "", map[string]any{
		"workspace_id": ws.String(), "kind": models.DiscoverySourceVMSensor,
		"instance_id": instance, "cluster_name": "laptop-" + instance,
	})
	if code != http.StatusCreated {
		l.t.Fatalf("register machine %s: %d %v", instance, code, body)
	}
	id, err := uuid.Parse(body["discovery_source_id"].(string))
	if err != nil {
		l.t.Fatal(err)
	}
	return id
}

func akRecord(typ, agent, rule string) map[string]any {
	return map[string]any{
		"ts": time.Now().UTC().Format(time.RFC3339Nano), "type": typ,
		"agent": map[string]any{"id": agent, "name": agent, "pid": 4242},
		"rule":  rule, "action": "deny", "kind": "network", "enforced": true, "severity": "HIGH",
		"tags": []string{"LLM06", "agentkit"},
	}
}

func akEvents(ws, src uuid.UUID, recs ...map[string]any) map[string]any {
	return map[string]any{"workspace_id": ws.String(), "discovery_source_id": src.String(), "events": recs}
}

const akPolicy = `apiVersion: authsec.ai/v1
kind: AgentPolicy
agent:
  id: claude-code
# keep this comment
mode: enforce
network:
  default: deny
  allow:
    - host: api.anthropic.com
      port: 443
`

func TestAgentKitMachineEventsAuth(t *testing.T) {
	l := newAgentKitLab(t)
	// IGA_DISCOVERY_INGEST_AUTH is off in the lab: these routes still demand
	// a credential.
	body := akEvents(l.wsA, l.mA, akRecord("decision", "claude-code", "network.deny"))
	for _, c := range []struct {
		name, bearer string
		body         map[string]any
		want         int
	}{
		{"no credential", "", body, http.StatusUnauthorized},
		{"made-up token", "aid_" + strings.Repeat("Z", 43), body, http.StatusUnauthorized},
		{"made-up connector credential", "authsec_act_nope", body, http.StatusUnauthorized},
		{"B's token naming A", l.tokB, body, http.StatusForbidden},
		{"A's token naming B's machine in A", l.tokA, akEvents(l.wsA, l.mB, akRecord("decision", "x", "")), http.StatusNotFound},
		{"A's token naming A's cluster source", l.tokA, akEvents(l.wsA, l.srcA1, akRecord("decision", "x", "")), http.StatusNotFound},
		{"A's token naming B", l.tokA, akEvents(l.wsB, l.mB, akRecord("decision", "x", "")), http.StatusForbidden},
		{"A's token, A's machine", l.tokA, body, http.StatusOK},
	} {
		if code, out := l.post("/agentkit/machine/events", c.bearer, c.body); code != c.want {
			t.Errorf("%s: %d %v, want %d", c.name, code, out, c.want)
		}
	}

	// A batch with bad records stores the good ones.
	code, out := l.post("/agentkit/machine/events", l.tokA, akEvents(l.wsA, l.mA,
		akRecord("detection", "nmap", "offensive_tool"),
		map[string]any{"type": "process", "ts": time.Now().Format(time.RFC3339)},
		map[string]any{"type": "decision"},
	))
	if code != http.StatusOK || out["accepted"] != float64(1) || out["rejected"] != float64(2) {
		t.Fatalf("mixed batch: %d %v", code, out)
	}
	// B writes to its own machine.
	if code, out := l.post("/agentkit/machine/events", l.tokB, akEvents(l.wsB, l.mB, akRecord("decision", "codex", "b-only"))); code != http.StatusOK {
		t.Fatalf("B ingest: %d %v", code, out)
	}

	// Console: A sees its two records, never B's.
	code, list, raw := l.do(http.MethodGet, "/authsec/discovery/agentkit/events", l.readA, nil)
	if code != http.StatusOK {
		t.Fatalf("list A: %d %s", code, raw)
	}
	evs := list["events"].([]any)
	if len(evs) != 2 || strings.Contains(raw, "b-only") || strings.Contains(raw, l.mB.String()) {
		t.Fatalf("A's list: %s", raw)
	}
	first := evs[0].(map[string]any)
	if first["severity"] != "high" && evs[1].(map[string]any)["severity"] != "high" {
		t.Errorf("severity not normalised: %s", raw)
	}
	// Filters: by B's machine from A is empty; by tag and type work.
	if _, l2, raw := l.do(http.MethodGet, "/authsec/discovery/agentkit/events?discovery_source_id="+l.mB.String(), l.readA, nil); len(l2["events"].([]any)) != 0 {
		t.Errorf("A filtering by B's machine: %s", raw)
	}
	if _, l2, raw := l.do(http.MethodGet, "/authsec/discovery/agentkit/events?tag=LLM06&type=detection", l.readA, nil); len(l2["events"].([]any)) != 1 {
		t.Errorf("tag+type filter: %s", raw)
	}
	// Paging.
	_, p1, raw := l.do(http.MethodGet, "/authsec/discovery/agentkit/events?limit=1", l.readA, nil)
	cur, _ := p1["next_cursor"].(string)
	if len(p1["events"].([]any)) != 1 || cur == "" {
		t.Fatalf("page 1: %s", raw)
	}
	_, p2, raw := l.do(http.MethodGet, "/authsec/discovery/agentkit/events?limit=1&before="+cur, l.readA, nil)
	if len(p2["events"].([]any)) != 1 || p2["next_cursor"] != nil {
		t.Fatalf("page 2: %s", raw)
	}
	// A cursor from B's workspace matches nothing in A.
	var bIDs []string
	if err := l.db.Table("agentkit_events").Where("workspace_id = ?", l.wsB).Limit(1).Pluck("id", &bIDs).Error; err != nil || len(bIDs) != 1 {
		t.Fatalf("B's event id: %v %v", bIDs, err)
	}
	if _, p3, raw := l.do(http.MethodGet, "/authsec/discovery/agentkit/events?before="+bIDs[0], l.readA, nil); len(p3["events"].([]any)) != 0 {
		t.Errorf("B's cursor in A: %s", raw)
	}
	// No session: 401.
	if code, _, _ := l.do(http.MethodGet, "/authsec/discovery/agentkit/events", "", nil); code != http.StatusUnauthorized {
		t.Errorf("events without a session: %d", code)
	}
}

func TestAgentKitActuationCredential(t *testing.T) {
	l := newAgentKitLab(t)
	act, err := services.NewActuationManager(l.db).EnableActuation(l.wsA, l.mA)
	if err != nil {
		t.Fatal(err)
	}
	// The credential decides workspace and source; the body may omit them.
	if code, out := l.post("/agentkit/machine/events", act, map[string]any{"events": []any{akRecord("sensor", "", "")}}); code != http.StatusOK {
		t.Fatalf("actuation credential: %d %v", code, out)
	}
	// Naming another workspace or machine is not found.
	if code, _ := l.post("/agentkit/machine/events", act, akEvents(l.wsB, l.mB)); code != http.StatusNotFound {
		t.Errorf("credential naming B: %d", code)
	}
	// Once the machine holds a credential, an ingest token no longer speaks for it.
	if code, _ := l.post("/agentkit/machine/events", l.tokA, akEvents(l.wsA, l.mA, akRecord("sensor", "", ""))); code != http.StatusUnauthorized {
		t.Errorf("ingest token for a credentialed machine: %d", code)
	}
	if code, _, _ := l.do(http.MethodGet, "/authsec/discovery/agentkit/machine/policies", act, nil); code != http.StatusOK {
		t.Errorf("policies with the credential: %d", code)
	}
}

func TestAgentKitPolicies(t *testing.T) {
	l := newAgentKitLab(t)
	const base = "/authsec/discovery/agentkit/policies"

	// Permissions.
	if code, _, _ := l.do(http.MethodPut, base+"/claude-code", l.readA, map[string]any{"document": akPolicy}); code != http.StatusForbidden {
		t.Errorf("PUT with discovery:read: %d", code)
	}
	// Validation.
	for name, doc := range map[string]string{
		"other agent": strings.Replace(akPolicy, "id: claude-code", "id: codex", 1),
		"bad mode":    strings.Replace(akPolicy, "mode: enforce", "mode: yes", 1),
		"not yaml":    "{{{",
		"wrong kind":  strings.Replace(akPolicy, "AgentPolicy", "Policy", 1),
	} {
		if code, _, raw := l.do(http.MethodPut, base+"/claude-code", l.adminA, map[string]any{"document": doc}); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, code, raw)
		}
	}
	if code, _, _ := l.do(http.MethodPut, base+"/Bad%20Agent", l.adminA, map[string]any{"document": akPolicy}); code != http.StatusBadRequest {
		t.Errorf("bad agent id: %d", code)
	}

	// Create, then an identical save is not a new version, then a stale base is 409.
	code, out, raw := l.do(http.MethodPut, base+"/claude-code", l.adminA, map[string]any{"document": akPolicy, "comment": "first", "base_version": 0})
	if code != http.StatusCreated || out["policy"].(map[string]any)["version"] != float64(1) {
		t.Fatalf("create: %d %s", code, raw)
	}
	if code, out, _ := l.do(http.MethodPut, base+"/claude-code", l.adminA, map[string]any{"document": akPolicy}); code != http.StatusOK || out["created"] != false {
		t.Errorf("same document again: %d %v", code, out)
	}
	v2 := strings.Replace(akPolicy, "default: deny", "default: allow", 1)
	if code, _, _ := l.do(http.MethodPut, base+"/claude-code", l.adminA, map[string]any{"document": v2, "base_version": 0}); code != http.StatusConflict {
		t.Errorf("stale base: %d", code)
	}
	if code, _, raw := l.do(http.MethodPut, base+"/claude-code", l.adminA, map[string]any{"document": v2, "base_version": 1}); code != http.StatusCreated {
		t.Fatalf("v2: %d %s", code, raw)
	}

	// B: its own policy at version 1, independent of A's numbering.
	bDoc := strings.Replace(akPolicy, "api.anthropic.com", "b-only.example.com", 1)
	if code, out, raw := l.do(http.MethodPut, base+"/claude-code", l.adminB, map[string]any{"document": bDoc}); code != http.StatusCreated || out["policy"].(map[string]any)["version"] != float64(1) {
		t.Fatalf("B create: %d %s", code, raw)
	}

	// Console reads are per workspace.
	_, list, raw := l.do(http.MethodGet, base, l.readA, nil)
	if pols := list["policies"].([]any); len(pols) != 1 || pols[0].(map[string]any)["version"] != float64(2) || strings.Contains(raw, "b-only") {
		t.Errorf("A's list: %s", raw)
	}
	if _, vs, raw := l.do(http.MethodGet, base+"/claude-code/versions", l.readA, nil); len(vs["versions"].([]any)) != 2 || strings.Contains(raw, "b-only") {
		t.Errorf("A's versions: %s", raw)
	}
	if code, _, _ := l.do(http.MethodGet, base+"/codex/versions", l.readA, nil); code != http.StatusNotFound {
		t.Errorf("versions of an agent without a policy: %d", code)
	}

	// Machines pull their own workspace's policies, with an etag.
	q := "?workspace_id=" + l.wsA.String() + "&discovery_source_id=" + l.mA.String()
	code, mp, raw := l.do(http.MethodGet, "/authsec/discovery/agentkit/machine/policies"+q, l.tokA, nil)
	if code != http.StatusOK || strings.Contains(raw, "b-only") || !strings.Contains(raw, "default: allow") {
		t.Fatalf("machine A pull: %d %s", code, raw)
	}
	etag := mp["etag"].(string)
	req := http.Header{"If-None-Match": {etag}}
	if code := l.getWithHeaders("/authsec/discovery/agentkit/machine/policies"+q, l.tokA, req); code != http.StatusNotModified {
		t.Errorf("unchanged pull: %d, want 304", code)
	}
	if code, _, _ := l.do(http.MethodGet, "/authsec/discovery/agentkit/machine/policies"+q, "", nil); code != http.StatusUnauthorized {
		t.Errorf("pull without a credential: %d", code)
	}
	if code, _, _ := l.do(http.MethodGet, "/authsec/discovery/agentkit/machine/policies"+q, l.tokB, nil); code != http.StatusForbidden {
		t.Errorf("B's token pulling A's: %d", code)
	}
	qb := "?workspace_id=" + l.wsB.String() + "&discovery_source_id=" + l.mB.String()
	if _, _, raw := l.do(http.MethodGet, "/authsec/discovery/agentkit/machine/policies"+qb, l.tokB, nil); !strings.Contains(raw, "b-only") || strings.Contains(raw, "api.anthropic.com") {
		t.Errorf("machine B pull: %s", raw)
	}
}

func (l *agentKitLab) getWithHeaders(path, bearer string, h http.Header) int {
	l.t.Helper()
	u, _ := url.Parse(path)
	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	for k, v := range h {
		req.Header[k] = v
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	l.eng.ServeHTTP(w, req)
	return w.Code
}

func TestAgentKitBlock(t *testing.T) {
	l := newAgentKitLab(t)
	const base = "/authsec/discovery/agentkit/policies"
	def := strings.Replace(strings.Replace(akPolicy, "id: claude-code", `id: "*"`, 1), "mode: enforce", "mode: monitor", 1)
	if code, _, raw := l.do(http.MethodPut, base+"/*", l.adminA, map[string]any{"document": def}); code != http.StatusCreated {
		t.Fatalf("default policy: %d %s", code, raw)
	}
	// codex has no policy: the block starts from a copy of "*".
	code, out, raw := l.do(http.MethodPost, base+"/codex/block", l.adminA, map[string]any{"type": "host", "value": "evil.example.com", "port": 443})
	if code != http.StatusCreated || out["from"] != "default" || out["enforced"] != false {
		t.Fatalf("block from default: %d %s", code, raw)
	}
	doc := out["policy"].(map[string]any)["document"].(string)
	for _, want := range []string{"id: codex", "evil.example.com", "api.anthropic.com", "# keep this comment"} {
		if !strings.Contains(doc, want) {
			t.Errorf("blocked document lacks %q:\n%s", want, doc)
		}
	}
	if err := services.CheckAgentKitPolicy("codex", doc); err != nil {
		t.Errorf("blocked document does not check: %v", err)
	}
	// The same block again changes nothing.
	if code, out, _ := l.do(http.MethodPost, base+"/codex/block", l.adminA, map[string]any{"type": "host", "value": "evil.example.com", "port": 443}); code != http.StatusOK || out["created"] != false {
		t.Errorf("repeat block: %d %v", code, out)
	}
	// A path block on an agent with no policy and (in B) no default: a new
	// enforce policy.
	code, out, raw = l.do(http.MethodPost, base+"/aider/block", l.adminB, map[string]any{"type": "path", "value": "{home}/.ssh"})
	if code != http.StatusCreated || out["from"] != "new" || out["enforced"] != true {
		t.Fatalf("block, new policy: %d %s", code, raw)
	}
	// B's block did not reach A, nor A's default B.
	if _, list, raw := l.do(http.MethodGet, base, l.readA, nil); len(list["policies"].([]any)) != 2 || strings.Contains(raw, "aider") {
		t.Errorf("A after B's block: %s", raw)
	}
	// Bad blocks.
	for _, b := range []map[string]any{
		{"type": "host", "value": "a b"}, {"type": "cidr", "value": "nope"},
		{"type": "path", "value": "relative"}, {"type": "disk", "value": "/x"},
		{"type": "path", "value": "/x", "port": 22},
	} {
		if code, _, raw := l.do(http.MethodPost, base+"/codex/block", l.adminA, b); code != http.StatusBadRequest {
			t.Errorf("block %v: %d %s", b, code, raw)
		}
	}
	if code, _, _ := l.do(http.MethodPost, base+"/codex/block", l.readA, map[string]any{"type": "host", "value": "x.example.com"}); code != http.StatusForbidden {
		t.Errorf("block with discovery:read: %d", code)
	}
}

func TestAgentKitMachineQuarantine(t *testing.T) {
	l := newAgentKitLab(t)
	// A sighting of an agent on machine A, as the daemon sends it.
	code, out := l.post("/sightings", l.tokA, map[string]any{
		"workspace_id": l.wsA.String(), "source": models.DiscoverySourceVMSensor, "discovery_source_id": l.mA.String(),
		"fingerprint": "aaaa:claude-code", "display_name": "Claude Code on laptop",
		"metadata": map[string]any{"machine": map[string]any{"agent_id": "claude-code", "host": "laptop"}},
	})
	if !is2xx(code) {
		t.Fatalf("sighting: %d %v", code, out)
	}
	var agent models.DiscoveredAgent
	if err := l.db.Where("workspace_id = ? AND fingerprint = ?", l.wsA, "aaaa:claude-code").First(&agent).Error; err != nil {
		t.Fatal(err)
	}
	// Without actuation on the machine nothing is queued (the decision
	// stands; the console shows it as not enforced).
	if queued, _ := services.EnforceQuarantine(l.db, l.wsA, &agent, false, "test"); queued {
		t.Fatal("queued for a machine without actuation")
	}
	if _, err := services.NewActuationManager(l.db).EnableActuation(l.wsA, l.mA); err != nil {
		t.Fatal(err)
	}
	queued, reason := services.EnforceQuarantine(l.db, l.wsA, &agent, false, "test")
	if !queued {
		t.Fatalf("quarantine not queued: %s", reason)
	}
	var inst models.ProvisioningInstruction
	if err := l.db.Where("workspace_id = ? AND discovery_source_id = ?", l.wsA, l.mA).First(&inst).Error; err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	_ = json.Unmarshal(inst.Payload, &payload)
	if inst.Kind != models.InstructionQuarantine || payload["target"] != "machine" || payload["agent_id"] != "claude-code" {
		t.Errorf("instruction: kind %s payload %v", inst.Kind, payload)
	}
	// No eviction for a machine.
	var n int64
	l.db.Model(&models.ProvisioningInstruction{}).Where("workspace_id = ? AND discovery_source_id = ?", l.wsA, l.mA).Count(&n)
	if n != 1 {
		t.Errorf("%d instructions, want 1", n)
	}
	// Release supersedes it.
	if queued, reason := services.EnforceQuarantine(l.db, l.wsA, &agent, true, "test"); !queued {
		t.Fatalf("release not queued: %s", reason)
	}
	// Machine B's queue is untouched.
	l.db.Model(&models.ProvisioningInstruction{}).Where("discovery_source_id = ?", l.mB).Count(&n)
	if n != 0 {
		t.Errorf("B's machine has %d instructions", n)
	}
}
