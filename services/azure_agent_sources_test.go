package services

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/models"
)

func TestLogicAgentFactsFindsNestedAgentLoops(t *testing.T) {
	def := json.RawMessage(`{
	  "triggers": {"manual": {"type": "Request"}},
	  "actions": {
	    "Scope": {"type": "Scope", "actions": {
	      "Default_Agent": {
	        "type": "Agent",
	        "inputs": {"parameters": {"deploymentId": "gpt-4o", "agentModelType": "AzureOpenAI",
	          "messages": [{"role": "System", "content": "SECRET PROMPT"}]}},
	        "tools": {
	          "Send_email": {"description": "x", "actions": {"Send": {"type": "ApiConnection"}}},
	          "Lookup": {"actions": {"Get": {"type": "Http", "inputs": {"headers": {"api-key": "SECRET"}}}}}
	        }
	      }
	    }},
	    "Condition": {"type": "If", "actions": {}, "else": {"actions": {"Second": {"type": "Agent"}}}}
	  }
	}`)
	params := json.RawMessage(`{"$connections": {"value": {"office365": {
	  "connectionId": "/subscriptions/S/resourceGroups/R/providers/Microsoft.Web/connections/office365",
	  "id": "/subscriptions/S/providers/Microsoft.Web/locations/eastus/managedApis/office365"}}}}`)

	facts := logicAgentFacts(def, params)
	if facts == nil {
		t.Fatal("no agent loop found")
	}
	raw, _ := json.Marshal(facts)
	if strings.Contains(string(raw), "SECRET") {
		t.Fatalf("a prompt or header was kept: %s", raw)
	}
	agents := facts["agents"].([]map[string]interface{})
	if len(agents) != 2 {
		t.Fatalf("agents = %d, want 2 (one nested in a scope, one in an else branch)", len(agents))
	}
	first := agents[0]
	if first["name"] != "Default_Agent" || first["deploymentId"] != "gpt-4o" {
		t.Fatalf("first agent = %v", first)
	}
	if got := strings.Join(first["tools"].([]string), ","); got != "Lookup,Send_email" {
		t.Fatalf("tools = %s", got)
	}
	if got := strings.Join(first["tool_action_types"].([]string), ","); got != "ApiConnection,Http" {
		t.Fatalf("tool action types = %s", got)
	}
	conns := facts["connections"].([]map[string]interface{})
	if len(conns) != 1 || conns[0]["name"] != "office365" {
		t.Fatalf("connections = %v", conns)
	}
}

func TestLogicAgentFactsIgnoresOrdinaryWorkflows(t *testing.T) {
	def := json.RawMessage(`{"actions": {"Http": {"type": "Http"}}}`)
	if f := logicAgentFacts(def, nil); f != nil {
		t.Fatalf("a workflow with no agent loop was kept: %v", f)
	}
	if f := logicAgentFacts(json.RawMessage(`null`), nil); f != nil {
		t.Fatalf("an unread definition was kept: %v", f)
	}
}

func TestFoundryAgentFactsKeepsNoSecrets(t *testing.T) {
	a := azure.FoundryAgent{
		ID: "asst_1", Name: "support", State: "enabled",
		InstanceIdentity: json.RawMessage(`{"principal_id": "AAAA-1", "client_id": "BBBB-2"}`),
		Versions: json.RawMessage(`{"latest": {"version": "3", "definition": {
		  "kind": "prompt", "model": "gpt-4.1", "instructions": "SECRET INSTRUCTIONS",
		  "tools": [
		    {"type": "mcp", "server_label": "github", "server_url": "https://api.example.com/mcp?code=SECRET",
		     "headers": {"Authorization": "Bearer SECRET"}},
		    {"type": "azure_ai_search", "project_connection_id": "search-conn"},
		    {"type": "code_interpreter"}
		  ]}}}`),
	}
	f := foundryAgentFacts(a)
	raw, _ := json.Marshal(f)
	if strings.Contains(string(raw), "SECRET") {
		t.Fatalf("instructions, a header or a URL secret was kept: %s", raw)
	}
	if f["kind"] != "prompt" || f["model"] != "gpt-4.1" || f["version"] != "3" {
		t.Fatalf("facts = %v", f)
	}
	if got := strings.Join(f["tool_types"].([]string), ","); got != "azure_ai_search,code_interpreter,mcp" {
		t.Fatalf("tool types = %s", got)
	}
	if got := f["instance_identity"].(map[string]interface{})["principal_id"]; got != "aaaa-1" {
		t.Fatalf("instance identity = %v", got)
	}
	if got := strings.Join(f["connections"].([]string), ","); got != "search-conn" {
		t.Fatalf("connections = %s", got)
	}
}

func TestTeamsAgentEntriesKeepsAppsWithABot(t *testing.T) {
	older := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)
	apps := []azure.TeamsApp{
		{ID: "b", DisplayName: "No bot", AppDefinitions: []azure.TeamsAppDefinition{{DisplayName: "No bot"}}},
		{ID: "a", DisplayName: "Helpdesk", AppDefinitions: []azure.TeamsAppDefinition{
			{DisplayName: "Helpdesk v1", Version: "1", LastModifiedDateTime: &older, Bot: &struct {
				ID string `json:"id"`
			}{ID: "OLD"}},
			{DisplayName: "Helpdesk v2", Version: "2", PublishingState: "published", LastModifiedDateTime: &newer, Bot: &struct {
				ID string `json:"id"`
			}{ID: "NEW-BOT"}},
		}},
	}
	counters := map[string]int{}
	out := teamsAgentEntries(apps, counters)
	if len(out) != 1 {
		t.Fatalf("entries = %d, want only the app with a bot", len(out))
	}
	if out[0]["bot_app_id"] != "new-bot" || out[0]["version"] != "2" {
		t.Fatalf("entry = %v, want the newest definition", out[0])
	}
	if counters["teams_org_apps"] != 2 || counters["teams_bot_apps"] != 1 {
		t.Fatalf("counters = %v", counters)
	}
}

func TestDirectoryRoleScope(t *testing.T) {
	cases := []struct {
		dir, app, kind string
	}{
		{"/", "", ""},
		{"", "", ""},
		{"/administrativeUnits/123", "", "administrative_unit"},
		{"/0f1e-app-object", "", "directory_object"},
	}
	for _, c := range cases {
		got := directoryRoleScope(azure.DirectoryRoleAssignment{DirectoryScopeID: c.dir, AppScopeID: c.app})
		if c.kind == "" {
			if got != nil {
				t.Fatalf("%q: scope = %v, want tenant-wide", c.dir, got)
			}
			continue
		}
		if got["scope_kind"] != c.kind || got["directory_scope_id"] != c.dir {
			t.Fatalf("%q: scope = %v", c.dir, got)
		}
	}
}

func TestDirectoryRoleSensitivityForCustomRoles(t *testing.T) {
	custom := azure.DirectoryRoleDefinition{IsBuiltIn: false}
	if got := directoryRoleSensitivity("custom-1", custom, []string{"microsoft.directory/applications/credentials/update"}); got != models.SensitivityHigh {
		t.Fatalf("credential-updating custom role = %s, want high", got)
	}
	if got := directoryRoleSensitivity("custom-2", custom, []string{"microsoft.directory/users/standard/read"}); got != models.SensitivityMedium {
		t.Fatalf("read-only custom role = %s, want med", got)
	}
}

func TestSubscriptionsReadCoversOnlyReadSubscriptions(t *testing.T) {
	reached := models.ScanCoverage{Surfaces: map[string]models.SurfaceCoverage{
		models.SurfaceAzureWorkloads: {State: models.CloudCoverageReached}}}
	r := azureSubscriptionsRead{wanted: 1, passes: []*azurePassResult{{Coverage: reached}}, ids: map[string]bool{"sub-a": true}}
	if !r.all(models.SurfaceAzureWorkloads) {
		t.Fatal("a fully read subscription is not complete")
	}
	if !r.covers("SUB-A") || r.covers("sub-b") || r.covers("") {
		t.Fatal("covers must match only the subscriptions the run read")
	}
	if (azureSubscriptionsRead{wanted: 2, passes: r.passes}).all(models.SurfaceAzureWorkloads) {
		t.Fatal("a run missing a subscription pass must not count as complete")
	}
}
