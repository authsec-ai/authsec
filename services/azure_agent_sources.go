package services

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sort"
	"strings"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

/* azure_agent_sources.go reads the agent sources that need no licence, beyond
   Agent ID, the agent registry, Foundry agent applications and Azure Bot
   Service bots:

     Teams app catalog       tenant pass: the organization's Teams apps with a
                             bot -- Copilot Studio agents and custom bots
                             published to Teams (AppCatalog.Read.All)
     Logic Apps agents       subscription pass: Consumption workflows whose
                             definition holds an agent loop (an "Agent"
                             action), under Reader
     Foundry project agents  subscription pass: each Foundry project's agents
                             from its data plane, when a Foundry data-plane
                             role is assigned to AuthSec (ARM Reader does not
                             reach it)

   Each records facts only, as Microsoft returns them: names, kinds, models,
   tool types, connections. Never an agent's instructions, and never a tool's
   headers, keys or other secrets. registerResourceAgents turns them into
   discovered agents. */

/* ---------------------------- Teams app catalog ---------------------------- */

const (
	azureTeamsCatalogPermission = "AppCatalog.Read.All"
	// azureTeamsAppsKeep caps the apps stored on the tenant connector.
	azureTeamsAppsKeep = 1000
)

// readTeamsAgents reads the organization's Teams apps that carry a bot. ok is
// false when the catalog could not be read, and what an earlier pass stored
// stays.
func (s *AzureOnboardingService) readTeamsAgents(ctx context.Context, graphToken string, surfaces map[string]models.SurfaceCoverage, counters map[string]int, ungranted map[string]bool) ([]map[string]interface{}, bool) {
	sc := models.SurfaceCoverage{State: models.CloudCoverageReached,
		API: "GET /v1.0/appCatalogs/teamsApps?$filter=distributionMethod eq 'organization'&$expand=appDefinitions($expand=bot)"}
	if ungranted[azureTeamsCatalogPermission] {
		sc.State, sc.ErrorCode = models.CloudCoverageDenied, models.AzureGraphPermissionNotGranted
		sc.Error = azureTeamsCatalogPermission + " is not granted to AuthSec in this tenant: an administrator adds it to the AuthSec app and grants consent again"
		surfaces[models.SurfaceEntraTeamsApps] = sc
		return nil, false
	}
	apps, err := s.api.ListOrganizationTeamsApps(ctx, graphToken)
	if err != nil && !errors.Is(err, azure.ErrPageLimit) {
		logAzureError("teams app catalog", err)
		surfaces[models.SurfaceEntraTeamsApps] = surfaceFailure(sc, err, 0)
		return nil, false
	}
	if errors.Is(err, azure.ErrPageLimit) {
		sc.State, sc.Error = models.CloudCoveragePartial, "stopped at the listing page limit"
	}
	out := teamsAgentEntries(apps, counters)
	sc.Count = len(out)
	surfaces[models.SurfaceEntraTeamsApps] = sc
	return out, true
}

// teamsAgentEntries keeps the apps with a bot, newest definition first, as
// stored facts.
func teamsAgentEntries(apps []azure.TeamsApp, counters map[string]int) []map[string]interface{} {
	sort.Slice(apps, func(i, j int) bool { return apps[i].ID < apps[j].ID })
	out := make([]map[string]interface{}, 0)
	for _, a := range apps {
		counters["teams_org_apps"]++
		var def *azure.TeamsAppDefinition
		for i := range a.AppDefinitions {
			d := &a.AppDefinitions[i]
			if d.Bot == nil || d.Bot.ID == "" {
				continue
			}
			if def == nil || (d.LastModifiedDateTime != nil && (def.LastModifiedDateTime == nil || d.LastModifiedDateTime.After(*def.LastModifiedDateTime))) {
				def = d
			}
		}
		if def == nil {
			continue
		}
		counters["teams_bot_apps"]++
		e := map[string]interface{}{
			"teams_app_id": a.ID, "external_id": a.ExternalID,
			"name":    firstNonEmpty(def.DisplayName, a.DisplayName),
			"version": def.Version, "publishing_state": def.PublishingState,
			"description": def.Description, "bot_app_id": strings.ToLower(def.Bot.ID),
		}
		if def.LastModifiedDateTime != nil {
			e["modified_at"] = def.LastModifiedDateTime.UTC()
		}
		if cb := def.CreatedBy; cb != nil {
			if cb.User != nil {
				e["created_by_user_id"], e["created_by"] = cb.User.ID, cb.User.DisplayName
			} else if cb.Application != nil {
				e["created_by_app_id"], e["created_by"] = cb.Application.ID, cb.Application.DisplayName
			}
		}
		out = append(out, e)
		if len(out) >= azureTeamsAppsKeep {
			break
		}
	}
	return out
}

// tenantTeamsAgents is the Teams catalog the last tenant pass stored.
func (s *AzureOnboardingService) tenantTeamsAgents(workspaceID, tenantConnectorID uuid.UUID) []map[string]interface{} {
	var row struct{ Apps []byte }
	if err := s.db.Model(&models.CloudConnector{}).Select("attrs->'teams_agents' AS apps").
		Where("workspace_id = ? AND id = ?", workspaceID, tenantConnectorID).Scan(&row).Error; err != nil || len(row.Apps) == 0 {
		return nil
	}
	var out []map[string]interface{}
	_ = json.Unmarshal(row.Apps, &out)
	return out
}

/* ------------------------------- Logic Apps -------------------------------- */

// azureLogicWorkflowQuery reads every Consumption workflow with its definition
// and the connections its parameters bind.
const azureLogicWorkflowQuery = `Resources
| where type =~ 'microsoft.logic/workflows'
| project id, name, location, state = tostring(properties.state),
    definition = properties.definition, parameters = properties.parameters
| order by id asc`

type azureLogicWorkflowRow struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Location   string          `json:"location"`
	State      string          `json:"state"`
	Definition json.RawMessage `json:"definition"`
	Parameters json.RawMessage `json:"parameters"`
}

// azureLogicDefinitionFetchLimit caps the workflows whose definition is read
// one by one when Resource Graph did not return it.
const azureLogicDefinitionFetchLimit = 200

// collectLogicAgents finds the subscription's Consumption workflows that run
// an agent loop, keyed by their ARM id (lowercased), with the facts of each.
func (s *AzureOnboardingService) collectLogicAgents(ctx context.Context, subscriptionID, armToken string, counters map[string]int) (map[string]map[string]interface{}, error) {
	rows, err := azureQueryAll[azureLogicWorkflowRow](ctx, s, armToken, subscriptionID, azureLogicWorkflowQuery)
	if err != nil && !errors.Is(err, azure.ErrPageLimit) {
		logAzureError("logic app workflows", err)
		return nil, err
	}
	capped := errors.Is(err, azure.ErrPageLimit)
	out := map[string]map[string]interface{}{}
	fetched := 0
	var firstErr error
	for _, r := range rows {
		counters["logic_workflows"]++
		def, params, state := r.Definition, r.Parameters, r.State
		if isJSONEmpty(def) {
			if fetched >= azureLogicDefinitionFetchLimit {
				counters["logic_workflow_definitions_unread"]++
				continue
			}
			fetched++
			w, err := s.api.GetLogicWorkflow(ctx, armToken, r.ID)
			if err != nil {
				counters["logic_workflow_definitions_unread"]++
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			def, params = w.Properties.Definition, w.Properties.Parameters
			if state == "" {
				state = w.Properties.State
			}
		}
		facts := logicAgentFacts(def, params)
		if facts == nil {
			continue
		}
		facts["workflow_name"] = r.Name
		facts["state"] = state
		facts["sku"] = "consumption"
		out[strings.ToLower(r.ID)] = facts
		counters["logic_agent_workflows"]++
	}
	switch {
	case capped:
		return out, azure.ErrPageLimit
	case firstErr != nil:
		return out, firstErr
	}
	return out, nil
}

func isJSONEmpty(raw json.RawMessage) bool {
	t := strings.TrimSpace(string(raw))
	return t == "" || t == "null" || t == "{}"
}

// logicAgentFacts are a workflow's agent loops, or nil when it has none: each
// Agent action's name, the model it names, its tools and the actions each
// tool runs, and the connections the workflow binds. Only names and types --
// never a prompt, a message or a parameter value.
func logicAgentFacts(definition, parameters json.RawMessage) map[string]interface{} {
	var def map[string]interface{}
	if json.Unmarshal(definition, &def) != nil {
		return nil
	}
	var agents []map[string]interface{}
	walkLogicActions(def["actions"], func(name string, action map[string]interface{}) {
		if !strings.EqualFold(str(action["type"]), "Agent") {
			return
		}
		a := map[string]interface{}{"name": name}
		if inputs, ok := action["inputs"].(map[string]interface{}); ok {
			if p, ok := inputs["parameters"].(map[string]interface{}); ok {
				for _, k := range []string{"deploymentId", "agentModelType", "modelName"} {
					if v := str(p[k]); v != "" {
						a[k] = v
					}
				}
				if ms, ok := p["agentModelSettings"].(map[string]interface{}); ok {
					if v := str(ms["deploymentId"]); v != "" {
						a["deploymentId"] = v
					}
				}
			}
		}
		if tools, ok := action["tools"].(map[string]interface{}); ok {
			var names []string
			uses := map[string]bool{}
			for tn, t := range tools {
				names = append(names, tn)
				if tm, ok := t.(map[string]interface{}); ok {
					walkLogicActions(tm["actions"], func(_ string, ta map[string]interface{}) {
						if t := str(ta["type"]); t != "" {
							uses[t] = true
						}
					})
				}
			}
			sort.Strings(names)
			a["tools"] = names
			a["tool_action_types"] = sortedKeys(uses)
		}
		agents = append(agents, a)
	})
	if len(agents) == 0 {
		return nil
	}
	sort.Slice(agents, func(i, j int) bool { return str(agents[i]["name"]) < str(agents[j]["name"]) })
	facts := map[string]interface{}{"agents": agents}
	// The API connections the workflow binds ($connections): what its tools
	// can reach, by connection name and its ARM id.
	var params map[string]interface{}
	if json.Unmarshal(parameters, &params) == nil {
		if c, ok := params["$connections"].(map[string]interface{}); ok {
			if v, ok := c["value"].(map[string]interface{}); ok {
				var conns []map[string]interface{}
				for name, raw := range v {
					m, _ := raw.(map[string]interface{})
					conns = append(conns, map[string]interface{}{
						"name": name, "connection_id": strings.ToLower(str(m["connectionId"])),
						"api_id": strings.ToLower(str(m["id"])),
					})
				}
				sort.Slice(conns, func(i, j int) bool { return str(conns[i]["name"]) < str(conns[j]["name"]) })
				facts["connections"] = conns
			}
		}
	}
	return facts
}

// walkLogicActions visits every action of a definition's actions map,
// including the ones nested in scopes, conditions, switches and loops.
func walkLogicActions(actions interface{}, visit func(name string, action map[string]interface{})) {
	m, ok := actions.(map[string]interface{})
	if !ok {
		return
	}
	for name, raw := range m {
		a, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		visit(name, a)
		walkLogicActions(a["actions"], visit)
		if e, ok := a["else"].(map[string]interface{}); ok {
			walkLogicActions(e["actions"], visit)
		}
		if d, ok := a["default"].(map[string]interface{}); ok {
			walkLogicActions(d["actions"], visit)
		}
		if cases, ok := a["cases"].(map[string]interface{}); ok {
			for _, c := range cases {
				if cm, ok := c.(map[string]interface{}); ok {
					walkLogicActions(cm["actions"], visit)
				}
			}
		}
	}
}

func str(v interface{}) string {
	s, _ := v.(string)
	return s
}

/* ----------------------------- Foundry agents ------------------------------ */

// azureFoundryProject is a Foundry project the pass recorded, with the endpoint
// of its account.
type azureFoundryProject struct {
	NativeID        string
	Name            string
	AccountEndpoint string
}

// collectFoundryAgents reads each Foundry project's agents from its data plane
// and records them on the project's row (attrs.project_agents). Without a
// Foundry data-plane role the data plane answers 403: the surface says so and
// nothing else changes.
func (s *AzureOnboardingService) collectFoundryAgents(ctx context.Context, workspaceID, connectorID uuid.UUID, foundryToken string, counters map[string]int) models.SurfaceCoverage {
	sc := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "GET {project}/agents?api-version=v1 (Foundry data plane)"}
	var projects []azureFoundryProject
	if err := s.db.Table("cloud_workload p").
		Select("p.native_id, p.name, a.attrs->>'endpoint' AS account_endpoint").
		Joins("JOIN cloud_workload a ON a.workspace_id = p.workspace_id AND a.connector_id = p.connector_id AND lower(a.attrs->>'resource_id') = lower(p.attrs->>'account_id') AND a.attrs->>'foundry_kind' = 'account'").
		Where("p.workspace_id = ? AND p.connector_id = ? AND p.attrs->>'foundry_kind' = 'project'", workspaceID, connectorID).
		Scan(&projects).Error; err != nil {
		return surfaceFailure(sc, err, 0)
	}
	if len(projects) == 0 {
		return sc
	}
	if foundryToken == "" {
		sc.State, sc.Error = models.CloudCoverageDenied, "AuthSec could not obtain a Foundry data-plane token in this tenant"
		return sc
	}
	denied, failed := 0, 0
	var firstErr error
	for _, p := range projects {
		endpoint := azure.FoundryProjectEndpoint(p.AccountEndpoint, p.Name)
		if endpoint == "" {
			failed++
			continue
		}
		agents, err := s.api.ListFoundryProjectAgents(ctx, foundryToken, endpoint)
		if err != nil && !errors.Is(err, azure.ErrPageLimit) {
			if azure.IsAccessDenied(err) {
				denied++
			} else {
				failed++
				if firstErr == nil {
					firstErr = err
				}
			}
			continue
		}
		facts := make([]map[string]interface{}, 0, len(agents))
		for _, a := range agents {
			facts = append(facts, foundryAgentFacts(a))
			counters["foundry_project_agents"]++
		}
		patch, _ := json.Marshal(map[string]interface{}{"project_agents": facts})
		if err := s.db.Exec("UPDATE cloud_workload SET attrs = attrs || ?::jsonb WHERE workspace_id = ? AND connector_id = ? AND native_id = ?",
			string(patch), workspaceID, connectorID, p.NativeID).Error; err != nil {
			log.Printf("[azure] scan: could not record Foundry agents of %s: %v", p.Name, err)
			failed++
		}
		sc.Count += len(facts)
	}
	switch {
	case denied == len(projects):
		sc.State, sc.ErrorCode = models.CloudCoverageDenied, "foundry_role_not_assigned"
		sc.Error = "no Foundry data-plane role is assigned to AuthSec on these Foundry accounts, so their projects' agents cannot be listed"
	case denied > 0 || failed > 0:
		sc.State = models.CloudCoveragePartial
		sc.Error = "the agents of some Foundry projects could not be listed"
		if firstErr != nil {
			sc.Error += ": " + firstErr.Error()
		}
	}
	return sc
}

// foundryAgentFacts keeps an agent's identity and what it is made of: its
// kind, model, tool types, MCP servers and connections. Never its
// instructions, and never a tool's headers or keys.
func foundryAgentFacts(a azure.FoundryAgent) map[string]interface{} {
	out := map[string]interface{}{"id": a.ID, "name": a.Name, "state": a.State}
	pick := func(raw json.RawMessage, keys ...string) map[string]interface{} {
		var m map[string]interface{}
		if json.Unmarshal(raw, &m) != nil {
			return nil
		}
		o := map[string]interface{}{}
		for _, k := range keys {
			if v := str(m[k]); v != "" {
				o[k] = strings.ToLower(v)
			}
		}
		return o
	}
	if id := pick(a.InstanceIdentity, "principal_id", "client_id", "object_id"); len(id) > 0 {
		out["instance_identity"] = id
	}
	if id := pick(a.Blueprint, "principal_id", "client_id", "object_id"); len(id) > 0 {
		out["blueprint"] = id
	}
	var versions map[string]interface{}
	if json.Unmarshal(a.Versions, &versions) == nil {
		latest, _ := versions["latest"].(map[string]interface{})
		if latest == nil {
			latest = versions
		}
		if v := str(latest["version"]); v != "" {
			out["version"] = v
		}
		if def, ok := latest["definition"].(map[string]interface{}); ok {
			for _, k := range []string{"kind", "model"} {
				if v := str(def[k]); v != "" {
					out[k] = v
				}
			}
			if tools, ok := def["tools"].([]interface{}); ok {
				types := map[string]bool{}
				var mcp []map[string]interface{}
				conns := map[string]bool{}
				for _, t := range tools {
					tm, _ := t.(map[string]interface{})
					tt := str(tm["type"])
					if tt != "" {
						types[tt] = true
					}
					if tt == "mcp" {
						mcp = append(mcp, map[string]interface{}{
							"server_label": str(tm["server_label"]), "server_url": safeTarget(str(tm["server_url"])),
						})
					}
					for _, k := range []string{"project_connection_id", "connection_id"} {
						if v := str(tm[k]); v != "" {
							conns[v] = true
						}
					}
				}
				out["tool_types"] = sortedKeys(types)
				if len(mcp) > 0 {
					out["mcp_servers"] = mcp
				}
				if len(conns) > 0 {
					out["connections"] = sortedKeys(conns)
				}
			}
		}
	}
	return out
}
