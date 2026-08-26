package platform

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DiscoveryGitHubController adds ONE route to the existing discovery surface:
// a trigger that scans a GitHub repo_scan source and reports what it finds as
// sightings.
//
// It lives in its own file and its own type so the working discovery
// controller is not touched. Everything downstream — the discovered_agents
// inventory, claim, quarantine, coverage — is the existing flow, unchanged.
type DiscoveryGitHubController struct {
	db *gorm.DB
}

// NewDiscoveryGitHubController constructs the controller.
func NewDiscoveryGitHubController(db *gorm.DB) *DiscoveryGitHubController {
	return &DiscoveryGitHubController{db: db}
}

// discoveryScannerOverride lets tests drive the scan from recorded fixtures.
var discoveryScannerOverride services.IGAProvider

// SetDiscoveryGitHubProvider installs a provider for testing without a tenant.
func SetDiscoveryGitHubProvider(p services.IGAProvider) { discoveryScannerOverride = p }

func (ctl *DiscoveryGitHubController) scanner() (*services.GitHubRepoScanner, error) {
	if discoveryScannerOverride != nil {
		return services.NewGitHubRepoScannerWithProvider(ctl.db, discoveryScannerOverride), nil
	}
	addr, token := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		// Without Vault there is no App private key, so no token can be minted.
		// Say so plainly rather than failing later with a confusing 500.
		return nil, errors.New("VAULT_ADDR/VAULT_TOKEN not configured; the GitHub App private key cannot be read")
	}
	vc, err := vault.NewClient(addr, token)
	if err != nil {
		return nil, err
	}
	return services.NewGitHubRepoScanner(ctl.db, vc), nil
}

// ScanGitHubSource handles POST /authsec/discovery/sources/:id/scan.
//
// Returns the coverage-honest result: repositories scanned, failed and
// truncated are reported separately, and complete_for_selected_scope is only
// true when every repository was fully inspected. A caller must not read an
// incomplete scan as "these are all the agents".
func (ctl *DiscoveryGitHubController) ScanGitHubSource(c *gin.Context) {
	workspaceStr := c.GetString("workspace_id")
	if workspaceStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id not found in token"})
		return
	}
	workspaceID, err := uuid.Parse(workspaceStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workspace_id"})
		return
	}
	sourceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid source id"})
		return
	}

	actor := c.GetString("client_id")
	if actor == "" {
		if u, uerr := middlewares.ResolveUserID(c); uerr == nil {
			actor = u
		}
	}
	if actor == "" {
		actor = "system"
	}

	sc, err := ctl.scanner()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	res, err := sc.Scan(c.Request.Context(), workspaceID, sourceID, actor)
	if err != nil {
		c.JSON(providerErrorStatus(err), gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "scan", "discovery_source",
		sourceID.String(), http.StatusOK, nil, res)

	c.JSON(http.StatusOK, gin.H{
		"message": "GitHub scan completed",
		"success": true,
		"data":    res,
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"note":  "sightings land in the existing discovered_agents inventory as unregistered; claim or quarantine them through the normal endpoints",
		},
	})
}

// ConnectorSourceRequest asks for a discovery source built from an existing
// connector connection.
type ConnectorSourceRequest struct {
	ConnectorID uuid.UUID `json:"connector_id" binding:"required"`
	DisplayName string    `json:"display_name,omitempty"`
}

// CreateSourceFromConnector handles
// POST /authsec/discovery/sources/from-connector.
//
// This is the missing link between "connect an org" and "scan it". The
// connector already holds the verified GitHub App installation for this
// workspace; this reads the installation id off that connection and creates
// the matching repo_scan discovery source, so an admin never has to copy an
// installation id by hand, nor mistype one belonging to another org.
//
// The source starts with NO repositories selected. Scanning is a deliberate
// act: an admin picks repositories first, so connecting an org can never
// quietly spend its whole API budget.
func (ctl *DiscoveryGitHubController) CreateSourceFromConnector(c *gin.Context) {
	workspaceID, actor, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req ConnectorSourceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	connRepo := repositories.NewConnectorRepository(ctl.db)
	// Workspace-scoped lookup: a connector id from another workspace resolves
	// to nothing rather than leaking a binding across tenants.
	connector, err := connRepo.GetByID(workspaceID, req.ConnectorID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "connector not found in this workspace"})
		return
	}
	// The connector must actually be a GitHub App connector.
	//
	// Without this check any workspace-bound connection carrying an external
	// account id — a Slack team, a Notion workspace — produced a repo_scan
	// source stamped provider_host "github.com" with that foreign id as its
	// installation_id. Nothing failed until the first scan tried to mint a
	// token, so the source looked healthy and the eventual error pointed at
	// the wrong thing. A source created from a connection must be created from
	// a GITHUB connection.
	if pk := strings.ToLower(connector.ProviderKey); pk != "github" && pk != "github_app" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "connector " + req.ConnectorID.String() + " is provider " +
				connector.ProviderKey + "; GitHub repository scanning requires a GitHub App connector",
		})
		return
	}

	conn, err := connRepo.GetWorkspaceConnection(req.ConnectorID)
	if err != nil || conn == nil || conn.ExternalAccountID == "" {
		c.JSON(http.StatusConflict, gin.H{
			"error": "connector has no GitHub App installation; complete the GitHub App connection first",
		})
		return
	}

	name := req.DisplayName
	if name == "" {
		name = connector.Name
	}

	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(ctl.db))
	src, err := disco.CreateSource(workspaceID, actor, services.DiscoverySourceInput{
		Kind:        models.DiscoverySourceRepoScan,
		DisplayName: name,
		Config: map[string]interface{}{
			"installation_id": conn.ExternalAccountID,
			"connector_id":    req.ConnectorID.String(),
			"provider_host":   "github.com",
			// Nothing selected yet: an explicit choice must come first.
			"repositories": map[string]interface{}{"mode": "selected", "include": []string{}},
		},
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "create", "discovery_source",
		src.ID.String(), http.StatusCreated, nil, src)

	c.JSON(http.StatusCreated, gin.H{
		"message": "Discovery source created from connector",
		"success": true,
		"data":    src,
		"meta": gin.H{
			"next_step": "GET /authsec/discovery/sources/" + src.ID.String() + "/repositories, " +
				"then PUT the selection, then POST .../scan",
			"note": "no repositories are selected yet, so a scan would inspect nothing",
		},
	})
}

// ListSourceRepositories handles
// GET /authsec/discovery/sources/:id/repositories.
//
// Returns what the installation actually exposes, with the current selection
// marked. Repositories GitHub did not grant simply do not appear; their absence
// is a limit of the installation, not evidence about their contents.
func (ctl *DiscoveryGitHubController) ListSourceRepositories(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sourceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid source id"})
		return
	}
	sc, err := ctl.scanner()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	repos, err := sc.ListSelectableRepositories(c.Request.Context(), workspaceID, sourceID)
	if err != nil {
		c.JSON(providerErrorStatus(err), gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": repos,
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			// A dedicated key, carrying the SAME constant the scan result uses.
			// "note" is a general-purpose field reused for several unrelated
			// messages on this controller, so a client cannot locate the
			// disclosure in it without string-matching prose. The mandatory
			// disclosure has to be findable by key, and identical wherever it
			// appears, or a UI will render one surface without it.
			"disclosure": services.ScanGrantDisclosure,
			"note": "this is what the installation exposes; repositories not granted are not listed, " +
				"and their absence is not evidence that they hold no agents",
		},
	})
}

// SelectRepositoriesRequest sets the scan plan.
type SelectRepositoriesRequest struct {
	Mode    string   `json:"mode" binding:"required"`
	Include []string `json:"include,omitempty"`
}

// SetSourceRepositories handles
// PUT /authsec/discovery/sources/:id/repositories — the "select repos or all"
// step. The plan is stored on the source so every later scan uses the same
// explicit boundary.
func (ctl *DiscoveryGitHubController) SetSourceRepositories(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sourceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid source id"})
		return
	}
	var req SelectRepositoriesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Mode != "all" && req.Mode != "selected" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mode must be all or selected"})
		return
	}
	if req.Mode == "selected" && len(req.Include) == 0 {
		// Scanning nothing would be indistinguishable from finding nothing.
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "mode selected requires at least one repository in include",
		})
		return
	}

	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(ctl.db))
	src, err := disco.GetSource(workspaceID, sourceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "discovery source not found"})
		return
	}

	// Merge into the existing config so the installation binding survives.
	cfg := map[string]interface{}{}
	if len(src.Config) > 0 {
		_ = json.Unmarshal(src.Config, &cfg)
	}
	cfg["repositories"] = map[string]interface{}{"mode": req.Mode, "include": req.Include}

	updated, err := disco.UpdateSource(workspaceID, sourceID, services.DiscoverySourceUpdateInput{
		Config: cfg,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "update", "discovery_source",
		sourceID.String(), http.StatusOK, src, updated)

	c.JSON(http.StatusOK, gin.H{
		"message": "Scan plan updated",
		"success": true,
		"data":    updated,
		"meta": gin.H{
			"selection_mode": req.Mode,
			"selected_count": len(req.Include),
			"note": "all means every repository this installation was granted, " +
				"not every repository in the organization",
		},
	})
}

// workspaceAndActor resolves the authenticated workspace and principal.
func (ctl *DiscoveryGitHubController) workspaceAndActor(c *gin.Context) (uuid.UUID, string, error) {
	ws := c.GetString("workspace_id")
	if ws == "" {
		return uuid.Nil, "", errors.New("workspace_id not found in token")
	}
	id, err := uuid.Parse(ws)
	if err != nil {
		return uuid.Nil, "", errors.New("invalid workspace_id")
	}
	actor := c.GetString("client_id")
	if actor == "" {
		if u, uerr := middlewares.ResolveUserID(c); uerr == nil {
			actor = u
		}
	}
	if actor == "" {
		actor = "system"
	}
	return id, actor, nil
}

// providerErrorStatus maps a failure to the status its MEANING deserves.
//
// A provider we could not reach is 503, never 400 and never an empty 200.
// "We could not look" and "we looked and found nothing" are opposite facts
// about a customer's security posture, and a 400 invites a client to render
// the first as the second.
func providerErrorStatus(err error) int {
	var unavail *services.ProviderUnavailableError
	if errors.As(err, &unavail) {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadRequest
}
