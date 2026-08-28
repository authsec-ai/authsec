package platform

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/vault"
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

// oauthService builds the GitHub App credential service.
//
// Same store, same key, same JWT signing as the connector broker uses -- a
// GitHub App private key grants access across every installation of that App,
// so a second copy of it would be a second thing to leak for no gain. What is
// NOT shared is any connector row: nothing here reads or writes one.
func (ctl *DiscoveryGitHubController) oauthService() (*services.ConnectorOAuthService, error) {
	addr, token := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		return nil, errors.New("VAULT_ADDR/VAULT_TOKEN not configured; the GitHub App private key cannot be read")
	}
	vc, err := vault.NewClient(addr, token)
	if err != nil {
		return nil, err
	}
	return services.NewConnectorOAuthService(ctl.db, vc), nil
}

// ScanGitHubSource handles POST /authsec/discovery/sources/:id/scan.
//
// The scan is QUEUED, not run inline, and the response is 202 with a run id to
// poll. It used to run inside this request, which failed in two ways that both
// got worse with estate size: an organisation-wide scan outlived the proxy's
// idle timeout and died half-finished, and its result existed only in the
// response body, so refreshing the page lost it for good.
//
// Validation that can be done up front still is — a disabled source or an empty
// selection returns 4xx here rather than becoming a failed run somebody has to
// go and find.
func (ctl *DiscoveryGitHubController) ScanGitHubSource(c *gin.Context) {
	workspaceID, actor, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sourceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid source id"})
		return
	}

	run, err := services.EnqueueGitHubScan(ctl.db, workspaceID, sourceID, actor)
	if errors.Is(err, repositories.ErrScanAlreadyActive) {
		// Not an error the admin needs to fix: point them at the scan already
		// running rather than starting a second one over the same repositories.
		c.JSON(http.StatusConflict, gin.H{
			"error":   "a scan is already queued or running for this source",
			"data":    run,
			"message": "watch the existing run instead of starting another",
		})
		return
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "scan", "discovery_source",
		sourceID.String(), http.StatusAccepted, nil, run)

	c.JSON(http.StatusAccepted, gin.H{
		"message": "GitHub scan queued",
		"success": true,
		"data":    run,
		"meta": gin.H{
			"as_of":     time.Now().UTC(),
			"poll":      "/authsec/discovery/scan-runs/" + run.ID.String(),
			"terminal":  []string{"succeeded", "failed", "cancelled"},
			"note":      "sightings land in the existing discovered_agents inventory as unregistered; claim or quarantine them through the normal endpoints",
			"warn_note": "read complete_for_selected_scope on the finished run; a partial scan is not an all-clear",
		},
	})
}

// GetScanRun handles GET /authsec/discovery/scan-runs/:run_id.
//
// This is the poll target while a scan is in flight and the permanent report
// once it finishes. Counters advance between repositories, so a console can
// show real movement rather than an indefinite spinner.
func (ctl *DiscoveryGitHubController) GetScanRun(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	runID, err := uuid.Parse(c.Param("run_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid run id"})
		return
	}
	run, err := repositories.NewDiscoveryScanRunRepository(ctl.db).Get(workspaceID, runID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan run not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": run,
		"meta": gin.H{
			"as_of":    time.Now().UTC(),
			"terminal": run.Terminal(),
			"note": "complete_for_selected_scope is only meaningful once status is succeeded; " +
				"repos_failed and repos_excluded are different answers and neither means clean",
		},
	})
}

// ListScanRuns handles GET /authsec/discovery/sources/:id/scan-runs — the scan
// history for one source, newest first.
//
// History is the point: an admin has to be able to answer "what did the last
// scan see, and has coverage got better or worse since?" without having been
// watching at the moment it ran.
func (ctl *DiscoveryGitHubController) ListScanRuns(c *gin.Context) {
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
	limit, _ := strconv.Atoi(c.Query("limit"))
	runs, err := repositories.NewDiscoveryScanRunRepository(ctl.db).
		ListForSource(workspaceID, sourceID, limit)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":  runs,
		"total": len(runs),
		"meta":  gin.H{"as_of": time.Now().UTC()},
	})
}

// CancelScanRun handles POST /authsec/discovery/scan-runs/:run_id/cancel.
//
// An organisation-wide scan can be a long and expensive mistake — the wrong
// selection, or a branch plan nobody meant to enable. Cancelling stops further
// work; it does NOT retract the sightings already reported, because those were
// really observed and quietly removing them would be its own kind of lie.
func (ctl *DiscoveryGitHubController) CancelScanRun(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	runID, err := uuid.Parse(c.Param("run_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid run id"})
		return
	}
	run, err := repositories.NewDiscoveryScanRunRepository(ctl.db).Cancel(workspaceID, runID)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "scan run is not queued or running, so it cannot be cancelled",
		})
		return
	}
	auditAdminMutation(c, workspaceID.String(), "cancel", "discovery_scan_run",
		runID.String(), http.StatusOK, nil, run)
	c.JSON(http.StatusOK, gin.H{
		"message": "Scan cancelled",
		"success": true,
		"data":    run,
		"meta": gin.H{
			"note": "findings already reported are kept; they were observed",
		},
	})
}

// AddOrganisationRequest asks for everything needed to start scanning one
// GitHub organisation, which is exactly one thing: which installation.
//
// Nothing else is accepted from the client. The account name, the App id and
// the display name are all derived server-side from the installation, because
// an attacker-supplied account name is precisely what the ownership check below
// exists to reject.
type AddOrganisationRequest struct {
	InstallationID string `json:"installation_id" binding:"required"`
}

// AddOrganisation handles POST /authsec/discovery/github/organisations.
//
// This is the whole "add a GitHub org" flow in one call: it creates the
// governance record, proves the installation belongs to this workspace, and
// creates the discovery source that scans it. One call rather than three
// because the intermediate states are not useful to anyone — a UI that crashed
// between them would leave a pending integration with no source, which reads as
// a broken integration the operator cannot act on.
//
// HOW OWNERSHIP IS PROVEN. iga_integrations refuses to verify a binding unless
// the installation's account matches an authenticated provider account, because
// an installation id arriving from a provider setup URL is attacker-controlled:
// anyone who can guess one could otherwise bind someone else's GitHub org into
// their workspace.
//
// This flow has no GitHub-authenticated admin to compare against — the operator
// is authenticated to AuthSec, not to github.com. So it supplies a different and
// stronger proof: the installation list is re-enumerated HERE, server-side,
// signed with this workspace's own App private key. An installation that comes
// back is by construction an installation of this workspace's App, and the
// account name is read from GitHub's answer rather than from the request body.
// An installation id that does not appear is refused outright — including one
// typed by hand, which is the case the original check was written for.
func (ctl *DiscoveryGitHubController) AddOrganisation(c *gin.Context) {
	workspaceID, actor, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req AddOrganisationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	installationID := strings.TrimSpace(req.InstallationID)
	if installationID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "installation_id is required"})
		return
	}

	oauth, err := ctl.oauthService()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	app, err := repositories.NewConnectorRepository(ctl.db).GetProviderApp(workspaceID, "github")
	if err != nil || app == nil || app.GitHubAppID == "" {
		c.JSON(http.StatusConflict, gin.H{
			"error": "this workspace has no GitHub App yet; register one before adding an organisation",
		})
		return
	}

	// The ownership proof. Enumerated with our own App key, so the account name
	// below is GitHub's answer and not the caller's claim.
	installs, err := oauth.ListGitHubInstallations(c.Request.Context(), workspaceID)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "could not confirm the installation with GitHub: " + err.Error(),
		})
		return
	}
	var match *services.GitHubInstallation
	for i := range installs {
		if installs[i].InstallationID == installationID {
			match = &installs[i]
			break
		}
	}
	if match == nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": "installation " + installationID + " is not an installation of this workspace's GitHub App. " +
				"Install the App on that organisation first, then try again.",
		})
		return
	}

	// Already added? Return the existing pair rather than creating a second
	// source for the same organisation. Two sources scanning one installation
	// would double the API spend and report the same agents twice.
	if existingSrc, existingInteg, found := ctl.findExisting(workspaceID, installationID); found {
		c.JSON(http.StatusOK, gin.H{
			"message": "This organisation is already connected",
			"success": true,
			"data": gin.H{
				"source":          existingSrc,
				"integration":     existingInteg,
				"already_existed": true,
			},
		})
		return
	}

	iga := services.NewIGAManager(repositories.NewIGARepository(ctl.db), nil)

	integ, err := iga.CreateIntegration(workspaceID, actor, services.IntegrationInput{
		Provider:          "github",
		ProviderHost:      "github.com",
		AppRegistrationID: app.GitHubAppID,
		SecretRef:         app.VaultPath,
		CapabilityProfile: map[string]interface{}{
			"repository_selection": match.RepositorySelection,
			"account_type":         match.AccountType,
		},
		RequestedPermissions: map[string]interface{}{"contents": "read", "metadata": "read"},
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Both accounts come from GitHub's own answer above, so the match is not a
	// formality being satisfied — it is the statement that this installation was
	// reachable with this workspace's App key.
	verified, err := iga.VerifyIntegration(workspaceID, integ.ID, services.VerifyInput{
		InstallationID:         installationID,
		AccountNativeID:        match.Account,
		AuthenticatedAccountID: match.Account,
		GrantedPermissions:     map[string]interface{}{"contents": "read", "metadata": "read"},
	})
	if err != nil {
		// Leave nothing half-built: an unverified integration with no source is
		// dead weight the operator cannot see or clear.
		_ = repositories.NewIGARepository(ctl.db).DeleteIntegration(workspaceID, integ.ID)
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}

	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(ctl.db))
	src, err := disco.CreateSource(workspaceID, actor, services.DiscoverySourceInput{
		Kind:        models.DiscoverySourceRepoScan,
		DisplayName: match.Account,
		Config: map[string]interface{}{
			"installation_id":     installationID,
			"integration_id":      verified.ID.String(),
			"app_registration_id": app.GitHubAppID,
			"provider_host":       "github.com",
			"account":             match.Account,
			// Nothing selected yet: an explicit choice must come first, so
			// connecting an org can never trigger an unbounded scan by itself.
			"repositories": map[string]interface{}{"mode": "selected", "include": []string{}},
		},
	})
	if err != nil {
		_ = repositories.NewIGARepository(ctl.db).DeleteIntegration(workspaceID, integ.ID)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "create", "discovery_source",
		src.ID.String(), http.StatusCreated, nil, gin.H{
			"integration_id":  verified.ID.String(),
			"installation_id": installationID,
			"account":         match.Account,
		})

	c.JSON(http.StatusCreated, gin.H{
		"message": match.Account + " connected",
		"success": true,
		"data": gin.H{
			"source":      src,
			"integration": verified,
		},
		"meta": gin.H{
			"next_step": "choose repositories for source " + src.ID.String() + ", then scan",
			"note":      "no repositories are selected yet, so a scan would inspect nothing",
		},
	})
}

// findExisting locates the source and integration already bound to an
// installation in this workspace, if any.
func (ctl *DiscoveryGitHubController) findExisting(
	workspaceID uuid.UUID, installationID string,
) (*models.DiscoverySource, *models.IGAIntegration, bool) {
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(ctl.db))
	sources, err := disco.ListSources(workspaceID, string(models.DiscoverySourceRepoScan), false)
	if err != nil {
		return nil, nil, false
	}
	for i := range sources {
		if sources[i].Kind != models.DiscoverySourceRepoScan {
			continue
		}
		var cfg struct {
			InstallationID string `json:"installation_id"`
			IntegrationID  string `json:"integration_id"`
		}
		if len(sources[i].Config) > 0 {
			_ = json.Unmarshal(sources[i].Config, &cfg)
		}
		if cfg.InstallationID != installationID {
			continue
		}
		var integ *models.IGAIntegration
		if id, perr := uuid.Parse(cfg.IntegrationID); perr == nil {
			integ, _ = repositories.NewIGARepository(ctl.db).GetIntegration(workspaceID, id)
		}
		return &sources[i], integ, true
	}
	return nil, nil, false
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": repos,
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"note": "this is what the installation exposes; repositories not granted are not listed, " +
				"and their absence is not evidence that they hold no agents",
		},
	})
}

// SelectRepositoriesRequest sets the scan plan.
type SelectRepositoriesRequest struct {
	Mode    string   `json:"mode" binding:"required"`
	Include []string `json:"include,omitempty"`

	// BranchMode is "default" (only the branch in effect) or "all". Omitted
	// means default, so an existing caller that knows nothing about branches
	// keeps its previous behaviour.
	BranchMode string `json:"branch_mode,omitempty"`
	// MaxBranchesPerRepo bounds all-branch scanning. Omitted takes the built-in
	// cap. Refs beyond it are counted and force the run incomplete.
	MaxBranchesPerRepo int `json:"max_branches_per_repo,omitempty"`
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
	branchMode := req.BranchMode
	if branchMode == "" {
		branchMode = models.BranchModeDefault
	}
	if branchMode != models.BranchModeDefault && branchMode != models.BranchModeAll {
		c.JSON(http.StatusBadRequest, gin.H{"error": "branch_mode must be default or all"})
		return
	}
	maxBranches := req.MaxBranchesPerRepo
	if maxBranches <= 0 {
		maxBranches = models.DefaultMaxBranchesPerRepo
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
	cfg["branches"] = map[string]interface{}{
		"mode": branchMode, "max_per_repo": maxBranches,
	}

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
			"selection_mode":        req.Mode,
			"selected_count":        len(req.Include),
			"branch_mode":           branchMode,
			"max_branches_per_repo": maxBranches,
			"note": "all means every repository this installation was granted, " +
				"not every repository in the organization",
			"branch_note": "branch_mode all also reads non-default refs, where a declaration may be " +
				"proposed but not merged; such findings are marked is_default_branch=false and are weaker evidence",
		},
	})
}

// workspaceAndActor resolves the authenticated workspace and principal.
//
// Delegates to the package-level helper so there is exactly one answer to "who
// is calling, and for which workspace" across the discovery controllers.
func (ctl *DiscoveryGitHubController) workspaceAndActor(c *gin.Context) (uuid.UUID, string, error) {
	return workspaceAndActorFrom(c)
}

/* --------------------- the workspace's GitHub App ----------------------- */

// The App is workspace-level, not per-organisation: one App, installed on as
// many organisations as the customer likes, each installation becoming its own
// integration. These endpoints exist so discovery never has to call the
// connector API to reach it — the credential store is shared on purpose, the
// product surface is not.

// GetGitHubApp handles GET /authsec/discovery/github/app.
//
// Answers only "is an App registered, and which one". Never returns key
// material: the private key lives in Vault and is not read here at all.
// "Not configured" is a normal answer with a 200, not an error — the caller
// needs to tell it apart from a failure, because they lead to opposite UI.
func (ctl *DiscoveryGitHubController) GetGitHubApp(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	app, err := repositories.NewConnectorRepository(ctl.db).GetProviderApp(workspaceID, "github")
	if err != nil || app == nil || app.GitHubAppID == "" {
		c.JSON(http.StatusOK, gin.H{"configured": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"configured": true,
		"app_id":     app.GitHubAppID,
		"created_at": app.CreatedAt,
	})
}

// DescribeGitHubApp handles GET /authsec/discovery/github/app/describe.
//
// Asks GitHub what the stored App actually is, so the console can show the
// operator that the right App is registered instead of echoing back a number
// they typed. A wrong App id becomes visible here rather than surfacing much
// later as an opaque token-minting failure.
func (ctl *DiscoveryGitHubController) DescribeGitHubApp(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	oauth, err := ctl.oauthService()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	info, err := oauth.DescribeGitHubApp(c.Request.Context(), workspaceID)
	if err != nil {
		// 502, not 400: the credentials are ours. The caller cannot fix this by
		// sending a different request.
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": info})
}

// SetGitHubApp handles POST /authsec/discovery/github/app — register an
// existing App by hand. The manifest flow is the primary path; this is the
// fallback for an App that already exists, or a customer who wants to create it
// themselves. Private key straight to Vault; only the App id is stored here.
func (ctl *DiscoveryGitHubController) SetGitHubApp(c *gin.Context) {
	workspaceID, actor, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req struct {
		AppID      string `json:"app_id" binding:"required"`
		PrivateKey string `json:"private_key" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if ctl.refuseAppChange(c, workspaceID, req.AppID) {
		return
	}
	oauth, err := ctl.oauthService()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	if err := oauth.SetGitHubApp(workspaceID, req.AppID, req.PrivateKey, actor); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// The App id is not secret. The private key is never echoed anywhere.
	auditAdminMutation(c, workspaceID.String(), "set_github_app", "discovery_github_app",
		req.AppID, http.StatusOK, nil, gin.H{"app_id": req.AppID})
	c.JSON(http.StatusOK, gin.H{"status": "configured", "app_id": req.AppID})
}

// ConvertGitHubAppManifest handles
// POST /authsec/discovery/github/app/manifest/convert.
//
// Completes GitHub's App-manifest flow: the operator approves one pre-filled
// screen on github.com, GitHub redirects back with a single-use code, and this
// exchanges it for the App id and private key. That removes App creation,
// permission selection, key generation and key upload from the operator
// entirely — the values never pass through anyone's clipboard.
func (ctl *DiscoveryGitHubController) ConvertGitHubAppManifest(c *gin.Context) {
	workspaceID, actor, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// A manifest conversion always produces a NEW App, so this can never be a
	// same-App key rotation.
	if ctl.refuseAppChange(c, workspaceID, "") {
		return
	}
	oauth, err := ctl.oauthService()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	info, err := oauth.ConvertGitHubAppManifest(c.Request.Context(), workspaceID, req.Code, actor)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	auditAdminMutation(c, workspaceID.String(), "create_github_app_via_manifest",
		"discovery_github_app", info.AppID, http.StatusOK, nil,
		gin.H{"app_id": info.AppID, "slug": info.Slug})
	c.JSON(http.StatusOK, gin.H{"data": info})
}

// DeleteGitHubApp handles DELETE /authsec/discovery/github/app.
//
// Refused while any integration still uses it. Pulling the credential out from
// under a live integration is the worse of the two orphan directions: the
// integration would keep listing itself as connected and fail only at scan time,
// with an error about a missing key that names nothing the operator recognises.
// Naming the blocking organisations turns that into one obvious next action.
//
// This does not uninstall the App from GitHub. Only the account owner can do
// that, on github.com, and saying so is the difference between a complete
// removal and one that appears to have failed when the App is still listed
// there.
func (ctl *DiscoveryGitHubController) DeleteGitHubApp(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	connRepo := repositories.NewConnectorRepository(ctl.db)
	app, err := connRepo.GetProviderApp(workspaceID, "github")
	if err != nil || app == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no GitHub App is registered for this workspace"})
		return
	}

	blocking := ctl.organisationsUsingApp(workspaceID)
	if len(blocking) > 0 {
		c.JSON(http.StatusConflict, gin.H{
			"error":                  "remove these GitHub organisations first: " + strings.Join(blocking, ", "),
			"blocking_organisations": blocking,
		})
		return
	}

	if app.VaultPath != "" {
		if oauth, verr := ctl.oauthService(); verr == nil {
			_ = oauth.DeleteGitHubAppKey(app.VaultPath)
		}
	}
	if err := connRepo.DeleteProviderApp(workspaceID, "github"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	auditAdminMutation(c, workspaceID.String(), "delete", "discovery_github_app",
		app.GitHubAppID, http.StatusOK, gin.H{"app_id": app.GitHubAppID}, nil)
	c.JSON(http.StatusOK, gin.H{
		"message": "GitHub App removed from this workspace",
		"success": true,
		"meta": gin.H{
			"note": "the App itself still exists on GitHub; delete or uninstall it there if you no longer want it",
		},
	})
}

// refuseAppChange blocks swapping the workspace's App while organisations are
// still bound to the current one.
//
// An installation belongs to the App it was created under. Registering a
// different App leaves every existing organisation pointing at credentials that
// can no longer mint a token for it, and nothing says so until the next scan
// fails with an error naming neither the App nor the organisation. Refusing, and
// naming what to remove first, is the difference between a clear instruction and
// a silent break.
//
// Returns true when it has already written a response.
func (ctl *DiscoveryGitHubController) refuseAppChange(
	c *gin.Context, workspaceID uuid.UUID, incomingAppID string,
) bool {
	current, err := repositories.NewConnectorRepository(ctl.db).GetProviderApp(workspaceID, "github")
	// Nothing registered yet, or the same App being re-registered (a key
	// rotation, which keeps every installation valid): nothing to protect.
	if err != nil || current == nil || current.GitHubAppID == "" {
		return false
	}
	if incomingAppID != "" && incomingAppID == current.GitHubAppID {
		return false
	}
	blocking := ctl.organisationsUsingApp(workspaceID)
	if len(blocking) == 0 {
		return false
	}
	c.JSON(http.StatusConflict, gin.H{
		"error": "remove these GitHub organisations first, then register the new App: " +
			strings.Join(blocking, ", "),
		"blocking_organisations": blocking,
		"reason": "each organisation was installed on App " + current.GitHubAppID +
			" and cannot be read by a different App",
	})
	return true
}

// organisationsUsingApp names the repo_scan sources still bound to an
// installation, for the delete refusal above.
func (ctl *DiscoveryGitHubController) organisationsUsingApp(workspaceID uuid.UUID) []string {
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(ctl.db))
	sources, err := disco.ListSources(workspaceID, string(models.DiscoverySourceRepoScan), false)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(sources))
	for i := range sources {
		out = append(out, sources[i].DisplayName)
	}
	return out
}

// ListGitHubInstallations handles GET /authsec/discovery/github/installations.
//
// Everywhere this workspace's App is installed, annotated with whether it has
// already been added here. The annotation is the point: without it the list
// shows organisations that are already connected as if they were new, and
// clicking one either duplicates the source or fails with a uniqueness error
// that explains nothing.
//
// The list is read live from GitHub, never from our tables. That is worth
// stating in the response, because an organisation appears here whether or not
// anything exists on our side — which reads as stale data unless it is said
// plainly.
func (ctl *DiscoveryGitHubController) ListGitHubInstallations(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	oauth, err := ctl.oauthService()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	list, err := oauth.ListGitHubInstallations(c.Request.Context(), workspaceID)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	out := make([]gin.H, 0, len(list))
	for i := range list {
		row := gin.H{
			"installation_id":      list[i].InstallationID,
			"account":              list[i].Account,
			"account_type":         list[i].AccountType,
			"repository_selection": list[i].RepositorySelection,
			"already_added":        false,
		}
		if src, _, found := ctl.findExisting(workspaceID, list[i].InstallationID); found {
			row["already_added"] = true
			row["source_id"] = src.ID.String()
		}
		out = append(out, row)
	}

	c.JSON(http.StatusOK, gin.H{
		"data": out,
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"note": "read live from GitHub, not from AuthSec. An organisation appears here " +
				"whenever the App is installed on it, whether or not it has been added here",
		},
	})
}
