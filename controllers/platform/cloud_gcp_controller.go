package platform

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/internal/tokens"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CloudGCPController is GCP onboarding: the first step of GCP cloud
// discovery and the only one that touches a customer credential.
//
// Mirrors CloudAWSController exactly in shape and placement — under
// /authsec/discovery/gcp/* alongside the AWS, Kubernetes and GitHub
// channels, not under /connectors, for the same reason: the connector
// broker is the action framework, and discovery must not depend on it.
//
// Nothing here discovers anything. It establishes the read-only connection
// (WIF or a fallback uploaded key) and records the cloud_connector row that
// every later GCP discovery surface resolves against.
type CloudGCPController struct {
	db *gorm.DB
}

// NewCloudGCPController constructs the controller.
func NewCloudGCPController(db *gorm.DB) *CloudGCPController {
	return &CloudGCPController{db: db}
}

// service builds the onboarding service. Unlike AWS's ctl.service(), a
// missing Vault configuration does NOT fail this outright — GCPOnboardingService
// accepts a nil vault.VaultClient and only errors from the json_key path when
// one is actually needed (GCPAuthService's own constructor comment). A
// deployment with no Vault wired can still onboard GCP connectors via WIF.
func (ctl *CloudGCPController) service() *services.GCPOnboardingService {
	var vc vault.VaultClient
	if addr, token := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN"); addr != "" && token != "" {
		if c, err := vault.NewClient(addr, token); err == nil {
			vc = c
		}
	}
	appIssuerURL := ""
	if config.AppConfig != nil {
		appIssuerURL = config.AppConfig.OAuthBaseURL()
	}
	// GCP_WIF_ISSUER_URL, if set, overrides ONLY what this connector mints
	// tokens as and renders into the setup script — never the app's general
	// OAuth issuer. See internal/gcp/issuer.go.
	issuerURL := gcp.ResolveWIFIssuerURL(appIssuerURL)
	issuer := tokens.NewNativeIssuer(ctl.db, tokens.NativeKeys(), issuerURL)
	return services.NewGCPOnboardingService(ctl.db, vc, issuer)
}

/* ------------------------------ onboarding kit ---------------------------- */

// GetOnboardingPackage handles GET /authsec/discovery/gcp/onboarding.
//
// Query params: reader_project_id, scope_id (both required to render a
// script — a reader SA always needs a home project, distinct from the scope
// being connected, per GCP-D9). scope_kind is optional (defaults to
// "project", the common case) — it only affects which gcloud subcommand the
// rendered role-grant commands use (organizations/folders/projects
// add-iam-policy-binding), not the WIF derivation itself, which is a pure
// function of (workspace_id, scope_id) alone.
//
// Always returns configured:true for both methods now — WIF trusts AuthSec's
// own already-public issuer (no external configuration needed) and json_key
// only needs Vault at CreateConnector time, not here. There is no more
// "not implemented" branch (GCP-D9 is resolved).
func (ctl *CloudGCPController) GetOnboardingPackage(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	readerProjectID := strings.TrimSpace(c.Query("reader_project_id"))
	scopeID := strings.TrimSpace(c.Query("scope_id"))
	if readerProjectID == "" || scopeID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "reader_project_id and scope_id are both required to render the setup script",
		})
		return
	}
	scopeKind := c.DefaultQuery("scope_kind", models.CloudScopeProject)

	// Validate BEFORE rendering. setup-reader.sh is a text/template, which
	// escapes nothing, and the customer runs the result in a gcloud-authenticated
	// shell. These two values land inside double quotes and in command position,
	// so an unvalidated one is a command the customer executes. This endpoint
	// needs only discovery:read, so whoever crafts the string need not be
	// whoever runs the script.
	if err := gcp.ValidateProjectID("reader_project_id", readerProjectID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := gcp.ValidateScopeID(scopeKind, scopeID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	poolID, providerID, wifSubject := gcp.DeriveWIFParams(workspaceID, scopeID)
	appIssuerURL := ""
	if config.AppConfig != nil {
		appIssuerURL = config.AppConfig.OAuthBaseURL()
	}
	// Same override as ctl.service() — must resolve identically, since this
	// is the issuer value rendered into the script's --issuer-uri= flag, and
	// it has to match what ctl.service()'s NativeIssuer actually mints
	// tokens as, or WIF breaks in a different, worse way (script configures
	// GCP to trust an issuer AuthSec never signs as).
	issuerURL := gcp.ResolveWIFIssuerURL(appIssuerURL)

	script, err := gcp.Render(gcp.Data{
		ReaderProjectID:    readerProjectID,
		ScopeKind:          scopeKind,
		ScopeID:            scopeID,
		PoolID:             poolID,
		ProviderID:         providerID,
		WIFSubject:         wifSubject,
		IssuerURL:          issuerURL,
		RoleSetStatus:      gcp.CurrentRoleSetStatus,
		SetupScriptVersion: gcp.Version,
		RoleGrantCommands:  gcp.RoleGrantCommands(scopeKind, scopeID),
		CoreServices:       gcp.CoreServices,
		DiscoveryServices:  gcp.DiscoveryServices,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"configured": true,
		"data": gin.H{
			"reader_project_id":    readerProjectID,
			"scope_kind":           scopeKind,
			"scope_id":             scopeID,
			"pool_id":              poolID,
			"provider_id":          providerID,
			"wif_subject":          wifSubject,
			"issuer_url":           issuerURL,
			"role_set":             gcp.ReaderRolesFor(scopeKind),
			"role_set_version":     gcp.ReaderRoleSetVersion,
			"role_set_status":      gcp.CurrentRoleSetStatus,
			"setup_script":         script,
			"setup_script_version": gcp.Version,
			"wif_instructions": "Run the script, then paste the provider resource it prints at the end " +
				"into the WIF form below.",
		},
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"next":  "POST /authsec/discovery/gcp/connectors with scope_kind, scope_id, reader_project_id and auth",
			"read_only": "the script creates one service account, its role grants, and (for WIF) a " +
				"workload identity pool/provider; nothing is installed and no software runs in your project",
		},
	})
}

/* -------------------------------- connectors ------------------------------ */

// gcpCreateConnectorRequest is the wire shape for CreateConnector. KeyJSON
// carries the uploaded service-account key file's raw text, embedded as a
// JSON string field (the key file is itself JSON) — never logged, never
// echoed back, and converted to []byte immediately on the way into
// services.GCPAuthInput.
type gcpCreateConnectorRequest struct {
	ScopeKind       string `json:"scope_kind"`
	ScopeID         string `json:"scope_id"`
	ReaderProjectID string `json:"reader_project_id"`
	DisplayName     string `json:"display_name"`
	Auth            struct {
		Method           string `json:"method"`
		KeyJSON          string `json:"key_json,omitempty"`
		ProviderResource string `json:"provider_resource,omitempty"`
		ReaderSAEmail    string `json:"reader_sa_email,omitempty"`
	} `json:"auth"`

	// Hints is optional customer-declared context no GCP API reports.
	// Non-secret by construction — an environment name, a naming convention, a
	// team — and never a credential, so it is safe on a row that is returned
	// to the console.
	Hints *models.GCPOnboardingHints `json:"hints,omitempty"`
}

// CreateConnector handles POST /authsec/discovery/gcp/connectors.
//
// Proves the connection and the claimed scope, then records it. The request
// body is never logged or echoed anywhere in this handler — on success the
// STORED connector (which carries no key material, see
// models.GCPConnectorAttrs) is what gets audited and returned, never the
// request struct itself.
func (ctl *CloudGCPController) CreateConnector(c *gin.Context) {
	workspaceID, actor, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var req gcpCreateConnectorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	in := services.GCPOnboardInput{
		ScopeKind:       req.ScopeKind,
		ScopeID:         req.ScopeID,
		ReaderProjectID: req.ReaderProjectID,
		DisplayName:     req.DisplayName,
		Hints:           req.Hints,
		Auth: services.GCPAuthInput{
			Method:           req.Auth.Method,
			KeyJSON:          []byte(req.Auth.KeyJSON),
			ProviderResource: req.Auth.ProviderResource,
			ReaderSAEmail:    req.Auth.ReaderSAEmail,
		},
	}
	// req.Auth.KeyJSON's backing string is not zeroed here -- Go strings are
	// immutable and the request body itself is already garbage-collectable
	// once this handler returns. What matters is that nothing between here and
	// the response writes req (or in.Auth.KeyJSON) to a log, an audit record,
	// or a response body -- verified below and in cloud_gcp_controller_test.go.

	svc := ctl.service()
	connector, created, err := svc.Onboard(c.Request.Context(), workspaceID, in, actor)
	if err != nil {
		status, body := mapGCPOnboardingError(err)
		c.JSON(status, body)
		return
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	auditAdminMutation(c, workspaceID.String(), "onboard", "cloud_connector",
		connector.ID.String(), status, nil, connector)

	c.JSON(status, gin.H{
		"success": true,
		"message": gcpOnboardMessage(created),
		"data":    connector,
		"meta": gin.H{
			"as_of":    time.Now().UTC(),
			"verified": connector.VerifiedAt,
			"note": "the connection is proven but nothing has been discovered yet; " +
				"identity discovery runs as a separate step",
		},
	})
}

func gcpOnboardMessage(created bool) string {
	if created {
		return "GCP scope connected"
	}
	return "GCP scope reconnected; the existing connector was updated in place"
}

// ListConnectors handles GET /authsec/discovery/gcp/connectors.
func (ctl *CloudGCPController) ListConnectors(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	rows, err := repositories.NewCloudConnectorRepository(ctl.db).
		List(workspaceID, models.CloudProviderGCP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{"as_of": time.Now().UTC(), "count": len(rows)},
	})
}

// GetConnector handles GET /authsec/discovery/gcp/connectors/:id.
func (ctl *CloudGCPController) GetConnector(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	row, err := ctl.service().Connector(workspaceID, id)
	if err != nil {
		status, body := mapGCPOnboardingError(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": row,
		"meta": gin.H{"as_of": time.Now().UTC()},
	})
}

// VerifyConnector handles POST /authsec/discovery/gcp/connectors/:id/verify.
func (ctl *CloudGCPController) VerifyConnector(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}

	connector, verr := ctl.service().VerifyConnector(c.Request.Context(), workspaceID, id)
	if verr != nil {
		status, body := mapGCPOnboardingError(verr)
		if connector != nil {
			body["data"] = connector
		}
		c.JSON(status, body)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "connection verified",
		"data":    connector,
		"meta":    gin.H{"as_of": time.Now().UTC()},
	})
}

// RevokeConnector handles DELETE /authsec/discovery/gcp/connectors/:id.
//
// Soft-revoke: purges the Vault credential for json_key (a documented no-op
// for wif), then marks the row 'revoked' and KEEPS it, for audit. This is a
// deliberate, known difference from the landed AWS DELETE (which
// hard-deletes the row) — not something awaiting further alignment. The
// route stays DELETE to keep the URL shape consistent with AWS despite the
// differing behaviour underneath it.
func (ctl *CloudGCPController) RevokeConnector(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	if err := ctl.service().RevokeConnector(workspaceID, id); err != nil {
		status, body := mapGCPOnboardingError(err)
		c.JSON(status, body)
		return
	}
	auditAdminMutation(c, workspaceID.String(), "revoke", "cloud_connector",
		id.String(), http.StatusOK, nil, nil)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "GCP connector revoked; the row is kept for audit",
		"meta": gin.H{
			"note": "the reader service account, its role grants and (for WIF) the workload identity " +
				"pool/provider still exist in your project; removing them is your step",
		},
	})
}

/* --------------------------------- scanning -------------------------------- */

// scanner builds the discovery scanner. Same Vault-optional reasoning as
// service(): a WIF connector needs no Vault at all, and a deployment without
// one must still be able to scan.
func (ctl *CloudGCPController) scanner() *services.GCPScanner {
	var vc vault.VaultClient
	if addr, token := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN"); addr != "" && token != "" {
		if c, err := vault.NewClient(addr, token); err == nil {
			vc = c
		}
	}
	appIssuerURL := ""
	if config.AppConfig != nil {
		appIssuerURL = config.AppConfig.OAuthBaseURL()
	}
	issuerURL := gcp.ResolveWIFIssuerURL(appIssuerURL)
	issuer := tokens.NewNativeIssuer(ctl.db, tokens.NativeKeys(), issuerURL)
	return services.NewGCPScanner(ctl.db, services.NewGCPAuthService(vc, issuer))
}

// ScanConnector handles POST /authsec/discovery/gcp/connectors/:id/scan.
//
// Mirrors cloudAWS.ScanIAM's contract: the scan runs in the background, this
// returns 202, and the durable record is the connector's own coverage blob, so
// polling is a GET of the connector and the report survives a page refresh.
//
// The `note` in the response is not decoration. A 202 plus a coverage status of
// `partial` is NOT an all-clear, and saying so only inside the coverage blob
// puts the warning somewhere the caller of this endpoint may never look. AWS's
// handler makes the same admission in its own success body; this is the same
// discipline, not a copied string.
func (ctl *CloudGCPController) ScanConnector(c *gin.Context) {
	workspaceID, actor, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}

	// Validate what can be validated up front, so an unusable connector is a
	// 4xx here rather than a failed scan someone has to go and find. The
	// scanner re-checks all of this: it runs in a goroutine that outlives this
	// request, and state can change in between.
	connector, err := ctl.service().Connector(workspaceID, id)
	if err != nil {
		status, body := mapGCPOnboardingError(err)
		c.JSON(status, body)
		return
	}
	if connector.Status == models.CloudConnectorRevoked {
		c.JSON(http.StatusConflict, gin.H{
			"error": "this connection was revoked; reconnect the scope before scanning",
			"fault": "customer_account",
		})
		return
	}
	if attrs := connector.GCPAttrs(); attrs.DiscoveryReadiness == models.GCPReadinessBlocked {
		c.JSON(http.StatusConflict, gin.H{
			"error":   "this connector is not ready for discovery",
			"reasons": attrs.DiscoveryReadinessReasons,
			"hint":    "re-run verify after fixing the reasons above",
			"fault":   "customer_account",
		})
		return
	}

	scanner := ctl.scanner()

	// context.Background(), not the request context: the request is about to
	// return, and cancelling the scan when it does would kill every scan
	// immediately. The scanner applies its own scan-wide and per-phase
	// deadlines, so this is bounded despite not being tied to the request.
	go func() {
		if _, err := scanner.Scan(context.Background(), workspaceID, id); err != nil {
			log.Printf("gcp scan: connector=%s workspace=%s: %v", id, workspaceID, err)
		}
	}()

	auditAdminMutation(c, workspaceID.String(), "scan", "cloud_connector",
		id.String(), http.StatusAccepted, nil, gin.H{"surface": "identities", "actor": actor})

	c.JSON(http.StatusAccepted, gin.H{
		"success": true,
		"message": "GCP service account and key discovery started",
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"poll":  "/authsec/discovery/gcp/connectors/" + id.String(),
			"writes": []string{
				"cloud_identity", "cloud_secret",
			},
			"surfaces": []string{gcp.SurfaceIdentities, gcp.SurfaceKeys},
			"note": "watch coverage.status on the connector; 'partial' means at least one " +
				"project was denied, throttled or refused by policy and the inventory is " +
				"NOT an all-clear. Only a 'complete' scan is allowed to remove anything, so " +
				"a partial result leaves the previous inventory in place rather than " +
				"reporting it as deleted. IAM bindings, resources and workloads are later " +
				"surfaces and are not read by this scan.",
		},
	})
}

func (ctl *CloudGCPController) workspaceAndActor(c *gin.Context) (uuid.UUID, string, error) {
	return workspaceAndActorFrom(c)
}

/* ------------------------------ error mapping ----------------------------- */

// mapGCPOnboardingError turns a service error into a status and a body that
// tells the operator whose problem it is — the {error, hint?, fault?}
// envelope, mirroring mapAWSOnboardingError exactly. fault classification per
// this ticket's own instruction: scope_not_readable, invalid_scope_id,
// key_invalid, permission_denied, wif_pool_missing all map to
// fault:"customer_account" (every one of them represents something wrong on
// the customer's side now that both auth methods are fully implemented);
// invalid_grant maps to fault:"gcp".
func mapGCPOnboardingError(err error) (int, gin.H) {
	switch {
	case errors.Is(err, repositories.ErrCloudConnectorNotFound):
		return http.StatusNotFound, gin.H{"error": "connector not found"}

	case errors.Is(err, services.ErrInvalidScopeID):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "check scope_kind (must be org, folder or project), scope_id and reader_project_id",
			"fault": "customer_account",
		}

	case errors.Is(err, services.ErrKeyedOnboardingClosed):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint": "use auth.method \"wif\" — fetch GET /discovery/gcp/onboarding for the setup script, " +
				"or connect with Google Authentication to have it configured for you",
			"fault": "customer_account",
		}

	case errors.Is(err, services.ErrConnectorRevoked):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "reconnect this scope (POST /connectors again with fresh credentials) instead of verifying a revoked connector",
			"fault": "customer_account",
		}

	// A fourth fault class alongside customer_account / gcp / authsec. The
	// three existing ones all imply somebody made a mistake; these two mean
	// somebody made a DECISION, and the console has to say so — telling a
	// customer to grant a role when a perimeter is blocking the call wastes
	// their time on a change that cannot work.
	case errors.Is(err, gcp.ErrVPCServiceControls):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint": "a VPC Service Controls perimeter is blocking this read. The reader may already hold every " +
				"permission it needs — whoever owns the perimeter has to allow AuthSec through it, via an " +
				"access level or an ingress rule. Granting more IAM roles will not change this.",
			"fault": "constrained",
		}

	case errors.Is(err, gcp.ErrOrgPolicyConstrained):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint": "an organization policy constraint is blocking this. This is a deliberate setting in the " +
				"customer's organization, not a missing permission — it has to be relaxed for this scope, or " +
				"the scope onboarded differently.",
			"fault": "constrained",
		}

	case errors.Is(err, services.ErrScopeNotReadable):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint": "confirm the reader service account has a role grant at this exact scope, and that " +
				"scope_kind/scope_id match what setup-reader.sh was run against",
			"fault": "customer_account",
		}

	case errors.Is(err, gcp.ErrWIFPoolMissing):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint": "confirm the workload identity pool/provider setup-reader.sh created still exists, " +
				"and that you pasted the exact provider resource name it printed at the end",
			"fault": "customer_account",
		}

	case errors.Is(err, gcp.ErrWIFIssuerUnreachable):
		// Deliberately distinct from ErrWIFPoolMissing above — the pasted
		// value already passed AuthSec's own cross-check before this call
		// was ever attempted; re-pasting it fixes nothing here.
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint": "the Workload Identity Federation issuer this deployment is configured with isn't reachable " +
				"from Google Cloud right now — if this is a local development tunnel, confirm it's still running " +
				"and matches what the WIF provider was created with",
			"fault": "authsec",
		}

	case errors.Is(err, gcp.ErrKeyInvalid):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "re-download the service account key JSON file from GCP and upload it again, unmodified",
			"fault": "customer_account",
		}

	case errors.Is(err, gcp.ErrPermissionDenied):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "grant the reader service account the roles setup-reader.sh requested, at the scope you are connecting",
			"fault": "customer_account",
		}

	case errors.Is(err, gcp.ErrInvalidGrant):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "the credential exchange was rejected by GCP; re-run setup-reader.sh and try again",
			"fault": "gcp",
		}

	case errors.Is(err, gcp.ErrWIFIssuerNotHTTPS):
		// Never the customer's fault, never GCP's fault — this deployment's
		// own WIF issuer configuration. Deliberately does not name the
		// actual issuer value (may be http://localhost:7001 in dev) in a
		// customer-facing response; that detail belongs in server logs, not
		// here.
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "use the JSON key authentication method instead, or contact an administrator about Workload Identity Federation for this deployment",
			"fault": "authsec",
		}
	}
	// Everything left is caller-supplied input the service refused before any
	// GCP call, or an AuthSec-side construction failure. 400 with the message
	// as written for the former; the service layer only returns the latter for
	// genuine misconfiguration (e.g. no issuer configured), which is rare
	// enough not to warrant its own mapped code here.
	return http.StatusBadRequest, gin.H{"error": err.Error()}
}
