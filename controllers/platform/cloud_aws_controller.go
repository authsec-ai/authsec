package platform

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CloudAWSController is AWS onboarding: the first step of AWS cloud discovery
// and the only one that touches a customer credential.
//
// It lives under /authsec/discovery/aws/* alongside the Kubernetes and GitHub
// channels, not under /connectors. The connector broker is the action
// framework; discovery must not depend on it, which is the same boundary the
// GitHub channel already keeps.
//
// Nothing here discovers anything. It establishes the read-only connection and
// records the cloud_connector row that IAM identity discovery, permissions,
// Bedrock, activity and classification all resolve against.
type CloudAWSController struct {
	db *gorm.DB

	// svc, when set, is the onboarding service every handler uses instead of
	// one built from VAULT_ADDR/VAULT_TOKEN -- the seam that lets the routes be
	// driven through gin with fake AWS and a memory vault.
	svc *services.AWSOnboardingService

	// cursors signs the run-history cursor (IGA_CURSOR_SECRET, as the graph
	// lists do), built on first use.
	cursorsOnce sync.Once
	cursors     *igaread.Reader
}

// NewCloudAWSController constructs the controller.
func NewCloudAWSController(db *gorm.DB) *CloudAWSController {
	return &CloudAWSController{db: db}
}

// WithOnboardingService makes every handler use svc. Tests use it; production
// builds the service per request from the environment.
func (ctl *CloudAWSController) WithOnboardingService(svc *services.AWSOnboardingService) *CloudAWSController {
	ctl.svc = svc
	return ctl
}

// authsecPrincipalEnv names the AuthSec AWS principal a customer's trust policy
// must allow. Deployment configuration, not per-workspace: one AuthSec identity
// assumes every customer role, and the ExternalId is what separates them.
const authsecPrincipalEnv = "AUTHSEC_AWS_DISCOVERY_PRINCIPAL_ARN"

// service builds the onboarding service, or explains why it cannot.
func (ctl *CloudAWSController) service() (*services.AWSOnboardingService, error) {
	if ctl.svc != nil {
		return ctl.svc, nil
	}
	addr, token := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		// The ExternalId is a shared secret with the customer's trust policy.
		// Without somewhere safe to put it, refuse plainly here rather than fail
		// later with a confusing 500.
		return nil, errors.New("VAULT_ADDR/VAULT_TOKEN not configured; the AWS external id cannot be stored")
	}
	vc, err := vault.NewClient(addr, token)
	if err != nil {
		return nil, err
	}
	return services.NewAWSOnboardingService(ctl.db, vc), nil
}

/* ------------------------------ onboarding kit ---------------------------- */

// GetOnboardingPackage handles GET /authsec/discovery/aws/onboarding.
//
// Returns everything the customer needs to create the read-only role: a freshly
// minted ExternalId, the AuthSec principal their trust policy must name, the
// CloudFormation template itself, and the permission list in a form a security
// reviewer can evaluate.
//
// The ExternalId is minted per call and is NOT stored here. It carries a
// signature over the workspace it was issued to, so it is only usable by this
// tenant, and it becomes real only when it comes back with a role ARN that can
// actually be assumed. A console must therefore hold the value it displayed and
// post that same one back — re-fetching this endpoint mid-flow issues a
// different id and the stack the customer just deployed will not match.
//
// "Not configured" is a 200 with configured:false, not an error: the caller has
// to tell a missing deployment setting apart from a failure, and they lead to
// opposite UI.
func (ctl *CloudAWSController) GetOnboardingPackage(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	principal := strings.TrimSpace(os.Getenv(authsecPrincipalEnv))
	if principal == "" {
		c.JSON(http.StatusOK, gin.H{
			"configured": false,
			"error": "this AuthSec deployment has no AWS discovery principal configured; " +
				"set " + authsecPrincipalEnv + " to the AuthSec IAM principal customers should trust",
		})
		return
	}

	externalID, err := services.MintExternalID(workspaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"configured": true,
		"data": gin.H{
			"external_id":           externalID,
			"authsec_principal_arn": principal,
			"template_format":       "cloudformation-yaml",
			"template_version":      awsdiscovery.TemplateVersion,
			"template":              awsdiscovery.CloudFormationTemplate,
			"stack_parameters": gin.H{
				"AuthSecPrincipalArn": principal,
				"ExternalId":          externalID,
			},
			"baseline_managed_policy": awsdiscovery.BaselineManagedPolicy,
			"additional_permissions":  awsdiscovery.AdditionalPermissions(),
			"hard_denies":             awsdiscovery.HardDenies(),
		},
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"next":  "POST /authsec/discovery/aws/connectors with the stack's RoleArn output and this external_id",
			"note": "the external id is a secret and is minted per request; display the one returned here " +
				"and post that same value back, do not re-fetch between the two steps",
			"read_only": "the stack creates one IAM role and nothing else; no software is installed in the account",
		},
	})
}

/* -------------------------------- connectors ------------------------------ */

// CreateConnector handles POST /authsec/discovery/aws/connectors.
//
// Assumes the role, reads the account id out of the resulting session, and
// records it. The account is taken from AWS rather than from the request body
// on purpose: it is the connector's identity, and a caller-supplied one could
// disagree with the role it actually points at.
func (ctl *CloudAWSController) CreateConnector(c *gin.Context) {
	workspaceID, actor, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var in services.AWSOnboardInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	svc, err := ctl.service()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	connector, created, err := svc.Onboard(c.Request.Context(), workspaceID, in, actor)
	if err != nil {
		// The client went away before the probe finished (browser fetch
		// timeout, closed tab). Answering 400 here would log a misleading
		// client error for a request AuthSec failed to finish in time; 499
		// marks it as aborted. The response is usually undeliverable — this
		// status exists so the access log tells aborts apart from real 400s.
		if c.Request.Context().Err() != nil {
			c.JSON(499, gin.H{
				"error":   "request aborted by the client before the AWS probe completed",
				"aborted": true,
			})
			return
		}
		status, body := mapAWSOnboardingError(err)
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
		"message": awsOnboardMessage(created),
		"data":    connector,
		"meta": gin.H{
			"as_of":    time.Now().UTC(),
			"verified": connector.VerifiedAt,
			"note": "the connection is proven but nothing has been discovered yet; " +
				"IAM identity discovery runs as a separate step",
		},
	})
}

func awsOnboardMessage(created bool) string {
	if created {
		return "AWS account connected"
	}
	// Re-onboarding an account already connected updates the same row. Say so,
	// so an operator who expected a second connector is not left wondering.
	return "AWS account reconnected; the existing connector was updated in place"
}

// ListConnectors handles GET /authsec/discovery/aws/connectors.
func (ctl *CloudAWSController) ListConnectors(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	rows, err := repositories.NewCloudConnectorRepository(ctl.db).
		List(workspaceID, models.CloudProviderAWS)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{"as_of": time.Now().UTC(), "count": len(rows)},
	})
}

// GetConnector handles GET /authsec/discovery/aws/connectors/:id.
func (ctl *CloudAWSController) GetConnector(c *gin.Context) {
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
	row, err := repositories.NewCloudConnectorRepository(ctl.db).Get(workspaceID, id)
	if err != nil {
		status, body := mapAWSOnboardingError(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": row,
		"meta": gin.H{"as_of": time.Now().UTC()},
	})
}

// VerifyConnector handles POST /authsec/discovery/aws/connectors/:id/verify.
//
// Re-proves an existing connection. A failure is recorded on the row and
// returned; it never removes anything the connector previously discovered,
// because a connection that cannot be used right now says nothing about whether
// what it found still exists.
func (ctl *CloudAWSController) VerifyConnector(c *gin.Context) {
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
	svc, err := ctl.service()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	connector, verr := svc.VerifyConnector(c.Request.Context(), workspaceID, id)
	if verr != nil {
		if c.Request.Context().Err() != nil {
			// Same abort distinction as CreateConnector: never log a client
			// going away as a 400 against the connector.
			c.JSON(499, gin.H{
				"error":   "request aborted by the client before the AWS probe completed",
				"aborted": true,
			})
			return
		}
		status, body := mapAWSOnboardingError(verr)
		// The row, when we have it, travels with the error: the console needs to
		// render the connector's new error state, not just a toast.
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

// RevokeConnector handles DELETE /authsec/discovery/aws/connectors/:id.
//
// Named for what it does, not for the HTTP verb it answers to: this revokes
// the connection rather than deleting the connector row or anything it
// discovered. See CloudConnectorRepository.Revoke for why.
func (ctl *CloudAWSController) RevokeConnector(c *gin.Context) {
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
	svc, err := ctl.service()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	if err := svc.RevokeConnector(workspaceID, id); err != nil {
		status, body := mapAWSOnboardingError(err)
		c.JSON(status, body)
		return
	}
	auditAdminMutation(c, workspaceID.String(), "revoke", "cloud_connector",
		id.String(), http.StatusOK, nil, nil)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "AWS connector revoked and its stored external id purged",
		"meta": gin.H{
			"note": "the read-only role still exists in the customer account; " +
				"deleting the CloudFormation stack is the customer's step. " +
				"Everything already discovered through this connector (identities, " +
				"permissions, resources) is kept, unchanged, for audit -- it is not " +
				"deleted by revoking. Re-onboarding the same account reactivates " +
				"this same connector rather than creating a second one.",
		},
	})
}

/* ------------------------------ identity scan ----------------------------- */

// ScanIAM handles POST /authsec/discovery/aws/connectors/:id/scan.
//
// Reads the IAM identity foundation — roles, users, access keys and the policy
// documents attached to each — and writes cloud_identity and cloud_secret.
//
// The scan runs in the background and this returns 202. A full IAM read on a
// large account is thousands of calls under a retrying client, which outlives
// any sensible proxy timeout; running it inline is the mistake migration 007
// documents fixing for the GitHub channel, and there is no reason to repeat it
// here.
//
// The durable record is the connector's own coverage blob, written as the scan
// proceeds — so the report survives a page refresh, and poll is just a GET of
// the connector.
func (ctl *CloudAWSController) ScanIAM(c *gin.Context) {
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
	svc, err := ctl.service()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	// Validate up front what can be validated, so an unusable connector is a
	// 4xx here rather than a failed scan someone has to go and find.
	connector, err := svc.Connector(workspaceID, id)
	if err != nil {
		status, body := mapAWSOnboardingError(err)
		c.JSON(status, body)
		return
	}
	if connector.Status == models.CloudConnectorRevoked {
		c.JSON(http.StatusConflict, gin.H{
			"error": "this connection was revoked; re-onboard the account before scanning",
		})
		return
	}

	// ENQUEUE, do not execute.
	//
	// This used to start a `go func()` and return 202. Three things followed,
	// all customer-visible: a backend restart lost the run with nothing
	// recording it had been in flight; two requests raced and whichever
	// finished last reconciled away the other's rows; and a worker everyone had
	// given up on could still publish results older than the run replacing it.
	//
	// A row in cloud_scan_run fixes all three, because it gives the scan an
	// owner, a lease and a fence token. The worker picks it up.
	run, err := repositories.NewCloudScanRunRepository(ctl.db).
		Enqueue(workspaceID, id, "manual")
	if err != nil {
		if errors.Is(err, repositories.ErrScanAlreadyLive) {
			// Not an error the operator caused, and not something a retry
			// improves: report the run already in flight so the console can
			// follow it instead of queueing a duplicate.
			live, _ := repositories.NewCloudScanRunRepository(ctl.db).Latest(workspaceID, id)
			body := gin.H{
				"error": "a scan is already queued or running for this connection",
			}
			if live != nil {
				body["meta"] = gin.H{"run_id": live.ID, "status": live.Status,
					"requested_at": live.RequestedAt}
			}
			c.JSON(http.StatusConflict, body)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "scan", "cloud_connector",
		id.String(), http.StatusAccepted, nil, gin.H{"surface": "iam", "actor": actor})

	c.JSON(http.StatusAccepted, gin.H{
		"success": true,
		"message": "scan queued",
		"meta": gin.H{
			"as_of":  time.Now().UTC(),
			"run_id": run.ID,
			"status": run.Status,
			"poll":   "/authsec/discovery/aws/scan-runs/" + run.ID.String(),
			"note": "the scan is QUEUED, not finished. Poll the run and wait for " +
				"status 'published' -- that is the only state in which the " +
				"inventory reflects this pass. A connector whose coverage.status " +
				"stops saying 'running' has not necessarily finished: coverage is " +
				"written after publication. 'partial' coverage means at least one " +
				"surface was denied or throttled and the inventory is not an " +
				"all-clear.",
			"writes": []string{
				"cloud_identity", "cloud_secret",
				"cloud_assume_edge", "cloud_permission", "cloud_resource",
				"cloud_workload", "cloud_usage",
			},
		},
	})
}

// ListIdentities handles GET /authsec/discovery/aws/identities.
func (ctl *CloudAWSController) ListIdentities(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	filter := repositories.CloudIdentityFilter{
		Kind:   c.Query("kind"),
		Limit:  atoiDefault(c.Query("limit"), 100),
		Offset: atoiDefault(c.Query("offset"), 0),
	}
	if raw := c.Query("connector_id"); raw != "" {
		cid, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector_id"})
			return
		}
		filter.ConnectorID = &cid
	}

	rows, total, err := repositories.NewCloudIdentityRepository(ctl.db).
		ListIdentities(workspaceID, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"as_of": time.Now().UTC(), "total": total,
			"limit": filter.Limit, "offset": filter.Offset,
			"note": "these are candidate identities, not agents. Nothing here asserts " +
				"that an identity belongs to an AI agent; classification is a later step",
		},
	})
}

// ListSecrets handles GET /authsec/discovery/aws/secrets.
//
// Metadata only. There is no column behind this endpoint that could hold a
// secret value, so there is nothing here to redact.
func (ctl *CloudAWSController) ListSecrets(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	identityID, err := parseOptionalUUID(c.Query("identity_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity_id"})
		return
	}
	connectorID, err := parseOptionalUUID(c.Query("connector_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector_id"})
		return
	}
	filter := repositories.CloudSecretFilter{
		IdentityID:  identityID,
		ConnectorID: connectorID,
		Limit:       atoiDefault(c.Query("limit"), 100),
		Offset:      atoiDefault(c.Query("offset"), 0),
	}

	rows, total, err := repositories.NewCloudIdentityRepository(ctl.db).ListSecrets(workspaceID, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"as_of": time.Now().UTC(), "total": total,
			"limit": filter.Limit, "offset": filter.Offset,
			"ordering": "oldest first — age is the finding",
			"note":     "key identifiers and dates only; no secret value is read or stored",
		},
	})
}

/* ------------------------- permissions and resources ----------------------- */

// ListAssumeEdges handles GET /authsec/discovery/aws/assume-edges.
//
// Optionally scoped to one identity_id, which is the console's actual use
// case: "who may become this role" rendered on the identity's own detail page.
func (ctl *CloudAWSController) ListAssumeEdges(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	identityID, err := parseOptionalUUID(c.Query("identity_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity_id"})
		return
	}
	connectorID, err := parseOptionalUUID(c.Query("connector_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector_id"})
		return
	}
	filter := repositories.CloudPermissionFilter{
		IdentityID:  identityID,
		ConnectorID: connectorID,
		Limit:       atoiDefault(c.Query("limit"), 100),
		Offset:      atoiDefault(c.Query("offset"), 0),
	}
	rows, total, err := repositories.NewCloudPermissionRepository(ctl.db).ListAssumeEdges(workspaceID, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"as_of": time.Now().UTC(), "total": total,
			"limit": filter.Limit, "offset": filter.Offset,
			"note": "who may assume this identity, and how. subject_kind=identity or " +
				"external_account means this role can be assumed from outside AuthSec's own view",
		},
	})
}

// ListPermissions handles GET /authsec/discovery/aws/permissions.
func (ctl *CloudAWSController) ListPermissions(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	identityID, err := parseOptionalUUID(c.Query("identity_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity_id"})
		return
	}
	connectorID, err := parseOptionalUUID(c.Query("connector_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector_id"})
		return
	}
	filter := repositories.CloudPermissionFilter{
		IdentityID:  identityID,
		ConnectorID: connectorID,
		Limit:       atoiDefault(c.Query("limit"), 100),
		Offset:      atoiDefault(c.Query("offset"), 0),
	}
	rows, total, err := repositories.NewCloudPermissionRepository(ctl.db).ListPermissions(workspaceID, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"as_of": time.Now().UTC(), "total": total,
			"limit": filter.Limit, "offset": filter.Offset,
			"note": "derivation=granted only -- these are policy statements, not computed " +
				"effective access. scope_kind=account_wide or prefix means resource_id is " +
				"deliberately null, not missing",
		},
	})
}

// ListResources handles GET /authsec/discovery/aws/resources.
func (ctl *CloudAWSController) ListResources(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	connectorID, err := parseOptionalUUID(c.Query("connector_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector_id"})
		return
	}
	filter := repositories.CloudPermissionFilter{
		ConnectorID: connectorID,
		Limit:       atoiDefault(c.Query("limit"), 100),
		Offset:      atoiDefault(c.Query("offset"), 0),
	}
	rows, total, err := repositories.NewCloudPermissionRepository(ctl.db).ListResources(workspaceID, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"as_of": time.Now().UTC(), "total": total,
			"limit": filter.Limit, "offset": filter.Offset,
			"note": "a resource exists here only because a permission statement named it; " +
				"this is not an inventory of everything in the account",
		},
	})
}

// ListWorkloads handles GET /authsec/discovery/aws/workloads.
//
// The compute that runs as a discovered identity. Filterable by identity so a
// console can answer "what actually runs as this role", which is the question
// that makes a role's permissions actionable.
func (ctl *CloudAWSController) ListWorkloads(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	identityID, err := parseOptionalUUID(c.Query("identity_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity_id"})
		return
	}
	connectorID, err := parseOptionalUUID(c.Query("connector_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector_id"})
		return
	}
	filter := repositories.CloudWorkloadFilter{
		IdentityID:  identityID,
		ConnectorID: connectorID,
		Limit:       atoiDefault(c.Query("limit"), 100),
		Offset:      atoiDefault(c.Query("offset"), 0),
	}
	rows, total, err := repositories.NewCloudWorkloadRepository(ctl.db).ListWorkloads(workspaceID, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Unattributed compute is the finding a console should surface, so it is
	// counted here rather than left for the caller to derive. Counted over
	// THIS page only -- with total now paginated, a caller wanting the
	// unattributed count across every workload must page through and sum, the
	// same as any other cross-page aggregate.
	unattributed := 0
	byKind := map[string]int{}
	for _, w := range rows {
		byKind[w.RuntimeKind]++
		if w.IdentityID == nil {
			unattributed++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"as_of": time.Now().UTC(), "total": total,
			"limit": filter.Limit, "offset": filter.Offset,
			"by_runtime_kind": byKind,
			"unattributed":    unattributed,
			"note": "a workload is compute that RUNS AS an identity, not an identity itself. " +
				"identity_id null means the role it names was not discovered -- compute " +
				"nobody can attribute, which is a finding rather than missing data. " +
				"Whether a workload is an agent is a separate judgement this table does not make. " +
				"by_runtime_kind and unattributed are counted over this page only, not the total.",
		},
	})
}

// ListUsage handles GET /authsec/discovery/aws/usage.
//
// Whether an identity actually exercised a service, as opposed to merely being
// permitted to.
func (ctl *CloudAWSController) ListUsage(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	identityID, err := parseOptionalUUID(c.Query("identity_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity_id"})
		return
	}
	connectorID, err := parseOptionalUUID(c.Query("connector_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector_id"})
		return
	}
	filter := repositories.CloudWorkloadFilter{
		IdentityID:  identityID,
		ConnectorID: connectorID,
		Limit:       atoiDefault(c.Query("limit"), 100),
		Offset:      atoiDefault(c.Query("offset"), 0),
	}
	rows, total, err := repositories.NewCloudWorkloadRepository(ctl.db).ListUsage(workspaceID, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// A null last_used_at is the actionable row -- the service this identity is
	// permitted to use and never has. Counted over this page only, same
	// caveat as ListWorkloads' unattributed count.
	neverUsed := 0
	for _, u := range rows {
		if u.LastUsedAt == nil {
			neverUsed++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"as_of": time.Now().UTC(), "total": total,
			"limit": filter.Limit, "offset": filter.Offset,
			"never_accessed": neverUsed,
			"note": "the grain is one row per (identity, service) because that is the grain " +
				"AWS reports -- it can say 'never touched S3', not 'used GetObject but " +
				"never PutObject'. last_used_at null means AWS reports the service was " +
				"never accessed in its tracking window; a service that could not be read " +
				"produces no row at all",
		},
	})
}

// ListObservations handles GET /authsec/discovery/aws/observations.
//
// The read path for evidence: why a cloud_* row exists, or -- for a
// subject-less fact like an AgentCore Workload Identity -- what was observed
// even though nothing in inventory names it. Filterable by exactly one
// subject (identity_id, permission_id, resource_id or workload_id) and by
// source_api, which is how CloudTrail activity, credential-report facts and
// resource-policy denies are told apart from each other and from everything
// else a scan recorded against the same subject.
//
// No connector_id filter: an observation already carries connector_id, but a
// caller asking "why do I believe this identity/resource/workload" has
// already picked the row and therefore already knows which connector it
// came from. Adding the filter would duplicate what the subject filter
// already narrows to.
func (ctl *CloudAWSController) ListObservations(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	identityID, err := parseOptionalUUID(c.Query("identity_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity_id"})
		return
	}
	permissionID, err := parseOptionalUUID(c.Query("permission_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid permission_id"})
		return
	}
	resourceID, err := parseOptionalUUID(c.Query("resource_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid resource_id"})
		return
	}
	workloadID, err := parseOptionalUUID(c.Query("workload_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workload_id"})
		return
	}
	filter := repositories.CloudObservationFilter{
		IdentityID:   identityID,
		PermissionID: permissionID,
		ResourceID:   resourceID,
		WorkloadID:   workloadID,
		SourceAPI:    c.Query("source_api"),
		Limit:        atoiDefault(c.Query("limit"), 100),
		Offset:       atoiDefault(c.Query("offset"), 0),
	}
	rows, total, err := repositories.NewCloudObservationRepository(ctl.db).ListObservations(workspaceID, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"as_of": time.Now().UTC(), "total": total,
			"limit": filter.Limit, "offset": filter.Offset,
			"note": "sanitized_facts is what AWS said, after redaction -- never a raw " +
				"response, and never a secret value. A row with every subject column " +
				"null is not an error: it is evidence with no inventory row to attach " +
				"to, such as an AgentCore Workload Identity.",
		},
	})
}

func parseOptionalUUID(raw string) (*uuid.UUID, error) {
	if raw == "" {
		return nil, nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func atoiDefault(raw string, def int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func (ctl *CloudAWSController) workspaceAndActor(c *gin.Context) (uuid.UUID, string, error) {
	return workspaceAndActorFrom(c)
}

/* ------------------------------ error mapping ----------------------------- */

// mapAWSOnboardingError turns a service error into a status and a body that
// tells the operator whose problem it is.
//
// The distinction is the point. "AWS refused the assume" is something the
// customer fixes in their own account and must not read as an AuthSec outage;
// "AuthSec has no AWS credentials" is the opposite and must not be shown to a
// customer as a mistake they made.
func mapAWSOnboardingError(err error) (int, gin.H) {
	switch {
	case errors.Is(err, repositories.ErrCloudConnectorNotFound):
		return http.StatusNotFound, gin.H{"error": "connector not found"}

	case errors.Is(err, services.ErrExternalIDNotIssued):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint": "start onboarding again from this workspace and use the external id it returns; " +
				"an external id issued to another workspace cannot be used here",
		}

	case errors.Is(err, services.ErrAWSProbeTimeout):
		return http.StatusGatewayTimeout, gin.H{
			"error": err.Error(),
			"hint": "AuthSec's assume-role probe got no answer from AWS in time; " +
				"try again, and if it persists check that this deployment's network path to STS is healthy",
			"fault": "aws",
		}

	case errors.Is(err, awsdiscovery.ErrNotAssumable):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint": "check three things in the customer account: the stack finished creating, " +
				"the ExternalId in the trust policy matches the one issued, and the trust policy " +
				"names the AuthSec principal shown during onboarding",
			"fault": "customer_account",
		}

	case errors.Is(err, awsdiscovery.ErrThrottled):
		return http.StatusTooManyRequests, gin.H{
			"error": err.Error(),
			"hint":  "AWS throttled the request after retries; try again shortly",
			"fault": "aws",
		}

	case errors.Is(err, awsdiscovery.ErrNoBaseCredentials):
		return http.StatusInternalServerError, gin.H{
			"error": err.Error(),
			"hint": "this is an AuthSec deployment problem, not a customer one: the backend has no " +
				"AWS identity to assume the customer role with",
			"fault": "authsec",
		}
	}
	// Everything left is caller-supplied input the service refused — a malformed
	// role ARN, an unknown region, an empty region list. 400 with the message as
	// written: those messages already name the field.
	return http.StatusBadRequest, gin.H{"error": err.Error()}
}

// GetScanRun handles GET /authsec/discovery/aws/scan-runs/:id.
//
// The console needs one authoritative answer to "is my scan finished?", and the
// connector's coverage is not it: coverage is written AFTER publication, so a
// reader watching coverage sees the previous pass until the moment the new one
// lands. Worse, the old handler returned 202 and the UI treated that as the
// work being underway, then stopped watching when coverage stopped saying
// "running" -- which the premature IAM commit made happen early.
//
// This endpoint reports the run itself. `status = published` is the only state
// in which the inventory reflects the pass.
func (ctl *CloudAWSController) GetScanRun(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	runID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "run id must be a uuid"})
		return
	}

	run, err := repositories.NewCloudScanRunRepository(ctl.db).Get(runID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan run not found"})
		return
	}
	// The workspace comes from the authenticated context, never the URL: a run
	// id from another workspace must read as absent, not as forbidden, so the
	// endpoint cannot be used to test whether an id exists.
	if run.WorkspaceID != workspaceID {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan run not found"})
		return
	}

	// The run gains projection: {status, rev} (§5.3): what became of its
	// projection job, and the revision it published -- null when the run has no
	// job (the switch was off, or it never published).
	projection, err := repositories.NewCloudScanRunRepository(ctl.db).Projection(workspaceID, runID)
	if err != nil {
		log.Printf("[discovery] scan run %s projection: %v", runID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read the run's projection"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": scanRunWithProjection{
			CloudScanRun: *run,
			Projection:   projectionView(projection),
		},
		"meta": gin.H{
			"as_of":    time.Now().UTC(),
			"terminal": run.Terminal(),
			"note": "status 'published' is the only state in which the inventory " +
				"reflects this pass. 'failed' and 'abandoned' are finished too, but " +
				"the inventory still shows the previous pass. Refresh inventory " +
				"views on 'published', not on the 202 that queued the scan.",
		},
	})
}
