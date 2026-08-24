package platform

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GovernanceController serves provisioning and the provenance that explains it.
//
// Every route here is authenticated and permission-gated, unlike the discovery
// ingress. The reasoning that made THAT unauthenticated does not transfer: a sighting
// grants nothing, whereas these endpoints grant and revoke authority.
type GovernanceController struct {
	db    *gorm.DB
	oauth *services.OAuthASService
}

// NewGovernanceController constructs a GovernanceController.
//
// It builds its own OAuthASService rather than taking one, because provisioning needs
// that service's atomic-approve primitive and nothing else in the request path shares
// it — passing one in would add a wiring dependency for a single constructor call.
func NewGovernanceController(db *gorm.DB) *GovernanceController {
	return &GovernanceController{db: db, oauth: services.NewOAuthASService(db)}
}

func (ctl *GovernanceController) provisioning() services.ProvisioningManager {
	return services.NewProvisioningManager(ctl.db, ctl.oauth)
}

func (ctl *GovernanceController) provenance() services.ProvenanceManager {
	return services.NewProvenanceManager(repositories.NewGovernanceRepository(ctl.db))
}

// workspace resolves the caller's workspace from the token. Never from the body — a
// caller must not be able to grant authority in someone else's workspace.
func (ctl *GovernanceController) workspace(c *gin.Context) (uuid.UUID, error) {
	raw := c.GetString("workspace_id")
	if raw == "" {
		return uuid.Nil, errors.New("workspace_id not found in token")
	}
	return uuid.Parse(raw)
}

func (ctl *GovernanceController) actingUser(c *gin.Context) (*uuid.UUID, string) {
	raw, err := middlewares.ResolveUserID(c)
	if err != nil || raw == "" {
		return nil, c.GetString("client_id")
	}
	parsed, perr := uuid.Parse(raw)
	if perr != nil || parsed == uuid.Nil {
		return nil, raw
	}
	label := c.GetString("email")
	if label == "" {
		label = raw
	}
	return &parsed, label
}

/* -------------------------------- requests ------------------------------- */

// ProvisionRequest is the body for POST /authsec/provisioning/agents/:id/provision.
type ProvisionRequest struct {
	ResourceServerID uuid.UUID `json:"resource_server_id" binding:"required"`
	RoleID           uuid.UUID `json:"role_id" binding:"required"`
	Justification    string    `json:"justification,omitempty"`
	Purpose          string    `json:"purpose,omitempty"`
	// ExpiresAt or Duration, not both. Duration is the friendlier form for a console
	// ("15m", "8h"); ExpiresAt is what an automated caller usually has.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Duration  string     `json:"duration,omitempty"`
	// IsStanding requests a permanent grant. Requires a justification — permanent
	// access is the audited exception, not the default.
	IsStanding bool `json:"is_standing,omitempty"`
}

// DeprovisionRequest is the body for POST /authsec/provisioning/agents/:id/deprovision.
type DeprovisionRequest struct {
	Reason string `json:"reason" binding:"required"`
	// Via defaults to 'admin'. Certification, expiry, leaver, and quarantine set their
	// own so the audit trail records which mechanism acted.
	Via string `json:"via,omitempty"`
}

/* ------------------------------- handlers -------------------------------- */

// ProvisionAgent handles POST /authsec/provisioning/agents/:id/provision — the
// transition from "claimed" to "governed principal".
//
// Everything commits together or nothing does (PG-2): identity, the paired entitlement
// anchor, the registration, the role binding with its expiry, the provenance that
// explains it, and the agent's governance status.
func (ctl *GovernanceController) ProvisionAgent(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	agentID, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var req ProvisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	expiresAt := req.ExpiresAt
	if req.Duration != "" {
		if expiresAt != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "provide either expires_at or duration, not both"})
			return
		}
		d, derr := time.ParseDuration(req.Duration)
		if derr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid duration: " + derr.Error()})
			return
		}
		if d <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "duration must be positive"})
			return
		}
		t := time.Now().Add(d)
		expiresAt = &t
	}

	actor, actorLabel := ctl.actingUser(c)
	out, err := ctl.provisioning().Provision(wsID, services.ProvisionInput{
		DiscoveredAgentID: agentID,
		ResourceServerID:  req.ResourceServerID,
		RoleID:            req.RoleID,
		Justification:     req.Justification,
		Purpose:           req.Purpose,
		ExpiresAt:         expiresAt,
		IsStanding:        req.IsStanding,
		ActingUser:        actor,
		ActingUserLabel:   actorLabel,
	})
	if err != nil {
		governanceError(c, err)
		return
	}

	auditAdminMutation(c, wsID.String(), "provision", "discovered_agent",
		agentID.String(), http.StatusCreated, nil, out)
	c.JSON(http.StatusCreated, out)
}

// DeprovisionAgent handles POST /authsec/provisioning/agents/:id/deprovision.
//
// The single revocation path (PG-6). It removes bindings, kills live tokens, revokes
// registrations, disables the anchor, and asserts zero residual — failing rather than
// reporting success if any binding is still resolvable.
func (ctl *GovernanceController) DeprovisionAgent(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	agentID, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var req DeprovisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	via := req.Via
	if via == "" {
		via = "admin"
	}
	actor, _ := ctl.actingUser(c)

	out, err := ctl.provisioning().Deprovision(wsID, services.DeprovisionInput{
		DiscoveredAgentID: &agentID,
		Via:               via,
		Reason:            req.Reason,
		By:                actor,
	})
	if err != nil {
		governanceError(c, err)
		return
	}

	auditAdminMutation(c, wsID.String(), "deprovision", "discovered_agent",
		agentID.String(), http.StatusOK, nil, out)
	c.JSON(http.StatusOK, out)
}

// ListProvenance handles GET /authsec/governance/provenance — the "why does this
// subject have this?" query.
//
// Filter with ?subject_type=&subject_id=&entitlement_type=&origin=&open=true
// &standing=true&lapsed=true&discovered_agent_id=.
func (ctl *GovernanceController) ListProvenance(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	limit, _ := strconv.Atoi(c.Query("limit"))
	offset, _ := strconv.Atoi(c.Query("offset"))

	f := repositories.ProvenanceFilter{
		SubjectType:     c.Query("subject_type"),
		EntitlementType: c.Query("entitlement_type"),
		Origin:          c.Query("origin"),
		OpenOnly:        c.Query("open") == "true",
		StandingOnly:    c.Query("standing") == "true",
		LapsedOnly:      c.Query("lapsed") == "true",
		Limit:           limit,
		Offset:          offset,
	}
	// A malformed uuid filter is ignored rather than fatal: a filter is a narrowing,
	// and a 400 on a stale console bookmark is more surprising than a broad result.
	if raw := c.Query("subject_id"); raw != "" {
		if parsed, perr := uuid.Parse(raw); perr == nil {
			f.SubjectID = &parsed
		}
	}
	if raw := c.Query("discovered_agent_id"); raw != "" {
		if parsed, perr := uuid.Parse(raw); perr == nil {
			f.DiscoveredAgentID = &parsed
		}
	}

	rows, total, err := ctl.provenance().List(wsID, f)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"provenance": rows, "total": total})
}

// GetProvenance handles GET /authsec/governance/provenance/:id.
func (ctl *GovernanceController) GetProvenance(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	out, err := ctl.provenance().Get(wsID, id)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// governanceError maps a service error to the right status.
func governanceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	case errors.Is(err, repositories.ErrProvenanceAlreadyOpen):
		// The entitlement is already granted and already explained. A conflict, not a
		// bad request — retrying the same provision is a legitimate mistake.
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
}

/* ------------------------------ separation of duties --------------------- */

func (ctl *GovernanceController) sod() services.SoDManager {
	return services.NewSoDManager(ctl.db)
}

// ListSoDRules handles GET /authsec/governance/sod/rules.
//
// Returns global (system) rules alongside the workspace's own, because a rule that
// applies to you is one you need to see even if you cannot edit it.
func (ctl *GovernanceController) ListSoDRules(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	rules, err := ctl.sod().ListRules(wsID)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": len(rules)})
}

// ListSoDViolations handles GET /authsec/governance/sod/violations?open=true.
func (ctl *GovernanceController) ListSoDViolations(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	limit, _ := strconv.Atoi(c.Query("limit"))
	offset, _ := strconv.Atoi(c.Query("offset"))

	rows, total, err := ctl.sod().ListViolations(wsID, c.Query("open") == "true", limit, offset)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"violations": rows, "total": total})
}

// ResolveSoDViolationRequest is the body for resolving a violation.
type ResolveSoDViolationRequest struct {
	// Status is 'accepted' (a documented risk acceptance) or 'remediated' (it was
	// actually fixed). The distinction matters to an auditor, so it is not inferred.
	Status string `json:"status" binding:"required"`
	Note   string `json:"note" binding:"required"`
}

// ResolveSoDViolation handles POST /authsec/governance/sod/violations/:id/resolve.
//
// The note is mandatory: an unexplained acceptance is indistinguishable from neglect,
// and this is the record an auditor reads months later.
func (ctl *GovernanceController) ResolveSoDViolation(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var req ResolveSoDViolationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actor, _ := ctl.actingUser(c)
	out, err := ctl.sod().ResolveViolation(wsID, id, req.Status, req.Note, actor)
	if err != nil {
		governanceError(c, err)
		return
	}
	auditAdminMutation(c, wsID.String(), "resolve", "sod_violation", id.String(),
		http.StatusOK, nil, out)
	c.JSON(http.StatusOK, out)
}

// SimulateSoDRequest asks "would this grant conflict?".
type SimulateSoDRequest struct {
	SubjectType string    `json:"subject_type" binding:"required"`
	SubjectID   uuid.UUID `json:"subject_id" binding:"required"`
	// RoleID is the role being contemplated. Omit to evaluate what the subject already
	// holds.
	RoleID *uuid.UUID `json:"role_id,omitempty"`
}

// SimulateSoD handles POST /authsec/governance/sod/simulate.
//
// Read-only, and it records nothing. It exists so a console can warn BEFORE an
// operator submits a grant, rather than surfacing the refusal as an error afterwards —
// a preventive control the user cannot see coming is just a confusing failure.
func (ctl *GovernanceController) SimulateSoD(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req SimulateSoDRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	in := services.SoDCheckInput{SubjectType: req.SubjectType, SubjectID: req.SubjectID}
	if req.RoleID != nil {
		in.AddingRoleID = *req.RoleID
	}
	decision, err := ctl.sod().Check(nil, wsID, in)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, decision)
}

// RunSoDScan handles POST /authsec/governance/sod/scan — an on-demand detective pass,
// for right after writing a new rule rather than waiting for the next tick.
func (ctl *GovernanceController) RunSoDScan(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	res, err := ctl.sod().Scan(wsID)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

/* ------------------------------- certification --------------------------- */

func (ctl *GovernanceController) certify() services.CertifyManager {
	return services.NewCertifyManager(ctl.db, ctl.oauth)
}

// CreateCampaignRequest is the body for POST /authsec/governance/campaigns.
type CreateCampaignRequest struct {
	Name        string                 `json:"name" binding:"required"`
	Description string                 `json:"description,omitempty"`
	Scope       services.CampaignScope `json:"scope,omitempty"`
	DueAt       *time.Time             `json:"due_at,omitempty"`
	// DueIn is the friendlier form ("30d" is not a Go duration, so use "720h").
	DueIn string `json:"due_in,omitempty"`
}

// CreateCampaign handles POST /authsec/governance/campaigns.
//
// An empty scope means the default: standing grants only. That is deliberate — grants
// with an expiry lapse on their own, so reviewing them spends the reviewer's attention
// on access that is about to disappear anyway.
func (ctl *GovernanceController) CreateCampaign(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req CreateCampaignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	dueAt := req.DueAt
	if req.DueIn != "" {
		if dueAt != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "provide either due_at or due_in, not both"})
			return
		}
		d, derr := time.ParseDuration(req.DueIn)
		if derr != nil || d <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid due_in (use a Go duration, e.g. 720h)"})
			return
		}
		t := time.Now().Add(d)
		dueAt = &t
	}

	_, actorLabel := ctl.actingUser(c)
	out, err := ctl.certify().CreateCampaign(wsID, actorLabel, services.CampaignInput{
		Name:        req.Name,
		Description: req.Description,
		Scope:       req.Scope,
		DueAt:       dueAt,
	})
	if err != nil {
		governanceError(c, err)
		return
	}
	auditAdminMutation(c, wsID.String(), "create", "certification_campaign",
		out.ID.String(), http.StatusCreated, nil, out)
	c.JSON(http.StatusCreated, out)
}

// ListCampaigns handles GET /authsec/governance/campaigns.
func (ctl *GovernanceController) ListCampaigns(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	out, err := ctl.certify().ListCampaigns(wsID)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"campaigns": out, "total": len(out)})
}

// GetCampaign handles GET /authsec/governance/campaigns/:id. A closed campaign carries
// its frozen export, which is the artifact an auditor reads.
func (ctl *GovernanceController) GetCampaign(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	out, err := ctl.certify().GetCampaign(wsID, id)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// GenerateCampaign handles POST /authsec/governance/campaigns/:id/generate — turns a
// draft into a reviewable campaign by materialising items with their evidence.
func (ctl *GovernanceController) GenerateCampaign(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	out, err := ctl.certify().Generate(wsID, id)
	if err != nil {
		governanceError(c, err)
		return
	}
	auditAdminMutation(c, wsID.String(), "generate", "certification_campaign",
		id.String(), http.StatusOK, nil, out)
	c.JSON(http.StatusOK, out)
}

// ListCampaignItems handles GET /authsec/governance/campaigns/:id/items.
//
// ?mine=true is the reviewer's own queue; ?pending=true hides what is already decided.
func (ctl *GovernanceController) ListCampaignItems(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	limit, _ := strconv.Atoi(c.Query("limit"))
	offset, _ := strconv.Atoi(c.Query("offset"))
	f := services.ItemFilter{
		PendingOnly: c.Query("pending") == "true",
		Limit:       limit,
		Offset:      offset,
	}
	if c.Query("mine") == "true" {
		actor, _ := ctl.actingUser(c)
		if actor == nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "mine=true needs an authenticated user; a machine principal has no review queue",
			})
			return
		}
		f.ReviewerUserID = actor
	}

	items, total, err := ctl.certify().ListItems(wsID, id, f)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total})
}

// DecideItemRequest is the body for deciding one item.
type DecideItemRequest struct {
	// Decision is keep | revoke | delegate.
	Decision string `json:"decision" binding:"required"`
	// Note is mandatory for 'keep': confirming access without saying why is the rubber
	// stamp certification exists to prevent.
	Note       string     `json:"note,omitempty"`
	DelegateTo *uuid.UUID `json:"delegate_to,omitempty"`
}

// DecideItem handles POST /authsec/governance/campaigns/:id/items/:item/decide.
//
// A 'revoke' executes the standard de-provision path, so a certification revoke has the
// same effect and audit shape as an expiry, a leaver, or an admin revoke (PG-6).
func (ctl *GovernanceController) DecideItem(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	itemID, err := uuid.Parse(c.Param("item"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid item id"})
		return
	}
	var req DecideItemRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actor, _ := ctl.actingUser(c)
	out, err := ctl.certify().Decide(wsID, itemID, services.DecisionInput{
		Decision:   req.Decision,
		Note:       req.Note,
		By:         actor,
		DelegateTo: req.DelegateTo,
	})
	if err != nil {
		governanceError(c, err)
		return
	}
	auditAdminMutation(c, wsID.String(), "decide", "certification_item",
		itemID.String(), http.StatusOK, nil, out)
	c.JSON(http.StatusOK, out)
}

// CloseCampaignRequest is the body for closing a campaign.
type CloseCampaignRequest struct {
	// Force closes with items still undecided. The export records how many, so the gap
	// is IN the artifact rather than hidden by it.
	Force bool `json:"force,omitempty"`
}

// CloseCampaign handles POST /authsec/governance/campaigns/:id/close — freezes the
// export, which is the artifact an auditor reads.
func (ctl *GovernanceController) CloseCampaign(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var req CloseCampaignRequest
	_ = c.ShouldBindJSON(&req) // body optional

	actor, _ := ctl.actingUser(c)
	out, err := ctl.certify().Close(wsID, id, actor, req.Force)
	if err != nil {
		governanceError(c, err)
		return
	}
	auditAdminMutation(c, wsID.String(), "close", "certification_campaign",
		id.String(), http.StatusOK, nil, out)
	c.JSON(http.StatusOK, out)
}

/* --------------------------------- actuation ----------------------------- */

func (ctl *GovernanceController) actuation() services.ActuationManager {
	return services.NewActuationManager(ctl.db)
}

// EnableActuation handles POST /authsec/governance/connectors/:id/actuation.
//
// Mints the per-connector actuation token and returns it ONCE. Only a hash is stored,
// so a leaked database backup yields nothing usable — and re-calling this rotates the
// credential, invalidating the previous one.
func (ctl *GovernanceController) EnableActuation(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token, err := ctl.actuation().EnableActuation(wsID, id)
	if err != nil {
		governanceError(c, err)
		return
	}
	// The token itself is deliberately NOT audited — an audit log that contains working
	// credentials is a credential store.
	auditAdminMutation(c, wsID.String(), "enable_actuation", "discovery_source",
		id.String(), http.StatusOK, nil, gin.H{"actuation_enabled": true})

	c.JSON(http.StatusOK, gin.H{
		"actuation_token": token,
		"note": "Shown once and never stored in plaintext. Install the agent with " +
			"--set roles='{discovery,actuation}' --set actuation.token=<this value>",
	})
}

// ListInstructions handles GET /authsec/governance/instructions?open=true — the
// operator's view of what enforcement is pending or has failed.
func (ctl *GovernanceController) ListInstructions(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	limit, _ := strconv.Atoi(c.Query("limit"))
	offset, _ := strconv.Atoi(c.Query("offset"))

	rows, total, err := ctl.actuation().ListInstructions(wsID, c.Query("open") == "true", limit, offset)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"instructions": rows, "total": total})
}

/* ------------------------- the agent's own surface ----------------------- */

// agentSource authenticates the calling in-cluster agent from its actuation token.
//
// The token determines WHICH connector is calling, so the agent never asserts its own
// cluster — removing the "agent claims to be a different cluster" case entirely.
func (ctl *GovernanceController) agentSource(c *gin.Context) (*models.DiscoverySource, bool) {
	token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	src, err := ctl.actuation().AuthenticateAgent(strings.TrimSpace(token))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return nil, false
	}
	return src, true
}

// LeaseInstructions handles GET /authsec/provisioning/instructions — the agent's poll.
//
// Authenticated by the actuation token, NOT by AuthMiddleware: this caller is a
// workload in a customer cluster, not a console user. Leasing is a mutation (it claims
// work) but is a GET because the agent polls it on a timer and the lease is the
// mechanism, not the intent.
func (ctl *GovernanceController) LeaseInstructions(c *gin.Context) {
	src, ok := ctl.agentSource(c)
	if !ok {
		return
	}
	max, _ := strconv.Atoi(c.Query("max"))
	leasedBy := c.Query("pod")
	if leasedBy == "" {
		leasedBy = "unknown"
	}

	// The lease TTL has to exceed how long an apply can reasonably take, or a slow
	// NetworkPolicy write would have its work reclaimed underneath it.
	items, err := ctl.actuation().Lease(src.ID, leasedBy, max, 2*time.Minute)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"instructions":  items,
		"cluster":       src.ClusterName,
		"lease_seconds": 120,
	})
}

// ReportInstructionRequest is the agent's outcome for one instruction.
type ReportInstructionRequest struct {
	Success bool                   `json:"success"`
	Error   string                 `json:"error,omitempty"`
	Result  map[string]interface{} `json:"result,omitempty"`
}

// ReportInstruction handles POST /authsec/provisioning/instructions/:id/result.
func (ctl *GovernanceController) ReportInstruction(c *gin.Context) {
	src, ok := ctl.agentSource(c)
	if !ok {
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var req ReportInstructionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	out, err := ctl.actuation().Report(src.ID, id, services.ReportInput{
		Success: req.Success,
		Error:   req.Error,
		Result:  req.Result,
	})
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

/* ------------------------------ human lifecycle -------------------------- */

func (ctl *GovernanceController) lifecycle() services.LifecycleManager {
	return services.NewLifecycleManager(ctl.db, ctl.oauth)
}

// CreateBirthrightRequest is the body for POST /authsec/governance/birthrights.
type CreateBirthrightRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description,omitempty"`
	// MatchKind is 'group' (default) or 'all'.
	MatchKind        string     `json:"match_kind,omitempty"`
	MatchGroupID     *uuid.UUID `json:"match_group_id,omitempty"`
	ResourceServerID uuid.UUID  `json:"resource_server_id" binding:"required"`
	RoleID           uuid.UUID  `json:"role_id" binding:"required"`
	// Duration time-boxes the grant ("720h"). Omitting it makes the birthright STANDING
	// for everyone it matches, which requires a justification.
	Duration      string `json:"duration,omitempty"`
	Justification string `json:"justification,omitempty"`
	// OnUnmatch is 'flag' (default) or 'revoke'.
	OnUnmatch string `json:"on_unmatch,omitempty"`
}

// CreateBirthright handles POST /authsec/governance/birthrights.
func (ctl *GovernanceController) CreateBirthright(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req CreateBirthrightRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var duration *time.Duration
	if req.Duration != "" {
		d, derr := time.ParseDuration(req.Duration)
		if derr != nil || d <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid duration (use a Go duration, e.g. 720h)"})
			return
		}
		duration = &d
	}

	_, actorLabel := ctl.actingUser(c)
	out, err := ctl.lifecycle().CreatePolicy(wsID, actorLabel, services.BirthrightInput{
		Name:             req.Name,
		Description:      req.Description,
		MatchKind:        req.MatchKind,
		MatchGroupID:     req.MatchGroupID,
		ResourceServerID: req.ResourceServerID,
		RoleID:           req.RoleID,
		Duration:         duration,
		Justification:    req.Justification,
		OnUnmatch:        req.OnUnmatch,
	})
	if err != nil {
		governanceError(c, err)
		return
	}
	auditAdminMutation(c, wsID.String(), "create", "birthright_policy",
		out.ID.String(), http.StatusCreated, nil, out)
	c.JSON(http.StatusCreated, out)
}

// ListBirthrights handles GET /authsec/governance/birthrights.
func (ctl *GovernanceController) ListBirthrights(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	out, err := ctl.lifecycle().ListPolicies(wsID)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"birthrights": out, "total": len(out)})
}

// DeleteBirthright handles DELETE /authsec/governance/birthrights/:id.
//
// Grants already made are NOT revoked: deleting a policy stops future grants, it is not
// a mass-revocation instruction. They become stale birthrights in the mover queue.
func (ctl *GovernanceController) DeleteBirthright(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := ctl.lifecycle().DeletePolicy(wsID, id); err != nil {
		governanceError(c, err)
		return
	}
	auditAdminMutation(c, wsID.String(), "delete", "birthright_policy",
		id.String(), http.StatusNoContent, nil, nil)
	c.JSON(http.StatusOK, gin.H{
		"deleted": true,
		"note": "existing grants were NOT revoked; they now appear in " +
			"GET /authsec/governance/jml/stale for review",
	})
}

// ReconcileJML handles POST /authsec/governance/jml/reconcile?dry_run=true.
//
// dry_run is the first thing to run against a real workspace: a birthright policy's
// blast radius is an entire group, so seeing the plan before it executes matters.
func (ctl *GovernanceController) ReconcileJML(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	actor, actorLabel := ctl.actingUser(c)
	opts := services.ReconcileOptions{
		DryRun:     c.Query("dry_run") == "true",
		Actor:      actor,
		ActorLabel: actorLabel,
	}

	// A single user can be reconciled directly, for an admin acting on one joiner or
	// leaver without waiting for the sweep.
	if raw := c.Query("user_id"); raw != "" {
		userID, perr := uuid.Parse(raw)
		if perr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
			return
		}
		out, rerr := ctl.lifecycle().ReconcileUser(wsID, userID, opts)
		if rerr != nil {
			governanceError(c, rerr)
			return
		}
		c.JSON(http.StatusOK, out)
		return
	}

	out, err := ctl.lifecycle().Reconcile(wsID, opts)
	if err != nil {
		governanceError(c, err)
		return
	}
	if !opts.DryRun {
		auditAdminMutation(c, wsID.String(), "reconcile", "jml", wsID.String(),
			http.StatusOK, nil, out)
	}
	c.JSON(http.StatusOK, out)
}

// ListStaleBirthrights handles GET /authsec/governance/jml/stale — the mover queue.
func (ctl *GovernanceController) ListStaleBirthrights(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	out, err := ctl.lifecycle().StaleBirthrights(wsID)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"stale": out, "total": len(out)})
}

// ListOrphanedAgents handles GET /authsec/governance/jml/orphans.
//
// Agents whose accountable owner has been deactivated. A report rather than an
// auto-revocation: a person leaving says nothing about whether the workload they
// registered should keep running, and killing production agents because somebody
// changed jobs is its own incident.
func (ctl *GovernanceController) ListOrphanedAgents(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	out, err := ctl.lifecycle().OrphanedAgents(wsID)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"orphaned_agents": out, "total": len(out)})
}

/* ----------------------- IGA estate correlation bridge -------------------- */

// The join between the k8s runtime inventory (discovered_agents) and the
// correlated estate (iga_agents). Proposals are automatic; accepting one is a
// human decision, gated on iga:review to match the other correlation decisions.

func (ctl *GovernanceController) igaBridge() services.IGABridgeManager {
	return services.NewIGABridgeManager(ctl.db)
}

// GetAgentIGALink handles GET /authsec/discovery/agents/:id/iga-link.
// A 200 with a null body means unlinked, which is a normal state and not a 404.
func (ctl *GovernanceController) GetAgentIGALink(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	out, err := ctl.igaBridge().GetLink(wsID, id)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"link": out})
}

// ListIGALinkProposals handles GET /authsec/governance/iga-links?pending=true —
// the reviewer queue of correlations awaiting a decision.
func (ctl *GovernanceController) ListIGALinkProposals(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	limit, _ := strconv.Atoi(c.Query("limit"))
	offset, _ := strconv.Atoi(c.Query("offset"))
	rows, total, err := ctl.igaBridge().ListProposals(wsID, limit, offset)
	if err != nil {
		governanceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"proposals": rows, "total": total})
}

// DecideIGALinkRequest is the body for a correlation decision. ExpectedVersion is
// required, not optional: a reviewer deciding from a stale screen must lose to
// whoever decided first rather than silently overwriting them.
type DecideIGALinkRequest struct {
	Decision        string `json:"decision" binding:"required"`
	ExpectedVersion int64  `json:"expected_version" binding:"required"`
}

// DecideAgentIGALink handles
// POST /authsec/discovery/agents/:id/iga-link/decisions.
func (ctl *GovernanceController) DecideAgentIGALink(c *gin.Context) {
	wsID, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var req DecideIGALinkRequest
	if err = c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actor, _ := ctl.actingUser(c)
	out, err := ctl.igaBridge().Decide(wsID, id, req.Decision, actor, req.ExpectedVersion)
	if err != nil {
		if errors.Is(err, services.ErrStaleLinkVersion) {
			// 409, not 400: the request was well-formed, it just lost a race.
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		governanceError(c, err)
		return
	}

	auditAdminMutation(c, wsID.String(), "decide", "discovered_agent_iga_link",
		id.String(), http.StatusOK, nil, out)
	c.JSON(http.StatusOK, out)
}
