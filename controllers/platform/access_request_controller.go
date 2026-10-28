package platform

import (
	"errors"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
)

// AccessRequestController serves the access-request surface under /api/iga/v2.
//
// An access request is the first half of the lease flow: a principal asks for
// time-bounded access, a reviewer approves or denies it, and approval materialises
// a lease. The request itself is never the grant; the lease is.
//
// Batch 15 extensions:
//   - Approve with real AuthNull challenge verification (not mock).
//   - Verify reviewer authorization server-side.
//   - Bind approval to exact scope (escalation ref, operation, policy revision).
type AccessRequestController struct {
	svc       *services.AccessLeaseService
	authNull  *services.AuthNullVerificationService
	escalation *services.EscalationService
}

// NewAccessRequestController constructs the controller.
func NewAccessRequestController(svc *services.AccessLeaseService) *AccessRequestController {
	return &AccessRequestController{svc: svc}
}

// SetAuthNullVerification attaches the AuthNull verification service for real
// challenge verification. When nil, the controller falls back to the pre-Batch-15
// approval flow without MFA verification.
func (ctl *AccessRequestController) SetAuthNullVerification(authNull *services.AuthNullVerificationService) {
	if ctl != nil {
		ctl.authNull = authNull
	}
}

// SetEscalationService attaches the escalation service for policy-configured
// escalation enforcement on approvals.
func (ctl *AccessRequestController) SetEscalationService(esc *services.EscalationService) {
	if ctl != nil {
		ctl.escalation = esc
	}
}

// workspace resolves the caller's workspace from the token. Never from the body.
func (ctl *AccessRequestController) workspace(c *gin.Context) (string, bool) {
	raw := c.GetString("workspace_id")
	if raw == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return "", false
	}
	return raw, true
}

// accessRequestError maps a service error to the right HTTP status.
func accessRequestError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrAccessRequestNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
	case errors.Is(err, services.ErrAccessRequestState):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, services.ErrAccessRequestInvalid):
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
	case errors.Is(err, services.ErrEscalationSelfApproval),
		errors.Is(err, services.ErrAuthNullSelfApproval):
		c.JSON(http.StatusForbidden, gin.H{"error": "self_approval_denied"})
	case errors.Is(err, services.ErrEscalationMFARequired),
		errors.Is(err, services.ErrAuthNullMockInProduction):
		c.JSON(http.StatusForbidden, gin.H{"error": "mfa_required"})
	case errors.Is(err, services.ErrAuthNullChallengeNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "challenge_not_found"})
	case errors.Is(err, services.ErrAuthNullChallengeExpired):
		c.JSON(http.StatusGone, gin.H{"error": "challenge_expired"})
	case errors.Is(err, services.ErrAuthNullChallengeReplayed):
		c.JSON(http.StatusConflict, gin.H{"error": "challenge_replayed"})
	case errors.Is(err, services.ErrAuthNullOperationChanged):
		c.JSON(http.StatusConflict, gin.H{"error": "operation_changed"})
	case errors.Is(err, services.ErrAuthNullFreshnessFailed):
		c.JSON(http.StatusForbidden, gin.H{"error": "stale_mfa"})
	case errors.Is(err, services.ErrAuthNullVerificationFailed):
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	case errors.Is(err, services.ErrEscalationConfigNotFound):
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "escalation_config_not_found"})
	case errors.Is(err, services.ErrEscalationConfigDisabled):
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "escalation_config_disabled"})
	case errors.Is(err, services.ErrEscalationPolicyRevision):
		c.JSON(http.StatusConflict, gin.H{"error": "policy_revision_changed"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal"})
	}
}

// CreateAccessRequest handles POST /api/iga/v2/access-requests.
func (ctl *AccessRequestController) CreateAccessRequest(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	var body services.CreateAccessRequestInput
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	out, err := ctl.svc.CreateAccessRequest(c.Request.Context(), ws, body)
	if err != nil {
		accessRequestError(c, err)
		return
	}
	c.JSON(http.StatusCreated, out)
}

// GetAccessRequest handles GET /api/iga/v2/access-requests/:id.
func (ctl *AccessRequestController) GetAccessRequest(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}
	out, err := ctl.svc.GetAccessRequest(c.Request.Context(), ws, id)
	if err != nil {
		accessRequestError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// approveBody is the request body for the approve endpoint. Batch 15 extends
// the original optional-reason body with AuthNull challenge verification fields
// and exact scope binding.
type approveBody struct {
	Reason         string `json:"reason"`
	ChallengeID    string `json:"challenge_id,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
	RequestHash    string `json:"request_hash,omitempty"`
	Signature      string `json:"signature,omitempty"`
	Assurance      string `json:"assurance,omitempty"`
	AuthTime       *time.Time `json:"auth_time,omitempty"`
	EscalationRef  string `json:"escalation_ref,omitempty"`
	PolicyRevision string `json:"policy_revision,omitempty"`
	OperationScope string `json:"operation_scope,omitempty"`
}

// ApproveAccessRequest handles POST /api/iga/v2/access-requests/:id/approve.
//
// Batch 15: Extended with real AuthNull challenge verification, reviewer
// authorization, and exact scope binding. When the AuthNull verification
// service is wired, the controller verifies the challenge before approving.
// When the escalation service is wired, it enforces self-approval and MFA
// rules from the policy escalation configuration.
func (ctl *AccessRequestController) ApproveAccessRequest(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}
	var body approveBody
	_ = c.ShouldBindJSON(&body) // body fields are optional for backward compat

	decidedBy := c.GetString("client_id")
	mfaVerified := false

	// --- Batch 15: Real AuthNull challenge verification ---
	if ctl.authNull != nil && body.ChallengeID != "" {
		// Verify the reviewer's identity against the token.
		reviewerID := c.GetString("user_id")
		if reviewerID == "" {
			reviewerID = decidedBy
		}

		// Determine auth_time.
		authTime := time.Now().UTC()
		if body.AuthTime != nil {
			authTime = *body.AuthTime
		}

		// Verify the AuthNull challenge.
		verifyResult, err := ctl.authNull.VerifyChallenge(c.Request.Context(), ws, services.VerifyChallengeInput{
			ChallengeID: body.ChallengeID,
			VerifierID:  reviewerID,
			RequestHash: body.RequestHash,
			Assurance:   body.Assurance,
			AuthTime:    authTime,
			Signature:   body.Signature,
			Nonce:       body.Nonce,
		})
		if err != nil {
			accessRequestError(c, err)
			return
		}

		// Bind the verified challenge to this access request.
		req, err := ctl.svc.GetAccessRequest(c.Request.Context(), ws, id)
		if err != nil {
			accessRequestError(c, err)
			return
		}

		if err := ctl.authNull.BindToRequest(c.Request.Context(), ws, services.BindChallengeInput{
			ChallengeID:     body.ChallengeID,
			AccessRequestID: id,
			RequesterID:     req.RequesterID,
		}); err != nil {
			accessRequestError(c, err)
			return
		}

		mfaVerified = verifyResult.Fresh
	}

	// Approve with escalation-aware config.
	lease, err := ctl.svc.ApproveAccessRequestWithConfig(c.Request.Context(), ws, id, services.ApproveAccessRequestInput{
		DecidedBy:      decidedBy,
		Reason:         body.Reason,
		EscalationRef:  body.EscalationRef,
		MFAVerified:    mfaVerified,
		ChallengeID:    body.ChallengeID,
		PolicyRevision: body.PolicyRevision,
		OperationScope: body.OperationScope,
	})
	if err != nil {
		accessRequestError(c, err)
		return
	}
	c.JSON(http.StatusOK, lease)
}

// DenyAccessRequest handles POST /api/iga/v2/access-requests/:id/deny.
func (ctl *AccessRequestController) DenyAccessRequest(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)

	decidedBy := c.GetString("client_id")
	if err := ctl.svc.DenyAccessRequest(c.Request.Context(), ws, id, decidedBy, body.Reason); err != nil {
		accessRequestError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "denied"})
}

// CancelAccessRequest handles POST /api/iga/v2/access-requests/:id/cancel.
func (ctl *AccessRequestController) CancelAccessRequest(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}
	if err := ctl.svc.CancelAccessRequest(c.Request.Context(), ws, id); err != nil {
		accessRequestError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "cancelled"})
}
