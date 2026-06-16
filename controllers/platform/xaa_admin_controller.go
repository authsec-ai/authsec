package platform

import (
	"net/http"
	"strings"

	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// XAAAdminController is the admin HTTP surface for Cross-App Access seeding.
//
// Two route groups:
//
//	/authsec/xaa/clients               — xaa_client_apps (master)
//	/authsec/applications/:id/xaa-policies — application_xaa_policies (tenant)
//
// All authenticated via the existing admin middleware (JWT). Tenant scope
// resolved from the JWT — admins can only see / mutate XAA rows in their own
// tenant.
type XAAAdminController struct {
	svc *services.XAAAdminService
}

func NewXAAAdminController() *XAAAdminController {
	return &XAAAdminController{svc: services.NewXAAAdminService(nil)}
}

// ── xaa_client_apps endpoints ────────────────────────────────────────────────

// CreateClient handles POST /authsec/xaa/clients.
//
// Body: {client_id, name, display_name?, issuance_mode?, client_secret?}.
// Returns the row plus a one-time `client_secret` field — capture it now,
// it's never shown again (we only persist the bcrypt hash).
func (ctrl *XAAAdminController) CreateClient(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id is not a uuid"})
		return
	}
	var in services.CreateXAAClientInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body: " + err.Error()})
		return
	}
	row, err := ctrl.svc.CreateClient(tenantUUID, in)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, row)
}

func (ctrl *XAAAdminController) ListClients(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id is not a uuid"})
		return
	}
	rows, err := ctrl.svc.ListClients(tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rows)
}

func (ctrl *XAAAdminController) GetClient(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	tenantUUID, _ := uuid.Parse(tenantID)
	clientRowID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	row, err := ctrl.svc.GetClient(tenantUUID, clientRowID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, row)
}

// RotateSecret handles POST /authsec/xaa/clients/:id/rotate-secret. Returns
// the new plaintext secret once.
func (ctrl *XAAAdminController) RotateSecret(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	tenantUUID, _ := uuid.Parse(tenantID)
	clientRowID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	row, err := ctrl.svc.RotateSecret(tenantUUID, clientRowID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, row)
}

func (ctrl *XAAAdminController) DeleteClient(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	tenantUUID, _ := uuid.Parse(tenantID)
	clientRowID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := ctrl.svc.DeleteClient(tenantUUID, clientRowID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// ── application_xaa_policies endpoints ───────────────────────────────────────

func (ctrl *XAAAdminController) ListPolicies(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	applicationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	rows, err := ctrl.svc.ListPolicies(tenantID, applicationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rows)
}

func (ctrl *XAAAdminController) CreatePolicy(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	applicationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	var in services.XAAPolicyInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body: " + err.Error()})
		return
	}
	row, err := ctrl.svc.CreatePolicy(tenantID, applicationID, in)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, row)
}

func (ctrl *XAAAdminController) UpdatePolicy(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	applicationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	policyID, err := uuid.Parse(c.Param("policy_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy_id"})
		return
	}
	var in services.UpdateXAAPolicyInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body: " + err.Error()})
		return
	}
	row, err := ctrl.svc.UpdatePolicy(tenantID, applicationID, policyID, in)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, row)
}

func (ctrl *XAAAdminController) DeletePolicy(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	applicationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	policyID, err := uuid.Parse(c.Param("policy_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy_id"})
		return
	}
	if err := ctrl.svc.DeletePolicy(tenantID, applicationID, policyID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}
