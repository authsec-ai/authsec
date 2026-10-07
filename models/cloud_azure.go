package models

import (
	"encoding/json"
	"time"
)

/* ------------------------- Azure connector attrs ---------------------------

   Azure joins the shared cloud_connector table with the discipline AWS and
   GCP established: no Azure-specific column on a shared table, one typed
   provider struct serialized into the existing attrs jsonb.

   One Entra tenant onboards as:

     cloud_connector  provider=azure  scope_kind=tenant        scope_id=<tenant id>
     cloud_connector  provider=azure  scope_kind=subscription  scope_id=<sub id>
                                                               parent_scope_id=<tenant id>
     ... one subscription row per subscription the Reader assignment was attempted on

   The tenant row records the Microsoft Graph side (the AuthSec service
   principal and its granted application permissions). Each subscription row
   records the Azure RBAC side (the Reader assignment on that subscription).
   The two are separate rows because they fail separately: Graph consent
   never grants a subscription role, and a subscription can lose its Reader
   assignment while the directory stays readable. */

// Azure Reader assignment outcomes, recorded per subscription.
const (
	// AzureReaderCreated: AuthSec created the assignment in this onboarding.
	AzureReaderCreated = "created"
	// AzureReaderExisting: a Reader assignment for the AuthSec service
	// principal already existed at the subscription.
	AzureReaderExisting = "already_assigned"
	// AzureReaderInherited: Reader is inherited from a management group above
	// the subscription. Nothing was created; nothing needs to be.
	AzureReaderInherited = "inherited"
	// AzureReaderDenied: the signed-in administrator may not create role
	// assignments on this subscription (no roleAssignments/write).
	AzureReaderDenied = "permission_denied"
	// AzureReaderSkipped: the subscription is not in a state that accepts
	// role assignments (Disabled, Deleted, Expired).
	AzureReaderSkipped = "skipped"
	// AzureReaderFailed: ARM refused the assignment for another reason.
	AzureReaderFailed = "failed"
)

// AzureProvisionedViaAdminConsent is the only Azure onboarding path.
const AzureProvisionedViaAdminConsent = "entra_admin_consent"

// Azure Graph permission states, from "granted" (an app role assignment
// exists) to "usable" (a read that permission allows actually succeeded).
const (
	AzureGraphPermissionUsable     = "usable"
	AzureGraphPermissionNotGranted = "not_granted"
	AzureGraphPermissionDenied     = "denied"
	// AzureGraphPermissionLicense: granted, but the tenant's Entra licence does
	// not include the data (sign-in logs need Entra ID P1/P2).
	AzureGraphPermissionLicense = "license_required"
	AzureGraphPermissionUnknown = "unknown"
)

// AzureGraphPermission is one Microsoft Graph application permission as seen in
// the customer tenant.
type AzureGraphPermission struct {
	Name    string `json:"name"`
	Granted bool   `json:"granted"`
	// Optional permissions are requested but not needed to connect; one not
	// granted means a tenant consented before AuthSec asked for it.
	Optional bool   `json:"optional,omitempty"`
	State    string `json:"state"`
	Detail   string `json:"detail,omitempty"`
}

// AzureTenantAttrs is the Azure tenant shape of CloudConnector.Attrs.
type AzureTenantAttrs struct {
	TenantID string `json:"tenant_id"`
	// AppID is AuthSec's multi-tenant application (client) id.
	AppID string `json:"app_id"`
	// ServicePrincipalObjectID is the object id of the AuthSec service
	// principal IN THIS TENANT -- the principal every Reader assignment names.
	ServicePrincipalObjectID string                 `json:"service_principal_object_id"`
	ServicePrincipalName     string                 `json:"service_principal_display_name,omitempty"`
	GraphPermissions         []AzureGraphPermission `json:"graph_permissions"`
	GraphVerifiedAt          *time.Time             `json:"graph_verified_at,omitempty"`
	// SubscriptionsVisible is how many subscriptions the signed-in
	// administrator could see at the last onboarding.
	SubscriptionsVisible int    `json:"subscriptions_visible"`
	ProvisionedVia       string `json:"provisioned_via"`
	// ProvisionedBy is the AuthSec actor, never the Microsoft account: the
	// administrator's Entra identity is not persisted.
	ProvisionedBy string `json:"provisioned_by"`
}

// AzureReaderAssignment is the Reader assignment state of one subscription.
type AzureReaderAssignment struct {
	Status string `json:"status"`
	// AssignmentID is the ARM resource id of the assignment AuthSec created
	// or found, when known.
	AssignmentID string `json:"assignment_id,omitempty"`
	// Scope is where the effective Reader assignment lives: the subscription,
	// or a management group above it.
	Scope     string     `json:"scope,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	// Verified is whether AuthSec's OWN app-only token could read the
	// subscription -- the only proof that counts. A created assignment is not
	// proven access until this is true.
	Verified   bool       `json:"verified"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// AzureSubscriptionAttrs is the Azure subscription shape of CloudConnector.Attrs.
type AzureSubscriptionAttrs struct {
	TenantID                 string                `json:"tenant_id"`
	DisplayName              string                `json:"display_name"`
	State                    string                `json:"state"`
	ServicePrincipalObjectID string                `json:"service_principal_object_id"`
	Reader                   AzureReaderAssignment `json:"reader"`
	ProvisionedVia           string                `json:"provisioned_via"`
	ProvisionedBy            string                `json:"provisioned_by"`
}

// AzureTenantAttrs decodes the tenant shape. Empty when unreadable.
func (c *CloudConnector) AzureTenantAttrs() AzureTenantAttrs {
	var a AzureTenantAttrs
	if len(c.Attrs) > 0 {
		_ = json.Unmarshal(c.Attrs, &a)
	}
	return a
}

// SetAzureTenantAttrs encodes the tenant shape into Attrs.
func (c *CloudConnector) SetAzureTenantAttrs(a AzureTenantAttrs) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	c.Attrs = raw
	return nil
}

// AzureSubscriptionAttrs decodes the subscription shape. Empty when unreadable.
func (c *CloudConnector) AzureSubscriptionAttrs() AzureSubscriptionAttrs {
	var a AzureSubscriptionAttrs
	if len(c.Attrs) > 0 {
		_ = json.Unmarshal(c.Attrs, &a)
	}
	return a
}

// SetAzureSubscriptionAttrs encodes the subscription shape into Attrs.
func (c *CloudConnector) SetAzureSubscriptionAttrs(a AzureSubscriptionAttrs) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	c.Attrs = raw
	return nil
}
