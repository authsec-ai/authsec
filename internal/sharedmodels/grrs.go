package sharedmodels

// Request struct for adding scopes
type UserDefinedScopesRequest struct {
	TenantID string   `json:"tenant_id" binding:"required"`
	Scopes   []string `json:"scopes" binding:"required"`
}

// Request struct for mapping scopes
type MapScopesRequest struct {
	TenantID string   `json:"tenant_id" binding:"required"`
	ClientID string   `json:"client_id" binding:"required"`
	Scopes   []string `json:"scopes" binding:"required"`
}

// Request struct for deleting scopes
type DeleteScopesRequest struct {
	TenantID string   `json:"tenant_id" binding:"required"`
	Scopes   []string `json:"scopes" binding:"required"`
}

// Request struct for adding resources
type UserDefinedResourcesRequest struct {
	TenantID  string   `json:"tenant_id" binding:"required"`
	Resources []string `json:"resources" binding:"required"`
}

// Request struct for mapping resources
type MapResourcesRequest struct {
	TenantID  string   `json:"tenant_id" binding:"required"`
	ClientID  string   `json:"client_id" binding:"required"`
	Resources []string `json:"resources" binding:"required"`
}

// Request struct for deleting resources
type DeleteResourcesRequest struct {
	TenantID  string   `json:"tenant_id" binding:"required"`
	Resources []string `json:"resources" binding:"required"`
}

// Request struct for adding roles
type UserDefinedRolesRequest struct {
	TenantID string   `json:"tenant_id" binding:"required"`
	Roles    []string `json:"roles" binding:"required"`
}

// Request struct for mapping roles
type MapRolesRequest struct {
	TenantID string   `json:"tenant_id" binding:"required"`
	ClientID string   `json:"client_id" binding:"required"`
	Roles    []string `json:"roles" binding:"required"`
}

// Request struct for deleting roles
type DeleteRolesRequest struct {
	TenantID string   `json:"tenant_id" binding:"required"`
	Roles    []string `json:"roles" binding:"required"`
}

// Request struct for adding groups
type UserDefinedGroupsRequest struct {
	TenantID string   `json:"tenant_id" binding:"required"`
	Groups   []string `json:"groups" binding:"required"`
}

// Request struct for mapping groups
type MapGroupsRequest struct {
	TenantID string   `json:"tenant_id" binding:"required"`
	ClientID string   `json:"client_id" binding:"required"`
	Groups   []string `json:"groups" binding:"required"`
}

// Request struct for deleting groups
type DeleteGroupsRequest struct {
	TenantID string   `json:"tenant_id" binding:"required"`
	Groups   []string `json:"groups" binding:"required"`
}
