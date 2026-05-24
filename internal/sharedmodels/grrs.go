package sharedmodels

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
