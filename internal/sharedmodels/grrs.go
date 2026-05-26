package sharedmodels

// Request struct for adding groups
type UserDefinedGroupsRequest struct {
	WorkspaceID string   `json:"workspace_id" binding:"required"`
	Groups   []string `json:"groups" binding:"required"`
}

// Request struct for mapping groups
type MapGroupsRequest struct {
	WorkspaceID string   `json:"workspace_id" binding:"required"`
	ClientID string   `json:"client_id" binding:"required"`
	Groups   []string `json:"groups" binding:"required"`
}

// Request struct for deleting groups
type DeleteGroupsRequest struct {
	WorkspaceID string   `json:"workspace_id" binding:"required"`
	Groups   []string `json:"groups" binding:"required"`
}
