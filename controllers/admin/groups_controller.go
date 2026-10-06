package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type GroupController struct{}

// AdminGroupListRequest represents the payload for admin tenant group listing
type AdminGroupListRequest struct {
	WorkspaceID string `json:"workspace_id"` // ignored: the token's workspace is used
	UserID   string `json:"user_id"`
}

// GroupRequest handles both string and object formats for groups
type GroupRequest struct {
	WorkspaceID string          `json:"workspace_id"` // ignored: the token's workspace is used
	ClientID  string          `json:"client_id,omitempty"`
	ProjectID string          `json:"project_id,omitempty"`
	Groups    json.RawMessage `json:"groups" binding:"required"`
}

// GroupItem represents a group with a name
type GroupItem struct {
	Name string `json:"name" binding:"required"`
}

// function to add user defined groups to the groups table in db

// AddUserDefinedGroups godoc
// @Summary Add user-defined groups
// @Description Adds custom groups under a tenant
// @Tags Groups
// @Accept json
// @Produce json
// @Param input body object true "Groups payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/groups [post]
func (gc *GroupController) AddUserDefinedGroups(c *gin.Context) {
	var req GroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	tc, db, ok := shared.TenantScope(c)
	if !ok {
		return
	}

	// Parse groups - handle both string array and object array formats
	var groupNames []string

	// First try to parse as array of strings
	var stringGroups []string
	if err := json.Unmarshal(req.Groups, &stringGroups); err == nil {
		groupNames = stringGroups
	} else {
		// Try to parse as array of objects with "name" field
		var objectGroups []GroupItem
		if err := json.Unmarshal(req.Groups, &objectGroups); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Groups must be either array of strings or array of objects with 'name' field"})
			return
		}
		// Extract names from objects
		for _, group := range objectGroups {
			if group.Name == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Group name cannot be empty"})
				return
			}
			groupNames = append(groupNames, group.Name)
		}
	}

	if len(groupNames) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one group is required"})
		return
	}

	createdGroups, err := AddUserDefinedGroups(db, tc.WorkspaceID, groupNames)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add groups: " + err.Error()})
		return
	}

	// Audit log: Groups created
	middlewares.Audit(c, "group", tc.WorkspaceID.String(), "create", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"workspace_id": tc.WorkspaceID.String(),
			"groups_count": len(createdGroups),
			"group_names":  groupNames,
		},
	})

	c.JSON(http.StatusOK, gin.H{
		"message": "Groups added successfully",
		"groups":  createdGroups,
	})
}

// function to map groups to client in client_groups table

// MapGroupsToClient godoc
// @Summary Map groups to client
// @Description Maps groups to a client under a tenant
// @Tags Groups
// @Accept json
// @Produce json
// @Param input body object true "Mapping payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/groups/map [post]
func (gc *GroupController) MapGroupsToClient(c *gin.Context) {
	var req models.MapGroupsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	if req.ClientID == "" || len(req.Groups) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ClientID and Groups are required"})
		return
	}
	tc, db, ok := shared.TenantScope(c)
	if !ok {
		return
	}

	if err := MapGroupsToClient(db, tc.WorkspaceID, req.ClientID, req.Groups); err != nil {
		if shared.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user or groups not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to map groups to client: " + err.Error()})
		return
	}

	// Audit log: Groups mapped to client
	middlewares.Audit(c, "group", req.ClientID, "map_to_client", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"workspace_id": tc.WorkspaceID.String(),
			"client_id": req.ClientID,
			"groups":    req.Groups,
		},
	})

	c.JSON(http.StatusOK, gin.H{"message": "Groups mapped to client successfully"})
}

// RemoveGroupsFromClient godoc
// @Summary Remove groups from client
// @Description Removes group associations from a client under a tenant
// @Tags Groups
// @Accept json
// @Produce json
// @Param input body object true "Unmapping payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/groups/map [delete]
func (gc *GroupController) RemoveGroupsFromClient(c *gin.Context) {
	var req models.RemoveGroupsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	if req.ClientID == "" || len(req.Groups) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ClientID and Groups are required"})
		return
	}
	tc, db, ok := shared.TenantScope(c)
	if !ok {
		return
	}

	if err := RemoveGroupsFromClient(db, req.ClientID, req.Groups); err != nil {
		if shared.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove groups from client: " + err.Error()})
		return
	}

	// Audit log: Groups removed from client
	middlewares.Audit(c, "group", req.ClientID, "unmap_from_client", &middlewares.AuditChanges{
		Before: map[string]interface{}{
			"workspace_id": tc.WorkspaceID.String(),
			"client_id": req.ClientID,
			"groups":    req.Groups,
		},
	})

	c.JSON(http.StatusOK, gin.H{"message": "Groups removed from client successfully"})
}

// function to get user defined groups for a tenant

// GetUserDefinedGroups godoc
// @Summary Get user-defined groups
// @Description Retrieves all groups created by the tenant
// @Tags Groups
// @Produce json
// @Param workspace_id path string true "Tenant ID"
// @Success 200 {object} object
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/groups/{workspace_id} [get]
func (gc *GroupController) GetUserDefinedGroups(c *gin.Context) {
	// The workspace comes from the token, never the URL.
	_, db, ok := shared.TenantScope(c)
	if !ok {
		return
	}

	groups, err := GetUserDefinedGroups(db)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch groups: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"groups": groups})
}

// AddUsersToGroup godoc
// @Summary Add multiple users to a group
// @Description Adds multiple users to a specified group within a tenant. Supports large arrays of user IDs.
// @Tags Groups
// @Accept json
// @Produce json
// @Param workspace_id path string true "Tenant ID"
// @Param input body models.AddUsersToGroupRequest true "Add users to group payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/groups/{workspace_id}/users/bulk [post]
func (gc *GroupController) AddUsersToGroup(c *gin.Context) {
	// The workspace comes from the token, never the URL.
	tc, db, ok := shared.TenantScope(c)
	if !ok {
		return
	}
	workspaceID := tc.WorkspaceID.String()

	var req models.AddUsersToGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	if len(req.UserIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one user ID is required"})
		return
	}

	if err := AddUsersToGroupBulk(db, tc.WorkspaceID, req.GroupID, req.UserIDs); err != nil {
		if shared.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "group or user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add users to group: " + err.Error()})
		return
	}

	// Audit log: Users added to group
	middlewares.Audit(c, "group", req.GroupID.String(), "add_users", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"workspace_id":  workspaceID,
			"group_id":   req.GroupID.String(),
			"user_count": len(req.UserIDs),
		},
	})

	c.JSON(http.StatusOK, gin.H{
		"message":    "Users added to group successfully",
		"group_id":   req.GroupID.String(),
		"user_count": len(req.UserIDs),
	})
}

// RemoveUsersFromGroup godoc
// @Summary Remove multiple users from a group
// @Description Removes multiple users from a specified group within a tenant. Supports large arrays of user IDs.
// @Tags Groups
// @Accept json
// @Produce json
// @Param workspace_id path string true "Tenant ID"
// @Param input body models.RemoveUsersFromGroupRequest true "Remove users from group payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/groups/{workspace_id}/users/bulk [delete]
func (gc *GroupController) RemoveUsersFromGroup(c *gin.Context) {
	// The workspace comes from the token, never the URL.
	tc, db, ok := shared.TenantScope(c)
	if !ok {
		return
	}
	workspaceID := tc.WorkspaceID.String()

	var req models.RemoveUsersFromGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	if len(req.UserIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one user ID is required"})
		return
	}

	if err := RemoveUsersFromGroupBulk(db, req.GroupID, req.UserIDs); err != nil {
		if shared.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove users from group: " + err.Error()})
		return
	}

	// Audit log: Users removed from group
	middlewares.Audit(c, "group", req.GroupID.String(), "remove_users", &middlewares.AuditChanges{
		Before: map[string]interface{}{
			"workspace_id":  workspaceID,
			"group_id":   req.GroupID.String(),
			"user_count": len(req.UserIDs),
		},
	})

	c.JSON(http.StatusOK, gin.H{
		"message":    "Users removed from group successfully",
		"group_id":   req.GroupID.String(),
		"user_count": len(req.UserIDs),
	})
}

// function to delete user defined groups from the groups table

// DeleteUserDefinedGroups godoc
// @Summary Delete user-defined groups
// @Description Deletes groups from the database for a tenant
// @Tags Groups
// @Accept json
// @Produce json
// @Param input body object true "Delete groups payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/groups [delete]
func (gc *GroupController) DeleteUserDefinedGroups(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: unable to read body"})
		return
	}

	// workspace_id from the body is discarded — token is the source of truth.
	tc, db, ok := shared.TenantScope(c)
	if !ok {
		return
	}
	_, groups, parseErr := parseDeleteGroupsPayload(body)
	if parseErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + parseErr.Error()})
		return
	}
	workspaceID := tc.WorkspaceID.String()

	queryGroups := []string{}
	queryGroups = append(queryGroups, c.QueryArray("group_ids")...)

	if single := c.Query("group"); single != "" {
		queryGroups = append(queryGroups, single)
	}
	groups = uniqueStrings(append(groups, queryGroups...))

	if len(groups) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one group-id is required"})
		return
	}
	groupIDs := make([]uuid.UUID, 0, len(groups))
	for _, g := range groups {
		id, err := uuid.Parse(g)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "group ids must be UUIDs"})
			return
		}
		groupIDs = append(groupIDs, id)
	}

	deleted, err := DeleteUserDefinedGroups(db, groupIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete groups: " + err.Error()})
		return
	}
	if deleted == 0 {
		// None of the ids is a group of this workspace.
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	// Audit log: Groups deleted
	middlewares.Audit(c, "group", workspaceID, "delete", &middlewares.AuditChanges{
		Before: map[string]interface{}{
			"workspace_id":   workspaceID,
			"group_ids":   groups,
			"group_count": len(groups),
		},
	})

	c.JSON(http.StatusOK, gin.H{"message": "Groups deleted successfully"})
}

func parseDeleteGroupsPayload(body []byte) (string, []string, error) {
	if len(body) == 0 {
		return "", nil, nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return "", nil, err
	}

	var workspaceID string
	if value, ok := raw["workspace_id"].(string); ok {
		workspaceID = value
	} else if value, ok := raw["tenantId"].(string); ok {
		workspaceID = value
	}

	groupKeys := []string{"groups", "group_names", "groupNames", "Groups"}
	var groups []string
	for _, key := range groupKeys {
		if value, ok := raw[key]; ok {
			groups = append(groups, coerceGroupValues(value)...)
		}
	}

	return workspaceID, uniqueStrings(groups), nil
}

func coerceGroupValues(value interface{}) []string {
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		return splitAndTrim(v)
	case []interface{}:
		var result []string
		for _, item := range v {
			result = append(result, coerceGroupValues(item)...)
		}
		return result
	case map[string]interface{}:
		keys := []string{"name", "value", "id", "group_name", "groupName"}
		var result []string
		for _, key := range keys {
			if str, ok := v[key].(string); ok {
				result = append(result, splitAndTrim(str)...)
			}
		}

		nestedKeys := []string{"values", "names", "items", "groups", "selected"}
		for _, key := range nestedKeys {
			if nested, ok := v[key]; ok {
				result = append(result, coerceGroupValues(nested)...)
			}
		}
		return result
	default:
		// attempt best-effort string conversion for other scalar types
		str := strings.TrimSpace(fmt.Sprint(v))
		if str == "" || str == "0" || str == "<nil>" || str == "false" {
			return nil
		}
		return []string{str}
	}
}

func splitAndTrim(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	if !strings.Contains(value, ",") {
		return []string{value}
	}

	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}

	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))

	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}

	return result
}

// UpdateUserDefinedGroup godoc
// @Summary Update a user-defined group
// @Description Updates the name and/or description of a specific group
// @Tags Groups
// @Accept json
// @Produce json
// @Param id path string true "Group ID"
// @Param input body object true "Update group payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/groups/{id} [put]
func (gc *GroupController) UpdateUserDefinedGroup(c *gin.Context) {
	groupID := c.Param("id")
	if groupID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Group ID is required"})
		return
	}

	var req struct {
		WorkspaceID string `json:"workspace_id"` // ignored: the token's workspace is used
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}
	tc, db, ok := shared.TenantScope(c)
	if !ok {
		return
	}

	if err := UpdateUserDefinedGroup(db, groupID, req.Name, req.Description); err != nil {
		if shared.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update group: " + err.Error()})
		return
	}

	// Audit log: Group updated
	middlewares.Audit(c, "group", groupID, "update", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"workspace_id": tc.WorkspaceID.String(),
			"group_id":    groupID,
			"name":        req.Name,
			"description": req.Description,
		},
	})

	c.JSON(http.StatusOK, gin.H{"message": "Group updated successfully"})
}

// AddUserToGroups godoc
// @Summary Add user to groups
// @Description Adds a user to specified groups within a tenant
// @Tags Groups
// @Accept json
// @Produce json
// @Param input body object true "Add user to groups payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/groups/users/add [post]
func (gc *GroupController) AddUserToGroups(c *gin.Context) {
	var req struct {
		WorkspaceID string   `json:"workspace_id"` // ignored: the token's workspace is used
		UserID   string   `json:"user_id" binding:"required"`
		Groups   []string `json:"groups" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	if req.UserID == "" || len(req.Groups) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "UserID and Groups are required"})
		return
	}
	tc, db, ok := shared.TenantScope(c)
	if !ok {
		return
	}

	if err := AddUserToGroups(db, tc.WorkspaceID, req.UserID, req.Groups); err != nil {
		if shared.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user or groups not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add user to groups: " + err.Error()})
		return
	}

	middlewares.Audit(c, "group", req.UserID, "add_user_to_groups", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"workspace_id": tc.WorkspaceID.String(),
			"user_id":   req.UserID,
			"groups":    req.Groups,
		},
	})

	c.JSON(http.StatusOK, gin.H{"message": "User added to groups successfully"})
}

// RemoveUserFromGroups godoc
// @Summary Remove user from groups
// @Description Removes a user from specified groups within a tenant
// @Tags Groups
// @Accept json
// @Produce json
// @Param input body object true "Remove user from groups payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/groups/users/remove [post]
func (gc *GroupController) RemoveUserFromGroups(c *gin.Context) {
	var req struct {
		WorkspaceID string   `json:"workspace_id"` // ignored: the token's workspace is used
		UserID   string   `json:"user_id" binding:"required"`
		Groups   []string `json:"groups" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	if req.UserID == "" || len(req.Groups) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "UserID and Groups are required"})
		return
	}
	tc, db, ok := shared.TenantScope(c)
	if !ok {
		return
	}

	if err := RemoveUserFromGroups(db, tc.WorkspaceID, req.UserID, req.Groups); err != nil {
		if shared.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user or groups not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove user from groups: " + err.Error()})
		return
	}

	middlewares.Audit(c, "group", req.UserID, "remove_user_from_groups", &middlewares.AuditChanges{
		Before: map[string]interface{}{
			"workspace_id": tc.WorkspaceID.String(),
			"user_id":   req.UserID,
			"groups":    req.Groups,
		},
	})

	c.JSON(http.StatusOK, gin.H{"message": "User removed from groups successfully"})
}

// GetMyGroups godoc
// @Summary Get current user's groups
// @Description Retrieves all groups the authenticated user belongs to within their active tenant
// @Tags Groups
// @Produce json
// @Security BearerAuth
// @Success 200 {object} object
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/user/groups/users [get]
func (gc *GroupController) GetMyGroups(c *gin.Context) {
	tc, db, ok := shared.TenantScope(c)
	if !ok {
		return
	}

	groups, err := GetUserGroups(db, tc.PrincipalID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch groups: " + err.Error()})
		return
	}

	users, err := fetchTenantGroupUsers(db)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := gin.H{
		"groups": groups,
		"users":  users,
	}

	if requestHasAdminRole(db, tc.PrincipalID) {
		admins, err := fetchTenantAdmins(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		response["admins"] = admins
	}

	c.JSON(http.StatusOK, response)
}

// ListTenantGroupsForAdmin godoc
// @Summary List groups within a tenant (admin)
// @Description Retrieves groups for a tenant; optionally filter by user membership
// @Tags Admin-Groups
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param input body AdminGroupListRequest true "Tenant group listing payload"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/admin/groups/list [post]
func (gc *GroupController) ListTenantGroupsForAdmin(c *gin.Context) {
	var req AdminGroupListRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, db, ok := shared.TenantScope(c)
	if !ok {
		return
	}

	var (
		groups []models.TenantGroup
		err    error
	)

	if strings.TrimSpace(req.UserID) != "" {
		groups, err = GetUserGroups(db, req.UserID)
	} else {
		groups, err = GetUserDefinedGroups(db)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	groupResponses := make([]gin.H, 0, len(groups))
	for _, group := range groups {
		members, err := GetGroupUsers(db, group.ID.String())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to fetch users for group %s: %v", group.ID, err)})
			return
		}

		groupResponses = append(groupResponses, gin.H{
			"group": group,
			"users": members,
		})
	}

	c.JSON(http.StatusOK, gin.H{"groups": groupResponses})
}

// GetGroupUsers godoc
// @Summary Get group users
// @Description Retrieves all users in a specific group within a tenant
// @Tags Groups
// @Produce json
// @Param workspace_id path string true "Tenant ID"
// @Param group_id path string true "Group ID"
// @Success 200 {object} object
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/groups/{workspace_id}/{group_id}/users [get]
func (gc *GroupController) GetGroupUsers(c *gin.Context) {
	// The workspace comes from the token, never the URL.
	_, db, ok := shared.TenantScope(c)
	if !ok {
		return
	}

	groupID := c.Param("group_id")
	if groupID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "GroupID is required"})
		return
	}

	users, err := GetGroupUsers(db, groupID)
	if err != nil {
		if shared.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch group users: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

// Database helper functions for group operations

// The helpers below take db already restricted to one workspace (see
// shared.TenantScope); "not in this workspace" is tenancy.ErrNotFound.

func AddUserDefinedGroups(db *gorm.DB, workspaceID uuid.UUID, groups []string) ([]models.TenantGroup, error) {
	var createdGroups []models.TenantGroup
	for _, groupName := range groups {
		group := models.TenantGroup{
			Name:     groupName,
			WorkspaceID: workspaceID,
		}
		if err := db.Where("name = ?", groupName).FirstOrCreate(&group).Error; err != nil {
			return nil, err
		}
		createdGroups = append(createdGroups, group)
	}
	return createdGroups, nil
}

func MapGroupsToClient(db *gorm.DB, workspaceID uuid.UUID, clientID string, groups []string) error {
	clientUUID, err := uuid.Parse(clientID)
	if err != nil {
		return fmt.Errorf("invalid client ID format: %w", err)
	}

	var user models.User
	if err := db.Where("client_id = ? AND deleted_at IS NULL", clientUUID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return tenancy.ErrNotFound
		}
		return fmt.Errorf("failed to find user: %w", err)
	}

	var groupModels []models.TenantGroup
	if err := db.Where("name IN ?", groups).Find(&groupModels).Error; err != nil {
		return fmt.Errorf("failed to find groups: %w", err)
	}
	if len(groupModels) == 0 {
		return tenancy.ErrNotFound
	}

	for _, group := range groupModels {
		if err := db.Exec(
			"INSERT INTO user_groups (user_id, group_id, workspace_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
			user.ID, group.ID, workspaceID,
		).Error; err != nil {
			return fmt.Errorf("failed to map group to user: %w", err)
		}
	}
	return nil
}

func RemoveGroupsFromClient(db *gorm.DB, clientID string, groups []string) error {
	clientUUID, err := uuid.Parse(clientID)
	if err != nil {
		return fmt.Errorf("invalid client ID format: %w", err)
	}

	var user models.User
	if err := db.Where("client_id = ? AND deleted_at IS NULL", clientUUID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return tenancy.ErrNotFound
		}
		return fmt.Errorf("failed to find user: %w", err)
	}

	var groupIDs []uuid.UUID
	if err := db.Model(&models.TenantGroup{}).Where("name IN ?", groups).Pluck("id", &groupIDs).Error; err != nil {
		return fmt.Errorf("failed to find groups: %w", err)
	}
	if len(groupIDs) == 0 {
		return nil
	}
	if err := db.Where("user_id = ? AND group_id IN ?", user.ID, groupIDs).Delete(&models.UserGroup{}).Error; err != nil {
		return fmt.Errorf("failed to remove group from user: %w", err)
	}
	return nil
}

func GetUserDefinedGroups(db *gorm.DB) ([]models.TenantGroup, error) {
	var groups []models.TenantGroup
	if err := db.Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("failed to query groups: %w", err)
	}
	return groups, nil
}

// DeleteUserDefinedGroups deletes the listed groups of the workspace and
// reports how many there were.
func DeleteUserDefinedGroups(db *gorm.DB, groupIDs []uuid.UUID) (int64, error) {
	res := db.Where("id IN ?", groupIDs).Delete(&models.TenantGroup{})
	return res.RowsAffected, res.Error
}

func UpdateUserDefinedGroup(db *gorm.DB, groupID, name, description string) error {
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		return tenancy.ErrNotFound
	}

	updateData := models.TenantGroup{
		Name:        name,
		Description: &description,
	}
	res := db.Model(&models.TenantGroup{}).Where("id = ?", groupUUID).Updates(updateData)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return tenancy.ErrNotFound
	}
	return nil
}

// AddUserToGroups adds a user to specified groups within a tenant
// AddUserToGroups adds a user of the workspace to the named groups.
func AddUserToGroups(db *gorm.DB, workspaceID uuid.UUID, userID string, groups []string) error {
	user, err := workspaceUser(db, userID)
	if err != nil {
		return err
	}

	var groupModels []models.TenantGroup
	if err := db.Where("name IN ?", groups).Find(&groupModels).Error; err != nil {
		return fmt.Errorf("failed to find groups: %w", err)
	}
	if len(groupModels) == 0 {
		return tenancy.ErrNotFound
	}

	for _, group := range groupModels {
		if err := db.Exec(
			"INSERT INTO user_groups (user_id, group_id, workspace_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
			user.ID, group.ID, workspaceID,
		).Error; err != nil {
			return fmt.Errorf("failed to add user to group: %w", err)
		}
	}
	return nil
}

// workspaceUser loads a live user of the workspace db is scoped to.
func workspaceUser(db *gorm.DB, userID string) (*models.User, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, tenancy.ErrNotFound
	}
	var user models.User
	if err := db.Where("id = ? AND deleted_at IS NULL", userUUID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, tenancy.ErrNotFound
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	return &user, nil
}

// RemoveUserFromGroups removes a user from specified groups within a tenant
// RemoveUserFromGroups removes a user of the workspace from the named groups.
func RemoveUserFromGroups(db *gorm.DB, _ uuid.UUID, userID string, groups []string) error {
	user, err := workspaceUser(db, userID)
	if err != nil {
		return err
	}

	var groupIDs []uuid.UUID
	if err := db.Model(&models.TenantGroup{}).Where("name IN ?", groups).Pluck("id", &groupIDs).Error; err != nil {
		return fmt.Errorf("failed to find groups: %w", err)
	}
	if len(groupIDs) == 0 {
		return nil
	}
	if err := db.Where("user_id = ? AND group_id IN ?", user.ID, groupIDs).Delete(&models.UserGroup{}).Error; err != nil {
		return fmt.Errorf("failed to remove user from group: %w", err)
	}
	return nil
}

// GetUserGroups retrieves all groups a user belongs to within a tenant
// GetUserGroups returns the workspace's groups the user belongs to. A user
// of another workspace has none here.
func GetUserGroups(db *gorm.DB, userID string) ([]models.TenantGroup, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID format: %w", err)
	}

	groups := make([]models.TenantGroup, 0)
	var groupIDs []uuid.UUID
	if err := db.Model(&models.UserGroup{}).Where("user_id = ?", userUUID).Pluck("group_id", &groupIDs).Error; err != nil {
		return nil, fmt.Errorf("failed to query user groups: %w", err)
	}
	if len(groupIDs) == 0 {
		return groups, nil
	}
	if err := db.Where("id IN ?", groupIDs).Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("failed to query user groups: %w", err)
	}
	return groups, nil
}

type groupUserSummary struct {
	ID       uuid.UUID  `json:"id"`
	Email    string     `json:"email"`
	Name     string     `json:"name"`
	Provider string     `json:"provider"`
	ClientID *uuid.UUID `json:"client_id,omitempty"`
	Active   bool       `json:"active"`
}

type groupAdminSummary struct {
	ID       uuid.UUID  `json:"id"`
	Email    string     `json:"email"`
	Name     string     `json:"name"`
	ClientID *uuid.UUID `json:"client_id,omitempty"`
	Active   bool       `json:"active"`
}

func fetchTenantGroupUsers(db *gorm.DB) ([]groupUserSummary, error) {
	users := make([]groupUserSummary, 0)
	if err := db.Table("users").
		Select("id, email, name, provider, client_id, active").
		Where("deleted_at IS NULL").
		Order("LOWER(email) ASC").
		Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to query tenant users: %w", err)
	}

	return users, nil
}

func fetchTenantAdmins(ctx context.Context) ([]groupAdminSummary, error) {
	db := config.GetDatabase()
	if db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	adminRepo := database.NewAdminUserRepository(db)
	admins, err := adminRepo.ListAdminUsersInWorkspace(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to query tenant admins: %w", err)
	}

	summaries := make([]groupAdminSummary, 0, len(admins))
	for _, admin := range admins {
		summaries = append(summaries, groupAdminSummary{
			ID:       admin.ID,
			Email:    admin.Email,
			Name:     admin.Name,
			ClientID: admin.ClientID,
			Active:   admin.Active,
		})
	}

	return summaries, nil
}

// requestHasAdminRole reports whether the caller is an active owner or admin
// member of the workspace db is scoped to. It read user_info, which the auth
// middleware never sets, so it was always false (AS-048).
func requestHasAdminRole(db *gorm.DB, userID uuid.UUID) bool {
	var adminRoleIDs []uuid.UUID
	if err := db.Model(&models.RBACRole{}).
		Where("LOWER(name) IN ?", []string{"owner", "admin", "administrator", "super_admin"}).
		Pluck("id", &adminRoleIDs).Error; err != nil || len(adminRoleIDs) == 0 {
		return false
	}
	var n int64
	if err := db.Table("workspace_memberships").
		Where("user_id = ? AND status = ? AND role_id IN ?", userID, "active", adminRoleIDs).
		Count(&n).Error; err != nil {
		return false
	}
	return n > 0
}

// GetGroupUsers retrieves all users in a specific group within a tenant
// GetGroupUsers returns the users of a group of the workspace. A group of
// another workspace is tenancy.ErrNotFound.
func GetGroupUsers(db *gorm.DB, groupID string) ([]models.User, error) {
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		return nil, tenancy.ErrNotFound
	}
	var group models.TenantGroup
	if err := db.Where("id = ?", groupUUID).First(&group).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, tenancy.ErrNotFound
		}
		return nil, fmt.Errorf("failed to load group: %w", err)
	}

	users := []models.User{}
	var userIDs []uuid.UUID
	if err := db.Model(&models.UserGroup{}).Where("group_id = ?", groupUUID).Pluck("user_id", &userIDs).Error; err != nil {
		return nil, fmt.Errorf("failed to query group users: %w", err)
	}
	if len(userIDs) == 0 {
		return users, nil
	}
	if err := db.Where("id IN ?", userIDs).Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to query group users: %w", err)
	}
	return users, nil
}

// AddUsersToGroupBulk adds multiple users to a group efficiently
// AddUsersToGroupBulk adds users to a group. The group and every user must
// belong to the workspace; otherwise nothing is written and the result is
// tenancy.ErrNotFound (the user ids were not checked before, AS-062 style).
func AddUsersToGroupBulk(db *gorm.DB, workspaceID uuid.UUID, groupID uuid.UUID, userIDs []uuid.UUID) error {
	var group models.TenantGroup
	if err := db.Where("id = ?", groupID).First(&group).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return tenancy.ErrNotFound
		}
		return fmt.Errorf("failed to verify group: %w", err)
	}

	unique := make(map[uuid.UUID]struct{}, len(userIDs))
	for _, id := range userIDs {
		unique[id] = struct{}{}
	}
	ids := make([]uuid.UUID, 0, len(unique))
	for id := range unique {
		ids = append(ids, id)
	}
	var found int64
	if err := db.Model(&models.User{}).Where("id IN ? AND deleted_at IS NULL", ids).Count(&found).Error; err != nil {
		return fmt.Errorf("failed to verify users: %w", err)
	}
	if found != int64(len(ids)) {
		return tenancy.ErrNotFound
	}

	return db.Transaction(func(tx *gorm.DB) error {
		for _, userID := range ids {
			if err := tx.Exec(
				// user_groups has no created_at/updated_at and its key is
				// (workspace_id, user_id, group_id); the old statement named
				// both wrongly and always failed.
				"INSERT INTO user_groups (user_id, group_id, workspace_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
				userID, groupID, workspaceID,
			).Error; err != nil {
				return fmt.Errorf("failed to add users to group: %w", err)
			}
		}
		return nil
	})
}

// RemoveUsersFromGroupBulk removes multiple users from a group efficiently
// RemoveUsersFromGroupBulk removes users from a group of the workspace.
func RemoveUsersFromGroupBulk(db *gorm.DB, groupID uuid.UUID, userIDs []uuid.UUID) error {
	var group models.TenantGroup
	if err := db.Where("id = ?", groupID).First(&group).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return tenancy.ErrNotFound
		}
		return fmt.Errorf("failed to verify group: %w", err)
	}

	batchSize := 100
	for i := 0; i < len(userIDs); i += batchSize {
		end := i + batchSize
		if end > len(userIDs) {
			end = len(userIDs)
		}
		if err := db.Where("group_id = ? AND user_id IN ?", groupID, userIDs[i:end]).
			Delete(&models.UserGroup{}).Error; err != nil {
			return fmt.Errorf("failed to remove users from group: %w", err)
		}
	}
	return nil
}
