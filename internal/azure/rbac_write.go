package azure

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

// Role-assignment writes for access policies (an allow is a role assignment
// AuthSec creates and later deletes; a block removes the principal's own
// assignments on the resource and later restores them exactly).

// Built-in role definition ids (the same in every tenant).
const (
	RoleReader      = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
	RoleContributor = "b24988ac-6180-42a0-ab88-20f7382dd24c"
	// Data roles of the types access policies map (Microsoft built-in roles).
	RoleSearchIndexDataReader       = "1407120a-92aa-4202-b7e9-c0e197c71c8f"
	RoleSearchIndexDataContributor  = "8ebe5a00-799e-43f5-93ac-243d3dce84a7"
	RoleKeyVaultSecretsUser         = "4633458b-17de-408a-b874-0445c86b69e6"
	RoleKeyVaultSecretsOfficer      = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"
	RoleCognitiveOpenAIUser         = "5e0bd9bd-7b93-4f28-af87-19fc36ad61bd"
	RoleStorageQueueDataReader      = "19e7f393-937e-4f77-808e-94535e297925"
	RoleStorageQueueDataContributor = "974c5e8b-45b9-4653-ba55-5f855dd0fb88"
	RoleStorageTableDataReader      = "76199698-9eea-4c19-bc75-cec21354c6b6"
	RoleStorageTableDataContributor = "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3"
	RoleStorageFileSMBReader        = "aba4ae5f-2193-4029-9191-0cb91df5e314"
	RoleStorageFileSMBContributor   = "0c867c2a-1d8c-454a-a3db-ab2ea1bdc8bb"
	RoleServiceBusDataReceiver      = "4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0"
	RoleServiceBusDataSender        = "69a216fc-b8fb-44d8-bc22-1f3c2cd27a39"
	RoleEventHubsDataReceiver       = "a638d3c7-ab3a-418d-83e6-5f17a39d4fde"
	RoleEventHubsDataSender         = "2b629674-e913-4c01-ae53-ef4638d8f975"
	RoleCognitiveOpenAIContributor  = "a001fd3d-188f-4b5d-821b-7da978bf7442"
	RoleStorageBlobDataReader       = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
	RoleStorageBlobDataContributor  = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
)

// RoleDefinitionResourceID is a built-in role's id under a subscription.
func RoleDefinitionResourceID(subscriptionID, roleGUID string) string {
	return SubscriptionScope(subscriptionID) + "/providers/Microsoft.Authorization/roleDefinitions/" + roleGUID
}

// RoleAssignmentSpec is everything a role assignment is created with -- what a
// restore needs to put back exactly what was removed.
type RoleAssignmentSpec struct {
	Scope            string `json:"scope"`
	Name             string `json:"name"`
	RoleDefinitionID string `json:"role_definition_id"`
	PrincipalID      string `json:"principal_id"`
	PrincipalType    string `json:"principal_type"`
	Description      string `json:"description,omitempty"`
	Condition        string `json:"condition,omitempty"`
	ConditionVersion string `json:"condition_version,omitempty"`
}

// SpecOf is the spec that recreates a listed assignment, condition (and its
// version) and description included.
func SpecOf(a RoleAssignment) RoleAssignmentSpec {
	return RoleAssignmentSpec{Scope: a.Properties.Scope, Name: a.Name, RoleDefinitionID: a.Properties.RoleDefinitionID,
		PrincipalID: a.Properties.PrincipalID, PrincipalType: a.Properties.PrincipalType, Condition: a.Properties.Condition,
		ConditionVersion: a.Properties.ConditionVersion, Description: a.Properties.Description}
}

// PutRoleAssignment creates (or leaves in place) the assignment named spec.Name
// at spec.Scope. Idempotent: the name is fixed by the caller.
func (c *Client) PutRoleAssignment(ctx context.Context, armToken string, spec RoleAssignmentSpec) (string, error) {
	cl, err := armauthorization.NewRoleAssignmentsClient("", staticToken(armToken), c.armOptions())
	if err != nil {
		return "", err
	}
	props := &armauthorization.RoleAssignmentProperties{
		RoleDefinitionID: to.Ptr(spec.RoleDefinitionID),
		PrincipalID:      to.Ptr(spec.PrincipalID),
	}
	if spec.PrincipalType != "" {
		pt := armauthorization.PrincipalType(spec.PrincipalType)
		props.PrincipalType = &pt
	}
	if spec.Description != "" {
		props.Description = to.Ptr(spec.Description)
	}
	if spec.Condition != "" {
		props.Condition = to.Ptr(spec.Condition)
		v := spec.ConditionVersion
		if v == "" {
			v = "2.0"
		}
		props.ConditionVersion = to.Ptr(v)
	}
	resp, err := cl.Create(ctx, strings.TrimPrefix(spec.Scope, "/"), spec.Name,
		armauthorization.RoleAssignmentCreateParameters{Properties: props}, nil)
	if err != nil {
		var re *azcore.ResponseError
		if errors.As(err, &re) && re.StatusCode == http.StatusConflict && strings.EqualFold(re.ErrorCode, "RoleAssignmentExists") {
			return spec.Scope + "/providers/Microsoft.Authorization/roleAssignments/" + spec.Name, nil
		}
		return "", armError(err)
	}
	return str(resp.ID), nil
}

// GetRoleAssignment reads one assignment by its resource id; nil when gone.
func (c *Client) GetRoleAssignment(ctx context.Context, armToken, id string) (*RoleAssignment, error) {
	cl, err := armauthorization.NewRoleAssignmentsClient("", staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	resp, err := cl.GetByID(ctx, strings.TrimPrefix(id, "/"), nil)
	if err != nil {
		var re *azcore.ResponseError
		if errors.As(err, &re) && re.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, armError(err)
	}
	ra := roleAssignmentFrom(&resp.RoleAssignment)
	return &ra, nil
}

// DeleteRoleAssignment removes one assignment by its resource id; gone is fine.
func (c *Client) DeleteRoleAssignment(ctx context.Context, armToken, id string) error {
	cl, err := armauthorization.NewRoleAssignmentsClient("", staticToken(armToken), c.armOptions())
	if err != nil {
		return err
	}
	if _, err := cl.DeleteByID(ctx, strings.TrimPrefix(id, "/"), nil); err != nil {
		var re *azcore.ResponseError
		if errors.As(err, &re) && (re.StatusCode == http.StatusNotFound || re.StatusCode == http.StatusNoContent) {
			return nil
		}
		return armError(err)
	}
	return nil
}
