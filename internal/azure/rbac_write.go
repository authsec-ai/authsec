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
	RoleReader                     = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
	RoleContributor                = "b24988ac-6180-42a0-ab88-20f7382dd24c"
	RoleStorageBlobDataReader      = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
	RoleStorageBlobDataContributor = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
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
