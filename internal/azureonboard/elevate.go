package azureonboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// Granting Reader one subscription at a time is the step that makes Azure
// onboarding feel manual, and it is the step that silently goes stale: a
// subscription created next month is not covered by an assignment made today.
//
// A single assignment at the tenant ROOT MANAGEMENT GROUP covers every
// subscription in the tenant, including ones that do not exist yet. The reason
// onboarding cannot simply do that is privilege. Writing a role assignment at
// the root group needs User Access Administrator THERE, and a Global
// Administrator does not hold it by default -- Entra roles and Azure RBAC are
// separate systems, so being able to administer a directory grants nothing over
// its resources.
//
// Microsoft's answer is elevateAccess: a Global Administrator may assign
// THEMSELVES User Access Administrator at root scope. In the portal it is the
// "Access management for Azure resources" toggle under Entra properties, and
// the runbook currently asks a customer to flip it by hand, sign out, sign back
// in, and then find the root management group in the IAM blade. It is also a
// plain ARM call, made with the delegated token this flow already holds -- which
// means the whole path can happen without the operator leaving AuthSec.
//
// Three rules this file keeps, because the capability it reaches for is the
// widest one in Azure RBAC:
//
//  1. Never elevate until the assignment has been TRIED and refused. An operator
//     who already holds the privilege is never elevated at all.
//  2. Never elevate implicitly. The caller asks for it by name.
//  3. Never remove an elevation this code did not create, and always attempt to
//     remove one it did -- reporting plainly when removal failed. Elevation does
//     not expire on its own, so a silent failure here leaves a human holding
//     root-scope User Access Administrator indefinitely.
//
// It is fully audited on Microsoft's side either way: Entra directory audit logs
// carry it under the "Azure RBAC (Elevated Access)" service, the Azure activity
// log records Microsoft.Authorization/elevateAccess/action, and the portal shows
// tenant administrators a standing banner naming everyone currently elevated.
// Nothing here happens quietly.

const (
	// UserAccessAdministratorRoleDefinitionID is the built-in User Access
	// Administrator role -- what elevateAccess grants at root scope. Like every
	// built-in role definition this GUID is identical in every tenant.
	UserAccessAdministratorRoleDefinitionID = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"

	// RootScope is the scope elevateAccess grants at: the tenant itself, above
	// every management group and subscription. Distinct from the root management
	// group, which sits one level below it.
	RootScope = "/"
)

// ErrNotGlobalAdmin means the signed-in operator cannot elevate, which almost
// always means they are not a Global Administrator of this tenant. Not a defect:
// most operators are not, and the manual instructions are the answer for them.
var ErrNotGlobalAdmin = errors.New(
	"azure refused to elevate access; the signed-in account is not a Global Administrator of this tenant")

// RootManagementGroupScope is the ARM scope covering every subscription in a
// tenant, present and future.
//
// A tenant's root management group id IS the tenant id, so this needs no lookup
// -- which matters, because a lookup would need ARM access, and ARM access is
// precisely what does not work yet at this point in onboarding.
func RootManagementGroupScope(tenantID string) string {
	return "/providers/Microsoft.Management/managementGroups/" + tenantID
}

// RoleAssignment is the subset of an ARM role assignment this package reads.
type RoleAssignment struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		RoleDefinitionID string `json:"roleDefinitionId"`
		PrincipalID      string `json:"principalId"`
		Scope            string `json:"scope"`
	} `json:"properties"`
}

// ElevateAccess assigns the SIGNED-IN OPERATOR User Access Administrator at root
// scope, using their own delegated token.
//
// Requires the caller to be a Global Administrator; anyone else gets 403, which
// is the expected and safe outcome rather than an error condition to route
// around. The grant is per-user, not tenant-wide: it affects the caller only.
//
// It does NOT expire. Whoever calls this owns removing it -- see RootElevation
// and DeleteRoleAssignment.
func (c *HTTPClient) ElevateAccess(ctx context.Context, userAccessToken string) error {
	endpoint := ARMBase + "/providers/Microsoft.Authorization/elevateAccess?api-version=" +
		APIVersionElevateAccess

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build elevate request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+userAccessToken)
	req.Header.Set("Content-Length", "0")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reach azure resource manager: %v", redactURLError(err))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	// Documented as 200. Accept the whole 2xx range: this endpoint predates the
	// current ARM conventions and returns no body to distinguish them by.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	var armErr struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &armErr)

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%w (%s)", ErrNotGlobalAdmin,
			orDefault(armErr.Error.Code, fmt.Sprintf("http %d", resp.StatusCode)))
	}
	return &APIError{
		Status:      resp.StatusCode,
		Code:        orDefault(armErr.Error.Code, fmt.Sprintf("http %d", resp.StatusCode)),
		Description: truncate(firstLine(armErr.Error.Message), maxErrorBody),
	}
}

// RootElevation returns the ARM id of a principal's root-scope User Access
// Administrator assignment, or "" when there is none.
//
// Called BEFORE elevating, for one reason: if the operator already holds this,
// it was granted by someone else for some other purpose, and removing it
// afterwards would revoke standing access AuthSec never granted. Knowing the
// difference is what makes the cleanup safe.
//
// principalObjectID comes from the oid claim of the operator's own token. That
// claim is not signature-verified (see objectIDFromToken), which is fine here:
// it is used only as a server-side filter, ARM authorises the read and the
// delete against the operator's token independently, and a wrong value can only
// ever produce "found nothing".
func (c *HTTPClient) RootElevation(
	ctx context.Context, userAccessToken, principalObjectID string,
) (string, error) {
	if strings.TrimSpace(principalObjectID) == "" {
		return "", errors.New("cannot look up elevation without the operator's object id")
	}

	q := url.Values{}
	q.Set("api-version", APIVersionRoleAssignments)
	q.Set("$filter", "principalId eq '"+principalObjectID+"'")
	endpoint := ARMBase + "/providers/Microsoft.Authorization/roleAssignments?" + q.Encode()

	var assignments []RoleAssignment
	if err := c.armGet(ctx, userAccessToken, endpoint, &assignments); err != nil {
		return "", err
	}

	for _, a := range assignments {
		// Both conditions matter. Scope "/" alone is not enough -- a principal can
		// hold other roles at root -- and the role id alone is not enough, because
		// User Access Administrator is commonly held at subscription scope.
		if a.Properties.Scope != RootScope {
			continue
		}
		if !strings.EqualFold(path.Base(a.Properties.RoleDefinitionID),
			UserAccessAdministratorRoleDefinitionID) {
			continue
		}
		return a.ID, nil
	}
	return "", nil
}

// DeleteRoleAssignment removes one role assignment by its full ARM id.
//
// 204 means it was already gone, which is the desired end state and therefore
// success -- reporting it as a failure would send an operator to undo something
// that is already undone.
func (c *HTTPClient) DeleteRoleAssignment(
	ctx context.Context, userAccessToken, assignmentID string,
) error {
	if strings.TrimSpace(assignmentID) == "" {
		return errors.New("no role assignment id to delete")
	}

	endpoint := ARMBase + assignmentID + "?api-version=" + APIVersionRoleAssignments

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build delete request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+userAccessToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reach azure resource manager: %v", redactURLError(err))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	var armErr struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &armErr)
	return &APIError{
		Status:      resp.StatusCode,
		Code:        orDefault(armErr.Error.Code, fmt.Sprintf("http %d", resp.StatusCode)),
		Description: truncate(firstLine(armErr.Error.Message), maxErrorBody),
	}
}
