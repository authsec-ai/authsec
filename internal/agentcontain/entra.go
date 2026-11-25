package agentcontain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/authsec-ai/authsec/internal/azure"
)

// The entra level (levels.go): disable the service principal (or agent
// identity) through Microsoft Graph and remove its Azure role assignments.
//
// Permissions (customer's consent): PATCH /servicePrincipals/{id}
// {accountEnabled:false} needs the Graph application permission
// Application.ReadWrite.All (an agent identity: AgentIdentity.EnableDisable.All
// or AgentIdentity.ReadWrite.All -- UNVERIFIED names, Graph's agent identity
// API is in preview). AuthSec's consent today requests read permissions only
// (internal/azure/rbac.go RequiredGraphAppRoles), so the level is refused with
// permission_missing until the tenant grants one. Removing role assignments
// needs Microsoft.Authorization/roleAssignments/write and /delete on each
// subscription (Role Based Access Control Administrator), as Azure access
// policies do.

// EntraGraphPermission is the Graph application permission the PATCH needs.
const EntraGraphPermission = "Application.ReadWrite.All"

// EntraAgentGraphPermissions are the agent-identity permissions that also
// allow it (UNVERIFIED names; Graph's agent identity API is in preview).
var EntraAgentGraphPermissions = []string{"AgentIdentity.EnableDisable.All", "AgentIdentity.ReadWrite.All"}

// Entra is what the entra level does in one tenant: Graph for the account,
// ARM for role assignments. Not found is ErrNotFound (or a nil read),
// refusals ErrDenied.
type Entra interface {
	AccountEnabled(ctx context.Context, objectID string) (bool, error)
	SetAccountEnabled(ctx context.Context, objectID string, enabled bool) error
	ListRoleAssignments(ctx context.Context, subscriptionID, principalID string) ([]azure.RoleAssignment, error)
	GetRoleAssignment(ctx context.Context, id string) (*azure.RoleAssignment, error)
	DeleteRoleAssignment(ctx context.Context, id string) error
	PutRoleAssignment(ctx context.Context, spec azure.RoleAssignmentSpec) error
}

// EntraAccountBefore is an entra_account step's before-state. Release
// re-enables the account only when AuthSec disabled it (WasEnabled).
type EntraAccountBefore struct {
	ObjectID   string `json:"object_id"`
	WasEnabled bool   `json:"was_enabled"`
}

// EntraRoleBefore is an azure_role_assignment step's before-state: the
// spec that recreates the assignment.
type EntraRoleBefore struct {
	SubscriptionID string                   `json:"subscription_id"`
	Spec           azure.RoleAssignmentSpec `json:"spec"`
}

// EntraEngine runs the entra level's steps (StepRunner).
type EntraEngine struct {
	API           Entra
	ObjectID      string
	Subscriptions []string
}

// Plan lists the steps: the account, then every role assignment of the
// principal in the subscriptions (inherited assignments from a management
// group are listed with their scope and removed there only if the caller
// may; a refusal fails that step alone).
func (e *EntraEngine) Plan(ctx context.Context) ([]Step, error) {
	out := []Step{{Kind: StepEntraAccount, Target: e.ObjectID}}
	for _, sub := range e.Subscriptions {
		as, err := e.API.ListRoleAssignments(ctx, sub, e.ObjectID)
		if err != nil {
			if Denied(err) {
				return nil, refused("permission_missing", "listing role assignments in subscription %s was refused: %v", sub, err)
			}
			return nil, err
		}
		for _, a := range as {
			if !strings.EqualFold(a.Properties.PrincipalID, e.ObjectID) {
				continue
			}
			b, _ := json.Marshal(EntraRoleBefore{SubscriptionID: sub, Spec: azure.SpecOf(a)})
			out = append(out, Step{Kind: StepAzureRoleAssignment, Target: strings.ToLower(a.ID), Before: b})
		}
	}
	return out, nil
}

func entraErr(op, target string, err error) error {
	switch {
	case Denied(err):
		return refused("permission_missing", "%s on %s was refused: AuthSec's app lacks the permission (Graph %s, or Role Based Access Control Administrator on the subscription): %v",
			op, target, EntraGraphPermission, err)
	case errors.Is(err, ErrNotFound):
		return refused("target_gone", "%s: %s no longer exists", op, target)
	}
	return err
}

// Before implements StepRunner.
func (e *EntraEngine) Before(ctx context.Context, st *Step) (bool, error) {
	switch st.Kind {
	case StepEntraAccount:
		on, err := e.API.AccountEnabled(ctx, st.Target)
		if err != nil {
			return false, entraErr("read accountEnabled", st.Target, err)
		}
		st.Before, _ = json.Marshal(EntraAccountBefore{ObjectID: st.Target, WasEnabled: on})
		if !on {
			st.Error = "the account is already disabled; release leaves it disabled"
			return true, nil
		}
	case StepAzureRoleAssignment:
		if len(st.Before) == 0 {
			return false, fmt.Errorf("role assignment step %s has no before-state", st.Target)
		}
	default:
		return false, fmt.Errorf("unknown step kind %q", st.Kind)
	}
	return false, nil
}

// Apply implements StepRunner.
func (e *EntraEngine) Apply(ctx context.Context, st *Step) error {
	switch st.Kind {
	case StepEntraAccount:
		if err := e.API.SetAccountEnabled(ctx, st.Target, false); err != nil {
			return entraErr("PATCH accountEnabled=false", st.Target, err)
		}
		on, err := e.API.AccountEnabled(ctx, st.Target)
		if err != nil {
			return err
		}
		if on {
			return fmt.Errorf("readback: %s accountEnabled is still true", st.Target)
		}
		st.After, _ = json.Marshal(map[string]any{"account_enabled": false})
	case StepAzureRoleAssignment:
		if err := e.API.DeleteRoleAssignment(ctx, st.Target); err != nil && !errors.Is(err, ErrNotFound) {
			return entraErr("delete role assignment", st.Target, err)
		}
		a, err := e.API.GetRoleAssignment(ctx, st.Target)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if a != nil {
			return fmt.Errorf("readback: role assignment %s still exists", st.Target)
		}
		st.After, _ = json.Marshal(map[string]any{"removed": true})
	default:
		return fmt.Errorf("unknown step kind %q", st.Kind)
	}
	return nil
}

// Restore implements StepRunner: the account is re-enabled only when AuthSec
// disabled it; a removed assignment is recreated from its recorded spec.
func (e *EntraEngine) Restore(ctx context.Context, st *Step) error {
	switch st.State {
	case StepSkipped, StepFailed, StepRestored:
		return nil
	}
	if len(st.Before) == 0 {
		return nil
	}
	switch st.Kind {
	case StepEntraAccount:
		var b EntraAccountBefore
		if err := json.Unmarshal(st.Before, &b); err != nil {
			return err
		}
		if !b.WasEnabled {
			return nil
		}
		if err := e.API.SetAccountEnabled(ctx, st.Target, true); err != nil {
			if errors.Is(err, ErrNotFound) {
				st.Error = "the service principal no longer exists; nothing to re-enable"
				return nil
			}
			return entraErr("PATCH accountEnabled=true", st.Target, err)
		}
		on, err := e.API.AccountEnabled(ctx, st.Target)
		if err != nil {
			return err
		}
		if !on {
			return fmt.Errorf("readback: %s accountEnabled is still false", st.Target)
		}
	case StepAzureRoleAssignment:
		var b EntraRoleBefore
		if err := json.Unmarshal(st.Before, &b); err != nil {
			return err
		}
		if err := e.API.PutRoleAssignment(ctx, b.Spec); err != nil {
			return entraErr("recreate role assignment", st.Target, err)
		}
		a, err := e.API.GetRoleAssignment(ctx, st.Target)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if a == nil {
			return fmt.Errorf("readback: role assignment %s was not recreated", st.Target)
		}
	default:
		return fmt.Errorf("unknown step kind %q", st.Kind)
	}
	return nil
}

// Readback implements StepRunner.
func (e *EntraEngine) Readback(ctx context.Context, st *Step) (bool, string, error) {
	switch st.Kind {
	case StepEntraAccount:
		on, err := e.API.AccountEnabled(ctx, st.Target)
		if err != nil {
			return false, "", err
		}
		return !on, fmt.Sprintf("accountEnabled %v", on), nil
	case StepAzureRoleAssignment:
		a, err := e.API.GetRoleAssignment(ctx, st.Target)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return false, "", err
		}
		return a == nil, "role assignment present", nil
	}
	return false, "", fmt.Errorf("unknown step kind %q", st.Kind)
}
