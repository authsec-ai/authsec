package igaread

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
)

// PlacedIdentityObjectIDs lists, lowercased, the object ids of the workspace's
// Azure identities the projection placed (azuregraph.PlaceManagedIdentities
// and PlaceAgentIdentities) in any one of the subscriptions, and in any one of
// the resource groups ("<subscription id>/<resource group>"), as the
// inventory's filters of the same names compare them. The discovered-agents
// list matches an agent with no ARM id of its own by these: the agent is where
// its identity is. Read under row-level security for the workspace, so it
// lives here rather than in the agents repository, which is not IGA code.
func PlacedIdentityObjectIDs(ctx context.Context, db *gorm.DB, ws uuid.UUID, subscriptions, groups []string) (bySubscription, byGroup []string, err error) {
	lower := func(in []string) []string {
		out := make([]string, len(in))
		for i, v := range in {
			out[i] = strings.ToLower(v)
		}
		return out
	}
	err = tenancy.InWorkspaceRead(ctx, db, ws, func(tx *gorm.DB) error {
		placed := func(cond string, values []string) ([]string, error) {
			var ids []string
			err := tx.Table("iga_identity_accounts").
				Distinct("lower(provider_attrs->>'object_id')").
				Where("workspace_id = ? AND provider = 'azure' AND lifecycle <> 'retired' AND coalesce(provider_attrs->>'object_id', '') <> ''", ws).
				Where(cond, values).
				Pluck("lower(provider_attrs->>'object_id')", &ids).Error
			return ids, err
		}
		if len(subscriptions) > 0 {
			if bySubscription, err = placed("lower(provider_attrs->>'subscription_id') IN ?", lower(subscriptions)); err != nil {
				return err
			}
		}
		if len(groups) > 0 {
			if byGroup, err = placed("lower(provider_attrs->>'subscription_id') || '/' || lower(provider_attrs->>'resource_group') IN ?", lower(groups)); err != nil {
				return err
			}
		}
		return nil
	})
	return bySubscription, byGroup, err
}
