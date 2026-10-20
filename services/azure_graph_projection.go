package services

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/authsec-ai/authsec/internal/azuregraph"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* azure_graph_projection.go puts what Azure discovery found into the shared
   IGA graph, so Azure identities, grants, resources, workloads and federation
   appear wherever the product reads the graph.

   Runs at the end of each discovery run, after every pass has finished, behind
   the same switch as the AWS and Kubernetes projections (IGA_GRAPH_PROJECTION):
   off, discovery is unchanged and nothing is written to iga_*.

   Each pass is projected in its own transaction, the tenant pass first so the
   subscription passes' grants and workloads find the identities they name.
   A pass is a reading of ONE connector; projecting it alone means a failure in
   one subscription leaves the others' projections standing. The mapping and
   the reconciliation rules are internal/azuregraph's. */

// projectGraph projects every finished pass of one discovery run.
func (s *AzureOnboardingService) projectGraph(ctx context.Context, workspaceID uuid.UUID, tenantID string, tenantPass *azurePassResult, subPasses []*azurePassResult) {
	gate := GraphProjection()
	if gate == nil || !gate.Enabled() {
		return
	}
	var passes []azuregraph.Pass
	if tenantPass != nil {
		passes = append(passes, s.graphPass(workspaceID, tenantID, models.CloudScopeTenant, tenantID, tenantPass))
	}
	for _, sp := range subPasses {
		subID, stage, label := "", "", ""
		if c, err := s.connectors.Get(workspaceID, sp.ConnectorID); err == nil {
			a := c.AzureSubscriptionAttrs()
			subID, stage, label = c.ScopeID, a.Stage, a.DisplayName
		}
		p := s.graphPass(workspaceID, tenantID, models.CloudScopeSubscription, subID, sp)
		p.Stage, p.ScopeLabel = stage, label
		passes = append(passes, p)
	}
	for _, p := range passes {
		if ctx.Err() != nil {
			return
		}
		started := time.Now()
		var res *azuregraph.Result
		// One transaction per pass, under row-level security for its workspace.
		err := tenancy.InWorkspace(ctx, s.db, p.WorkspaceID, func(tx *gorm.DB) error {
			r, err := azuregraph.ProjectPass(tx, p, time.Now())
			res = r
			return err
		})
		switch {
		case errors.Is(err, azuregraph.ErrSuperseded):
			log.Printf("[azure] graph: pass %s on connector %s was superseded; the newer pass projects instead", p.RunID, p.ConnectorID)
		case err != nil:
			log.Printf("[azure] graph: projecting pass %s on connector %s failed: %v", p.RunID, p.ConnectorID, err)
		default:
			log.Printf("[azure] graph: %s %s projected in %s: %d identities, %d resources, %d entitlements, %d workloads, "+
				"%d credentials, %d grants, %d relationships (%d unresolved); %d partitions closed, %d stale, %d objects retired",
				p.ScopeKind, p.ScopeID, time.Since(started).Round(time.Millisecond),
				res.Identities, res.Resources, res.Entitlements, res.Workloads, res.Credentials,
				res.AccessEdges, res.Relationships, res.Unresolved,
				res.Reconcile.PartitionsClosed, res.Reconcile.PartitionsStale, res.Reconcile.ObjectsRetired)
		}
	}
}

func (s *AzureOnboardingService) graphPass(workspaceID uuid.UUID, tenantID, scopeKind, scopeID string, r *azurePassResult) azuregraph.Pass {
	return azuregraph.Pass{
		WorkspaceID: workspaceID, ConnectorID: r.ConnectorID, ScopeKind: scopeKind, ScopeID: scopeID,
		TenantID: tenantID, RunID: r.RunID, Generation: r.Generation, Coverage: r.Coverage,
	}
}
