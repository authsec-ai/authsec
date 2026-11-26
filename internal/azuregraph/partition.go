package azuregraph

import (
	"strings"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// Partition is the evidence boundary reconciliation may never cross (§2.7): the
// rows ONE connector's pass is responsible for, of one class or edge type. A
// row may be ended only when a pass over its partition read every surface that
// writes it, and did not see the row.
//
// Partitions are per connector because Azure's two halves fail separately: a
// subscription can lose Reader while the directory stays readable, and a
// tenant can lose consent while every subscription is still readable. One
// half going blind must never retire what the other can still see.
type Partition struct {
	ConnectorID uuid.UUID
	// Target is "node" for an object class, else the edge table it owns.
	Target string
	// Class is the node class (identity, resource, entitlement, workload) or
	// the edge type (access_edge, member_of, executes_as, can_assume).
	Class string
}

// Partition targets.
const (
	TargetNode         = "node"
	TargetAccessEdge   = "access_edge"
	TargetRelationship = "relationship"
	// TargetAgentNode is the second support of objects Microsoft Entra Agent
	// ID listed (attrs.agent_listed): it closes only when those listings were
	// read in full, so an agent only they return outlives a pass that could
	// not read them, as anything else outlives a surface that failed.
	TargetAgentNode = "agent_node"
)

// ClassCanAssumeAgent is the can_assume partition of edges that land on an
// Agent ID object: who obtains an agent's tokens, a blueprint's federated
// credentials, and its owners. They close only when Agent ID was read in full.
const ClassCanAssumeAgent = "can_assume_agent"

// ClassAccessEdgeAgent is the access-edge partition of the grants agent
// identities inherit from their blueprints (derived, never read off the
// agent): they close only when Agent ID and every blueprint's inheritable
// permissions were read in full.
const ClassAccessEdgeAgent = "access_edge_agent"

// agentSurfaces are the Microsoft Entra Agent ID listings.
var agentSurfaces = []string{
	models.SurfaceEntraAgentIdentities, models.SurfaceEntraAgentBlueprints,
	models.SurfaceEntraAgentBlueprintPrincipals, models.SurfaceEntraAgentUsers,
}

// Key is the value stamped on every row the partition owns and the scope of
// every retirement query. FROZEN once deployed: a row written under another
// spelling is never reconciled, and a support row no query matches reads as
// "nothing supports this object", which retires it.
func (p Partition) Key() string {
	return strings.Join([]string{"azure", p.ConnectorID.String(), p.Target, p.Class}, "|")
}

// partitionSpec is one partition and the surfaces that must all have been read
// in full for a pass to end rows in it.
type partitionSpec struct {
	target, class string
	surfaces      []string
}

// tenantPartitions are what a tenant (Microsoft Graph) pass owns.
var tenantPartitions = []partitionSpec{
	{TargetNode, models.ObjectIdentity, []string{
		models.SurfaceEntraUsers, models.SurfaceEntraGroups,
		models.SurfaceEntraApplications, models.SurfaceEntraServicePrincipals}},
	// API-plane resources (one per permission an API exposes) exist because a
	// grant names them, so they share the grants' surfaces.
	{TargetNode, models.ObjectResource, []string{
		models.SurfaceEntraServicePrincipals, models.SurfaceEntraAppRoleAssignments,
		models.SurfaceEntraDelegatedGrants}},
	{TargetNode, models.ObjectEntitlement, []string{
		models.SurfaceEntraDirectoryRoles, models.SurfaceEntraAppRoleAssignments,
		models.SurfaceEntraDelegatedGrants}},
	{TargetAccessEdge, TargetAccessEdge, []string{
		models.SurfaceEntraDirectoryRoles, models.SurfaceEntraAppRoleAssignments,
		models.SurfaceEntraDelegatedGrants}},
	{TargetRelationship, models.RelTypeMemberOf, []string{
		models.SurfaceEntraGroups, models.SurfaceEntraGroupMembers}},
	{TargetRelationship, models.RelTypeCanAssume, []string{
		models.SurfaceEntraApplications, models.SurfaceEntraFederatedCredentials,
		models.SurfaceEntraOwners}},
	{TargetAgentNode, models.ObjectIdentity, agentSurfaces},
	{TargetRelationship, ClassCanAssumeAgent, append([]string{
		models.SurfaceEntraApplications, models.SurfaceEntraFederatedCredentials,
		models.SurfaceEntraOwners}, agentSurfaces...)},
	{TargetAccessEdge, ClassAccessEdgeAgent, append([]string{
		models.SurfaceEntraAppRoleAssignments, models.SurfaceEntraDelegatedGrants,
		models.SurfaceEntraAgentInheritance}, agentSurfaces...)},
}

// subscriptionPartitions are what a subscription (ARM) pass owns.
var subscriptionPartitions = []partitionSpec{
	{TargetNode, models.ObjectResource, []string{models.SurfaceAzureResources}},
	{TargetNode, models.ObjectEntitlement, []string{
		models.SurfaceAzureRoleAssignments, models.SurfaceAzureKeyVaultAccessPolicies}},
	// Workloads come from two surfaces (models.AzureFoundryRuntimeKinds are
	// the Foundry surface's): either one short, and none is ended.
	{TargetNode, models.ObjectWorkload, []string{models.SurfaceAzureWorkloads, models.SurfaceAzureFoundry}},
	{TargetAccessEdge, TargetAccessEdge, []string{
		models.SurfaceAzureRoleAssignments, models.SurfaceAzureKeyVaultAccessPolicies}},
	{TargetRelationship, models.RelTypeExecutesAs, []string{models.SurfaceAzureWorkloads, models.SurfaceAzureFoundry}},
	{TargetRelationship, models.RelTypeCanAssume, []string{models.SurfaceAzureIdentityFederation}},
}

// Pass is one finished discovery pass: the reading a projection applies.
type Pass struct {
	WorkspaceID uuid.UUID
	ConnectorID uuid.UUID
	// ScopeKind is the connector's: tenant or subscription.
	ScopeKind string
	// ScopeID is the tenant id or subscription id; TenantID the tenant either
	// way.
	ScopeID  string
	TenantID string
	// ScopeLabel is the subscription's display name; empty for a tenant pass
	// (the tenant is labelled by its id).
	ScopeLabel string
	RunID      uuid.UUID
	// Stage is the subscription's environment from its tags (production,
	// non_production, unknown); empty for a tenant pass.
	Stage string
	// Generation is the pass's: the cloud_* rows it confirmed carry it.
	Generation int
	Coverage   models.ScanCoverage
}

// Partition returns this pass's partition of a target and class.
func (p Pass) Partition(target, class string) Partition {
	return Partition{ConnectorID: p.ConnectorID, Target: target, Class: class}
}

// specs returns the partitions this pass owns.
func (p Pass) specs() []partitionSpec {
	if p.ScopeKind == models.CloudScopeTenant {
		return tenantPartitions
	}
	return subscriptionPartitions
}

// agentsRead reports whether this pass read every Agent ID listing in full.
func (p Pass) agentsRead() bool {
	for _, s := range agentSurfaces {
		if !p.Coverage.Surfaces[s].Authoritative() {
			return false
		}
	}
	return true
}

// CanEnd reports whether this pass may END rows in a partition: it finished,
// and read every surface that writes the partition in full. Anything less
// yields stale, never ended -- a permissions outage must read as an outage,
// not as a mass revocation.
func (p Pass) CanEnd(spec partitionSpec) bool {
	if p.Coverage.Status == models.ScanStatusFailed || p.Coverage.Status == models.ScanStatusRunning {
		return false
	}
	for _, s := range spec.surfaces {
		if !p.Coverage.Surfaces[s].Authoritative() {
			return false
		}
	}
	return true
}
