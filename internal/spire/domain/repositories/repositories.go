// Package repositories defines the persistence interfaces of the embedded
// SPIRE control plane.
//
// Every method acts on the workspace carried by ctx (tenancy.WithContext),
// which the caller resolved from a verified credential; no method takes a
// workspace argument. The exceptions are WorkspaceRepository, which reads
// the workspace registry itself, and JoinTokenRepository.Consume, whose
// token decides the workspace.
package repositories

import (
	"context"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
)

// WorkspaceRepository reads the workspace registry (the workspaces table),
// which is not tenant-owned: a row is looked up by its own id or domain to
// resolve a credential's workspace.
type WorkspaceRepository interface {
	GetByID(ctx context.Context, id string) (*models.Tenant, error)
	GetByDomain(ctx context.Context, domain string) (*models.Tenant, error)
	// GetByTrustDomain maps a SPIFFE trust domain (a workspace id or the
	// workspace's domain) to an active workspace.
	GetByTrustDomain(ctx context.Context, trustDomain string) (*models.Tenant, error)
	UpdateVaultMount(ctx context.Context, id, vaultMount string) error
}

// AgentRepository stores attested agents (spire_agents).
type AgentRepository interface {
	Create(ctx context.Context, agent *models.Agent) error
	GetByID(ctx context.Context, id string) (*models.Agent, error)
	GetBySpiffeID(ctx context.Context, spiffeID string) (*models.Agent, error)
	GetByNode(ctx context.Context, nodeID string) (*models.Agent, error)
	Update(ctx context.Context, agent *models.Agent) error
	List(ctx context.Context) ([]*models.Agent, error)
	UpdateLastSeen(ctx context.Context, id string) error
}

// JoinTokenRepository stores node attestation join tokens
// (spire_join_tokens).
type JoinTokenRepository interface {
	Create(ctx context.Context, token *models.JoinToken, tokenHash string) error
	List(ctx context.Context) ([]*models.JoinToken, error)
	Revoke(ctx context.Context, id string) error
	// Consume marks the unused, unexpired, unrevoked token with this hash as
	// used by nodeID, atomically, and returns it (its workspace included).
	// ctx carries no workspace: the token decides it. A non-empty
	// assertedWorkspace must equal the token's workspace, or the token is
	// neither consumed nor returned.
	Consume(ctx context.Context, tokenHash, nodeID, assertedWorkspace string) (*models.JoinToken, error)
}

// WorkloadEntryRepository stores registration entries
// (spire_workload_entries) and the SVIDs issued for them
// (spire_workload_svids).
type WorkloadEntryRepository interface {
	Create(ctx context.Context, entry *models.WorkloadEntry) error
	GetByID(ctx context.Context, id string) (*models.WorkloadEntry, error)
	GetBySpiffeID(ctx context.Context, spiffeID string) (*models.WorkloadEntry, error)
	List(ctx context.Context, filter *models.WorkloadEntryFilter) ([]*models.WorkloadEntry, error)
	Count(ctx context.Context, filter *models.WorkloadEntryFilter) (int, error)
	ListByParent(ctx context.Context, parentID string) ([]*models.WorkloadEntry, error)
	Update(ctx context.Context, entry *models.WorkloadEntry) error
	Delete(ctx context.Context, id string) error
	FindMatchingEntries(ctx context.Context, selectors map[string]string) ([]*models.WorkloadEntry, error)
	RecordSVID(ctx context.Context, svid *models.WorkloadSVID) error
	GetSVIDBySerial(ctx context.Context, serialNumber string) (*models.WorkloadSVID, error)
	MarkSVIDRevoked(ctx context.Context, serialNumber string) error
}

// WorkloadRepository stores directly attested workloads
// (spire_attested_workloads).
type WorkloadRepository interface {
	GetByID(ctx context.Context, id string) (*models.Workload, error)
	GetBySpiffeID(ctx context.Context, spiffeID string) (*models.Workload, error)
	Create(ctx context.Context, workload *models.Workload) error
}

// CertificateRepository stores certificates issued to attested workloads
// (spire_certificates).
type CertificateRepository interface {
	GetBySerialNumber(ctx context.Context, serialNumber string) (*models.Certificate, error)
	GetActiveByWorkload(ctx context.Context, workloadID string) (*models.Certificate, error)
	Create(ctx context.Context, cert *models.Certificate) error
	Revoke(ctx context.Context, id string) error
}

// PolicyRepository stores attestation policies (spire_attestation_policies).
type PolicyRepository interface {
	Create(ctx context.Context, policy *models.AttestationPolicy) error
	FindMatchingPolicy(ctx context.Context, attestationType string, selectors map[string]string) (*models.AttestationPolicy, error)
}

// AuditRepository stores the attest / renew / revoke audit trail
// (spire_icp_audit_logs).
type AuditRepository interface {
	Create(ctx context.Context, log *models.AuditLog) error
	List(ctx context.Context, limit, offset int) ([]*models.AuditLog, error)
}
