package ghgraph

import (
	"github.com/google/uuid"
)

// The repo-scan half of the GitHub graph.
//
// The repository scanner (services/discovery_github_scanner.go) writes its
// findings to discovered_agents under a repo_scan discovery source, not to the
// IGA tables, and it has no scan-run row the support model can point at -- its
// runs live in discovery_scan_runs. So its support names the discovery source
// alone (CONTRACT, "Provenance"), and "confirmed by this run" is decided from
// the inventory itself: a sighting the run reported had its last_seen_at
// advanced after the run began.

// DeclaredSighting is one repo-scan discovered agent, reduced to what the graph
// needs.
type DeclaredSighting struct {
	ID            uuid.UUID
	Fingerprint   string
	DisplayName   string
	Repository    string // owner/name, from the finding's own metadata
	Path          string
	RuleID        string
	Branch        string
	DefaultBranch bool
	CountsAsAgent bool
}

// DeclaredPartitionKey is the one partition a repo-scan source's support lives
// in. Coverage is decided per repository at reconcile time from the run's own
// record of what it excluded, so the key does not need to carry it.
//
// Frozen once deployed, for the reason Partition.Key gives.
func DeclaredPartitionKey(sourceID uuid.UUID) string {
	return sourceID.String() + "|repo_scan|" + KindDeclaredAgent
}

// ProjectDeclared maps repo-scan sightings to workloads.
func ProjectDeclared(host, account string, in []DeclaredSighting) []Node {
	out := make([]Node, 0, len(in))
	for _, s := range in {
		name := s.DisplayName
		if name == "" {
			name = s.Path
		}
		if name == "" {
			name = s.Fingerprint
		}
		native := s.Fingerprint
		if s.Repository != "" && s.Path != "" {
			native = s.Repository + "/" + s.Path
		}
		out = append(out, Node{
			SourceKey:   DeclaredAgentKey(host, s.Fingerprint),
			Kind:        KindDeclaredAgent,
			DisplayName: name,
			Attrs: withScope(map[string]any{
				"native_id":           native,
				"fingerprint":         s.Fingerprint,
				"discovered_agent_id": s.ID.String(),
				"repository":          s.Repository,
				"path":                s.Path,
				"rule_id":             s.RuleID,
				"branch":              s.Branch,
				"is_default_branch":   s.DefaultBranch,
				"counts_as_agent":     s.CountsAsAgent,
				// A parsed file is a declaration, never a deployment: the same
				// claim discovered_agents.evidence_mode records.
				"evidence_mode": "declared",
			}, account, s.Repository),
		})
	}
	return out
}
