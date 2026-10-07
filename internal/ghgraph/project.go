// Package ghgraph turns a GitHub IGA scan into the shared iga_* graph under
// provider 'github'.
//
// A SIBLING OF internal/k8sgraph, NOT AN EDIT OF THE LEGACY WRITER. The GitHub
// IGA pipeline (services/iga_service.go) already writes canonical rows, but
// they are unkeyed (an empty source_key), duplicated on every scan, never ended,
// and read by the existing GitHub screens exactly as they are. Changing them
// would change those screens. So this package projects the same scan a second
// time, into KEYED rows the unified inventory can list, support and retire --
// and the legacy rows stay exactly as they were, invisible to it.
//
// Nothing here opens a database connection. It maps a scan to rows; the
// service writes them. The split is what makes the mapping testable, and the
// mapping is where a silent error becomes a wrong answer about who can do what.
package ghgraph

import (
	"strings"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// Sep is the unit separator joining source-key segments: the same one
// internal/igagraph and internal/k8sgraph use. It cannot occur in a GitHub
// login, repository name, path or node id, so no join is ambiguous.
const Sep = "\x1f"

// The kinds the unified projections write (CONTRACT, "Kinds").
const (
	KindRepository      = "github_repository"
	KindAppInstallation = "github_app_installation"
	KindDeployKey       = "github_deploy_key"
	KindCopilotAgent    = "github_copilot_agent"
	KindActionsWorkflow = "github_actions_workflow"
	KindDeclaredAgent   = "github_declared_agent"
)

// ScopeKindOrg is the scope every GitHub row is listed under.
const ScopeKindOrg = "github_org"

// WorkflowRuleID is the rule whose repo declarations are Actions workflows that
// invoke an agent. It is the FIRST rule the catalogue matches for a workflow
// path, which is the one the scan records on the observation.
const WorkflowRuleID = "workflow.agent-invocation"

// Key builds a namespaced source key: github ␟ host ␟ kind ␟ part ␟ part…
//
// THE ONLY PLACE A KEY IS FORMATTED. Two spellings of a key is the duplication
// bug wearing a different hat: the second spelling creates a second node that
// looks like a real one. The host is in the key because github.com and a GHES
// host number their objects independently.
func Key(host, kind string, parts ...string) string {
	return models.ProviderGitHub + Sep + host + Sep + kind + Sep + strings.Join(parts, Sep)
}

// RepositoryKey identifies a repository by its immutable id, never by
// full_name, which changes on rename or transfer.
func RepositoryKey(host, repoID string) string { return Key(host, "repository", repoID) }

// InstallationKey identifies one App installation. ONE per installation: the
// legacy writer records it once per repository it can see, which is the same
// principal counted N times.
func InstallationKey(host, installationID string) string {
	return Key(host, "app_installation", installationID)
}

// DeployKeyKey identifies a deploy key. GitHub numbers deploy keys globally,
// and one key belongs to exactly one repository.
func DeployKeyKey(host, keyID string) string { return Key(host, "deploy_key", keyID) }

// DeployKeyCredentialKey identifies the key's credential metadata.
func DeployKeyCredentialKey(host, keyID string) string {
	return Key(host, "deploy_key_credential", keyID)
}

// DeployKeyGrantKey identifies the statement a deploy key carries, and the
// grant edge that hangs off it: one key, one repository, one right.
func DeployKeyGrantKey(host, keyID string) string { return Key(host, "deploy_key_grant", keyID) }

// CopilotAgentKey identifies a provider-declared agent. The agent endpoint is
// per repository and its ids are not documented as global, so the repository
// is part of the identity.
func CopilotAgentKey(host, repoID, agentID string) string {
	return Key(host, "copilot_agent", repoID, agentID)
}

// WorkflowKey identifies a workflow file in a repository.
func WorkflowKey(host, repoID, path string) string {
	return Key(host, "actions_workflow", repoID, path)
}

// DeclaredAgentKey identifies a repo-scan sighting by the fingerprint
// discovered_agents is unique on, so a re-scan upserts the same node.
func DeclaredAgentKey(host, fingerprint string) string {
	return Key(host, "declared_agent", fingerprint)
}

// ScopeAttrs are the CONTRACT scope keys every row carries in provider_attrs.
//
// scope_id is the installation's account when known, else the owner half of
// the repository's full_name: an installation lives on exactly one account, so
// the two agree on real data, and the fallback keeps a row listable when the
// integration predates the account being recorded.
func ScopeAttrs(account, fullName string) map[string]any {
	scope := account
	if scope == "" {
		if owner, _, ok := strings.Cut(fullName, "/"); ok {
			scope = owner
		}
	}
	var sub any
	if fullName != "" {
		sub = fullName
	}
	return map[string]any{
		"scope_kind":  ScopeKindOrg,
		"scope_id":    scope,
		"scope_label": scope,
		"sub_scope":   sub,
	}
}

// withScope merges the scope keys into a row's own attributes.
func withScope(attrs map[string]any, account, fullName string) map[string]any {
	for k, v := range ScopeAttrs(account, fullName) {
		attrs[k] = v
	}
	return attrs
}

/* -------------------------------- the input ------------------------------- */

// Snapshot is what one GitHub IGA scan observed, reduced to what the graph
// needs. The service fills it while the scan runs; nothing here reads GitHub.
type Snapshot struct {
	IntegrationID  uuid.UUID
	Host           string
	Account        string // iga_integrations.account_native_id
	InstallationID string // the verified binding; "" writes no installation
	Repos          []Repo
}

// Repo is one repository scope and what the scan read inside it.
type Repo struct {
	// NativeID is the scope's recognition key: the node id when GitHub gave
	// one, else the numeric id. It is what every other key in the repository
	// hangs off, so it must be the same value the legacy scan recorded.
	NativeID      string
	NodeID        string
	FullName      string
	DefaultBranch string
	Archived      bool

	// Coverage is the scan's state per object class in this repository.
	//
	// ABSENT MEANS THE READ SUCCEEDED. The scan only records a class it
	// degraded, declined, or found something in; a listing that succeeded and
	// returned nothing leaves no entry. Present and not complete means it could
	// not look, which is never evidence of absence.
	Coverage map[string]string

	DeployKeys    []DeployKey
	CopilotAgents []CopilotAgent
	Workflows     []Workflow
}

// DeployKey is one deploy key and the right it carries.
type DeployKey struct {
	ID    string
	Title string
	// Rights is GitHub's own wording, {"contents": "read"|"write"}.
	Rights map[string]string
	// Conditional marks a grant whose effect depends on controls the scan
	// cannot observe; it keeps the edge partial with an unknown conclusion.
	Conditional bool
}

// CopilotAgent is one provider-declared agent.
type CopilotAgent struct {
	ID          string
	Name        string
	Description string
	Tools       []string
}

// Workflow is one Actions workflow the scan recorded as an agent invocation.
type Workflow struct {
	Path string
	Name string
}

/* ------------------------------- the output ------------------------------- */

// Node is a vertex to upsert: an identity, resource or workload.
//
// Every node's Attrs carries native_id, the readable id the inventory shows
// (a repository's full_name, "<full_name>/keys/<id>" for a deploy key, ...):
// the source key's tail is an opaque node id, and nobody recognises one.
type Node struct {
	SourceKey   string
	Kind        string // account_kind | resource_kind | runtime_kind
	DisplayName string
	Partition   Partition
	// Attrs is written to provider_attrs. Structure only -- never a value that
	// could be a credential.
	Attrs map[string]any
}

// Credential is a deploy key's non-secret metadata.
type Credential struct {
	SourceKey     string
	IdentityKey   string
	KeyIdentifier string
}

// Statement is the right a deploy key carries on its repository.
type Statement struct {
	SourceKey   string
	ResourceKey string
	Rights      map[string]string
	NativeScope string
	Partition   Partition
}

// Grant is one deploy key -> statement edge, on the repository.
type Grant struct {
	SourceKey    string
	SubjectKey   string
	StatementKey string
	ResourceKey  string
	NativeScope  string
	Partition    Partition
	// CalculationState is "complete" only when GitHub stated the right in full
	// and nothing the scan cannot see conditions it.
	CalculationState    string
	EffectiveConclusion string
}

// Result is everything one scan projects to.
type Result struct {
	Resources   []Node
	Identities  []Node
	Workloads   []Node
	Credentials []Credential
	Statements  []Statement
	Grants      []Grant
}

// Project maps a scan to graph rows.
//
// Like k8sgraph it writes NO iga_agents rows. The legacy pipeline already
// promotes Copilot agents to iga_agents; a second agent row per agent would
// make every name ambiguous to the Kubernetes bridge, which then proposes
// nothing (§2.2, E16).
func Project(s Snapshot) Result {
	var res Result
	host := s.Host

	if s.InstallationID != "" {
		res.Identities = append(res.Identities, Node{
			SourceKey:   InstallationKey(host, s.InstallationID),
			Kind:        KindAppInstallation,
			DisplayName: "installation " + s.InstallationID,
			Partition:   Partition{IntegrationID: s.IntegrationID, Class: ClassInstallation},
			Attrs: withScope(map[string]any{
				"native_id":       s.InstallationID,
				"installation_id": s.InstallationID,
				"account":         s.Account,
				"provider_host":   host,
			}, s.Account, ""),
		})
	}

	for i := range s.Repos {
		r := s.Repos[i]
		repoKey := RepositoryKey(host, r.NativeID)
		part := func(class string) Partition {
			return Partition{IntegrationID: s.IntegrationID, Repo: r.NativeID, Class: class}
		}
		nodeID := r.NodeID
		if nodeID == "" {
			nodeID = r.NativeID
		}

		res.Resources = append(res.Resources, Node{
			SourceKey:   repoKey,
			Kind:        KindRepository,
			DisplayName: r.FullName,
			Partition:   part(ClassRepository),
			Attrs: withScope(map[string]any{
				"native_id":      r.FullName,
				"full_name":      r.FullName,
				"node_id":        nodeID,
				"default_branch": r.DefaultBranch,
				"archived":       r.Archived,
			}, s.Account, r.FullName),
		})

		for _, k := range r.DeployKeys {
			idKey := DeployKeyKey(host, k.ID)
			stKey := DeployKeyGrantKey(host, k.ID)
			readOnly := true
			for _, v := range k.Rights {
				if strings.EqualFold(v, "write") || strings.EqualFold(v, "admin") {
					readOnly = false
				}
			}
			res.Identities = append(res.Identities, Node{
				SourceKey:   idKey,
				Kind:        KindDeployKey,
				DisplayName: k.Title,
				Partition:   part(ClassDeployKey),
				Attrs: withScope(map[string]any{
					"native_id":  r.FullName + "/keys/" + k.ID,
					"key_id":     k.ID,
					"title":      k.Title,
					"read_only":  readOnly,
					"repository": r.FullName,
				}, s.Account, r.FullName),
			})
			res.Credentials = append(res.Credentials, Credential{
				SourceKey:     DeployKeyCredentialKey(host, k.ID),
				IdentityKey:   idKey,
				KeyIdentifier: k.ID,
			})
			res.Statements = append(res.Statements, Statement{
				SourceKey:   stKey,
				ResourceKey: repoKey,
				Rights:      k.Rights,
				NativeScope: r.NativeID,
				Partition:   part(ClassDeployKey),
			})
			calc, conclusion := "complete", "effective"
			if k.Conditional || len(k.Rights) == 0 {
				// A path exists, but whether it resolves depends on what we
				// cannot see. "effective" would be a claim the evidence does
				// not support -- the same rule the legacy writer applies.
				calc, conclusion = "partial", "unknown"
			}
			res.Grants = append(res.Grants, Grant{
				SourceKey:           stKey,
				SubjectKey:          idKey,
				StatementKey:        stKey,
				ResourceKey:         repoKey,
				NativeScope:         r.NativeID,
				Partition:           part(ClassDeployKey),
				CalculationState:    calc,
				EffectiveConclusion: conclusion,
			})
		}

		for _, a := range r.CopilotAgents {
			name := a.Name
			if name == "" {
				name = a.ID
			}
			res.Workloads = append(res.Workloads, Node{
				SourceKey:   CopilotAgentKey(host, r.NativeID, a.ID),
				Kind:        KindCopilotAgent,
				DisplayName: name,
				Partition:   part(ClassCopilotAgent),
				Attrs: withScope(map[string]any{
					"native_id":      r.FullName + "/" + name,
					"agent_id":       a.ID,
					"name":           a.Name,
					"description":    a.Description,
					"declared_tools": a.Tools,
					"repository":     r.FullName,
				}, s.Account, r.FullName),
			})
		}

		for _, w := range r.Workflows {
			name := w.Name
			if name == "" {
				name = w.Path
			}
			res.Workloads = append(res.Workloads, Node{
				SourceKey:   WorkflowKey(host, r.NativeID, w.Path),
				Kind:        KindActionsWorkflow,
				DisplayName: name,
				Partition:   part(ClassWorkflow),
				Attrs: withScope(map[string]any{
					"native_id":  r.FullName + "/" + w.Path,
					"path":       w.Path,
					"name":       w.Name,
					"repository": r.FullName,
				}, s.Account, r.FullName),
			})
		}
	}
	return res
}
