package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GitHubRepoScanner makes GitHub a discovery channel for the EXISTING agent
// inventory, exactly like the Kubernetes webhook already is.
//
// Nothing here is a new inventory. It enumerates a workspace's repositories,
// applies the versioned rule catalogue to allowlisted declaration files, and
// reports each hit through DiscoveryManager.ReportSighting with
// source="repo_scan". The rows land in discovered_agents alongside the
// Kubernetes sightings, and the existing claim, quarantine and coverage APIs
// govern them unchanged — a repeated scan is an upsert on the same fingerprint,
// not a duplicate.
//
// Two pieces are reused rather than rebuilt:
//   - credentials: the workspace's GitHub App already lives in the connector
//     broker, with the private key in Vault. A second key store for the same
//     App would be strictly worse.
//   - transport: the pagination, rate-limit and conditional-request handling in
//     GitHubProvider, which is covered by its own tests.
type GitHubRepoScanner struct {
	discovery DiscoveryManager
	provider  IGAProvider
	catalog   IGARuleCatalog
}

// NewGitHubRepoScanner wires the scanner to the live GitHub client, taking App
// credentials from the connector broker.
func NewGitHubRepoScanner(db *gorm.DB, vaultClient vault.VaultClient) *GitHubRepoScanner {
	return &GitHubRepoScanner{
		discovery: NewDiscoveryManager(repositories.NewDiscoveryRepository(db)),
		provider:  NewGitHubProviderFromConnector(db, vaultClient),
		catalog:   DefaultRuleCatalog(),
	}
}

// NewGitHubRepoScannerWithProvider injects a provider directly, so the scan can
// be exercised against recorded fixtures without a tenant.
func NewGitHubRepoScannerWithProvider(db *gorm.DB, p IGAProvider) *GitHubRepoScanner {
	return &GitHubRepoScanner{
		discovery: NewDiscoveryManager(repositories.NewDiscoveryRepository(db)),
		provider:  p,
		catalog:   DefaultRuleCatalog(),
	}
}

// GitHubScanResult reports what one scan saw. Repositories that could not be
// read are counted separately from repositories that held nothing: "we could
// not look" and "there was nothing there" are different answers, and collapsing
// them is how a permission problem turns into a false all-clear.
type GitHubScanResult struct {
	SourceID     uuid.UUID `json:"source_id"`
	ReposScanned int       `json:"repos_scanned"`
	ReposFailed  int       `json:"repos_failed"`
	// Excluded by the plan. Reported separately from failures: choosing not to
	// scan something is not the same as being unable to.
	ReposExcluded   int       `json:"repos_excluded"`
	Excluded        []string  `json:"excluded_repositories,omitempty"`
	SelectionMode   string    `json:"selection_mode"`
	ReposTruncated  int       `json:"repos_truncated"`
	FilesFetched    int       `json:"files_fetched"`
	SightingsNew    int       `json:"sightings_new"`
	SightingsBumped int       `json:"sightings_bumped"`
	Complete        bool      `json:"complete_for_selected_scope"`
	Warnings        []string  `json:"warnings,omitempty"`
	ScannedAt       time.Time `json:"scanned_at"`
}

// githubScannerConfig is the per-source config stored on discovery_sources.
//
// Repositories is the scan PLAN. Selection is explicit: a repository is
// selected, or it is excluded, and an excluded repository is reported as
// not_configured rather than quietly contributing nothing. That distinction is
// the difference between "we did not look there" and "there is nothing there".
type githubScannerConfig struct {
	InstallationID    string        `json:"installation_id"`
	AppRegistrationID string        `json:"app_registration_id"`
	ProviderHost      string        `json:"provider_host"`
	Repositories      RepoSelection `json:"repositories"`
	ConnectorID       string        `json:"connector_id,omitempty"`
}

// RepoSelection is how an admin narrows a scan.
//
// Mode "all" means every repository the installation can see — note that the
// installation itself may already be a selected-repository install, so "all"
// is always "all we were granted", never "all the org has". Mode "selected"
// scans only Include; anything else in the installation is excluded and
// reported as such.
type RepoSelection struct {
	Mode    string   `json:"mode"`              // "all" | "selected"
	Include []string `json:"include,omitempty"` // owner/name entries
}

// wants reports whether a repository is in the plan.
func (r RepoSelection) wants(fullName string) bool {
	if r.Mode != "selected" {
		return true
	}
	for _, want := range r.Include {
		if strings.EqualFold(want, fullName) {
			return true
		}
	}
	return false
}

// RepoChoice is one repository offered to an admin for selection, with whether
// the current plan already includes it.
type RepoChoice struct {
	NativeID      string `json:"native_id"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Selected      bool   `json:"selected"`
}

// ListSelectableRepositories returns what the installation can see, so an admin
// can choose before spending API budget on a scan. It is the "select repos or
// all" step, and it reflects the installation grant rather than the whole org:
// a repository GitHub never exposed to us cannot appear here, and its absence
// is a coverage limit, not evidence that it holds no agents.
func (s *GitHubRepoScanner) ListSelectableRepositories(ctx context.Context, workspaceID, sourceID uuid.UUID) ([]RepoChoice, error) {
	src, err := s.discovery.GetSource(workspaceID, sourceID)
	if err != nil {
		return nil, err
	}
	var cfg githubScannerConfig
	if len(src.Config) > 0 {
		_ = json.Unmarshal(src.Config, &cfg)
	}
	pctx := ProviderContext{
		WorkspaceID: workspaceID, IntegrationID: sourceID.String(),
		AppRegistrationID: cfg.AppRegistrationID, InstallationID: cfg.InstallationID,
		ProviderHost: cfg.ProviderHost,
	}
	scopes, err := s.provider.ListScopes(ctx, pctx)
	if err != nil {
		return nil, err
	}
	out := make([]RepoChoice, 0, len(scopes))
	for _, sc := range scopes {
		if sc.Kind != "repository" {
			continue
		}
		out = append(out, RepoChoice{
			NativeID: sc.NativeID, FullName: sc.DisplayName,
			DefaultBranch: sc.DefaultBranch, Selected: cfg.Repositories.wants(sc.DisplayName),
		})
	}
	return out, nil
}

// Scan enumerates the installation's repositories and reports sightings.
//
// It is deliberately conservative about failure: a repository that cannot be
// read is recorded as a warning and the scan continues, and the result is only
// marked complete when every repository was fully inspected. A caller must not
// read an incomplete scan as an authoritative picture.
func (s *GitHubRepoScanner) Scan(ctx context.Context, workspaceID, sourceID uuid.UUID, actor string) (*GitHubScanResult, error) {
	src, err := s.discovery.GetSource(workspaceID, sourceID)
	if err != nil {
		return nil, err
	}
	if src.Kind != models.DiscoverySourceRepoScan {
		return nil, fmt.Errorf("source %s is kind %q; GitHub scanning requires %q",
			sourceID, src.Kind, models.DiscoverySourceRepoScan)
	}
	if !src.Enabled {
		return nil, fmt.Errorf("discovery source %s is disabled", sourceID)
	}

	var cfg githubScannerConfig
	if len(src.Config) > 0 {
		_ = json.Unmarshal(src.Config, &cfg)
	}
	if cfg.ProviderHost == "" {
		cfg.ProviderHost = "github.com"
	}

	pctx := ProviderContext{
		WorkspaceID:       workspaceID,
		IntegrationID:     sourceID.String(),
		AppRegistrationID: cfg.AppRegistrationID,
		InstallationID:    cfg.InstallationID,
		ProviderHost:      cfg.ProviderHost,
	}

	mode := cfg.Repositories.Mode
	if mode == "" {
		mode = "all"
	}
	res := &GitHubScanResult{
		SourceID: sourceID, Complete: true, SelectionMode: mode, ScannedAt: time.Now(),
	}

	scopes, err := s.provider.ListScopes(ctx, pctx)
	if err != nil {
		return nil, fmt.Errorf("enumerate repositories: %w", err)
	}

	for _, scope := range scopes {
		if scope.Kind != "repository" {
			continue
		}
		// Not in the plan. Counted, not silently dropped: an admin must be able
		// to see that this repository was deliberately left out.
		if !cfg.Repositories.wants(scope.DisplayName) {
			res.ReposExcluded++
			res.Excluded = append(res.Excluded, scope.DisplayName)
			continue
		}

		entries, truncated, err := s.provider.ListTree(ctx, pctx, scope)
		if err != nil {
			// A repository we cannot read is a gap in coverage, not an absence
			// of agents, and it must not fail the whole scan.
			res.ReposFailed++
			res.Complete = false
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("%s: %v", scope.DisplayName, err))
			continue
		}
		if truncated {
			// The tree cut off, so files beyond the limit were never seen.
			res.ReposTruncated++
			res.Complete = false
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("%s: git tree truncated; unwalked subtrees not inspected", scope.DisplayName))
		}
		res.ReposScanned++

		// CODEOWNERS once per repository, matched per declaration path below.
		coRules, _ := s.provider.ListCodeowners(ctx, pctx, scope)

		for _, e := range entries {
			rule, ok := s.catalog.MatchRule(e.Path)
			if !ok {
				continue // not a path any rule can interpret; never fetched
			}

			body, err := s.provider.FetchBlob(ctx, pctx, scope, e)
			if err != nil {
				res.ReposFailed++
				res.Complete = false
				res.Warnings = append(res.Warnings,
					fmt.Sprintf("%s:%s: %v", scope.DisplayName, e.Path, err))
				continue
			}
			res.FilesFetched++

			facts, secretRefs, err := rule.Extract(e.Path, body)
			if err != nil || facts == nil {
				// A malformed or uninteresting file is not an agent.
				continue
			}
			// Names only. A secret value is never read, stored or reported.
			if len(secretRefs) > 0 {
				facts["secret_references"] = secretRefs
			}
			if owners := MatchCodeowners(coRules, e.Path); len(owners) > 0 {
				facts["codeowners"] = owners
			}
			facts["repository"] = scope.DisplayName
			facts["path"] = e.Path
			facts["rule_id"] = rule.ID
			facts["rule_version"] = rule.Version
			facts["evidence_mode"] = rule.EvidenceMode
			facts["content_sha256"] = HashBody(body)
			// The blob SHA lets a later scan skip an unchanged file.
			facts["blob_sha"] = e.SHA

			// The fingerprint is what makes a re-scan idempotent: same repo,
			// same path, same row.
			fingerprint := fmt.Sprintf("gh:%s:%s", scope.NativeID, e.Path)

			_, created, err := s.discovery.ReportSighting(workspaceID, actor, SightingInput{
				Source:            models.DiscoverySourceRepoScan,
				DiscoverySourceID: &sourceID,
				Fingerprint:       fingerprint,
				DisplayName:       declarationName(facts, e.Path),
				Metadata:          facts,
				// Anything found by a repo scan came from a version-controlled
				// declaration, so it is automated by construction — the scanner
				// never has to guess at origin.
				DeploymentOrigin: models.DeploymentOriginAutomated,
			})
			if err != nil {
				res.Warnings = append(res.Warnings,
					fmt.Sprintf("%s:%s: report sighting: %v", scope.DisplayName, e.Path, err))
				res.Complete = false
				continue
			}
			if created {
				res.SightingsNew++
			} else {
				res.SightingsBumped++
			}
		}
	}

	return res, nil
}

// declarationName prefers the name the declaration gives itself, falling back
// to the path so a row is never anonymous.
func declarationName(facts map[string]interface{}, path string) string {
	if v, ok := facts["name"].(string); ok && v != "" {
		return v
	}
	return path
}
