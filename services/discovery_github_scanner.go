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
//   - credentials: the workspace's single GitHub App registration, with the
//     private key in Vault. That key grants access across every installation of
//     the App, so a second store holding a copy would be strictly worse.
//   - transport: the pagination, rate-limit and conditional-request handling in
//     GitHubProvider, which is covered by its own tests.
type GitHubRepoScanner struct {
	discovery DiscoveryManager
	provider  IGAProvider
	catalog   IGARuleCatalog
	// catalogs resolves the workspace's pattern overlay at scan time. Nil means
	// "run the built-in catalogue", which is what a fixture-driven test wants.
	//
	// Resolved per SCAN rather than at construction: the patterns belong to the
	// workspace being scanned, and a scanner built once and reused across
	// workspaces would otherwise apply the first workspace's rules to everyone.
	catalogs *RuleCatalogService
}

// NewGitHubRepoScanner wires the scanner to the live GitHub client, taking App
// credentials from the connector broker.
func NewGitHubRepoScanner(db *gorm.DB, vaultClient vault.VaultClient) *GitHubRepoScanner {
	return &GitHubRepoScanner{
		discovery: NewDiscoveryManager(repositories.NewDiscoveryRepository(db)),
		provider:  NewGitHubProviderForWorkspaceApp(db, vaultClient),
		catalog:   DefaultRuleCatalog(),
		catalogs:  NewRuleCatalogService(db),
	}
}

// NewGitHubRepoScannerWithProvider injects a provider directly, so the scan can
// be exercised against recorded fixtures without a tenant.
func NewGitHubRepoScannerWithProvider(db *gorm.DB, p IGAProvider) *GitHubRepoScanner {
	return &GitHubRepoScanner{
		discovery: NewDiscoveryManager(repositories.NewDiscoveryRepository(db)),
		provider:  p,
		catalog:   DefaultRuleCatalog(),
		catalogs:  NewRuleCatalogService(db),
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
	ReposExcluded  int      `json:"repos_excluded"`
	Excluded       []string `json:"excluded_repositories,omitempty"`
	SelectionMode  string   `json:"selection_mode"`
	ReposSelected  int      `json:"repos_selected"`
	ReposTruncated int      `json:"repos_truncated"`

	// BranchMode is the ref plan this run actually executed under.
	BranchMode      string `json:"branch_mode"`
	BranchesScanned int    `json:"branches_scanned"`
	// BranchesSkipped counts refs known to exist and deliberately not read
	// because the per-repository cap cut them off. Always forces Complete false.
	BranchesSkipped int `json:"branches_skipped"`

	FilesFetched int `json:"files_fetched"`
	// FilesFailed counts unreadable files inside repositories that opened fine.
	FilesFailed     int       `json:"files_failed"`
	SightingsNew    int       `json:"sightings_new"`
	SightingsBumped int       `json:"sightings_bumped"`
	Complete        bool      `json:"complete_for_selected_scope"`
	Warnings        []string  `json:"warnings,omitempty"`
	ScannedAt       time.Time `json:"scanned_at"`

	// Done lists the units ("owner/name@ref") this run finished, in order. It is
	// the resume cursor: a retry skips everything already in here.
	Done []string `json:"-"`
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
	// IntegrationID is the iga_integrations row that holds the verified
	// installation binding this source scans through. It is the source's link
	// back to its governance record — verified_at, granted permissions and the
	// cross-workspace rebinding guard all live there, not here.
	IntegrationID string `json:"integration_id,omitempty"`
	// Branches is the ref coverage plan. Absent means default-branch only,
	// which is what every source did before branch coverage existed.
	Branches BranchSelection `json:"branches,omitempty"`
}

// BranchSelection is how far beyond the default branch a scan reaches.
//
// Mode "default" reads only the branch whose contents are actually in effect.
// Mode "all" additionally reads other refs, where a declaration may be merely
// proposed. MaxPerRepo bounds the cost: refs beyond it are counted and force
// the run incomplete, never dropped in silence.
type BranchSelection struct {
	Mode       string `json:"mode,omitempty"` // "default" | "all"
	MaxPerRepo int    `json:"max_per_repo,omitempty"`
}

// resolve fills in the defaults, so callers never branch on empty strings.
func (b BranchSelection) resolve() (mode string, max int) {
	mode = b.Mode
	if mode != models.BranchModeAll {
		mode = models.BranchModeDefault
	}
	max = b.MaxPerRepo
	if max <= 0 {
		max = models.DefaultMaxBranchesPerRepo
	}
	return mode, max
}

// providerContext builds the provider call context for a source.
//
// IntegrationID must be the real iga_integrations id. It used to be given the
// SOURCE id, which meant every provider call and every issue it recorded
// carried a source uuid in a field named integration_id — traceable only by
// someone who already knew about the substitution.
func (c githubScannerConfig) providerContext(workspaceID uuid.UUID) ProviderContext {
	host := c.ProviderHost
	if host == "" {
		host = "github.com"
	}
	return ProviderContext{
		WorkspaceID:       workspaceID,
		IntegrationID:     c.IntegrationID,
		AppRegistrationID: c.AppRegistrationID,
		InstallationID:    c.InstallationID,
		ProviderHost:      host,
	}
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
	pctx := cfg.providerContext(workspaceID)
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

// ScanOptions carries the parts of a scan that come from the run record rather
// than the source config: where a previous attempt got to, and how to report
// progress back.
type ScanOptions struct {
	// Done are units already finished by an earlier attempt of the same run.
	// They are skipped, which is what makes an interrupted org-wide scan resume
	// instead of re-paying for every repository it already read.
	Done map[string]bool

	// OnUnit is called after each unit completes, with the running result. It is
	// how the console sees movement during a long scan. Returning an error
	// aborts the scan — the worker uses that to stop promptly when its lease is
	// gone or the process is shutting down.
	OnUnit func(res *GitHubScanResult) error

	// Base carries forward what EARLIER attempts of the same run achieved.
	//
	// Without it, every counter restarts at zero on resume and the run appears
	// to go backwards: a retry that skips ninety already-scanned repositories
	// would report "0 files fetched, 0 sightings" and overwrite the real totals.
	// Only genuinely cumulative fields are carried; anything recomputed from
	// scratch on each attempt (the selection, the exclusions, the branch cap) is
	// deliberately left to start fresh.
	Base *GitHubScanResult
}

// Scan runs a scan to completion with no resume state and no progress
// reporting. Retained for callers that genuinely want it synchronous — tests,
// and any small single-repository scan.
func (s *GitHubRepoScanner) Scan(ctx context.Context, workspaceID, sourceID uuid.UUID, actor string) (*GitHubScanResult, error) {
	return s.ScanWithOptions(ctx, workspaceID, sourceID, actor, ScanOptions{})
}

// ScanWithOptions enumerates the installation's repositories and reports
// sightings, one unit (repository at a ref) at a time.
//
// It is deliberately conservative about failure: a repository that cannot be
// read is recorded as a warning and the scan continues, and the result is only
// marked complete when every selected unit was fully inspected. A caller must
// not read an incomplete scan as an authoritative picture.
func (s *GitHubRepoScanner) ScanWithOptions(ctx context.Context, workspaceID, sourceID uuid.UUID, actor string, opts ScanOptions) (*GitHubScanResult, error) {
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

	pctx := cfg.providerContext(workspaceID)

	mode := cfg.Repositories.Mode
	if mode == "" {
		mode = "all"
	}
	// Refuse a scan that would inspect nothing.
	//
	// A newly added organisation starts with an explicit empty selection,
	// so this is the state of the very FIRST scan anyone runs. Left unguarded it
	// excludes every repository, leaves Complete true, and returns
	// scanned=0 / complete_for_selected_scope=true -- which a UI cannot help but
	// render as "we looked and your organisation is clean". It is vacuously
	// true and operationally a lie. An error is the honest answer: the admin has
	// not chosen anything yet.
	if mode == "selected" && len(cfg.Repositories.Include) == 0 {
		return nil, fmt.Errorf("no repositories selected: choose repositories for this source before scanning")
	}

	// The patterns belong to the workspace, so they are resolved here rather
	// than at construction. A failure is fatal to the scan on purpose: falling
	// back to the built-in catalogue would scan with rules the customer did not
	// choose and report the result as though they had.
	catalog := s.catalog
	if s.catalogs != nil {
		resolved, _, cerr := s.catalogs.Resolve(workspaceID)
		if cerr != nil {
			return nil, fmt.Errorf("resolve detection patterns: %w", cerr)
		}
		catalog = resolved
	}

	branchMode, maxBranches := cfg.Branches.resolve()

	res := &GitHubScanResult{
		SourceID: sourceID, Complete: true, SelectionMode: mode,
		BranchMode: branchMode, ScannedAt: time.Now(),
	}
	if b := opts.Base; b != nil {
		// Cumulative work only. A unit skipped as already-done contributes
		// nothing to this attempt, so its files and sightings have to be carried
		// or they vanish from the report.
		res.ReposFailed = b.ReposFailed
		res.ReposTruncated = b.ReposTruncated
		res.FilesFetched = b.FilesFetched
		res.FilesFailed = b.FilesFailed
		res.SightingsNew = b.SightingsNew
		res.SightingsBumped = b.SightingsBumped
		res.Warnings = append(res.Warnings, b.Warnings...)
		// A problem seen by an earlier attempt did not stop being a problem.
		res.Complete = res.Complete && b.Complete
	}

	scopes, err := s.provider.ListScopes(ctx, pctx)
	if err != nil {
		return nil, fmt.Errorf("enumerate repositories: %w", err)
	}

	repoScopes := 0
	for _, scope := range scopes {
		if scope.Kind == "repository" {
			repoScopes++
		}
	}
	if repoScopes == 0 {
		// The installation is reachable but grants nothing. "Complete" would be
		// vacuously true, so say plainly that there was nothing to look at.
		res.Warnings = append(res.Warnings,
			"this installation exposes no repositories, so nothing was scanned; grant repository access on GitHub")
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
		res.ReposSelected++

		refs := s.refsFor(ctx, pctx, scope, branchMode, maxBranches, res)

		// CODEOWNERS once per repository. Read from the default branch: it is the
		// ownership that is actually in force, and a feature branch may not have
		// merged its own CODEOWNERS change yet.
		coRules, _ := s.provider.ListCodeowners(ctx, pctx, scope)

		// path -> blob SHA already reported from the default branch. A
		// non-default ref carrying an identical blob at an identical path is the
		// SAME declaration sitting on an unmerged or undeleted branch, not a
		// second finding. Without this, every stale branch of a repository
		// duplicates its whole agent inventory.
		onDefault := map[string]string{}
		// Refs pointing at the same commit share a tree by definition, so the
		// second one needs no API call at all.
		walkedCommits := map[string]bool{}
		repoCounted := false

		for _, br := range refs {
			unit := scope.DisplayName + "@" + br.Name
			if opts.Done[unit] {
				continue // finished by an earlier attempt of this run
			}
			// Honour cancellation between units rather than mid-repository, so a
			// stopped scan always leaves a coherent cursor.
			if err := ctx.Err(); err != nil {
				return res, err
			}

			if br.CommitSHA != "" && walkedCommits[br.CommitSHA] {
				res.BranchesScanned++
				res.Done = append(res.Done, unit)
				continue
			}

			refScope := scope
			if !br.IsDefault {
				refScope.Ref = br.Name
			}

			entries, truncated, terr := s.provider.ListTree(ctx, pctx, refScope)
			if terr != nil {
				// Something we cannot read is a gap in coverage, not an absence of
				// agents, and it must not fail the whole scan. An unreadable
				// DEFAULT branch means the repository itself is unreadable; an
				// unreadable side branch does not.
				if br.IsDefault {
					res.ReposFailed++
				}
				res.Complete = false
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %v", unit, terr))
				continue
			}
			if truncated {
				// The tree cut off, so files beyond the limit were never seen.
				res.ReposTruncated++
				res.Complete = false
				res.Warnings = append(res.Warnings,
					fmt.Sprintf("%s: git tree truncated; unwalked subtrees not inspected", unit))
			}
			if br.CommitSHA != "" {
				walkedCommits[br.CommitSHA] = true
			}
			if !repoCounted {
				res.ReposScanned++
				repoCounted = true
			}
			res.BranchesScanned++

			for _, e := range entries {
				rule, ok := catalog.MatchRule(e.Path)
				if !ok {
					continue // not a path any rule can interpret; never fetched
				}
				// Already reported from the default branch, byte for byte.
				if !br.IsDefault && onDefault[e.Path] == e.SHA && e.SHA != "" {
					continue
				}

				body, ferr := s.provider.FetchBlob(ctx, pctx, refScope, e)
				if ferr != nil {
					// A file we could not read is a hole in coverage. Counted
					// separately from ReposFailed: the repository opened fine, so
					// reporting only repository failures shows "0 failed" beside
					// a page of file errors.
					res.FilesFailed++
					res.Complete = false
					res.Warnings = append(res.Warnings,
						fmt.Sprintf("%s:%s: %v", unit, e.Path, ferr))
					continue
				}
				res.FilesFetched++

				facts, secretRefs, xerr := rule.Extract(e.Path, body)
				if xerr != nil || facts == nil {
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
				// The catalogue version this finding came from. Patterns are
				// configurable, so "which ruleset produced this?" is a real
				// question — and because raw bodies are discarded after parse, a
				// changed ruleset cannot be replayed over stored evidence. This
				// is what lets the console mark older findings as stale instead
				// of presenting them as current.
				facts["catalog_version"] = catalog.Version
				facts["evidence_mode"] = rule.EvidenceMode
				facts["content_sha256"] = HashBody(body)
				// The blob SHA lets a later scan skip an unchanged file.
				facts["blob_sha"] = e.SHA
				// Which ref this was found on, and whether that ref is the one in
				// effect. A reviewer must be able to tell a live declaration from
				// one merely proposed on a branch.
				facts["branch"] = br.Name
				facts["is_default_branch"] = br.IsDefault

				if br.IsDefault {
					onDefault[e.Path] = e.SHA
				}

				_, created, rerr := s.discovery.ReportSighting(workspaceID, actor, SightingInput{
					Source:            models.DiscoverySourceRepoScan,
					DiscoverySourceID: &sourceID,
					Fingerprint:       declarationFingerprint(scope.NativeID, br, e.Path),
					DisplayName:       declarationName(facts, e.Path),
					Metadata:          facts,
					// A parsed file is a DECLARATION, not a deployment. It may never
					// have run, and nothing in the file says how it was deployed, so
					// "automated" would be an assertion we cannot support.
					DeploymentOrigin: models.DeploymentOriginUnknown,
				})
				if rerr != nil {
					res.Warnings = append(res.Warnings,
						fmt.Sprintf("%s:%s: report sighting: %v", unit, e.Path, rerr))
					res.Complete = false
					continue
				}
				if created {
					res.SightingsNew++
				} else {
					res.SightingsBumped++
				}
			}

			res.Done = append(res.Done, unit)
			if opts.OnUnit != nil {
				if perr := opts.OnUnit(res); perr != nil {
					// The caller wants us to stop — lease lost, or shutting down.
					// The cursor is current, so the retry picks up here.
					return res, perr
				}
			}
		}
	}

	return res, nil
}

// refsFor resolves which refs of a repository this scan should read.
//
// Default mode returns exactly the default branch, which is what the scanner
// did before branch coverage existed. All mode enumerates refs and caps them,
// degrading to the default branch — loudly — whenever the refs cannot be
// listed. Every degradation records a warning and clears Complete, because in
// each case we know there was more to read and did not read it.
func (s *GitHubRepoScanner) refsFor(
	ctx context.Context, pctx ProviderContext, scope ProviderScope,
	branchMode string, maxBranches int, res *GitHubScanResult,
) []ProviderBranch {
	defaultOnly := []ProviderBranch{{Name: scope.DefaultBranch, IsDefault: true}}
	if branchMode != models.BranchModeAll {
		return defaultOnly
	}

	lister, ok := s.provider.(BranchLister)
	if !ok {
		res.Complete = false
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"%s: this provider cannot enumerate branches; only the default branch was read",
			scope.DisplayName))
		return defaultOnly
	}

	branches, err := lister.ListBranches(ctx, pctx, scope)
	if err != nil {
		res.Complete = false
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"%s: could not list branches (%v); only the default branch was read",
			scope.DisplayName, err))
		return defaultOnly
	}
	if len(branches) == 0 {
		return defaultOnly
	}

	// The default branch goes first, always. Its contents are what is in effect,
	// and scanning it first is what lets every later ref suppress the copies it
	// shares with it.
	ordered := make([]ProviderBranch, 0, len(branches))
	rest := make([]ProviderBranch, 0, len(branches))
	sawDefault := false
	for _, b := range branches {
		if b.Name == scope.DefaultBranch {
			b.IsDefault = true
			ordered = append(ordered, b)
			sawDefault = true
			continue
		}
		b.IsDefault = false
		rest = append(rest, b)
	}
	if !sawDefault {
		ordered = append(ordered, defaultOnly[0])
	}
	ordered = append(ordered, rest...)

	if len(ordered) > maxBranches {
		// Counted and reported, never dropped in silence: we know these refs
		// exist and chose not to spend the budget on them.
		res.BranchesSkipped += len(ordered) - maxBranches
		res.Complete = false
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"%s: %d branches exceed the per-repository cap of %d; %d were not read",
			scope.DisplayName, len(ordered), maxBranches, len(ordered)-maxBranches))
		ordered = ordered[:maxBranches]
	}
	return ordered
}

// declarationFingerprint is what makes a re-scan idempotent: the same
// declaration on the same ref resolves to the same inventory row.
//
// The default branch keeps the ORIGINAL, ref-free form. That is deliberate:
// every finding recorded before branch coverage existed used it, and changing
// it would orphan those rows and re-report the whole estate as new. Only
// non-default refs carry a ref-qualified key, which is also what keeps a
// declaration on main distinct from a different version of it on a branch.
func declarationFingerprint(repoNativeID string, br ProviderBranch, path string) string {
	if br.IsDefault {
		return fmt.Sprintf("gh:%s:%s", repoNativeID, path)
	}
	return fmt.Sprintf("gh:%s@%s:%s", repoNativeID, br.Name, path)
}

// declarationName prefers the name the declaration gives itself, falling back
// to the path so a row is never anonymous.
func declarationName(facts map[string]interface{}, path string) string {
	if v, ok := facts["name"].(string); ok && v != "" {
		return v
	}
	return path
}
