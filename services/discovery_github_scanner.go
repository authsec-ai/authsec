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
	// ReposFailed counts REPOSITORIES we could not read at all, and Failed
	// names them with the reason.
	//
	// A per-FILE fetch failure is counted in FilesFailed instead, never here.
	// Merging them makes the number unreadable: one dead repository plus one
	// readable repository with four unfetchable declarations would report
	// "failed: 5" for a two-repository estate, and an admin cannot tell a
	// permission problem on a whole repository from a few bad blobs inside a
	// repository that otherwise scanned fine. Different causes, different
	// fixes, different counters.
	ReposFailed int      `json:"repos_failed"`
	Failed      []string `json:"failed_repositories,omitempty"`
	// FilesFailed counts declarations inside an otherwise-scanned repository
	// whose blob could not be fetched.
	FilesFailed int      `json:"files_failed"`
	FailedFiles []string `json:"failed_files,omitempty"`
	// Excluded is every repository the scan did not read by choice or by
	// missing grant, named. Reported separately from failures: choosing not to
	// scan something is not the same as being unable to.
	//
	// It is deliberately a ROLL-UP, so "what did we leave out?" has one answer.
	// SelectedNotGranted below is the subset that carries the reason.
	ReposExcluded int      `json:"repos_excluded"`
	Excluded      []string `json:"excluded_repositories,omitempty"`
	// Selected by the plan but never exposed by the installation.
	//
	// Kept apart from Excluded because the two demand different actions from
	// different people: Excluded is "our admin chose not to scan this" and is
	// fixed by editing the plan, while this is "our admin asked for this and
	// GitHub never granted it" and is fixed only on GitHub. Folding them
	// together hides the second, which is the one that silently shrinks
	// coverage while the plan still claims the repository is covered.
	ReposSelectedNotGranted int      `json:"repos_selected_not_granted"`
	SelectedNotGranted      []string `json:"selected_not_granted,omitempty"`
	// Scanned, and archived on GitHub. A subset of ReposScanned, not a skip:
	// an archived repository is read-only, not empty, and its declarations
	// still name real secrets and runtimes. Skipping it would quietly shrink
	// coverage, so it is inspected and annotated instead — the count is here
	// so an admin can discount findings that can no longer be merged.
	ReposArchived int      `json:"repos_archived"`
	Archived      []string `json:"archived_repositories,omitempty"`
	SelectionMode string   `json:"selection_mode"`
	// Truncated names the repositories whose tree cut off, so TRUNCATED is
	// explainable per repository like every other outcome rather than being a
	// bare count an admin cannot act on.
	Truncated []string `json:"truncated_repositories,omitempty"`
	// Disclosure is UNCONDITIONAL and travels in the payload rather than in UI
	// copy, so a client cannot omit it by accident. A scan can only ever speak
	// for what the installation was granted.
	Disclosure     string `json:"disclosure"`
	ReposTruncated int    `json:"repos_truncated"`
	// PathsRecovered counts paths a truncated tree hid that per-directory
	// listing got back. It is the measure of how much a truncated repository
	// was still worth: high recovery means the partial result is nearly whole,
	// zero means the cut-off landed where the catalogue could not follow.
	PathsRecovered int `json:"paths_recovered"`
	FilesFetched   int `json:"files_fetched"`
	// BlobsSkipped counts unchanged files whose blob SHA matched the stored
	// one, so no fetch was spent. Reported because it is the difference between
	// a cheap refresh and a full re-read of every declaration in the estate.
	BlobsSkipped    int `json:"blobs_skipped"`
	SightingsNew    int `json:"sightings_new"`
	SightingsBumped int `json:"sightings_bumped"`
	// AgentsCounted and CandidatesRecorded are reported SEPARATELY and are
	// never summed into one "agents discovered" number.
	//
	// A single weak signal is a candidate, not an agent. An inventory carrying
	// hundreds of junk rows in its headline count gets abandoned, and once it
	// is abandoned every real finding is missed too — so the split is not
	// cosmetic, it is what keeps the count trustworthy enough to be read.
	AgentsCounted      int       `json:"agents_counted"`
	CandidatesRecorded int       `json:"candidates_recorded"`
	Complete           bool      `json:"complete_for_selected_scope"`
	Warnings           []string  `json:"warnings,omitempty"`
	ScannedAt          time.Time `json:"scanned_at"`
}

// storedBlobSHA reads the blob SHA a previous scan recorded for a sighting.
//
// Metadata is the store of record here rather than a dedicated column, because
// the SHA is provider-specific evidence about one file and the inventory row is
// provider-neutral. A missing or unparseable value simply means "no basis to
// skip", which fails safe toward fetching.
func storedBlobSHA(a *models.DiscoveredAgent) string {
	if a == nil || len(a.Metadata) == 0 {
		return ""
	}
	var m map[string]interface{}
	if err := json.Unmarshal(a.Metadata, &m); err != nil {
		return ""
	}
	sha, _ := m["blob_sha"].(string)
	return sha
}

// ScanGrantDisclosure is the coverage limit every GitHub scan carries.
//
// It states the one thing a reader cannot infer from the counters: the scan
// saw only what the installation exposed, so a repository's absence from
// these numbers is not evidence that it holds no agents.
const ScanGrantDisclosure = "repositories not granted to this installation are not listed or scanned, " +
	"and their absence from this result is not evidence that they hold no agents"

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
	// Archived is shown at selection time so an admin can judge the cost
	// before spending API budget: findings here are real but unfixable in
	// place, since the repository can no longer be merged to.
	Archived bool `json:"archived"`
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
		// Reaching GitHub failed. Typed, so the handler answers 503 rather
		// than letting an empty picker imply the installation grants nothing.
		return nil, unavailable("list repositories", err)
	}
	out := make([]RepoChoice, 0, len(scopes))
	for _, sc := range scopes {
		if sc.Kind != "repository" {
			continue
		}
		out = append(out, RepoChoice{
			NativeID: sc.NativeID, FullName: sc.DisplayName,
			DefaultBranch: sc.DefaultBranch, Selected: cfg.Repositories.wants(sc.DisplayName),
			Archived: sc.Archived,
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
	// Refuse a scan that would inspect nothing.
	//
	// A source created from a connector starts with an explicit empty selection,
	// so this is the state of the very FIRST scan anyone runs. Left unguarded it
	// excludes every repository, leaves Complete true, and returns
	// scanned=0 / complete_for_selected_scope=true -- which a UI cannot help but
	// render as "we looked and your organisation is clean". It is vacuously
	// true and operationally a lie. An error is the honest answer: the admin has
	// not chosen anything yet.
	if mode == "selected" && len(cfg.Repositories.Include) == 0 {
		return nil, fmt.Errorf("no repositories selected: choose repositories for this source before scanning")
	}

	res := &GitHubScanResult{
		SourceID: sourceID, Complete: true, SelectionMode: mode,
		Disclosure: ScanGrantDisclosure, ScannedAt: time.Now(),
	}

	scopes, err := s.provider.ListScopes(ctx, pctx)
	if err != nil {
		// Enumeration itself failed, so nothing was inspected at all. This is
		// the whole-scan failure case and must never surface as a completed
		// scan that found nothing.
		return nil, unavailable("enumerate repositories", err)
	}

	repoScopes := 0
	for _, scope := range scopes {
		if scope.Kind == "repository" {
			repoScopes++
		}
	}

	// The plan may name repositories this installation never exposed: a stale
	// entry, a repository since deleted or transferred out, or a grant that was
	// simply never made on GitHub.
	//
	// Only a diff against the live grant can surface those. Walking the grant
	// alone — which is all the scan loop below does — can never mention a
	// repository that is absent from it, so such an entry would vanish without
	// a trace while the stored plan still implies it is covered. That is the
	// difference between "we did not look there" and "there is nothing there",
	// reported in the admin's own words: the name they typed.
	if mode == "selected" {
		granted := make(map[string]struct{}, repoScopes)
		for _, scope := range scopes {
			if scope.Kind == "repository" {
				granted[strings.ToLower(scope.DisplayName)] = struct{}{}
			}
		}
		for _, want := range cfg.Repositories.Include {
			if _, ok := granted[strings.ToLower(want)]; ok {
				continue
			}
			res.ReposSelectedNotGranted++
			res.SelectedNotGranted = append(res.SelectedNotGranted, want)
			// Also reported as excluded, by bare name.
			//
			// Excluded is the roll-up of everything the scan did not read, so a
			// reader checking "what was left out" finds it in one place;
			// SelectedNotGranted is the actionable subset that says WHY, and
			// warnings carry the sentence. The name is unannotated here on
			// purpose: a consumer matching on the repository it asked for must
			// find an exact match, not a string with a reason glued to it.
			res.ReposExcluded++
			res.Excluded = append(res.Excluded, want)
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"%s: selected for scanning but not granted to this installation; "+
					"it was not inspected — grant it on GitHub or remove it from the plan", want))
			// Part of the selected scope went uninspected, so the scan cannot
			// claim to be complete FOR THAT SCOPE. Reporting complete here is
			// how a missing grant turns into a false all-clear.
			res.Complete = false
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
		// Counted, then scanned anyway. See ReposArchived: read-only is not
		// empty, and an archived declaration still names a live secret.
		if scope.Archived {
			res.ReposArchived++
			res.Archived = append(res.Archived, scope.DisplayName)
		}

		entries, truncated, err := s.provider.ListTree(ctx, pctx, scope)
		if err != nil {
			// A repository we cannot read is a gap in coverage, not an absence
			// of agents, and it must not fail the whole scan.
			res.ReposFailed++
			res.Failed = append(res.Failed,
				fmt.Sprintf("%s: %v", scope.DisplayName, err))
			res.Complete = false
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("%s: %v", scope.DisplayName, err))
			continue
		}
		if truncated {
			// The tree cut off, so files beyond the limit were never seen.
			res.ReposTruncated++
			res.Truncated = append(res.Truncated, scope.DisplayName)
			res.Complete = false

			// Recover what the catalogue can still name by directory. The
			// cut-off is arbitrary, so a declaration we care about may sit just
			// past it; asking for the handful of directories the rules name
			// costs a few calls and turns most of a truncated repository back
			// into real coverage.
			//
			// Complete stays false regardless. Recovery narrows the gap, it
			// does not close it: a rule with a bare-basename glob can match at
			// any depth, and those depths were never walked.
			recovered, dirs := RecoverTruncatedTree(ctx, s.provider, pctx, scope, s.catalog, entries)
			entries = append(entries, recovered...)
			res.PathsRecovered += len(recovered)
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"%s: git tree truncated; recovered %d path(s) from %d catalogue director(ies), "+
					"but paths outside them were never inspected",
				scope.DisplayName, len(recovered), dirs))
		}
		res.ReposScanned++

		// CODEOWNERS once per repository, matched per declaration path below.
		coRules, _ := s.provider.ListCodeowners(ctx, pctx, scope)

		// Findings are BUFFERED for the whole repository before any is
		// reported, because the combination rule is a per-repository
		// judgement: "langchain in requirements.txt" and "OPENAI_API_KEY
		// nearby" are each too weak to count alone and together are strong.
		// Reporting file-by-file would have to decide before the corroborating
		// signal has been seen, so every weak finding would be filed at its
		// individual strength and the promotion could never happen.
		var pending []pendingFinding
		var signals []RuleSignal

		for _, e := range entries {
			// EVERY rule claiming this path, not just the first: a workflow
			// may declare an agent invocation AND run on a self-hosted
			// runner, and those are different facts about the same file.
			rules := s.catalog.MatchRules(e.Path)
			if len(rules) == 0 {
				continue // not a path any rule can interpret; never fetched
			}

			// The fingerprint is what makes a re-scan idempotent: same repo,
			// same path, same row.
			fingerprint := fmt.Sprintf("gh:%s:%s", scope.NativeID, e.Path)

			// Incremental refresh. GitHub hands over the blob SHA for free in
			// the tree listing, so an unchanged file costs nothing to skip.
			//
			// The sighting is still reported, with EMPTY facts: the upsert keeps
			// stored metadata when it receives none, so this advances last-seen
			// and the sighting count without re-fetching or re-parsing. That
			// distinction is load-bearing — skipping the REPORT as well as the
			// fetch would let every unchanged agent decay into looking stale,
			// which reads as "possibly gone" for exactly the agents we just
			// confirmed are still declared.
			if prev, err := s.discovery.GetAgentByFingerprint(
				workspaceID, models.DiscoverySourceRepoScan, fingerprint,
			); err == nil && prev != nil && e.SHA != "" && storedBlobSHA(prev) == e.SHA {
				if _, _, err := s.discovery.ReportSighting(workspaceID, actor, SightingInput{
					Source:            models.DiscoverySourceRepoScan,
					DiscoverySourceID: &sourceID,
					Fingerprint:       fingerprint,
					DeploymentOrigin:  models.DeploymentOriginUnknown,
				}); err != nil {
					res.Warnings = append(res.Warnings, fmt.Sprintf(
						"%s:%s: touch unchanged sighting: %v", scope.DisplayName, e.Path, err))
					res.Complete = false
					continue
				}
				res.BlobsSkipped++
				res.SightingsBumped++
				continue
			}

			body, err := s.provider.FetchBlob(ctx, pctx, scope, e)
			if err != nil {
				// A file we could not fetch inside a repository we DID read.
				// Counted apart from ReposFailed so "5 failed" never conflates
				// five dead repositories with five bad blobs in one.
				res.FilesFailed++
				res.FailedFiles = append(res.FailedFiles,
					fmt.Sprintf("%s:%s: %v", scope.DisplayName, e.Path, err))
				res.Complete = false
				res.Warnings = append(res.Warnings,
					fmt.Sprintf("%s:%s: %v", scope.DisplayName, e.Path, err))
				continue
			}
			res.FilesFetched++

			// Run every claiming rule and merge what fires. A rule that
			// declines (nil facts) or fails to parse contributes nothing and
			// must not suppress the others — one malformed section of a file
			// is not evidence that the rest of it is uninteresting.
			facts := map[string]interface{}{}
			var firedRules []IGARule
			var secretRefs []string
			for _, rule := range rules {
				rf, rs, rerr := rule.ExtractRedacted(e.Path, body)
				if rerr != nil || rf == nil {
					continue
				}
				for k, v := range rf {
					if _, clash := facts[k]; !clash {
						facts[k] = v
					}
				}
				secretRefs = append(secretRefs, rs...)
				firedRules = append(firedRules, rule)
			}
			if len(firedRules) == 0 {
				// Nothing in this file matched any rule's content test.
				continue
			}
			// Names only. A secret value is never read, stored or reported.
			if len(secretRefs) > 0 {
				facts["secret_references"] = dedupeStrings(secretRefs)
			}
			if owners := MatchCodeowners(coRules, e.Path); len(owners) > 0 {
				facts["codeowners"] = owners
			}
			facts["repository"] = scope.DisplayName
			facts["path"] = e.Path
			// Set only when true, so its presence is the signal: a reviewer
			// judging whether a declaration is still live needs to know the
			// repository can no longer be merged to.
			if scope.Archived {
				facts["repository_archived"] = true
			}
			// rule_id names the STRONGEST rule that fired, which is what the
			// row is worth; rule_ids lists every signal, which is what makes
			// the finding explainable and what a retraction needs when one
			// rule turns out to be wrong.
			primary := firedRules[0]
			var ruleIDs []string
			for _, r := range firedRules {
				ruleIDs = append(ruleIDs, r.ID+"@"+r.Version)
				if r.Confidence == ConfidenceHigh && primary.Confidence != ConfidenceHigh {
					primary = r
				}
			}
			facts["rule_id"] = primary.ID
			facts["rule_version"] = primary.Version
			facts["rule_ids"] = ruleIDs
			facts["evidence_mode"] = primary.EvidenceMode
			facts["content_sha256"] = HashBody(body)
			// The blob SHA lets a later scan skip an unchanged file.
			facts["blob_sha"] = e.SHA

			// This file's own strength, before corroboration across the repo.
			facts["confidence"] = StrongestConfidence(firedRules)

			for _, r := range firedRules {
				signals = append(signals, RuleSignal{
					RuleID:     r.ID,
					Confidence: r.Confidence,
					Path:       e.Path,
				})
			}

			pending = append(pending, pendingFinding{
				fingerprint: fingerprint,
				displayName: declarationName(facts, e.Path),
				path:        e.Path,
				facts:       facts,
			})
		}

		// The whole repository has been read, so the signals can corroborate
		// each other. Combined confidence decides only ONE thing: whether a
		// finding may be counted as an agent or belongs in the candidate
		// bucket a human reviews. Everything is recorded either way — be
		// permissive about what you RECORD, strict about what you COUNT.
		combined := CombineConfidence(signals)
		countable := CountsAsAgent(combined)
		for _, pf := range pending {
			pf.facts["combined_confidence"] = combined
			pf.facts["counts_as_agent"] = countable
			if !countable {
				// Named in the row itself so a reviewer never has to infer why
				// something is not in the headline count.
				pf.facts["review_bucket"] = "candidate"
			}

			_, created, err := s.discovery.ReportSighting(workspaceID, actor, SightingInput{
				Source:            models.DiscoverySourceRepoScan,
				DiscoverySourceID: &sourceID,
				Fingerprint:       pf.fingerprint,
				DisplayName:       pf.displayName,
				Metadata:          pf.facts,
				// A parsed file is a DECLARATION, not a deployment. It may never
				// have run, and nothing in the file says how it was deployed, so
				// "automated" would be an assertion we cannot support.
				DeploymentOrigin: models.DeploymentOriginUnknown,
			})
			if err != nil {
				res.Warnings = append(res.Warnings,
					fmt.Sprintf("%s:%s: report sighting: %v", scope.DisplayName, pf.path, err))
				res.Complete = false
				continue
			}
			if created {
				res.SightingsNew++
			} else {
				res.SightingsBumped++
			}
			// Separate counts, never summed into one "agents discovered".
			if countable {
				res.AgentsCounted++
			} else {
				res.CandidatesRecorded++
			}
		}
	}

	return res, nil
}

// pendingFinding is one buffered declaration awaiting its repository's combined
// confidence. It exists only for the length of one repository's scan.
type pendingFinding struct {
	fingerprint string
	displayName string
	path        string
	facts       map[string]interface{}
}

// declarationName prefers the name the declaration gives itself, falling back
// to the path so a row is never anonymous.
func declarationName(facts map[string]interface{}, path string) string {
	if v, ok := facts["name"].(string); ok && v != "" {
		return v
	}
	return path
}

// ProviderUnavailableError marks a failure to REACH GitHub, as distinct from a
// caller mistake or a genuinely empty result.
//
// It exists as a type rather than a convention because the two facts it
// separates look identical on screen and are opposites in meaning:
//
//	zero-because-broken  -> the provider is unreachable, coverage FAILED,
//	                        and the customer's real posture is unknown
//	zero-because-clean   -> we looked at everything selected and found nothing
//
// A caller that cannot tell them apart will eventually render "0 agents" over a
// broken connection, which reads as an all-clear. Making it a type means the
// unavailable case cannot silently serialise as an empty list: a handler must
// either match it and answer 503, or fail loudly.
type ProviderUnavailableError struct {
	Op  string
	Err error
}

func (e *ProviderUnavailableError) Error() string {
	if e.Op == "" {
		return "github unavailable: " + e.Err.Error()
	}
	return e.Op + ": github unavailable: " + e.Err.Error()
}

func (e *ProviderUnavailableError) Unwrap() error { return e.Err }

// unavailable wraps a provider transport failure so callers can answer 503.
func unavailable(op string, err error) error {
	if err == nil {
		return nil
	}
	return &ProviderUnavailableError{Op: op, Err: err}
}

// dedupeStrings keeps first-seen order so evidence is stable across runs.
func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
