package services

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
)

// IGAManager orchestrates the discovery flow: connect and verify, enumerate,
// classify, decide, project. The invariant that shapes all of it is that
// evidence is written before it is interpreted, and nothing is promoted to a
// confirmed agent without either provider-declared semantics or a human.
type IGAManager interface {
	// Connect
	CreateIntegration(workspaceID uuid.UUID, createdBy string, in IntegrationInput) (*models.IGAIntegration, error)
	VerifyIntegration(workspaceID, id uuid.UUID, in VerifyInput) (*models.IGAIntegration, error)
	GetIntegration(workspaceID, id uuid.UUID) (*models.IGAIntegration, error)
	ListIntegrations(workspaceID uuid.UUID) ([]models.IGAIntegration, error)
	Disconnect(workspaceID, id uuid.UUID) error

	// Enumerate
	StartScan(workspaceID, integrationID uuid.UUID, mode, requestedBy string) (*models.IGAScanRun, error)
	RunScan(ctx context.Context, workspaceID, scanRunID uuid.UUID) (*ScanReport, error)
	GetScanRun(workspaceID, id uuid.UUID) (*models.IGAScanRun, error)
	Coverage(workspaceID, integrationID uuid.UUID) ([]models.IGACoverageState, error)
	SourceHealth(workspaceID uuid.UUID, integrationID *uuid.UUID) ([]models.IGAOperationalIssue, error)

	// Govern
	ListCandidates(workspaceID uuid.UUID, state string, limit, offset int) ([]models.IGACandidate, int64, error)
	// Cursor variants. Offset pagination is prohibited for a changing
	// inventory, so these are what the API actually uses.
	ListAgentsPage(workspaceID uuid.UUID, rollup, cursor string, limit int) (*AgentPage, error)
	ListCandidatesPage(workspaceID uuid.UUID, state, cursor string, limit int) (*CandidatePage, error)
	ListIdentityAccountsPage(workspaceID uuid.UUID, cursor string, limit int) (*IdentityPage, error)
	AgentAccessPaths(workspaceID, agentID uuid.UUID) ([]repositories.AccessPath, AccessSummary, error)
	DecideCandidate(workspaceID, id uuid.UUID, expectedVersion int64, decision, reason, by string) (*models.IGACandidate, error)
	ListAgents(workspaceID uuid.UUID, rollup string, limit, offset int) ([]models.IGAAgent, int64, error)
	AgentDetail(workspaceID, agentID uuid.UUID) (*AgentDetail, error)
	AgentEvidence(workspaceID, agentID uuid.UUID) ([]models.IGAObservation, error)
	DecideOwnership(workspaceID, id uuid.UUID, expectedVersion int64, decision, by string) (*models.IGAOwnershipCandidate, error)

	// Ingress
	AcceptWebhook(in WebhookInput) (*WebhookResult, error)
	RunWorkerOnce(ctx context.Context, worker string) (bool, error)
}

// IntegrationInput is the create payload. The installation id is deliberately
// absent: it arrives from the provider and is untrusted until verified.
type IntegrationInput struct {
	Provider          string
	ProviderHost      string
	AppRegistrationID string
	// SecretRef points at the approved secrets store entry holding the App
	// private key. A POINTER only -- no key material reaches this database, and
	// the field is json:"-" so it never reaches a client either.
	//
	// Nothing reads it to mint a token; the credential is resolved from the
	// workspace's App registration. It is here so a row can SAY where its
	// credential lives, which is what makes an orphaned or repointed key
	// traceable later. Leaving it empty on this path while the migration filled
	// it would put two shapes of the same row in one table.
	SecretRef            string
	CapabilityProfile    map[string]interface{}
	RequestedPermissions map[string]interface{}
}

// VerifyInput carries what the callback learned. AuthenticatedAccountID is the
// account of the GitHub admin who actually authorized — it must match the
// installation's account, or the binding is refused.
type VerifyInput struct {
	InstallationID         string
	AccountNativeID        string
	AuthenticatedAccountID string
	GrantedPermissions     map[string]interface{}
}

// ScanReport is the human-readable outcome of one enumeration.
type ScanReport struct {
	ScanRunID       uuid.UUID                 `json:"scan_run_id"`
	Generation      int64                     `json:"generation"`
	ScopesSeen      int                       `json:"scopes_seen"`
	SourceObjects   int                       `json:"source_objects"`
	Observations    int                       `json:"observations"`
	Candidates      int                       `json:"candidates"`
	AgentsConfirmed int                       `json:"agents_confirmed"`
	Identities      int                       `json:"identities"`
	Credentials     int                       `json:"credentials"`
	AccessEdges     int                       `json:"access_edges"`
	Tombstoned      int                       `json:"tombstoned"`
	BlobsFetched    int                       `json:"blobs_fetched"`
	BlobsSkipped    int                       `json:"blobs_skipped_unchanged"`
	Coverage        []models.IGACoverageState `json:"coverage"`
	Issues          []string                  `json:"issues"`
}

// AgentDetail is the Agent 360 payload: the agent plus the evidence, access and
// ownership around it, with coverage attached so absence is never read as zero.
type AgentDetail struct {
	Agent               *models.IGAAgent               `json:"agent"`
	Instances           []models.IGAAgentInstance      `json:"instances"`
	InstanceCoverage    string                         `json:"instance_coverage"`
	AccessPaths         []repositories.AccessPath      `json:"access_paths"`
	AccessSummary       AccessSummary                  `json:"access_summary"`
	OwnershipCandidates []models.IGAOwnershipCandidate `json:"ownership_candidates"`
	AttributeValues     []models.IGAAttributeValue     `json:"attribute_values"`
	Correlations        []models.IGACorrelation        `json:"correlations"`
	EvidenceCount       int                            `json:"evidence_count"`
	Coverage            []models.IGACoverageState      `json:"coverage"`
}

// AccessSummary splits access paths by how well they were calculated. This is
// the difference between "this agent reaches nothing" and "we have not worked
// out what it reaches" — an empty list alone cannot express that, and reading
// one as the other is exactly the failure mode the contract forbids.
type AccessSummary struct {
	Inbound   int    `json:"inbound"`
	Outbound  int    `json:"outbound"`
	Complete  int    `json:"complete"`
	Partial   int    `json:"partial"`
	Unknown   int    `json:"unknown"`
	State     string `json:"state"`
	Statement string `json:"statement"`
}

// WebhookInput is the raw ingress. Body is the UNMODIFIED bytes: the signature
// is computed over exactly what arrived, so it must not be re-marshalled.
type WebhookInput struct {
	AppRegistrationID string
	DeliveryID        string
	EventType         string
	Action            string
	Signature         string
	Secret            string
	Body              []byte
	InstallationID    string
}

// WebhookResult tells the route what status to return.
type WebhookResult struct {
	Accepted   bool
	Redelivery bool
	Reason     string
}

type igaManager struct {
	repo     repositories.IGARepository
	provider IGAProvider
	catalog  IGARuleCatalog
}

// NewIGAManager constructs an IGAManager. The provider is injected so the
// pipeline can run against recorded fixtures until the Stage-0 spike produces
// a verified real client.
func NewIGAManager(repo repositories.IGARepository, provider IGAProvider) IGAManager {
	return &igaManager{repo: repo, provider: provider, catalog: DefaultRuleCatalog()}
}

const normalizerVersion = "0.1.0"

func mustJSON(v interface{}) json.RawMessage {
	if v == nil {
		return json.RawMessage("{}")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("{}")
	}
	return b
}

/* -------------------------------- connect ------------------------------ */

func (m *igaManager) CreateIntegration(workspaceID uuid.UUID, createdBy string, in IntegrationInput) (*models.IGAIntegration, error) {
	if in.Provider == "" || in.ProviderHost == "" || in.AppRegistrationID == "" {
		return nil, errors.New("provider, provider_host and app_registration_id are required")
	}
	rec := &models.IGAIntegration{
		ID:                   uuid.New(),
		WorkspaceID:          workspaceID,
		Provider:             in.Provider,
		ProviderHost:         in.ProviderHost,
		AppRegistrationID:    in.AppRegistrationID,
		SecretRef:            in.SecretRef,
		CapabilityProfile:    mustJSON(in.CapabilityProfile),
		RequestedPermissions: mustJSON(in.RequestedPermissions),
		GrantedPermissions:   json.RawMessage("{}"),
		Status:               "pending",
		CreatedBy:            createdBy,
	}
	if err := m.repo.CreateIntegration(rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// VerifyIntegration turns an untrusted installation id into a trusted binding.
//
// The check that matters: a setup-URL installation_id is attacker-supplied, so
// it is only accepted when the installation's account matches the account of
// the admin who actually authenticated. Without this, anyone who can guess an
// installation id could bind someone else's GitHub org to their workspace.
func (m *igaManager) VerifyIntegration(workspaceID, id uuid.UUID, in VerifyInput) (*models.IGAIntegration, error) {
	if in.InstallationID == "" {
		return nil, errors.New("installation_id is required")
	}
	if in.AuthenticatedAccountID == "" {
		return nil, fmt.Errorf("%w: no authenticated provider account to match against",
			repositories.ErrIGABindingFailed)
	}
	if in.AccountNativeID != in.AuthenticatedAccountID {
		return nil, fmt.Errorf("%w: installation account %q does not match authenticated account %q",
			repositories.ErrIGABindingFailed, in.AccountNativeID, in.AuthenticatedAccountID)
	}
	return m.repo.VerifyIntegration(workspaceID, id, in.InstallationID, in.AccountNativeID,
		mustJSON(in.GrantedPermissions))
}

func (m *igaManager) GetIntegration(workspaceID, id uuid.UUID) (*models.IGAIntegration, error) {
	return m.repo.GetIntegration(workspaceID, id)
}

func (m *igaManager) ListIntegrations(workspaceID uuid.UUID) ([]models.IGAIntegration, error) {
	return m.repo.ListIntegrations(workspaceID)
}

func (m *igaManager) Disconnect(workspaceID, id uuid.UUID) error {
	return m.repo.DisconnectIntegration(workspaceID, id)
}

/* ------------------------------- enumerate ----------------------------- */

func (m *igaManager) StartScan(workspaceID, integrationID uuid.UUID, mode, requestedBy string) (*models.IGAScanRun, error) {
	integ, err := m.repo.GetIntegration(workspaceID, integrationID)
	if err != nil {
		return nil, err
	}
	if integ.VerifiedAt == nil {
		return nil, fmt.Errorf("%w: integration is not verified", repositories.ErrIGABindingFailed)
	}
	if mode == "" {
		mode = models.ScanModeFull
	}
	gen, err := m.repo.NextGeneration(workspaceID, integrationID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	run := &models.IGAScanRun{
		ID:                 uuid.New(),
		WorkspaceID:        workspaceID,
		IntegrationID:      integrationID,
		Mode:               mode,
		Generation:         gen,
		Status:             models.ScanRunning,
		RequestedBy:        requestedBy,
		NormalizerVersion:  normalizerVersion,
		RuleCatalogVersion: m.catalog.Version,
		StartedAt:          &now,
		Counters:           json.RawMessage("{}"),
	}
	if err := m.repo.CreateScanRun(run); err != nil {
		return nil, err
	}
	return run, nil
}

// RunScan is the enumeration funnel. Order is by cost, and evidence is written
// before anything is interpreted:
//
//	Lane A  native agents        provider-declared, strongest evidence
//	Lane C  identities/access    never an agent by itself
//	Lane B  SBOM   -> ranking + corroboration, one call
//	        tree   -> one call, every path, no contents
//	        fetch  -> only allowlisted paths, skipped when the hash is unchanged
//	        parse  -> redact, persist facts + hash, discard the body
//
// A scope that fails degrades that scope's coverage to partial; it does not
// fail the scan, and it never reduces to a zero count.
func (m *igaManager) RunScan(ctx context.Context, workspaceID, scanRunID uuid.UUID) (*ScanReport, error) {
	run, err := m.repo.GetScanRun(workspaceID, scanRunID)
	if err != nil {
		return nil, err
	}
	integ, err := m.repo.GetIntegration(workspaceID, run.IntegrationID)
	if err != nil {
		return nil, err
	}

	pctx := ProviderContext{
		WorkspaceID:       workspaceID,
		IntegrationID:     integ.ID.String(),
		AppRegistrationID: integ.AppRegistrationID,
		ProviderHost:      integ.ProviderHost,
	}
	if integ.InstallationID != nil {
		pctx.InstallationID = *integ.InstallationID
	}

	report := &ScanReport{ScanRunID: run.ID, Generation: run.Generation}

	caps, err := m.provider.Capabilities(ctx, pctx)
	if err != nil {
		_ = m.repo.FailScan(workspaceID, run.ID, "capability_probe_failed")
		return nil, err
	}

	scopes, err := m.provider.ListScopes(ctx, pctx)
	if err != nil {
		_ = m.repo.FailScan(workspaceID, run.ID, "scope_enumeration_failed")
		return nil, err
	}
	report.ScopesSeen = len(scopes)

	var coverage []models.IGACoverageState
	now := time.Now()

	for _, scope := range scopes {
		// Persist the scope so coverage has somewhere to hang, and so an
		// excluded or denied scope stays visible rather than vanishing.
		scopeRow := &models.IGAIntegrationScope{
			ID:                   uuid.New(),
			WorkspaceID:          workspaceID,
			IntegrationID:        integ.ID,
			NativeScopeKind:      scope.Kind,
			NativeScopeID:        scope.NativeID,
			SelectionState:       "selected",
			Filters:              json.RawMessage("{}"),
			EffectivePermissions: mustJSON(caps),
		}
		if err := m.repo.UpsertScope(scopeRow); err != nil {
			return nil, err
		}
		scopes, err := m.repo.ListScopes(workspaceID, integ.ID)
		if err != nil {
			return nil, err
		}
		scopeID := scopeRow.ID
		for _, s := range scopes {
			if s.NativeScopeKind == scope.Kind && s.NativeScopeID == scope.NativeID {
				scopeID = s.ID
				break
			}
		}

		perClass := map[string]*classOutcome{}
		mark := func(class string) *classOutcome {
			if perClass[class] == nil {
				perClass[class] = &classOutcome{state: models.CoverageComplete}
			}
			return perClass[class]
		}

		// --- Lane A: provider-declared agents -------------------------------
		if caps[models.ClassAgentProfile] == models.CoverageUnsupported {
			mark(models.ClassAgentProfile).state = models.CoverageUnsupported
			mark(models.ClassAgentProfile).reason = "provider or licence does not expose custom agents"
		} else {
			objs, err := m.provider.ListNativeAgents(ctx, pctx, scope)
			if err != nil {
				m.degrade(workspaceID, integ.ID, mark(models.ClassAgentProfile), scope, "agent_profile", err, report)
			} else {
				for _, o := range objs {
					m.ingest(workspaceID, integ, run, scope, o, models.ClassAgentProfile, report)
					mark(models.ClassAgentProfile).inspected++
				}
			}
		}

		// --- Lane C: identities, credentials and the access graph -----------
		objs, err := m.provider.ListIdentities(ctx, pctx, scope)
		if err != nil {
			m.degrade(workspaceID, integ.ID, mark(models.ClassAppInstallation), scope, "app_installation", err, report)
		} else {
			for _, o := range objs {
				m.ingest(workspaceID, integ, run, scope, o, models.ClassAppInstallation, report)
				mark(models.ClassAppInstallation).inspected++
			}
		}

		// Native grants become resources, entitlements and access edges. This
		// is what makes "which repositories can this identity write to?"
		// answerable — without it the inventory is a list with no consequences.
		grants, err := m.provider.ListGrants(ctx, pctx, scope)
		if err != nil {
			m.degrade(workspaceID, integ.ID, mark(models.ClassDeployKey), scope, "grant", err, report)
		} else {
			for _, g := range grants {
				m.ingestGrant(workspaceID, integ, run, scope, g, report)
				mark(grantClass(g.SubjectKind)).inspected++
			}
		}

		// Checkpoint the scope. A worker killed here resumes from this cursor
		// instead of restarting the whole enumeration.
		_ = m.repo.SaveCheckpoint(&models.IGAScanCheckpoint{
			WorkspaceID: workspaceID, ScanRunID: run.ID,
			ObjectClass: models.ClassRepository, PartitionKey: scope.NativeID,
			Cursor: scope.NativeID, Watermark: &now,
		})

		// --- Lane B, repositories only --------------------------------------
		if scope.Kind == "repository" {
			if caps[models.ClassRepoDeclaration] == models.CoverageNotConfigured {
				// The customer declined the code-evidence tier. That is
				// not_configured with a remedy, never "no agents found".
				c := mark(models.ClassRepoDeclaration)
				c.state = models.CoverageNotConfigured
				c.reason = "code evidence tier not granted for this installation"
			} else {
				// Step 2 — SBOM: one call, ranking and corroboration only.
				sbom, err := m.provider.ListSBOM(ctx, pctx, scope)
				if err != nil {
					m.degrade(workspaceID, integ.ID, mark(models.ClassSBOMComponent), scope, "sbom_component", err, report)
				} else {
					for _, o := range sbom {
						m.ingest(workspaceID, integ, run, scope, o, models.ClassSBOMComponent, report)
						mark(models.ClassSBOMComponent).inspected++
					}
				}

				// CODEOWNERS once per repo. Owners are matched per declaration
				// path below with last-match-wins precedence.
				coRules, coErr := m.provider.ListCodeowners(ctx, pctx, scope)
				if coErr != nil {
					coRules = nil // absent ownership evidence is not a scan failure
				}

				// Step 3 — tree: one call, every path, no contents.
				entries, truncated, err := m.provider.ListTree(ctx, pctx, scope)
				c := mark(models.ClassRepoDeclaration)
				if err != nil {
					m.degrade(workspaceID, integ.ID, c, scope, "repo_declaration", err, report)
				} else {
					if truncated {
						// The honest response to truncation. Reporting the
						// entries we did see as complete is how "0 agents"
						// gets manufactured out of a big monorepo.
						c.state = models.CoveragePartial
						c.reason = "git tree truncated (100k entries / 7MB); unwalked subtrees not inspected"
						_ = m.repo.RecordIssue(&models.IGAOperationalIssue{
							ID: uuid.New(), WorkspaceID: workspaceID, IntegrationID: &integ.ID,
							IssueKind: "tree_truncated", Severity: "warning",
							ObjectClass: models.ClassRepoDeclaration, ScopeRef: scope.DisplayName,
							Detail:      mustJSON(map[string]interface{}{"entries_seen": len(entries)}),
							FirstSeenAt: now, LastSeenAt: now,
						})
						report.Issues = append(report.Issues,
							fmt.Sprintf("%s: tree truncated, coverage partial", scope.DisplayName))
					}

					// Step 4 — fetch only allowlisted paths.
					for _, e := range entries {
						rule, ok := m.catalog.MatchRule(e.Path)
						if !ok {
							continue
						}
						recognition := fmt.Sprintf("%s:%s", scope.NativeID, e.Path)

						// Cheap-refresh check. The tree already handed us the
						// provider's blob SHA, so an unchanged file needs no
						// fetch at all — this is what makes a refresh cost ~2
						// calls per repo instead of one per declaration.
						//
						// Compare like with like: raw_hash stores the PROVIDER
						// blob SHA precisely so the next tree listing can be
						// diffed against it. (Comparing it to a sha256 of the
						// body would never match, and the skip would be dead.)
						if prior, err := m.findPriorHash(workspaceID, integ.ID, recognition); err == nil &&
							prior != "" && prior == e.SHA {
							// Still stamp the object as seen in this generation.
							// Skipping the fetch must NOT look like absence, or
							// the tombstone sweep would delete a file that is
							// merely unchanged.
							m.touchSourceObject(workspaceID, integ, run, recognition)
							report.BlobsSkipped++
							c.inspected++
							continue
						}

						body, err := m.provider.FetchBlob(ctx, pctx, scope, e)
						if err != nil {
							m.degrade(workspaceID, integ.ID, c, scope, "repo_declaration", err, report)
							continue
						}
						report.BlobsFetched++

						// Step 5 — parse, redact, persist facts + hash, discard.
						facts, secretRefs, err := rule.Extract(e.Path, body)
						if err != nil {
							_ = m.repo.RecordIssue(&models.IGAOperationalIssue{
								ID: uuid.New(), WorkspaceID: workspaceID, IntegrationID: &integ.ID,
								IssueKind: "api_failure", Severity: "info",
								ObjectClass: models.ClassRepoDeclaration, ScopeRef: e.Path,
								Detail:      mustJSON(map[string]interface{}{"parse_error": err.Error()}),
								FirstSeenAt: now, LastSeenAt: now,
							})
							continue
						}
						if facts == nil {
							c.inspected++
							continue // rule matched the path but found no fact
						}
						if len(secretRefs) > 0 {
							facts["secret_references"] = secretRefs // names only
						}

						// The content hash is integrity evidence; it rides on the
						// observation. The body itself is never written.
						facts["content_sha256"] = HashBody(body)

						owners := MatchCodeowners(coRules, e.Path)
						if len(owners) > 0 {
							facts["codeowners"] = owners
						}

						obj := ProviderObject{
							ObjectType:      models.ClassRepoDeclaration,
							NativeID:        recognition,
							DisplayName:     e.Path,
							Payload:         facts,
							EvidenceMode:    rule.EvidenceMode,
							OwnerCandidates: owners,
						}
						// raw_hash = the provider blob SHA, so the next scan can
						// diff the tree listing against it without fetching.
						m.ingestWithRule(workspaceID, integ, run, scope, obj,
							models.ClassRepoDeclaration, rule, e.SHA, report)
						c.inspected++
					}
				}
			}
		}

		for class, o := range perClass {
			cs := models.IGACoverageState{
				ID: uuid.New(), WorkspaceID: workspaceID, IntegrationID: integ.ID,
				IntegrationScopeID: scopeID, ObjectClass: class,
				State: o.state, ReasonCode: o.reason,
				LastAttemptAt: &now, InspectedCount: o.inspected, DeniedCount: o.denied,
			}
			if o.state == models.CoverageComplete {
				cs.LastSuccessAt = &now
			}
			coverage = append(coverage, cs)
		}
	}

	// Publication transaction: succeeded + coverage + authoritative generation.
	if err := m.repo.PublishScan(workspaceID, run.ID, coverage); err != nil {
		return nil, err
	}
	report.Coverage = coverage

	// Deletion safety runs ONLY after a successful publication, and only over
	// scopes that were fully enumerated. An interrupted or partial scan cannot
	// prove absence, so it must never tombstone anything.
	tomb, err := m.sweepAbsent(workspaceID, integ.ID, run.Generation, coverage)
	if err != nil {
		report.Issues = append(report.Issues, fmt.Sprintf("deletion sweep skipped: %v", err))
	}
	report.Tombstoned = tomb

	return report, nil
}

// maxDisappearanceRatio guards against a permission change or an API outage
// looking like a mass deletion. If more than this share of a scope's objects
// vanish at once, nothing is tombstoned and an operator is asked to look.
//
// The threshold is a placeholder: the spec requires it be set from
// production-scale testing rather than invented, so it is deliberately
// conservative and flagged rather than tuned here.
const defaultMaxDisappearanceRatio = 0.30

// maxDisappearanceRatio reads the threshold from the environment so an operator
// can tune it from a real scale run without a code change — which is the only
// honest way to set it, since the correct value depends on estate size and
// churn that nobody has measured yet.
func maxDisappearanceRatio() float64 {
	if v := os.Getenv("IGA_MAX_DISAPPEARANCE_RATIO"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f <= 1 {
			return f
		}
	}
	return defaultMaxDisappearanceRatio
}

// sweepAbsent tombstones objects that a complete, authoritative enumeration did
// not see. Objects in partial or failed scopes are left alone — "we could not
// look" is not "it is gone".
func (m *igaManager) sweepAbsent(workspaceID, integrationID uuid.UUID, generation int64, coverage []models.IGACoverageState) (int, error) {
	complete := map[string]bool{}
	for _, c := range coverage {
		if c.State == models.CoverageComplete {
			complete[c.ObjectClass] = true
		}
	}
	if len(complete) == 0 {
		return 0, nil
	}

	total := 0
	for class := range complete {
		alive, missing, err := m.repo.CountGenerationDrift(workspaceID, integrationID, class, generation)
		if err != nil {
			return total, err
		}
		if missing == 0 {
			continue
		}
		if alive+missing > 0 {
			ratio := float64(missing) / float64(alive+missing)
			if ratio > maxDisappearanceRatio() {
				now := time.Now()
				_ = m.repo.RecordIssue(&models.IGAOperationalIssue{
					ID: uuid.New(), WorkspaceID: workspaceID, IntegrationID: &integrationID,
					IssueKind: "api_failure", Severity: "critical", ObjectClass: class,
					Detail: mustJSON(map[string]interface{}{
						"reason":  "mass disappearance guard tripped; nothing tombstoned",
						"missing": missing, "alive": alive,
					}),
					FirstSeenAt: now, LastSeenAt: now,
				})
				continue
			}
		}
		n, err := m.repo.TombstoneAbsent(workspaceID, integrationID, class, generation)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// recordOwnership derives technical-owner candidates from CODEOWNERS.
//
// These are candidates, never sponsors: a code owner is responsible for review,
// which is not the same as being accountable for an agent. Sponsorship stays a
// separate governance action that must resolve to a person.
func (m *igaManager) recordOwnership(workspaceID uuid.UUID, subjectID uuid.UUID, rules []CodeownerRule, declPath string) int {
	owners := MatchCodeowners(rules, declPath)
	if len(owners) == 0 {
		return 0
	}
	n := 0
	for i, o := range owners {
		kind := "user"
		if strings.Contains(o, "/") {
			// An @org/team handle may be notified, but cannot itself be the
			// accountable person.
			kind = "team"
		}
		if err := m.repo.UpsertOwnershipCandidate(&models.IGAOwnershipCandidate{
			ID: uuid.New(), WorkspaceID: workspaceID,
			SubjectKind: "agent", SubjectID: subjectID,
			CandidateKind: kind, CandidateRef: o,
			EvidenceSource: "CODEOWNERS match on " + declPath,
			// Earlier entries on the winning line rank higher.
			Rank: 100 - i, State: "proposed",
		}); err == nil {
			n++
		}
	}
	return n
}

// recordSurvivingAttribute writes a canonical value with its authority rank.
//
// When a second source disagrees, the loser is not discarded: it is stored as
// 'contested' so the disagreement stays visible instead of being silently
// overwritten by whoever wrote last.
func (m *igaManager) recordSurvivingAttribute(workspaceID uuid.UUID, entityKind string, entityID uuid.UUID, attribute string, value interface{}, observationID uuid.UUID, mode string) {
	rank := models.EvidenceRank(mode)
	existing, err := m.repo.GetSurvivingAttribute(workspaceID, entityKind, entityID, attribute)
	if err == nil && existing != nil {
		if rank <= existing.AuthorityRank {
			// Weaker or equal evidence never displaces the incumbent; it is
			// recorded as a contradiction.
			_ = m.repo.AppendAttributeValue(&models.IGAAttributeValue{
				ID: uuid.New(), WorkspaceID: workspaceID, EntityKind: entityKind,
				EntityID: entityID, Attribute: attribute, Value: mustJSON(value),
				ObservationID: &observationID, AuthorityRank: rank,
				State: "contested", FallbackReason: "lower authority than surviving value",
			})
			return
		}
		// Stronger evidence wins; the previous value is kept as superseded.
		_ = m.repo.SupersedeAttribute(workspaceID, existing.ID)
	}
	_ = m.repo.AppendAttributeValue(&models.IGAAttributeValue{
		ID: uuid.New(), WorkspaceID: workspaceID, EntityKind: entityKind,
		EntityID: entityID, Attribute: attribute, Value: mustJSON(value),
		ObservationID: &observationID, AuthorityRank: rank, State: "surviving",
	})
}

type classOutcome struct {
	state     string
	reason    string
	inspected int64
	denied    int64
}

// grantClass maps a grant subject to the object class its coverage lands under,
// so a missing PAT permission does not silently degrade deploy-key coverage.
func grantClass(subjectKind string) string {
	switch subjectKind {
	case "fine_grained_pat":
		return models.ClassFineGrainedPAT
	case "deploy_key":
		return models.ClassDeployKey
	case "webhook":
		return models.ClassWebhook
	default:
		return models.ClassAppInstallation
	}
}

// ingestGrant turns one native grant into the canonical access triple:
//
//	identity_account  --entitlement-->  resource
//
// The native rights are preserved verbatim alongside the normalized reading, so
// a reviewer always sees what the provider actually said.
//
// calculation_state is the honest part. A grant we can see in full on a
// selected repository is 'complete'. A grant whose effect depends on controls
// we cannot observe — org policy, rulesets, SSO enforcement — is 'partial' with
// an 'unknown' conclusion, because a source grant is not automatically
// effective access.
func (m *igaManager) ingestGrant(workspaceID uuid.UUID, integ *models.IGAIntegration, run *models.IGAScanRun, scope ProviderScope, g ProviderGrant, report *ScanReport) {
	now := time.Now()

	// The identity holding the grant.
	identity := &models.IGAIdentityAccount{
		ID: uuid.New(), WorkspaceID: workspaceID,
		DisplayName: g.SubjectName, AccountKind: g.SubjectKind,
		IdentityBacking: "provider_native", RollupState: models.RollupConfirmed,
	}
	if err := m.repo.UpsertIdentityAccount(identity); err != nil {
		report.Issues = append(report.Issues, fmt.Sprintf("identity %s: %v", g.SubjectNativeID, err))
		return
	}
	report.Identities++

	// Non-secret credential metadata, bound to the identity. Never a value.
	if g.CredentialType != "" {
		_ = m.repo.UpsertCredential(&models.IGACredential{
			ID: uuid.New(), WorkspaceID: workspaceID, IdentityAccountID: identity.ID,
			CredentialType: g.CredentialType, Issuer: integ.ProviderHost,
			KeyIdentifier: g.KeyIdentifier, ExpiresAt: g.ExpiresAt, LastUsedAt: g.LastUsedAt,
			RotationPosture: rotationPosture(g.ExpiresAt, now), Lifecycle: models.LifecycleActive,
		})
		report.Credentials++
	}

	// The protected thing.
	resource := &models.IGAResource{
		ID: uuid.New(), WorkspaceID: workspaceID,
		ResourceKind: "repository", DisplayName: scope.DisplayName,
		Stage: "unknown", Lifecycle: models.LifecycleActive,
	}
	if err := m.repo.UpsertResource(resource); err != nil {
		report.Issues = append(report.Issues, fmt.Sprintf("resource %s: %v", scope.DisplayName, err))
		return
	}

	// The grant itself.
	ent := &models.IGAEntitlement{
		ID: uuid.New(), WorkspaceID: workspaceID, ResourceID: &resource.ID,
		NativeGrantKind:  g.GrantKind,
		NativeRights:     mustJSON(g.NativeRights),
		NormalizedRights: mustJSON(NormalizeRights(g.NativeRights)),
		NativeScope:      scope.NativeID,
		// Revocable through a supported provider path.
		Remediable: g.SubjectKind != "app_installation",
	}
	if err := m.repo.UpsertEntitlement(ent); err != nil {
		report.Issues = append(report.Issues, fmt.Sprintf("entitlement %s: %v", g.GrantKind, err))
		return
	}

	calc, conclusion := models.CalcComplete, models.ConclusionEffective
	if g.Conditional || len(g.NativeRights) == 0 {
		// We can see that a path exists but not whether it resolves. Saying
		// "effective" here would be a claim the evidence does not support.
		calc, conclusion = models.CalcPartial, models.ConclusionUnknown
	}

	if err := m.repo.UpsertAccessEdge(&models.IGAAccessEdge{
		ID: uuid.New(), WorkspaceID: workspaceID,
		SubjectKind: "identity_account", SubjectID: identity.ID,
		EntitlementID: &ent.ID, ResourceID: &resource.ID,
		Direction: "outbound", PathKind: g.GrantKind,
		CalculationState: calc, EffectiveConclusion: conclusion,
		NativeScope: scope.NativeID, ObservedAt: &now,
	}); err != nil {
		report.Issues = append(report.Issues, fmt.Sprintf("access edge %s: %v", g.GrantKind, err))
		return
	}
	report.AccessEdges++
}

// rotationPosture reports credential hygiene from expiry metadata alone. It
// says "unknown" rather than guessing when the provider exposes no expiry.
func rotationPosture(expires *time.Time, now time.Time) string {
	if expires == nil {
		return "no_expiry"
	}
	if expires.Before(now) {
		return "expired"
	}
	if expires.Sub(now) > 365*24*time.Hour {
		return "long_lived"
	}
	return "bounded"
}

// degrade turns a per-scope failure into partial coverage plus an operational
// issue. It never fails the scan and never reduces a count to zero.
func (m *igaManager) degrade(workspaceID, integrationID uuid.UUID, c *classOutcome, scope ProviderScope, class string, err error, report *ScanReport) {
	c.state = models.CoveragePartial
	c.reason = err.Error()
	c.denied++
	now := time.Now()
	kind := "api_failure"
	if strings.Contains(strings.ToLower(err.Error()), "permission") ||
		strings.Contains(err.Error(), "403") {
		kind = "permission_denied"
	}
	_ = m.repo.RecordIssue(&models.IGAOperationalIssue{
		ID: uuid.New(), WorkspaceID: workspaceID, IntegrationID: &integrationID,
		IssueKind: kind, Severity: "warning", ObjectClass: class,
		ScopeRef:    scope.DisplayName,
		Detail:      mustJSON(map[string]interface{}{"error": err.Error()}),
		FirstSeenAt: now, LastSeenAt: now,
	})
	report.Issues = append(report.Issues, fmt.Sprintf("%s/%s: %v", scope.DisplayName, class, err))
}

// findPriorHash returns the content hash we stored last time we parsed this
// path, or "" if we have never seen it. A miss is not an error.
func (m *igaManager) findPriorHash(workspaceID, integrationID uuid.UUID, recognitionKey string) (string, error) {
	prior, err := m.repo.FindSourceObjectByKey(workspaceID, integrationID,
		models.ClassRepoDeclaration, recognitionKey)
	if err != nil {
		if errors.Is(err, repositories.ErrIGANotFound) {
			return "", nil
		}
		return "", err
	}
	return prior.RawHash, nil
}

func (m *igaManager) ingest(workspaceID uuid.UUID, integ *models.IGAIntegration, run *models.IGAScanRun, scope ProviderScope, o ProviderObject, class string, report *ScanReport) {
	m.ingestWithRule(workspaceID, integ, run, scope, o, class, IGARule{}, "", report)
}

// touchSourceObject records "seen again, unchanged" for a file whose fetch was
// skipped. It advances last_seen_at and scan_generation WITHOUT appending an
// observation: nothing new was learned, so there is no new fact to record —
// but the object must not look absent to the deletion sweep.
func (m *igaManager) touchSourceObject(workspaceID uuid.UUID, integ *models.IGAIntegration, run *models.IGAScanRun, recognition string) {
	_ = m.repo.TouchSourceObject(workspaceID, integ.ID,
		models.ClassRepoDeclaration, recognition, run.Generation)
}

// ingestWithRule writes source object -> observation -> (maybe) candidate.
// Order is deliberate and is the projection rule: evidence lands first, and
// only then may anything be proposed or promoted.
func (m *igaManager) ingestWithRule(workspaceID uuid.UUID, integ *models.IGAIntegration, run *models.IGAScanRun, scope ProviderScope, o ProviderObject, class string, rule IGARule, rawHash string, report *ScanReport) {
	now := time.Now()
	recognition := o.NativeID
	if recognition == "" {
		recognition = fmt.Sprintf("%s:%s", scope.NativeID, o.DisplayName)
	}

	src := &models.IGASourceObject{
		ID:             uuid.New(),
		WorkspaceID:    workspaceID,
		IntegrationID:  integ.ID,
		ObjectType:     class,
		RecognitionKey: recognition,
		NativeID:       o.NativeID,
		// Locator is descriptive: a rename changes this, never the identity.
		Locator:           mustJSON(map[string]interface{}{"scope": scope.DisplayName, "name": o.DisplayName}),
		NormalizedPayload: mustJSON(o.Payload),
		RawHash:           rawHash,
		SourceSubjectKey:  scope.NativeID,
		ScanGeneration:    &run.Generation,
		Lifecycle:         models.LifecycleActive,
		FirstSeenAt:       now,
		LastSeenAt:        now,
	}
	stored, err := m.repo.UpsertSourceObject(src)
	if err != nil {
		report.Issues = append(report.Issues, fmt.Sprintf("source object %s: %v", recognition, err))
		return
	}
	report.SourceObjects++

	mode := o.EvidenceMode
	if mode == "" {
		mode = models.EvidenceIdentityGrant
	}
	obs := &models.IGAObservation{
		ID:                uuid.New(),
		WorkspaceID:       workspaceID,
		SourceObjectID:    stored.ID,
		ScanRunID:         &run.ID,
		Mode:              mode,
		FactPayload:       mustJSON(o.Payload),
		ObservedAt:        now,
		NormalizerVersion: normalizerVersion,
		RuleID:            rule.ID,
		RuleVersion:       rule.Version,
		// Idempotency: the same fact from the same generation is one row.
		DedupeKey: fmt.Sprintf("%s|%s|%d|%s", class, recognition, run.Generation, mode),
	}
	storedObs, err := m.repo.AppendObservation(obs)
	if err != nil {
		report.Issues = append(report.Issues, fmt.Sprintf("observation %s: %v", recognition, err))
		return
	}
	report.Observations++

	// Identity and SBOM evidence never proposes an agent. That is the whole
	// point of the lane separation: a GitHub App, a PAT or a dependency is not
	// an AI agent, and counting it as one is the failure mode being avoided.
	if class == models.ClassAppInstallation || class == models.ClassSBOMComponent {
		if class == models.ClassAppInstallation {
			_ = m.repo.UpsertIdentityAccount(&models.IGAIdentityAccount{
				ID: uuid.New(), WorkspaceID: workspaceID,
				DisplayName: o.DisplayName, AccountKind: "app_installation",
				IdentityBacking: "provider_app", RollupState: models.RollupConfirmed,
			})
		}
		return
	}

	// Everything else becomes a candidate carrying its rule and evidence.
	cand := &models.IGACandidate{
		ID:                 uuid.New(),
		WorkspaceID:        workspaceID,
		SourceObjectID:     stored.ID,
		ProposedObjectKind: "agent",
		ProposalSignature:  fmt.Sprintf("agent|%s", recognition),
		RuleID:             rule.ID,
		RuleVersion:        rule.Version,
		EvidenceMode:       mode,
		State:              models.CandidatePending,
	}
	storedCand, err := m.repo.UpsertCandidate(cand)
	if err != nil {
		report.Issues = append(report.Issues, fmt.Sprintf("candidate %s: %v", recognition, err))
		return
	}
	if storedCand.ID == cand.ID {
		report.Candidates++
	}
	_ = m.repo.LinkObservation(&models.IGAObservationLink{
		ID: uuid.New(), WorkspaceID: workspaceID, ObservationID: storedObs.ID,
		TargetKind: "candidate", TargetID: storedCand.ID, Relation: "supports",
	})

	// Only provider-declared evidence may auto-confirm. Everything weaker waits
	// for a human, which is what keeps a dependency or a workflow reference
	// from silently becoming a confirmed agent.
	if models.CanAutoConfirm(mode) && storedCand.State == models.CandidatePending {
		if _, err := m.promote(workspaceID, storedCand, storedObs, o.DisplayName, "auto: provider-declared agent", "system", o.OwnerCandidates); err == nil {
			report.AgentsConfirmed++
		}
	}
}

// promote turns a confirmed candidate into a canonical agent, wiring the
// evidence link so the agent can always be drilled back to what justified it.
func (m *igaManager) promote(workspaceID uuid.UUID, cand *models.IGACandidate, obs *models.IGAObservation, displayName, reason, by string, owners []string) (*models.IGAAgent, error) {
	decided, err := m.repo.DecideCandidate(workspaceID, cand.ID, cand.Version, models.CandidateConfirmed, reason, by)
	if err != nil {
		return nil, err
	}

	rollup := models.RollupConfirmed
	if !models.CanAutoConfirm(cand.EvidenceMode) {
		// A human confirmed it, but the underlying evidence is still weaker
		// than provider-declared. Say so rather than overstating.
		rollup = models.RollupUnknown
	}
	agent := &models.IGAAgent{
		ID: uuid.New(), WorkspaceID: workspaceID,
		DisplayName: displayName, Classification: cand.EvidenceMode,
		Status: "active", RollupState: rollup, Lifecycle: models.LifecycleActive,
	}
	if err := m.repo.CreateAgent(agent); err != nil {
		return nil, err
	}

	// Strong provider-native bindings may auto-link; weaker ones stay proposals.
	strength := models.CorrelationWeak
	state := models.CorrelationProposed
	if models.CanAutoConfirm(cand.EvidenceMode) {
		strength, state = models.CorrelationStrong, models.CorrelationAccepted
	}
	_ = m.repo.CreateCorrelation(&models.IGACorrelation{
		ID: uuid.New(), WorkspaceID: workspaceID, SourceObjectID: decided.SourceObjectID,
		CanonicalKind: "agent", CanonicalID: agent.ID,
		JoinKey: cand.ProposalSignature, Strength: strength, State: state,
	})
	if obs != nil {
		_ = m.repo.LinkObservation(&models.IGAObservationLink{
			ID: uuid.New(), WorkspaceID: workspaceID, ObservationID: obs.ID,
			TargetKind: "agent", TargetID: agent.ID, Relation: "supports",
		})
	}

	// Ownership. CODEOWNERS gives technical-owner CANDIDATES — never a sponsor,
	// and never confirmed automatically: code-review responsibility is not
	// accountability for an agent.
	recorded := 0
	for i, o := range owners {
		kind := "user"
		if strings.Contains(o, "/") {
			// An @org/team may be notified, but cannot be the accountable person.
			kind = "team"
		}
		if err := m.repo.UpsertOwnershipCandidate(&models.IGAOwnershipCandidate{
			ID: uuid.New(), WorkspaceID: workspaceID, SubjectKind: "agent", SubjectID: agent.ID,
			CandidateKind: kind, CandidateRef: o,
			EvidenceSource: "CODEOWNERS", Rank: 100 - i, State: "proposed",
		}); err == nil {
			recorded++
		}
	}
	if recorded == 0 {
		// Record the ABSENCE explicitly. An unowned agent is a finding, and an
		// empty ownership list would read as "not checked" rather than
		// "checked, and nobody owns this".
		_ = m.repo.UpsertOwnershipCandidate(&models.IGAOwnershipCandidate{
			ID: uuid.New(), WorkspaceID: workspaceID, SubjectKind: "agent", SubjectID: agent.ID,
			CandidateKind: "unknown", CandidateRef: "", EvidenceSource: "no ownership evidence in source",
			Rank: 0, State: "proposed",
		})
	}

	// Survivorship for the display name, ranked by the strength of the evidence
	// behind it. A later, weaker source disagreeing is kept as contested rather
	// than overwriting.
	if obs != nil {
		m.recordSurvivingAttribute(workspaceID, "agent", agent.ID, "display_name",
			displayName, obs.ID, cand.EvidenceMode)
	}
	return agent, nil
}

func (m *igaManager) GetScanRun(workspaceID, id uuid.UUID) (*models.IGAScanRun, error) {
	return m.repo.GetScanRun(workspaceID, id)
}

func (m *igaManager) Coverage(workspaceID, integrationID uuid.UUID) ([]models.IGACoverageState, error) {
	return m.repo.ListCoverage(workspaceID, integrationID)
}

func (m *igaManager) SourceHealth(workspaceID uuid.UUID, integrationID *uuid.UUID) ([]models.IGAOperationalIssue, error) {
	return m.repo.ListIssues(workspaceID, integrationID)
}

/* --------------------------------- govern ------------------------------ */

func (m *igaManager) ListCandidates(workspaceID uuid.UUID, state string, limit, offset int) ([]models.IGACandidate, int64, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	return m.repo.ListCandidates(workspaceID, state, limit, offset)
}

func (m *igaManager) DecideCandidate(workspaceID, id uuid.UUID, expectedVersion int64, decision, reason, by string) (*models.IGACandidate, error) {
	switch decision {
	case models.CandidateConfirmed:
		cand, err := m.repo.GetCandidate(workspaceID, id)
		if err != nil {
			return nil, err
		}
		if cand.State != models.CandidatePending {
			return nil, fmt.Errorf("candidate is already %s", cand.State)
		}
		if cand.Version != expectedVersion {
			return nil, repositories.ErrIGAVersionStale
		}
		src, err := m.repo.GetSourceObject(workspaceID, cand.SourceObjectID)
		if err != nil {
			return nil, err
		}
		obsList, _ := m.repo.ListObservations(workspaceID, cand.SourceObjectID)
		var obs *models.IGAObservation
		if len(obsList) > 0 {
			obs = &obsList[0]
		}
		name := src.NativeID
		if _, err := m.promote(workspaceID, cand, obs, name, reason, by, ownersFromSource(src)); err != nil {
			return nil, err
		}
		return m.repo.GetCandidate(workspaceID, id)

	case models.CandidateRejected, models.CandidateInsufficient:
		return m.repo.DecideCandidate(workspaceID, id, expectedVersion, decision, reason, by)
	default:
		return nil, fmt.Errorf("unknown decision %q", decision)
	}
}

func (m *igaManager) ListAgents(workspaceID uuid.UUID, rollup string, limit, offset int) ([]models.IGAAgent, int64, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	return m.repo.ListAgents(workspaceID, rollup, limit, offset)
}

func (m *igaManager) AgentDetail(workspaceID, agentID uuid.UUID) (*AgentDetail, error) {
	agent, err := m.repo.GetAgent(workspaceID, agentID)
	if err != nil {
		return nil, err
	}
	// An agent's own edges, plus the edges of any identity it has been
	// CONFIRMED to use. A weak, undecided correlation must not silently import
	// another principal's access.
	paths, _ := m.repo.ListAccessPaths(workspaceID, agentID)
	corrs, _ := m.repo.ListCorrelationsFor(workspaceID, "agent", agentID)
	for _, c := range corrs {
		if c.State == models.CorrelationAccepted && c.CanonicalKind == "identity_account" {
			extra, _ := m.repo.ListAccessPaths(workspaceID, c.CanonicalID)
			paths = append(paths, extra...)
		}
	}

	owners, _ := m.repo.ListOwnershipCandidates(workspaceID, agentID)
	links, _ := m.repo.ListObservationLinks(workspaceID, "agent", agentID)
	attrs, _ := m.repo.ListAttributeValues(workspaceID, "agent", agentID)

	return &AgentDetail{
		Agent:     agent,
		Instances: []models.IGAAgentInstance{},
		// GitHub evidence cannot prove a deployment executed, so the absence of
		// instances is reported as unknown rather than as "not running".
		InstanceCoverage:    models.CoverageUnknown,
		AccessPaths:         paths,
		AccessSummary:       summarizeAccess(paths),
		OwnershipCandidates: owners,
		AttributeValues:     attrs,
		Correlations:        corrs,
		EvidenceCount:       len(links),
	}, nil
}

// summarizeAccess describes how much of the access picture was actually
// computed, so a caller cannot mistake "nothing calculated" for "no access".
func summarizeAccess(paths []repositories.AccessPath) AccessSummary {
	s := AccessSummary{}
	for _, p := range paths {
		if p.Edge.Direction == "inbound" {
			s.Inbound++
		} else {
			s.Outbound++
		}
		switch p.Edge.CalculationState {
		case models.CalcComplete:
			s.Complete++
		case models.CalcPartial:
			s.Partial++
		default:
			s.Unknown++
		}
	}
	switch {
	case len(paths) == 0:
		s.State = models.CalcUnknown
		s.Statement = "no access paths have been calculated for this agent; this is not evidence that it has no access"
	case s.Complete == len(paths):
		s.State = models.CalcComplete
		s.Statement = "all observed access paths were fully calculated"
	default:
		s.State = models.CalcPartial
		s.Statement = "some access paths could not be fully calculated; unsupported controls or missing evidence leave them unknown"
	}
	return s
}

// AgentEvidence returns the observations behind an agent, walking the links so
// both supporting and contradicting evidence surface. This is the drill-down
// that makes every canonical fact accountable to what produced it.
func (m *igaManager) AgentEvidence(workspaceID, agentID uuid.UUID) ([]models.IGAObservation, error) {
	if _, err := m.repo.GetAgent(workspaceID, agentID); err != nil {
		return nil, err
	}
	out, err := m.repo.ListObservationsForTarget(workspaceID, "agent", agentID)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []models.IGAObservation{}
	}
	return out, nil
}

func (m *igaManager) DecideOwnership(workspaceID, id uuid.UUID, expectedVersion int64, decision, by string) (*models.IGAOwnershipCandidate, error) {
	if decision != "confirmed" && decision != "rejected" {
		return nil, fmt.Errorf("unknown decision %q", decision)
	}
	// Confirming a technical owner never assigns a business sponsor: that is a
	// separate governance action that must resolve to a person.
	return m.repo.DecideOwnership(workspaceID, id, expectedVersion, decision, by)
}

/* -------------------------------- ingress ------------------------------ */

// AcceptWebhook implements the normative ingress order: verify the signature
// over the RAW body, resolve the binding server-side, commit the delivery and
// its job in one transaction, and only then let the caller return 2xx.
func (m *igaManager) AcceptWebhook(in WebhookInput) (*WebhookResult, error) {
	now := time.Now()
	bodyHash := HashBody(in.Body)

	// 1. Signature, over the unmodified bytes, compared in constant time.
	if !verifyGitHubSignature(in.Secret, in.Body, in.Signature) {
		_ = m.repo.RecordRejectedDelivery(&models.IGAWebhookDelivery{
			ID: uuid.New(), AppRegistrationID: in.AppRegistrationID, DeliveryID: in.DeliveryID,
			EventType: in.EventType, Action: in.Action, BodyHash: bodyHash,
			ReceivedAt: now, State: models.DeliveryRejectedSignature,
		})
		return nil, repositories.ErrIGASignature
	}

	// 2. Binding resolved server-side. The payload's installation id is a
	//    lookup key, never an authorization: it selects a row that must already
	//    be verified and active, and the workspace comes from THAT row.
	integ, err := m.repo.ResolveBinding(in.AppRegistrationID, in.InstallationID)
	if err != nil {
		_ = m.repo.RecordRejectedDelivery(&models.IGAWebhookDelivery{
			ID: uuid.New(), AppRegistrationID: in.AppRegistrationID, DeliveryID: in.DeliveryID,
			EventType: in.EventType, Action: in.Action, BodyHash: bodyHash,
			ReceivedAt: now, SignatureValidatedAt: &now, State: models.DeliveryRejectedBinding,
		})
		return nil, repositories.ErrIGABindingFailed
	}

	// 3. Delivery + job, one transaction, before any acknowledgement.
	delivery := &models.IGAWebhookDelivery{
		ID: uuid.New(), AppRegistrationID: in.AppRegistrationID, DeliveryID: in.DeliveryID,
		WorkspaceID: &integ.WorkspaceID, IntegrationID: &integ.ID,
		EventType: in.EventType, Action: in.Action, BodyHash: bodyHash,
		ReceivedAt: now, SignatureValidatedAt: &now, State: models.DeliveryAccepted,
	}
	job := &models.IGADurableJob{
		ID: uuid.New(), WorkspaceID: integ.WorkspaceID, IntegrationID: integ.ID,
		JobKind: "rescan_affected_scope",
		// Coalescing key: many events for one object collapse to one rescan.
		DedupeKey:   fmt.Sprintf("%s|%s", in.EventType, in.DeliveryID),
		State:       models.JobReady,
		AvailableAt: now,
	}
	_, redelivery, err := m.repo.AcceptDelivery(delivery, job)
	if err != nil {
		return nil, err
	}
	return &WebhookResult{Accepted: true, Redelivery: redelivery}, nil
}

// verifyGitHubSignature checks X-Hub-Signature-256 with a timing-safe compare.
func verifyGitHubSignature(secret string, body []byte, header string) bool {
	if secret == "" || header == "" {
		return false
	}
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(strings.TrimPrefix(header, prefix)))
}

// RunWorkerOnce claims and processes at most one durable job. Returns false
// when the queue is empty. A crash mid-job leaves a reclaimable lease.
func (m *igaManager) RunWorkerOnce(ctx context.Context, worker string) (bool, error) {
	job, err := m.repo.ClaimJob(worker, 5*time.Minute)
	if err != nil {
		if errors.Is(err, repositories.ErrIGANotFound) {
			return false, nil
		}
		return false, err
	}

	switch job.JobKind {
	case "rescan_affected_scope":
		run, err := m.StartScan(job.WorkspaceID, job.IntegrationID, models.ScanModeIncremental, "worker")
		if err != nil {
			_ = m.repo.CompleteJob(job.WorkspaceID, job.ID, models.JobFailed, err.Error())
			return true, err
		}
		if _, err := m.RunScan(ctx, job.WorkspaceID, run.ID); err != nil {
			_ = m.repo.CompleteJob(job.WorkspaceID, job.ID, models.JobFailed, err.Error())
			return true, err
		}
	default:
		_ = m.repo.CompleteJob(job.WorkspaceID, job.ID, models.JobDead, "unknown job kind")
		return true, nil
	}

	return true, m.repo.CompleteJob(job.WorkspaceID, job.ID, models.JobDone, "")
}

// ownersFromSource recovers the CODEOWNERS candidates recorded on a source
// object at scan time, so a later human confirmation attributes the agent to
// the same owners the scan saw rather than losing them.
func ownersFromSource(src *models.IGASourceObject) []string {
	if src == nil || len(src.NormalizedPayload) == 0 {
		return nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(src.NormalizedPayload, &payload); err != nil {
		return nil
	}
	raw, ok := payload["codeowners"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

/* --------------------------- cursor pagination -------------------------- */

// AgentPage, CandidatePage and IdentityPage each carry their OWN total. The
// contract forbids adding confirmed agents, candidates and identities into a
// single "agents discovered" number, so they never share a count.
type AgentPage struct {
	Items      []models.IGAAgent `json:"items"`
	Total      int64             `json:"total_confirmed_agents"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

type CandidatePage struct {
	Items      []models.IGACandidate `json:"items"`
	Total      int64                 `json:"total_candidates"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

type IdentityPage struct {
	Items      []models.IGAIdentityAccount `json:"items"`
	Total      int64                       `json:"total_identities"`
	NextCursor string                      `json:"next_cursor,omitempty"`
}

// encodeCursor produces an opaque position token. Clients must not construct or
// modify it, which is why it is base64 rather than readable fields.
func encodeCursor(t time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(fmt.Sprintf("%d|%s", t.UTC().UnixNano(), id.String())))
}

func decodeCursor(s string) (*repositories.CursorKeyT, error) {
	if s == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("malformed cursor")
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed cursor")
	}
	ns, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("malformed cursor")
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return nil, fmt.Errorf("malformed cursor")
	}
	return repositories.NewCursorKey(time.Unix(0, ns), id), nil
}

func pageLimit(limit int) int {
	if limit <= 0 || limit > 200 {
		return 50
	}
	return limit
}

func (m *igaManager) ListAgentsPage(workspaceID uuid.UUID, rollup, cursor string, limit int) (*AgentPage, error) {
	after, err := decodeCursor(cursor)
	if err != nil {
		return nil, err
	}
	limit = pageLimit(limit)
	// Fetch one extra to learn whether another page exists without a count.
	items, err := m.repo.ListAgentsCursor(workspaceID, rollup, after, limit+1)
	if err != nil {
		return nil, err
	}
	total, err := m.repo.CountAgents(workspaceID, rollup)
	if err != nil {
		return nil, err
	}
	out := &AgentPage{Total: total}
	if len(items) > limit {
		last := items[limit-1]
		out.NextCursor = encodeCursor(last.CreatedAt, last.ID)
		items = items[:limit]
	}
	out.Items = items
	return out, nil
}

func (m *igaManager) ListCandidatesPage(workspaceID uuid.UUID, state, cursor string, limit int) (*CandidatePage, error) {
	after, err := decodeCursor(cursor)
	if err != nil {
		return nil, err
	}
	limit = pageLimit(limit)
	items, err := m.repo.ListCandidatesCursor(workspaceID, state, after, limit+1)
	if err != nil {
		return nil, err
	}
	total, err := m.repo.CountCandidates(workspaceID, state)
	if err != nil {
		return nil, err
	}
	out := &CandidatePage{Total: total}
	if len(items) > limit {
		last := items[limit-1]
		out.NextCursor = encodeCursor(last.CreatedAt, last.ID)
		items = items[:limit]
	}
	out.Items = items
	return out, nil
}

func (m *igaManager) ListIdentityAccountsPage(workspaceID uuid.UUID, cursor string, limit int) (*IdentityPage, error) {
	after, err := decodeCursor(cursor)
	if err != nil {
		return nil, err
	}
	limit = pageLimit(limit)
	items, err := m.repo.ListIdentityAccounts(workspaceID, after, limit+1)
	if err != nil {
		return nil, err
	}
	out := &IdentityPage{Total: int64(len(items))}
	if len(items) > limit {
		last := items[limit-1]
		out.NextCursor = encodeCursor(last.CreatedAt, last.ID)
		items = items[:limit]
		out.Total = int64(len(items))
	}
	out.Items = items
	return out, nil
}

// AgentAccessPaths answers "what can this agent reach?" together with how much
// of that answer was actually calculated.
func (m *igaManager) AgentAccessPaths(workspaceID, agentID uuid.UUID) ([]repositories.AccessPath, AccessSummary, error) {
	if _, err := m.repo.GetAgent(workspaceID, agentID); err != nil {
		return nil, AccessSummary{}, err
	}
	paths, err := m.repo.ListAccessPaths(workspaceID, agentID)
	if err != nil {
		return nil, AccessSummary{}, err
	}
	corrs, _ := m.repo.ListCorrelationsFor(workspaceID, "agent", agentID)
	for _, c := range corrs {
		if c.State == models.CorrelationAccepted && c.CanonicalKind == "identity_account" {
			extra, _ := m.repo.ListAccessPaths(workspaceID, c.CanonicalID)
			paths = append(paths, extra...)
		}
	}
	return paths, summarizeAccess(paths), nil
}
