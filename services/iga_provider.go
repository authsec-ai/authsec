package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// IGAProvider is the read surface a discovery source must implement. The
// methods mirror the enumeration funnel in order of cost:
//
//	Capabilities   what this installation is actually allowed to see
//	ListScopes     the estate (orgs, repositories)
//	ListNativeAgents  Lane A — the provider says "this is an agent"
//	ListIdentities    Lane C — apps, PATs, deploy keys, webhooks
//	ListSBOM       Lane B step 2 — one call, supporting signal only
//	ListTree       Lane B step 3 — one call, every path, no contents
//	FetchBlob      Lane B step 4 — only allowlisted paths survive to here
//
// Keeping this an interface is deliberate: the real GitHub client cannot be
// written honestly until the Stage-0 spike records which endpoints exist on
// which plan, and a fixture-backed implementation lets the entire pipeline be
// exercised and tested before then.
type IGAProvider interface {
	Name() string
	Capabilities(ctx context.Context, in ProviderContext) (map[string]string, error)
	ListScopes(ctx context.Context, in ProviderContext) ([]ProviderScope, error)
	ListNativeAgents(ctx context.Context, in ProviderContext, scope ProviderScope) ([]ProviderObject, error)
	ListIdentities(ctx context.Context, in ProviderContext, scope ProviderScope) ([]ProviderObject, error)
	ListSBOM(ctx context.Context, in ProviderContext, scope ProviderScope) ([]ProviderObject, error)
	ListTree(ctx context.Context, in ProviderContext, scope ProviderScope) (entries []TreeEntry, truncated bool, err error)

	// ListTreeDir lists ONE directory level, non-recursively, for the recovery
	// path after ListTree reports truncation. dir is a repo-relative directory
	// ("" is the root) and returned paths are full repo paths.
	//
	// A truncated tree is the one case where the single-call budget cannot
	// hold: the cut-off is arbitrary, so the paths the catalogue names may sit
	// on either side of it. Re-listing only the directories the catalogue can
	// name recovers most of them for a handful of extra calls, without walking
	// a repository we were never going to read in full.
	ListTreeDir(ctx context.Context, in ProviderContext, scope ProviderScope, dir string) ([]TreeEntry, error)

	FetchBlob(ctx context.Context, in ProviderContext, scope ProviderScope, entry TreeEntry) ([]byte, error)

	// ListGrants returns the native access grants observable for a scope: an
	// installation's repository permissions, a PAT's permission set, a deploy
	// key's read/write posture. These become entitlements and access edges —
	// the answer to "what can this identity actually reach?".
	ListGrants(ctx context.Context, in ProviderContext, scope ProviderScope) ([]ProviderGrant, error)

	// ListCodeowners returns CODEOWNERS rules for a repository. GitHub applies
	// LAST matching pattern precedence, so order is significant and must be
	// preserved as returned.
	ListCodeowners(ctx context.Context, in ProviderContext, scope ProviderScope) ([]CodeownerRule, error)
}

// ProviderGrant is one native access grant. NativeRights keeps the provider's
// own wording; the normalized reading is derived from it, never instead of it.
type ProviderGrant struct {
	// SubjectNativeID identifies the principal holding the grant — an
	// installation, a PAT owner, a deploy key.
	SubjectNativeID string
	SubjectKind     string // app_installation | fine_grained_pat | deploy_key
	SubjectName     string
	GrantKind       string            // installation_permission | pat_permission | deploy_key
	NativeRights    map[string]string // e.g. {"contents":"write"}
	// Conditional marks a grant whose effect depends on controls we cannot
	// observe (org policy, rulesets, SSO enforcement). It forces the edge's
	// calculation_state to partial and its conclusion to unknown.
	Conditional bool
	// Credential metadata; non-secret only. Never a value.
	CredentialType string
	KeyIdentifier  string
	ExpiresAt      *time.Time
	LastUsedAt     *time.Time
}

// CodeownerRule is one CODEOWNERS line: a path pattern and its owners.
type CodeownerRule struct {
	Pattern string
	Owners  []string // "@user" or "@org/team"
}

// ProviderContext is what a provider needs to make calls on behalf of one
// verified integration. The token is minted per call and never persisted.
type ProviderContext struct {
	// WorkspaceID resolves which workspace's GitHub App credentials to use.
	WorkspaceID       uuid.UUID
	IntegrationID     string
	AppRegistrationID string
	InstallationID    string
	ProviderHost      string
}

// ProviderScope is one enumerable container: an organization or a repository.
type ProviderScope struct {
	Kind          string // "organization" | "repository"
	NativeID      string // immutable provider id — the recognition key input
	DisplayName   string // owner/name — a LOCATOR, never identity
	DefaultBranch string
	// Archived reports the provider's own read-only flag. It qualifies a
	// finding rather than suppressing it: declarations in an archived
	// repository still name real secrets, but nobody can merge a fix.
	Archived bool
}

// ProviderObject is one raw thing the provider returned, before any
// interpretation. Payload keeps provider-native fields; they may only ever
// land in source_objects / observations.
type ProviderObject struct {
	ObjectType   string
	NativeID     string
	DisplayName  string
	Payload      map[string]interface{}
	EvidenceMode string
	// OwnerCandidates are the CODEOWNERS owners matching this object's path,
	// resolved at scan time with last-match-wins precedence.
	OwnerCandidates []string
}

// TreeEntry is one path from the recursive tree listing. SHA is the blob hash
// GitHub hands over for free — it is what makes incremental refresh cheap,
// because an unchanged SHA means the fetch can be skipped entirely.
type TreeEntry struct {
	Path string
	SHA  string
	Size int64
}

/* ----------------------------- rule catalogue --------------------------- */

// IGARule is one detection rule. Every rule declares the paths it needs, the
// evidence mode it produces, and — critically — the strongest outcome it is
// allowed to reach. A rule may only auto-confirm when the provider itself
// declares an agent; everything else emits a candidate for a human.
type IGARule struct {
	ID           string
	Version      string
	ObjectClass  string
	PathGlobs    []string
	EvidenceMode string
	// Confidence is how much this rule's match is worth ON ITS OWN.
	//
	// It is not severity and not a score to be averaged. It answers one
	// question: may a single match of this rule be counted as an agent, or
	// does it only ever propose a candidate? HIGH may be counted; MEDIUM and
	// LOW may not, and LOW needs corroboration before it is even worth a
	// reviewer's attention. See CombineConfidence.
	Confidence string
	// SensitiveKeys are redacted before persistence and never leave the parser.
	SensitiveKeys []string
	// Extract pulls typed facts out of a matched file. It returns non-secret
	// facts plus any secret NAMES referenced (names only, never values).
	Extract func(filePath string, body []byte) (facts map[string]interface{}, secretRefs []string, err error)
}

// Rule confidence. Deliberately three coarse values rather than a number:
// a numeric score invites averaging, and averaging two weak signals into a
// reassuring middle is exactly the failure this catalogue must not have.
const (
	// ConfidenceHigh — an explicit agent action, manifest or MCP config. A
	// single match may be counted.
	ConfidenceHigh = "high"
	// ConfidenceMedium — a framework in a container or IaC declaration.
	ConfidenceMedium = "medium"
	// ConfidenceLow — a dependency or a bare provider credential name.
	// Capability, not use: the library may be imported by nothing.
	ConfidenceLow = "low"
)

// CombineConfidence implements the rule that decides product quality.
//
// A LOW signal alone is a CANDIDATE, never an agent. TWO INDEPENDENT low
// signals in the same repository promote to MEDIUM — "langchain in
// requirements.txt" and "OPENAI_API_KEY in a workflow" is very likely an
// agent, while either alone is not. Independence is what makes the promotion
// meaningful, so two matches of the SAME rule id count once.
//
// The asymmetry with the cluster collector is deliberate and documented: for
// admission control, leaning permissive is right because a false positive
// costs one Ignore click. A repository scan produces far more candidates, and
// an inventory carrying hundreds of junk rows gets abandoned — at which point
// every real finding is missed too. Be permissive about what you RECORD, and
// strict about what you COUNT.
func CombineConfidence(signals []RuleSignal) string {
	distinctLow := map[string]struct{}{}
	best := ""
	for _, sig := range signals {
		switch sig.Confidence {
		case ConfidenceHigh:
			return ConfidenceHigh
		case ConfidenceMedium:
			best = ConfidenceMedium
		case ConfidenceLow:
			distinctLow[sig.RuleID] = struct{}{}
		}
	}
	if best == ConfidenceMedium {
		return ConfidenceMedium
	}
	if len(distinctLow) >= 2 {
		// Two independent weak signals corroborate each other.
		return ConfidenceMedium
	}
	if len(distinctLow) == 1 {
		return ConfidenceLow
	}
	return ""
}

// RuleSignal is one rule firing in one repository, for combination scoring.
type RuleSignal struct {
	RuleID     string
	Confidence string
	Path       string
}

// CountsAsAgent reports whether a combined confidence may enter the AGENT
// count, as opposed to the separate candidate bucket a human reviews.
//
// Only HIGH qualifies. This single predicate is where "never mix candidates
// into the agent count" is enforced, so the rule cannot be forgotten at a call
// site.
func CountsAsAgent(combined string) bool { return combined == ConfidenceHigh }

// providerCredentialNames are model-provider credential names, which score
// higher than generic suffixes because a generic name matches ordinary
// applications and generates the noise that gets an inventory abandoned.
var providerCredentialNames = []string{
	"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AZURE_OPENAI",
	"GOOGLE_API_KEY", "GEMINI_API_KEY", "COHERE_API_KEY",
	"MISTRAL_API_KEY", "LANGCHAIN_API_KEY", "LANGSMITH_API_KEY",
	"HUGGINGFACE", "HUGGING_FACE", "GROQ_API_KEY", "TOGETHER_API_KEY",
	"PERPLEXITY_API_KEY", "REPLICATE_API_TOKEN", "FIREWORKS_API_KEY",
	"DEEPSEEK_API_KEY", "XAI_API_KEY", "OPENROUTER_API_KEY",
}

// genericCredentialSuffixes match ordinary applications too, so a match on one
// of these alone is weighted LOW and documented as known over-matching.
var genericCredentialSuffixes = []string{"_API_KEY", "_TOKEN", "_SECRET"}

// Matches reports whether this rule wants the given path.
// vendoredPathSegments are directories whose contents are somebody else's code.
//
// This guard exists because Matches falls back to the BASENAME, so a glob like
// "package.json" also matches node_modules/left-pad/package.json. A repository
// that commits its dependencies would otherwise contribute thousands of matched
// paths, each costing a blob fetch — enough to exhaust an installation's hourly
// rate limit on one repository, and to fill the inventory with findings about
// libraries rather than about the customer's own agents.
var vendoredPathSegments = []string{
	"node_modules", "vendor", "third_party", "thirdparty",
	".venv", "venv", "site-packages", "bower_components",
	"dist", "build", ".git", "testdata", "fixtures", "__pycache__",
}

// isVendoredPath reports whether any path segment is a vendored directory.
// Segment-exact, not substring: a directory legitimately named "distribution"
// or "buildkite" must not be skipped.
func isVendoredPath(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		for _, v := range vendoredPathSegments {
			if strings.EqualFold(seg, v) {
				return true
			}
		}
	}
	return false
}

func (r IGARule) Matches(p string) bool {
	if isVendoredPath(p) {
		return false
	}
	base := path.Base(p)
	for _, g := range r.PathGlobs {
		if ok, _ := path.Match(g, p); ok {
			return true
		}
		if ok, _ := path.Match(g, base); ok {
			return true
		}
	}
	return false
}

// RedactedMarker replaces a sensitive VALUE while preserving the fact that the
// key was declared. "this tool declares an apiKey" is useful evidence; the key
// material behind it is not, and storing it turns the inventory into a target.
const RedactedMarker = "[redacted]"

// baselineSensitiveKeys is the redaction floor applied to EVERY rule.
//
// It exists because per-rule SensitiveKeys is author-supplied, and an author
// who forgets an entry would otherwise silently persist a live credential. A
// floor means a new rule is safe by default and a forgotten key is a missing
// nicety rather than a breach. Names still survive redaction: they are
// harvested separately by collectSecretNames, so "names only, never values"
// holds without depending on any one Extract implementation.
var baselineSensitiveKeys = []string{
	"apikey", "api_key", "apisecret", "api_secret",
	"token", "auth_token", "access_token", "refresh_token", "id_token",
	"secret", "client_secret", "password", "passwd", "passphrase",
	"credential", "credentials", "private_key", "privatekey",
	"authorization", "auth", "bearer", "session", "cookie",
	// Values here are routinely credentials, and only the NAMES are evidence.
	"env", "environment", "env_file", "with", "run", "args", "command",
	// Prompt bodies carry business logic and sometimes credentials. Presence
	// and length are the evidence; the text never is.
	"prompt", "prompts", "instructions", "system_prompt", "systemprompt",
	"headers", "header",
}

// sensitiveKeySet builds the effective redaction set for a rule: the baseline
// floor plus whatever the rule declares, matched case- and separator-
// insensitively so apiKey, api_key and APIKEY are one key.
func sensitiveKeySet(extra []string) map[string]struct{} {
	out := make(map[string]struct{}, len(baselineSensitiveKeys)+len(extra))
	add := func(k string) {
		k = strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(k))
		if k != "" {
			out[k] = struct{}{}
		}
	}
	for _, k := range baselineSensitiveKeys {
		add(k)
	}
	for _, k := range extra {
		add(k)
	}
	return out
}

func normalizeKey(k string) string {
	return strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(k))
}

// redactValue walks a fact value to ANY depth and replaces the value of every
// sensitive key, leaving structure and non-sensitive names intact.
//
// Depth is the whole point. The leak this closes was a rule copying a nested
// structure verbatim — tools:[{name:"db",apiKey:"sk-live-..."}] — where a
// top-level key check sees only "tools" and waves it through.
func redactValue(v interface{}, sensitive map[string]struct{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, inner := range t {
			if _, bad := sensitive[normalizeKey(k)]; bad {
				out[k] = RedactedMarker
				continue
			}
			out[k] = redactValue(inner, sensitive)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, inner := range t {
			out[i] = redactValue(inner, sensitive)
		}
		return out
	default:
		return v
	}
}

// ExtractRedacted is the ONLY extraction entry point a scanner may call.
//
// Extract itself is written per rule and cannot be trusted to redact — the
// catalogue's SensitiveKeys used to be documentation with nothing enforcing it,
// which is exactly how a nested apiKey reached the database. Funnelling every
// caller through here makes redaction structural instead of a promise each rule
// author has to remember to keep.
func (r IGARule) ExtractRedacted(filePath string, body []byte) (map[string]interface{}, []string, error) {
	facts, secretRefs, err := r.Extract(filePath, body)
	if err != nil || facts == nil {
		return facts, secretRefs, err
	}
	sensitive := sensitiveKeySet(r.SensitiveKeys)
	out := make(map[string]interface{}, len(facts))
	for k, v := range facts {
		if _, bad := sensitive[normalizeKey(k)]; bad {
			out[k] = RedactedMarker
			continue
		}
		out[k] = redactValue(v, sensitive)
	}
	return out, secretRefs, nil
}

// IGARuleCatalog is a versioned set of rules. The version is recorded on every
// scan run, so a rule change is visible in the evidence trail — and because raw
// bodies are discarded, a catalogue bump requires a rescan rather than a replay.
type IGARuleCatalog struct {
	Version string
	Rules   []IGARule
}

// agentFrameworkTokens is the shared framework vocabulary for repository
// evidence. It mirrors the Kubernetes collector's vocabulary on purpose: the
// same agent declared in a repo and observed in a cluster must be recognisable
// by both, or one channel silently misses what the other catches — which reads
// to a customer as a product bug rather than a sync problem.
//
// These are deliberately PACKAGE and ACTION names, not bare words. The cluster
// collector can afford substring matches on "claude" or "cursor" because a false
// positive there costs one Ignore click. A repository scan produces far more
// candidates, and an inventory carrying junk gets abandoned — at which point
// every real finding is missed too. So: "@anthropic-ai/claude-code", never
// "claude".
var agentFrameworkTokens = []string{
	"@anthropic-ai/claude-code", "claude-code", "anthropic",
	"openai-agents", "openai_agents", "openai-codex", "codex-cli",
	"langchain", "langserve", "langgraph", "langsmith",
	"llama-index", "llama_index", "llamaindex",
	"crewai", "crew-ai",
	"autogen", "pyautogen",
	"autogpt", "auto-gpt",
	"semantic-kernel", "semantic_kernel",
	"haystack-ai", "farm-haystack",
	"dspy-ai",
	"modelcontextprotocol", "mcp-server", "mcp_server", "fastmcp",
	"aider-chat", "ollama", "vllm",
	"cursor-agent", "cursor-cli",
}

// agentActionMarkers are CI actions and CLIs that invoke an agent. Distinct from
// the framework list: an action reference is a much stronger signal than a
// dependency, because a workflow step is something that actually runs.
var agentActionMarkers = []string{
	"anthropics/claude-code-action",
	"anthropics/claude-code-base-action",
	"github/copilot-cli",
	"openai/codex-action",
	"google-github-actions/run-gemini-cli",
	"cursor/cursor-agent-action",
	"aider-ai/aider-github-action",
	"claude-code", "codex exec", "aider --",
}

// containsAny reports which of `tokens` appear in `text`, lower-cased. Order
// follows `tokens` so output is stable across runs.
func containsAny(text string, tokens []string) []string {
	lower := strings.ToLower(text)
	var hits []string
	seen := map[string]bool{}
	for _, t := range tokens {
		if seen[t] || !strings.Contains(lower, strings.ToLower(t)) {
			continue
		}
		seen[t] = true
		hits = append(hits, t)
	}
	return hits
}

// DefaultRuleCatalog covers the declaration shapes that can be parsed without
// guessing at a provider schema.
//
// It is NOT the Stage-4 catalogue. Real rules need official schema references,
// positive/negative/malformed fixtures and measured precision on a labelled
// corpus before any of them may auto-classify. Until then every rule here tops
// out at a candidate.
//
// Coverage claim this catalogue supports, and nothing wider: agents declared in
// GitHub Actions workflows, agent manifests, MCP server configuration, container
// and compose files, and language dependency manifests. It cannot see a
// framework baked into a generically-named image at build time, a credential
// read from a mounted file or fetched at runtime, or anything in a repository
// the installation was not granted.
func DefaultRuleCatalog() IGARuleCatalog {
	return IGARuleCatalog{
		// Bumping this version schedules a rescan: bodies are discarded after
		// parse, so a corrected rule cannot be replayed over stored evidence.
		Version: "1.0.0",
		Rules: []IGARule{
			// ---- 2.1 CI/CD -----------------------------------------------
			{
				ID:            "workflow.agent-invocation",
				Version:       "0.2.0",
				ObjectClass:   models.ClassRepoDeclaration,
				PathGlobs:     []string{".github/workflows/*.yml", ".github/workflows/*.yaml"},
				EvidenceMode:  models.EvidenceInvocationDeclared,
				Confidence:    ConfidenceHigh,
				SensitiveKeys: []string{"env", "with", "run"},
				Extract:       extractWorkflowInvocation,
			},
			{
				// Records the EDGE, not a count. Detect only the leaf and a
				// reusable workflow called from 200 repositories reports 200
				// agents; detect only the definition and it reports one. Both
				// are wrong, so the counting decision is left to correlation
				// where both ends of the edge are visible.
				ID:          "workflow.reusable-and-composite",
				Version:     "0.1.0",
				ObjectClass: models.ClassRepoDeclaration,
				PathGlobs: []string{
					".github/workflows/*.yml", ".github/workflows/*.yaml",
					"action.yml", "action.yaml", "*/action.yml", "*/action.yaml",
				},
				EvidenceMode:  models.EvidenceInvocationDeclared,
				Confidence:    ConfidenceMedium,
				SensitiveKeys: []string{"env", "with", "run", "inputs"},
				Extract:       extractReusableWorkflow,
			},
			{
				// Context, never detection: a self-hosted runner means the
				// agent executes inside the customer network, which changes the
				// severity of every other finding in the same file.
				ID:            "workflow.self-hosted-runner",
				Version:       "0.1.0",
				ObjectClass:   models.ClassRepoDeclaration,
				PathGlobs:     []string{".github/workflows/*.yml", ".github/workflows/*.yaml"},
				EvidenceMode:  models.EvidenceToolConfiguration,
				Confidence:    ConfidenceLow,
				SensitiveKeys: []string{"env", "with", "run"},
				Extract:       extractSelfHostedRunner,
			},
			// ---- 2.2 Declarative manifests -------------------------------
			{
				ID:            "manifest.agent-declaration",
				Version:       "0.2.0",
				ObjectClass:   models.ClassRepoDeclaration,
				PathGlobs:     []string{"*.agent.json", "agent.json", "agents.json", "agent.yaml", "agent.yml"},
				EvidenceMode:  models.EvidenceDeploymentDeclared,
				Confidence:    ConfidenceHigh,
				SensitiveKeys: []string{"apiKey", "api_key", "token", "secret", "password", "prompt", "instructions"},
				Extract:       extractAgentManifest,
			},
			{
				// The highest-value rule in the catalogue. An MCP config is a
				// literal list of what an agent may touch -- filesystem,
				// database, internal API -- which makes it the closest thing in
				// a repository to an entitlement grant, and the bridge from
				// discovery into IGA.
				ID:          "manifest.mcp-server-config",
				Version:     "0.2.0",
				ObjectClass: models.ClassRepoDeclaration,
				PathGlobs: []string{
					".mcp.json", "mcp.json",
					".cursor/mcp.json", ".vscode/mcp.json",
					".claude/settings.json", ".claude/settings.local.json",
					"claude_desktop_config.json",
				},
				EvidenceMode:  models.EvidenceToolConfiguration,
				Confidence:    ConfidenceHigh,
				SensitiveKeys: []string{"env", "headers", "token", "apiKey", "api_key", "password"},
				Extract:       extractMCPConfig,
			},
			// ---- 2.3 Container and runtime -------------------------------
			{
				ID:          "container.dockerfile",
				Version:     "0.1.0",
				ObjectClass: models.ClassRepoDeclaration,
				PathGlobs: []string{
					"Dockerfile", "Dockerfile.*", "*/Dockerfile", "*/Dockerfile.*",
				},
				EvidenceMode:  models.EvidenceFrameworkDep,
				Confidence:    ConfidenceMedium,
				SensitiveKeys: []string{"ENV", "ARG"},
				Extract:       extractDockerfile,
			},
			{
				ID:          "container.compose",
				Version:     "0.1.0",
				ObjectClass: models.ClassRepoDeclaration,
				PathGlobs: []string{
					"docker-compose.yml", "docker-compose.yaml",
					"docker-compose.*.yml", "docker-compose.*.yaml",
					"compose.yml", "compose.yaml",
				},
				EvidenceMode:  models.EvidenceDeploymentDeclared,
				Confidence:    ConfidenceMedium,
				SensitiveKeys: []string{"environment", "env_file"},
				Extract:       extractCompose,
			},
			// ---- 2.4 Dependency evidence --------------------------------
			// Split by ecosystem rather than one merged rule, because the
			// combination rule counts DISTINCT rule ids: langchain in
			// requirements.txt and an agent SDK in package.json are two
			// independent weak signals, and one merged id would silently
			// suppress the promotion they should trigger.
			{
				ID:          "dependency.python",
				Version:     "0.1.0",
				ObjectClass: models.ClassRepoDeclaration,
				PathGlobs: []string{
					"requirements.txt", "requirements-*.txt", "*/requirements.txt",
					"pyproject.toml", "Pipfile", "poetry.lock",
				},
				EvidenceMode:  models.EvidenceFrameworkDep,
				Confidence:    ConfidenceLow,
				SensitiveKeys: []string{},
				Extract:       extractDependencyManifest,
			},
			{
				ID:          "dependency.node",
				Version:     "0.1.0",
				ObjectClass: models.ClassRepoDeclaration,
				PathGlobs: []string{
					"package.json", "*/package.json",
					"package-lock.json", "yarn.lock", "pnpm-lock.yaml",
				},
				EvidenceMode:  models.EvidenceFrameworkDep,
				Confidence:    ConfidenceLow,
				SensitiveKeys: []string{},
				Extract:       extractDependencyManifest,
			},
			{
				ID:            "dependency.go",
				Version:       "0.1.0",
				ObjectClass:   models.ClassRepoDeclaration,
				PathGlobs:     []string{"go.mod", "go.sum"},
				EvidenceMode:  models.EvidenceFrameworkDep,
				Confidence:    ConfidenceLow,
				SensitiveKeys: []string{},
				Extract:       extractDependencyManifest,
			},
			// ---- 2.5 Infrastructure as code -----------------------------
			{
				// IAM references are the highest-value extraction here: they
				// name the identity the agent will actually run as, which is
				// the join to the identity side of IGA.
				ID:            "iac.terraform",
				Version:       "0.1.0",
				ObjectClass:   models.ClassRepoDeclaration,
				PathGlobs:     []string{"*.tf", "*/*.tf", "*.tfvars"},
				EvidenceMode:  models.EvidenceDeploymentDeclared,
				Confidence:    ConfidenceMedium,
				SensitiveKeys: []string{"env", "environment", "variables", "secret"},
				Extract:       extractTerraform,
			},
			{
				// THE CORRELATION HOOK. What this reports as DECLARED is what
				// the cluster collector later reports as OBSERVED; matching the
				// two is the shadow-agent detection the product aims at, and it
				// works only while both channels share one vocabulary.
				ID:          "iac.kubernetes-in-repo",
				Version:     "0.1.0",
				ObjectClass: models.ClassRepoDeclaration,
				PathGlobs: []string{
					"k8s/*.yaml", "k8s/*.yml", "deploy/*.yaml", "deploy/*.yml",
					"manifests/*.yaml", "manifests/*.yml",
					"kubernetes/*.yaml", "kubernetes/*.yml",
					"charts/*/templates/*.yaml",
				},
				EvidenceMode:  models.EvidenceDeploymentDeclared,
				Confidence:    ConfidenceMedium,
				SensitiveKeys: []string{"env", "envFrom", "data", "stringData"},
				Extract:       extractKubernetesManifest,
			},
			{
				ID:            "iac.helm-values",
				Version:       "0.1.0",
				ObjectClass:   models.ClassRepoDeclaration,
				PathGlobs:     []string{"values.yaml", "values-*.yaml", "*/values.yaml", "Chart.yaml"},
				EvidenceMode:  models.EvidenceDeploymentDeclared,
				Confidence:    ConfidenceMedium,
				SensitiveKeys: []string{"env", "environment", "secrets"},
				Extract:       extractHelmValues,
			},
			// ---- 2.6 Secret and identity references ---------------------
			{
				// LOW even for a provider-specific name, so a credential
				// reference can never alone enter the agent count. Two
				// independent LOW signals promote to MEDIUM, which is exactly
				// the "langchain in requirements AND OPENAI_API_KEY nearby"
				// case this rule exists to complete.
				ID:            "secret.reference",
				Version:       "0.1.0",
				ObjectClass:   models.ClassRepoDeclaration,
				PathGlobs:     []string{".env.example", ".env.sample", ".env.template", "*/.env.example"},
				EvidenceMode:  models.EvidenceSecretReference,
				Confidence:    ConfidenceLow,
				SensitiveKeys: []string{},
				Extract:       extractSecretReference,
			},
			// CODEOWNERS is deliberately NOT a detection rule here. The
			// catalogue is explicit that it yields "ownership attribution, not
			// detection", so emitting sightings from it would manufacture an
			// agent row for every CODEOWNERS file. It is consumed instead via
			// ListCodeowners/MatchCodeowners with GitHub's last-match-wins
			// precedence and attached to the rows real rules produce.
		},
	}
}

// AllPathGlobs is the union allowlist used to filter a tree listing down to the
// handful of files worth fetching.
func (c IGARuleCatalog) AllPathGlobs() []string {
	var out []string
	for _, r := range c.Rules {
		out = append(out, r.PathGlobs...)
	}
	return out
}

// MatchRule returns the first rule wanting this path.
// MatchRules returns EVERY rule that claims this path, in catalogue order.
//
// More than one rule legitimately inspects the same file: a workflow can carry
// both an agent invocation and a self-hosted runner, and those are different
// facts about it. MatchRule (singular) returns only the first, so using it for
// extraction silently suppresses every later rule sharing a glob — the runner
// rule would never fire, and its severity context would be lost with no error
// anywhere to show it.
func (c IGARuleCatalog) MatchRules(p string) []IGARule {
	var out []IGARule
	for _, r := range c.Rules {
		if r.Matches(p) {
			out = append(out, r)
		}
	}
	return out
}

// StrongestConfidence returns the highest confidence among the given rules.
// Every signal is recorded; the highest is what the row is worth.
func StrongestConfidence(rules []IGARule) string {
	best := ""
	for _, r := range rules {
		switch r.Confidence {
		case ConfidenceHigh:
			return ConfidenceHigh
		case ConfidenceMedium:
			best = ConfidenceMedium
		case ConfidenceLow:
			if best == "" {
				best = ConfidenceLow
			}
		}
	}
	return best
}

// MatchRule returns the FIRST rule claiming a path. Kept for callers that only
// need to know whether a path is worth fetching at all; use MatchRules for
// extraction.
func (c IGARuleCatalog) MatchRule(p string) (IGARule, bool) {
	for _, r := range c.Rules {
		if r.Matches(p) {
			return r, true
		}
	}
	return IGARule{}, false
}

// workflowName reads a workflow's own `name:` so an inventory row is labelled
// the way its author labelled it, not by file path.
//
// Deliberately not a YAML parse: only a line beginning at column 0 with `name:`
// counts, which is the one place a top-level workflow name can legally sit. A
// nested step name is indented and so cannot be mistaken for it.
func workflowName(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "name:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(line, "name:"))
		v = strings.Trim(v, "\"'")
		if v != "" {
			return v
		}
	}
	return ""
}

// extractWorkflowInvocation looks for a workflow step invoking a documented
// agent runtime. It records WHICH runtime and the step name — never the `run:`
// body, `env:` values or `with:` arguments, any of which can carry secrets.
func extractWorkflowInvocation(filePath string, body []byte) (map[string]interface{}, []string, error) {
	text := string(body)
	runtimes := containsAny(text, agentActionMarkers)
	if len(runtimes) == 0 {
		// Fall back to the framework vocabulary: a workflow that pip-installs
		// langchain and runs it is an agent invocation too, just declared less
		// explicitly than a named action.
		if frameworks := containsAny(text, agentFrameworkTokens); len(frameworks) > 0 {
			facts := map[string]interface{}{
				"declared_frameworks": frameworks,
				"workflow_path":       filePath,
				"signal_strength":     "indirect",
			}
			if n := workflowName(text); n != "" {
				facts["name"] = n
			}
			return facts, collectSecretNames(text), nil
		}
		return nil, nil, nil // no fact to record; not an error
	}
	facts := map[string]interface{}{
		"declared_runtimes": runtimes,
		"workflow_path":     filePath,
		"signal_strength":   "direct",
	}
	if n := workflowName(text); n != "" {
		facts["name"] = n
	}
	// The trigger and the permissions block decide BLAST RADIUS, and that is
	// the whole reason to parse a workflow rather than just note the action
	// name. An agent on pull_request_target with write permissions and access
	// to repository secrets is a materially different risk from the same agent
	// behind workflow_dispatch. A presence boolean cannot express that, so the
	// trigger set and the granted scopes are both recorded.
	if triggers := workflowTriggers(text); len(triggers) > 0 {
		facts["triggers"] = triggers
		for _, t := range triggers {
			if elevatedTriggers[t] {
				facts["elevated_trigger"] = t
				break
			}
		}
	}
	if perms := workflowPermissions(text); len(perms) > 0 {
		// Scope names and their read/write level. These are GitHub's own
		// permission words, not secrets — the thing a reviewer needs in order
		// to judge what the agent could do.
		facts["permissions"] = perms
		for scope, level := range perms {
			if level == "write" || level == "write-all" {
				facts["has_write_permission"] = true
				facts["write_scope"] = scope
				break
			}
		}
	} else if strings.Contains(text, "permissions:") {
		facts["declares_permissions"] = true
	}
	if runner := firstYAMLValue(text, "runs-on"); runner != "" {
		facts["runner"] = runner
	}
	return facts, collectSecretNames(text), nil
}

// workflowTriggers reads the `on:` block's event names.
var workflowTriggerVocabulary = []string{
	"pull_request_target", "pull_request", "push", "workflow_dispatch",
	"workflow_call", "schedule", "issue_comment", "issues",
	"release", "repository_dispatch", "workflow_run", "fork",
}

// elevatedTriggers run with elevated context or on untrusted input, which is
// what makes an otherwise ordinary agent step dangerous.
var elevatedTriggers = map[string]bool{
	"pull_request_target": true,
	"workflow_run":        true,
	"issue_comment":       true,
	"repository_dispatch": true,
}

func workflowTriggers(text string) []string {
	lower := strings.ToLower(text)
	// Only look at the region before jobs:, so a job named "push" or a step
	// mentioning an event does not masquerade as a trigger.
	if idx := strings.Index(lower, "\njobs:"); idx > 0 {
		lower = lower[:idx]
	}
	var out []string
	seen := map[string]bool{}
	for _, ev := range workflowTriggerVocabulary {
		if seen[ev] || !strings.Contains(lower, ev) {
			continue
		}
		// pull_request_target contains pull_request; record the specific one.
		if ev == "pull_request" && strings.Contains(lower, "pull_request_target") &&
			!strings.Contains(strings.ReplaceAll(lower, "pull_request_target", ""), "pull_request") {
			continue
		}
		seen[ev] = true
		out = append(out, ev)
	}
	return out
}

// workflowPermissions reads the permissions block as scope -> level.
//
// GitHub's permission words are not secrets and they are exactly what a
// reviewer needs, so unlike env or with values these are kept.
func workflowPermissions(text string) map[string]string {
	lines := strings.Split(text, "\n")
	out := map[string]string{}
	for i, line := range lines {
		if strings.TrimSpace(strings.ToLower(line)) != "permissions:" {
			// The shorthand form: permissions: write-all
			if t := strings.TrimSpace(strings.ToLower(line)); strings.HasPrefix(t, "permissions:") {
				v := strings.TrimSpace(strings.TrimPrefix(t, "permissions:"))
				if v != "" {
					out["all"] = v
				}
			}
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		for _, next := range lines[i+1:] {
			if strings.TrimSpace(next) == "" {
				continue
			}
			nextIndent := len(next) - len(strings.TrimLeft(next, " \t"))
			if nextIndent <= indent {
				break // dedented out of the block
			}
			parts := strings.SplitN(strings.TrimSpace(next), ":", 2)
			if len(parts) != 2 {
				continue
			}
			scope := strings.TrimSpace(parts[0])
			level := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
			if scope != "" && level != "" {
				out[scope] = strings.ToLower(level)
			}
			if len(out) >= 20 {
				break
			}
		}
	}
	return out
}

// extractMCPConfig records which MCP servers a repository configures and what
// transport each uses. Server env blocks and headers are where credentials live,
// so only their KEY names are kept.
func extractMCPConfig(filePath string, body []byte) (map[string]interface{}, []string, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil, fmt.Errorf("malformed MCP config at %s: %w", filePath, err)
	}
	servers, ok := raw["mcpServers"].(map[string]interface{})
	if !ok {
		if servers, ok = raw["servers"].(map[string]interface{}); !ok {
			return nil, nil, nil // a settings file with no MCP block is not a finding
		}
	}
	names := make([]string, 0, len(servers))
	transports := map[string]interface{}{}
	envKeys := []string{}
	for name, v := range servers {
		names = append(names, name)
		cfg, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		switch {
		case cfg["url"] != nil:
			transports[name] = "http"
		case cfg["command"] != nil:
			transports[name] = "stdio"
		}
		if env, ok := cfg["env"].(map[string]interface{}); ok {
			for k := range env {
				envKeys = append(envKeys, k)
			}
		}
	}
	sort.Strings(names)
	sort.Strings(envKeys)
	facts := map[string]interface{}{
		"config_path": filePath,
		"mcp_servers": names,
	}
	if len(transports) > 0 {
		facts["mcp_transports"] = transports
	}
	if len(envKeys) > 0 {
		// Key names only. These describe what the server is handed, not what it
		// was handed.
		facts["mcp_env_keys"] = envKeys
	}
	return facts, collectSecretNames(string(body)), nil
}

// extractDockerfile looks for an agent framework installed or invoked at build
// time. ENV and ARG values are never read — only the names, and only via
// collectSecretNames.
func extractDockerfile(filePath string, body []byte) (map[string]interface{}, []string, error) {
	text := string(body)
	frameworks := containsAny(text, agentFrameworkTokens)
	if len(frameworks) == 0 {
		return nil, nil, nil
	}
	facts := map[string]interface{}{
		"dockerfile_path":     filePath,
		"declared_frameworks": frameworks,
	}
	// The base image is useful context and is not sensitive.
	for _, line := range strings.Split(text, "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(strings.ToUpper(t), "FROM ") {
			facts["base_image"] = strings.TrimSpace(t[5:])
			break
		}
	}
	return facts, collectSecretNames(text), nil
}

// extractCompose records services whose image or command indicates an agent.
// Environment blocks contribute names only.
func extractCompose(filePath string, body []byte) (map[string]interface{}, []string, error) {
	text := string(body)
	frameworks := containsAny(text, agentFrameworkTokens)
	if len(frameworks) == 0 {
		return nil, nil, nil
	}
	return map[string]interface{}{
		"compose_path":        filePath,
		"declared_frameworks": frameworks,
	}, collectSecretNames(text), nil
}

// extractDependencyManifest records agent frameworks present as dependencies.
//
// This is capability, not use: the package may be imported by nothing. The fact
// carries `requires_corroboration` so nothing downstream can promote it to an
// agent on its own — a dependency-only match belongs in a candidate list an
// admin reviews, never in the agent count.
func extractDependencyManifest(filePath string, body []byte) (map[string]interface{}, []string, error) {
	frameworks := containsAny(string(body), agentFrameworkTokens)
	if len(frameworks) == 0 {
		return nil, nil, nil
	}
	return map[string]interface{}{
		"manifest_path":          filePath,
		"declared_frameworks":    frameworks,
		"signal_strength":        "weak",
		"requires_corroboration": true,
	}, nil, nil
}

// extractAgentManifest parses a declared agent manifest, keeping only typed
// non-secret fields. Prompt bodies and instructions are excluded by default.
func extractAgentManifest(filePath string, body []byte) (map[string]interface{}, []string, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil, fmt.Errorf("malformed manifest at %s: %w", filePath, err)
	}
	facts := map[string]interface{}{"manifest_path": filePath}
	for _, k := range []string{"name", "description", "model", "version"} {
		if v, ok := raw[k]; ok {
			facts[k] = v
		}
	}
	if tools, ok := raw["tools"]; ok {
		facts["declared_tools"] = tools
	}
	// A prompt's EXISTENCE and LENGTH are the evidence; its text never is.
	// Prompts carry business logic and sometimes credentials, so recording the
	// shape lets a reviewer see that an agent is instructed without putting the
	// instructions — or anything hidden in them — into our database.
	for _, k := range []string{"prompt", "system_prompt", "systemPrompt", "instructions"} {
		v, ok := raw[k]
		if !ok {
			continue
		}
		facts["prompt_present"] = true
		if str, isStr := v.(string); isStr {
			facts["prompt_length"] = len(str)
		}
		break
	}
	if mcp, ok := raw["mcpServers"]; ok {
		// Tool-access evidence: which MCP servers, not their credentials.
		names := []string{}
		if m, ok := mcp.(map[string]interface{}); ok {
			for name := range m {
				names = append(names, name)
			}
		}
		facts["mcp_servers"] = names
	}
	return facts, collectSecretNames(string(body)), nil
}

// collectSecretNames records secret NAMES referenced by a declaration. A name
// is redacted evidence and never creates an agent by itself; a value is never
// read at all.
func collectSecretNames(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, token := range strings.FieldsFunc(text, func(r rune) bool {
		return !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) {
		if len(token) < 8 || seen[token] {
			continue
		}
		if strings.HasSuffix(token, "_API_KEY") || strings.HasSuffix(token, "_TOKEN") ||
			strings.HasSuffix(token, "_SECRET") {
			seen[token] = true
			out = append(out, token)
		}
	}
	return out
}

// HashBody is the content hash stored in place of the body itself.
func HashBody(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

/* --------------------------- fixture provider --------------------------- */

// FixtureProvider serves recorded responses instead of calling a provider.
//
// This is the Stage-0 artefact turned into a test double: the spike is required
// to record sanitized response fixtures, and those fixtures are what a real
// conformance test replays. It lets the whole pipeline — enumeration,
// truncation handling, rules, classification, projection, coverage — be
// exercised deterministically with no network and no tenant.
type FixtureProvider struct {
	ProviderName string
	Caps         map[string]string
	Scopes       []ProviderScope
	NativeAgents map[string][]ProviderObject // keyed by scope NativeID
	Identities   map[string][]ProviderObject
	SBOM         map[string][]ProviderObject
	Trees        map[string][]TreeEntry
	Truncated    map[string]bool
	// DirTrees serves ListTreeDir, keyed by "scopeNativeID:dir" ("" is the
	// root). It exists so a fixture can model the case that matters: a
	// truncated recursive tree that HID a path the per-directory listing then
	// recovers. Left nil, ListTreeDir just filters Trees.
	DirTrees   map[string][]TreeEntry
	Blobs      map[string][]byte // keyed by "scopeNativeID:path"
	Grants     map[string][]ProviderGrant
	Codeowners map[string][]CodeownerRule
	// FailScopes forces an error for a scope, to exercise partial coverage.
	FailScopes map[string]error
}

func (f *FixtureProvider) ListGrants(_ context.Context, _ ProviderContext, s ProviderScope) ([]ProviderGrant, error) {
	if err := f.FailScopes[s.NativeID]; err != nil {
		return nil, err
	}
	return f.Grants[s.NativeID], nil
}

func (f *FixtureProvider) ListCodeowners(_ context.Context, _ ProviderContext, s ProviderScope) ([]CodeownerRule, error) {
	if err := f.FailScopes[s.NativeID]; err != nil {
		return nil, err
	}
	return f.Codeowners[s.NativeID], nil
}

// NormalizeRights derives a provider-neutral reading from native rights. The
// native wording is always kept alongside; this is a convenience for policy,
// never a replacement for what the provider actually said.
func NormalizeRights(native map[string]string) map[string]interface{} {
	admin, write, read := false, false, false
	for _, v := range native {
		switch strings.ToLower(v) {
		case "admin":
			admin, write, read = true, true, true
		case "write":
			write, read = true, true
		case "read":
			read = true
		}
	}
	return map[string]interface{}{"read": read, "write": write, "admin": admin}
}

// MatchCodeowners returns the owners for a path. GitHub applies LAST matching
// pattern precedence, so the file is walked forwards and the last hit wins —
// getting this backwards would attribute an agent to the wrong team.
func MatchCodeowners(rules []CodeownerRule, filePath string) []string {
	var owners []string
	for _, r := range rules {
		if codeownerMatch(r.Pattern, filePath) {
			owners = r.Owners
		}
	}
	return owners
}

func codeownerMatch(pattern, filePath string) bool {
	p := strings.TrimPrefix(pattern, "/")
	f := strings.TrimPrefix(filePath, "/")
	if p == "*" {
		return true
	}
	// A directory pattern covers everything beneath it.
	if strings.HasSuffix(p, "/") {
		return strings.HasPrefix(f, p)
	}
	if ok, _ := path.Match(p, f); ok {
		return true
	}
	if ok, _ := path.Match(p, path.Base(f)); ok {
		return true
	}
	// A bare directory name also covers its contents.
	return strings.HasPrefix(f, p+"/")
}

func (f *FixtureProvider) Name() string {
	if f.ProviderName == "" {
		return "fixture"
	}
	return f.ProviderName
}

func (f *FixtureProvider) Capabilities(_ context.Context, _ ProviderContext) (map[string]string, error) {
	if f.Caps == nil {
		return map[string]string{}, nil
	}
	return f.Caps, nil
}

func (f *FixtureProvider) ListScopes(_ context.Context, _ ProviderContext) ([]ProviderScope, error) {
	return f.Scopes, nil
}

func (f *FixtureProvider) ListNativeAgents(_ context.Context, _ ProviderContext, s ProviderScope) ([]ProviderObject, error) {
	if err := f.FailScopes[s.NativeID]; err != nil {
		return nil, err
	}
	return f.NativeAgents[s.NativeID], nil
}

func (f *FixtureProvider) ListIdentities(_ context.Context, _ ProviderContext, s ProviderScope) ([]ProviderObject, error) {
	if err := f.FailScopes[s.NativeID]; err != nil {
		return nil, err
	}
	return f.Identities[s.NativeID], nil
}

func (f *FixtureProvider) ListSBOM(_ context.Context, _ ProviderContext, s ProviderScope) ([]ProviderObject, error) {
	if err := f.FailScopes[s.NativeID]; err != nil {
		return nil, err
	}
	return f.SBOM[s.NativeID], nil
}

func (f *FixtureProvider) ListTree(_ context.Context, _ ProviderContext, s ProviderScope) ([]TreeEntry, bool, error) {
	if err := f.FailScopes[s.NativeID]; err != nil {
		return nil, false, err
	}
	return f.Trees[s.NativeID], f.Truncated[s.NativeID], nil
}

func (f *FixtureProvider) FetchBlob(_ context.Context, _ ProviderContext, s ProviderScope, e TreeEntry) ([]byte, error) {
	b, ok := f.Blobs[s.NativeID+":"+e.Path]
	if !ok {
		return nil, fmt.Errorf("no fixture blob for %s:%s", s.NativeID, e.Path)
	}
	return b, nil
}

/* --------------------------- unavailable provider ----------------------- */

// UnavailableProvider is what a discovery source returns when it cannot be
// reached at all: live mode disabled, Vault down, no App configured.
//
// Every method fails rather than returning an empty result. That distinction is
// the whole point. A provider that returns "no repositories, no agents, no
// error" makes a scan succeed, publish complete coverage and report zero agents
// — an authoritative all-clear manufactured out of a misconfiguration. Refusing
// makes the scan fail loudly and leaves coverage unknown, which is the honest
// state when nothing was inspected.
type UnavailableProvider struct {
	Reason string
}

func (p *UnavailableProvider) err() error {
	reason := p.Reason
	if reason == "" {
		reason = "discovery provider is not configured"
	}
	// TYPED, not a plain error. This provider is the production default
	// whenever the live client is not enabled, so it is the most common way a
	// caller ever learns the provider is unusable — and the contract is that an
	// unavailable provider answers 503 and never an empty 200. A plain error
	// falls through a handler's default branch to 400, which reads to a client
	// as "your request was wrong" rather than "we could not look", and one step
	// further as "nothing found".
	return &ProviderUnavailableError{
		Op:  "provider",
		Err: errors.New(reason),
	}
}

func (p *UnavailableProvider) Name() string { return "unavailable" }

func (p *UnavailableProvider) Capabilities(context.Context, ProviderContext) (map[string]string, error) {
	return nil, p.err()
}

func (p *UnavailableProvider) ListScopes(context.Context, ProviderContext) ([]ProviderScope, error) {
	return nil, p.err()
}

func (p *UnavailableProvider) ListNativeAgents(context.Context, ProviderContext, ProviderScope) ([]ProviderObject, error) {
	return nil, p.err()
}

func (p *UnavailableProvider) ListIdentities(context.Context, ProviderContext, ProviderScope) ([]ProviderObject, error) {
	return nil, p.err()
}

func (p *UnavailableProvider) ListSBOM(context.Context, ProviderContext, ProviderScope) ([]ProviderObject, error) {
	return nil, p.err()
}

func (p *UnavailableProvider) ListTree(context.Context, ProviderContext, ProviderScope) ([]TreeEntry, bool, error) {
	return nil, false, p.err()
}

func (p *UnavailableProvider) FetchBlob(context.Context, ProviderContext, ProviderScope, TreeEntry) ([]byte, error) {
	return nil, p.err()
}

func (p *UnavailableProvider) ListGrants(context.Context, ProviderContext, ProviderScope) ([]ProviderGrant, error) {
	return nil, p.err()
}

func (p *UnavailableProvider) ListCodeowners(context.Context, ProviderContext, ProviderScope) ([]CodeownerRule, error) {
	return nil, p.err()
}

/* -------------------- truncated-tree recovery (AS-106) ------------------- */

// TargetDirectories returns the directories this catalogue can name from its
// globs, root included, for use when a recursive tree came back truncated.
//
// Only globs carrying a directory part are resolvable: ".github/workflows/*.yml"
// names a directory, while a bare "package.json" may sit at any depth and so
// cannot. That asymmetry is why recovery is a PARTIAL remedy and never restores
// a complete claim — a nested declaration beyond the cut-off stays unseen, and
// the coverage state has to keep saying so.
func (c IGARuleCatalog) TargetDirectories() []string {
	seen := map[string]struct{}{"": {}}
	dirs := []string{""} // the root always holds top-level manifests
	for _, r := range c.Rules {
		for _, g := range r.PathGlobs {
			d := path.Dir(g)
			if d == "." || d == "/" || strings.ContainsAny(d, "*?[") {
				continue // no fixed directory to ask for
			}
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// RecoverTruncatedTree re-lists the catalogue's known directories and returns
// the entries that the truncated tree did not already contain.
//
// Errors are swallowed per directory on purpose: this runs only after the tree
// was ALREADY truncated, so the caller's coverage is degraded either way and a
// missing subdirectory must not escalate a partial result into a failure. The
// returned count of directories actually recovered is what the caller reports.
func RecoverTruncatedTree(
	ctx context.Context,
	p IGAProvider,
	in ProviderContext,
	scope ProviderScope,
	cat IGARuleCatalog,
	have []TreeEntry,
) (added []TreeEntry, dirsRecovered int) {
	known := make(map[string]struct{}, len(have))
	for _, e := range have {
		known[e.Path] = struct{}{}
	}
	for _, dir := range cat.TargetDirectories() {
		entries, err := p.ListTreeDir(ctx, in, scope, dir)
		if err != nil {
			continue
		}
		var newHere int
		for _, e := range entries {
			if _, dup := known[e.Path]; dup {
				continue
			}
			known[e.Path] = struct{}{}
			added = append(added, e)
			newHere++
		}
		if newHere > 0 {
			dirsRecovered++
		}
	}
	return added, dirsRecovered
}

// ListTreeDir serves one directory from the fixture's DirTrees, falling back to
// filtering the full tree so existing fixtures need no changes: a fixture that
// declares a truncated tree can still exercise recovery by listing entries the
// truncated view omitted.
func (f *FixtureProvider) ListTreeDir(_ context.Context, _ ProviderContext, s ProviderScope, dir string) ([]TreeEntry, error) {
	if err := f.FailScopes[s.NativeID]; err != nil {
		return nil, err
	}
	if f.DirTrees != nil {
		if entries, ok := f.DirTrees[s.NativeID+":"+dir]; ok {
			return entries, nil
		}
	}
	var out []TreeEntry
	for _, e := range f.Trees[s.NativeID] {
		if path.Dir(e.Path) == dirOrRoot(dir) {
			out = append(out, e)
		}
	}
	return out, nil
}

// dirOrRoot maps the empty directory to path.Dir's own spelling of the root.
func dirOrRoot(dir string) string {
	if dir == "" {
		return "."
	}
	return dir
}

func (p *UnavailableProvider) ListTreeDir(context.Context, ProviderContext, ProviderScope, string) ([]TreeEntry, error) {
	return nil, p.err()
}
