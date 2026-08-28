package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	// Ref overrides which git ref content reads resolve against. Empty means
	// DefaultBranch, which is what every caller wanted before branch coverage
	// existed — so leaving it unset preserves the previous behaviour exactly.
	//
	// It is a separate field rather than an overwrite of DefaultBranch because
	// a finding has to record BOTH: which ref it was found on, and whether that
	// ref is the one actually in effect. A declaration on an unmerged branch is
	// weaker evidence than the same declaration on the default branch, and the
	// two must never be presented identically.
	Ref string
}

// EffectiveRef is the git ref reads should resolve against.
func (s ProviderScope) EffectiveRef() string {
	if s.Ref != "" {
		return s.Ref
	}
	return s.DefaultBranch
}

// ProviderBranch is one ref in a repository.
//
// CommitSHA is what makes all-branch scanning affordable: branches that point
// at the same commit have identical trees, so the scan reads that tree once and
// attributes the result to every branch sharing it. On a real repository most
// stale branches share a head with something already walked.
type ProviderBranch struct {
	Name      string
	CommitSHA string
	IsDefault bool
}

// BranchLister is an OPTIONAL provider capability: enumerate a repository's
// refs.
//
// It is kept off IGAProvider deliberately. A provider that cannot enumerate
// branches is still a perfectly good provider — it simply cannot support
// all-branch coverage, and the scanner degrades to the default branch and says
// so in the run's warnings. Widening the mandatory interface would instead
// force every implementation, including test doubles, to grow a method most of
// them have no meaning for.
type BranchLister interface {
	ListBranches(ctx context.Context, in ProviderContext, scope ProviderScope) ([]ProviderBranch, error)
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
	// SensitiveKeys are redacted before persistence and never leave the parser.
	SensitiveKeys []string
	// Extractor names the parser in extractorRegistry. It is what configuration
	// may choose; the parser itself is always code.
	Extractor string
	// Extract is Extractor bound to a resolved vocabulary. Populated by
	// bindCatalog — never set by hand, or a rule would silently match on the
	// built-in token list while claiming to use the workspace's.
	Extract func(filePath string, body []byte) (facts map[string]interface{}, secretRefs []string, err error)
}

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

// defaultSecretSuffixes decide which environment-variable NAMES are recorded
// as credential references. Suffixes, not substrings: "_TOKEN" catches
// GITHUB_TOKEN without also catching every variable containing the word token.
// Only the NAME is ever recorded; the value is not read.
var defaultSecretSuffixes = []string{"_API_KEY", "_TOKEN", "_SECRET"}

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
	c := IGARuleCatalog{
		// Bumping this version schedules a rescan: bodies are discarded after
		// parse, so a corrected rule cannot be replayed over stored evidence.
		Version: "0.2.0",
		Rules: []IGARule{
			{
				ID:            "workflow.agent-invocation",
				Version:       "0.1.0",
				ObjectClass:   models.ClassRepoDeclaration,
				PathGlobs:     []string{".github/workflows/*.yml", ".github/workflows/*.yaml"},
				EvidenceMode:  models.EvidenceInvocationDeclared,
				SensitiveKeys: []string{"env", "with", "run"},
				Extractor:     "workflow",
			},
			{
				ID:            "manifest.agent-declaration",
				Version:       "0.1.0",
				ObjectClass:   models.ClassRepoDeclaration,
				PathGlobs:     []string{"*.agent.json", "agent.json", "agents.json"},
				EvidenceMode:  models.EvidenceDeploymentDeclared,
				SensitiveKeys: []string{"apiKey", "api_key", "token", "secret", "password", "prompt", "instructions"},
				Extractor:     "manifest",
			},
			{
				// The highest-value rule here. An MCP config is a literal list
				// of what an agent may touch — filesystem, database, internal
				// API — which makes it the closest thing in a repository to an
				// entitlement grant, and the bridge from discovery into IGA.
				ID:          "config.mcp-servers",
				Version:     "0.1.0",
				ObjectClass: models.ClassRepoDeclaration,
				PathGlobs: []string{
					".mcp.json", "mcp.json",
					".cursor/mcp.json", ".vscode/mcp.json",
					".claude/settings.json", ".claude/settings.local.json",
					"claude_desktop_config.json",
				},
				EvidenceMode:  models.EvidenceToolConfiguration,
				SensitiveKeys: []string{"env", "headers", "token", "apiKey", "api_key", "password"},
				Extractor:     "mcp",
			},
			{
				ID:          "container.dockerfile",
				Version:     "0.1.0",
				ObjectClass: models.ClassRepoDeclaration,
				PathGlobs: []string{
					"Dockerfile", "Dockerfile.*", "*/Dockerfile", "*/Dockerfile.*",
				},
				EvidenceMode:  models.EvidenceFrameworkDep,
				SensitiveKeys: []string{"ENV", "ARG"},
				Extractor:     "dockerfile",
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
				SensitiveKeys: []string{"environment", "env_file"},
				Extractor:     "compose",
			},
			{
				// Weakest rule in the set, and labelled as such in its own
				// output: a dependency proves capability, not use. The library
				// may be imported by nothing. Never count one of these as an
				// agent on its own.
				ID:          "dependency.manifest",
				Version:     "0.1.0",
				ObjectClass: models.ClassRepoDeclaration,
				PathGlobs: []string{
					"requirements.txt", "requirements-*.txt", "*/requirements.txt",
					"pyproject.toml", "Pipfile",
					"package.json", "*/package.json",
					"go.mod",
				},
				EvidenceMode:  models.EvidenceFrameworkDep,
				SensitiveKeys: []string{},
				Extractor:     "dependency",
			},
		},
	}
	bindCatalog(&c, DefaultVocabulary())
	return c
}

// DefaultVocabulary is the shipped token set, before any workspace overlay.
func DefaultVocabulary() EffectiveVocabulary {
	return EffectiveVocabulary{
		FrameworkTokens: agentFrameworkTokens,
		ActionMarkers:   agentActionMarkers,
		SecretSuffixes:  defaultSecretSuffixes,
	}
}

// bindCatalog resolves each rule's named extractor against a vocabulary.
func bindCatalog(c *IGARuleCatalog, v EffectiveVocabulary) {
	for i := range c.Rules {
		if factory, ok := extractorRegistry[c.Rules[i].Extractor]; ok {
			c.Rules[i].Extract = factory(v)
		}
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
func extractWorkflowInvocation(v EffectiveVocabulary, filePath string, body []byte) (map[string]interface{}, []string, error) {
	text := string(body)
	runtimes := containsAny(text, v.ActionMarkers)
	if len(runtimes) == 0 {
		// Fall back to the framework vocabulary: a workflow that pip-installs
		// langchain and runs it is an agent invocation too, just declared less
		// explicitly than a named action.
		if frameworks := containsAny(text, v.FrameworkTokens); len(frameworks) > 0 {
			facts := map[string]interface{}{
				"declared_frameworks": frameworks,
				"workflow_path":       filePath,
				"signal_strength":     "indirect",
			}
			if n := workflowName(text); n != "" {
				facts["name"] = n
			}
			return facts, collectSecretNames(v.SecretSuffixes, text), nil
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
	// The trigger and permission block decide blast radius: an agent on a
	// fork-triggered event with write permissions and repo secrets is a
	// different risk from one behind a manual dispatch. Recorded as presence
	// only — never the values, which can carry anything.
	if strings.Contains(text, "pull_request_target") {
		facts["elevated_trigger"] = "pull_request_target"
	}
	if strings.Contains(text, "permissions:") {
		facts["declares_permissions"] = true
	}
	return facts, collectSecretNames(v.SecretSuffixes, text), nil
}

// extractMCPConfig records which MCP servers a repository configures and what
// transport each uses. Server env blocks and headers are where credentials live,
// so only their KEY names are kept.
func extractMCPConfig(v EffectiveVocabulary, filePath string, body []byte) (map[string]interface{}, []string, error) {
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
	return facts, collectSecretNames(v.SecretSuffixes, string(body)), nil
}

// extractDockerfile looks for an agent framework installed or invoked at build
// time. ENV and ARG values are never read — only the names, and only via
// collectSecretNames.
func extractDockerfile(v EffectiveVocabulary, filePath string, body []byte) (map[string]interface{}, []string, error) {
	text := string(body)
	frameworks := containsAny(text, v.FrameworkTokens)
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
	return facts, collectSecretNames(v.SecretSuffixes, text), nil
}

// extractCompose records services whose image or command indicates an agent.
// Environment blocks contribute names only.
func extractCompose(v EffectiveVocabulary, filePath string, body []byte) (map[string]interface{}, []string, error) {
	text := string(body)
	frameworks := containsAny(text, v.FrameworkTokens)
	if len(frameworks) == 0 {
		return nil, nil, nil
	}
	return map[string]interface{}{
		"compose_path":        filePath,
		"declared_frameworks": frameworks,
	}, collectSecretNames(v.SecretSuffixes, text), nil
}

// extractDependencyManifest records agent frameworks present as dependencies.
//
// This is capability, not use: the package may be imported by nothing. The fact
// carries `requires_corroboration` so nothing downstream can promote it to an
// agent on its own — a dependency-only match belongs in a candidate list an
// admin reviews, never in the agent count.
func extractDependencyManifest(v EffectiveVocabulary, filePath string, body []byte) (map[string]interface{}, []string, error) {
	frameworks := containsAny(string(body), v.FrameworkTokens)
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
func extractAgentManifest(v EffectiveVocabulary, filePath string, body []byte) (map[string]interface{}, []string, error) {
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
	return facts, collectSecretNames(v.SecretSuffixes, string(body)), nil
}

// collectSecretNames records secret NAMES referenced by a declaration. A name
// is redacted evidence and never creates an agent by itself; a value is never
// read at all.
func collectSecretNames(suffixes []string, text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, token := range strings.FieldsFunc(text, func(r rune) bool {
		return !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) {
		if len(token) < 8 || seen[token] {
			continue
		}
		for _, suf := range suffixes {
			if strings.HasSuffix(token, suf) {
				seen[token] = true
				out = append(out, token)
				break
			}
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
	Blobs        map[string][]byte // keyed by "scopeNativeID:path"
	Grants       map[string][]ProviderGrant
	Codeowners   map[string][]CodeownerRule
	// FailScopes forces an error for a scope, to exercise partial coverage.
	FailScopes map[string]error

	// Branches, keyed by scope NativeID. Nil means the fixture does not model
	// branches, and all-branch scanning degrades to the default branch.
	Branches map[string][]ProviderBranch
	// RefTrees holds per-ref trees, keyed "scopeNativeID@ref". A ref with no
	// entry here falls back to Trees, so existing fixtures keep working
	// unchanged while a branch-aware test can vary content per ref.
	RefTrees map[string][]TreeEntry
	// FailBranches forces ListBranches to error for a scope, to exercise the
	// "could not enumerate refs" degradation path.
	FailBranches map[string]error
}

func (f *FixtureProvider) ListBranches(_ context.Context, _ ProviderContext, s ProviderScope) ([]ProviderBranch, error) {
	if err := f.FailBranches[s.NativeID]; err != nil {
		return nil, err
	}
	if err := f.FailScopes[s.NativeID]; err != nil {
		return nil, err
	}
	return f.Branches[s.NativeID], nil
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
	// A ref-specific tree wins when the fixture defines one; otherwise every ref
	// sees the same tree, which is the right default for fixtures written before
	// branch coverage existed.
	if s.Ref != "" {
		if entries, ok := f.RefTrees[s.NativeID+"@"+s.Ref]; ok {
			return entries, f.Truncated[s.NativeID], nil
		}
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
	return fmt.Errorf("provider unavailable: %s", reason)
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
