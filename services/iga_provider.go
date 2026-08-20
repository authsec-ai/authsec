package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
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
	// Extract pulls typed facts out of a matched file. It returns non-secret
	// facts plus any secret NAMES referenced (names only, never values).
	Extract func(filePath string, body []byte) (facts map[string]interface{}, secretRefs []string, err error)
}

// Matches reports whether this rule wants the given path.
func (r IGARule) Matches(p string) bool {
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

// DefaultRuleCatalog is a deliberately small starter set covering the two
// declaration shapes that can be parsed without guessing at provider schemas.
//
// It is NOT the Stage-4 catalogue. Real rules need official schema references,
// positive/negative/malformed fixtures and measured precision on a labelled
// corpus before any of them may auto-classify. Until then every rule here tops
// out at a candidate.
func DefaultRuleCatalog() IGARuleCatalog {
	return IGARuleCatalog{
		Version: "0.1.0-starter",
		Rules: []IGARule{
			{
				ID:            "workflow.agent-invocation",
				Version:       "0.1.0",
				ObjectClass:   models.ClassRepoDeclaration,
				PathGlobs:     []string{".github/workflows/*.yml", ".github/workflows/*.yaml"},
				EvidenceMode:  models.EvidenceInvocationDeclared,
				SensitiveKeys: []string{"env", "with", "run"},
				Extract:       extractWorkflowInvocation,
			},
			{
				ID:            "manifest.agent-declaration",
				Version:       "0.1.0",
				ObjectClass:   models.ClassRepoDeclaration,
				PathGlobs:     []string{"*.agent.json", "agent.json", "agents.json"},
				EvidenceMode:  models.EvidenceDeploymentDeclared,
				SensitiveKeys: []string{"apiKey", "api_key", "token", "secret", "password", "prompt", "instructions"},
				Extract:       extractAgentManifest,
			},
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
func (c IGARuleCatalog) MatchRule(p string) (IGARule, bool) {
	for _, r := range c.Rules {
		if r.Matches(p) {
			return r, true
		}
	}
	return IGARule{}, false
}

// extractWorkflowInvocation looks for a workflow step invoking a documented
// agent runtime. It records WHICH runtime and the step name — never the `run:`
// body, `env:` values or `with:` arguments, any of which can carry secrets.
func extractWorkflowInvocation(filePath string, body []byte) (map[string]interface{}, []string, error) {
	text := string(body)
	var runtimes []string
	for _, marker := range []string{
		"anthropics/claude-code-action",
		"github/copilot-cli",
		"openai/codex-action",
	} {
		if strings.Contains(text, marker) {
			runtimes = append(runtimes, marker)
		}
	}
	if len(runtimes) == 0 {
		return nil, nil, nil // no fact to record; not an error
	}
	return map[string]interface{}{
		"declared_runtimes": runtimes,
		"workflow_path":     filePath,
	}, collectSecretNames(text), nil
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
	Blobs        map[string][]byte // keyed by "scopeNativeID:path"
	Grants       map[string][]ProviderGrant
	Codeowners   map[string][]CodeownerRule
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
