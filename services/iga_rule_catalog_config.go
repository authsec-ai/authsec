package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
Configurable detection patterns.

The built-in catalogue in DefaultRuleCatalog() is the baseline. A workspace
layers an OVERLAY on top of it: add or remove tokens, add globs to a rule, turn
a rule off, or declare a custom rule that points new globs at an existing
extractor.

Two decisions shape everything here.

ADD/REMOVE, NOT REPLACE. An overlay never stores a copy of a built-in list. If
it did, a workspace that customised once would be frozen on that day's
vocabulary and would silently stop receiving every marker shipped afterwards —
a regression with no symptom, which is the worst kind in a detection product.
Deltas mean a customer gets their additions AND our improvements.

EXTRACTORS ARE CODE. Config picks a parser by name from a fixed registry; it
cannot define one. Pointing a new glob at an existing parser covers the common
request ("our manifests are called bot.json"). A genuinely new file FORMAT needs
a release. The alternative is an expression language evaluated over
customer-supplied config against untrusted repository content, which is a large
attack surface bought for a need nobody has raised.
*/

// StringDelta is an add/remove pair applied to a built-in list.
type StringDelta struct {
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

// apply layers the delta over a base list, preserving base order and appending
// additions. Matching is case-insensitive because these are matched
// case-insensitively at scan time; letting "LangChain" and "langchain" both
// live in the list would double every hit.
func (d StringDelta) apply(base []string) []string {
	drop := map[string]bool{}
	for _, r := range d.Remove {
		drop[strings.ToLower(strings.TrimSpace(r))] = true
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(base)+len(d.Add))
	for _, b := range base {
		k := strings.ToLower(b)
		if drop[k] || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, b)
	}
	for _, a := range d.Add {
		a = strings.TrimSpace(a)
		k := strings.ToLower(a)
		if a == "" || drop[k] || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, a)
	}
	return out
}

// VocabularyOverlay tunes the shared token lists.
type VocabularyOverlay struct {
	// FrameworkTokens are package names implying an agent framework is present.
	FrameworkTokens StringDelta `json:"framework_tokens,omitempty"`
	// ActionMarkers are CI actions and CLIs that INVOKE an agent — a stronger
	// signal than a dependency, because a workflow step actually runs.
	ActionMarkers StringDelta `json:"action_markers,omitempty"`
	// SecretSuffixes decide which environment variable NAMES are recorded as
	// credential references. Values are never read.
	SecretSuffixes StringDelta `json:"secret_suffixes,omitempty"`
}

// RuleOverlay tunes one built-in rule.
type RuleOverlay struct {
	// Enabled turns a rule off entirely. Nil means "leave as shipped" — which is
	// deliberately distinct from false, so an overlay that only edits globs does
	// not accidentally disable the rule.
	Enabled       *bool       `json:"enabled,omitempty"`
	PathGlobs     StringDelta `json:"path_globs,omitempty"`
	SensitiveKeys StringDelta `json:"sensitive_keys,omitempty"`
}

// CustomRule points new globs at an EXISTING extractor.
type CustomRule struct {
	ID            string   `json:"id"`
	Extractor     string   `json:"extractor"`
	PathGlobs     []string `json:"path_globs"`
	EvidenceMode  string   `json:"evidence_mode,omitempty"`
	SensitiveKeys []string `json:"sensitive_keys,omitempty"`
}

// RuleCatalogOverlay is the whole per-workspace configuration.
type RuleCatalogOverlay struct {
	Vocabularies VocabularyOverlay      `json:"vocabularies,omitempty"`
	Rules        map[string]RuleOverlay `json:"rules,omitempty"`
	CustomRules  []CustomRule           `json:"custom_rules,omitempty"`
}

/* ----------------------------- extractor registry ---------------------- */

// extractorFn is a parser that has been bound to a resolved vocabulary.
type extractorFn func(filePath string, body []byte) (map[string]interface{}, []string, error)

// extractorRegistry maps a configurable NAME to a real parser.
//
// A name here is the only thing config may choose. Adding an entry is a
// deliberate act in review, which is what keeps "configurable patterns" from
// becoming "configurable code paths".
//
// Each entry takes the effective vocabulary and returns a bound parser. The
// vocabulary is threaded through as an ARGUMENT rather than read from a package
// variable: two workspaces have different token lists, and a package-level
// "current vocabulary" would be a data race that silently scanned one tenant's
// repositories with another tenant's patterns.
var extractorRegistry = map[string]func(EffectiveVocabulary) extractorFn{
	"workflow":   bindVocab(extractWorkflowInvocation),
	"manifest":   bindVocab(extractAgentManifest),
	"mcp":        bindVocab(extractMCPConfig),
	"dockerfile": bindVocab(extractDockerfile),
	"compose":    bindVocab(extractCompose),
	"dependency": bindVocab(extractDependencyManifest),
	"text":       bindVocab(extractGenericText),
}

// bindVocab turns a vocabulary-taking extractor into a factory.
func bindVocab(f func(EffectiveVocabulary, string, []byte) (map[string]interface{}, []string, error)) func(EffectiveVocabulary) extractorFn {
	return func(v EffectiveVocabulary) extractorFn {
		return func(p string, b []byte) (map[string]interface{}, []string, error) {
			return f(v, p, b)
		}
	}
}

// ExtractorNames lists the registry, sorted, for the API to advertise. A UI
// building a rule picker needs the authoritative list, not a hardcoded copy.
func ExtractorNames() []string {
	out := make([]string, 0, len(extractorRegistry))
	for k := range extractorRegistry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// extractGenericText is the fallback parser for file types no dedicated
// extractor understands.
//
// It reads the file as text and reports which framework tokens, action markers
// and secret-shaped names appear. That is strictly weaker than a structural
// parse — it cannot tell a real invocation from the same string inside a
// comment or a changelog — so it is labelled as such in its own output and its
// findings top out at framework_dependency. It exists so a customer can point a
// rule at an unusual file today instead of waiting for a release.
func extractGenericText(v EffectiveVocabulary, filePath string, body []byte) (map[string]interface{}, []string, error) {
	text := string(body)
	frameworks := containsAny(text, v.FrameworkTokens)
	actions := containsAny(text, v.ActionMarkers)
	if len(frameworks) == 0 && len(actions) == 0 {
		// Nothing recognisable. Not an agent, and not worth a row.
		return nil, nil, nil
	}
	facts := map[string]interface{}{
		"kind": "text_match",
		// Stated in the record itself: whoever reviews this must know it came
		// from a substring scan and not from understanding the file.
		"match_confidence": "low",
		"match_basis":      "unstructured text scan; a token may appear in a comment or documentation",
	}
	if len(frameworks) > 0 {
		facts["frameworks"] = frameworks
	}
	if len(actions) > 0 {
		facts["action_markers"] = actions
	}
	return facts, collectSecretNames(v.SecretSuffixes, text), nil
}

/* -------------------------------- validation --------------------------- */

// Caps. A detection catalogue is also a spending plan: every glob widens what a
// scan fetches, and every token widens what it matches. These bounds keep a
// mistaken paste from turning one scan into an organisation-wide download.
const (
	maxOverlayGlobs       = 200
	maxOverlayTokens      = 500
	maxCustomRules        = 50
	maxGlobLength         = 200
	maxTokenLength        = 200
	minTokenLength        = 3
	maxOverlayBytesOnWire = 256 << 10
)

// Validate rejects an overlay that is malformed, unsafe or unaffordable.
//
// Every rejection here is a cost or correctness problem that would otherwise
// surface as a mysterious scan failure, an exhausted rate limit, or an
// inventory full of noise.
func (o *RuleCatalogOverlay) Validate() error {
	base := DefaultRuleCatalog()
	known := map[string]bool{}
	for _, r := range base.Rules {
		known[r.ID] = true
	}

	globCount := 0
	for id, ru := range o.Rules {
		if !known[id] {
			return fmt.Errorf("unknown rule %q: overlays tune the built-in rules; "+
				"use custom_rules to add a new one", id)
		}
		for _, g := range ru.PathGlobs.Add {
			if err := validateGlob(g); err != nil {
				return fmt.Errorf("rule %s: %w", id, err)
			}
			globCount++
		}
		for _, k := range ru.SensitiveKeys.Add {
			if err := validateToken(k, "sensitive key"); err != nil {
				return fmt.Errorf("rule %s: %w", id, err)
			}
		}
	}

	if len(o.CustomRules) > maxCustomRules {
		return fmt.Errorf("%d custom rules exceeds the limit of %d",
			len(o.CustomRules), maxCustomRules)
	}
	seen := map[string]bool{}
	for i, cr := range o.CustomRules {
		if cr.ID == "" {
			return fmt.Errorf("custom rule %d: id is required", i)
		}
		if known[cr.ID] {
			return fmt.Errorf("custom rule %q collides with a built-in rule; "+
				"tune that one through `rules` instead", cr.ID)
		}
		if seen[cr.ID] {
			return fmt.Errorf("duplicate custom rule id %q", cr.ID)
		}
		seen[cr.ID] = true
		if !validRuleID(cr.ID) {
			return fmt.Errorf("custom rule %q: id may contain only letters, digits, dot, dash and underscore", cr.ID)
		}
		if _, ok := extractorRegistry[cr.Extractor]; !ok {
			return fmt.Errorf("custom rule %q: unknown extractor %q; available: %s",
				cr.ID, cr.Extractor, strings.Join(ExtractorNames(), ", "))
		}
		if len(cr.PathGlobs) == 0 {
			return fmt.Errorf("custom rule %q: at least one path glob is required, "+
				"otherwise the rule can never match anything", cr.ID)
		}
		for _, g := range cr.PathGlobs {
			if err := validateGlob(g); err != nil {
				return fmt.Errorf("custom rule %s: %w", cr.ID, err)
			}
			globCount++
		}
		if cr.EvidenceMode != "" && !validEvidenceMode(cr.EvidenceMode) {
			return fmt.Errorf("custom rule %q: unknown evidence_mode %q", cr.ID, cr.EvidenceMode)
		}
	}
	if globCount > maxOverlayGlobs {
		return fmt.Errorf("%d added path globs exceeds the limit of %d; "+
			"every glob widens what each scan downloads", globCount, maxOverlayGlobs)
	}

	tokenCount := 0
	for _, d := range []StringDelta{
		o.Vocabularies.FrameworkTokens, o.Vocabularies.ActionMarkers, o.Vocabularies.SecretSuffixes,
	} {
		for _, t := range d.Add {
			if err := validateToken(t, "token"); err != nil {
				return err
			}
			tokenCount++
		}
	}
	if tokenCount > maxOverlayTokens {
		return fmt.Errorf("%d added tokens exceeds the limit of %d", tokenCount, maxOverlayTokens)
	}
	return nil
}

// validateGlob refuses patterns that would match essentially everything.
//
// The scanner fetches every matched path. A glob with no literal text — "*",
// "**", "*.*" — turns a scan of a large repository into a download of it, which
// exhausts the installation's rate limit for every other caller and fills the
// inventory with files that were never evidence of anything. The rule catalogue
// is the fetch budget, so this is the place to enforce it.
func validateGlob(g string) error {
	g = strings.TrimSpace(g)
	if g == "" {
		return fmt.Errorf("empty path glob")
	}
	if len(g) > maxGlobLength {
		return fmt.Errorf("path glob %q is longer than %d characters", g, maxGlobLength)
	}
	if strings.Contains(g, "..") {
		return fmt.Errorf("path glob %q must not contain '..'", g)
	}
	literal := strings.Map(func(r rune) rune {
		switch r {
		case '*', '?', '[', ']', '/', '.', '-', '_':
			return -1
		}
		return r
	}, g)
	if len(literal) < 3 {
		return fmt.Errorf("path glob %q is too broad: it needs at least 3 literal characters "+
			"so a scan fetches declaration files rather than the whole repository", g)
	}
	return nil
}

// validateToken keeps the vocabulary specific enough to be useful.
//
// A two-character token like "ai" matches almost every file in existence. The
// resulting inventory is noise, and an inventory nobody trusts gets ignored —
// at which point the real findings inside it are missed too.
func validateToken(t, kind string) error {
	t = strings.TrimSpace(t)
	if len(t) < minTokenLength {
		return fmt.Errorf("%s %q is too short (minimum %d characters): a short token "+
			"matches almost everything and fills the inventory with noise", kind, t, minTokenLength)
	}
	if len(t) > maxTokenLength {
		return fmt.Errorf("%s %q is longer than %d characters", kind, t, maxTokenLength)
	}
	return nil
}

func validRuleID(id string) bool {
	if len(id) > 100 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

func validEvidenceMode(m string) bool {
	switch m {
	case models.EvidencePlatformDeclared, models.EvidenceDeploymentDeclared,
		models.EvidenceInvocationDeclared, models.EvidenceFrameworkDep,
		models.EvidenceToolConfiguration, models.EvidenceSecretReference:
		return true
	}
	return false
}

/* ------------------------------- resolution ---------------------------- */

// Hash is the content fingerprint of an overlay, used to build the effective
// catalogue version. Marshalling a normalised copy keeps the hash stable across
// map iteration order, which would otherwise change the version on every read
// and mark every finding stale for no reason.
func (o RuleCatalogOverlay) Hash() string {
	if o.IsEmpty() {
		return ""
	}
	norm := o
	sort.Slice(norm.CustomRules, func(i, j int) bool {
		return norm.CustomRules[i].ID < norm.CustomRules[j].ID
	})
	b, err := json.Marshal(normalisedOverlay(norm))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:4])
}

// normalisedOverlay renders the overlay with deterministic ordering.
func normalisedOverlay(o RuleCatalogOverlay) map[string]interface{} {
	rules := make([]map[string]interface{}, 0, len(o.Rules))
	ids := make([]string, 0, len(o.Rules))
	for id := range o.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := o.Rules[id]
		rules = append(rules, map[string]interface{}{
			"id": id, "enabled": r.Enabled,
			"globs": r.PathGlobs, "keys": r.SensitiveKeys,
		})
	}
	return map[string]interface{}{
		"vocab": o.Vocabularies, "rules": rules, "custom": o.CustomRules,
	}
}

// IsEmpty reports an overlay that changes nothing.
func (o RuleCatalogOverlay) IsEmpty() bool {
	return len(o.Rules) == 0 && len(o.CustomRules) == 0 &&
		len(o.Vocabularies.FrameworkTokens.Add) == 0 && len(o.Vocabularies.FrameworkTokens.Remove) == 0 &&
		len(o.Vocabularies.ActionMarkers.Add) == 0 && len(o.Vocabularies.ActionMarkers.Remove) == 0 &&
		len(o.Vocabularies.SecretSuffixes.Add) == 0 && len(o.Vocabularies.SecretSuffixes.Remove) == 0
}

// EffectiveVocabulary is the token set a scan actually matches on, after the
// overlay. Returned separately from the catalogue because the extractors read
// these lists directly.
type EffectiveVocabulary struct {
	FrameworkTokens []string `json:"framework_tokens"`
	ActionMarkers   []string `json:"action_markers"`
	SecretSuffixes  []string `json:"secret_suffixes"`
}

// ApplyOverlay layers an overlay on the built-in catalogue and returns the
// catalogue a scan should run.
//
// The version becomes "<builtin>+ws:<hash>" so a finding always names the exact
// ruleset that produced it — built-in version and customisation together.
func ApplyOverlay(o RuleCatalogOverlay) (IGARuleCatalog, EffectiveVocabulary) {
	base := DefaultRuleCatalog()
	vocab := EffectiveVocabulary{
		FrameworkTokens: o.Vocabularies.FrameworkTokens.apply(agentFrameworkTokens),
		ActionMarkers:   o.Vocabularies.ActionMarkers.apply(agentActionMarkers),
		SecretSuffixes:  o.Vocabularies.SecretSuffixes.apply(defaultSecretSuffixes),
	}
	if o.IsEmpty() {
		return base, vocab
	}

	out := IGARuleCatalog{Version: base.Version + "+ws:" + o.Hash()}
	for _, r := range base.Rules {
		ov, ok := o.Rules[r.ID]
		if ok {
			if ov.Enabled != nil && !*ov.Enabled {
				continue // switched off for this workspace
			}
			r.PathGlobs = ov.PathGlobs.apply(r.PathGlobs)
			r.SensitiveKeys = ov.SensitiveKeys.apply(r.SensitiveKeys)
		}
		out.Rules = append(out.Rules, r)
	}
	for _, cr := range o.CustomRules {
		if _, ok := extractorRegistry[cr.Extractor]; !ok {
			continue // validation rejects this on write; skip defensively on read
		}
		mode := cr.EvidenceMode
		if mode == "" {
			// Unstated evidence defaults to the WEAKEST reading. A custom rule
			// must never claim stronger evidence than it was configured to.
			mode = models.EvidenceFrameworkDep
		}
		out.Rules = append(out.Rules, IGARule{
			ID:            cr.ID,
			Version:       "custom",
			ObjectClass:   models.ClassRepoDeclaration,
			PathGlobs:     cr.PathGlobs,
			EvidenceMode:  mode,
			SensitiveKeys: cr.SensitiveKeys,
			Extractor:     cr.Extractor,
		})
	}
	// Bind every rule — built-in and custom — to THIS workspace's vocabulary.
	// Built-in rules arrive bound to the shipped token list, so rebinding is
	// what makes an added or removed token actually take effect.
	bindCatalog(&out, vocab)
	return out, vocab
}

// DescribeRule renders one rule for the API, without the function pointer.
type DescribedRule struct {
	ID            string   `json:"id"`
	Version       string   `json:"version"`
	Extractor     string   `json:"extractor"`
	PathGlobs     []string `json:"path_globs"`
	EvidenceMode  string   `json:"evidence_mode"`
	SensitiveKeys []string `json:"sensitive_keys,omitempty"`
	BuiltIn       bool     `json:"built_in"`
}

// DescribeCatalog renders the effective catalogue as JSON-safe data — the
// function pointer cannot be serialised, and the extractor NAME is what a
// console needs anyway.
func DescribeCatalog(c IGARuleCatalog, o RuleCatalogOverlay) []DescribedRule {
	custom := map[string]bool{}
	for _, cr := range o.CustomRules {
		custom[cr.ID] = true
	}
	out := make([]DescribedRule, 0, len(c.Rules))
	for _, r := range c.Rules {
		out = append(out, DescribedRule{
			ID: r.ID, Version: r.Version, Extractor: r.Extractor,
			PathGlobs: r.PathGlobs, EvidenceMode: r.EvidenceMode,
			SensitiveKeys: r.SensitiveKeys, BuiltIn: !custom[r.ID],
		})
	}
	return out
}

/* --------------------------- workspace resolution ---------------------- */

// RuleCatalogService reads and writes a workspace's pattern overlay, and
// resolves the catalogue a scan should actually run.
type RuleCatalogService struct {
	repo repositories.DiscoveryRuleCatalogRepository
}

// NewRuleCatalogService constructs the service.
func NewRuleCatalogService(db *gorm.DB) *RuleCatalogService {
	return &RuleCatalogService{repo: repositories.NewDiscoveryRuleCatalogRepository(db)}
}

// Overlay returns the workspace's stored overlay, or an empty one.
//
// An absent row is the normal case, not an error: it means "run what we ship".
func (s *RuleCatalogService) Overlay(workspaceID uuid.UUID) (RuleCatalogOverlay, error) {
	var o RuleCatalogOverlay
	row, err := s.repo.Get(workspaceID)
	if err != nil {
		if errors.Is(err, repositories.ErrRuleCatalogNotFound) {
			return o, nil
		}
		return o, err
	}
	if len(row.Overlay) > 0 {
		if err := json.Unmarshal(row.Overlay, &o); err != nil {
			// Stored config we cannot read must not silently become "no
			// patterns" — that would quietly scan for nothing and report a
			// clean estate. Fail loudly so the scan errors instead.
			return o, fmt.Errorf("stored rule catalog for this workspace is unreadable: %w", err)
		}
	}
	return o, nil
}

// Resolve returns the catalogue and vocabulary a scan should use.
func (s *RuleCatalogService) Resolve(workspaceID uuid.UUID) (IGARuleCatalog, EffectiveVocabulary, error) {
	o, err := s.Overlay(workspaceID)
	if err != nil {
		return IGARuleCatalog{}, EffectiveVocabulary{}, err
	}
	cat, vocab := ApplyOverlay(o)
	return cat, vocab, nil
}

// Save validates and stores an overlay. An overlay that changes nothing deletes
// the row instead, so "reset to defaults" and "save an empty form" agree.
func (s *RuleCatalogService) Save(workspaceID uuid.UUID, o RuleCatalogOverlay, actor string) (RuleCatalogOverlay, error) {
	if err := o.Validate(); err != nil {
		return o, err
	}
	if o.IsEmpty() {
		return o, s.repo.Delete(workspaceID)
	}
	raw, err := json.Marshal(o)
	if err != nil {
		return o, err
	}
	if len(raw) > maxOverlayBytesOnWire {
		return o, fmt.Errorf("rule catalog overlay is %d bytes, over the %d byte limit",
			len(raw), maxOverlayBytesOnWire)
	}
	return o, s.repo.Upsert(&models.DiscoveryRuleCatalog{
		WorkspaceID: workspaceID,
		Overlay:     raw,
		BasedOn:     DefaultRuleCatalog().Version,
		OverlayHash: o.Hash(),
		UpdatedBy:   actor,
	})
}

// Reset removes the overlay, returning the workspace to the built-in patterns.
func (s *RuleCatalogService) Reset(workspaceID uuid.UUID) error {
	return s.repo.Delete(workspaceID)
}

// PathMatch is the dry-run answer for one path: which rule claims it, if any.
//
// This exists because the cost of a wrong glob is not a validation error, it is
// a scan that quietly downloads too much or looks in the wrong place. Letting
// someone test a path before saving turns that into a two-second check.
type PathMatch struct {
	Path         string `json:"path"`
	Matched      bool   `json:"matched"`
	RuleID       string `json:"rule_id,omitempty"`
	Extractor    string `json:"extractor,omitempty"`
	EvidenceMode string `json:"evidence_mode,omitempty"`
	// Reason explains a non-match, so "why is my file not picked up?" is
	// answerable without reading the source.
	Reason string `json:"reason,omitempty"`
}

// TestPaths reports which rule would claim each path under a given overlay.
func TestPaths(o RuleCatalogOverlay, paths []string) []PathMatch {
	cat, _ := ApplyOverlay(o)
	out := make([]PathMatch, 0, len(paths))
	for _, p := range paths {
		m := PathMatch{Path: p}
		if isVendoredPath(p) {
			m.Reason = "skipped: path is inside a vendored directory (node_modules, vendor, .venv and similar), " +
				"which holds somebody else's code"
			out = append(out, m)
			continue
		}
		if r, ok := cat.MatchRule(p); ok {
			m.Matched, m.RuleID = true, r.ID
			m.Extractor, m.EvidenceMode = r.Extractor, r.EvidenceMode
		} else {
			m.Reason = "no rule's path globs match; the file would never be fetched"
		}
		out = append(out, m)
	}
	return out
}

// CountStaleFindings splits a workspace's repo_scan findings into those produced
// by the CURRENT catalogue version and those produced by an earlier one.
//
// It exists because patterns are now editable. Raw file bodies are discarded
// after parse, so a changed rule cannot be re-applied to stored evidence — the
// only way to bring a finding up to date is to read the repository again.
// Surfacing the count is what keeps "found by an older ruleset" visible instead
// of letting a stale finding pass as current.
//
// Findings written before catalog_version existed have no such key; they are
// counted as stale, which is the honest reading — they were produced by a
// ruleset we can no longer name.
func CountStaleFindings(db *gorm.DB, workspaceID uuid.UUID, currentVersion string) (stale, current int64, err error) {
	q := db.Table("discovered_agents").
		Where("workspace_id = ? AND source = ?", workspaceID, models.DiscoverySourceRepoScan)
	if err = q.Session(&gorm.Session{}).
		Where("metadata->>'catalog_version' = ?", currentVersion).
		Count(&current).Error; err != nil {
		return 0, 0, err
	}
	if err = q.Session(&gorm.Session{}).
		Where("metadata->>'catalog_version' IS DISTINCT FROM ?", currentVersion).
		Count(&stale).Error; err != nil {
		return 0, 0, err
	}
	return stale, current, nil
}
