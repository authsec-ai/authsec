package igagov

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// BundleFormat versions the bundle's fact layout; it is inside the hashed
// facts, so a layout change can never collide with an older bundle.
const BundleFormat = "igagov.bundle/1"

// Trust levels (050 iga_gov_evidence_bundle.trust).
const (
	TrustTrusted   = "trusted"
	TrustPartial   = "partial"
	TrustUntrusted = "untrusted"
)

// Source kinds. R1a compiles only from AWS publications; any other kind is
// untrusted until its prerequisite holds (K-1 for Kubernetes, §12.2).
const (
	SourceAWSPublication = "aws_publication"
	SourceK8sSweep       = "k8s_sweep"
)

// Gap kinds: evidence the approver must accept item by item (an
// iga_gov_acceptance row of kind evidence_gap per gap key, §2.8). DECISION
// D24: an uncollected form of a REMOVED namespace is a bundle gap (§2.11's
// example); the compiler's first-attachment `unanalysed` set (acceptance
// kind unanalysed_form) may name the same form, and the compiler must not
// ask for both: ProveFirstAttachment leaves a form that is already a gap out
// of the unanalysed set and lists it under covered_by_gaps.
const (
	GapResourcePolicyCoverage = "resource_policy_coverage"
	GapUnanalysedForm         = "unanalysed_form"
	GapPolicyUnparseable      = "policy_unparseable"
	GapConsumersUnresolved    = "consumers_unresolved"
)

// TrustRules are the freshness rules for sources (§2.11 "fresh enough for
// the facts used"). DECISION D15: the spec's only AWS freshness figure is
// 24 hours (§2.8 revalidation, §3.4 named scan), so a source whose activity
// report (or, without one, publication) is older than MaxSourceAge is stale.
type TrustRules struct {
	MaxSourceAge time.Duration
}

// DefaultTrustRules returns the R1a rules.
func DefaultTrustRules() TrustRules { return TrustRules{MaxSourceAge: 24 * time.Hour} }

// BundleSource is one source of a bundle (§2.11 "sources"), with the trust
// the builder derived for it. Authenticated and Ordered are recorded, so a
// reader of the stored facts can see why a source was (un)trusted.
type BundleSource struct {
	Kind                      string   `json:"kind"`
	Rev                       int64    `json:"rev"`
	PublishedAt               *string  `json:"published_at"`
	ConnectorID               string   `json:"connector_id"`
	ConnectorRun              string   `json:"connector_run"`
	Authenticated             bool     `json:"authenticated"`
	Ordered                   bool     `json:"ordered"`
	Trust                     string   `json:"trust"`
	TrustReasons              []string `json:"trust_reasons"`
	FreshnessHours            int      `json:"freshness_hours"`
	ActivityReportGeneratedAt *string  `json:"activity_report_generated_at"`
	ResourcePolicyCoverage    string   `json:"resource_policy_coverage"`
	ResourcePolicyRun         *string  `json:"resource_policy_run"`
}

// BundleSourceInput is a source as the builder service reads it.
type BundleSourceInput struct {
	Kind                      string
	Rev                       int64
	PublishedAt               time.Time
	ConnectorID               string
	ConnectorRun              string
	Authenticated             bool
	Ordered                   bool
	ActivityReportGeneratedAt *time.Time
	// ResourcePolicyCoverage summarises the run's coverage
	// (SummarizeCoverage): complete, partial or not_collected.
	ResourcePolicyCoverage string
	ResourcePolicyRun      string
}

// BundleTarget is the role the bundle is for.
type BundleTarget struct {
	AccountID   string `json:"account_id"`
	RoleID      string `json:"role_id"`
	RoleARN     string `json:"role_arn"`
	EstateScope string `json:"estate_scope"`
}

// BundleGrant is one identity statement granting services to the role.
type BundleGrant struct {
	PolicyARN      string   `json:"policy_arn"`
	AssignmentKind string   `json:"assignment_kind"`
	StatementKey   string   `json:"statement_key"`
	StatementHash  string   `json:"statement_hash"`
	Services       []string `json:"services"`
}

// BundleActivity is one service's activity fact as the plan uses it.
type BundleActivity struct {
	Service             string  `json:"service"`
	State               string  `json:"state"`
	Outcome             string  `json:"outcome"`
	LastAuthenticatedAt *string `json:"last_authenticated_at"`
	GrantAgeBasis       string  `json:"grant_age_basis"`
	VerifiedGrantFrom   *string `json:"verified_grant_from"`
	QualifiedDays       int     `json:"qualified_days"`
}

// ActivityFromQualification renders a §2.6 qualification as a bundle fact.
func ActivityFromQualification(q Qualification) BundleActivity {
	return BundleActivity{Service: q.Service, State: EvidenceCollected, Outcome: q.Outcome,
		LastAuthenticatedAt: ts(q.LastAuthenticatedAt), GrantAgeBasis: q.GrantAgeBasis,
		VerifiedGrantFrom: ts(q.VerifiedGrantFrom), QualifiedDays: q.QualifiedDays}
}

// Gap is one evidence gap (§2.11 "gaps").
type Gap struct {
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	Service  string `json:"service,omitempty"`
	Form     string `json:"form,omitempty"`
	Region   string `json:"region,omitempty"`
	Resource string `json:"resource,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Count    int    `json:"count,omitempty"`
}

// GapHash is the item_hash of a gap (DomainGap over JCS(gap)).
func GapHash(g Gap) (string, error) { return HashCanonicalTagged(DomainGap, g) }

// BundleFacts is the canonical content of an evidence bundle (§2.11): what
// the iga_gov_evidence_bundle.facts / canonical columns hold. DECISION D16:
// beyond the spec's example it records the format, the catalog version, the
// build time (the reference of every freshness figure) and the removed
// services (trust depends on them), so trust can be re-derived from the
// stored facts alone.
type BundleFacts struct {
	Format              string           `json:"format"`
	Catalog             string           `json:"catalog"`
	BuiltAt             string           `json:"built_at"`
	Sources             []BundleSource   `json:"sources"`
	Target              BundleTarget     `json:"target"`
	RemovedServices     []string         `json:"removed_services"`
	Grants              []BundleGrant    `json:"grants"`
	Consumers           []ImpactConsumer `json:"consumers"`
	ConsumersUnresolved int              `json:"consumers_unresolved"`
	Owners              []string         `json:"owners"`
	Activity            []BundleActivity `json:"activity"`
	Routes              []Route          `json:"routes"`
	Gaps                []Gap            `json:"gaps"`
}

// BundleInput is everything the builder service gathered for one target,
// outside the pipeline barrier, from the latest complete evaluation and the
// role connector's run (§2.11 "Bounded evaluation").
type BundleInput struct {
	BuiltAt             time.Time
	Sources             []BundleSourceInput
	Target              BundleTarget
	RemovedServices     []string
	Grants              []BundleGrant
	Consumers           []ImpactConsumer
	ConsumersUnresolved int
	Owners              []string
	Activity            []BundleActivity
	// RouteAnalyses are AnalyzeRoutes results for the removed services, from
	// the named scan; their not-analysed entries become gaps, the rest routes.
	RouteAnalyses []RouteAnalysis
}

// Bundle is a built, canonical, hashed bundle with its trust.
type Bundle struct {
	Facts        BundleFacts
	Canonical    []byte
	Hash         string
	Trust        string
	TrustReasons []string
	// GapRefs are the gaps' keys and hashes, for material_hash and
	// acceptance rows.
	GapRefs []GapRef
}

// SummarizeCoverage reduces one run's coverage rows to the source's
// resource_policy_coverage: complete when every collected form is complete
// in every enabled Region (account-scoped forms: every row complete, at
// least one row); not_collected when there are no rows; partial otherwise.
func SummarizeCoverage(ev *ResourcePolicyEvidence, enabledRegions []string) string {
	if ev == nil || len(ev.Coverage) == 0 {
		return CoverageNotCollected
	}
	for _, f := range AllForms() {
		if f.State != FormCollected {
			continue
		}
		ra := AnalyzeRoutes(f.Namespace, RoleRef{}, &ResourcePolicyEvidence{Coverage: ev.Coverage}, enabledRegions)
		for _, r := range ra.Routes {
			if r.Effect == RouteEffectNotAnalysed && r.Form == f.Name {
				return CoveragePartial
			}
		}
	}
	return CoverageComplete
}

func gapFor(r Route) Gap {
	switch r.Reason {
	case "form_not_collected":
		return Gap{Kind: GapUnanalysedForm, Key: "unanalysed_form:" + r.Form, Service: r.Service, Form: r.Form, Reason: r.Reason}
	case "policy_unparseable":
		return Gap{Kind: GapPolicyUnparseable, Key: "policy_unparseable:" + r.Resource, Service: r.Service,
			Form: r.Form, Region: r.Region, Resource: r.Resource, Reason: r.Reason}
	case "no_resource_policy_coverage":
		return Gap{Kind: GapResourcePolicyCoverage, Key: "resource_policy_coverage:" + r.Service + ":*",
			Service: r.Service, Reason: r.Reason}
	}
	region := r.Region
	if region == "" {
		region = "*"
	}
	return Gap{Kind: GapResourcePolicyCoverage, Key: "resource_policy_coverage:" + r.Form + ":" + region,
		Service: r.Service, Form: r.Form, Region: r.Region, Reason: r.Reason}
}

func sourceTrust(in BundleSourceInput, builtAt time.Time, rules TrustRules) BundleSource {
	s := BundleSource{
		Kind: in.Kind, Rev: in.Rev, PublishedAt: ts(&in.PublishedAt), ConnectorID: in.ConnectorID,
		ConnectorRun: in.ConnectorRun, Authenticated: in.Authenticated, Ordered: in.Ordered,
		ActivityReportGeneratedAt: ts(in.ActivityReportGeneratedAt),
		ResourcePolicyCoverage:    in.ResourcePolicyCoverage, ResourcePolicyRun: nilIfEmpty(in.ResourcePolicyRun),
		TrustReasons: []string{},
	}
	if s.ResourcePolicyCoverage == "" {
		s.ResourcePolicyCoverage = CoverageNotCollected
	}
	ref := in.PublishedAt
	if in.ActivityReportGeneratedAt != nil {
		ref = *in.ActivityReportGeneratedAt
	}
	age := builtAt.Sub(ref)
	if age < 0 {
		age = 0
	}
	s.FreshnessHours = int(age / time.Hour)
	var untrusted, partial []string
	if in.Kind != SourceAWSPublication {
		if in.Kind == SourceK8sSweep {
			untrusted = append(untrusted, "provider_not_supported:K-1")
		} else {
			untrusted = append(untrusted, "source_kind_not_supported")
		}
	}
	if !in.Authenticated {
		untrusted = append(untrusted, "unauthenticated")
	}
	if !in.Ordered {
		untrusted = append(untrusted, "unordered")
	}
	if age > rules.MaxSourceAge {
		untrusted = append(untrusted, "stale")
	}
	if s.ResourcePolicyCoverage != CoverageComplete {
		partial = append(partial, "resource_policy_coverage_"+s.ResourcePolicyCoverage)
	}
	switch {
	case len(untrusted) > 0:
		s.Trust = TrustUntrusted
		s.TrustReasons = append(untrusted, partial...)
	case len(partial) > 0:
		s.Trust = TrustPartial
		s.TrustReasons = partial
	default:
		s.Trust = TrustTrusted
	}
	sort.Strings(s.TrustReasons)
	return s
}

// ClassifyBundleTrust is §2.11's trust from a bundle's facts alone:
// untrusted when any source is untrusted or a removed service has no
// collected activity fact (it cannot support a removal: P-09, A53 a);
// partial when there are gaps or a partial source — the approver must accept
// each gap (A53 b); trusted otherwise. Reasons are sorted and name the source
// or service, for the 422 evidence_untrusted remedy.
func ClassifyBundleTrust(f BundleFacts) (string, []string) {
	var untrusted, partial []string
	for _, s := range f.Sources {
		label := s.Kind + ":" + s.ConnectorRun
		for _, r := range s.TrustReasons {
			switch s.Trust {
			case TrustUntrusted:
				untrusted = append(untrusted, "source "+label+": "+r)
			case TrustPartial:
				partial = append(partial, "source "+label+": "+r)
			}
		}
		if s.Trust == TrustUntrusted && len(s.TrustReasons) == 0 {
			untrusted = append(untrusted, "source "+label+": untrusted")
		}
	}
	act := map[string]BundleActivity{}
	for _, a := range f.Activity {
		act[a.Service] = a
	}
	for _, svc := range f.RemovedServices {
		if a, ok := act[svc]; !ok || a.State != EvidenceCollected {
			untrusted = append(untrusted, "activity_not_collected:"+svc)
		}
	}
	for _, g := range f.Gaps {
		partial = append(partial, "gap "+g.Key)
	}
	switch {
	case len(untrusted) > 0:
		return TrustUntrusted, sortedUnique(append(untrusted, partial...))
	case len(partial) > 0:
		return TrustPartial, sortedUnique(partial)
	}
	return TrustTrusted, []string{}
}

// BuildBundle builds an evidence bundle (§2.11): it derives each source's
// freshness and trust, turns the removed services' unanalysed resource-policy
// evidence into gaps (and unresolved consumers into a gap), sorts every list,
// canonicalises the facts (RFC 8785), hashes them (bundle_hash = content
// hash of the canonical text, exactly what the 050 insert trigger recomputes)
// and classifies trust. It refuses a bundle with no source (050 trigger) or
// without a target.
func BuildBundle(in BundleInput, rules TrustRules) (Bundle, error) {
	if len(in.Sources) == 0 {
		return Bundle{}, errors.New("igagov: an evidence bundle must name at least one source")
	}
	if in.BuiltAt.IsZero() {
		return Bundle{}, errors.New("igagov: an evidence bundle needs its build time")
	}
	if !reAccount.MatchString(in.Target.AccountID) || in.Target.RoleID == "" || in.Target.RoleARN == "" {
		return Bundle{}, errors.New("igagov: an evidence bundle needs its target account, RoleId and ARN")
	}
	if in.ConsumersUnresolved < 0 {
		return Bundle{}, errors.New("igagov: consumers_unresolved cannot be negative")
	}
	f := BundleFacts{
		Format: BundleFormat, Catalog: CatalogLabel(), BuiltAt: *tsv(in.BuiltAt),
		Target: in.Target, RemovedServices: sortedUnique(in.RemovedServices),
		ConsumersUnresolved: in.ConsumersUnresolved, Owners: sortedUnique(in.Owners),
		Routes: []Route{}, Gaps: []Gap{},
	}
	if f.Target.EstateScope == "" {
		f.Target.EstateScope = "aws:account:" + f.Target.AccountID
	}
	for _, s := range in.Sources {
		f.Sources = append(f.Sources, sourceTrust(s, in.BuiltAt, rules))
	}
	sort.Slice(f.Sources, func(i, j int) bool {
		a, b := f.Sources[i], f.Sources[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.ConnectorID != b.ConnectorID {
			return a.ConnectorID < b.ConnectorID
		}
		if a.Rev != b.Rev {
			return a.Rev < b.Rev
		}
		return a.ConnectorRun < b.ConnectorRun
	})
	f.Grants = make([]BundleGrant, 0, len(in.Grants))
	for _, g := range in.Grants {
		g.Services = sortedUnique(g.Services)
		f.Grants = append(f.Grants, g)
	}
	sort.Slice(f.Grants, func(i, j int) bool {
		a, b := f.Grants[i], f.Grants[j]
		if a.PolicyARN != b.PolicyARN {
			return a.PolicyARN < b.PolicyARN
		}
		if a.StatementKey != b.StatementKey {
			return a.StatementKey < b.StatementKey
		}
		return a.StatementHash < b.StatementHash
	})
	f.Consumers = Impact{Consumers: in.Consumers}.Normalized().Consumers
	f.Activity = append([]BundleActivity{}, in.Activity...)
	sort.Slice(f.Activity, func(i, j int) bool { return f.Activity[i].Service < f.Activity[j].Service })
	for i := 1; i < len(f.Activity); i++ {
		if f.Activity[i].Service == f.Activity[i-1].Service {
			return Bundle{}, fmt.Errorf("igagov: activity lists %s twice", f.Activity[i].Service)
		}
	}
	gaps := map[string]Gap{}
	removed := map[string]bool{}
	for _, s := range f.RemovedServices {
		removed[s] = true
	}
	for _, ra := range in.RouteAnalyses {
		if !removed[ra.Service] {
			continue
		}
		for _, r := range ra.Routes {
			if r.Effect == RouteEffectNotAnalysed {
				g := gapFor(r)
				gaps[g.Key] = g
				continue
			}
			f.Routes = append(f.Routes, r)
		}
	}
	if in.ConsumersUnresolved > 0 {
		g := Gap{Kind: GapConsumersUnresolved, Key: GapConsumersUnresolved, Count: in.ConsumersUnresolved}
		gaps[g.Key] = g
	}
	for _, k := range sortedKeys(gaps) {
		f.Gaps = append(f.Gaps, gaps[k])
	}
	SortRoutes(f.Routes)

	canon, err := CanonicalizeValue(f)
	if err != nil {
		return Bundle{}, err
	}
	if err := checkStorable(canon); err != nil {
		return Bundle{}, err
	}
	b := Bundle{Facts: f, Canonical: canon, Hash: ContentHash(canon)}
	b.Trust, b.TrustReasons = ClassifyBundleTrust(f)
	for _, g := range f.Gaps {
		h, err := GapHash(g)
		if err != nil {
			return Bundle{}, err
		}
		b.GapRefs = append(b.GapRefs, GapRef{Key: g.Key, Hash: h})
	}
	return b, nil
}

// ParseBundle verifies stored bundle text — canonical, hashing to
// bundleHash, naming at least one source (the 050 trigger's checks) — and
// returns its facts and re-derived trust. A plan's evidence can be re-read
// from the row this way without trusting the stored trust column.
func ParseBundle(canonical []byte, bundleHash string) (BundleFacts, string, []string, error) {
	c, err := Canonicalize(canonical)
	if err != nil {
		return BundleFacts{}, "", nil, err
	}
	if !bytes.Equal(c, canonical) {
		return BundleFacts{}, "", nil, errors.New("igagov: bundle text is not canonical")
	}
	if ContentHash(canonical) != bundleHash {
		return BundleFacts{}, "", nil, errors.New("igagov: bundle hash does not match its canonical facts")
	}
	var f BundleFacts
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return BundleFacts{}, "", nil, fmt.Errorf("igagov: bundle facts: %w", err)
	}
	if len(f.Sources) == 0 {
		return BundleFacts{}, "", nil, errors.New("igagov: evidence bundle must name at least one source")
	}
	trust, reasons := ClassifyBundleTrust(f)
	return f, trust, reasons, nil
}
