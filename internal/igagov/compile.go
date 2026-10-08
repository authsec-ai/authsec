package igagov

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
)

// This file is §3.4's compiler and §8.3's plan derivation: the live read and
// its artifact_state (§2.8), role eligibility (§3.1), removal justification,
// the exclusion-only AuthSec boundary (§3.2), structure-preserving narrowing
// of a customer boundary and its split copy (§3.3, §3.4), the
// first-attachment proof (§3.4, §3.9), and the apply / undo / role-only
// recovery / remove-control plans with their hashes (§2.8, §8.3, §8.5, §8.9,
// §8.10). Split and split_revert (§11) are in split.go; the single classifier
// is in recover.go.
//
// Every function is pure: the live read, the evidence and every time are
// inputs. Outputs fit iga_gov_plan (050): its kind / delivery / eligibility /
// attachment / disposition / first-attachment CHECKs are mirrored by
// Plan.CheckStorable and proved against PostgreSQL by
// tests/igagovschema/compiled_plans_test.go.

/* ------------------------------------------------------------------------- */
/*                                Vocabulary                                  */
/* ------------------------------------------------------------------------- */

// Plan kinds, eligibility, attachments and dispositions (050 CHECKs).
const (
	PlanApply         = "apply"
	PlanUndo          = "undo"
	PlanRemoveControl = "remove_control"
	PlanSplit         = "split"
	PlanSplitRevert   = "split_revert"

	EligibilityEligible   = "eligible"
	EligibilityIaCOnly    = "iac_only"
	EligibilityIneligible = "ineligible"

	AttachmentPresent   = "present"
	AttachmentAbsent    = "absent"
	AttachmentUnchanged = "unchanged"

	DispositionKeep         = "keep"
	DispositionDelete       = "delete"
	DispositionRetainShared = "retain_shared"

	// BasisLiveRead: every plan here is compiled from a discovery-role read
	// (050 basis; graph_rev is reserved for plans compiled without one).
	BasisLiveRead = "live_read"
)

// §3.2 names and limits.
const (
	AuthSecPolicyPath      = "/authsec/"
	AuthSecBoundaryPrefix  = "AuthSecBoundary-"
	AuthSecBoundarySid     = "AuthSecAllowAllExceptRemoved"
	PolicyVersion20121017  = "2012-10-17"
	MaxPolicyChars         = 6144 // characters excluding whitespace (L-08)
	MaxPolicyNameLen       = 128
	MaxPolicyVersions      = 5
	TagManagedBy           = "authsec:managed-by"
	TagWorkspace           = "authsec:workspace"
	TagControl             = "authsec:control"
	TagPolicy              = "authsec:policy"
	TagChange              = "authsec:change"
	TagManagedByValue      = "authsec"
	RoleTagManagedBy       = "ManagedBy"
	RoleTagManagedByValue  = "AuthSec"
	RoleTagProtected       = "authsec:protected"
	ContinuityImmutable    = "immutable"
	ContinuityRecognition  = "recognition_only"
	pathServiceLinked      = "/aws-service-role/"
	pathAWSReserved        = "/aws-reserved/"
	domainRoleDefinition   = "authsec.igagov.role_definition.v1"
	unanalysedOtherAccount = "other_accounts"
)

// DeploymentPlaceholder stands for the deploying deployment's id in a tag
// value of an op (§3.2 authsec:change=<deployment id>). DECISION D27: a plan
// is compiled before any deployment exists and may be deployed by a later
// one, so the op carries this placeholder and the executor substitutes the
// deployment id before computing the attempt's request_hash.
const DeploymentPlaceholder = "${deployment_id}"

// Version selectors of a DeletePolicyVersion op (§8.5).
const (
	SelectOldestNonDefault = "oldest_non_default"
	SelectAllNonDefault    = "all_non_default"
)

// Op names. The first seven are the IAM writes of §3.5 / §8.5; AuthSec runs
// them for direct delivery. For iac_pr and export the same list is the native
// change the customer's tool makes (the J1 step list, §8.11), never run by
// AuthSec. Split steps are in split.go.
const (
	OpCreatePolicy                  = "CreatePolicy"
	OpCreatePolicyVersion           = "CreatePolicyVersion"
	OpDeletePolicyVersion           = "DeletePolicyVersion"
	OpTagPolicy                     = "TagPolicy"
	OpDeletePolicy                  = "DeletePolicy"
	OpPutRolePermissionsBoundary    = "PutRolePermissionsBoundary"
	OpDeleteRolePermissionsBoundary = "DeleteRolePermissionsBoundary"
)

// Refusal codes: why a plan is ineligible (iga_gov_plan.ineligible_reason).
const (
	RefuseRoleGone                 = "role_gone"
	RefuseRoleRecreated            = "role_recreated"
	RefuseServiceLinked            = "service_linked_role"
	RefuseAWSReserved              = "aws_reserved_role"
	RefuseAuthSecManagedRole       = "authsec_managed_role"
	RefuseProtectedRole            = "protected_role"
	RefuseRecognitionOnly          = "recognition_only_identity"
	RefuseNotInActivityReport      = "service_not_in_activity_report"
	RefuseRemovalNotJustified      = "removal_not_justified"
	RefuseRemovalIsDependency      = "removal_is_dependency"
	RefuseDocumentTooLarge         = "document_too_large"
	RefuseEvidenceIncomplete       = "resource_policy_evidence_incomplete"
	RefuseBlocksBoundary           = "resource_policy_blocks_boundary"
	RefuseCustomerBoundaryDirect   = "customer_boundary_requires_iac"
	RefuseNotNarrowable            = "customer_boundary_not_narrowable"
	RefuseNarrowedEmpty            = "customer_boundary_would_be_empty"
	RefuseArtifactOwnedElsewhere   = "artifact_owned_elsewhere"
	RefuseArtifactOtherControl     = "artifact_owned_by_other_control"
	RefuseConsumersChanged         = "artifact_consumers_changed"
	RefuseChangedOutsideAuthSec    = "artifact_changed_outside_authsec"
	RefusePolicyNameInUse          = "boundary_policy_name_in_use"
	RefusePolicyNameTooLong        = "policy_name_too_long"
	RefuseRoleOnlyNotNeeded        = "role_only_recovery_not_needed"
	RefuseRoleOnlyUnavailable      = "role_only_recovery_unavailable"
	RefuseBaselineMissing          = "baseline_boundary_missing"
	RefuseDirectNeedsAuthSecTarget = "direct_requires_authsec_boundary"
)

// Refusal is one reason a plan is ineligible, with the object it names
// ("S3 access point policies could not be read in eu-west-1").
type Refusal struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

func (r Refusal) String() string {
	if r.Detail == "" {
		return r.Code
	}
	return r.Code + ": " + r.Detail
}

// CompileError is a compilation that produced no plan at all: inputs that do
// not belong together, a live read missing what the plan needs, or evidence
// that is untrusted (§2.11: "untrusted blocks compilation with the remedy").
// DECISION D44: an ineligible role, removal, proof or boundary is NOT an
// error: it is a plan with eligibility ineligible, every reason listed
// (iga_gov_plan.ineligible_reason), no ops and no undo, storable under the
// 050 CHECKs, so the UI can show why (§3.4 "plan | ineligible(reason)").
type CompileError struct {
	Code    string
	Reasons []string
}

func (e *CompileError) Error() string {
	return "igagov: compile: " + e.Code + ": " + strings.Join(e.Reasons, "; ")
}

// Compile error codes.
const (
	ErrCodeInvalidIntent     = "invalid_intent"
	ErrCodeEvidenceUntrusted = "evidence_untrusted"
	ErrCodeEvidenceMismatch  = "evidence_mismatch"
	ErrCodeLiveIncomplete    = "live_read_incomplete"
	ErrCodeNoArtifact        = "no_artifact_to_remove"
	ErrCodeInput             = "invalid_input"
)

func compileErr(code string, reasons ...string) error {
	return &CompileError{Code: code, Reasons: reasons}
}

/* ------------------------------------------------------------------------- */
/*                         The live read and its state                        */
/* ------------------------------------------------------------------------- */

// LiveRole is the discovery-role read of a role (§3.5: GetRole,
// ListAttachedRolePolicies, ListRolePolicies, GetRolePolicy).
type LiveRole struct {
	RoleID    string
	ARN       string
	Name      string
	Path      string
	AccountID string
	Partition string // "aws" when empty
	Tags      map[string]string
	// Continuity is iga_identity_accounts.continuity; "" means immutable.
	Continuity string
	// BoundaryARN is the role's permissions boundary ("" = none).
	BoundaryARN string
	// ManagedPolicies and InlinePolicies are the role's own permission
	// policies with canonical document hashes (§2.8 apply precondition).
	ManagedPolicies []PolicyRef
	InlinePolicies  []PolicyRef
	// TrustPolicyHash is the canonical hash of the trust policy (§11).
	TrustPolicyHash string
}

// LivePolicy is the discovery-role read of one managed policy (§3.5:
// GetPolicy, GetPolicyVersion, ListPolicyVersions, ListEntitiesForPolicy).
type LivePolicy struct {
	ARN  string
	Path string
	Name string
	Tags map[string]string
	// DefaultDocument is the default version's document as AWS returns it
	// (URL-encoded or not); it is canonicalised here.
	DefaultDocument string
	// VersionCount is the number of versions (IAM keeps at most 5).
	VersionCount int
	// AttachmentSet is every entity using the policy, every usage type.
	AttachmentSet []AttachedEntity
}

// LiveRead is one discovery-role read (§3.5, §8.3). Policies holds every
// policy read, by ARN; a nil value records NoSuchEntity, a missing key means
// the policy was not read. The role's boundary and every policy a plan names
// (desired, replaced, split copy) must be read: Plan.PoliciesToRead lists
// them for a recovery read.
type LiveRead struct {
	ReadAt   time.Time
	Role     *LiveRole // nil: GetRole returned NoSuchEntity
	Policies map[string]*LivePolicy
	// Roles and Bindings serve dedicated-identity plans (§11): other roles
	// read by ARN (nil = NoSuchEntity), and each migration subject's current
	// role ARN.
	Roles    map[string]*LiveRole
	Bindings map[string]string
}

func (r *LiveRole) partition() string {
	if r.Partition != "" {
		return r.Partition
	}
	if p := strings.SplitN(r.ARN, ":", 3); len(p) == 3 && p[1] != "" {
		return p[1]
	}
	return "aws"
}

func (r *LiveRole) ref() RoleRef {
	return RoleRef{RoleID: r.RoleID, ARN: r.ARN, Name: r.Name, AccountID: r.AccountID, Partition: r.partition()}
}

// DocumentHash returns the canonical hash of the policy's default document.
func (p *LivePolicy) DocumentHash() (string, error) {
	return DocumentHash(p.DefaultDocument)
}

// otherUsers is the attachment set without this role's use of the policy as
// its boundary — the "other entities' use" fact (§2.8). This role attaching
// the policy as a PERMISSIONS policy is another use, and stays.
func otherUsers(set []AttachedEntity, roleID string) []AttachedEntity {
	out := []AttachedEntity{}
	for _, e := range set {
		if e.Kind == "role" && e.ID == roleID && e.Usage == UsageBoundary {
			continue
		}
		out = append(out, e)
	}
	return ArtifactStateFacts{RoleID: "x", AttachmentSet: out}.Normalized().AttachmentSet
}

func (lr LiveRead) policy(arn string) (*LivePolicy, error) {
	p, ok := lr.Policies[arn]
	if !ok {
		return nil, compileErr(ErrCodeLiveIncomplete, "policy "+arn+" was not read")
	}
	return p, nil
}

// ArtifactState is §2.8's one definition of the artifact's state, from a
// discovery-role read: the role's incarnation, its current boundary and that
// boundary's canonical default-document hash (both null when there is none),
// and the boundary policy's full attachment set (every usage type). It
// excludes the role's own permission policies. Compilation, execution,
// recovery, undo and remove-control all use it.
func ArtifactState(live LiveRead) (ArtifactStateFacts, error) {
	if live.Role == nil {
		return ArtifactStateFacts{}, compileErr(ErrCodeLiveIncomplete, "the role was not found")
	}
	s := ArtifactStateFacts{RoleID: live.Role.RoleID, AttachmentSet: []AttachedEntity{}}
	if arn := live.Role.BoundaryARN; arn != "" {
		p, err := live.policy(arn)
		if err != nil {
			return ArtifactStateFacts{}, err
		}
		if p == nil {
			return ArtifactStateFacts{}, compileErr(ErrCodeLiveIncomplete, "the role's boundary "+arn+" returned NoSuchEntity")
		}
		h, err := p.DocumentHash()
		if err != nil {
			return ArtifactStateFacts{}, fmt.Errorf("igagov: boundary document of %s: %w", arn, err)
		}
		s.BoundaryARN, s.BoundaryDocumentHash = strPtr(arn), strPtr(h)
		s.AttachmentSet = append(s.AttachmentSet, p.AttachmentSet...)
	}
	return s.Normalized(), nil
}

func strPtr(s string) *string { return &s }

func derefOr(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

// protectionTags are the role tags eligibility depends on (§3.1); they enter
// the apply precondition so a tag added after review changes the plan.
// DECISION D51: §2.8 says "protection tags" without a list; they are exactly
// the two tags §3.1 decides eligibility by (ManagedBy, authsec:protected).
func protectionTags(tags map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range tags {
		if k == RoleTagManagedBy || k == RoleTagProtected {
			out[k] = v
		}
	}
	return out
}

// ApplyPreconditionFor is §2.8's apply precondition from a live read.
func ApplyPreconditionFor(live LiveRead) (ApplyPrecondition, error) {
	st, err := ArtifactState(live)
	if err != nil {
		return ApplyPrecondition{}, err
	}
	r := live.Role
	return ApplyPrecondition{ArtifactState: st, RoleARN: r.ARN, RolePath: r.Path, ProtectionTags: protectionTags(r.Tags),
		ManagedPolicies: append([]PolicyRef{}, r.ManagedPolicies...), InlinePolicies: append([]PolicyRef{}, r.InlinePolicies...)}, nil
}

// roleDefinitionHash covers what the apply precondition adds to
// artifact_state (role ARN, path, protection tags, own policies). The
// classifier compares it only while every artifact fact is at its before
// value (DECISION D33).
func roleDefinitionHash(r *LiveRole) (string, error) {
	return HashCanonicalTagged(domainRoleDefinition, struct {
		RoleARN         string            `json:"role_arn"`
		RolePath        string            `json:"role_path"`
		ProtectionTags  map[string]string `json:"protection_tags"`
		ManagedPolicies []PolicyRef       `json:"managed_policies"`
		InlinePolicies  []PolicyRef       `json:"inline_policies"`
	}{r.ARN, r.Path, protectionTags(r.Tags), sortedRefs(r.ManagedPolicies), sortedRefs(r.InlinePolicies)})
}

/* ------------------------------------------------------------------------- */
/*                               Eligibility                                  */
/* ------------------------------------------------------------------------- */

// RoleEligibility is §3.1: eligibility by path and tag, never by name.
// DECISION D28: tag values are compared case-insensitively, so the compiler
// refuses at least everything the enforcement role's exact-match denies do.
func RoleEligibility(r LiveRole) []Refusal {
	var out []Refusal
	switch {
	case strings.HasPrefix(r.Path, pathServiceLinked):
		out = append(out, Refusal{RefuseServiceLinked, "path " + r.Path})
	case strings.HasPrefix(r.Path, pathAWSReserved):
		out = append(out, Refusal{RefuseAWSReserved, "path " + r.Path})
	}
	if strings.EqualFold(r.Tags[RoleTagManagedBy], RoleTagManagedByValue) {
		out = append(out, Refusal{RefuseAuthSecManagedRole, "tagged ManagedBy=AuthSec"})
	}
	if strings.EqualFold(r.Tags[RoleTagProtected], "true") {
		out = append(out, Refusal{RefuseProtectedRole, "tagged authsec:protected=true"})
	}
	if r.Continuity == ContinuityRecognition {
		out = append(out, Refusal{RefuseRecognitionOnly, "identity continuity is recognition_only"})
	}
	return out
}

// checkIncarnation is §2.2 / §8.3: the live RoleId must be the control's.
func checkIncarnation(live LiveRead, roleID string) []Refusal {
	if live.Role == nil {
		return []Refusal{{RefuseRoleGone, "role " + roleID + " returned NoSuchEntity"}}
	}
	if live.Role.RoleID != roleID {
		return []Refusal{{RefuseRoleRecreated, "live RoleId " + live.Role.RoleID + " is not " + roleID}}
	}
	return nil
}

/* ------------------------------------------------------------------------- */
/*                         Documents: build and narrow                        */
/* ------------------------------------------------------------------------- */

// PolicyChars counts a document's characters excluding whitespace, as IAM
// does for its 6,144-character managed-policy limit (§3.2, L-08).
func PolicyChars(text []byte) int {
	n := 0
	for _, r := range string(text) {
		if !unicode.IsSpace(r) {
			n++
		}
	}
	return n
}

// ExcludeOnlyDocument is §3.2's R1a boundary: one Allow with NotAction of
// the removed namespaces (as "<ns>:*", lower-cased, sorted, de-duplicated)
// on "*". It allows everything else, so it cannot take away access nobody
// selected (§3.4 "preservation is by construction"). It returns the RFC 8785
// text and its content hash.
func ExcludeOnlyDocument(remove []string) ([]byte, string, error) {
	if len(remove) == 0 {
		return nil, "", errors.New("igagov: an exclusion-only boundary needs at least one removed namespace")
	}
	var actions []string
	for _, s := range remove {
		ns := strings.ToLower(strings.TrimSpace(s))
		if !reService.MatchString(ns) {
			return nil, "", fmt.Errorf("igagov: %q is not an IAM service namespace", s)
		}
		actions = append(actions, ns+":*")
	}
	doc := map[string]any{
		"Version": PolicyVersion20121017,
		"Statement": []any{map[string]any{
			"Sid": AuthSecBoundarySid, "Effect": EffectAllow, "NotAction": sortedUnique(actions), "Resource": "*",
		}},
	}
	c, err := CanonicalizeValue(doc)
	if err != nil {
		return nil, "", err
	}
	return c, ContentHash(c), nil
}

// BoundaryExcludes reports whether a boundary document excludes namespace ns
// entirely: no Allow statement grants any action of ns (Statement
// .GrantsNamespace, which counts NotAction and wildcards). This is the
// per-service "exclusion" fact of §8.7 for any boundary in force, AuthSec's
// or a customer's; conditions and resources are ignored, so a conditional
// grant counts as not excluded (never over-claims a removal).
func BoundaryExcludes(doc PolicyDocument, ns string) bool {
	for _, st := range doc.Statements {
		if st.GrantsNamespace(ns) {
			return false
		}
	}
	return true
}

// ExclusionChanges compares two boundaries (nil text = no boundary, which
// excludes nothing) over the candidate namespaces: what the change newly
// excludes, what stays excluded, and what it stops excluding (§8.7 history
// `change`).
func ExclusionChanges(beforeText, afterText *string, candidates []string) (newly, already, unexcluded []string, err error) {
	dec := func(t *string) (*PolicyDocument, error) {
		if t == nil {
			return nil, nil
		}
		d, err := DecodePolicyDocument(*t)
		if err != nil {
			return nil, err
		}
		return &d, nil
	}
	b, err := dec(beforeText)
	if err != nil {
		return nil, nil, nil, err
	}
	a, err := dec(afterText)
	if err != nil {
		return nil, nil, nil, err
	}
	excl := func(d *PolicyDocument, ns string) bool { return d != nil && BoundaryExcludes(*d, ns) }
	newly, already, unexcluded = []string{}, []string{}, []string{}
	for _, ns := range sortedUnique(candidates) {
		be, ae := excl(b, ns), excl(a, ns)
		switch {
		case !be && ae:
			newly = append(newly, ns)
		case be && ae:
			already = append(already, ns)
		case be && !ae:
			unexcluded = append(unexcluded, ns)
		}
	}
	return newly, already, unexcluded, nil
}

// notActionNamespaces lists literal namespaces in NotAction lists of Allow
// statements (the exclusions of an AuthSec boundary), as candidates for
// ExclusionChanges.
func notActionNamespaces(text *string) []string {
	if text == nil {
		return nil
	}
	d, err := DecodePolicyDocument(*text)
	if err != nil {
		return nil
	}
	var out []string
	for _, st := range d.Statements {
		if st.Effect != EffectAllow || !st.IsNotAction {
			continue
		}
		for _, p := range st.NotAction {
			if ns, _, ok := SplitAction(p); ok && !strings.ContainsAny(ns, "*?") {
				out = append(out, strings.ToLower(ns))
			}
		}
	}
	return out
}

// Statement results of a narrowing (§3.4: "kept | narrowed | deleted").
const (
	NarrowKept     = "kept"
	NarrowNarrowed = "narrowed"
	NarrowDeleted  = "deleted"
)

// NarrowedStatement records what narrowing did to one statement.
type NarrowedStatement struct {
	Index          int      `json:"index"`
	Sid            string   `json:"sid,omitempty"`
	Effect         string   `json:"effect"`
	Result         string   `json:"result"`
	RemovedActions []string `json:"removed_actions,omitempty"`
}

// Narrowing is the record §3.4 requires: per statement kept / narrowed /
// deleted, and the proof that the result's action set is a subset of the
// original's with every other statement element unchanged (L-07).
type Narrowing struct {
	Statements  []NarrowedStatement `json:"statements"`
	Changed     bool                `json:"changed"`
	SubsetProof bool                `json:"subset_proof"`
}

// namespaceWildcard: a '*' or '?' in the namespace part of an action, or an
// action with no namespace at all ("*"). DECISION D29: "sqs:*" names one
// namespace and is removable; "s*:*" or "*" is a namespace wildcard.
func namespaceWildcard(action string) bool {
	ns, _, ok := SplitAction(action)
	return !ok || strings.ContainsAny(ns, "*?")
}

// NarrowCustomerBoundary is §3.4's structure-preserving narrowing: each
// Allow keeps Sid, Effect, Resource, NotResource, Condition and every other
// element byte-identical (canonical form); only Action entries whose
// namespace is in remove are deleted; an Allow left with no action is
// deleted; Deny statements are unchanged. It is refused (refusal set) when
// any Allow uses NotAction, Action "*" or a namespace wildcard, or when
// nothing would remain. It returns the canonical narrowed text and hash.
func NarrowCustomerBoundary(text string, remove []string) ([]byte, string, Narrowing, *Refusal, error) {
	doc, err := DecodePolicyDocument(text)
	if err != nil {
		return nil, "", Narrowing{}, nil, err
	}
	for i, st := range doc.Statements {
		if st.Effect != EffectAllow {
			continue
		}
		if st.IsNotAction {
			return nil, "", Narrowing{}, &Refusal{RefuseNotNarrowable, fmt.Sprintf("statement %d (%s) uses NotAction", i, st.Sid)}, nil
		}
		for _, a := range st.Action {
			if namespaceWildcard(a) {
				return nil, "", Narrowing{}, &Refusal{RefuseNotNarrowable, fmt.Sprintf("statement %d (%s) uses %q", i, st.Sid, a)}, nil
			}
		}
	}
	rm := map[string]bool{}
	for _, s := range remove {
		rm[strings.ToLower(s)] = true
	}
	raw, err := DecodePolicyText(text)
	if err != nil {
		return nil, "", Narrowing{}, nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, "", Narrowing{}, nil, fmt.Errorf("%w: %v", ErrPolicyDocument, err)
	}
	wasObject := strings.HasPrefix(strings.TrimSpace(string(top["Statement"])), "{")
	n := Narrowing{Statements: []NarrowedStatement{}}
	var kept []json.RawMessage
	for i, st := range doc.Statements {
		rec := NarrowedStatement{Index: i, Sid: st.Sid, Effect: st.Effect, Result: NarrowKept}
		if st.Effect != EffectAllow {
			kept = append(kept, st.Raw)
			n.Statements = append(n.Statements, rec)
			continue
		}
		var remaining []string
		for _, a := range st.Action {
			ns, _, _ := SplitAction(a)
			if rm[strings.ToLower(ns)] {
				rec.RemovedActions = append(rec.RemovedActions, a)
				continue
			}
			remaining = append(remaining, a)
		}
		switch {
		case len(rec.RemovedActions) == 0:
			kept = append(kept, st.Raw)
		case len(remaining) == 0:
			rec.Result = NarrowDeleted
			n.Changed = true
		default:
			rec.Result = NarrowNarrowed
			n.Changed = true
			var m map[string]json.RawMessage
			if err := json.Unmarshal(st.Raw, &m); err != nil {
				return nil, "", Narrowing{}, nil, err
			}
			acts, _ := json.Marshal(remaining)
			m["Action"] = acts
			b, err := json.Marshal(m)
			if err != nil {
				return nil, "", Narrowing{}, nil, err
			}
			kept = append(kept, b)
		}
		n.Statements = append(n.Statements, rec)
	}
	if len(kept) == 0 {
		return nil, "", Narrowing{}, &Refusal{RefuseNarrowedEmpty, "every statement of the boundary would be deleted"}, nil
	}
	if wasObject && len(kept) == 1 {
		top["Statement"] = kept[0]
	} else {
		arr, err := json.Marshal(kept)
		if err != nil {
			return nil, "", Narrowing{}, nil, err
		}
		top["Statement"] = arr
	}
	out, err := json.Marshal(top)
	if err != nil {
		return nil, "", Narrowing{}, nil, err
	}
	c, err := Canonicalize(out)
	if err != nil {
		return nil, "", Narrowing{}, nil, err
	}
	if err := checkStorable(c); err != nil {
		return nil, "", Narrowing{}, nil, err
	}
	n.SubsetProof = subsetProof(doc, string(c), n)
	if !n.SubsetProof {
		return nil, "", Narrowing{}, nil, errors.New("igagov: narrowing produced a document that is not a subset of the original")
	}
	return c, ContentHash(c), n, nil, nil
}

// subsetProof re-decodes the narrowed document and checks, statement by
// statement, that every surviving statement equals its original except for
// Action, whose entries are an order-preserving subset of the original's.
func subsetProof(orig PolicyDocument, narrowed string, n Narrowing) bool {
	got, err := DecodePolicyDocument(narrowed)
	if err != nil {
		return false
	}
	j := 0
	for i, rec := range n.Statements {
		if rec.Result == NarrowDeleted {
			continue
		}
		if j >= len(got.Statements) {
			return false
		}
		o, g := orig.Statements[i], got.Statements[j]
		j++
		if withoutAction(o.Raw) != withoutAction(g.Raw) || o.IsNotAction != g.IsNotAction {
			return false
		}
		k := 0
		for _, a := range g.Action {
			for k < len(o.Action) && o.Action[k] != a {
				k++
			}
			if k == len(o.Action) {
				return false
			}
			k++
		}
		if rec.Result == NarrowKept && len(g.Action) != len(o.Action) {
			return false
		}
	}
	return j == len(got.Statements)
}

func withoutAction(raw json.RawMessage) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return "\x00invalid"
	}
	delete(m, "Action")
	b, _ := json.Marshal(m)
	c, err := Canonicalize(b)
	if err != nil {
		return "\x00invalid"
	}
	return string(c)
}

/* ------------------------------------------------------------------------- */
/*                         The first-attachment proof                         */
/* ------------------------------------------------------------------------- */

// IncompleteForm is a collected form whose coverage is not complete in a
// Region (or account-wide).
type IncompleteForm struct {
	Form   string `json:"form"`
	Region string `json:"region,omitempty"`
	State  string `json:"state"`
}

// Blocker is an observed resource policy that makes a first attachment
// unsafe: a Deny + NotPrincipal statement exempting this role (its ARN, a
// session, its account, or "*"), or an unparseable policy.
type Blocker struct {
	Kind     string `json:"kind"` // deny_not_principal | unparseable
	Form     string `json:"form"`
	Region   string `json:"region,omitempty"`
	Resource string `json:"resource"`
	Sid      string `json:"sid,omitempty"`
}

// Blocker kinds.
const (
	BlockerDenyNotPrincipal = "deny_not_principal"
	BlockerUnparseable      = "unparseable"
)

// FirstAttachmentProof is §3.4's proof for a role going from no boundary to
// a boundary, from ONE scan's immutable evidence (§3.9).
type FirstAttachmentProof struct {
	ScanRunID  string           `json:"scan_run_id"`
	Incomplete []IncompleteForm `json:"incomplete"`
	Blockers   []Blocker        `json:"blockers"`
	// Unanalysed is what the approver must accept item by item (acceptance
	// kind unanalysed_form): uncollected forms of the account's services and
	// resources in other accounts, minus forms already a bundle gap.
	Unanalysed []UnanalysedItem `json:"unanalysed"`
	// CoveredByGaps names forms left out of Unanalysed because the bundle
	// already lists them as gaps (DECISION D24/D30): one acceptance each.
	CoveredByGaps []string `json:"covered_by_gaps"`
}

// Blocked reports whether the proof refuses the first attachment.
func (p FirstAttachmentProof) Blocked() bool { return len(p.Incomplete) > 0 || len(p.Blockers) > 0 }

// Refusals renders the proof's blocks as refusal reasons, one per object.
func (p FirstAttachmentProof) Refusals() []Refusal {
	var out []Refusal
	for _, f := range p.Incomplete {
		d := f.Form + " " + f.State
		if f.Region != "" {
			d = f.Form + " in " + f.Region + " " + f.State
		}
		out = append(out, Refusal{RefuseEvidenceIncomplete, d})
	}
	for _, b := range p.Blockers {
		out = append(out, Refusal{RefuseBlocksBoundary, b.Kind + " " + b.Resource})
	}
	return out
}

func notPrincipalExempts(p *Principal, role RoleRef) bool {
	if p == nil {
		return false
	}
	// DECISION D31: a NotPrincipal of "*" exempts everyone, this role
	// included, and AWS denies any principal with a boundary "regardless of
	// the values specified in the NotPrincipal element" — so it blocks too.
	return p.Wildcard || principalLists(p, role)
}

// ProveFirstAttachment is §3.4's first-attachment proof from the named
// scan's evidence:
//
//   - every collected form complete in every enabled Region (account-scoped
//     forms: every row complete, at least one) — else incomplete, naming it;
//   - no observed policy of any form has a Deny with NotPrincipal exempting
//     the role, and none is unparseable — else a blocker, naming it;
//   - every uncollected form of the account's services, and "resources in
//     other accounts", is unanalysed (DECISION D30: accountServices are the
//     namespaces the caller knows the account uses; nil means every
//     uncollected form in the catalog). A form the bundle already lists as a
//     gap is not listed again (D24).
func ProveFirstAttachment(role RoleRef, scanRunID string, ev *ResourcePolicyEvidence, enabledRegions, accountServices []string, gaps []Gap) FirstAttachmentProof {
	p := FirstAttachmentProof{ScanRunID: scanRunID, Incomplete: []IncompleteForm{}, Blockers: []Blocker{},
		Unanalysed: []UnanalysedItem{}, CoveredByGaps: []string{}}
	for _, f := range AllForms() {
		if f.State != FormCollected {
			continue
		}
		if ev == nil {
			p.Incomplete = append(p.Incomplete, IncompleteForm{Form: f.Name, State: CoverageNotCollected})
			continue
		}
		ra := AnalyzeRoutes(f.Namespace, RoleRef{}, ev.coverageOnly(), enabledRegions)
		for _, r := range ra.Routes {
			if r.Form == f.Name && r.Effect == RouteEffectNotAnalysed {
				p.Incomplete = append(p.Incomplete, IncompleteForm{Form: f.Name, Region: r.Region, State: r.Reason})
			}
		}
	}
	if ev != nil {
		for _, ob := range ev.Observations {
			if !ob.PolicyPresent {
				continue
			}
			if ob.ParseState == ParseUnparseable || ob.Document == nil {
				p.Blockers = append(p.Blockers, Blocker{Kind: BlockerUnparseable, Form: ob.Form, Region: ob.Region, Resource: ob.ResourceARN})
				continue
			}
			for _, st := range ob.Document.Statements {
				if st.Effect == EffectDeny && notPrincipalExempts(st.NotPrincipal, role) {
					p.Blockers = append(p.Blockers, Blocker{Kind: BlockerDenyNotPrincipal, Form: ob.Form, Region: ob.Region,
						Resource: ob.ResourceARN, Sid: st.Sid})
				}
			}
		}
	}
	sort.Slice(p.Blockers, func(i, j int) bool {
		a, b := p.Blockers[i], p.Blockers[j]
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Sid < b.Sid
	})
	gapKeys := map[string]bool{}
	for _, g := range gaps {
		gapKeys[g.Key] = true
	}
	var svc map[string]bool
	if accountServices != nil {
		svc = map[string]bool{}
		for _, s := range accountServices {
			svc[s] = true
		}
	}
	for _, f := range AllForms() {
		if f.State != FormUncollected || (svc != nil && !svc[f.Namespace]) {
			continue
		}
		key := "unanalysed_form:" + f.Name
		if gapKeys[key] {
			p.CoveredByGaps = append(p.CoveredByGaps, f.Name)
			continue
		}
		p.Unanalysed = append(p.Unanalysed, UnanalysedItem{Key: key, Form: f.Name, Reason: "form_not_collected"})
	}
	p.Unanalysed = append(p.Unanalysed, UnanalysedItem{Key: unanalysedOtherAccount, Reason: "resources_in_other_accounts"})
	p.Unanalysed = sortedUnanalysed(p.Unanalysed)
	return p
}

/* ------------------------------------------------------------------------- */
/*                                  Plans                                     */
/* ------------------------------------------------------------------------- */

// Op is one native operation of a plan, in execution order (§2.8 JCS(ops),
// §8.5). Fields not used by an op are omitted.
type Op struct {
	Op                string            `json:"op"`
	RoleName          string            `json:"role_name,omitempty"`
	RoleARN           string            `json:"role_arn,omitempty"`
	PolicyARN         string            `json:"policy_arn,omitempty"`
	PolicyName        string            `json:"policy_name,omitempty"`
	Path              string            `json:"path,omitempty"`
	DocumentHash      string            `json:"document_hash,omitempty"`
	SetAsDefault      bool              `json:"set_as_default,omitempty"`
	Tags              map[string]string `json:"tags,omitempty"`
	Select            string            `json:"select,omitempty"`
	IfVersionsAtLeast int               `json:"if_versions_at_least,omitempty"`
	// Dedicated-identity steps (§11, split.go).
	SubjectARN      string `json:"subject_arn,omitempty"`
	TrustPolicyHash string `json:"trust_policy_hash,omitempty"`
	ResourceARN     string `json:"resource_arn,omitempty"`
	Principal       string `json:"principal,omitempty"`
	InlineName      string `json:"inline_name,omitempty"`
	InstanceProfile string `json:"instance_profile,omitempty"`
	OnlyIfUnused    bool   `json:"only_if_unused,omitempty"`
	// Binding and Steps describe a BindSubject / DeleteRole step: the
	// binding kind and the native calls it consists of (§11 table).
	Binding string   `json:"binding,omitempty"`
	Steps   []string `json:"steps,omitempty"`
}

// BoundaryRef names a boundary and its document.
type BoundaryRef struct {
	ARN          string `json:"arn"`
	DocumentHash string `json:"document_hash"`
}

// PlanDiff is iga_gov_plan.diff: what the plan changes and why, for review
// and for recovery. Facts is the classifier's fact table (§2.8); it is
// stored here because the plan's columns alone do not carry the expected
// state of every policy a plan touches (DECISION D32).
type PlanDiff struct {
	Case            string                `json:"case"`
	BoundaryBefore  *BoundaryRef          `json:"boundary_before"`
	BoundaryAfter   *BoundaryRef          `json:"boundary_after"`
	NewlyExcluded   []string              `json:"newly_excluded"`
	AlreadyExcluded []string              `json:"already_excluded"`
	NewlyUnexcluded []string              `json:"newly_unexcluded"`
	Narrowing       *Narrowing            `json:"narrowing,omitempty"`
	FirstAttachment *FirstAttachmentProof `json:"first_attachment,omitempty"`
	Split           *SplitDetail          `json:"split,omitempty"`
	Notes           []string              `json:"notes"`
	Facts           []Fact                `json:"facts"`
}

// Plan cases (PlanDiff.Case).
const (
	CaseNoneToAuthSec       = "none_to_authsec"
	CaseAuthSecVersion      = "authsec_version"
	CaseCustomerInPlace     = "customer_in_place"
	CaseCustomerSplit       = "customer_split"
	CaseUndoDeleteNew       = "undo_delete_new_boundary"
	CaseUndoEarlierDocument = "undo_earlier_document"
	CaseUndoCustomerInPlace = "undo_customer_in_place"
	CaseUndoSplit           = "undo_split_copy"
	CaseRecoverDetach       = "role_only_detach"
	CaseRecoverNewPolicy    = "role_only_new_policy"
	CaseRecoverSplit        = "role_only_repoint_shared"
	CaseRemoveDetach        = "remove_detach"
	CaseRemoveInPlace       = "remove_restore_in_place"
	CaseRemoveRepoint       = "remove_repoint_baseline"
	CaseSplitIsolate        = "split_isolate"
	CaseSplitRevert         = "split_revert"
	NoteAlreadyInPlace      = "already_in_place"
	NoteNothingToNarrow     = "customer_boundary_already_excludes"
	NoteBaselineDocChanged  = "baseline_document_changed"
	NoteCopyRetained        = "copy_retained_for_other_users"
	NotePolicyRetained      = "policy_retained_for_other_users"
)

// ArchivedDocument is a document the plan read or will write; the service
// inserts each into iga_gov_document before the plan (the plan's FKs).
type ArchivedDocument struct {
	Hash      string `json:"hash"`
	Canonical string `json:"canonical"`
}

// Plan is one compiled plan, shaped as an iga_gov_plan row (minus ids and
// times the service assigns). Nil pointers are SQL NULL.
type Plan struct {
	ControlID               string             `json:"control_id"`
	Kind                    string             `json:"kind"`
	Delivery                string             `json:"delivery"`
	Eligibility             string             `json:"eligibility"`
	IneligibleReason        string             `json:"ineligible_reason"`
	Refusals                []Refusal          `json:"refusals"`
	Basis                   string             `json:"basis"`
	BasisReadAt             time.Time          `json:"basis_read_at"`
	Precondition            json.RawMessage    `json:"precondition"`
	PreconditionHash        string             `json:"precondition_hash"`
	BeforeDocumentHash      *string            `json:"before_document_hash"`
	DesiredAttachment       string             `json:"desired_attachment"`
	DesiredBoundaryARN      *string            `json:"desired_boundary_arn"`
	DesiredDocumentHash     *string            `json:"desired_document_hash"`
	ReplacedBoundaryARN     *string            `json:"replaced_boundary_arn"`
	ArtifactDisposition     string             `json:"artifact_disposition"`
	BundleHash              string             `json:"bundle_hash"`
	EvidenceRev             int64              `json:"evidence_rev"`
	ResourcePolicyScanRunID *string            `json:"resource_policy_scan_run_id"`
	FirstAttachment         bool               `json:"first_attachment"`
	Unanalysed              []UnanalysedItem   `json:"unanalysed"`
	Impact                  Impact             `json:"impact"`
	ImpactHash              string             `json:"impact_hash"`
	Ops                     []Op               `json:"operations"`
	Diff                    PlanDiff           `json:"diff"`
	PlanHash                string             `json:"plan_hash"`
	MaterialHash            string             `json:"material_hash"`
	GapRefs                 []GapRef           `json:"gap_refs"`
	Documents               []ArchivedDocument `json:"documents"`
	// Facts is the classifier's fact table (also in Diff.Facts).
	Facts []Fact `json:"-"`
}

// Eligible reports whether the plan can be approved and deployed by its
// delivery.
func (p Plan) Eligible() bool { return p.Eligibility != EligibilityIneligible }

// HashInput returns the plan's §2.8 plan_hash input.
func (p Plan) HashInput() PlanHashInput {
	return PlanHashInput{ControlID: p.ControlID, Kind: p.Kind, Delivery: p.Delivery, DesiredAttachment: p.DesiredAttachment,
		DesiredBoundaryARN: p.DesiredBoundaryARN, DesiredDocumentHash: p.DesiredDocumentHash,
		ReplacedBoundaryARN: p.ReplacedBoundaryARN, ArtifactDisposition: p.ArtifactDisposition, BundleHash: p.BundleHash,
		EvidenceRev: p.EvidenceRev, ResourcePolicyScanRunID: p.ResourcePolicyScanRunID, FirstAttachment: p.FirstAttachment,
		Unanalysed: p.Unanalysed, PreconditionHash: p.PreconditionHash, Ops: p.Ops}
}

// PoliciesToRead lists every policy ARN the classifier needs from a live
// read of this plan (the role's boundary aside).
func (p Plan) PoliciesToRead() []string {
	var out []string
	for _, f := range p.Facts {
		if f.Kind == FactPolicyDocument {
			out = append(out, f.Subject)
		}
	}
	return sortedUnique(out)
}

// CheckStorable mirrors 050's iga_gov_plan CHECKs (ineligible reason,
// attachment, kind, disposition, first attachment) so a compiler bug fails
// here before PostgreSQL refuses the row.
func (p Plan) CheckStorable() error {
	var errs []string
	inel := p.Eligibility == EligibilityIneligible
	if inel != (p.IneligibleReason != "") {
		errs = append(errs, "iga_gov_plan_ineligible_chk")
	}
	if !inel {
		switch p.DesiredAttachment {
		case AttachmentPresent:
			if p.DesiredBoundaryARN == nil || p.DesiredDocumentHash == nil {
				errs = append(errs, "iga_gov_plan_attachment_chk")
			}
		default:
			if p.DesiredBoundaryARN != nil || p.DesiredDocumentHash != nil {
				errs = append(errs, "iga_gov_plan_attachment_chk")
			}
		}
	}
	split := p.Kind == PlanSplit || p.Kind == PlanSplitRevert
	if split != (p.DesiredAttachment == AttachmentUnchanged) ||
		(p.Kind == PlanApply && p.DesiredAttachment != AttachmentPresent) ||
		(split && p.Delivery != DeliveryIaCPR && p.Delivery != DeliveryExport) {
		errs = append(errs, "iga_gov_plan_kind_chk")
	}
	if (p.DesiredAttachment == AttachmentAbsent && p.ArtifactDisposition != DispositionDelete && p.ArtifactDisposition != DispositionRetainShared) ||
		(p.Kind != PlanUndo && p.Kind != PlanRemoveControl && p.ArtifactDisposition != DispositionKeep) ||
		(p.ArtifactDisposition != DispositionKeep && (p.ReplacedBoundaryARN == nil ||
			(p.DesiredBoundaryARN != nil && *p.ReplacedBoundaryARN == *p.DesiredBoundaryARN))) {
		errs = append(errs, "iga_gov_plan_disposition_chk")
	}
	if p.FirstAttachment && (p.DesiredAttachment != AttachmentPresent || p.ResourcePolicyScanRunID == nil) {
		errs = append(errs, "iga_gov_plan_first_attachment_chk")
	}
	if len(errs) > 0 {
		return fmt.Errorf("igagov: plan violates %s", strings.Join(errs, ", "))
	}
	return nil
}

// ControlRef is the control a plan is compiled for, with what its tags and
// ledger say (§2.3, §3.2).
type ControlRef struct {
	ID        string
	PolicyID  string
	AccountID string
	RoleID    string
	// WorkspaceRef is the opaque authsec:workspace tag value.
	WorkspaceRef string
	// OwnedPolicyARNs are the boundary policies the ledger records as this
	// control's (iga_gov_artifact boundary_policy rows present).
	OwnedPolicyARNs []string
}

func (c ControlRef) validate() error {
	if c.ID == "" || c.RoleID == "" || !reAccount.MatchString(c.AccountID) || c.WorkspaceRef == "" {
		return compileErr(ErrCodeInput, "the control needs an id, account, RoleId and workspace ref")
	}
	return nil
}

func (c ControlRef) owns(arn string) bool {
	for _, a := range c.OwnedPolicyARNs {
		if a == arn {
			return true
		}
	}
	return false
}

// ownerValue is the policy_owner fact value of a policy's tags.
func ownerValue(tags map[string]string) string {
	if tags[TagManagedBy] != TagManagedByValue {
		return "customer"
	}
	return "authsec:" + tags[TagWorkspace] + ":" + tags[TagControl]
}

func (c ControlRef) ownerValue() string { return "authsec:" + c.WorkspaceRef + ":" + c.ID }

func (c ControlRef) createTags() map[string]string {
	return map[string]string{TagManagedBy: TagManagedByValue, TagWorkspace: c.WorkspaceRef, TagControl: c.ID,
		TagPolicy: c.PolicyID, TagChange: DeploymentPlaceholder}
}

func (c ControlRef) changeTags() map[string]string {
	return map[string]string{TagPolicy: c.PolicyID, TagChange: DeploymentPlaceholder}
}

// EvidenceRef is the evidence a plan is compiled from: the bundle (§2.11),
// the graph revision, and the role connector's scan whose resource-policy
// observations were read (§3.9).
type EvidenceRef struct {
	Bundle      Bundle
	EvidenceRev int64
	ScanRunID   string
}

func (e EvidenceRef) validate(roleID string) error {
	if e.Bundle.Hash == "" || len(e.Bundle.Facts.Sources) == 0 {
		return compileErr(ErrCodeInput, "a plan needs its evidence bundle")
	}
	if e.Bundle.Trust == TrustUntrusted {
		return compileErr(ErrCodeEvidenceUntrusted, e.Bundle.TrustReasons...)
	}
	if e.EvidenceRev <= 0 || e.ScanRunID == "" {
		return compileErr(ErrCodeInput, "a plan needs its evidence revision and resource-policy scan run")
	}
	if e.Bundle.Facts.Target.RoleID != roleID {
		return compileErr(ErrCodeEvidenceMismatch, "the bundle is for role "+e.Bundle.Facts.Target.RoleID)
	}
	revOK, runOK := false, false
	for _, s := range e.Bundle.Facts.Sources {
		revOK = revOK || s.Rev == e.EvidenceRev
		runOK = runOK || s.ConnectorRun == e.ScanRunID || derefOr(s.ResourcePolicyRun, "") == e.ScanRunID
	}
	if !revOK || !runOK {
		return compileErr(ErrCodeEvidenceMismatch, "the evidence revision and scan run must be the bundle's source")
	}
	return nil
}

func (e EvidenceRef) gaps() []Gap { return e.Bundle.Facts.Gaps }

// plan starts a plan with the evidence identifiers and an empty diff.
func (e EvidenceRef) plan(controlID, kind, delivery string, readAt time.Time) Plan {
	return Plan{ControlID: controlID, Kind: kind, Delivery: delivery, Eligibility: EligibilityEligible,
		Refusals: []Refusal{}, Basis: BasisLiveRead, BasisReadAt: readAt.UTC(), ArtifactDisposition: DispositionKeep,
		BundleHash: e.Bundle.Hash, EvidenceRev: e.EvidenceRev, ResourcePolicyScanRunID: strPtr(e.ScanRunID),
		Unanalysed: []UnanalysedItem{}, Ops: []Op{}, GapRefs: append([]GapRef{}, e.Bundle.GapRefs...),
		Diff:      PlanDiff{Notes: []string{}, NewlyExcluded: []string{}, AlreadyExcluded: []string{}, NewlyUnexcluded: []string{}},
		Documents: []ArchivedDocument{}}
}

func (p *Plan) refuse(rs ...Refusal) {
	p.Refusals = append(p.Refusals, rs...)
}

func (p *Plan) archive(hash string, canonical []byte) {
	for _, d := range p.Documents {
		if d.Hash == hash {
			return
		}
	}
	p.Documents = append(p.Documents, ArchivedDocument{Hash: hash, Canonical: string(canonical)})
	sort.Slice(p.Documents, func(i, j int) bool { return p.Documents[i].Hash < p.Documents[j].Hash })
}

func (p *Plan) archiveText(text string) (string, error) {
	c, h, err := CanonicalDocument(text)
	if err != nil {
		return "", err
	}
	p.archive(h, c)
	return h, nil
}

// seal finishes a plan: an ineligible plan has no ops; the impact, plan and
// material hashes are computed, the facts copied into the diff, and the
// storage CHECKs asserted.
func (p *Plan) seal() error {
	if len(p.Refusals) > 0 {
		p.Eligibility = EligibilityIneligible
		parts := make([]string, len(p.Refusals))
		for i, r := range p.Refusals {
			parts[i] = r.String()
		}
		p.IneligibleReason = strings.Join(parts, "; ")
		p.Ops = []Op{}
	}
	if p.Ops == nil {
		p.Ops = []Op{}
	}
	sortFacts(p.Facts)
	p.Diff.Facts = p.Facts
	p.Impact = p.Impact.Normalized()
	ih, err := ImpactHash(p.Impact)
	if err != nil {
		return err
	}
	p.ImpactHash = ih
	in := p.HashInput()
	if p.PlanHash, err = PlanHash(in); err != nil {
		return err
	}
	if p.MaterialHash, err = MaterialHash(MaterialHashInput{Plan: in, ImpactHash: ih, Gaps: p.GapRefs}); err != nil {
		return err
	}
	return p.CheckStorable()
}

// impactFor is §2.8's impact from the bundle's facts: consumers, owners,
// removed and retained services with basis, the statement revisions of every
// identity statement granting a removed service, and the removed services'
// resource-policy routes.
func impactFor(b BundleFacts, remove []RemoveEntry, retain []RetainEntry) Impact {
	rm := map[string]bool{}
	im := Impact{Consumers: append([]ImpactConsumer{}, b.Consumers...), OwnerUserIDs: append([]string{}, b.Owners...),
		Removed: []ImpactService{}, Retained: []ImpactService{}, StatementRevisions: []string{}, Routes: []Route{}}
	for _, e := range remove {
		rm[e.Service] = true
		im.Removed = append(im.Removed, ImpactService{Service: e.Service, Basis: e.Basis})
	}
	for _, e := range retain {
		im.Retained = append(im.Retained, ImpactService{Service: e.Service, Basis: e.Basis})
	}
	for _, g := range b.Grants {
		for _, s := range g.Services {
			if rm[s] {
				im.StatementRevisions = append(im.StatementRevisions, g.StatementHash)
				break
			}
		}
	}
	for _, r := range b.Routes {
		if rm[r.Service] {
			im.Routes = append(im.Routes, r)
		}
	}
	return im
}

/* ------------------------------------------------------------------------- */
/*                       Apply and undo (right-sizing)                        */
/* ------------------------------------------------------------------------- */

// TargetInput is everything §8.3 compiles one target of a right_size
// version from.
type TargetInput struct {
	Control  ControlRef
	Intent   RightSizeIntent
	Live     LiveRead
	Evidence EvidenceRef
	// ScanEvidence is the named scan's immutable resource-policy evidence
	// (nil when the run collected none).
	ScanEvidence   *ResourcePolicyEvidence
	EnabledRegions []string
	// AccountServices are the namespaces the account uses, for the
	// unanalysed set (D30); nil lists every uncollected form.
	AccountServices    []string
	DependencyContexts []DependencyContext
}

// TargetPlans is a target's apply plan and the undo plan derived from its
// artifact delta. Undo is nil when the apply is ineligible.
type TargetPlans struct {
	Apply Plan
	Undo  *Plan
}

// boundaryKind classifies the role's current boundary (§3.3).
type boundaryKind int

const (
	bkNone boundaryKind = iota
	bkAuthSec
	bkCustomerExclusive
	bkCustomerShared
)

// AuthSecBoundaryARN is §3.2's policy ARN for a role.
func AuthSecBoundaryARN(partition, account, roleID string) string {
	return "arn:" + partition + ":iam::" + account + ":policy" + AuthSecPolicyPath + AuthSecBoundaryPrefix + roleID
}

// SplitCopyARN is §3.3's split copy: the shared policy's name + "-<RoleId>",
// on the shared policy's path, in the role's account (DECISION D34).
func SplitCopyARN(partition, account, path, sharedName, roleID string) (arn, name string) {
	if path == "" {
		path = "/"
	}
	name = sharedName + "-" + roleID
	return "arn:" + partition + ":iam::" + account + ":policy" + path + name, name
}

func isAuthSecPath(arn string) bool { return strings.Contains(arn, ":policy"+AuthSecPolicyPath) }

// CompileTarget is §3.4 / §8.3 for one target of a right_size_services
// version: the apply plan, and its undo derived from the artifact delta.
//
// DECISION D43: eligibility is a property of the target (eligible: J3 is
// possible; iac_only: a customer boundary), not of a binding's or IaC
// source's state today — those are deploy-time gates (§4.3) and T3.17's
// supported-form matrix. A plan whose OWN delivery cannot happen (direct on
// a customer boundary, A4 "J3 refused") is ineligible with the reason.
//
// DECISION D47: ops are the native change in execution order for every
// delivery; for iac_pr / export AuthSec never runs them — they are the step
// list the customer's tool makes (J1 export), and the classifier's prefix
// rule does not apply to them.
//
// DECISION D54: impact routes, consumers, owners and grants come from the
// bundle's facts (the plan's complete basis, §2.11); the named scan's
// observations are read only for the first-attachment proof, which needs
// every form and every Deny statement, not just the removed namespaces.
func CompileTarget(in TargetInput) (TargetPlans, error) {
	if err := in.Control.validate(); err != nil {
		return TargetPlans{}, err
	}
	if err := ValidateIntent(Intent{Kind: IntentRightSizeServices, RightSize: &in.Intent}); err != nil {
		return TargetPlans{}, compileErr(ErrCodeInvalidIntent, err.Error())
	}
	found := false
	for _, s := range in.Intent.Subjects {
		found = found || (s.RoleID == in.Control.RoleID && s.AccountID == in.Control.AccountID)
	}
	if !found {
		return TargetPlans{}, compileErr(ErrCodeInput, "the control's role is not a subject of the intent")
	}
	if err := in.Evidence.validate(in.Control.RoleID); err != nil {
		return TargetPlans{}, err
	}
	var removeSet []string
	for _, e := range in.Intent.Remove {
		removeSet = append(removeSet, e.Service)
	}
	if strings.Join(sortedUnique(removeSet), ",") != strings.Join(in.Evidence.Bundle.Facts.RemovedServices, ",") {
		return TargetPlans{}, compileErr(ErrCodeEvidenceMismatch, "the bundle was built for another removal set")
	}

	ap := in.Evidence.plan(in.Control.ID, PlanApply, in.Intent.Delivery, in.Live.ReadAt)
	ap.DesiredAttachment = AttachmentPresent
	ap.Impact = impactFor(in.Evidence.Bundle.Facts, in.Intent.Remove, in.Intent.Retain)

	// Incarnation and eligibility by path and tag (§2.2, §3.1).
	if rs := checkIncarnation(in.Live, in.Control.RoleID); rs != nil {
		ap.refuse(rs...)
		if err := goneRolePrecondition(&ap, in.Live, in.Control.RoleID); err != nil {
			return TargetPlans{}, err
		}
		return TargetPlans{Apply: ap}, ap.seal()
	}
	role := in.Live.Role
	ap.refuse(RoleEligibility(*role)...)

	// §3.4 (1): each removal is justified.
	ap.refuse(justifyRemovals(in.Intent.Remove, in.Evidence.Bundle.Facts.Activity, in.DependencyContexts)...)

	pre, err := ApplyPreconditionFor(in.Live)
	if err != nil {
		return TargetPlans{}, err
	}
	pc, err := pre.Canonical()
	if err != nil {
		return TargetPlans{}, err
	}
	ap.Precondition = pc
	if ap.PreconditionHash, err = ApplyPreconditionHash(pre); err != nil {
		return TargetPlans{}, err
	}
	defHash, err := roleDefinitionHash(role)
	if err != nil {
		return TargetPlans{}, err
	}

	// The current boundary.
	part, acct := role.partition(), role.AccountID
	var cur *LivePolicy
	var curHash string
	var curOthers []AttachedEntity
	kind := bkNone
	if role.BoundaryARN != "" {
		if cur, err = in.Live.policy(role.BoundaryARN); err != nil {
			return TargetPlans{}, err
		}
		if cur == nil {
			return TargetPlans{}, compileErr(ErrCodeLiveIncomplete, "the role's boundary returned NoSuchEntity")
		}
		if curHash, err = ap.archiveText(cur.DefaultDocument); err != nil {
			return TargetPlans{}, err
		}
		ap.BeforeDocumentHash = strPtr(curHash)
		curOthers = otherUsers(cur.AttachmentSet, role.RoleID)
		switch {
		case isAuthSecPath(role.BoundaryARN):
			kind = bkAuthSec
		case len(curOthers) == 0:
			kind = bkCustomerExclusive
		default:
			kind = bkCustomerShared
		}
	}

	ctx := applyCtx{in: in, role: role, plan: &ap, part: part, acct: acct, cur: cur, curHash: curHash,
		curOthers: curOthers, defHash: defHash}
	var undo *Plan
	switch kind {
	case bkNone:
		undo, err = ctx.none()
	case bkAuthSec:
		undo, err = ctx.authsec()
	case bkCustomerExclusive:
		undo, err = ctx.customerExclusive()
	case bkCustomerShared:
		undo, err = ctx.customerShared()
	}
	if err != nil {
		return TargetPlans{}, err
	}
	if err := ap.seal(); err != nil {
		return TargetPlans{}, err
	}
	if !ap.Eligible() {
		return TargetPlans{Apply: ap}, nil
	}
	if err := undo.seal(); err != nil {
		return TargetPlans{}, err
	}
	return TargetPlans{Apply: ap, Undo: undo}, nil
}

// goneRolePrecondition gives an ineligible plan for a missing or recreated
// role the precondition of what was read (DECISION D35): the live role's
// state when it exists, otherwise the control's RoleId with no boundary.
func goneRolePrecondition(p *Plan, live LiveRead, roleID string) error {
	var pre ApplyPrecondition
	if live.Role != nil {
		lp, err := ApplyPreconditionFor(live)
		if err != nil {
			return err
		}
		pre = lp
	} else {
		pre = ApplyPrecondition{ArtifactState: ArtifactStateFacts{RoleID: roleID, AttachmentSet: []AttachedEntity{}}}
	}
	c, err := pre.Canonical()
	if err != nil {
		return err
	}
	p.Precondition = c
	p.PreconditionHash, err = ApplyPreconditionHash(pre)
	return err
}

// justifyRemovals is §3.4 (1): every removal has a qualified basis in the
// bundle's activity facts (collected, no attempt, ≥ 30 qualified days, a
// known grant age), appears in the activity report (a collected fact), and
// is not a dependency of the workload context.
func justifyRemovals(remove []RemoveEntry, activity []BundleActivity, ctxs []DependencyContext) []Refusal {
	act := map[string]BundleActivity{}
	for _, a := range activity {
		act[a.Service] = a
	}
	var out []Refusal
	for _, e := range remove {
		a, ok := act[e.Service]
		switch {
		case !ok || a.State != EvidenceCollected:
			out = append(out, Refusal{RefuseNotInActivityReport, e.Service})
		case a.Outcome != QualNoAttempt:
			out = append(out, Refusal{RefuseRemovalNotJustified, e.Service + ": activity outcome " + a.Outcome})
		case a.QualifiedDays < MinQualifiedDays:
			out = append(out, Refusal{RefuseRemovalNotJustified, fmt.Sprintf("%s: %d qualified days", e.Service, a.QualifiedDays)})
		case a.GrantAgeBasis != GrantAgeObservedSinceChange && a.GrantAgeBasis != GrantAgePredatesObservation:
			out = append(out, Refusal{RefuseRemovalNotJustified, e.Service + ": grant age " + a.GrantAgeBasis})
		}
		if d, dep := IsDependency(e.Service, ctxs); dep {
			out = append(out, Refusal{RefuseRemovalIsDependency, e.Service + " (" + d.Catalog + ")"})
		}
	}
	return out
}

type applyCtx struct {
	in        TargetInput
	role      *LiveRole
	plan      *Plan
	part      string
	acct      string
	cur       *LivePolicy
	curHash   string
	curOthers []AttachedEntity
	defHash   string
}

func (c applyCtx) removed() []string {
	var out []string
	for _, e := range c.in.Intent.Remove {
		out = append(out, e.Service)
	}
	return sortedUnique(out)
}

// candidates are the namespaces whose exclusion a diff reports.
func (c applyCtx) candidates(texts ...*string) []string {
	out := c.removed()
	for _, e := range c.in.Intent.Retain {
		out = append(out, e.Service)
	}
	for _, t := range texts {
		out = append(out, notActionNamespaces(t)...)
	}
	return sortedUnique(out)
}

func (c applyCtx) checkSize(canonical []byte) {
	if n := PolicyChars(canonical); n > MaxPolicyChars {
		c.plan.refuse(Refusal{RefuseDocumentTooLarge, fmt.Sprintf("%d characters excluding whitespace (limit %d)", n, MaxPolicyChars)})
	}
}

func (c applyCtx) setDiff(p *Plan, caseName string, before, after *BoundaryRef, beforeText, afterText *string) error {
	p.Diff.Case = caseName
	p.Diff.BoundaryBefore, p.Diff.BoundaryAfter = before, after
	n, a, u, err := ExclusionChanges(beforeText, afterText, c.candidates(beforeText, afterText))
	if err != nil {
		return err
	}
	p.Diff.NewlyExcluded, p.Diff.AlreadyExcluded, p.Diff.NewlyUnexcluded = n, a, u
	return nil
}

// undoBase starts the undo plan: same control, delivery and evidence; its
// precondition is artifact_state after the apply (§8.3).
func (c applyCtx) undoBase(post ArtifactStateFacts) (*Plan, error) {
	u := c.in.Evidence.plan(c.in.Control.ID, PlanUndo, c.in.Intent.Delivery, c.in.Live.ReadAt)
	u.Eligibility = c.plan.Eligibility
	pc, err := CanonicalizeValue(struct {
		ArtifactState ArtifactStateFacts `json:"artifact_state"`
	}{post.Normalized()})
	if err != nil {
		return nil, err
	}
	u.Precondition = pc
	if u.PreconditionHash, err = StatePreconditionHash(post); err != nil {
		return nil, err
	}
	u.BeforeDocumentHash = post.BoundaryDocumentHash
	// DECISION D36: the undo's impact names the same consumers and owners;
	// the services it gives back are Restored, nothing is Removed.
	u.Impact = Impact{Consumers: c.plan.Impact.Consumers, OwnerUserIDs: c.plan.Impact.OwnerUserIDs,
		Removed: []ImpactService{}, Retained: []ImpactService{}, StatementRevisions: []string{}, Routes: []Route{}}
	u.Documents = append([]ArchivedDocument{}, c.plan.Documents...)
	return &u, nil
}

func (c applyCtx) restoredImpact(u *Plan) {
	for _, s := range u.Diff.NewlyUnexcluded {
		u.Impact.Restored = append(u.Impact.Restored, ImpactService{Service: s, Basis: "undo"})
	}
}

func (c applyCtx) roleFacts(withDefinition bool) []Fact {
	fs := []Fact{factRole(c.role.RoleID)}
	if withDefinition {
		fs = append(fs, Fact{Key: FactRoleDefinition, Kind: FactRoleDefinition, Before: c.defHash, After: c.defHash, OnlyBefore: true})
	}
	return fs
}

func (c applyCtx) postState(arn, docHash string, others []AttachedEntity) ArtifactStateFacts {
	set := append([]AttachedEntity{}, others...)
	set = append(set, AttachedEntity{Kind: "role", ID: c.role.RoleID, Name: c.role.Name, Usage: UsageBoundary})
	return ArtifactStateFacts{RoleID: c.role.RoleID, BoundaryARN: strPtr(arn), BoundaryDocumentHash: strPtr(docHash), AttachmentSet: set}.Normalized()
}

// none: no boundary → a new AuthSec boundary (first attachment). §3.3 row 1.
func (c applyCtx) none() (*Plan, error) {
	p := c.plan
	arn := AuthSecBoundaryARN(c.part, c.acct, c.role.RoleID)
	name := AuthSecBoundaryPrefix + c.role.RoleID
	if len(name) > MaxPolicyNameLen {
		p.refuse(Refusal{RefusePolicyNameTooLong, name})
	}
	doc, h, err := ExcludeOnlyDocument(c.removed())
	if err != nil {
		return nil, err
	}
	p.archive(h, doc)
	c.checkSize(doc)
	p.DesiredBoundaryARN, p.DesiredDocumentHash = strPtr(arn), strPtr(h)
	p.FirstAttachment = true
	// DECISION D48: a policy already named AuthSecBoundary-<RoleId> while
	// the role has no boundary (a lost artifact, a role-only recovery that
	// left it with other users) is never adopted silently.
	if existing, ok := c.in.Live.Policies[arn]; ok && existing != nil {
		if existing.Tags[TagManagedBy] == TagManagedByValue && existing.Tags[TagWorkspace] != c.in.Control.WorkspaceRef {
			p.refuse(Refusal{RefuseArtifactOwnedElsewhere, arn})
		} else {
			p.refuse(Refusal{RefusePolicyNameInUse, arn})
		}
	}
	proof := ProveFirstAttachment(c.role.ref(), c.in.Evidence.ScanRunID, c.in.ScanEvidence, c.in.EnabledRegions,
		c.in.AccountServices, c.in.Evidence.gaps())
	p.refuse(proof.Refusals()...)
	p.Unanalysed = proof.Unanalysed
	p.Diff.FirstAttachment = &proof
	p.Ops = []Op{
		{Op: OpCreatePolicy, PolicyARN: arn, PolicyName: name, Path: AuthSecPolicyPath, DocumentHash: h, Tags: c.in.Control.createTags()},
		{Op: OpPutRolePermissionsBoundary, RoleName: c.role.Name, PolicyARN: arn},
	}
	docText := string(doc)
	if err := c.setDiff(p, CaseNoneToAuthSec, nil, &BoundaryRef{arn, h}, nil, &docText); err != nil {
		return nil, err
	}
	owner := c.in.Control.ownerValue()
	p.Facts = append(c.roleFacts(true),
		factBoundary(ValueNone, arn),
		factPolicyDoc(arn, ValueAbsent, h),
		factPolicyOwner(arn, ValueAbsent, owner),
		factPolicyUsers(arn, nil, nil))

	// Undo: absent; the new policy is replaced and deleted.
	u, err := c.undoBase(c.postState(arn, h, nil))
	if err != nil {
		return nil, err
	}
	u.DesiredAttachment = AttachmentAbsent
	u.ReplacedBoundaryARN = strPtr(arn)
	u.ArtifactDisposition = DispositionDelete
	u.Ops = []Op{
		{Op: OpDeleteRolePermissionsBoundary, RoleName: c.role.Name},
		{Op: OpDeletePolicyVersion, PolicyARN: arn, Select: SelectAllNonDefault},
		{Op: OpDeletePolicy, PolicyARN: arn},
	}
	if err := c.setDiff(u, CaseUndoDeleteNew, &BoundaryRef{arn, h}, nil, &docText, nil); err != nil {
		return nil, err
	}
	c.restoredImpact(u)
	u.Facts = append(c.roleFacts(false),
		factBoundary(arn, ValueNone),
		factPolicyDoc(arn, h, ValueAbsent),
		factPolicyOwner(arn, owner, ValueAbsent),
		factPolicyUsers(arn, nil, nil))
	return u, nil
}

// pruneOp is §8.5's "(DeletePolicyVersion oldest non-default, if 5 exist)".
// DECISION D46: a plan cannot name the version id an undo will meet, so
// version deletes carry a selector (oldest_non_default with a version-count
// condition, or all_non_default before DeletePolicy) that the executor
// resolves against its own read, after archiving each document; the
// condition makes a re-sent prune a no-op (§8.5 recognition).
func pruneOp(arn string) Op {
	return Op{Op: OpDeletePolicyVersion, PolicyARN: arn, Select: SelectOldestNonDefault, IfVersionsAtLeast: MaxPolicyVersions}
}

// authsec: AuthSec's own boundary → a new default version. §3.3 row 2.
func (c applyCtx) authsec() (*Plan, error) {
	p := c.plan
	arn := c.role.BoundaryARN
	ctl := c.in.Control
	switch {
	case c.cur.Tags[TagManagedBy] == TagManagedByValue && c.cur.Tags[TagWorkspace] != ctl.WorkspaceRef:
		p.refuse(Refusal{RefuseArtifactOwnedElsewhere, arn})
	case ownerValue(c.cur.Tags) != ctl.ownerValue() || !ctl.owns(arn):
		p.refuse(Refusal{RefuseArtifactOtherControl, arn})
	}
	// DECISION D49: §8.3 says "blocked artifact_consumers_changed"; at
	// compile time that is an ineligible plan with that reason.
	if len(c.curOthers) > 0 {
		p.refuse(Refusal{RefuseConsumersChanged, fmt.Sprintf("%s is used by %d other entities", arn, len(c.curOthers))})
	}
	doc, h, err := ExcludeOnlyDocument(c.removed())
	if err != nil {
		return nil, err
	}
	p.archive(h, doc)
	c.checkSize(doc)
	p.DesiredBoundaryARN, p.DesiredDocumentHash = strPtr(arn), strPtr(h)
	beforeText, afterText := c.cur.DefaultDocument, string(doc)
	if h == c.curHash {
		p.Diff.Notes = append(p.Diff.Notes, NoteAlreadyInPlace)
	} else {
		if c.cur.VersionCount >= MaxPolicyVersions {
			p.Ops = append(p.Ops, pruneOp(arn))
		}
		p.Ops = append(p.Ops,
			Op{Op: OpCreatePolicyVersion, PolicyARN: arn, DocumentHash: h, SetAsDefault: true},
			Op{Op: OpTagPolicy, PolicyARN: arn, Tags: ctl.changeTags()})
	}
	if err := c.setDiff(p, CaseAuthSecVersion, &BoundaryRef{arn, c.curHash}, &BoundaryRef{arn, h}, &beforeText, &afterText); err != nil {
		return nil, err
	}
	owner := ctl.ownerValue()
	p.Facts = append(c.roleFacts(true),
		factBoundary(arn, arn),
		factPolicyDoc(arn, c.curHash, h),
		factPolicyOwner(arn, owner, owner),
		factPolicyUsers(arn, c.curOthers, c.curOthers))

	// Undo: the earlier document as a new default version of the same policy.
	u, err := c.undoBase(c.postState(arn, h, c.curOthers))
	if err != nil {
		return nil, err
	}
	u.DesiredAttachment = AttachmentPresent
	u.DesiredBoundaryARN, u.DesiredDocumentHash = strPtr(arn), strPtr(c.curHash)
	if h != c.curHash {
		post := c.cur.VersionCount + 1
		if c.cur.VersionCount >= MaxPolicyVersions {
			post = MaxPolicyVersions
		}
		if post >= MaxPolicyVersions {
			u.Ops = append(u.Ops, pruneOp(arn))
		}
		u.Ops = append(u.Ops,
			Op{Op: OpCreatePolicyVersion, PolicyARN: arn, DocumentHash: c.curHash, SetAsDefault: true},
			Op{Op: OpTagPolicy, PolicyARN: arn, Tags: ctl.changeTags()})
	} else {
		u.Diff.Notes = append(u.Diff.Notes, NoteAlreadyInPlace)
	}
	if err := c.setDiff(u, CaseUndoEarlierDocument, &BoundaryRef{arn, h}, &BoundaryRef{arn, c.curHash}, &afterText, &beforeText); err != nil {
		return nil, err
	}
	c.restoredImpact(u)
	u.Facts = append(c.roleFacts(false),
		factBoundary(arn, arn),
		factPolicyDoc(arn, h, c.curHash),
		factPolicyOwner(arn, owner, owner),
		factPolicyUsers(arn, c.curOthers, c.curOthers))
	return u, nil
}

// narrow narrows the current customer boundary or records the refusal.
func (c applyCtx) narrow() ([]byte, string, *Narrowing, error) {
	doc, h, n, ref, err := NarrowCustomerBoundary(c.cur.DefaultDocument, c.removed())
	if err != nil {
		return nil, "", nil, err
	}
	if ref != nil {
		c.plan.refuse(*ref)
		return nil, "", nil, nil
	}
	c.plan.archive(h, doc)
	c.checkSize(doc)
	return doc, h, &n, nil
}

// customerExclusive: a customer boundary used only by this role, narrowed in
// place through a PR or export (J3 refused). §3.3 row 3.
func (c applyCtx) customerExclusive() (*Plan, error) {
	p := c.plan
	arn := c.role.BoundaryARN
	p.Eligibility = EligibilityIaCOnly
	if p.Delivery == DeliveryDirect {
		p.refuse(Refusal{RefuseCustomerBoundaryDirect, arn + " is a customer boundary; AuthSec never edits it in AWS (J2/J1 only)"})
	}
	doc, h, n, err := c.narrow()
	if err != nil {
		return nil, err
	}
	if n == nil { // refused
		p.DesiredBoundaryARN = strPtr(arn)
		p.Facts = c.roleFacts(true)
		return nil, nil
	}
	p.Diff.Narrowing = n
	p.DesiredBoundaryARN, p.DesiredDocumentHash = strPtr(arn), strPtr(h)
	if !n.Changed {
		p.Diff.Notes = append(p.Diff.Notes, NoteNothingToNarrow, NoteAlreadyInPlace)
	} else {
		p.Ops = []Op{{Op: OpCreatePolicyVersion, PolicyARN: arn, DocumentHash: h, SetAsDefault: true}}
	}
	beforeText, afterText := c.cur.DefaultDocument, string(doc)
	if err := c.setDiff(p, CaseCustomerInPlace, &BoundaryRef{arn, c.curHash}, &BoundaryRef{arn, h}, &beforeText, &afterText); err != nil {
		return nil, err
	}
	p.Facts = append(c.roleFacts(true),
		factBoundary(arn, arn),
		factPolicyDoc(arn, c.curHash, h),
		factPolicyUsers(arn, nil, nil))

	u, err := c.undoBase(c.postState(arn, h, nil))
	if err != nil {
		return nil, err
	}
	u.DesiredAttachment = AttachmentPresent
	u.DesiredBoundaryARN, u.DesiredDocumentHash = strPtr(arn), strPtr(c.curHash)
	if n.Changed {
		u.Ops = []Op{{Op: OpCreatePolicyVersion, PolicyARN: arn, DocumentHash: c.curHash, SetAsDefault: true}}
	} else {
		u.Diff.Notes = append(u.Diff.Notes, NoteAlreadyInPlace)
	}
	if err := c.setDiff(u, CaseUndoCustomerInPlace, &BoundaryRef{arn, h}, &BoundaryRef{arn, c.curHash}, &afterText, &beforeText); err != nil {
		return nil, err
	}
	c.restoredImpact(u)
	u.Facts = append(c.roleFacts(false),
		factBoundary(arn, arn),
		factPolicyDoc(arn, h, c.curHash),
		factPolicyUsers(arn, nil, nil))
	return u, nil
}

// customerShared: a customer boundary used by another entity. The shared
// document is never changed; the role gets a split copy through a PR or
// export (J3 refused). §3.3 row 4.
func (c applyCtx) customerShared() (*Plan, error) {
	p := c.plan
	shared := c.role.BoundaryARN
	p.Eligibility = EligibilityIaCOnly
	if p.Delivery == DeliveryDirect {
		p.refuse(Refusal{RefuseCustomerBoundaryDirect, shared + " is a shared customer boundary; AuthSec proposes a split copy only through J2/J1"})
	}
	copyARN, copyName := SplitCopyARN(c.part, c.acct, c.cur.Path, c.cur.Name, c.role.RoleID)
	if len(copyName) > MaxPolicyNameLen {
		p.refuse(Refusal{RefusePolicyNameTooLong, copyName})
	}
	doc, h, n, err := c.narrow()
	if err != nil {
		return nil, err
	}
	if n == nil {
		p.DesiredBoundaryARN = strPtr(copyARN)
		p.Facts = c.roleFacts(true)
		return nil, nil
	}
	p.Diff.Narrowing = n
	beforeText, afterText := c.cur.DefaultDocument, string(doc)
	if !n.Changed {
		// Nothing to narrow: the shared boundary already excludes the
		// services; no copy is made (DECISION D37).
		p.DesiredBoundaryARN, p.DesiredDocumentHash = strPtr(shared), strPtr(c.curHash)
		p.Diff.Notes = append(p.Diff.Notes, NoteNothingToNarrow, NoteAlreadyInPlace)
		if err := c.setDiff(p, CaseCustomerSplit, &BoundaryRef{shared, c.curHash}, &BoundaryRef{shared, c.curHash}, &beforeText, &beforeText); err != nil {
			return nil, err
		}
		p.Facts = append(c.roleFacts(true), factBoundary(shared, shared), factPolicyDoc(shared, c.curHash, c.curHash),
			factPolicyUsers(shared, c.curOthers, c.curOthers))
		u, err := c.undoBase(c.postState(shared, c.curHash, c.curOthers))
		if err != nil {
			return nil, err
		}
		u.DesiredAttachment = AttachmentPresent
		u.DesiredBoundaryARN, u.DesiredDocumentHash = strPtr(shared), strPtr(c.curHash)
		u.Diff.Notes = append(u.Diff.Notes, NoteAlreadyInPlace)
		if err := c.setDiff(u, CaseUndoSplit, &BoundaryRef{shared, c.curHash}, &BoundaryRef{shared, c.curHash}, &beforeText, &beforeText); err != nil {
			return nil, err
		}
		u.Facts = append(c.roleFacts(false), factBoundary(shared, shared), factPolicyDoc(shared, c.curHash, c.curHash),
			factPolicyUsers(shared, c.curOthers, c.curOthers))
		return u, nil
	}
	if existing, ok := c.in.Live.Policies[copyARN]; ok && existing != nil {
		p.refuse(Refusal{RefusePolicyNameInUse, copyARN})
	}
	p.DesiredBoundaryARN, p.DesiredDocumentHash = strPtr(copyARN), strPtr(h)
	p.ReplacedBoundaryARN = strPtr(shared) // named; disposition keep: untouched
	p.Ops = []Op{
		{Op: OpCreatePolicy, PolicyARN: copyARN, PolicyName: copyName, Path: c.cur.Path, DocumentHash: h},
		{Op: OpPutRolePermissionsBoundary, RoleName: c.role.Name, PolicyARN: copyARN},
	}
	if err := c.setDiff(p, CaseCustomerSplit, &BoundaryRef{shared, c.curHash}, &BoundaryRef{copyARN, h}, &beforeText, &afterText); err != nil {
		return nil, err
	}
	p.Facts = append(c.roleFacts(true),
		factBoundary(shared, copyARN),
		factPolicyDoc(copyARN, ValueAbsent, h),
		factPolicyUsers(copyARN, nil, nil),
		factPolicyDoc(shared, c.curHash, c.curHash),
		factPolicyUsers(shared, c.curOthers, c.curOthers))

	// Undo: back to the shared boundary; the copy is named and deleted.
	u, err := c.undoBase(c.postState(copyARN, h, nil))
	if err != nil {
		return nil, err
	}
	u.DesiredAttachment = AttachmentPresent
	u.DesiredBoundaryARN, u.DesiredDocumentHash = strPtr(shared), strPtr(c.curHash)
	u.ReplacedBoundaryARN = strPtr(copyARN)
	u.ArtifactDisposition = DispositionDelete
	u.Ops = []Op{
		{Op: OpPutRolePermissionsBoundary, RoleName: c.role.Name, PolicyARN: shared},
		{Op: OpDeletePolicyVersion, PolicyARN: copyARN, Select: SelectAllNonDefault},
		{Op: OpDeletePolicy, PolicyARN: copyARN},
	}
	if err := c.setDiff(u, CaseUndoSplit, &BoundaryRef{copyARN, h}, &BoundaryRef{shared, c.curHash}, &afterText, &beforeText); err != nil {
		return nil, err
	}
	c.restoredImpact(u)
	u.Facts = append(c.roleFacts(false),
		factBoundary(copyARN, shared),
		factPolicyDoc(copyARN, h, ValueAbsent),
		factPolicyUsers(copyARN, nil, nil),
		factPolicyDoc(shared, c.curHash, c.curHash),
		factPolicyUsers(shared, c.curOthers, c.curOthers))
	return u, nil
}

/* ------------------------------------------------------------------------- */
/*                          Role-only recovery (§8.9)                         */
/* ------------------------------------------------------------------------- */

// RecoveryInput compiles a role-only recovery plan for an undo that is
// blocked because the artifact gained other users (§8.9).
type RecoveryInput struct {
	Control ControlRef
	// Undo is the blocked undo plan (it names the before-state and the
	// policy the apply installed).
	Undo Plan
	// UndoneDeploymentID names the deployment being undone; its first 8 hex
	// characters suffix the -u policy (DECISION D38).
	UndoneDeploymentID string
	// EarlierDocument is the text of the undo's desired document (from
	// iga_gov_document) when the before-state was an earlier AuthSec
	// document.
	EarlierDocument string
	Live            LiveRead
	Evidence        EvidenceRef
}

// RecoveryPolicyARN is §8.9's AuthSecBoundary-<RoleId>-u<deployment 8hex>.
func RecoveryPolicyARN(partition, account, roleID, deploymentID string) (arn, name string) {
	hex := strings.ReplaceAll(strings.ToLower(deploymentID), "-", "")
	if len(hex) > 8 {
		hex = hex[:8]
	}
	name = AuthSecBoundaryPrefix + roleID + "-u" + hex
	return "arn:" + partition + ":iam::" + account + ":policy" + AuthSecPolicyPath + name, name
}

// CompileRoleOnlyRecovery is §8.9's role-only recovery plan (kind undo,
// disposition retain_shared): it restores this role's before-state without
// touching the shared artifact or its other users.
func CompileRoleOnlyRecovery(in RecoveryInput) (Plan, error) {
	if err := in.Control.validate(); err != nil {
		return Plan{}, err
	}
	if in.Undo.Kind != PlanUndo || in.Undo.ControlID != in.Control.ID {
		return Plan{}, compileErr(ErrCodeInput, "role-only recovery derives from this control's undo plan")
	}
	if err := in.Evidence.validate(in.Control.RoleID); err != nil {
		return Plan{}, err
	}
	p := in.Evidence.plan(in.Control.ID, PlanUndo, in.Undo.Delivery, in.Live.ReadAt)
	p.Eligibility = in.Undo.Eligibility
	p.ArtifactDisposition = DispositionRetainShared
	p.Impact = in.Undo.Impact
	p.Impact.Restored = append([]ImpactService{}, in.Undo.Impact.Restored...)
	var undoState ArtifactStateFacts
	if err := json.Unmarshal(in.Undo.Precondition, &struct {
		ArtifactState *ArtifactStateFacts `json:"artifact_state"`
	}{&undoState}); err != nil {
		return Plan{}, compileErr(ErrCodeInput, "the undo plan's precondition is not an artifact_state")
	}
	if rs := checkIncarnation(in.Live, in.Control.RoleID); rs != nil {
		p.refuse(rs...)
		p.DesiredAttachment = in.Undo.DesiredAttachment
		p.ReplacedBoundaryARN = undoState.BoundaryARN
		if p.ReplacedBoundaryARN == nil {
			p.ReplacedBoundaryARN = strPtr("unknown")
		}
		if err := statePrecondition(&p, ArtifactStateFacts{RoleID: in.Control.RoleID, AttachmentSet: []AttachedEntity{}}); err != nil {
			return Plan{}, err
		}
		return p, p.seal()
	}
	role := in.Live.Role
	st, err := ArtifactState(in.Live)
	if err != nil {
		return Plan{}, err
	}
	if err := statePrecondition(&p, st); err != nil {
		return Plan{}, err
	}
	p.BeforeDocumentHash = st.BoundaryDocumentHash
	installed := derefOr(undoState.BoundaryARN, "")
	p.ReplacedBoundaryARN = strPtr(installed)
	if installed == "" || derefOr(st.BoundaryARN, "") != installed ||
		derefOr(st.BoundaryDocumentHash, "") != derefOr(undoState.BoundaryDocumentHash, "") {
		p.refuse(Refusal{RefuseChangedOutsideAuthSec, fmt.Sprintf("boundary %s / %s is not what the apply left (%s / %s)",
			derefOr(st.BoundaryARN, "none"), derefOr(st.BoundaryDocumentHash, "none"), installed, derefOr(undoState.BoundaryDocumentHash, "none"))})
	}
	others := otherUsers(st.AttachmentSet, role.RoleID)
	if len(others) == 0 {
		p.refuse(Refusal{RefuseRoleOnlyNotNeeded, installed + " has no other users; run the undo itself"})
	}
	docHash := derefOr(undoState.BoundaryDocumentHash, "")
	owner := in.Control.ownerValue()
	part := role.partition()
	base := []Fact{factRole(role.RoleID)}
	switch {
	case in.Undo.DesiredAttachment == AttachmentAbsent:
		p.DesiredAttachment = AttachmentAbsent
		p.Ops = []Op{{Op: OpDeleteRolePermissionsBoundary, RoleName: role.Name}}
		p.Diff.Case = CaseRecoverDetach
		p.Diff.BoundaryBefore = &BoundaryRef{installed, docHash}
		p.Facts = append(base, factBoundary(installed, ValueNone), factPolicyDoc(installed, docHash, docHash),
			factPolicyOwner(installed, owner, owner), factPolicyUsers(installed, others, others))
	case in.Undo.ReplacedBoundaryARN == nil && isAuthSecPath(derefOr(in.Undo.DesiredBoundaryARN, "")):
		// Earlier AuthSec document under a new -u policy.
		if in.EarlierDocument == "" {
			return Plan{}, compileErr(ErrCodeInput, "the earlier document's text is needed for a -u policy")
		}
		eh, err := p.archiveText(in.EarlierDocument)
		if err != nil {
			return Plan{}, err
		}
		if eh != derefOr(in.Undo.DesiredDocumentHash, "") {
			return Plan{}, compileErr(ErrCodeInput, "the earlier document does not hash to the undo's desired document")
		}
		uarn, uname := RecoveryPolicyARN(part, role.AccountID, role.RoleID, in.UndoneDeploymentID)
		if existing, ok := in.Live.Policies[uarn]; ok && existing != nil {
			p.refuse(Refusal{RefusePolicyNameInUse, uarn})
		}
		p.DesiredAttachment = AttachmentPresent
		p.DesiredBoundaryARN, p.DesiredDocumentHash = strPtr(uarn), strPtr(eh)
		p.Ops = []Op{
			{Op: OpCreatePolicy, PolicyARN: uarn, PolicyName: uname, Path: AuthSecPolicyPath, DocumentHash: eh, Tags: in.Control.createTags()},
			{Op: OpPutRolePermissionsBoundary, RoleName: role.Name, PolicyARN: uarn},
		}
		p.Diff.Case = CaseRecoverNewPolicy
		p.Diff.BoundaryBefore, p.Diff.BoundaryAfter = &BoundaryRef{installed, docHash}, &BoundaryRef{uarn, eh}
		p.Facts = append(base, factBoundary(installed, uarn),
			factPolicyDoc(uarn, ValueAbsent, eh), factPolicyOwner(uarn, ValueAbsent, owner), factPolicyUsers(uarn, nil, nil),
			factPolicyDoc(installed, docHash, docHash), factPolicyOwner(installed, owner, owner), factPolicyUsers(installed, others, others))
	case in.Undo.ReplacedBoundaryARN != nil && in.Undo.DesiredBoundaryARN != nil:
		// Split copy gained users: point the role back at the shared
		// boundary as it is now; leave the copy with its users.
		shared := *in.Undo.DesiredBoundaryARN
		sp, err := in.Live.policy(shared)
		if err != nil {
			return Plan{}, err
		}
		if sp == nil {
			p.refuse(Refusal{RefuseBaselineMissing, shared})
			p.DesiredAttachment = AttachmentPresent
			p.DesiredBoundaryARN = strPtr(shared)
			break
		}
		sh, err := p.archiveText(sp.DefaultDocument)
		if err != nil {
			return Plan{}, err
		}
		sOthers := otherUsers(sp.AttachmentSet, role.RoleID)
		p.DesiredAttachment = AttachmentPresent
		p.DesiredBoundaryARN, p.DesiredDocumentHash = strPtr(shared), strPtr(sh)
		p.Ops = []Op{{Op: OpPutRolePermissionsBoundary, RoleName: role.Name, PolicyARN: shared}}
		p.Diff.Case = CaseRecoverSplit
		p.Diff.BoundaryBefore, p.Diff.BoundaryAfter = &BoundaryRef{installed, docHash}, &BoundaryRef{shared, sh}
		p.Diff.Notes = append(p.Diff.Notes, NoteCopyRetained)
		p.Facts = append(base, factBoundary(installed, shared),
			factPolicyDoc(installed, docHash, docHash), factPolicyUsers(installed, others, others),
			factPolicyDoc(shared, sh, sh), factPolicyUsers(shared, sOthers, sOthers))
	default:
		// A customer boundary narrowed in place: restoring its document
		// would change the new users too (DECISION D38).
		p.refuse(Refusal{RefuseRoleOnlyUnavailable, "the boundary is a customer document narrowed in place; restore it through the customer's own change"})
		p.DesiredAttachment = in.Undo.DesiredAttachment
	}
	if p.Diff.Case != CaseRecoverSplit && p.Diff.Case != "" {
		p.Diff.Notes = append(p.Diff.Notes, NotePolicyRetained)
	}
	if p.Delivery == DeliveryDirect {
		for _, op := range p.Ops {
			if op.PolicyARN != "" && !isAuthSecPath(op.PolicyARN) {
				p.refuse(Refusal{RefuseDirectNeedsAuthSecTarget, op.PolicyARN})
			}
		}
	}
	return p, p.seal()
}

func statePrecondition(p *Plan, st ArtifactStateFacts) error {
	pc, err := CanonicalizeValue(struct {
		ArtifactState ArtifactStateFacts `json:"artifact_state"`
	}{st.Normalized()})
	if err != nil {
		return err
	}
	p.Precondition = pc
	p.PreconditionHash, err = StatePreconditionHash(st)
	return err
}

/* ------------------------------------------------------------------------- */
/*                          Remove AuthSec control (§8.10)                    */
/* ------------------------------------------------------------------------- */

// Baseline is iga_gov_control's baseline: the role's boundary before
// AuthSec's first change (nil ARN = no boundary).
type Baseline struct {
	BoundaryARN  *string
	DocumentHash *string
	// Document is the baseline document's text (iga_gov_document) when
	// there was a boundary.
	Document string
}

// RemoveControlInput compiles one remove_control plan per control (§8.10).
type RemoveControlInput struct {
	Control  ControlRef
	Baseline Baseline
	// LastDeployed is the boundary AuthSec last deployed on the role (the
	// latest verified deployment's post-state): restoring the baseline is
	// refused when the live boundary differs from it.
	LastDeployed BoundaryRef
	Delivery     string
	Live         LiveRead
	Evidence     EvidenceRef
	// ExcludedServices are the services AuthSec has excluded on the role
	// (posture rows): candidates for the access that returns.
	ExcludedServices []string
}

// CompileRemoveControl is §8.10: restore the control's baseline, never
// writing a document other entities use.
func CompileRemoveControl(in RemoveControlInput) (Plan, error) {
	if err := in.Control.validate(); err != nil {
		return Plan{}, err
	}
	switch in.Delivery {
	case DeliveryDirect, DeliveryIaCPR, DeliveryExport:
	default:
		return Plan{}, compileErr(ErrCodeInput, "delivery must be direct, iac_pr or export")
	}
	if err := in.Evidence.validate(in.Control.RoleID); err != nil {
		return Plan{}, err
	}
	if (in.Baseline.BoundaryARN == nil) != (in.Baseline.DocumentHash == nil) {
		return Plan{}, compileErr(ErrCodeInput, "baseline ARN and document hash are set together")
	}
	p := in.Evidence.plan(in.Control.ID, PlanRemoveControl, in.Delivery, in.Live.ReadAt)
	p.Impact = Impact{Consumers: in.Evidence.Bundle.Facts.Consumers, OwnerUserIDs: in.Evidence.Bundle.Facts.Owners,
		Removed: []ImpactService{}, Retained: []ImpactService{}, StatementRevisions: []string{}, Routes: []Route{}}
	if rs := checkIncarnation(in.Live, in.Control.RoleID); rs != nil {
		p.refuse(rs...)
		p.DesiredAttachment = AttachmentAbsent
		p.ArtifactDisposition = DispositionDelete
		p.ReplacedBoundaryARN = strPtr(in.LastDeployed.ARN)
		if err := statePrecondition(&p, ArtifactStateFacts{RoleID: in.Control.RoleID, AttachmentSet: []AttachedEntity{}}); err != nil {
			return Plan{}, err
		}
		return p, p.seal()
	}
	role := in.Live.Role
	st, err := ArtifactState(in.Live)
	if err != nil {
		return Plan{}, err
	}
	// DECISION D45: no boundary means no artifact in AWS (the control is
	// planned, e.g. after an undo of its first deployment); an absent plan
	// would have nothing to name as replaced (050 disposition CHECK), so
	// there is no plan and the control is retired directly.
	if st.BoundaryARN == nil {
		return Plan{}, compileErr(ErrCodeNoArtifact, "the role has no boundary; the control can be retired without a plan")
	}
	if err := statePrecondition(&p, st); err != nil {
		return Plan{}, err
	}
	cur := *st.BoundaryARN
	curHash := *st.BoundaryDocumentHash
	p.BeforeDocumentHash = st.BoundaryDocumentHash
	curPol, _ := in.Live.policy(cur)
	if _, err := p.archiveText(curPol.DefaultDocument); err != nil {
		return Plan{}, err
	}
	if cur != in.LastDeployed.ARN || curHash != in.LastDeployed.DocumentHash {
		p.refuse(Refusal{RefuseChangedOutsideAuthSec, fmt.Sprintf("the role's boundary is %s / %s, not what AuthSec last deployed (%s / %s)",
			cur, curHash, in.LastDeployed.ARN, in.LastDeployed.DocumentHash)})
	}
	others := otherUsers(st.AttachmentSet, role.RoleID)
	owner := in.Control.ownerValue()
	curOwnerFacts := func(before, after string) []Fact {
		if !isAuthSecPath(cur) {
			return nil
		}
		return []Fact{factPolicyOwner(cur, before, after)}
	}
	base := []Fact{factRole(role.RoleID)}
	var afterText *string
	curText := curPol.DefaultDocument
	switch {
	case in.Baseline.BoundaryARN == nil:
		p.DesiredAttachment = AttachmentAbsent
		p.ReplacedBoundaryARN = strPtr(cur)
		p.Diff.Case = CaseRemoveDetach
		if len(others) == 0 {
			p.ArtifactDisposition = DispositionDelete
			p.Ops = []Op{
				{Op: OpDeleteRolePermissionsBoundary, RoleName: role.Name},
				{Op: OpDeletePolicyVersion, PolicyARN: cur, Select: SelectAllNonDefault},
				{Op: OpDeletePolicy, PolicyARN: cur},
			}
			p.Facts = append(base, factBoundary(cur, ValueNone), factPolicyDoc(cur, curHash, ValueAbsent), factPolicyUsers(cur, nil, nil))
			p.Facts = append(p.Facts, curOwnerFacts(owner, ValueAbsent)...)
		} else {
			p.ArtifactDisposition = DispositionRetainShared
			p.Ops = []Op{{Op: OpDeleteRolePermissionsBoundary, RoleName: role.Name}}
			p.Diff.Notes = append(p.Diff.Notes, NotePolicyRetained)
			p.Facts = append(base, factBoundary(cur, ValueNone), factPolicyDoc(cur, curHash, curHash), factPolicyUsers(cur, others, others))
			p.Facts = append(p.Facts, curOwnerFacts(owner, owner)...)
		}
	case *in.Baseline.BoundaryARN == cur:
		// In place: restore the baseline document, only while this role is
		// its only user.
		bh, err := p.archiveText(in.Baseline.Document)
		if err != nil {
			return Plan{}, err
		}
		if bh != *in.Baseline.DocumentHash {
			return Plan{}, compileErr(ErrCodeInput, "the baseline document does not hash to the recorded baseline")
		}
		if len(others) > 0 {
			p.refuse(Refusal{RefuseConsumersChanged, fmt.Sprintf("%s is used by %d other entities; restoring its document would change them", cur, len(others))})
		}
		p.DesiredAttachment = AttachmentPresent
		p.DesiredBoundaryARN, p.DesiredDocumentHash = strPtr(cur), strPtr(bh)
		p.Diff.Case = CaseRemoveInPlace
		if bh == curHash {
			p.Diff.Notes = append(p.Diff.Notes, NoteAlreadyInPlace)
		} else {
			if isAuthSecPath(cur) {
				pol := curPol
				if pol.VersionCount >= MaxPolicyVersions {
					p.Ops = append(p.Ops, pruneOp(cur))
				}
				p.Ops = append(p.Ops, Op{Op: OpCreatePolicyVersion, PolicyARN: cur, DocumentHash: bh, SetAsDefault: true},
					Op{Op: OpTagPolicy, PolicyARN: cur, Tags: in.Control.changeTags()})
			} else {
				p.Ops = []Op{{Op: OpCreatePolicyVersion, PolicyARN: cur, DocumentHash: bh, SetAsDefault: true}}
			}
		}
		afterText = &in.Baseline.Document
		p.Facts = append(base, factBoundary(cur, cur), factPolicyDoc(cur, curHash, bh), factPolicyUsers(cur, others, others))
		p.Facts = append(p.Facts, curOwnerFacts(owner, owner)...)
	default:
		// Re-point the role at the baseline boundary as it is now; delete
		// the replaced policy only if this role is its only user.
		b := *in.Baseline.BoundaryARN
		bp, err := in.Live.policy(b)
		if err != nil {
			return Plan{}, err
		}
		p.DesiredAttachment = AttachmentPresent
		p.DesiredBoundaryARN = strPtr(b)
		p.ReplacedBoundaryARN = strPtr(cur)
		p.Diff.Case = CaseRemoveRepoint
		if bp == nil {
			p.refuse(Refusal{RefuseBaselineMissing, b})
			break
		}
		bh, err := p.archiveText(bp.DefaultDocument)
		if err != nil {
			return Plan{}, err
		}
		if bh != *in.Baseline.DocumentHash {
			p.Diff.Notes = append(p.Diff.Notes, NoteBaselineDocChanged)
		}
		bOthers := otherUsers(bp.AttachmentSet, role.RoleID)
		p.DesiredDocumentHash = strPtr(bh)
		p.Ops = []Op{{Op: OpPutRolePermissionsBoundary, RoleName: role.Name, PolicyARN: b}}
		p.Facts = append(base, factBoundary(cur, b), factPolicyDoc(b, bh, bh), factPolicyUsers(b, bOthers, bOthers))
		if len(others) == 0 {
			p.ArtifactDisposition = DispositionDelete
			p.Ops = append(p.Ops, Op{Op: OpDeletePolicyVersion, PolicyARN: cur, Select: SelectAllNonDefault},
				Op{Op: OpDeletePolicy, PolicyARN: cur})
			p.Facts = append(p.Facts, factPolicyDoc(cur, curHash, ValueAbsent), factPolicyUsers(cur, nil, nil))
			p.Facts = append(p.Facts, curOwnerFacts(owner, ValueAbsent)...)
		} else {
			p.ArtifactDisposition = DispositionRetainShared
			p.Diff.Notes = append(p.Diff.Notes, NoteCopyRetained)
			p.Facts = append(p.Facts, factPolicyDoc(cur, curHash, curHash), factPolicyUsers(cur, others, others))
			p.Facts = append(p.Facts, curOwnerFacts(owner, owner)...)
		}
		bt := bp.DefaultDocument
		afterText = &bt
	}
	p.Diff.BoundaryBefore = &BoundaryRef{cur, curHash}
	if p.DesiredBoundaryARN != nil && p.DesiredDocumentHash != nil {
		p.Diff.BoundaryAfter = &BoundaryRef{*p.DesiredBoundaryARN, *p.DesiredDocumentHash}
	}
	cands := append(append([]string{}, in.ExcludedServices...), notActionNamespaces(&curText)...)
	n, a, u, err := ExclusionChanges(&curText, afterText, cands)
	if err != nil {
		return Plan{}, err
	}
	p.Diff.NewlyExcluded, p.Diff.AlreadyExcluded, p.Diff.NewlyUnexcluded = n, a, u
	for _, s := range u {
		p.Impact.Restored = append(p.Impact.Restored, ImpactService{Service: s, Basis: "remove_control"})
	}
	// Direct delivery writes only AuthSec boundaries (§3.6): every policy an
	// op writes or attaches must be under /authsec/ (DECISION D53: otherwise
	// the plan is ineligible for direct and iac_only for PR/export).
	if p.Delivery == DeliveryDirect {
		for _, op := range p.Ops {
			if op.PolicyARN != "" && !isAuthSecPath(op.PolicyARN) {
				p.refuse(Refusal{RefuseDirectNeedsAuthSecTarget, op.PolicyARN})
				break
			}
		}
	}
	if p.Eligibility == EligibilityEligible && (!isAuthSecPath(cur) || (p.DesiredBoundaryARN != nil && !isAuthSecPath(*p.DesiredBoundaryARN))) {
		p.Eligibility = EligibilityIaCOnly
	}
	return p, p.seal()
}

/* ------------------------------------------------------------------------- */
/*                         One control per role (§2.3)                        */
/* ------------------------------------------------------------------------- */

// LiveControl is an existing iga_gov_control of the workspace.
type LiveControl struct {
	ID        string
	PolicyID  string
	AccountID string
	RoleID    string
	State     string
}

// ErrRoleControlledByPolicy is §2.3's 409 role_controlled_by_policy.
type ErrRoleControlledByPolicy struct {
	ControlID string
	PolicyID  string
}

func (e *ErrRoleControlledByPolicy) Error() string {
	return "role_controlled_by_policy: the role is controlled by policy " + e.PolicyID
}

// ResolveControl is §2.3 for a version's subject: the live control of the
// role if the same policy owns it, nil when a new planned control must be
// created, or ErrRoleControlledByPolicy (409, with the policy to edit) when
// another policy controls the role (A20).
func ResolveControl(controls []LiveControl, accountID, roleID, policyID string) (*LiveControl, error) {
	for i := range controls {
		c := controls[i]
		if c.State == "removed" || c.AccountID != accountID || c.RoleID != roleID {
			continue
		}
		if c.PolicyID != policyID {
			return nil, &ErrRoleControlledByPolicy{ControlID: c.ID, PolicyID: c.PolicyID}
		}
		return &c, nil
	}
	return nil, nil
}
