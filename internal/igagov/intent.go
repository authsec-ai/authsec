package igagov

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Intent kinds (§2.7, §11).
const (
	IntentRightSizeServices = "right_size_services"
	IntentRemoveControl     = "remove_control"
	IntentDedicatedIdentity = "dedicated_identity"
)

// Retain and remove bases (§2.7).
const (
	RetainObserved   = "observed"
	RetainDependency = "dependency"
	RetainOwner      = "owner"
	RetainUnreviewed = "unreviewed"

	RemoveNoAttempt = "no_attempt"
)

// Deliveries (050 iga_gov_plan.delivery).
const (
	DeliveryDirect = "direct"
	DeliveryIaCPR  = "iac_pr"
	DeliveryExport = "export"
)

// Binding kinds of a dedicated-identity subject (§11).
const (
	BindingECSTaskRole        = "ecs_task_role"
	BindingLambdaRole         = "lambda_role"
	BindingEC2InstanceProfile = "ec2_instance_profile"
)

// Intent bounds that mirror 055 iga_gov_settings CHECKs (DECISION D23: the
// requirements table says observation 7–90 days, default 30; 055 says
// 1–90, default 7; the DDL wins).
const (
	MinObservationDays = 1
	MaxObservationDays = 90
	MinCanaryHours     = 1
	MaxCanaryHours     = 336
)

// Subject is a role an intent targets, by immutable RoleId (§2.2).
type Subject struct {
	IdentityAccountID string `json:"identity_account_id"`
	RoleID            string `json:"role_id"`
	AccountID         string `json:"account_id"`
}

// RetainEntry is one retained service with its basis (§2.7, P-12).
//
// Subjects scopes an OWNER retain (basis owner) to the subjects -- by
// identity_account_id -- its owner owns (§2.9, §7.4): the service is kept
// for those roles only and still removed for every other subject of the
// policy. Empty (the field absent, so existing intents and their hashes are
// unchanged) means the entry applies to every subject. See ForSubject.
type RetainEntry struct {
	Service     string   `json:"service"`
	Basis       string   `json:"basis"`
	LastAttempt string   `json:"last_attempt,omitempty"`
	Catalog     string   `json:"catalog,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	ReviewBy    string   `json:"review_by,omitempty"`
	Subjects    []string `json:"subjects,omitempty"`
}

// AppliesTo reports whether the entry retains its service for the subject
// identityAccountID (an unscoped entry applies to every subject).
func (e RetainEntry) AppliesTo(identityAccountID string) bool {
	if len(e.Subjects) == 0 {
		return true
	}
	for _, s := range e.Subjects {
		if s == identityAccountID {
			return true
		}
	}
	return false
}

// ForSubject is the intent as it applies to ONE subject (identity account
// id): services an owner-scoped retain keeps for this subject leave Remove
// and join Retain (unscoped, as if retained for the whole policy); scoped
// retains of other subjects are dropped. Every per-target consumer --
// compilation, the canary health check, observation -- reads this, never the
// policy-wide lists, so one owner's retain never changes another owner's
// role (fix/p3-tidy).
func (r RightSizeIntent) ForSubject(identityAccountID string) RightSizeIntent {
	out := r
	kept := map[string]bool{}
	out.Retain = []RetainEntry{}
	for _, e := range r.Retain {
		if !e.AppliesTo(identityAccountID) {
			continue
		}
		if len(e.Subjects) > 0 {
			kept[e.Service] = true
			e.Subjects = nil
		}
		out.Retain = append(out.Retain, e)
	}
	sort.SliceStable(out.Retain, func(i, j int) bool { return out.Retain[i].Service < out.Retain[j].Service })
	out.Remove = []RemoveEntry{}
	for _, e := range r.Remove {
		if !kept[e.Service] {
			out.Remove = append(out.Remove, e)
		}
	}
	return out
}

// IntentRoute is a resource-policy route named on a removal (§2.7, §3.4).
type IntentRoute struct {
	Resource  string `json:"resource,omitempty"`
	Principal string `json:"principal,omitempty"`
	Form      string `json:"form,omitempty"`
}

// RemoveEntry is one removed service with its qualified basis (§2.6, §2.7).
type RemoveEntry struct {
	Service       string        `json:"service"`
	Basis         string        `json:"basis"`
	QualifiedDays int           `json:"qualified_days"`
	GrantAgeBasis string        `json:"grant_age_basis"`
	RouteUsage    string        `json:"route_usage,omitempty"`
	RouteState    string        `json:"route_state,omitempty"`
	Routes        []IntentRoute `json:"routes,omitempty"`
}

// RolloutIntent is the rollout section of a right-size intent.
type RolloutIntent struct {
	CanaryTarget string `json:"canary_target,omitempty"`
	CanaryHours  int    `json:"canary_hours,omitempty"`
}

// RightSizeIntent is the `right_size_services` intent (§2.7).
type RightSizeIntent struct {
	Kind            string         `json:"kind"`
	Subjects        []Subject      `json:"subjects"`
	Retain          []RetainEntry  `json:"retain"`
	Remove          []RemoveEntry  `json:"remove"`
	ObservationDays int            `json:"observation_days"`
	Rollout         *RolloutIntent `json:"rollout,omitempty"`
	Delivery        string         `json:"delivery"`
	FindingIDs      []string       `json:"finding_ids,omitempty"`
	EvidenceRev     int64          `json:"evidence_rev"`
}

// RemoveControlIntent is the `remove_control` intent (§2.7, §8.10).
type RemoveControlIntent struct {
	Kind       string   `json:"kind"`
	ControlIDs []string `json:"control_ids"`
	Reason     string   `json:"reason"`
}

// DedicatedWorkload is the subject a dedicated-identity intent moves (§11).
type DedicatedWorkload struct {
	WorkloadID  string `json:"workload_id"`
	BindingKind string `json:"binding_kind"`
	BindingRef  string `json:"binding_ref"`
}

// InlinePolicyRef is an inline policy copied by hash (§11).
type InlinePolicyRef struct {
	Name         string `json:"name"`
	DocumentHash string `json:"document_hash"`
}

// NewRole is the role a dedicated-identity intent creates (§11).
type NewRole struct {
	Name              string            `json:"name"`
	Path              string            `json:"path"`
	TrustPolicyHash   string            `json:"trust_policy_hash"`
	ManagedPolicyARNs []string          `json:"managed_policy_arns"`
	InlinePolicies    []InlinePolicyRef `json:"inline_policies"`
	BoundaryARN       string            `json:"boundary_arn,omitempty"`
}

// DedicatedIdentityIntent is the `dedicated_identity` intent (§11).
type DedicatedIdentityIntent struct {
	Kind     string            `json:"kind"`
	Source   Subject           `json:"source"`
	Workload DedicatedWorkload `json:"workload"`
	NewRole  NewRole           `json:"new_role"`
	Delivery string            `json:"delivery"`
}

// Intent is a parsed, typed version intent: exactly one member is set,
// matching Kind.
type Intent struct {
	Kind              string
	RightSize         *RightSizeIntent
	RemoveControl     *RemoveControlIntent
	DedicatedIdentity *DedicatedIdentityIntent
}

// MarshalJSON renders the member that Kind names.
func (in Intent) MarshalJSON() ([]byte, error) {
	switch in.Kind {
	case IntentRightSizeServices:
		return json.Marshal(in.RightSize)
	case IntentRemoveControl:
		return json.Marshal(in.RemoveControl)
	case IntentDedicatedIdentity:
		return json.Marshal(in.DedicatedIdentity)
	}
	return nil, fmt.Errorf("igagov: unknown intent kind %q", in.Kind)
}

// IntentError is one field-level problem; ValidateIntent returns them all.
type IntentError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// IntentErrors is the list a 422 response carries.
type IntentErrors []IntentError

func (e IntentErrors) Error() string {
	parts := make([]string, len(e))
	for i, x := range e {
		parts[i] = x.Field + ": " + x.Message
	}
	return "invalid intent: " + strings.Join(parts, "; ")
}

var (
	reUUID     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reAccount  = regexp.MustCompile(`^[0-9]{12}$`)
	reRoleID   = regexp.MustCompile(`^AROA[A-Z0-9]{8,124}$`)
	reService  = regexp.MustCompile(`^[a-z0-9-]+$`) // 051 posture CHECK
	reHash     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reRoleName = regexp.MustCompile(`^[\w+=,.@-]{1,64}$`)
	reRolePath = regexp.MustCompile(`^/([\x21-\x7e]{0,510}/)?$`)
	reARN      = regexp.MustCompile(`^arn:[a-z0-9-]+:[a-z0-9-]*:[a-z0-9-]*:[0-9]*:.+$`)
	reInlineNm = regexp.MustCompile(`^[\w+=,.@-]{1,128}$`)
)

// ParseIntent decodes a version intent strictly (unknown members refused, so
// the typed intent is the whole intent) and validates it. The returned
// errors are IntentErrors when the JSON parsed.
func ParseIntent(raw []byte) (Intent, error) {
	if _, err := Canonicalize(raw); err != nil {
		return Intent{}, IntentErrors{{Field: "", Code: "not_json", Message: err.Error()}}
	}
	var head struct {
		Kind string `json:"kind"`
	}
	_ = json.Unmarshal(raw, &head)
	in := Intent{Kind: head.Kind}
	dec := func(v any) error {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(v); err != nil {
			return IntentErrors{{Field: "", Code: "shape", Message: err.Error()}}
		}
		return nil
	}
	var err error
	switch head.Kind {
	case IntentRightSizeServices:
		in.RightSize = &RightSizeIntent{}
		err = dec(in.RightSize)
	case IntentRemoveControl:
		in.RemoveControl = &RemoveControlIntent{}
		err = dec(in.RemoveControl)
	case IntentDedicatedIdentity:
		in.DedicatedIdentity = &DedicatedIdentityIntent{}
		err = dec(in.DedicatedIdentity)
	default:
		return Intent{}, IntentErrors{{Field: "kind", Code: "unknown_kind", Message: fmt.Sprintf("unknown intent kind %q", head.Kind)}}
	}
	if err != nil {
		return Intent{}, err
	}
	if err := ValidateIntent(in); err != nil {
		return Intent{}, err
	}
	return in, nil
}

type collector struct{ errs IntentErrors }

func (c *collector) add(field, code, format string, args ...any) {
	c.errs = append(c.errs, IntentError{Field: field, Code: code, Message: fmt.Sprintf(format, args...)})
}

func (c *collector) result() error {
	if len(c.errs) == 0 {
		return nil
	}
	sort.SliceStable(c.errs, func(i, j int) bool { return c.errs[i].Field < c.errs[j].Field })
	return c.errs
}

// ValidateIntent is `igagov.ValidateIntent` (§2.7): the intent's shape and
// every rule that needs no evidence. Evidence rules — a removal's basis
// still holds, the service is not a dependency of the workload context, it
// is in the activity report (§3.4 (1)) — belong to the compiler, which has
// the bundle. Returns IntentErrors listing every problem, or nil.
func ValidateIntent(in Intent) error {
	c := &collector{}
	switch in.Kind {
	case IntentRightSizeServices:
		if in.RightSize == nil {
			c.add("kind", "shape", "right_size_services intent has no body")
			break
		}
		validateRightSize(c, *in.RightSize)
	case IntentRemoveControl:
		if in.RemoveControl == nil {
			c.add("kind", "shape", "remove_control intent has no body")
			break
		}
		validateRemoveControl(c, *in.RemoveControl)
	case IntentDedicatedIdentity:
		if in.DedicatedIdentity == nil {
			c.add("kind", "shape", "dedicated_identity intent has no body")
			break
		}
		validateDedicated(c, *in.DedicatedIdentity)
	default:
		c.add("kind", "unknown_kind", "unknown intent kind %q", in.Kind)
	}
	return c.result()
}

func validateSubject(c *collector, field string, s Subject) {
	if !reUUID.MatchString(s.IdentityAccountID) {
		c.add(field+".identity_account_id", "invalid", "must be a UUID")
	}
	if !reRoleID.MatchString(s.RoleID) {
		c.add(field+".role_id", "invalid", "must be an IAM RoleId (AROA…)")
	}
	if !reAccount.MatchString(s.AccountID) {
		c.add(field+".account_id", "invalid", "must be a 12-digit AWS account id")
	}
}

func validDate(s string) bool {
	if _, err := time.Parse("2006-01-02", s); err == nil {
		return true
	}
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}

func validateRightSize(c *collector, r RightSizeIntent) {
	if r.Kind != IntentRightSizeServices {
		c.add("kind", "invalid", "kind must be %s", IntentRightSizeServices)
	}
	if len(r.Subjects) == 0 {
		c.add("subjects", "required", "at least one subject is required (no selector targets in R1a, P-06)")
	}
	roles := map[string]bool{}
	for i, s := range r.Subjects {
		f := fmt.Sprintf("subjects[%d]", i)
		validateSubject(c, f, s)
		if roles[s.RoleID] {
			c.add(f+".role_id", "duplicate", "role %s is listed twice", s.RoleID)
		}
		roles[s.RoleID] = true
	}

	subjectIDs := map[string]bool{}
	for _, s := range r.Subjects {
		subjectIDs[s.IdentityAccountID] = true
	}
	retained := map[string]bool{}          // unscoped (every subject)
	scoped := map[string]map[string]bool{} // service -> subjects an owner retains it for
	for i, e := range r.Retain {
		f := fmt.Sprintf("retain[%d]", i)
		if !reService.MatchString(e.Service) {
			c.add(f+".service", "invalid", "must be an IAM service namespace")
		}
		if len(e.Subjects) > 0 {
			// An owner-scoped retain (§2.9, §7.4): its service may still be
			// removed for the other subjects.
			if e.Basis != RetainOwner {
				c.add(f+".subjects", "invalid", "only an owner retain is scoped to subjects")
			}
			if scoped[e.Service] == nil {
				scoped[e.Service] = map[string]bool{}
			}
			for j, s := range e.Subjects {
				if !subjectIDs[s] {
					c.add(fmt.Sprintf("%s.subjects[%d]", f, j), "invalid", "%s is not a subject of this intent", s)
				}
				if scoped[e.Service][s] {
					c.add(fmt.Sprintf("%s.subjects[%d]", f, j), "duplicate", "service %s is retained twice for %s", e.Service, s)
				}
				scoped[e.Service][s] = true
			}
		} else {
			if retained[e.Service] {
				c.add(f+".service", "duplicate", "service %s is retained twice", e.Service)
			}
			retained[e.Service] = true
		}
		switch e.Basis {
		case RetainObserved:
			if e.LastAttempt == "" || !validDate(e.LastAttempt) {
				c.add(f+".last_attempt", "required", "an observed retain needs the last attempt time")
			}
		case RetainDependency:
			if _, _, err := ParseDependencyRef(e.Catalog); err != nil {
				c.add(f+".catalog", "invalid", "%v", err)
			}
		case RetainOwner:
			if strings.TrimSpace(e.Reason) == "" {
				c.add(f+".reason", "required", "an owner retain needs a reason")
			}
			if e.ReviewBy == "" || !validDate(e.ReviewBy) {
				c.add(f+".review_by", "required", "an owner retain needs a review date (§3.8)")
			}
		case RetainUnreviewed:
		default:
			c.add(f+".basis", "invalid", "retain basis must be observed, dependency, owner or unreviewed")
		}
	}

	for svc := range scoped {
		if retained[svc] {
			c.add("retain", "duplicate", "service %s is retained for every subject and again for some", svc)
		}
	}
	if len(r.Remove) == 0 {
		c.add("remove", "required", "a right_size_services intent removes at least one service")
	}
	// Each subject still removes something once its owners' retains apply.
	for i, s := range r.Subjects {
		if len(r.Remove) > 0 && len(r.ForSubject(s.IdentityAccountID).Remove) == 0 {
			c.add(fmt.Sprintf("subjects[%d]", i), "nothing_to_remove", "the owners' retains leave nothing to remove for role %s", s.RoleID)
		}
	}
	removed := map[string]bool{}
	for i, e := range r.Remove {
		f := fmt.Sprintf("remove[%d]", i)
		if !reService.MatchString(e.Service) {
			c.add(f+".service", "invalid", "must be an IAM service namespace")
		}
		if removed[e.Service] {
			c.add(f+".service", "duplicate", "service %s is removed twice", e.Service)
		}
		removed[e.Service] = true
		if retained[e.Service] {
			c.add(f+".service", "conflict", "service %s is both retained and removed", e.Service)
		}
		if e.Basis != RemoveNoAttempt {
			c.add(f+".basis", "invalid", "remove basis must be no_attempt")
		}
		if e.QualifiedDays < MinQualifiedDays {
			c.add(f+".qualified_days", "not_qualified", "a removal needs at least %d qualified days (§2.6)", MinQualifiedDays)
		}
		if e.GrantAgeBasis != GrantAgeObservedSinceChange && e.GrantAgeBasis != GrantAgePredatesObservation {
			c.add(f+".grant_age_basis", "invalid", "grant_age_basis must be observed_since_change or predates_observation; an unknown grant is unreviewed, never removed")
		}
		validateRemoveRoutes(c, f, e)
	}

	if r.ObservationDays < MinObservationDays || r.ObservationDays > MaxObservationDays {
		c.add("observation_days", "out_of_range", "must be %d..%d", MinObservationDays, MaxObservationDays)
	}
	if r.Rollout != nil {
		if r.Rollout.CanaryTarget != "" && !roles[r.Rollout.CanaryTarget] {
			c.add("rollout.canary_target", "invalid", "the canary must be one of the subjects")
		}
		if r.Rollout.CanaryHours != 0 && (r.Rollout.CanaryHours < MinCanaryHours || r.Rollout.CanaryHours > MaxCanaryHours) {
			c.add("rollout.canary_hours", "out_of_range", "must be %d..%d", MinCanaryHours, MaxCanaryHours)
		}
	}
	switch r.Delivery {
	case DeliveryDirect, DeliveryIaCPR, DeliveryExport:
	default:
		c.add("delivery", "invalid", "delivery must be direct, iac_pr or export")
	}
	seen := map[string]bool{}
	for i, id := range r.FindingIDs {
		if !reUUID.MatchString(id) {
			c.add(fmt.Sprintf("finding_ids[%d]", i), "invalid", "must be a UUID")
		}
		if seen[id] {
			c.add(fmt.Sprintf("finding_ids[%d]", i), "duplicate", "finding listed twice")
		}
		seen[id] = true
	}
	if r.EvidenceRev <= 0 {
		c.add("evidence_rev", "required", "the revision the intent was proposed from is required")
	}
}

func validateRemoveRoutes(c *collector, f string, e RemoveEntry) {
	if e.RouteUsage != "" && e.RouteUsage != RouteUsageNoneObserved && e.RouteUsage != RouteUsageConfirmRequired {
		c.add(f+".route_usage", "invalid", "route_usage must be none_observed or confirm_required")
	}
	switch e.RouteState {
	case "", RouteStateNoneObserved, RouteStateBypassKnown, RouteStateEffectUnknown, RouteStateNotAnalysed:
	default:
		c.add(f+".route_state", "invalid", "unknown route_state")
	}
	if e.RouteUsage == RouteUsageNoneObserved && e.RouteState != "" && e.RouteState != RouteStateNoneObserved {
		c.add(f+".route_state", "conflict", "route_usage none_observed requires route_state none_observed (§3.4)")
	}
	if e.RouteUsage == RouteUsageNoneObserved && len(e.Routes) > 0 {
		c.add(f+".routes", "conflict", "route_usage none_observed lists no routes")
	}
	if e.RouteState != "" && e.RouteState != RouteStateNoneObserved && len(e.Routes) == 0 {
		c.add(f+".routes", "required", "route_state %s must list its routes or forms", e.RouteState)
	}
	for j, rt := range e.Routes {
		rf := fmt.Sprintf("%s.routes[%d]", f, j)
		if rt.Resource == "" && rt.Form == "" {
			c.add(rf, "required", "a route names a resource or a form")
		}
		if rt.Resource != "" && !strings.HasPrefix(rt.Resource, "arn:") {
			c.add(rf+".resource", "invalid", "must be an ARN")
		}
		switch rt.Principal {
		case "", PrincipalRoleARN, PrincipalRoleSession, PrincipalWildcard:
		default:
			c.add(rf+".principal", "invalid", "principal must be role_arn, role_session or wildcard")
		}
	}
}

func validateRemoveControl(c *collector, r RemoveControlIntent) {
	if r.Kind != IntentRemoveControl {
		c.add("kind", "invalid", "kind must be %s", IntentRemoveControl)
	}
	if len(r.ControlIDs) == 0 {
		c.add("control_ids", "required", "at least one control is required")
	}
	seen := map[string]bool{}
	for i, id := range r.ControlIDs {
		f := fmt.Sprintf("control_ids[%d]", i)
		if !reUUID.MatchString(id) {
			c.add(f, "invalid", "must be a UUID")
		}
		if seen[id] {
			c.add(f, "duplicate", "control listed twice")
		}
		seen[id] = true
	}
	if strings.TrimSpace(r.Reason) == "" {
		c.add("reason", "required", "removing AuthSec control needs a reason")
	}
}

func validateDedicated(c *collector, d DedicatedIdentityIntent) {
	if d.Kind != IntentDedicatedIdentity {
		c.add("kind", "invalid", "kind must be %s", IntentDedicatedIdentity)
	}
	validateSubject(c, "source", d.Source)
	if !reUUID.MatchString(d.Workload.WorkloadID) {
		c.add("workload.workload_id", "invalid", "must be a UUID")
	}
	switch d.Workload.BindingKind {
	case BindingECSTaskRole, BindingLambdaRole, BindingEC2InstanceProfile:
	default:
		c.add("workload.binding_kind", "invalid", "binding_kind must be ecs_task_role, lambda_role or ec2_instance_profile (§11)")
	}
	if !reARN.MatchString(d.Workload.BindingRef) {
		c.add("workload.binding_ref", "invalid", "must be an ARN")
	}
	nr := d.NewRole
	if !reRoleName.MatchString(nr.Name) {
		c.add("new_role.name", "invalid", "must be a valid IAM role name")
	}
	if !reRolePath.MatchString(nr.Path) {
		c.add("new_role.path", "invalid", "must be an IAM path (\"/\" or \"/a/b/\")")
	}
	if !reHash.MatchString(nr.TrustPolicyHash) {
		c.add("new_role.trust_policy_hash", "invalid", "must be sha256:<64 hex>")
	}
	seen := map[string]bool{}
	for i, a := range nr.ManagedPolicyARNs {
		f := fmt.Sprintf("new_role.managed_policy_arns[%d]", i)
		if !reARN.MatchString(a) {
			c.add(f, "invalid", "must be an ARN")
		}
		if seen[a] {
			c.add(f, "duplicate", "policy listed twice")
		}
		seen[a] = true
	}
	names := map[string]bool{}
	for i, p := range nr.InlinePolicies {
		f := fmt.Sprintf("new_role.inline_policies[%d]", i)
		if !reInlineNm.MatchString(p.Name) {
			c.add(f+".name", "invalid", "must be a valid inline policy name")
		}
		if names[p.Name] {
			c.add(f+".name", "duplicate", "inline policy listed twice")
		}
		names[p.Name] = true
		if !reHash.MatchString(p.DocumentHash) {
			c.add(f+".document_hash", "invalid", "must be sha256:<64 hex>")
		}
	}
	if nr.BoundaryARN != "" && !reARN.MatchString(nr.BoundaryARN) {
		c.add("new_role.boundary_arn", "invalid", "must be an ARN")
	}
	if d.Delivery != DeliveryIaCPR && d.Delivery != DeliveryExport {
		c.add("delivery", "invalid", "a dedicated identity is delivered only as iac_pr or export (§11; 050 iga_gov_plan_kind_chk)")
	}
}

// CanonicalIntent returns JCS(intent) and its intent_hash (§2.8) for a
// validated intent.
func CanonicalIntent(in Intent) (canonical []byte, hash string, err error) {
	if err := ValidateIntent(in); err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, "", err
	}
	c, err := Canonicalize(raw)
	if err != nil {
		return nil, "", err
	}
	if err := checkStorable(c); err != nil {
		return nil, "", errors.New("igagov: intent text contains U+0000")
	}
	return c, taggedHash(DomainIntent, c), nil
}
