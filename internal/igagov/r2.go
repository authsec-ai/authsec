package igagov

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Phase 3 R2 -- time-bound access and session response
// (SPEC-iga-phase3-policy.md §12.3; requirements C-10, E-09, R-08). There is
// no R2 implementation spec: every assumption is a DECISION R2-n comment,
// listed here and repeated where the code applies it. Everything R2 runs
// behind R2 (services/iga_gov_r2.go); this file is pure.
//
// DECISION R2-1 (PRODUCT, made by the coordinator as the default; flag for
// Aditya): requirement R-08 "scoped temporary sessions" is restated for R2
// as "time-bounded access". Brokered sessions -- AuthSec calling AssumeRole
// with a session policy on the agent's behalf -- are OUT of R2 and moved to
// R3, because they make AuthSec a runtime credential dependency of the agent.
//
// DECISION R2-2: time-conditioned retention is compiled INTO the AuthSec
// boundary: the retained-until service (or action) joins the exclusion list
// of the boundary's one Allow-NotAction statement, and a second Allow
// statement grants it back with Condition DateLessThan aws:CurrentTime
// <until>. Before <until> the role keeps the access; from <until> on AWS
// itself stops matching the conditioned statement, so the ceiling narrows
// without AuthSec running (E-09 "outages and missed housekeeping"). The
// boundary stays a ceiling that grants nothing (§3.1).
//
// DECISION R2-3: one conditioned statement per distinct <until>, Sid
// AuthSecRetainUntil<yyyymmddhhmmss>, ordered by <until>, Resource "*", the
// retained services as "<ns>:*" and the retained actions literally, sorted.
// <until> is rendered in UTC with second precision (ISO 8601, as AWS date
// condition operators accept).
//
// DECISION R2-4: time-bound retention is offered only on AuthSec's own
// boundary (J3, and its J2/J1 renderings of the same document). A customer
// boundary is narrowed by REMOVING actions (§3.4), never by adding a
// statement, so a time-bound retain on a role with a customer boundary is
// refused (time_bound_requires_authsec_boundary).
//
// DECISION R2-5: <until> must be at least one hour after the compile's live
// read, and at most 400 days after it; anything else is refused
// (time_bound_until_out_of_range).
//
// DECISION R2-6: time-bound retention requires basis owner (an owner-
// retained service with a reason and review date) -- the person accountable
// decides the date. A service may not be both retained-until and removed;
// an action retained-until may not be in remove_actions, and its namespace
// may not be removed whole.
//
// DECISION R2-7: the per-service exclusion fact of §8.7 becomes time-aware
// while R2 is on (BoundaryExcludesAt): an Allow statement whose only effect-
// limiting condition AuthSec can evaluate offline -- DateLessThan /
// DateLessThanEquals on aws:CurrentTime -- and whose every date has passed
// grants nothing. Any other condition keeps the conservative R1a reading
// (a conditional grant counts as a grant). With R2 off the R1a function is
// used unchanged.
//
// DECISION R2-8: temporary grants are AuthSec-owned customer-managed
// policies under /authsec/, named AuthSecGrant-<RoleId>-<grant 8hex>, tagged
// authsec:managed-by / workspace / grant / expires-at, ATTACHED to the role
// (a permissions policy, privilege expansion). Their single statement is
// Allow <exactly the requested literal actions> on <exactly the requested
// resources> with DateLessThan aws:CurrentTime <expires_at>, so the grant is
// inert after expiry even if the expiry job never runs; the job then
// detaches and deletes it.
//
// DECISION R2-9: a temporary grant names literal actions only (no "*" or
// "?" anywhere, at most 50) and resources as ARNs or "*" (at most 20): the
// document is generated from the request alone and can never widen beyond
// what the request names. A request whose actions intersect the escalation
// catalog (§3.7) needs an explicit acknowledgement text.
//
// DECISION R2-10: grant duration 15 minutes .. 30 days.
//
// DECISION R2-11: session revocation is AWS's documented "revoke active
// sessions" deny -- Deny "*" on "*" when aws:TokenIssueTime is before the
// cutoff -- which denies every session issued before the cutoff and none
// issued after it. It is delivered as an AuthSec-owned MANAGED policy
// /authsec/AuthSecRevokeOlderSessions-<RoleId>-<revocation 8hex> ATTACHED to
// the role, not as an inline policy (DECISION R2-14): IAM has no condition
// key that scopes iam:PutRolePolicy to an inline policy name, so granting it
// to the enforcement role would let it write any inline policy to any
// unprotected role. A managed deny attached to the role is evaluated exactly
// like an inline one (both are identity-based policies), and attaching it
// needs only iam:AttachRolePolicy scoped by iam:PolicyARN to /authsec/.
// FLAG for review: the coordinator's brief said "inline deny"; this is the
// deliberate substitute.
//
// DECISION R2-12: the cutoff is fixed when the revocation is approved (or at
// request time for an emergency revocation), never earlier than the request,
// so sessions issued while approval was pending are cut too. The inline deny
// is removed automatically MaxRoleSessionLifetime (12 h, the IAM maximum for
// a role session) plus a one-hour margin after the cutoff, when no session
// issued before the cutoff can still be valid; keep_hours may extend that
// (at most 7 days).
//
// DECISION R2-13: direct (J3) execution of a dedicated-identity split is
// offered for Lambda functions only, for a new role under the path
// /authsec/split/ (the enforcement template v2 scopes role creation and
// deletion to that path), for a source role WITHOUT a permissions boundary
// (copying a boundary would attach the source's boundary policy to a second
// role), for a function with no aliases (moving aliases needs PublishVersion
// and UpdateAlias, which v2 does not grant), and with no compatibility item
// that the PR would have edited. Anything else stays PR/export (§11).

// R2 names (§3.2 conventions).
const (
	GrantPolicyPrefix       = "AuthSecGrant-"
	GrantSid                = "AuthSecTemporaryGrant"
	RevokePolicyPrefix      = "AuthSecRevokeOlderSessions-"
	RevokeSid               = "AuthSecRevokeOlderSessions"
	SplitDirectRolePath     = "/authsec/split/"
	RetainUntilSidPrefix    = "AuthSecRetainUntil"
	TagGrant                = "authsec:grant"
	TagExpiresAt            = "authsec:expires-at"
	TagSplitControl         = "authsec:split-control"
	CondDateLessThan        = "DateLessThan"
	CondDateLessThanEquals  = "DateLessThanEquals"
	KeyCurrentTime          = "aws:CurrentTime"
	KeyTokenIssueTime       = "aws:TokenIssueTime"
	MaxGrantActions         = 50
	MaxGrantResources       = 20
	MinGrantDuration        = 15 * time.Minute
	MaxGrantDuration        = 30 * 24 * time.Hour
	MaxRoleSessionLifetime  = 12 * time.Hour
	RevokeRemovalMargin     = time.Hour
	MaxRevokeKeep           = 7 * 24 * time.Hour
	MinTimeBoundLead        = time.Hour
	MaxTimeBoundLead        = 400 * 24 * time.Hour
	TimeBoundNoticeLead     = 7 * 24 * time.Hour
	TimeBoundKindService    = "service"
	TimeBoundKindAction     = "action"
	RefuseTimeBoundCustomer = "time_bound_requires_authsec_boundary"
	RefuseTimeBoundRange    = "time_bound_until_out_of_range"
	RefuseSplitDirectScope  = "split_direct_not_supported"
)

// AWSTime renders t as AWS date-condition text: UTC, second precision.
func AWSTime(t time.Time) string { return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z") }

// ParseUntil parses an intent's until (RFC 3339, or a date meaning 00:00 UTC
// that day).
func ParseUntil(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Truncate(time.Second), nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("igagov: %q is neither RFC 3339 nor a date", s)
	}
	return t.UTC(), nil
}

/* ------------------------------------------------------------------------- */
/*                     Time-conditioned retention (piece 1)                   */
/* ------------------------------------------------------------------------- */

// RetainActionUntilEntry is one action kept until a date inside a service the
// role otherwise keeps (R2): the action, its namespace, the date, and the
// owner's reason (DECISION R2-6).
type RetainActionUntilEntry struct {
	Action  string `json:"action"`
	Service string `json:"service"`
	Until   string `json:"until"`
	Reason  string `json:"reason"`
}

// TimeBoundItem is one service or action a plan keeps only until a date
// (iga_gov_plan.diff.time_bound and impact.time_bound; omitted when empty).
type TimeBoundItem struct {
	Kind  string `json:"kind"` // service | action
	Key   string `json:"key"`  // namespace, or the literal action
	Until string `json:"until"`
}

// HasTimeBound reports whether an intent carries any R2 time-bound member.
func (r RightSizeIntent) HasTimeBound() bool {
	if len(r.RetainActionsUntil) > 0 {
		return true
	}
	for _, e := range r.Retain {
		if e.Until != "" {
			return true
		}
	}
	return false
}

// TimeBoundItems lists the intent's time-bound retentions, normalised (UTC
// second precision) and sorted by (until, kind, key). Call it on
// ForSubject's result: owner-scoped retains of other subjects are dropped
// there.
func (r RightSizeIntent) TimeBoundItems() []TimeBoundItem {
	var out []TimeBoundItem
	for _, e := range r.Retain {
		if e.Until == "" {
			continue
		}
		if t, err := ParseUntil(e.Until); err == nil {
			out = append(out, TimeBoundItem{Kind: TimeBoundKindService, Key: e.Service, Until: AWSTime(t)})
		}
	}
	for _, e := range r.RetainActionsUntil {
		a, ok := CanonicalAction(e.Action)
		t, err := ParseUntil(e.Until)
		if ok && err == nil {
			out = append(out, TimeBoundItem{Kind: TimeBoundKindAction, Key: a, Until: AWSTime(t)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Until != b.Until {
			return a.Until < b.Until
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Key < b.Key
	})
	return out
}

// validateTimeBound is R2's shape rules for until (DECISION R2-6).
func validateTimeBound(c *collector, r RightSizeIntent, removedSvc map[string]bool) {
	for i, e := range r.Retain {
		if e.Until == "" {
			continue
		}
		f := fmt.Sprintf("retain[%d]", i)
		if e.Basis != RetainOwner {
			c.add(f+".until", "invalid", "only an owner retain may be kept until a date")
		}
		if _, err := ParseUntil(e.Until); err != nil {
			c.add(f+".until", "invalid", "until must be an RFC 3339 time or a date")
		}
	}
	removedAct := map[string]bool{}
	for _, e := range r.RemoveActions {
		removedAct[ActionKey(e.Action)] = true
	}
	seen := map[string]bool{}
	for i, e := range r.RetainActionsUntil {
		f := fmt.Sprintf("retain_actions_until[%d]", i)
		a, ok := CanonicalAction(e.Action)
		if !ok || a != e.Action {
			c.add(f+".action", "invalid", "must be one literal IAM action <namespace>:<Name> with a lower-case namespace and no wildcard")
			continue
		}
		ns, _, _ := SplitAction(a)
		if e.Service != ns {
			c.add(f+".service", "invalid", "must be the action's namespace %s", ns)
		}
		if seen[ActionKey(a)] {
			c.add(f+".action", "duplicate", "action %s is kept until a date twice", a)
		}
		seen[ActionKey(a)] = true
		if removedSvc[ns] {
			c.add(f+".action", "conflict", "service %s is removed whole", ns)
		}
		if removedAct[ActionKey(a)] {
			c.add(f+".action", "conflict", "action %s is both removed and kept until a date", a)
		}
		if _, err := ParseUntil(e.Until); err != nil {
			c.add(f+".until", "invalid", "until must be an RFC 3339 time or a date")
		}
		if strings.TrimSpace(e.Reason) == "" {
			c.add(f+".reason", "required", "keeping an action until a date needs a reason")
		}
	}
}

// checkTimeBoundRange is DECISION R2-5 at compile time.
func checkTimeBoundRange(items []TimeBoundItem, readAt time.Time) []Refusal {
	var out []Refusal
	for _, it := range items {
		t, err := ParseUntil(it.Until)
		if err != nil || t.Before(readAt.Add(MinTimeBoundLead)) || t.After(readAt.Add(MaxTimeBoundLead)) {
			out = append(out, Refusal{RefuseTimeBoundRange, it.Kind + " " + it.Key + " until " + it.Until})
		}
	}
	return out
}

// TimeBoundBoundaryDocument is the AuthSec boundary with time-conditioned
// retention (DECISION R2-2, R2-3): the exclusion-only Allow-NotAction
// statement whose list also holds every time-bound service ("<ns>:*") and
// action, plus one Allow per distinct until granting them back while
// aws:CurrentTime is before it. With no items it is exactly
// ExcludeOnlyActionsDocument.
func TimeBoundBoundaryDocument(remove, actions []string, items []TimeBoundItem) ([]byte, string, error) {
	if len(items) == 0 {
		return ExcludeOnlyActionsDocument(remove, actions)
	}
	rm := map[string]bool{}
	var entries []string
	for _, s := range remove {
		ns := strings.ToLower(strings.TrimSpace(s))
		if !reService.MatchString(ns) {
			return nil, "", fmt.Errorf("igagov: %q is not an IAM service namespace", s)
		}
		rm[ns] = true
		entries = append(entries, ns+":*")
	}
	seen := map[string]bool{}
	addAction := func(x string) error {
		a, ok := CanonicalAction(x)
		if !ok {
			return fmt.Errorf("igagov: %q is not one literal IAM action", x)
		}
		ns, _, _ := SplitAction(a)
		if rm[ns] || seen[ActionKey(a)] {
			return nil
		}
		seen[ActionKey(a)] = true
		entries = append(entries, a)
		return nil
	}
	for _, x := range actions {
		if err := addAction(x); err != nil {
			return nil, "", err
		}
	}
	byUntil := map[string][]string{}
	for _, it := range items {
		var grant string
		switch it.Kind {
		case TimeBoundKindService:
			ns := strings.ToLower(it.Key)
			if !reService.MatchString(ns) {
				return nil, "", fmt.Errorf("igagov: %q is not an IAM service namespace", it.Key)
			}
			if rm[ns] {
				return nil, "", fmt.Errorf("igagov: service %s is both removed and kept until a date", ns)
			}
			grant = ns + ":*"
			if !seen[grant] {
				seen[grant] = true
				entries = append(entries, grant)
			}
		case TimeBoundKindAction:
			a, ok := CanonicalAction(it.Key)
			if !ok {
				return nil, "", fmt.Errorf("igagov: %q is not one literal IAM action", it.Key)
			}
			if err := addAction(a); err != nil {
				return nil, "", err
			}
			grant = a
		default:
			return nil, "", fmt.Errorf("igagov: unknown time-bound kind %q", it.Kind)
		}
		byUntil[it.Until] = append(byUntil[it.Until], grant)
	}
	stmts := []any{map[string]any{
		"Sid": AuthSecBoundarySid, "Effect": EffectAllow, "NotAction": sortedUnique(entries), "Resource": "*",
	}}
	for _, until := range sortedKeys(byUntil) {
		t, err := ParseUntil(until)
		if err != nil {
			return nil, "", err
		}
		stmts = append(stmts, map[string]any{
			"Sid": RetainUntilSidPrefix + t.Format("20060102150405"), "Effect": EffectAllow,
			"Action": sortedUnique(byUntil[until]), "Resource": "*",
			"Condition": map[string]any{CondDateLessThan: map[string]any{KeyCurrentTime: AWSTime(t)}},
		})
	}
	c, err := CanonicalizeValue(map[string]any{"Version": PolicyVersion20121017, "Statement": stmts})
	if err != nil {
		return nil, "", err
	}
	return c, ContentHash(c), nil
}

// StatementExpiredAt reports whether an Allow statement can no longer match
// at now because of a DateLessThan / DateLessThanEquals on aws:CurrentTime
// whose every value is at or before now (DECISION R2-7). A statement without
// such a condition, or with an unparseable date, is not expired.
func StatementExpiredAt(st Statement, now time.Time) bool {
	for _, c := range st.Conditions {
		if !strings.EqualFold(c.Key, KeyCurrentTime) {
			continue
		}
		op := c.Operator
		if op != CondDateLessThan && op != CondDateLessThanEquals {
			continue
		}
		if len(c.Values) == 0 {
			continue
		}
		all := true
		for _, v := range c.Values {
			t, err := time.Parse(time.RFC3339, strings.Trim(v, `"`))
			if err != nil {
				all = false
				break
			}
			if op == CondDateLessThan && t.After(now) {
				all = false
			}
			if op == CondDateLessThanEquals && !now.After(t) {
				all = false
			}
		}
		if all {
			return true
		}
	}
	return false
}

// BoundaryExcludesAt is BoundaryExcludes that also treats an Allow whose
// aws:CurrentTime date has passed as granting nothing (DECISION R2-7).
func BoundaryExcludesAt(doc PolicyDocument, ns string, now time.Time) bool {
	for _, st := range doc.Statements {
		if StatementExpiredAt(st, now) {
			continue
		}
		if st.GrantsNamespace(ns) {
			return false
		}
	}
	return true
}

// TimeBoundOf lists the time-conditioned grants of a boundary document (the
// AuthSecRetainUntil statements) as items, for drift and notices.
func TimeBoundOf(text string) []TimeBoundItem {
	d, err := DecodePolicyDocument(text)
	if err != nil {
		return nil
	}
	var out []TimeBoundItem
	for _, st := range d.Statements {
		if st.Effect != EffectAllow || !strings.HasPrefix(st.Sid, RetainUntilSidPrefix) {
			continue
		}
		until := ""
		for _, c := range st.Conditions {
			if strings.EqualFold(c.Key, KeyCurrentTime) && len(c.Values) > 0 {
				until = strings.Trim(c.Values[0], `"`)
			}
		}
		for _, a := range st.Action {
			if ns, act, ok := SplitAction(a); ok && act == "*" {
				out = append(out, TimeBoundItem{Kind: TimeBoundKindService, Key: strings.ToLower(ns), Until: until})
			} else {
				out = append(out, TimeBoundItem{Kind: TimeBoundKindAction, Key: a, Until: until})
			}
		}
	}
	return out
}

/* ------------------------------------------------------------------------- */
/*                         Temporary grants (piece 2)                         */
/* ------------------------------------------------------------------------- */

// GrantRequest is what a temporary grant names (DECISION R2-9).
type GrantRequest struct {
	RoleID    string
	AccountID string
	Actions   []string
	Resources []string
	ExpiresAt time.Time
}

// ErrGrantInvalid wraps every refusal of a grant request's shape.
var ErrGrantInvalid = errors.New("igagov: invalid temporary grant")

// NormalizeGrant validates and normalises a grant's actions (canonical,
// sorted, unique) and resources (sorted, unique; "*" alone when present).
func NormalizeGrant(actions, resources []string) ([]string, []string, error) {
	if len(actions) == 0 || len(actions) > MaxGrantActions {
		return nil, nil, fmt.Errorf("%w: 1..%d actions are required", ErrGrantInvalid, MaxGrantActions)
	}
	var acts []string
	seen := map[string]bool{}
	for _, a := range actions {
		ca, ok := CanonicalAction(a)
		if !ok {
			return nil, nil, fmt.Errorf("%w: %q is not one literal IAM action (no wildcards)", ErrGrantInvalid, a)
		}
		if seen[ActionKey(ca)] {
			continue
		}
		seen[ActionKey(ca)] = true
		acts = append(acts, ca)
	}
	sort.Strings(acts)
	if len(resources) == 0 {
		resources = []string{"*"}
	}
	if len(resources) > MaxGrantResources {
		return nil, nil, fmt.Errorf("%w: at most %d resources", ErrGrantInvalid, MaxGrantResources)
	}
	var res []string
	star := false
	for _, r := range resources {
		r = strings.TrimSpace(r)
		switch {
		case r == "*":
			star = true
		case reARN.MatchString(r):
			res = append(res, r)
		default:
			return nil, nil, fmt.Errorf("%w: resource %q must be an ARN or \"*\"", ErrGrantInvalid, r)
		}
	}
	if star {
		res = []string{"*"}
	}
	return acts, sortedUnique(res), nil
}

// GrantEscalations lists the escalation-catalog patterns (§3.7) the grant
// would give (DECISION R2-9).
func GrantEscalations(actions, resources []string) []string {
	return EscalationsGranted(Statement{Effect: EffectAllow, Action: actions, Resource: resources})
}

// GrantPolicyName is AuthSecGrant-<RoleId>-<grant id 8 hex>.
func GrantPolicyName(roleID, grantID string) string {
	return GrantPolicyPrefix + roleID + "-" + strings.ReplaceAll(grantID, "-", "")[:8]
}

// GrantPolicyARN is the grant policy's ARN in the role's account.
func GrantPolicyARN(partition, account, name string) string {
	if partition == "" {
		partition = "aws"
	}
	return "arn:" + partition + ":iam::" + account + ":policy" + AuthSecPolicyPath + name
}

// TemporaryGrantDocument is the grant policy (DECISION R2-8): one Allow of
// exactly the normalised actions on exactly the normalised resources, while
// aws:CurrentTime is before expiresAt.
func TemporaryGrantDocument(actions, resources []string, expiresAt time.Time) ([]byte, string, error) {
	acts, res, err := NormalizeGrant(actions, resources)
	if err != nil {
		return nil, "", err
	}
	var resource any = res
	if len(res) == 1 {
		resource = res[0]
	}
	doc := map[string]any{
		"Version": PolicyVersion20121017,
		"Statement": []any{map[string]any{
			"Sid": GrantSid, "Effect": EffectAllow, "Action": acts, "Resource": resource,
			"Condition": map[string]any{CondDateLessThan: map[string]any{KeyCurrentTime: AWSTime(expiresAt)}},
		}},
	}
	c, err := CanonicalizeValue(doc)
	if err != nil {
		return nil, "", err
	}
	if PolicyChars(c) > MaxPolicyChars {
		return nil, "", fmt.Errorf("%w: the grant document is larger than %d characters", ErrGrantInvalid, MaxPolicyChars)
	}
	return c, ContentHash(c), nil
}

// GrantRequestHash is what a grant approval binds: role, actions,
// resources, expiry and document hash (§2.8's binding idea for R2).
func GrantRequestHash(roleID, accountID string, actions, resources []string, expiresAt time.Time, documentHash string) (string, error) {
	return HashCanonicalTagged("authsec.igagov.r2.temporary_grant.v1", struct {
		RoleID    string   `json:"role_id"`
		AccountID string   `json:"account_id"`
		Actions   []string `json:"actions"`
		Resources []string `json:"resources"`
		ExpiresAt string   `json:"expires_at"`
		Document  string   `json:"document_hash"`
	}{roleID, accountID, actions, resources, AWSTime(expiresAt), documentHash})
}

// GrantRequestKey identifies "the same request for the same role" for the
// one-live-grant rule: role and the normalised action and resource sets.
func GrantRequestKey(roleID, accountID string, actions, resources []string) (string, error) {
	return HashCanonicalTagged("authsec.igagov.r2.temporary_grant_key.v1", struct {
		RoleID    string   `json:"role_id"`
		AccountID string   `json:"account_id"`
		Actions   []string `json:"actions"`
		Resources []string `json:"resources"`
	}{roleID, accountID, actions, resources})
}

/* ------------------------------------------------------------------------- */
/*                         Session revocation (piece 3)                       */
/* ------------------------------------------------------------------------- */

// RevokeSessionsDocument is DECISION R2-11's inline deny.
func RevokeSessionsDocument(issuedBefore time.Time) ([]byte, string, error) {
	doc := map[string]any{
		"Version": PolicyVersion20121017,
		"Statement": []any{map[string]any{
			"Sid": RevokeSid, "Effect": EffectDeny, "Action": "*", "Resource": "*",
			"Condition": map[string]any{CondDateLessThan: map[string]any{KeyTokenIssueTime: AWSTime(issuedBefore)}},
		}},
	}
	c, err := CanonicalizeValue(doc)
	if err != nil {
		return nil, "", err
	}
	return c, ContentHash(c), nil
}

// RevokePolicyName is AuthSecRevokeOlderSessions-<RoleId>-<revocation 8hex>.
func RevokePolicyName(roleID, revocationID string) string {
	return RevokePolicyPrefix + roleID + "-" + strings.ReplaceAll(revocationID, "-", "")[:8]
}

// RevocationRequestHash is what a revocation approval binds.
func RevocationRequestHash(roleID, accountID string, issuedBefore time.Time, documentHash string, removeAfter time.Time) (string, error) {
	return HashCanonicalTagged("authsec.igagov.r2.session_revocation.v1", struct {
		RoleID       string `json:"role_id"`
		AccountID    string `json:"account_id"`
		IssuedBefore string `json:"issued_before"`
		Document     string `json:"document_hash"`
		RemoveAfter  string `json:"remove_after"`
	}{roleID, accountID, AWSTime(issuedBefore), documentHash, AWSTime(removeAfter)})
}

// RevocationRemoveAfter is DECISION R2-12's automatic removal time.
func RevocationRemoveAfter(issuedBefore time.Time, keep time.Duration) time.Time {
	min := MaxRoleSessionLifetime + RevokeRemovalMargin
	if keep < min {
		keep = min
	}
	if keep > MaxRevokeKeep {
		keep = MaxRevokeKeep
	}
	return issuedBefore.UTC().Add(keep).Truncate(time.Second)
}

/* ------------------------------------------------------------------------- */
/*                       Direct Lambda split (piece 4)                        */
/* ------------------------------------------------------------------------- */

// splitDirectRefusals is DECISION R2-13: what keeps a split from direct
// execution.
func splitDirectRefusals(in SplitInput, src *LiveRole) []Refusal {
	var out []Refusal
	if !in.DirectAllowed {
		return []Refusal{{RefuseSplitDirect, "isolation is delivered only as a PR or export (§11); direct execution needs R2 to be available"}}
	}
	if in.SubjectKind != SubjectLambdaFunction {
		out = append(out, Refusal{RefuseSplitDirectScope, "direct isolation moves Lambda functions only; " + in.SubjectKind + " stays PR/export"})
	}
	if in.Intent.NewRole.Path != SplitDirectRolePath {
		out = append(out, Refusal{RefuseSplitDirectScope, "a directly created role lives under " + SplitDirectRolePath})
	}
	if src != nil && src.BoundaryARN != "" {
		out = append(out, Refusal{RefuseSplitDirectScope, "the source role has a permissions boundary; copying it is PR/export only"})
	}
	if len(in.Aliases) > 0 {
		out = append(out, Refusal{RefuseSplitDirectScope, "the function has aliases (" + strings.Join(sortedUnique(in.Aliases), ", ") + "); moving them is PR/export only"})
	}
	for k, v := range in.MappedResources {
		if v {
			out = append(out, Refusal{RefuseSplitDirectScope, "compatibility item " + k + " would be edited by a PR"})
		}
	}
	return out
}
