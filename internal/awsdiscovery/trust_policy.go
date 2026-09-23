package awsdiscovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Trust-policy parsing: turning a role's AssumeRolePolicyDocument into the
// statements that say who may assume it (SPEC-iga-phase2-graph.md §1.4 "Trust
// and cross-account", §4.7 Trust, T3.4; P2-DECISIONS D-42..D-46).
//
// This file knows AWS and nothing about AuthSec, same as iam.go. The string
// values below are chosen to equal AuthSec's schema vocabularies exactly --
// cloud_assume_edge's subject kinds and mechanisms, iga_relationship.mechanism
// (031) and iga_external_principal.mechanism (034) -- so callers can write them
// through unchanged. This package does not import models to enforce that,
// since it must not know AuthSec's persistence shapes; internal/igagraph has a
// test that fails when the two drift, and a mismatch on the legacy table fails
// loudly as a CHECK violation on write.
//
// Two readers consume this file:
//
//   - ParseTrustDocument, the statement parser the collector validates with
//     (ValidateTrustDocument -> cloud_identity.trust_parse_error) and the
//     projector re-runs (§4.7): Allow AND Deny, every principal form,
//     conditions verbatim, NotPrincipal recorded, per-statement isolation.
//   - ParseTrustPolicy, the flattening adapter the legacy cloud_assume_edge
//     writer (Cloud Inventory, §1.5) has always called, now built on the
//     statement parser so both read one document the same way.

// Legacy cloud_assume_edge vocabulary (models.AssumeSubject*/AssumeMechanism*).
const (
	SubjectKindCloudService = "cloud_service"
	SubjectKindIdentity     = "identity"
	SubjectKindK8sSA        = "k8s_service_account"
	SubjectKindCIPipeline   = "ci_pipeline"
	SubjectKindExternal     = "external_account"
)

// Edge mechanisms (iga_relationship.mechanism, 031; the first three are also
// cloud_assume_edge's). Which one a principal gets follows from the ACTION its
// statement allows (D-43): sts:AssumeRole, sts:AssumeRoleWithWebIdentity,
// sts:AssumeRoleWithSAML.
const (
	MechanismSTSAssumeRole  = "sts_assume_role"
	MechanismOIDCFederation = "oidc_federation"
	MechanismSAMLFederation = "saml_federation"
	// MechanismEKSPodIdentity is not produced by this file: no trust policy
	// mentions the service account in a Pod Identity binding. It is declared
	// here so every mechanism value lives together, and is written by the EKS
	// surface in eks.go.
	MechanismEKSPodIdentity = "eks_pod_identity"
)

// External-principal kinds (iga_external_principal.mechanism, 034): what KIND
// of far endpoint a principal is, independent of how it assumes the role.
const (
	ExternalAWSAccount   = "aws_account"         // "any principal in that account the account permits"
	ExternalAWSPrincipal = "aws_principal"       // one named AWS principal, or "*"
	ExternalAWSService   = "aws_service"         // lambda.amazonaws.com
	ExternalOIDC         = "oidc"                // an OIDC issuer and subject
	ExternalSAML         = "saml"                // a SAML provider and subject
	ExternalK8sSA        = "k8s_service_account" // IRSA and EKS Pod Identity alike
)

// IssuerAWS is the issuer of every principal AWS itself names -- accounts, IAM
// and STS principals, service principals (D-42). Only federated principals
// have an issuer of their own.
const IssuerAWS = "aws"

// Principal entry types: the keys of a Principal block, plus the literal "*".
const (
	PrincipalAWS       = "AWS"
	PrincipalService   = "Service"
	PrincipalFederated = "Federated"
	PrincipalAnyone    = "*"
)

// The three STS actions that assume a role. Anything else a trust statement
// allows (sts:TagSession, sts:SetSourceIdentity) assumes nothing.
const (
	actionAssumeRole            = "sts:AssumeRole"
	actionAssumeRoleWebIdentity = "sts:AssumeRoleWithWebIdentity"
	actionAssumeRoleSAML        = "sts:AssumeRoleWithSAML"
)

// accountIDPattern matches a bare 12-digit AWS account id, the shape AWS
// accepts as a Principal.AWS value meaning "anyone in this account".
var accountIDPattern = regexp.MustCompile(`^\d{12}$`)

// accountRootPattern matches an account root principal ARN.
var accountRootPattern = regexp.MustCompile(`^arn:[^:]+:iam::(\d{12}):root$`)

// k8sSubjectPattern matches the IRSA subject claim shape. This is the ONLY
// signal that tells an IRSA federation apart from any other OIDC federation --
// AWS does not label it, the subject string is the only evidence.
var k8sSubjectPattern = regexp.MustCompile(`^system:serviceaccount:[^:]+:[^:]+$`)

// stringOrSlice unmarshals an IAM policy field that AWS allows to be written
// as either a single string or a list -- true of Principal.AWS,
// Principal.Service, Principal.Federated, Action and Resource. Anything else
// (a number, an object, a list holding one) is an error: a field we cannot
// read is never silently an empty one.
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		if single != "" {
			*s = []string{single}
		}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(b, &multi); err != nil {
		return err
	}
	*s = multi
	return nil
}

// conditionBlock is operator -> condition key -> the key's STRING values, e.g.
// {"StringEquals": {"token.actions.githubusercontent.com:sub": ["repo:org/repo:*"]}}.
//
// It is a READING AID for subject claims, never the stored condition: the
// statement keeps its Condition verbatim (TrustStatement.Condition). A value
// that is not a string -- {"Bool": {"aws:MultiFactorAuthPresent": true}},
// {"NumericLessThan": {"aws:MultiFactorAuthAge": 3600}} -- is simply not a
// subject claim, so it is left out here instead of failing the document. That
// failure is exactly what T3.4's gate names.
type conditionBlock map[string]map[string]stringOrSlice

// decodeConditions validates a Condition block's SHAPE -- an object of
// operators, each an object of keys -- and collects its string values. Only a
// wrong shape is an error.
func decodeConditions(raw json.RawMessage) (conditionBlock, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var ops map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &ops); err != nil {
		return nil, fmt.Errorf("Condition: %v", err)
	}
	out := make(conditionBlock, len(ops))
	for op, keys := range ops {
		kv := make(map[string]stringOrSlice, len(keys))
		for key, v := range keys {
			var vals stringOrSlice
			if err := json.Unmarshal(v, &vals); err == nil {
				kv[key] = vals
			}
			// A boolean, number or null value: kept verbatim in the raw
			// condition, not a string claim. Not an error.
		}
		out[op] = kv
	}
	return out, nil
}

// negatedOperator reports whether an IAM condition operator states what must
// NOT match. "StringNotEquals" and "StringNotLike" exclude their values; the
// "IfExists" suffix and "ForAnyValue:"/"ForAllValues:" prefixes do not change
// that, so the test is on the operator body.
func negatedOperator(op string) bool {
	return strings.Contains(operatorBody(op), "Not")
}

// operatorBody strips the set-operator prefix and the IfExists suffix.
func operatorBody(op string) string {
	if i := strings.LastIndex(op, ":"); i >= 0 {
		op = op[i+1:]
	}
	return strings.TrimSuffix(op, "IfExists")
}

// stringOperator reports whether op compares strings -- the only operators
// whose values can be subject claims. {"Null": {"x:sub": "false"}} says the key
// is PRESENT; reading "false" as a subject would name a principal that does
// not exist.
func stringOperator(op string) bool {
	return strings.HasPrefix(operatorBody(op), "String")
}

// subValues returns every value a POSITIVE string operator requires of a key
// accepted by match, in a deterministic order (operators, then keys, sorted;
// values in document order; duplicates removed), and whether a NEGATIVE one
// named such a key.
//
// The operator is load-bearing. Reading the value under StringNotEquals as
// though it were StringEquals asserts a trust relationship the policy exists
// to forbid -- "anyone except repo:acme/deploy" would be recorded as
// "repo:acme/deploy", naming the one principal that cannot assume the role.
// And the order is load-bearing too: these values become source keys, and a
// Go map's iteration order would re-key the edge between runs.
func (c conditionBlock) subValues(match func(key string) bool) (values []string, negated bool) {
	ops := make([]string, 0, len(c))
	for op := range c {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	seen := map[string]bool{}
	for _, op := range ops {
		if !stringOperator(op) {
			continue
		}
		keys := make([]string, 0, len(c[op]))
		for k := range c[op] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if !match(key) || len(c[op][key]) == 0 {
				continue
			}
			if negatedOperator(op) {
				negated = true
				continue
			}
			for _, v := range c[op][key] {
				if !seen[v] {
					seen[v] = true
					values = append(values, v)
				}
			}
		}
	}
	return values, negated
}

// subClaim is the legacy single-subject reading: the FIRST subject a positive
// operator requires under any ":sub" key, and whether a negative one was
// present. A negative condition yields no subject and sets negated, so the
// caller records an unscoped federation rather than a confident wrong one.
func (c conditionBlock) subClaim() (sub string, negated bool) {
	values, negated := c.subValues(func(key string) bool {
		return strings.HasSuffix(strings.ToLower(key), ":sub")
	})
	if len(values) > 0 {
		sub = values[0]
	}
	return sub, negated
}

/* ------------------------------ the statement ----------------------------- */

// TrustPrincipalEntry is one entry of a statement's Principal, verbatim: its
// type (AWS, Service, Federated, or the literal "*") and its value.
type TrustPrincipalEntry struct {
	Type  string
	Value string
}

// TrustStatement is one statement of a trust document, normalised.
//
// Every field AWS uses to decide who may assume the role is kept, because a
// trust statement stripped of its conditions reads as broader than it is.
// Nothing here is evaluated.
type TrustStatement struct {
	// Index is the statement's position in the ORIGINAL document, counting
	// statements that could not be used; descriptive, never identity.
	Index int
	// Sid is the statement id where the author set one.
	Sid string
	// Effect is lowercased: "allow" | "deny", the same convention as
	// PolicyStatement. A Deny is a restriction on the role, never a
	// relationship (§2.2).
	Effect     string
	Actions    []string
	NotActions []string
	// Principals are the entries of Principal. NotPrincipal entries are NEVER
	// here: "everyone except X" names no principal we could draw an edge from.
	Principals []TrustPrincipalEntry
	// NotPrincipal is the NotPrincipal element, compact and verbatim, or nil.
	// Recorded so the role can say it uses NotPrincipal (§4.7:
	// trust_has_not_principal); never resolved.
	NotPrincipal json.RawMessage
	// Condition is the Condition block, compact and verbatim, or nil when the
	// statement had none -- stored as iga_relationship.conditions (NULL = no
	// Condition, 031). Recorded, never evaluated.
	Condition json.RawMessage
	// Raw is the statement exactly as the document carried it, compacted.
	Raw json.RawMessage

	cond conditionBlock
}

// HasNotPrincipal reports whether the statement uses NotPrincipal.
func (s TrustStatement) HasNotPrincipal() bool { return len(s.NotPrincipal) > 0 }

// ContentHash is the statement's content identity for a Sid-less trust
// statement key (§2.6 applied to trust, P2-DECISIONS D-46): SHA-256 over the
// canonical JSON of Effect, Principal, NotPrincipal, Action, NotAction and
// Condition. Principal IS hashed -- a trust statement has no Resource, and
// its principals are what it says. Sid is not: a Sid-keyed statement keeps its
// identity across edits.
func (s TrustStatement) ContentHash() string {
	principals := map[string][]string{}
	for _, p := range s.Principals {
		principals[p.Type] = append(principals[p.Type], p.Value)
	}
	for t := range principals {
		principals[t] = canonicalList(principals[t])
	}
	canon := map[string]any{
		"Effect":    strings.ToLower(s.Effect),
		"Principal": principals, // json.Marshal sorts map keys
		"Action":    canonicalList(s.Actions),
		"NotAction": canonicalList(s.NotActions),
	}
	for name, raw := range map[string]json.RawMessage{"NotPrincipal": s.NotPrincipal, "Condition": s.Condition} {
		if len(raw) == 0 {
			continue
		}
		var v any
		if err := json.Unmarshal(raw, &v); err == nil {
			canon[name] = v
		} else {
			canon[name] = string(raw)
		}
	}
	b, _ := json.Marshal(canon)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// allows reports whether the statement's Action / NotAction permits one STS
// action. IAM action patterns: case-insensitive, with * and ? wildcards. A
// NotAction statement allows every action it does not exclude.
func (s TrustStatement) allows(action string) bool {
	if len(s.NotActions) > 0 {
		for _, pat := range s.NotActions {
			if actionMatches(pat, action) {
				return false
			}
		}
		return true
	}
	for _, pat := range s.Actions {
		if actionMatches(pat, action) {
			return true
		}
	}
	return false
}

func actionMatches(pattern, action string) bool {
	return wildcardMatch(strings.ToLower(pattern), strings.ToLower(action))
}

// wildcardMatch is IAM's glob: * matches any run, ? any one character.
func wildcardMatch(pattern, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// TrustSubject is one principal a statement names, normalised to the far
// endpoint it identifies (P2-DECISIONS D-42) and the mechanism by which it may
// assume the role (D-43).
type TrustSubject struct {
	// Entry is the principal entry this subject came from, verbatim.
	Entry TrustPrincipalEntry
	// Kind is the external-principal kind (034): aws_account, aws_principal,
	// aws_service, oidc, saml or k8s_service_account.
	Kind string
	// Issuer and Subject are the far endpoint's identity (iga_external_principal
	// issuer / subject_claim). Together they are its recognition key, and the
	// edge's (D-41): a principal that later resolves to an identity keeps them.
	Issuer  string
	Subject string
	// Account is the AWS account the principal names, when it names one.
	Account string
	// IdentityARN is set when the principal is the exact ARN of an IAM role or
	// user -- the one form that may be an identity in the workspace (§4.7).
	// Session ARNs, unique ids and "*" never are.
	IdentityARN string
	// Mechanism is how it may assume the role: sts_assume_role,
	// oidc_federation or saml_federation.
	Mechanism string
	// Wildcard reports that Subject is a pattern (or "*"): it names a set of
	// principals, never one, and never resolves (§2.12).
	Wildcard bool
}

// Subjects returns every principal this statement names, one per far endpoint,
// in a deterministic order. A federated principal yields one subject per
// positive `sub` value, or one unscoped "*" subject when there is none. A
// principal whose type the statement's actions cannot serve -- a Federated
// principal under sts:AssumeRole alone, anything under sts:TagSession alone --
// yields nothing: the statement permits no assumption by it (D-43).
//
// Callers decide what an effect means; a Deny statement's subjects are what it
// denies, never who may assume the role.
func (s TrustStatement) Subjects() []TrustSubject {
	federated := 0
	for _, p := range s.Principals {
		if p.Type == PrincipalFederated {
			federated++
		}
	}
	var out []TrustSubject
	seen := map[string]bool{}
	add := func(sub TrustSubject) {
		sub.Wildcard = sub.Subject == "*" || strings.ContainsAny(sub.Subject, "*?")
		k := sub.Issuer + "\x00" + sub.Subject
		if !seen[k] {
			seen[k] = true
			out = append(out, sub)
		}
	}
	for _, p := range s.Principals {
		switch p.Type {
		case PrincipalAnyone:
			// Anyone at all: the mechanism is the first assume action allowed.
			mech := ""
			for _, m := range []struct{ action, mech string }{
				{actionAssumeRole, MechanismSTSAssumeRole},
				{actionAssumeRoleWebIdentity, MechanismOIDCFederation},
				{actionAssumeRoleSAML, MechanismSAMLFederation},
			} {
				if s.allows(m.action) {
					mech = m.mech
					break
				}
			}
			if mech != "" {
				add(TrustSubject{Entry: p, Kind: ExternalAWSPrincipal, Issuer: IssuerAWS, Subject: "*", Mechanism: mech})
			}
		case PrincipalAWS:
			if s.allows(actionAssumeRole) {
				sub := classifyAWSEntry(p.Value)
				sub.Entry, sub.Mechanism = p, MechanismSTSAssumeRole
				add(sub)
			}
		case PrincipalService:
			if s.allows(actionAssumeRole) {
				add(TrustSubject{Entry: p, Kind: ExternalAWSService, Issuer: IssuerAWS, Subject: p.Value,
					Mechanism: MechanismSTSAssumeRole})
			}
		case PrincipalFederated:
			for _, sub := range s.federatedSubjects(p, federated == 1) {
				add(sub)
			}
		}
	}
	return out
}

// federatedSubjects classifies one Federated entry: an OIDC provider ARN (its
// issuer is the host after ":oidc-provider/"), a SAML provider ARN (its issuer
// is the ARN itself), or a named web-identity provider such as
// accounts.google.com or cognito-identity.amazonaws.com (its issuer is the
// name). The subjects are the positive `sub` values the conditions require of
// that issuer -- or "*" when there are none, or only negative ones.
//
// `alone` is whether this is the statement's only Federated entry. Then any
// "…:sub" key is unambiguously about it; with two, only a key naming its own
// issuer is.
func (s TrustStatement) federatedSubjects(p TrustPrincipalEntry, alone bool) []TrustSubject {
	base := TrustSubject{Entry: p, Kind: ExternalOIDC, Issuer: p.Value, Mechanism: MechanismOIDCFederation}
	action := actionAssumeRoleWebIdentity
	prefix := ""
	switch {
	case strings.Contains(p.Value, ":saml-provider/"):
		base.Kind, base.Mechanism, action, prefix = ExternalSAML, MechanismSAMLFederation, actionAssumeRoleSAML, "saml"
		base.Account = arnAccount(p.Value)
	case strings.Contains(p.Value, ":oidc-provider/") && oidcIssuerFromARN(p.Value) != "":
		base.Issuer = oidcIssuerFromARN(p.Value)
		base.Account = arnAccount(p.Value)
		prefix = base.Issuer
	default:
		prefix = p.Value
	}
	if !s.allows(action) {
		return nil
	}
	want := strings.ToLower(prefix) + ":sub"
	values, _ := s.cond.subValues(func(key string) bool {
		k := strings.ToLower(key)
		return k == want || (alone && strings.HasSuffix(k, ":sub"))
	})
	if len(values) == 0 {
		// No usable sub condition: none was present, or the only ones present
		// were negative and name principals that may NOT assume the role.
		// Either way the federation is not scoped to one subject we can name,
		// and is recorded as unscoped -- a finding, never a silence.
		values = []string{"*"}
	}
	out := make([]TrustSubject, 0, len(values))
	for _, v := range values {
		sub := base
		sub.Subject = v
		if sub.Kind == ExternalOIDC && k8sSubjectPattern.MatchString(v) && !strings.ContainsAny(v, "*?") {
			// IRSA. The same service account an EKS Pod Identity association
			// binds: one node, whichever way it assumes the role (D-42).
			sub.Kind = ExternalK8sSA
		}
		out = append(out, sub)
	}
	return out
}

// classifyAWSEntry normalises one Principal.AWS value (D-42): an account --
// bare id or :root ARN, one node either way -- is aws_account; anything else
// is aws_principal, and only the exact ARN of an IAM role or user may resolve
// to an identity. A unique id (AROA…, AIDA…) is what AWS writes into a trust
// policy once the principal it named is deleted; a session ARN names a
// session. Neither is an identity, so neither ever resolves.
func classifyAWSEntry(v string) TrustSubject {
	switch {
	case v == "*":
		return TrustSubject{Kind: ExternalAWSPrincipal, Issuer: IssuerAWS, Subject: "*"}
	case accountIDPattern.MatchString(v):
		return TrustSubject{Kind: ExternalAWSAccount, Issuer: IssuerAWS, Subject: v, Account: v}
	}
	if m := accountRootPattern.FindStringSubmatch(v); m != nil {
		return TrustSubject{Kind: ExternalAWSAccount, Issuer: IssuerAWS, Subject: m[1], Account: m[1]}
	}
	sub := TrustSubject{Kind: ExternalAWSPrincipal, Issuer: IssuerAWS, Subject: v, Account: arnAccount(v)}
	if acct, ok := IdentityPrincipalARN(v); ok {
		sub.Account, sub.IdentityARN = acct, v
	}
	return sub
}

// IdentityPrincipalARN reports whether s is the exact ARN of an IAM role or
// user, and its account: arn:<partition>:iam::<account>:role/... or :user/....
func IdentityPrincipalARN(s string) (account string, ok bool) {
	parts := strings.SplitN(s, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" || !accountIDPattern.MatchString(parts[4]) {
		return "", false
	}
	if strings.HasPrefix(parts[5], "role/") || strings.HasPrefix(parts[5], "user/") {
		return parts[4], true
	}
	return "", false
}

// arnAccount returns an ARN's account field when it is a 12-digit account.
func arnAccount(s string) string {
	parts := strings.SplitN(s, ":", 6)
	if len(parts) == 6 && parts[0] == "arn" && accountIDPattern.MatchString(parts[4]) {
		return parts[4]
	}
	return ""
}

/* ------------------------------- the document ----------------------------- */

// TrustDocument is a parsed trust policy: the statements it could read, and
// the ones it could not.
type TrustDocument struct {
	Statements []TrustStatement
	// Skipped names every statement that could not be read, by index and
	// reason. Isolated, so its neighbours still parse -- but NOT harmless: a
	// document with a skipped statement is unreadable (D-45), because what the
	// skipped statement declared before would otherwise look absent.
	Skipped []TrustStatementError
}

// TrustStatementError is one statement that could not be read.
type TrustStatementError struct {
	Index  int
	Reason string
}

// HasDeny reports whether any statement is a Deny (provider_attrs.trust_has_deny).
func (d *TrustDocument) HasDeny() bool {
	for _, st := range d.Statements {
		if st.Effect == "deny" {
			return true
		}
	}
	return false
}

// HasNotPrincipal reports whether any statement uses NotPrincipal
// (provider_attrs.trust_has_not_principal).
func (d *TrustDocument) HasNotPrincipal() bool {
	for _, st := range d.Statements {
		if st.HasNotPrincipal() {
			return true
		}
	}
	return false
}

// ParseTrustDocument reads every statement of a role's decoded trust document,
// Allow AND Deny, with conditions kept verbatim (T3.4).
//
// A document that is not a JSON object with a Statement returns
// ErrMalformedPolicy: "trusts nobody" and "could not be read" are different
// answers. A statement that cannot be read is isolated -- skipped and named in
// Skipped, with its index and reason -- so one malformed statement does not
// hide what the others say.
func ParseTrustDocument(doc json.RawMessage) (*TrustDocument, error) {
	if len(bytes.TrimSpace(doc)) == 0 {
		return nil, fmt.Errorf("%w: empty trust document", ErrMalformedPolicy)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedPolicy, err)
	}
	stmt := bytes.TrimSpace(top["Statement"])
	if len(stmt) == 0 || string(stmt) == "null" {
		return nil, fmt.Errorf("%w: no Statement", ErrMalformedPolicy)
	}
	var raws []json.RawMessage
	switch stmt[0] {
	case '{':
		raws = []json.RawMessage{stmt}
	case '[':
		if err := json.Unmarshal(stmt, &raws); err != nil {
			return nil, fmt.Errorf("%w: Statement: %v", ErrMalformedPolicy, err)
		}
	default:
		return nil, fmt.Errorf("%w: Statement is neither an object nor a list", ErrMalformedPolicy)
	}

	out := &TrustDocument{}
	for i, raw := range raws {
		st, err := parseTrustStatement(i, raw)
		if err != nil {
			out.Skipped = append(out.Skipped, TrustStatementError{Index: i, Reason: err.Error()})
			continue
		}
		out.Statements = append(out.Statements, st)
	}
	return out, nil
}

type rawTrustStatement struct {
	Sid          json.RawMessage `json:"Sid"`
	Effect       json.RawMessage `json:"Effect"`
	Principal    json.RawMessage `json:"Principal"`
	NotPrincipal json.RawMessage `json:"NotPrincipal"`
	Action       json.RawMessage `json:"Action"`
	NotAction    json.RawMessage `json:"NotAction"`
	Condition    json.RawMessage `json:"Condition"`
}

// present treats an absent member and an explicit null alike.
func present(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && string(t) != "null"
}

// parseTrustStatement reads one statement, or says why it cannot. Every
// element is decoded on its own terms: a Principal block that fails to decode
// is a failed statement, never a statement that names nobody.
func parseTrustStatement(index int, raw json.RawMessage) (TrustStatement, error) {
	var r rawTrustStatement
	if err := json.Unmarshal(raw, &r); err != nil {
		return TrustStatement{}, fmt.Errorf("not an object: %v", err)
	}
	st := TrustStatement{Index: index, Raw: json.RawMessage(compactJSON(raw))}

	if present(r.Sid) {
		if err := json.Unmarshal(r.Sid, &st.Sid); err != nil {
			return st, fmt.Errorf("Sid: %v", err)
		}
	}
	var effect string
	if !present(r.Effect) {
		return st, errors.New("no Effect")
	}
	if err := json.Unmarshal(r.Effect, &effect); err != nil {
		return st, fmt.Errorf("Effect: %v", err)
	}
	switch strings.ToLower(effect) {
	case "allow", "deny":
		st.Effect = strings.ToLower(effect)
	default:
		return st, fmt.Errorf("Effect %q is neither Allow nor Deny", effect)
	}

	switch {
	case present(r.Action) && present(r.NotAction):
		return st, errors.New("both Action and NotAction")
	case present(r.Action):
		a, err := decodeActions("Action", r.Action)
		if err != nil {
			return st, err
		}
		st.Actions = a
	case present(r.NotAction):
		a, err := decodeActions("NotAction", r.NotAction)
		if err != nil {
			return st, err
		}
		st.NotActions = a
	default:
		return st, errors.New("neither Action nor NotAction")
	}

	switch {
	case present(r.Principal) && present(r.NotPrincipal):
		return st, errors.New("both Principal and NotPrincipal")
	case present(r.Principal):
		entries, err := decodePrincipalBlock(r.Principal)
		if err != nil {
			return st, fmt.Errorf("Principal: %v", err)
		}
		st.Principals = entries
	case present(r.NotPrincipal):
		// Validated like Principal, stored verbatim, never emitted as
		// principals.
		if _, err := decodePrincipalBlock(r.NotPrincipal); err != nil {
			return st, fmt.Errorf("NotPrincipal: %v", err)
		}
		st.NotPrincipal = json.RawMessage(compactJSON(r.NotPrincipal))
	default:
		return st, errors.New("neither Principal nor NotPrincipal")
	}

	if present(r.Condition) {
		cond, err := decodeConditions(r.Condition)
		if err != nil {
			return st, err
		}
		st.cond = cond
		st.Condition = json.RawMessage(compactJSON(r.Condition))
	}
	return st, nil
}

// decodeActions reads an Action or NotAction element: a string or a list of
// strings, naming at least one action.
func decodeActions(name string, raw json.RawMessage) ([]string, error) {
	var a stringOrSlice
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	if len(a) == 0 {
		return nil, fmt.Errorf("%s: names no action", name)
	}
	return a, nil
}

// decodePrincipalBlock reads the two shapes AWS allows: the literal "*", or an
// object whose AWS / Service / Federated members are a string or a list of
// strings. Anything else -- another key (CanonicalUser has no meaning in a
// trust policy), a non-string entry, an empty block -- is an error, not a
// principal quietly dropped.
func decodePrincipalBlock(raw json.RawMessage) ([]TrustPrincipalEntry, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s != "*" {
			return nil, fmt.Errorf("the only string form is \"*\", got %q", s)
		}
		return []TrustPrincipalEntry{{Type: PrincipalAnyone, Value: "*"}}, nil
	}
	var block map[string]json.RawMessage
	if err := json.Unmarshal(raw, &block); err != nil {
		return nil, err
	}
	for k := range block {
		switch k {
		case PrincipalAWS, PrincipalService, PrincipalFederated:
		default:
			return nil, fmt.Errorf("unsupported principal type %q", k)
		}
	}
	var out []TrustPrincipalEntry
	// A fixed type order: a Go map would reorder the entries between runs.
	for _, typ := range []string{PrincipalAWS, PrincipalService, PrincipalFederated} {
		v, ok := block[typ]
		if !ok || !present(v) {
			continue
		}
		var vals stringOrSlice
		if err := json.Unmarshal(v, &vals); err != nil {
			return nil, fmt.Errorf("%s: %v", typ, err)
		}
		for _, val := range vals {
			if strings.TrimSpace(val) == "" {
				return nil, fmt.Errorf("%s: empty entry", typ)
			}
			out = append(out, TrustPrincipalEntry{Type: typ, Value: val})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("names no principal")
	}
	return out, nil
}

// ValidateTrustDocument is the collector's readability check for a role's
// trust document (T3.3/T3.4, P2-DECISIONS D-45): "" when every statement
// parses, otherwise the reason, written to cloud_identity.trust_parse_error so
// the projector protects the role's trust edges instead of ending them.
//
// It runs ParseTrustDocument -- the parser the projector re-runs -- so
// "readable at collection" and "readable at projection" are one decision. ANY
// skipped statement makes the document unreadable: the projector would
// otherwise confirm its neighbours and end what the skipped statement declared
// before, which is ending what could not be read.
func ValidateTrustDocument(doc json.RawMessage) string {
	parsed, err := ParseTrustDocument(doc)
	if err != nil {
		return "parse: " + strings.TrimPrefix(err.Error(), ErrMalformedPolicy.Error()+": ")
	}
	if n := len(parsed.Skipped); n > 0 {
		reasons := make([]string, 0, n)
		for _, s := range parsed.Skipped {
			reasons = append(reasons, fmt.Sprintf("statement index %d: %s", s.Index, s.Reason))
		}
		return fmt.Sprintf("parse: %d statement(s) unusable: %s", n, strings.Join(reasons, "; "))
	}
	return ""
}

// ReadTrustDocument is what a collector records for one role's decoded
// AssumeRolePolicyDocument: the document verbatim, its SHA-256, and
// ValidateTrustDocument's verdict. A document that is not JSON at all is
// returned as nil -- it cannot be stored as JSON -- with its reason, so the
// role is unreadable rather than a role that trusts nobody. One that IS JSON is
// returned even when a statement in it is unusable: the stored document is
// what AWS said, and the reason says why it could not be read.
func ReadTrustDocument(decoded string) (doc json.RawMessage, sha256Hex, parseError string) {
	raw := json.RawMessage(decoded)
	if strings.TrimSpace(decoded) != "" && json.Valid(raw) {
		doc = raw
		sum := sha256.Sum256(raw)
		sha256Hex = hex.EncodeToString(sum[:])
	} else if strings.TrimSpace(decoded) != "" {
		return nil, "", "parse: the trust document is not JSON"
	}
	return doc, sha256Hex, ValidateTrustDocument(doc)
}

/* --------------------- the legacy cloud_assume_edge view ------------------ */

// TrustPrincipal is one Allow principal, flattened into cloud_assume_edge's
// vocabulary: the shape the legacy writer (Cloud Inventory, §1.5) records.
type TrustPrincipal struct {
	SubjectKind string
	Subject     string
	// Issuer is "" unless the principal is federated.
	Issuer string
	// K8sRef is set only when SubjectKind is SubjectKindK8sSA, format
	// system:serviceaccount:<ns>:<sa>.
	K8sRef    string
	Mechanism string
}

// ParseTrustPolicy flattens a role's decoded AssumeRolePolicyDocument into the
// Allow principals cloud_assume_edge records. Deny statements and NotPrincipal
// are not that table's concern; the graph reads them through
// ParseTrustDocument.
//
// Built on ParseTrustDocument, so the two read a document identically. A
// document with ANY unreadable statement is an error here too (D-45): the
// legacy writer counts it as a parse failure, which keeps its reconciliation
// from deleting what the unread statement declared.
func ParseTrustPolicy(doc string) ([]TrustPrincipal, error) {
	if strings.TrimSpace(doc) == "" {
		return nil, nil
	}
	parsed, err := ParseTrustDocument(json.RawMessage(doc))
	if err != nil {
		// Same rule as ParsePolicyDocument: a document we cannot read is a
		// coverage failure, not a role that trusts nobody.
		return nil, err
	}
	if len(parsed.Skipped) > 0 {
		return nil, fmt.Errorf("%w: %d statement(s) unusable", ErrMalformedPolicy, len(parsed.Skipped))
	}

	var out []TrustPrincipal
	for _, stmt := range parsed.Statements {
		if stmt.Effect != "allow" {
			continue
		}
		webIdentity := actionsInclude(stmt.Actions, "sts:assumerolewithwebidentity")
		out = append(out, legacyPrincipals(stmt, webIdentity)...)
	}
	return out, nil
}

func actionsInclude(actions []string, wantLower string) bool {
	for _, a := range actions {
		if strings.ToLower(a) == wantLower {
			return true
		}
	}
	return false
}

// legacyPrincipals keeps the legacy table's order: the wildcard, services,
// AWS principals, then federated principals.
func legacyPrincipals(stmt TrustStatement, webIdentity bool) []TrustPrincipal {
	var out []TrustPrincipal
	for _, typ := range []string{PrincipalAnyone, PrincipalService, PrincipalAWS, PrincipalFederated} {
		for _, p := range stmt.Principals {
			if p.Type != typ {
				continue
			}
			switch typ {
			case PrincipalAnyone:
				out = append(out, TrustPrincipal{
					SubjectKind: SubjectKindExternal, Subject: "*", Mechanism: MechanismSTSAssumeRole,
				})
			case PrincipalService:
				out = append(out, TrustPrincipal{
					SubjectKind: SubjectKindCloudService, Subject: p.Value, Mechanism: MechanismSTSAssumeRole,
				})
			case PrincipalAWS:
				out = append(out, TrustPrincipal{
					SubjectKind: classifyAWSPrincipal(p.Value), Subject: p.Value, Mechanism: MechanismSTSAssumeRole,
				})
			case PrincipalFederated:
				out = append(out, federatedPrincipal(p.Value, stmt.cond, webIdentity))
			}
		}
	}
	return out
}

// classifyAWSPrincipal splits Principal.AWS into a specific, known identity
// versus an unnamed "anyone in that account" grant -- the distinction the
// legacy schema's identity/external_account split exists for.
func classifyAWSPrincipal(principal string) string {
	if principal == "*" || accountIDPattern.MatchString(principal) ||
		accountRootPattern.MatchString(principal) {
		return SubjectKindExternal
	}
	return SubjectKindIdentity
}

// federatedPrincipal classifies a federation edge for the legacy table. The
// subject claim is the only signal that tells IRSA apart from any other
// OIDC-federated caller (GitHub Actions, GitLab CI, or a customer's own IdP)
// -- AWS does not label the provider by type.
func federatedPrincipal(providerARN string, cond conditionBlock, webIdentity bool) TrustPrincipal {
	issuer := oidcIssuerFromARN(providerARN)
	sub, _ := cond.subClaim()

	p := TrustPrincipal{Subject: providerARN, Issuer: issuer, Mechanism: MechanismSTSAssumeRole}
	if webIdentity {
		p.Mechanism = MechanismOIDCFederation
	}

	switch {
	case sub == "":
		// No usable sub condition -- either none was present, or the only
		// ones present were negative and name principals that may NOT assume
		// the role. Recorded as ci_pipeline rather than dropped: an unscoped
		// federation trust is a finding worth surfacing, not a reason to go
		// silent.
		p.SubjectKind = SubjectKindCIPipeline
	case k8sSubjectPattern.MatchString(sub):
		p.SubjectKind = SubjectKindK8sSA
		p.K8sRef = sub
		p.Subject = sub
	default:
		p.SubjectKind = SubjectKindCIPipeline
		p.Subject = sub
	}
	return p
}
