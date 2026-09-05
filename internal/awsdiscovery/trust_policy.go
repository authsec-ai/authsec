package awsdiscovery

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Trust-policy parsing: turning a role's AssumeRolePolicyDocument into the
// principals that may assume it.
//
// This file knows AWS and nothing about AuthSec, same as iam.go. The string
// values below are chosen to equal the cloud_assume_edge schema's enum values
// exactly, so the service layer can write them through unchanged -- but this
// package does not import models to enforce that, since it must not know
// AuthSec's persistence shapes. The two must be kept in step by hand; a
// mismatch fails loudly as a CHECK constraint violation on write, not
// silently.
const (
	SubjectKindCloudService = "cloud_service"
	SubjectKindIdentity     = "identity"
	SubjectKindK8sSA        = "k8s_service_account"
	SubjectKindCIPipeline   = "ci_pipeline"
	SubjectKindExternal     = "external_account"

	MechanismSTSAssumeRole  = "sts_assume_role"
	MechanismOIDCFederation = "oidc_federation"
)

// TrustPrincipal is one principal from a trust policy, classified.
type TrustPrincipal struct {
	SubjectKind string
	Subject     string
	// Issuer is "" unless Mechanism is MechanismOIDCFederation.
	Issuer string
	// K8sRef is set only when SubjectKind is SubjectKindK8sSA, format
	// system:serviceaccount:<ns>:<sa>.
	K8sRef    string
	Mechanism string
}

// accountIDPattern matches a bare 12-digit AWS account id, the shape AWS
// accepts as a Principal.AWS value meaning "anyone in this account".
var accountIDPattern = regexp.MustCompile(`^\d{12}$`)

// accountRootPattern matches an account root principal ARN.
var accountRootPattern = regexp.MustCompile(`^arn:[^:]+:iam::\d{12}:root$`)

// k8sSubjectPattern matches the IRSA subject claim shape. This is the ONLY
// signal that tells an IRSA federation apart from any other OIDC federation --
// AWS does not label it, the subject string is the only evidence.
var k8sSubjectPattern = regexp.MustCompile(`^system:serviceaccount:[^:]+:[^:]+$`)

// stringOrSlice unmarshals an IAM policy field that AWS allows to be written
// as either a single string or a list -- true of Principal.AWS,
// Principal.Service, Principal.Federated, Action, and every condition value.
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

type principalBlock struct {
	AWS       stringOrSlice `json:"AWS"`
	Service   stringOrSlice `json:"Service"`
	Federated stringOrSlice `json:"Federated"`
}

// conditionBlock is operator -> condition key -> value(s), e.g.
// {"StringEquals": {"token.actions.githubusercontent.com:sub": "repo:org/repo:*"}}.
type conditionBlock map[string]map[string]stringOrSlice

// subClaim returns the first condition value keyed on anything ending ":sub",
// across every operator. IAM does not care which comparison operator names the
// sub condition, and a trust policy uses exactly one in practice.
func (c conditionBlock) subClaim() string {
	for _, kv := range c {
		for key, values := range kv {
			if strings.HasSuffix(key, ":sub") && len(values) > 0 {
				return values[0]
			}
		}
	}
	return ""
}

type trustStatement struct {
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Action    stringOrSlice   `json:"Action"`
	Condition conditionBlock  `json:"Condition"`
}

// trustStatementList unmarshals Statement, which AWS allows to be a single
// object or an array of them.
type trustStatementList []trustStatement

func (l *trustStatementList) UnmarshalJSON(b []byte) error {
	var one trustStatement
	if err := json.Unmarshal(b, &one); err == nil && one.Effect != "" {
		*l = []trustStatement{one}
		return nil
	}
	var many []trustStatement
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*l = many
	return nil
}

type trustPolicyDocument struct {
	Statement trustStatementList `json:"Statement"`
}

// ParseTrustPolicy classifies every principal in a role's decoded
// AssumeRolePolicyDocument.
//
// Only Allow statements are read. A Deny in a trust policy describes who may
// NOT assume the role, which is not a positive edge this table records; it is
// vanishingly rare in practice and, unlike an IAM permission policy, has no
// resource or action fan-out to preserve, so nothing is lost by skipping it.
//
// A statement that fails to parse is skipped rather than failing the whole
// document: one malformed statement must not hide every principal AWS
// otherwise makes clear.
func ParseTrustPolicy(doc string) []TrustPrincipal {
	if strings.TrimSpace(doc) == "" {
		return nil
	}
	var parsed trustPolicyDocument
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return nil
	}

	var out []TrustPrincipal
	for _, stmt := range parsed.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		webIdentity := actionsInclude(stmt.Action, "sts:assumerolewithwebidentity")
		out = append(out, principalsFor(stmt, webIdentity)...)
	}
	return out
}

func actionsInclude(actions []string, wantLower string) bool {
	for _, a := range actions {
		if strings.ToLower(a) == wantLower {
			return true
		}
	}
	return false
}

func principalsFor(stmt trustStatement, webIdentity bool) []TrustPrincipal {
	block, wildcard := decodePrincipal(stmt.Principal)
	var out []TrustPrincipal

	if wildcard {
		out = append(out, TrustPrincipal{
			SubjectKind: SubjectKindExternal, Subject: "*", Mechanism: MechanismSTSAssumeRole,
		})
	}
	for _, svc := range block.Service {
		out = append(out, TrustPrincipal{
			SubjectKind: SubjectKindCloudService, Subject: svc, Mechanism: MechanismSTSAssumeRole,
		})
	}
	for _, aws := range block.AWS {
		out = append(out, TrustPrincipal{
			SubjectKind: classifyAWSPrincipal(aws), Subject: aws, Mechanism: MechanismSTSAssumeRole,
		})
	}
	for _, fed := range block.Federated {
		out = append(out, federatedPrincipal(fed, stmt.Condition, webIdentity))
	}
	return out
}

// decodePrincipal handles the two shapes AWS allows: the literal string "*"
// (wildcard is true), or an object naming Service/AWS/Federated principals.
func decodePrincipal(raw json.RawMessage) (block principalBlock, wildcard bool) {
	if len(raw) == 0 {
		return block, false
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return block, asString == "*"
	}
	_ = json.Unmarshal(raw, &block)
	return block, false
}

// classifyAWSPrincipal splits Principal.AWS into a specific, known identity
// versus an unnamed "anyone in that account" grant -- the distinction the
// schema's identity/external_account split exists for.
func classifyAWSPrincipal(principal string) string {
	if principal == "*" || accountIDPattern.MatchString(principal) ||
		accountRootPattern.MatchString(principal) {
		return SubjectKindExternal
	}
	return SubjectKindIdentity
}

// federatedPrincipal classifies an OIDC federation edge. The subject claim is
// the only signal that tells IRSA apart from any other OIDC-federated caller
// (GitHub Actions, GitLab CI, or a customer's own IdP) -- AWS does not label
// the provider by type.
func federatedPrincipal(providerARN string, cond conditionBlock, webIdentity bool) TrustPrincipal {
	issuer := oidcIssuerFromARN(providerARN)
	sub := cond.subClaim()

	p := TrustPrincipal{Subject: providerARN, Issuer: issuer, Mechanism: MechanismSTSAssumeRole}
	if webIdentity {
		p.Mechanism = MechanismOIDCFederation
	}

	switch {
	case sub == "":
		// No sub condition: the federation is not scoped to one principal.
		// Recorded as ci_pipeline rather than dropped -- an unscoped federation
		// trust is a finding worth surfacing, not a reason to go silent.
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
