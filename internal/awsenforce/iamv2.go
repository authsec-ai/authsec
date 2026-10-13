package awsenforce

import (
	"context"
)

// Enforcement template v2 (SPEC-iga-phase3-policy.md §12.3, release R2):
// what the v2 enforcement role may do beyond v1, and the self-test
// capabilities that prove it. A v1 binding never sees any of this: its
// self-test runs exactly the §3.6 probes and its state is decided by
// Capabilities alone.
//
// DECISION R2-14: IAM has NO condition key that restricts
// iam:PutRolePolicy / iam:DeleteRolePolicy to an inline policy NAME (their
// resource is the role; the policy name and document are unconstrainable),
// so a PutRolePolicy grant on customer roles would let the enforcement role
// write any inline policy to any unprotected role (privilege escalation).
// Session revocation therefore uses an AuthSec-owned MANAGED deny policy
// under /authsec/ attached with iam:AttachRolePolicy, and v2 grants
// iam:AttachRolePolicy / iam:DetachRolePolicy on role/* ONLY with
// Condition ArnLike iam:PolicyARN = arn:<partition>:iam::<account>:policy/authsec/*
// -- the same /authsec/ scoping v1 uses for boundaries. v2 grants NO
// PutRolePolicy on customer roles; temporary grants are the same attach of
// an AuthSec policy.
//
// DECISION R2-15: direct Lambda split execution is in v2 only when the
// stack's EnableLambdaSplit parameter is 'true': iam:CreateRole (path
// /authsec/split/, request tag authsec:managed-by=authsec), iam:TagRole,
// iam:DeleteRole, iam:PutRolePolicy, iam:DeleteRolePolicy,
// iam:AttachRolePolicy, iam:DetachRolePolicy on role/authsec/split/* (any
// policy ARN: a split copies the source role's managed policies by ARN),
// iam:PassRole on role/* only to lambda.amazonaws.com (a revert passes the
// original source role back, which can be any role), and
// lambda:UpdateFunctionConfiguration on this account's functions. v1's
// path and tag protections are extended to every new role action, and a
// role under /authsec/split/ AuthSec did not tag is never changed.

// CreateRoleInput is a CreateRole request (an AuthSec split role).
type CreateRoleInput struct {
	Name, Path, TrustDocument, Description string
	Tags                                   map[string]string
}

// IAMv2 is the enforcement template v2 additions.
type IAMv2 interface {
	IAM
	AttachRolePolicy(ctx context.Context, roleName, policyARN string) error
	DetachRolePolicy(ctx context.Context, roleName, policyARN string) error
	PutRolePolicy(ctx context.Context, roleName, policyName, document string) error
	DeleteRolePolicy(ctx context.Context, roleName, policyName string) error
	CreateRole(ctx context.Context, in CreateRoleInput) (arn string, err error)
	DeleteRole(ctx context.Context, roleName string) error
	// UpdateFunctionRole sets $LATEST's execution role (lambda:UpdateFunctionConfiguration Role=roleARN) in the function ARN's region.
	UpdateFunctionRole(ctx context.Context, functionARN, roleARN string) error
}

// AsIAMv2 returns c as an IAMv2 when its implementation has the v2 methods.
// Whether AWS ALLOWS them is a property of the stack (template v2, and
// EnableLambdaSplit), proven by the self-test, not of the client.
func AsIAMv2(c IAM) (IAMv2, bool) {
	v2, ok := c.(IAMv2)
	return v2, ok
}

// The template v2 capabilities.
const (
	CapAttachAuthSecPolicy  = "attach_authsec_policy"
	CapRefusesForeignAttach = "refuses_foreign_attach"
	CapDetachAuthSecPolicy  = "detach_authsec_policy"
	CapSplitRoleLifecycle   = "split_role_lifecycle"
	CapUpdateFunctionRole   = "update_function_role"
)

// CapabilitiesV2 lists every template v2 capability in probe order. They are
// stored beside the §3.6 ones in a v2 binding's capabilities, but never
// decide the binding's state (Report.State reads Capabilities only).
var CapabilitiesV2 = []string{
	CapAttachAuthSecPolicy, CapRefusesForeignAttach, CapDetachAuthSecPolicy,
	CapSplitRoleLifecycle, CapUpdateFunctionRole,
}

// The R2 features a v2 binding's capabilities enable.
const (
	FeatureTemporaryGrants = "temporary_grants"
	FeatureSessionRevoke   = "session_revoke"
	FeatureLambdaSplit     = "lambda_split"
)

// ErrorCodeForeignAttachAccepted is the code recorded when AWS ACCEPTED the
// attachment of a non-AuthSec policy that refuses_foreign_attach must see
// refused (as ErrorCodeForeignBoundaryAccepted for boundaries).
const ErrorCodeForeignAttachAccepted = "ForeignAttachAccepted"

// V2CapabilitiesFor lists the capabilities a feature needs, in probe order;
// nil for an unknown feature.
//
// Temporary grants and session revocation both create an AuthSec policy,
// attach it to a role, and later detach and delete it; the attach condition
// must refuse a foreign policy. A Lambda split needs the split-role
// lifecycle. update_function_role is never probed by the self-test (it has
// no function), so no feature requires it to be ok here: the first direct
// split proves it.
func V2CapabilitiesFor(feature string) []string {
	switch feature {
	case FeatureTemporaryGrants, FeatureSessionRevoke:
		return []string{CapCreatePolicy, CapDeletePolicy, CapAttachAuthSecPolicy, CapRefusesForeignAttach, CapDetachAuthSecPolicy}
	case FeatureLambdaSplit:
		return []string{CapSplitRoleLifecycle}
	default:
		return nil
	}
}

// MissingV2Capabilities lists the capabilities feature needs that are not ok
// in caps, each as "name: status (code)" like Report.Failing (a capability
// absent from caps is "name: untested"). An unknown feature returns
// []string{"unknown feature"}; a nil or empty result means none is missing.
func MissingV2Capabilities(caps map[string]CapabilityResult, feature string) []string {
	need := V2CapabilitiesFor(feature)
	if need == nil {
		return []string{"unknown feature"}
	}
	return failingOf(caps, need)
}

// FailingV2 lists the template v2 capabilities that are not ok, in probe
// order, as Failing does for the §3.6 ones. It is empty for a v1 self-test
// only in the sense that every v2 capability is then reported missing
// ("name: untested"): callers ask it of v2 bindings.
func (r Report) FailingV2() []string {
	return failingOf(r.Capabilities, CapabilitiesV2)
}

// failingOf is Failing over an explicit capability list.
func failingOf(caps map[string]CapabilityResult, names []string) []string {
	var out []string
	for _, c := range names {
		res, ok := caps[c]
		if !ok {
			out = append(out, c+": "+StatusUntested)
			continue
		}
		if res.Status == StatusOK {
			continue
		}
		s := c + ": " + res.Status
		if res.ErrorCode != "" {
			s += " (" + res.ErrorCode + ")"
		}
		out = append(out, s)
	}
	return out
}
