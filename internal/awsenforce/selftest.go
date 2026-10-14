// Package awsenforce is the AWS side of Phase 3 enforcement
// (SPEC-iga-phase3-policy.md §3.5, §3.6, §4.4): what the enforcement role may
// do, and the binding self-test that proves it.
//
// T3.09 added the self-test: the probes of §3.6 run against the stack's own
// self-test role, classified per capability. T3.10 adds, beside this file,
// the deployment side: discovery-role reads into an igagov.LiveRead
// (reads.go, reads_live.go) and the enforcement-role writes of one
// deployment (deploy.go): request resolution and hashing, one call per
// attempt with SDK retries off, and the classification of what AWS answered.
//
// An adapter in the awsdiscovery sense: it knows AWS and nothing about
// AuthSec's database. The binding service (services/
// cloud_enforcement_binding_service.go) decides what a result means for the
// binding row.
package awsenforce

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

// The §3.6 capabilities, in probe order.
const (
	CapAssume                 = "assume"
	CapCreatePolicy           = "create_policy"
	CapVersionManagement      = "version_management"
	CapAttachBoundary         = "attach_boundary"
	CapRefusesForeignBoundary = "refuses_foreign_boundary"
	CapDetachBoundary         = "detach_boundary"
	CapDeletePolicy           = "delete_policy"
)

// Capabilities lists every §3.6 capability in probe order.
var Capabilities = []string{
	CapAssume, CapCreatePolicy, CapVersionManagement, CapAttachBoundary,
	CapRefusesForeignBoundary, CapDetachBoundary, CapDeletePolicy,
}

// Per-capability statuses (§3.6: ok | denied | error | untested).
const (
	StatusOK       = "ok"
	StatusDenied   = "denied"
	StatusError    = "error"
	StatusUntested = "untested"
)

// Binding states a self-test report decides (§3.6). They are the
// cloud_enforcement_binding.state values of the same names.
const (
	StateVerified = "verified"
	StatePartial  = "partial"
	StateError    = "error"
)

// ErrorCodeForeignBoundaryAccepted is the code recorded when AWS ACCEPTED the
// foreign boundary the refuses_foreign_boundary probe must be refused.
//
// DECISION (T3.09): §3.6 offers ok | denied | error | untested. "denied"
// would read as "AWS refused the capability", the opposite of what happened,
// so an accepted foreign boundary is `error` with this code.
const ErrorCodeForeignBoundaryAccepted = "ForeignBoundaryAccepted"

// CapabilityResult is one capability's outcome, as stored in
// cloud_enforcement_binding.capabilities.
type CapabilityResult struct {
	Status    string    `json:"status"`
	ErrorCode string    `json:"error_code,omitempty"`
	Message   string    `json:"message,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// Report is one self-test run.
type Report struct {
	Capabilities map[string]CapabilityResult `json:"capabilities"`
	// LeakedPolicyARN names the test policy when cleanup could not delete it
	// (for example because detach was denied). Empty when cleanup succeeded or
	// no policy was created.
	LeakedPolicyARN string    `json:"leaked_policy_arn,omitempty"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
}

// State is §3.6's rule: `verified` when every capability is ok, `error` when
// `assume` is not ok, `partial` otherwise. A capability missing from the
// report counts as not ok.
func (r Report) State() string {
	if r.Capabilities[CapAssume].Status != StatusOK {
		return StateError
	}
	for _, c := range Capabilities {
		if r.Capabilities[c].Status != StatusOK {
			return StatePartial
		}
	}
	return StateVerified
}

// Failing lists the capabilities that are not ok, in probe order, each as
// "name: status (code)".
func (r Report) Failing() []string {
	var out []string
	for _, c := range Capabilities {
		res, ok := r.Capabilities[c]
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

// IAM is the slice of IAM the enforcement role is granted (§3.6), as the
// self-test and the deployment writes (T3.10) use it. Every method is a
// single call with SDK retries off: a probe AWS refused must be reported, not
// retried into a different answer, and a mutation must never be re-signed and
// re-sent by the SDK without a write-ahead attempt (§8.1).
type IAM interface {
	CreatePolicy(ctx context.Context, in CreatePolicyInput) (arn string, err error)
	CreatePolicyVersion(ctx context.Context, policyARN, document string, setAsDefault bool) (versionID string, err error)
	DeletePolicyVersion(ctx context.Context, policyARN, versionID string) error
	PutRolePermissionsBoundary(ctx context.Context, roleName, boundaryARN string) error
	DeleteRolePermissionsBoundary(ctx context.Context, roleName string) error
	DeletePolicy(ctx context.Context, policyARN string) error
	// TagPolicy adds or overwrites tags on a policy (§3.2 authsec:change).
	TagPolicy(ctx context.Context, policyARN string, tags map[string]string) error
}

// CreatePolicyInput is a CreatePolicy request.
type CreatePolicyInput struct {
	Path     string
	Name     string
	Document string
	Tags     map[string]string
}

// Identity is what sts:GetCallerIdentity reported for the assumed session.
type Identity struct {
	AccountID string
	ARN       string
}

// AssumeInput is everything needed to become a binding's enforcement role
// (§4.4): the role, the ExternalId from Vault, the STS region, the session
// name. DurationSeconds is fixed at 900 by the implementation.
type AssumeInput struct {
	RoleARN     string
	ExternalID  string
	Region      string
	SessionName string
}

// Assumer assumes the enforcement role and proves the session with
// GetCallerIdentity. The live implementation is LiveAssumer; tests use a fake.
type Assumer interface {
	AssumeEnforcement(ctx context.Context, in AssumeInput) (IAM, *Identity, error)
}

// SelfTestInput is one binding's self-test.
type SelfTestInput struct {
	BindingID       uuid.UUID
	AccountID       string
	Partition       string // aws, aws-us-gov, aws-cn; empty is aws
	RoleARN         string
	SelfTestRoleARN string
	ExternalID      string
	Region          string
	// Now is the clock (tests). Nil is time.Now.
	Now func() time.Time
	// RunID distinguishes this run's test policy from a leaked earlier one.
	// Empty draws a random one.
	RunID string
	// TemplateV2 is true for a binding whose stack is enforcement template
	// v2 (awsdiscovery.IsEnforcementTemplateV2 of its template_version): the
	// CapabilitiesV2 probes run too (DECISION R2-14, R2-15). False is the
	// §3.6 self-test exactly as before.
	TemplateV2 bool
}

// SelfTestSessionName names the self-test's assumed session, so CloudTrail
// shows which binding's self-test made each call.
//
// DECISION (T3.09): §4.4 names deployment sessions authsec-enforce-<deployment
// id 16hex>; a self-test has no deployment, so it is
// authsec-enforce-selftest-<binding id 16hex>, which no deployment session name
// can equal.
func SelfTestSessionName(bindingID uuid.UUID) string {
	return "authsec-enforce-selftest-" + strings.ReplaceAll(bindingID.String(), "-", "")[:16]
}

// SelfTestPolicyName names the test policy of one run.
//
// DECISION (T3.09): §3.6 says AuthSecSelfTest-<binding id>; a run suffix is
// added because a run whose cleanup was refused (detach denied, so DeletePolicy
// hits DeleteConflict) leaves the policy behind, and the enforcement role can
// read nothing to adopt it -- a fixed name would make every later run fail
// create_policy with EntityAlreadyExists instead of reporting the real cause.
func SelfTestPolicyName(bindingID uuid.UUID, runID string) string {
	return "AuthSecSelfTest-" + bindingID.String() + "-" + runID
}

// SelfTestPolicyPath is the path of every AuthSec policy (§3.2).
const SelfTestPolicyPath = "/authsec/"

// selfTestDocument is the test boundary: it denies everything, so whatever it
// is attached to (only ever the inert self-test role) can do nothing.
func selfTestDocument(version int) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Sid":"AuthSecSelfTestV%d","Effect":"Deny","Action":"*","Resource":"*"}]}`, version)
}

// ForeignBoundaryARN is the AWS-managed policy the refuses_foreign_boundary
// probe tries to set (§3.6): any non-/authsec/ policy must be refused.
func ForeignBoundaryARN(partition string) string {
	if partition == "" {
		partition = "aws"
	}
	return "arn:" + partition + ":iam::aws:policy/ReadOnlyAccess"
}

// accessDeniedCodes are the authorization error codes AWS uses (§8.6).
var accessDeniedCodes = map[string]bool{
	"AccessDenied": true, "AccessDeniedException": true,
	"UnauthorizedOperation": true, "Client.UnauthorizedOperation": true,
}

// ErrorCode returns the AWS error code carried by err, or "" when it carries
// none (a transport error, a timeout).
func ErrorCode(err error) string {
	var api smithy.APIError
	if errors.As(err, &api) {
		return api.ErrorCode()
	}
	return ""
}

// IsAccessDenied reports whether err is an AWS authorization refusal.
func IsAccessDenied(err error) bool { return accessDeniedCodes[ErrorCode(err)] }

// classify maps one probe's error to a capability result.
func classify(err error, at time.Time) CapabilityResult {
	switch {
	case err == nil:
		return CapabilityResult{Status: StatusOK, CheckedAt: at}
	case IsAccessDenied(err):
		return CapabilityResult{Status: StatusDenied, ErrorCode: ErrorCode(err), Message: trimMessage(err), CheckedAt: at}
	default:
		code := ErrorCode(err)
		if code == "" {
			code = "Unknown"
			if errors.Is(err, context.DeadlineExceeded) {
				code = "Timeout"
			}
		}
		return CapabilityResult{Status: StatusError, ErrorCode: code, Message: trimMessage(err), CheckedAt: at}
	}
}

// trimMessage keeps an error message short enough for the capabilities blob.
// AWS error messages name the action and the resource, never a credential.
func trimMessage(err error) string {
	m := err.Error()
	if len(m) > 300 {
		m = m[:300] + "..."
	}
	return m
}

func untested(at time.Time, why string) CapabilityResult {
	return CapabilityResult{Status: StatusUntested, Message: why, CheckedAt: at}
}

// RunSelfTest runs the §3.6 probes, against the stack's self-test role only:
//
//	assume                    AssumeRole with the ExternalId; GetCallerIdentity account = binding's
//	create_policy             CreatePolicy /authsec/AuthSecSelfTest-<binding>-<run> with tags
//	version_management        CreatePolicyVersion (default) then DeletePolicyVersion v1
//	attach_boundary           PutRolePermissionsBoundary(self-test role, test policy)
//	refuses_foreign_boundary  PutRolePermissionsBoundary(self-test role, ReadOnlyAccess) must be AccessDenied
//	detach_boundary           DeleteRolePermissionsBoundary(self-test role)
//	delete_policy             DeletePolicy(test policy)
//
// A probe whose precondition failed is `untested` (no policy: nothing to
// version, attach or delete; no boundary attached: nothing to detach), with
// the reason. refuses_foreign_boundary needs no test policy and always runs
// once the role is assumed. Cleanup (detach, delete) is attempted whatever
// failed before it.
//
// With in.TemplateV2 the template v2 probes (runV2Probes) run between
// detach_boundary and delete_policy. They are recorded beside the §3.6
// capabilities but never change State or Failing, which read Capabilities
// only, so a binding's state machine is the same for v1 and v2.
func RunSelfTest(ctx context.Context, a Assumer, in SelfTestInput) Report {
	now := in.Now
	if now == nil {
		now = time.Now
	}
	rep := Report{Capabilities: map[string]CapabilityResult{}, StartedAt: now().UTC()}
	set := func(c string, r CapabilityResult) { rep.Capabilities[c] = r }
	finish := func() Report {
		for _, c := range Capabilities {
			if _, ok := rep.Capabilities[c]; !ok {
				set(c, untested(now().UTC(), "not run: the role could not be assumed"))
			}
		}
		if in.TemplateV2 {
			for _, c := range CapabilitiesV2 {
				if _, ok := rep.Capabilities[c]; !ok {
					set(c, untested(now().UTC(), "not run: the role could not be assumed"))
				}
			}
		}
		rep.FinishedAt = now().UTC()
		return rep
	}

	// assume
	iam, id, err := a.AssumeEnforcement(ctx, AssumeInput{
		RoleARN: in.RoleARN, ExternalID: in.ExternalID, Region: in.Region,
		SessionName: SelfTestSessionName(in.BindingID),
	})
	switch {
	case err != nil:
		set(CapAssume, classify(err, now().UTC()))
		return finish()
	case id == nil || id.AccountID != in.AccountID:
		got := ""
		if id != nil {
			got = id.AccountID
		}
		set(CapAssume, CapabilityResult{Status: StatusError, ErrorCode: "AccountMismatch",
			Message:   fmt.Sprintf("the session landed in account %s, the binding is for %s", got, in.AccountID),
			CheckedAt: now().UTC()})
		return finish()
	}
	set(CapAssume, CapabilityResult{Status: StatusOK, CheckedAt: now().UTC()})

	roleName, _, err := roleNameOf(in.SelfTestRoleARN)
	if err != nil {
		for _, c := range Capabilities[1:] {
			set(c, CapabilityResult{Status: StatusError, ErrorCode: "InvalidSelfTestRole", Message: err.Error(), CheckedAt: now().UTC()})
		}
		if in.TemplateV2 {
			for _, c := range CapabilitiesV2 {
				set(c, CapabilityResult{Status: StatusError, ErrorCode: "InvalidSelfTestRole", Message: err.Error(), CheckedAt: now().UTC()})
			}
		}
		return finish()
	}
	runID := in.RunID
	if runID == "" {
		runID = strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	}

	// create_policy
	policyARN, err := iam.CreatePolicy(ctx, CreatePolicyInput{
		Path: SelfTestPolicyPath, Name: SelfTestPolicyName(in.BindingID, runID), Document: selfTestDocument(1),
		Tags: map[string]string{"authsec:managed-by": "authsec", "authsec:selftest": in.BindingID.String()},
	})
	set(CapCreatePolicy, classify(err, now().UTC()))
	created := err == nil && policyARN != ""
	if err == nil && policyARN == "" {
		set(CapCreatePolicy, CapabilityResult{Status: StatusError, ErrorCode: "NoPolicyArn",
			Message: "CreatePolicy returned no ARN", CheckedAt: now().UTC()})
	}

	// version_management
	if created {
		_, verr := iam.CreatePolicyVersion(ctx, policyARN, selfTestDocument(2), true)
		if verr == nil {
			verr = iam.DeletePolicyVersion(ctx, policyARN, "v1")
		}
		set(CapVersionManagement, classify(verr, now().UTC()))
	} else {
		set(CapVersionManagement, untested(now().UTC(), "not run: no test policy was created"))
	}

	// attach_boundary
	attached := false
	if created {
		aerr := iam.PutRolePermissionsBoundary(ctx, roleName, policyARN)
		set(CapAttachBoundary, classify(aerr, now().UTC()))
		attached = aerr == nil
	} else {
		set(CapAttachBoundary, untested(now().UTC(), "not run: no test policy was created"))
	}

	// refuses_foreign_boundary
	ferr := iam.PutRolePermissionsBoundary(ctx, roleName, ForeignBoundaryARN(in.Partition))
	switch {
	case ferr == nil:
		set(CapRefusesForeignBoundary, CapabilityResult{Status: StatusError, ErrorCode: ErrorCodeForeignBoundaryAccepted,
			Message:   "AWS accepted a non-AuthSec permissions boundary; the attach condition does not restrict",
			CheckedAt: now().UTC()})
		// The foreign boundary replaced the test boundary. Put the test
		// boundary back so detach_boundary probes what it is meant to
		// (removing an AuthSec boundary), not the foreign one.
		if attached {
			attached = iam.PutRolePermissionsBoundary(ctx, roleName, policyARN) == nil
		}
	case IsAccessDenied(ferr):
		set(CapRefusesForeignBoundary, CapabilityResult{Status: StatusOK, ErrorCode: ErrorCode(ferr), CheckedAt: now().UTC()})
	default:
		set(CapRefusesForeignBoundary, classify(ferr, now().UTC()))
	}

	// detach_boundary
	if attached {
		set(CapDetachBoundary, classify(iam.DeleteRolePermissionsBoundary(ctx, roleName), now().UTC()))
	} else {
		set(CapDetachBoundary, untested(now().UTC(), "not run: no AuthSec test boundary is attached"))
	}

	// template v2: after detach_boundary and before delete_policy, so the
	// test policy is attached as a role policy and detached again before it
	// is deleted.
	if in.TemplateV2 {
		runV2Probes(ctx, iam, in, roleName, runID, policyARN, created, now, set)
	}

	// delete_policy
	if created {
		derr := iam.DeletePolicy(ctx, policyARN)
		set(CapDeletePolicy, classify(derr, now().UTC()))
		if derr != nil {
			rep.LeakedPolicyARN = policyARN
		}
	} else {
		set(CapDeletePolicy, untested(now().UTC(), "not run: no test policy was created"))
	}
	return finish()
}

// roleNameOf splits a role ARN into name and path without importing the
// discovery adapter's pattern twice.
func roleNameOf(arn string) (name, path string, err error) {
	const marker = ":role/"
	i := strings.Index(arn, marker)
	if !strings.HasPrefix(arn, "arn:") || i < 0 || i+len(marker) >= len(arn) {
		return "", "", fmt.Errorf("%q is not an IAM role ARN", arn)
	}
	rest := arn[i+len(marker):]
	j := strings.LastIndex(rest, "/")
	if j < 0 {
		return rest, "/", nil
	}
	return rest[j+1:], "/" + rest[:j+1], nil
}

// SelfTestSplitRolePath is the path of every AuthSec split role (DECISION
// R2-15); the split_role_lifecycle probe creates its throwaway role there.
const SelfTestSplitRolePath = "/authsec/split/"

// SelfTestSplitRoleName names the split_role_lifecycle probe's throwaway role
// of one run.
func SelfTestSplitRoleName(runID string) string { return "AuthSecSelfTestSplit-" + runID }

// selfTestSplitInlinePolicy names the inline policy the split_role_lifecycle
// probe puts on (and deletes from) its throwaway role.
const selfTestSplitInlinePolicy = "AuthSecSelfTestDenyAll"

// runV2Probes runs the template v2 probes (CapabilitiesV2), against the
// self-test role and the run's test policy only, plus one throwaway split
// role it creates and deletes itself:
//
//	attach_authsec_policy   AttachRolePolicy(self-test role, test policy)
//	refuses_foreign_attach  AttachRolePolicy(self-test role, ReadOnlyAccess) must be AccessDenied
//	detach_authsec_policy   DetachRolePolicy(self-test role, test policy)
//	split_role_lifecycle    CreateRole /authsec/split/AuthSecSelfTestSplit-<run>, PutRolePolicy,
//	                        DeleteRolePolicy, DeleteRole
//	update_function_role    never probed (the self-test has no Lambda function)
//
// A client without the v2 operations marks every v2 capability untested.
func runV2Probes(ctx context.Context, c IAM, in SelfTestInput, roleName, runID, policyARN string, created bool,
	now func() time.Time, set func(string, CapabilityResult)) {
	at := func() time.Time { return now().UTC() }
	v2, ok := AsIAMv2(c)
	if !ok {
		for _, cp := range CapabilitiesV2 {
			set(cp, untested(at(), "not run: the enforcement client has no template v2 operations"))
		}
		return
	}

	// attach_authsec_policy (DECISION R2-14: AttachRolePolicy scoped by
	// iam:PolicyARN to /authsec/).
	attached := false
	if created {
		err := v2.AttachRolePolicy(ctx, roleName, policyARN)
		set(CapAttachAuthSecPolicy, classify(err, at()))
		attached = err == nil
	} else {
		set(CapAttachAuthSecPolicy, untested(at(), "not run: no test policy was created"))
	}

	// refuses_foreign_attach: any non-/authsec/ policy must be refused.
	foreign := ForeignBoundaryARN(in.Partition)
	ferr := v2.AttachRolePolicy(ctx, roleName, foreign)
	switch {
	case ferr == nil:
		msg := "AWS accepted the attachment of a non-AuthSec policy; the attach condition does not restrict"
		// Take it off again at once (the self-test role denies everything
		// inline, so it granted nothing meanwhile).
		if derr := v2.DetachRolePolicy(ctx, roleName, foreign); derr != nil {
			msg += "; detaching it again failed (" + classify(derr, at()).ErrorCode + "): remove " + foreign + " from " + roleName + " by hand"
		}
		set(CapRefusesForeignAttach, CapabilityResult{Status: StatusError, ErrorCode: ErrorCodeForeignAttachAccepted,
			Message: msg, CheckedAt: at()})
	case IsAccessDenied(ferr):
		set(CapRefusesForeignAttach, CapabilityResult{Status: StatusOK, ErrorCode: ErrorCode(ferr), CheckedAt: at()})
	default:
		set(CapRefusesForeignAttach, classify(ferr, at()))
	}

	// detach_authsec_policy
	if attached {
		set(CapDetachAuthSecPolicy, classify(v2.DetachRolePolicy(ctx, roleName, policyARN), at()))
	} else {
		set(CapDetachAuthSecPolicy, untested(at(), "not run: the AuthSec test policy is not attached"))
	}

	// split_role_lifecycle (DECISION R2-15)
	set(CapSplitRoleLifecycle, splitRoleProbe(ctx, v2, in, runID, at))

	// update_function_role
	set(CapUpdateFunctionRole, untested(at(), "not probed: the self-test has no Lambda function; the first direct split proves it"))
}

// splitRoleProbe is split_role_lifecycle: create a throwaway split role that
// only this account's root may assume, put and delete a deny-all inline
// policy, delete the role. The result is the first error; a refused
// CreateRole is `denied` (the stack was deployed with EnableLambdaSplit
// 'false'). Cleanup is attempted whatever failed before it.
func splitRoleProbe(ctx context.Context, v2 IAMv2, in SelfTestInput, runID string, at func() time.Time) CapabilityResult {
	partition := in.Partition
	if partition == "" {
		partition = "aws"
	}
	name := SelfTestSplitRoleName(runID)
	trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Sid":"SameAccountRootOnly","Effect":"Allow",`+
		`"Principal":{"AWS":"arn:%s:iam::%s:root"},"Action":"sts:AssumeRole"}]}`, partition, in.AccountID)
	if _, err := v2.CreateRole(ctx, CreateRoleInput{
		Name: name, Path: SelfTestSplitRolePath, TrustDocument: trust,
		Description: "AuthSec enforcement self-test: throwaway split role, deleted by the same run.",
		Tags:        map[string]string{"authsec:managed-by": "authsec", "authsec:selftest": in.BindingID.String()},
	}); err != nil {
		r := classify(err, at())
		if r.Status == StatusDenied {
			r.Message = "CreateRole under " + SelfTestSplitRolePath + " was refused: the stack does not enable Lambda splits (EnableLambdaSplit). " + r.Message
		}
		return r
	}
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	perr := v2.PutRolePolicy(ctx, name, selfTestSplitInlinePolicy, selfTestDocument(1))
	keep(perr)
	if perr == nil {
		keep(v2.DeleteRolePolicy(ctx, name, selfTestSplitInlinePolicy))
	}
	derr := v2.DeleteRole(ctx, name)
	keep(derr)
	r := classify(first, at())
	if derr != nil {
		r.Message = "the throwaway role " + SelfTestSplitRolePath + name + " was left behind; " + r.Message
	}
	return r
}
