// Package awsenforce is the AWS side of Phase 3 enforcement
// (SPEC-iga-phase3-policy.md §3.5, §3.6, §4.4): what the enforcement role may
// do, and the binding self-test that proves it.
//
// T3.09 adds only the self-test: the probes of §3.6 run against the stack's own
// self-test role, classified per capability. The deployment writes, recovery
// and readback (T3.10) are a later task and will live beside this file.
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
// self-test uses it. Every method is a single call with SDK retries off: a
// self-test probe that AWS refused must be reported, not retried into a
// different answer.
type IAM interface {
	CreatePolicy(ctx context.Context, in CreatePolicyInput) (arn string, err error)
	CreatePolicyVersion(ctx context.Context, policyARN, document string, setAsDefault bool) (versionID string, err error)
	DeletePolicyVersion(ctx context.Context, policyARN, versionID string) error
	PutRolePermissionsBoundary(ctx context.Context, roleName, boundaryARN string) error
	DeleteRolePermissionsBoundary(ctx context.Context, roleName string) error
	DeletePolicy(ctx context.Context, policyARN string) error
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
