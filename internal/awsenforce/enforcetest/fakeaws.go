package enforcetest

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/smithy-go"

	"github.com/authsec-ai/authsec/internal/awsenforce"
)

// FakeAWS is one AWS account as the enforcement role sees it: STS (assume with
// an ExternalId) and the IAM calls of awsenforce.IAM. Every IAM call is first
// AUTHORISED by simulating Policy -- the enforcement role's policy, normally
// read from the template (NewFakeAWSFromTemplate) -- and only then applied to
// the in-memory roles and policies with IAM's own semantics (EntityAlreadyExists,
// DeleteConflict, NoSuchEntity, the five-version limit).
type FakeAWS struct {
	mu sync.Mutex

	Account    string
	Policy     Policy
	RoleARN    string // the enforcement role the trust policy belongs to
	ExternalID string // the ExternalId the trust policy requires

	// AssumeErr, when set, is returned by every AssumeEnforcement.
	AssumeErr error
	// Fail injects an error for an IAM action name (for example
	// "iam:CreatePolicyVersion") after authorisation passes.
	Fail map[string]error

	Roles    map[string]*Role    // by role name
	Policies map[string]*Managed // by policy ARN

	// Calls records "action resource -> outcome" for every IAM call.
	Calls   []string
	Assumes []awsenforce.AssumeInput
}

// Role is an IAM role in the fake account.
type Role struct {
	Name     string
	Path     string
	Tags     map[string]string
	Boundary string
}

// Managed is a customer-managed policy in the fake account.
type Managed struct {
	ARN      string
	Versions []string
	Default  string
	next     int
	Tags     map[string]string
}

// NewFakeAWSFromTemplate builds the account from the enforcement template: the
// enforcement role's policy is the template's (resolved for account), and the
// account holds the stack's self-test role, named from suffix and tagged as
// the template tags it.
func NewFakeAWSFromTemplate(templateYAML, account, suffix, externalID string) (*FakeAWS, error) {
	t, err := ParseTemplate(templateYAML)
	if err != nil {
		return nil, err
	}
	p, err := EnforcementPolicy(t, account)
	if err != nil {
		return nil, err
	}
	f := &FakeAWS{
		Account: account, Policy: p, ExternalID: externalID,
		RoleARN:  "arn:aws:iam::" + account + ":role/AuthSecEnforcement-" + suffix,
		Roles:    map[string]*Role{},
		Policies: map[string]*Managed{},
		Fail:     map[string]error{},
	}
	f.AddRole("AuthSecEnforcement-"+suffix, "/", map[string]string{"ManagedBy": "AuthSec"})
	f.AddRole("AuthSecEnforcementSelfTest-"+suffix, "/", map[string]string{"authsec:selftest": "true"})
	return f, nil
}

// SelfTestRoleARN is the ARN of the stack's self-test role for suffix.
func (f *FakeAWS) SelfTestRoleARN(suffix string) string {
	return "arn:aws:iam::" + f.Account + ":role/AuthSecEnforcementSelfTest-" + suffix
}

// AddRole adds a role.
func (f *FakeAWS) AddRole(name, path string, tags map[string]string) *Role {
	f.mu.Lock()
	defer f.mu.Unlock()
	if tags == nil {
		tags = map[string]string{}
	}
	r := &Role{Name: name, Path: path, Tags: tags}
	f.Roles[name] = r
	return r
}

// RoleARNOf is a role's ARN.
func (f *FakeAWS) RoleARNOf(r *Role) string {
	return "arn:aws:iam::" + f.Account + ":role" + r.Path + r.Name
}

// APIError builds an AWS-shaped error.
func APIError(code, msg string) error {
	return &smithy.GenericAPIError{Code: code, Message: msg}
}

// AssumeEnforcement implements awsenforce.Assumer.
func (f *FakeAWS) AssumeEnforcement(_ context.Context, in awsenforce.AssumeInput) (awsenforce.IAM, *awsenforce.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Assumes = append(f.Assumes, in)
	if f.AssumeErr != nil {
		return nil, nil, f.AssumeErr
	}
	if in.RoleARN != f.RoleARN || in.ExternalID != f.ExternalID {
		return nil, nil, APIError("AccessDenied", "User: arn:aws:iam::111111111111:role/AuthSec is not authorized to perform: sts:AssumeRole on resource: "+in.RoleARN)
	}
	return f, &awsenforce.Identity{
		AccountID: f.Account,
		ARN:       "arn:aws:sts::" + f.Account + ":assumed-role/" + strings.TrimPrefix(in.RoleARN, "arn:aws:iam::"+f.Account+":role/") + "/" + in.SessionName,
	}, nil
}

// Probe evaluates a request against the role's policy without changing
// anything (for the A11 forced-attempt assertions).
func (f *FakeAWS) Probe(action, resource string, context map[string]string) Decision {
	return f.Policy.Evaluate(Request{Action: action, Resource: resource, Context: context})
}

func (f *FakeAWS) authorise(action, resource string, ctx map[string]string) error {
	d := f.Policy.Evaluate(Request{Action: action, Resource: resource, Context: ctx})
	outcome := "allowed"
	if !d.Allowed {
		outcome = "denied"
	}
	f.Calls = append(f.Calls, action+" "+resource+" -> "+outcome)
	if d.Allowed {
		if err := f.Fail[action]; err != nil {
			return err
		}
		return nil
	}
	how := "because no identity-based policy allows the " + action + " action"
	if d.Explicit {
		how = "with an explicit deny in an identity-based policy"
	}
	return APIError("AccessDenied", fmt.Sprintf("User: %s/session is not authorized to perform: %s on resource: %s %s",
		f.RoleARN, action, resource, how))
}

func (f *FakeAWS) roleContext(r *Role) map[string]string {
	ctx := map[string]string{}
	for k, v := range r.Tags {
		ctx["aws:ResourceTag/"+k] = v
	}
	return ctx
}

func (f *FakeAWS) policyExists(arn string) bool {
	if strings.HasPrefix(arn, "arn:aws:iam::aws:policy/") {
		return true // AWS managed
	}
	_, ok := f.Policies[arn]
	return ok
}

// CreatePolicy implements awsenforce.IAM.
func (f *FakeAWS) CreatePolicy(_ context.Context, in awsenforce.CreatePolicyInput) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	arn := "arn:aws:iam::" + f.Account + ":policy" + in.Path + in.Name
	if err := f.authorise("iam:CreatePolicy", arn, nil); err != nil {
		return "", err
	}
	if len(in.Tags) > 0 {
		// CreatePolicy with tags also needs iam:TagPolicy (AWS IAM user guide,
		// "Permissions required to tag IAM entities").
		if err := f.authorise("iam:TagPolicy", arn, nil); err != nil {
			return "", err
		}
	}
	if _, ok := f.Policies[arn]; ok {
		return "", APIError("EntityAlreadyExists", "A policy called "+in.Name+" already exists.")
	}
	f.Policies[arn] = &Managed{ARN: arn, Versions: []string{"v1"}, Default: "v1", next: 2, Tags: in.Tags}
	return arn, nil
}

// CreatePolicyVersion implements awsenforce.IAM.
func (f *FakeAWS) CreatePolicyVersion(_ context.Context, arn, _ string, setAsDefault bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.authorise("iam:CreatePolicyVersion", arn, nil); err != nil {
		return "", err
	}
	p, ok := f.Policies[arn]
	if !ok {
		return "", APIError("NoSuchEntity", "Policy "+arn+" does not exist")
	}
	if len(p.Versions) >= 5 {
		return "", APIError("LimitExceeded", "A managed policy can have up to 5 versions.")
	}
	v := fmt.Sprintf("v%d", p.next)
	p.next++
	p.Versions = append(p.Versions, v)
	if setAsDefault {
		p.Default = v
	}
	return v, nil
}

// DeletePolicyVersion implements awsenforce.IAM.
func (f *FakeAWS) DeletePolicyVersion(_ context.Context, arn, version string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.authorise("iam:DeletePolicyVersion", arn, nil); err != nil {
		return err
	}
	p, ok := f.Policies[arn]
	if !ok {
		return APIError("NoSuchEntity", "Policy "+arn+" does not exist")
	}
	if p.Default == version {
		return APIError("DeleteConflict", "Cannot delete the default version of a policy.")
	}
	for i, v := range p.Versions {
		if v == version {
			p.Versions = append(p.Versions[:i], p.Versions[i+1:]...)
			return nil
		}
	}
	return APIError("NoSuchEntity", "Version "+version+" does not exist")
}

// PutRolePermissionsBoundary implements awsenforce.IAM.
func (f *FakeAWS) PutRolePermissionsBoundary(_ context.Context, roleName, boundary string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.Roles[roleName]
	resource := "arn:aws:iam::" + f.Account + ":role/" + roleName
	ctx := map[string]string{"iam:PermissionsBoundary": boundary}
	if ok {
		resource = f.RoleARNOf(r)
		for k, v := range f.roleContext(r) {
			ctx[k] = v
		}
	}
	if err := f.authorise("iam:PutRolePermissionsBoundary", resource, ctx); err != nil {
		return err
	}
	if !ok {
		return APIError("NoSuchEntity", "The role with name "+roleName+" cannot be found.")
	}
	if !f.policyExists(boundary) {
		return APIError("NoSuchEntity", "Policy "+boundary+" does not exist or is not attachable.")
	}
	r.Boundary = boundary
	return nil
}

// DeleteRolePermissionsBoundary implements awsenforce.IAM. The
// iam:PermissionsBoundary key carries the boundary CURRENTLY attached, as
// §3.6 expects AWS to supply it; with none attached the key is absent.
func (f *FakeAWS) DeleteRolePermissionsBoundary(_ context.Context, roleName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.Roles[roleName]
	resource := "arn:aws:iam::" + f.Account + ":role/" + roleName
	ctx := map[string]string{}
	if ok {
		resource = f.RoleARNOf(r)
		ctx = f.roleContext(r)
		if r.Boundary != "" {
			ctx["iam:PermissionsBoundary"] = r.Boundary
		}
	}
	if err := f.authorise("iam:DeleteRolePermissionsBoundary", resource, ctx); err != nil {
		return err
	}
	if !ok {
		return APIError("NoSuchEntity", "The role with name "+roleName+" cannot be found.")
	}
	r.Boundary = ""
	return nil
}

// DeletePolicy implements awsenforce.IAM.
func (f *FakeAWS) DeletePolicy(_ context.Context, arn string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.authorise("iam:DeletePolicy", arn, nil); err != nil {
		return err
	}
	p, ok := f.Policies[arn]
	if !ok {
		return APIError("NoSuchEntity", "Policy "+arn+" does not exist")
	}
	for _, r := range f.Roles {
		if r.Boundary == arn {
			return APIError("DeleteConflict", "Cannot delete a policy attached to entities.")
		}
	}
	if len(p.Versions) > 1 {
		return APIError("DeleteConflict", "This policy has more than one version. Before you delete a policy, you must delete the policy's versions.")
	}
	delete(f.Policies, arn)
	return nil
}

// RemoveStatement drops a statement by Sid from the simulated policy, as a
// customer editing the stack would (A22).
func (f *FakeAWS) RemoveStatement(sid string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, st := range f.Policy.Statements {
		if st.Sid == sid {
			f.Policy.Statements = append(f.Policy.Statements[:i:i], f.Policy.Statements[i+1:]...)
			return true
		}
	}
	return false
}
