package enforcetest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/smithy-go"

	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/igagov"
)

// FakeAWS is one AWS account as the enforcement role sees it: STS (assume with
// an ExternalId) and the IAM calls of awsenforce.IAM. Every IAM call is first
// AUTHORISED by simulating Policy -- the enforcement role's policy, normally
// read from the template (NewFakeAWSFromTemplate) -- and only then applied to
// the in-memory roles and policies with IAM's own semantics (EntityAlreadyExists,
// DeleteConflict, NoSuchEntity, the five-version limit).
//
// T3.10 adds what a deployment needs: policy documents per version, RoleIds,
// managed and inline permission policies, TagPolicy, the discovery role's
// read view (Discovery, which the enforcement policy does not govern: the
// discovery role holds SecurityAudit), and fault injection after a write was
// applied (AfterApply: "AWS accepted it, the answer never arrived").
type FakeAWS struct {
	mu sync.Mutex

	Account    string
	Policy     Policy
	RoleARN    string // the enforcement role the trust policy belongs to
	ExternalID string // the ExternalId the trust policy requires

	// AssumeErr, when set, is returned by every AssumeEnforcement.
	AssumeErr error
	// Fail injects an error for an IAM action name (for example
	// "iam:CreatePolicyVersion") after authorisation passes and BEFORE the
	// write is applied: AWS refused it.
	Fail map[string]error
	// AfterApply runs, outside the account lock, after an authorised write
	// for that action name was APPLIED; its error (if any) is what the caller
	// gets instead of the answer -- a crash, a timeout or a reset after AWS
	// accepted the request. A hook may block on ctx to model a client
	// timeout. Set it before the calls it should affect.
	AfterApply map[string]func(ctx context.Context) error
	// ReadFail injects an error for a discovery read by IAM action name
	// ("iam:GetPolicyVersion").
	ReadFail map[string]error

	Roles    map[string]*Role    // by role name
	Policies map[string]*Managed // by policy ARN

	// Calls records "action resource -> outcome" for every IAM write call.
	Calls   []string
	Assumes []awsenforce.AssumeInput
	// Reads counts discovery reads.
	Reads int

	// Now is the account's clock for CloudTrail event times (default
	// time.Now); tests with a moved clock set it.
	Now func() time.Time
	// TrailErr, when set, is what every LookupEvents returns: the trail
	// cannot be read.
	TrailErr error

	// trail is the account's CloudTrail: one record per IAM write call AWS
	// received (applied or refused), in arrival order.
	trail []TrailRecord
	// holds delay the next call of an action BEFORE it reaches the account
	// (HoldNext): the request is in flight until released.
	holds map[string]chan struct{}

	clock int
	reqNo int
}

// Role is an IAM role in the fake account.
type Role struct {
	Name     string
	Path     string
	Tags     map[string]string
	Boundary string
	// RoleID is the role's unique id (AROA...).
	RoleID string
	// Attached are managed policies attached as permissions policies.
	Attached []string
	// Inline are inline policies by name.
	Inline map[string]string
	// Trust is the assume-role policy document.
	Trust string
}

// Managed is a customer-managed policy in the fake account.
type Managed struct {
	ARN      string
	Path     string
	Name     string
	Versions []string
	Default  string
	next     int
	Tags     map[string]string
	// Docs are the documents by version id.
	Docs map[string]string
	// Created orders versions by creation (the fake's CreateDate).
	Created map[string]int
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
		RoleARN:    "arn:aws:iam::" + account + ":role/AuthSecEnforcement-" + suffix,
		Roles:      map[string]*Role{},
		Policies:   map[string]*Managed{},
		Fail:       map[string]error{},
		AfterApply: map[string]func(ctx context.Context) error{},
		ReadFail:   map[string]error{},
	}
	f.AddRole("AuthSecEnforcement-"+suffix, "/", map[string]string{"ManagedBy": "AuthSec"})
	f.AddRole("AuthSecEnforcementSelfTest-"+suffix, "/", map[string]string{"authsec:selftest": "true"})
	return f, nil
}

// SelfTestRoleARN is the ARN of the stack's self-test role for suffix.
func (f *FakeAWS) SelfTestRoleARN(suffix string) string {
	return "arn:aws:iam::" + f.Account + ":role/AuthSecEnforcementSelfTest-" + suffix
}

// FakeRoleID derives a stable AROA... id from a role name.
func FakeRoleID(name string) string {
	h := sha256.Sum256([]byte("role:" + name))
	return "AROA" + strings.ToUpper(hex.EncodeToString(h[:]))[:17]
}

// AddRole adds a role (RoleId derived from its name; a recreated role gets a
// new one with RecreateRole).
func (f *FakeAWS) AddRole(name, path string, tags map[string]string) *Role {
	f.mu.Lock()
	defer f.mu.Unlock()
	if tags == nil {
		tags = map[string]string{}
	}
	r := &Role{Name: name, Path: path, Tags: tags, RoleID: FakeRoleID(name), Inline: map[string]string{},
		Trust: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}`}
	f.Roles[name] = r
	return r
}

// RoleARNOf is a role's ARN.
func (f *FakeAWS) RoleARNOf(r *Role) string {
	return "arn:aws:iam::" + f.Account + ":role" + r.Path + r.Name
}

// PolicyARN is the ARN of a customer-managed policy at path/name.
func (f *FakeAWS) PolicyARN(path, name string) string {
	return "arn:aws:iam::" + f.Account + ":policy" + path + name
}

// AddPolicy creates a managed policy directly (test setup: not authorised by
// the enforcement policy), with one version per document, the last default.
func (f *FakeAWS) AddPolicy(path, name string, tags map[string]string, docs ...string) *Managed {
	f.mu.Lock()
	defer f.mu.Unlock()
	arn := f.PolicyARN(path, name)
	m := &Managed{ARN: arn, Path: path, Name: name, next: 1, Tags: map[string]string{}, Docs: map[string]string{}, Created: map[string]int{}}
	for k, v := range tags {
		m.Tags[k] = v
	}
	for _, d := range docs {
		v := m.addVersion(f, d)
		m.Default = v
	}
	f.Policies[arn] = m
	return m
}

func (m *Managed) addVersion(f *FakeAWS, doc string) string {
	if m.next == 0 {
		m.next = 1
	}
	if m.Docs == nil {
		m.Docs = map[string]string{}
	}
	if m.Created == nil {
		m.Created = map[string]int{}
	}
	v := fmt.Sprintf("v%d", m.next)
	m.next++
	f.clock++
	m.Versions = append(m.Versions, v)
	m.Docs[v] = doc
	m.Created[v] = f.clock
	return v
}

// AttachPermissions attaches a managed policy to a role as a permissions
// policy (setup).
func (f *FakeAWS) AttachPermissions(roleName, arn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Roles[roleName].Attached = append(f.Roles[roleName].Attached, arn)
}

// SetBoundary sets a role's boundary directly (setup, or a customer's own
// change outside AuthSec).
func (f *FakeAWS) SetBoundary(roleName, arn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Roles[roleName].Boundary = arn
}

// SetDefaultDocument adds a version with doc and makes it the default
// (a customer editing a policy outside AuthSec).
func (f *FakeAWS) SetDefaultDocument(arn, doc string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.Policies[arn]
	m.Default = m.addVersion(f, doc)
}

// AddVersion adds a version with doc, the default only when setDefault (setup).
func (f *FakeAWS) AddVersion(arn, doc string, setDefault bool) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.Policies[arn]
	v := m.addVersion(f, doc)
	if setDefault {
		m.Default = v
	}
	return v
}

// PolicyState returns a copy of a policy's versions, default and default
// document, and whether it exists.
func (f *FakeAWS) PolicyState(arn string) (versions []string, def, doc string, tags map[string]string, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.Policies[arn]
	if !ok {
		return nil, "", "", nil, false
	}
	return append([]string{}, m.Versions...), m.Default, m.Docs[m.Default], copyMap(m.Tags), true
}

// BoundaryOf returns a role's boundary.
func (f *FakeAWS) BoundaryOf(roleName string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Roles[roleName].Boundary
}

// Count returns how many write calls of action were made (authorised or not).
func (f *FakeAWS) Count(action string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.Calls {
		if strings.HasPrefix(c, action+" ") {
			n++
		}
	}
	return n
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
	arn := "arn:aws:sts::" + f.Account + ":assumed-role/" + strings.TrimPrefix(in.RoleARN, "arn:aws:iam::"+f.Account+":role/") + "/" + in.SessionName
	return sessionIAM{f: f, arn: arn}, &awsenforce.Identity{AccountID: f.Account, ARN: arn}, nil
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

// answered finishes a write: on success it records a request id for the
// caller (awsenforce.RecordRequestID) and runs the AfterApply hook, outside
// the lock. unlock must be the caller's deferred-free unlock.
func (f *FakeAWS) answered(ctx context.Context, c call, err error) error {
	f.record(ctx, c, err)
	action := ""
	if err == nil {
		action = c.action
	}
	hook := f.AfterApply[action]
	if err == nil {
		f.reqNo++
		awsenforce.RecordRequestID(ctx, fmt.Sprintf("fake-req-%d", f.reqNo))
	}
	f.mu.Unlock()
	if err == nil && hook != nil {
		return hook(ctx)
	}
	return err
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
func (f *FakeAWS) CreatePolicy(ctx context.Context, in awsenforce.CreatePolicyInput) (string, error) {
	f.waitHold("iam:CreatePolicy")
	f.mu.Lock()
	c := call{op: "CreatePolicy", action: "iam:CreatePolicy", params: map[string]any{"policyName": in.Name, "path": in.Path, "policyDocument": in.Document}}
	arn := "arn:aws:iam::" + f.Account + ":policy" + in.Path + in.Name
	if err := f.authorise("iam:CreatePolicy", arn, nil); err != nil {
		return "", f.answered(ctx, c, err)
	}
	if len(in.Tags) > 0 {
		// CreatePolicy with tags also needs iam:TagPolicy (AWS IAM user guide,
		// "Permissions required to tag IAM entities").
		if err := f.authorise("iam:TagPolicy", arn, nil); err != nil {
			return "", f.answered(ctx, c, err)
		}
	}
	if _, ok := f.Policies[arn]; ok {
		return "", f.answered(ctx, c, APIError("EntityAlreadyExists", "A policy called "+in.Name+" already exists."))
	}
	m := &Managed{ARN: arn, Path: in.Path, Name: in.Name, next: 1, Tags: map[string]string{}}
	for k, v := range in.Tags {
		m.Tags[k] = v
	}
	m.Default = m.addVersion(f, in.Document)
	f.Policies[arn] = m
	c.response = map[string]any{"policy": map[string]any{"arn": arn, "defaultVersionId": m.Default}}
	return arn, f.answered(ctx, c, nil)
}

// CreatePolicyVersion implements awsenforce.IAM.
func (f *FakeAWS) CreatePolicyVersion(ctx context.Context, arn, document string, setAsDefault bool) (string, error) {
	f.waitHold("iam:CreatePolicyVersion")
	f.mu.Lock()
	c := call{op: "CreatePolicyVersion", action: "iam:CreatePolicyVersion", params: map[string]any{"policyArn": arn, "policyDocument": document, "setAsDefault": setAsDefault}}
	if err := f.authorise("iam:CreatePolicyVersion", arn, nil); err != nil {
		return "", f.answered(ctx, c, err)
	}
	p, ok := f.Policies[arn]
	if !ok {
		return "", f.answered(ctx, c, APIError("NoSuchEntity", "Policy "+arn+" does not exist"))
	}
	if len(p.Versions) >= 5 {
		return "", f.answered(ctx, c, APIError("LimitExceeded", "A managed policy can have up to 5 versions."))
	}
	v := p.addVersion(f, document)
	if setAsDefault {
		p.Default = v
	}
	c.response = map[string]any{"policyVersion": map[string]any{"versionId": v, "isDefaultVersion": setAsDefault}}
	return v, f.answered(ctx, c, nil)
}

// DeletePolicyVersion implements awsenforce.IAM.
func (f *FakeAWS) DeletePolicyVersion(ctx context.Context, arn, version string) error {
	f.waitHold("iam:DeletePolicyVersion")
	f.mu.Lock()
	c := call{op: "DeletePolicyVersion", action: "iam:DeletePolicyVersion", params: map[string]any{"policyArn": arn, "versionId": version}}
	if err := f.authorise("iam:DeletePolicyVersion", arn, nil); err != nil {
		return f.answered(ctx, c, err)
	}
	p, ok := f.Policies[arn]
	if !ok {
		return f.answered(ctx, c, APIError("NoSuchEntity", "Policy "+arn+" does not exist"))
	}
	if p.Default == version {
		return f.answered(ctx, c, APIError("DeleteConflict", "Cannot delete the default version of a policy."))
	}
	for i, v := range p.Versions {
		if v == version {
			p.Versions = append(p.Versions[:i], p.Versions[i+1:]...)
			delete(p.Docs, v)
			delete(p.Created, v)
			return f.answered(ctx, c, nil)
		}
	}
	return f.answered(ctx, c, APIError("NoSuchEntity", "Version "+version+" does not exist"))
}

// TagPolicy implements awsenforce.IAM.
func (f *FakeAWS) TagPolicy(ctx context.Context, arn string, tags map[string]string) error {
	f.waitHold("iam:TagPolicy")
	f.mu.Lock()
	c := call{op: "TagPolicy", action: "iam:TagPolicy", params: map[string]any{"policyArn": arn, "tags": tags}}
	if err := f.authorise("iam:TagPolicy", arn, nil); err != nil {
		return f.answered(ctx, c, err)
	}
	p, ok := f.Policies[arn]
	if !ok {
		return f.answered(ctx, c, APIError("NoSuchEntity", "Policy "+arn+" does not exist"))
	}
	for k, v := range tags {
		p.Tags[k] = v
	}
	return f.answered(ctx, c, nil)
}

// PutRolePermissionsBoundary implements awsenforce.IAM.
func (f *FakeAWS) PutRolePermissionsBoundary(ctx context.Context, roleName, boundary string) error {
	f.waitHold("iam:PutRolePermissionsBoundary")
	f.mu.Lock()
	c := call{op: "PutRolePermissionsBoundary", action: "iam:PutRolePermissionsBoundary", params: map[string]any{"roleName": roleName, "permissionsBoundary": boundary}}
	r, ok := f.Roles[roleName]
	resource := "arn:aws:iam::" + f.Account + ":role/" + roleName
	actx := map[string]string{"iam:PermissionsBoundary": boundary}
	if ok {
		resource = f.RoleARNOf(r)
		for k, v := range f.roleContext(r) {
			actx[k] = v
		}
	}
	if err := f.authorise("iam:PutRolePermissionsBoundary", resource, actx); err != nil {
		return f.answered(ctx, c, err)
	}
	if !ok {
		return f.answered(ctx, c, APIError("NoSuchEntity", "The role with name "+roleName+" cannot be found."))
	}
	if !f.policyExists(boundary) {
		return f.answered(ctx, c, APIError("NoSuchEntity", "Policy "+boundary+" does not exist or is not attachable."))
	}
	r.Boundary = boundary
	return f.answered(ctx, c, nil)
}

// DeleteRolePermissionsBoundary implements awsenforce.IAM. The
// iam:PermissionsBoundary key carries the boundary CURRENTLY attached, as
// §3.6 expects AWS to supply it; with none attached the key is absent.
func (f *FakeAWS) DeleteRolePermissionsBoundary(ctx context.Context, roleName string) error {
	f.waitHold("iam:DeleteRolePermissionsBoundary")
	f.mu.Lock()
	c := call{op: "DeleteRolePermissionsBoundary", action: "iam:DeleteRolePermissionsBoundary", params: map[string]any{"roleName": roleName}}
	r, ok := f.Roles[roleName]
	resource := "arn:aws:iam::" + f.Account + ":role/" + roleName
	actx := map[string]string{}
	if ok {
		resource = f.RoleARNOf(r)
		actx = f.roleContext(r)
		if r.Boundary != "" {
			actx["iam:PermissionsBoundary"] = r.Boundary
		}
	}
	if err := f.authorise("iam:DeleteRolePermissionsBoundary", resource, actx); err != nil {
		return f.answered(ctx, c, err)
	}
	if !ok {
		return f.answered(ctx, c, APIError("NoSuchEntity", "The role with name "+roleName+" cannot be found."))
	}
	r.Boundary = ""
	return f.answered(ctx, c, nil)
}

// DeletePolicy implements awsenforce.IAM.
func (f *FakeAWS) DeletePolicy(ctx context.Context, arn string) error {
	f.waitHold("iam:DeletePolicy")
	f.mu.Lock()
	c := call{op: "DeletePolicy", action: "iam:DeletePolicy", params: map[string]any{"policyArn": arn}}
	if err := f.authorise("iam:DeletePolicy", arn, nil); err != nil {
		return f.answered(ctx, c, err)
	}
	p, ok := f.Policies[arn]
	if !ok {
		return f.answered(ctx, c, APIError("NoSuchEntity", "Policy "+arn+" does not exist"))
	}
	for _, r := range f.Roles {
		if r.Boundary == arn {
			return f.answered(ctx, c, APIError("DeleteConflict", "Cannot delete a policy attached to entities."))
		}
		for _, a := range r.Attached {
			if a == arn {
				return f.answered(ctx, c, APIError("DeleteConflict", "Cannot delete a policy attached to entities."))
			}
		}
	}
	if len(p.Versions) > 1 {
		return f.answered(ctx, c, APIError("DeleteConflict", "This policy has more than one version. Before you delete a policy, you must delete the policy's versions."))
	}
	delete(f.Policies, arn)
	return f.answered(ctx, c, nil)
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

/* ------------------------------ discovery view ----------------------------- */

// Discovery is the account as the DISCOVERY role reads it (§3.5): every
// awsenforce.DiscoveryIAM read, not governed by the enforcement policy.
func (f *FakeAWS) Discovery() awsenforce.DiscoveryIAM { return fakeDiscovery{f} }

type fakeDiscovery struct{ f *FakeAWS }

func noSuchEntity(what string) error { return APIError("NoSuchEntity", what+" cannot be found.") }

func (d fakeDiscovery) begin(action string) error {
	d.f.mu.Lock()
	d.f.Reads++
	return d.f.ReadFail[action]
}

func (d fakeDiscovery) GetRole(_ context.Context, roleName string) (*awsenforce.RoleInfo, error) {
	defer d.f.mu.Unlock()
	if err := d.begin("iam:GetRole"); err != nil {
		return nil, err
	}
	r, ok := d.f.Roles[roleName]
	if !ok {
		return nil, noSuchEntity("The role with name " + roleName)
	}
	return &awsenforce.RoleInfo{RoleID: r.RoleID, ARN: d.f.RoleARNOf(r), Name: r.Name, Path: r.Path,
		Tags: copyMap(r.Tags), BoundaryARN: r.Boundary, TrustDocument: r.Trust}, nil
}

func (d fakeDiscovery) ListAttachedRolePolicies(_ context.Context, roleName string) ([]string, error) {
	defer d.f.mu.Unlock()
	if err := d.begin("iam:ListAttachedRolePolicies"); err != nil {
		return nil, err
	}
	r, ok := d.f.Roles[roleName]
	if !ok {
		return nil, noSuchEntity("The role with name " + roleName)
	}
	return append([]string{}, r.Attached...), nil
}

func (d fakeDiscovery) ListRolePolicies(_ context.Context, roleName string) ([]string, error) {
	defer d.f.mu.Unlock()
	if err := d.begin("iam:ListRolePolicies"); err != nil {
		return nil, err
	}
	r, ok := d.f.Roles[roleName]
	if !ok {
		return nil, noSuchEntity("The role with name " + roleName)
	}
	var out []string
	for n := range r.Inline {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func (d fakeDiscovery) GetRolePolicy(_ context.Context, roleName, policyName string) (string, error) {
	defer d.f.mu.Unlock()
	if err := d.begin("iam:GetRolePolicy"); err != nil {
		return "", err
	}
	r, ok := d.f.Roles[roleName]
	if !ok {
		return "", noSuchEntity("The role with name " + roleName)
	}
	doc, ok := r.Inline[policyName]
	if !ok {
		return "", noSuchEntity("The role policy with name " + policyName)
	}
	return doc, nil
}

func (d fakeDiscovery) GetPolicy(_ context.Context, arn string) (*awsenforce.PolicyInfo, error) {
	defer d.f.mu.Unlock()
	if err := d.begin("iam:GetPolicy"); err != nil {
		return nil, err
	}
	p, ok := d.f.Policies[arn]
	if !ok {
		return nil, noSuchEntity("Policy " + arn)
	}
	return &awsenforce.PolicyInfo{ARN: p.ARN, Path: p.Path, Name: p.Name, Tags: copyMap(p.Tags), DefaultVersionID: p.Default}, nil
}

func (d fakeDiscovery) GetPolicyVersion(_ context.Context, arn, versionID string) (string, error) {
	defer d.f.mu.Unlock()
	if err := d.begin("iam:GetPolicyVersion"); err != nil {
		return "", err
	}
	p, ok := d.f.Policies[arn]
	if !ok {
		return "", noSuchEntity("Policy " + arn)
	}
	doc, ok := p.Docs[versionID]
	if !ok {
		return "", noSuchEntity("Policy version " + versionID)
	}
	return doc, nil
}

func (d fakeDiscovery) ListPolicyVersions(_ context.Context, arn string) ([]awsenforce.PolicyVersionInfo, error) {
	defer d.f.mu.Unlock()
	if err := d.begin("iam:ListPolicyVersions"); err != nil {
		return nil, err
	}
	p, ok := d.f.Policies[arn]
	if !ok {
		return nil, noSuchEntity("Policy " + arn)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var out []awsenforce.PolicyVersionInfo
	for _, v := range p.Versions {
		out = append(out, awsenforce.PolicyVersionInfo{VersionID: v, IsDefault: v == p.Default,
			CreateDate: base.Add(time.Duration(p.Created[v]) * time.Minute)})
	}
	return out, nil
}

func (d fakeDiscovery) ListEntitiesForPolicy(_ context.Context, arn string) ([]igagov.AttachedEntity, error) {
	defer d.f.mu.Unlock()
	if err := d.begin("iam:ListEntitiesForPolicy"); err != nil {
		return nil, err
	}
	if _, ok := d.f.Policies[arn]; !ok {
		return nil, noSuchEntity("Policy " + arn)
	}
	out := []igagov.AttachedEntity{}
	for _, r := range d.f.Roles {
		if r.Boundary == arn {
			out = append(out, igagov.AttachedEntity{Kind: "role", ID: r.RoleID, Name: r.Name, Usage: igagov.UsageBoundary})
		}
		for _, a := range r.Attached {
			if a == arn {
				out = append(out, igagov.AttachedEntity{Kind: "role", ID: r.RoleID, Name: r.Name, Usage: igagov.UsagePermissions})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID+out[i].Usage < out[j].ID+out[j].Usage })
	return out, nil
}

func copyMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

/* -------------------------------- CloudTrail -------------------------------- */

// call is one IAM write as CloudTrail records it.
type call struct {
	op       string // CloudTrail eventName
	action   string // the AfterApply key (iam:<op>)
	params   map[string]any
	response map[string]any
}

// TrailRecord is one CloudTrail record of the fake account: what AWS
// received, applied or refused. Tests edit the trail (EditTrail) to make it
// disagree with the account (A58 d).
type TrailRecord struct {
	EventID   string
	EventName string
	EventTime time.Time
	// PrincipalARN is the caller: an assumed-role session ARN for the
	// enforcement role's calls, "" for calls made on the account directly.
	PrincipalARN string
	ErrorCode    string
	Request      map[string]any
	Response     map[string]any
}

type sessionKey struct{}

// sessionIAM is the enforcement client of one assumed session: its calls are
// recorded in CloudTrail under the session's ARN.
type sessionIAM struct {
	f   *FakeAWS
	arn string
}

func (s sessionIAM) ctx(ctx context.Context) context.Context {
	return context.WithValue(ctx, sessionKey{}, s.arn)
}

func (s sessionIAM) CreatePolicy(ctx context.Context, in awsenforce.CreatePolicyInput) (string, error) {
	return s.f.CreatePolicy(s.ctx(ctx), in)
}
func (s sessionIAM) CreatePolicyVersion(ctx context.Context, arn, document string, setAsDefault bool) (string, error) {
	return s.f.CreatePolicyVersion(s.ctx(ctx), arn, document, setAsDefault)
}
func (s sessionIAM) DeletePolicyVersion(ctx context.Context, arn, version string) error {
	return s.f.DeletePolicyVersion(s.ctx(ctx), arn, version)
}
func (s sessionIAM) TagPolicy(ctx context.Context, arn string, tags map[string]string) error {
	return s.f.TagPolicy(s.ctx(ctx), arn, tags)
}
func (s sessionIAM) PutRolePermissionsBoundary(ctx context.Context, roleName, boundary string) error {
	return s.f.PutRolePermissionsBoundary(s.ctx(ctx), roleName, boundary)
}
func (s sessionIAM) DeleteRolePermissionsBoundary(ctx context.Context, roleName string) error {
	return s.f.DeleteRolePermissionsBoundary(s.ctx(ctx), roleName)
}
func (s sessionIAM) DeletePolicy(ctx context.Context, arn string) error {
	return s.f.DeletePolicy(s.ctx(ctx), arn)
}

func (f *FakeAWS) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// record appends the CloudTrail record of a write the account received (the
// caller holds the lock). err is AWS's answer: an API error is recorded with
// its code; nil is an applied request.
func (f *FakeAWS) record(ctx context.Context, c call, err error) {
	if c.op == "" {
		return
	}
	principal, _ := ctx.Value(sessionKey{}).(string)
	rec := TrailRecord{EventID: fmt.Sprintf("fake-evt-%d", len(f.trail)+1), EventName: c.op, EventTime: f.now().UTC(),
		PrincipalARN: principal, Request: c.params}
	if err != nil {
		var api smithy.APIError
		if errors.As(err, &api) {
			rec.ErrorCode = api.ErrorCode()
		} else {
			rec.ErrorCode = "InternalFailure"
		}
	} else {
		rec.Response = c.response
	}
	f.trail = append(f.trail, rec)
}

// Trail returns a copy of the account's CloudTrail records.
func (f *FakeAWS) Trail() []TrailRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]TrailRecord{}, f.trail...)
}

// EditTrail replaces the account's CloudTrail records with edit's result.
func (f *FakeAWS) EditTrail(edit func([]TrailRecord) []TrailRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.trail = edit(append([]TrailRecord{}, f.trail...))
}

// HoldNext delays the NEXT call of action (for example
// "iam:CreatePolicyVersion") before it reaches the account: the caller
// waits, as for a request still in flight, until release is called; then
// the request is applied (or refused) as if it arrived at that moment. The
// caller's own timeout does not cancel it (A58 b, e).
func (f *FakeAWS) HoldNext(action string) (release func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.holds == nil {
		f.holds = map[string]chan struct{}{}
	}
	ch := make(chan struct{})
	f.holds[action] = ch
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

func (f *FakeAWS) waitHold(action string) {
	f.mu.Lock()
	ch := f.holds[action]
	delete(f.holds, action)
	f.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

// LookupEvents is CloudTrail's LookupEvents over the account's records
// (awsenforce.TrailAPI): the EventName lookup attribute, the time window
// (inclusive), 50 events per page, newest first, each with the record as
// CloudTrailEvent JSON. TrailErr fails every call.
func (f *FakeAWS) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.TrailErr != nil {
		return nil, f.TrailErr
	}
	name := ""
	for _, a := range in.LookupAttributes {
		if a.AttributeKey == cttypes.LookupAttributeKeyEventName {
			name = aws.ToString(a.AttributeValue)
		}
	}
	var match []TrailRecord
	for i := len(f.trail) - 1; i >= 0; i-- {
		r := f.trail[i]
		if name != "" && r.EventName != name {
			continue
		}
		if in.StartTime != nil && r.EventTime.Before(*in.StartTime) {
			continue
		}
		if in.EndTime != nil && r.EventTime.After(*in.EndTime) {
			continue
		}
		match = append(match, r)
	}
	start := 0
	if in.NextToken != nil {
		fmt.Sscanf(*in.NextToken, "%d", &start)
	}
	end := start + 50
	out := &cloudtrail.LookupEventsOutput{}
	if end < len(match) {
		out.NextToken = aws.String(fmt.Sprintf("%d", end))
	} else {
		end = len(match)
	}
	for _, r := range match[start:end] {
		raw := map[string]any{"eventVersion": "1.08", "eventID": r.EventID, "eventName": r.EventName,
			"eventTime": r.EventTime.Format(time.RFC3339), "eventSource": "iam.amazonaws.com", "awsRegion": "us-east-1",
			"requestParameters": r.Request, "responseElements": r.Response}
		if r.PrincipalARN != "" {
			raw["userIdentity"] = map[string]any{"type": "AssumedRole", "arn": r.PrincipalARN}
		} else {
			raw["userIdentity"] = map[string]any{"type": "IAMUser", "arn": "arn:aws:iam::" + f.Account + ":user/admin"}
		}
		if r.ErrorCode != "" {
			raw["errorCode"] = r.ErrorCode
		}
		b, _ := json.Marshal(raw)
		t := r.EventTime
		out.Events = append(out.Events, cttypes.Event{EventId: aws.String(r.EventID), EventName: aws.String(r.EventName),
			EventTime: &t, EventSource: aws.String("iam.amazonaws.com"), CloudTrailEvent: aws.String(string(b))})
	}
	return out, nil
}
