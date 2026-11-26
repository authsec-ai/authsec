// Package remediatetest is test support for remediation: a fake AWS account
// whose every write is authorised by simulating the remediation role's REAL
// policy, read from the embedded template (enforcetest's simulator), so a
// statement removed from the template changes what the fake allows, the way
// it would in AWS. Reads (the discovery role) are always allowed.
package remediatetest

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/smithy-go"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
	"github.com/authsec-ai/authsec/internal/awsremediate"
)

// Principal is a fake role or user.
type Principal struct {
	Kind     string
	Name     string
	Tags     map[string]string
	Attached []string
	Inline   map[string]string
	Keys     []awsremediate.AccessKey
}

// Policy is a fake managed policy.
type Policy struct {
	ARN      string
	Tags     map[string]string
	Versions []awsremediate.PolicyVersion
	Docs     map[string]string
	next     int
}

// Secret is a fake Secrets Manager secret.
type Secret struct {
	ARN             string
	Tags            map[string]string
	RotationEnabled bool
	Current         string
	Values          map[string]string // version -> value (never read by AuthSec)
	next            int
}

// Call is one write the fake answered.
type Call struct {
	Action   string
	Resource string
	Session  string
	Err      string
	At       time.Time
}

// Account is the fake.
type Account struct {
	mu         sync.Mutex
	AccountID  string
	policy     enforcetest.Policy
	Principals map[string]*Principal // by ARN
	Policies   map[string]*Policy    // by ARN
	Secrets    map[string]*Secret    // by ARN
	Calls      []Call
	// Fail makes the named action fail with the given AWS error code.
	Fail map[string]string
	// LieOnRead makes reads of the named principal or policy ARN return
	// the state BEFORE the last write (a readback mismatch).
	LieOnRead map[string]bool
	stale     map[string]*Principal
	staleP    map[string]*Policy
	keyN      int
	Now       func() time.Time
}

// New builds a fake account whose writes are authorised by the remediation
// template's policy.
func New(account string) (*Account, error) {
	tpl, err := enforcetest.ParseTemplate(awsdiscovery.RemediationCloudFormationTemplate)
	if err != nil {
		return nil, err
	}
	p, err := enforcetest.RolePolicy(tpl, "AuthSecRemediationRole", account)
	if err != nil {
		return nil, err
	}
	return &Account{AccountID: account, policy: p, Principals: map[string]*Principal{}, Policies: map[string]*Policy{},
		Secrets: map[string]*Secret{}, Fail: map[string]string{}, LieOnRead: map[string]bool{},
		stale: map[string]*Principal{}, staleP: map[string]*Policy{}, Now: time.Now}, nil
}

// RemoveStatement drops a statement from the simulated policy (a stack
// without it).
func (a *Account) RemoveStatement(sid string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var keep []enforcetest.Statement
	for _, s := range a.policy.Statements {
		if s.Sid != sid {
			keep = append(keep, s)
		}
	}
	a.policy.Statements = keep
}

// ARN helpers.
func (a *Account) RoleARN(name string) string { return "arn:aws:iam::" + a.AccountID + ":role/" + name }
func (a *Account) UserARN(name string) string { return "arn:aws:iam::" + a.AccountID + ":user/" + name }
func (a *Account) PolicyARN(path, name string) string {
	return "arn:aws:iam::" + a.AccountID + ":policy" + path + name
}
func (a *Account) SecretARN(name string) string {
	return "arn:aws:secretsmanager:us-east-1:" + a.AccountID + ":secret:" + name + "-AbCdEf"
}

// AddRole adds a role.
func (a *Account) AddRole(name string, tags map[string]string) *Principal {
	p := &Principal{Kind: awsremediate.PrincipalRole, Name: name, Tags: tags, Inline: map[string]string{}}
	a.Principals[a.RoleARN(name)] = p
	return p
}

// AddUser adds a user.
func (a *Account) AddUser(name string, tags map[string]string, keys ...awsremediate.AccessKey) *Principal {
	p := &Principal{Kind: awsremediate.PrincipalUser, Name: name, Tags: tags, Inline: map[string]string{}, Keys: keys}
	a.Principals[a.UserARN(name)] = p
	return p
}

// AddPolicy adds a managed policy with one (default) version.
func (a *Account) AddPolicy(arn, doc string, tags map[string]string) *Policy {
	p := &Policy{ARN: arn, Tags: tags, Docs: map[string]string{}}
	p.add(doc, true, a.Now())
	a.Policies[arn] = p
	return p
}

func (p *Policy) add(doc string, def bool, at time.Time) string {
	p.next++
	id := fmt.Sprintf("v%d", p.next)
	if def {
		for i := range p.Versions {
			p.Versions[i].IsDefault = false
		}
	}
	p.Versions = append(p.Versions, awsremediate.PolicyVersion{ID: id, IsDefault: def, Created: at})
	p.Docs[id] = doc
	return id
}

// Default is the policy's default version id and document.
func (p *Policy) Default() (string, string) {
	for _, v := range p.Versions {
		if v.IsDefault {
			return v.ID, p.Docs[v.ID]
		}
	}
	return "", ""
}

// AddSecret adds a secret.
func (a *Account) AddSecret(name string, tags map[string]string, rotation bool) *Secret {
	s := &Secret{ARN: a.SecretARN(name), Tags: tags, RotationEnabled: rotation, Values: map[string]string{}}
	s.next++
	s.Current = fmt.Sprintf("ver-%d", s.next)
	s.Values[s.Current] = "initial"
	a.Secrets[s.ARN] = s
	return s
}

// apiErr is an AWS API error with a code.
type apiErr struct{ code, msg string }

func (e apiErr) Error() string                 { return e.code + ": " + e.msg }
func (e apiErr) ErrorCode() string             { return e.code }
func (e apiErr) ErrorMessage() string          { return e.msg }
func (e apiErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

// APIError builds an AWS API error (tests).
func APIError(code string) error { return apiErr{code: code, msg: code} }

type sessionKey struct{}

// WithSession marks ctx as a remediation session (the writer the fake
// assumer returns records it on every call).
func WithSession(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, sessionKey{}, name)
}

func (a *Account) authorise(ctx context.Context, action, resource string, cond map[string]string) error {
	sess, _ := ctx.Value(sessionKey{}).(string)
	call := Call{Action: action, Resource: resource, Session: sess, At: a.Now()}
	if code, ok := a.Fail[action]; ok {
		call.Err = code
		a.Calls = append(a.Calls, call)
		return apiErr{code: code, msg: action + " failed (injected)"}
	}
	d := a.policy.Evaluate(enforcetest.Request{Action: action, Resource: resource, Context: cond})
	if !d.Allowed {
		call.Err = "AccessDenied"
		a.Calls = append(a.Calls, call)
		return apiErr{code: "AccessDenied", msg: "User is not authorized to perform: " + action + " on resource: " + resource}
	}
	a.Calls = append(a.Calls, call)
	return nil
}

func tagCtx(tags map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range tags {
		out["aws:ResourceTag/"+k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func (a *Account) principal(p awsremediate.Principal) (*Principal, string, error) {
	arn := a.RoleARN(p.Name)
	if p.Kind == awsremediate.PrincipalUser {
		arn = a.UserARN(p.Name)
	}
	pr := a.Principals[arn]
	if pr == nil {
		return nil, arn, apiErr{code: "NoSuchEntity", msg: p.Name + " cannot be found"}
	}
	return pr, arn, nil
}

func iamAction(p awsremediate.Principal, role, user string) string {
	if p.Kind == awsremediate.PrincipalUser {
		return "iam:" + user
	}
	return "iam:" + role
}

func (a *Account) snapshot(arn string, pr *Principal) {
	if !a.LieOnRead[arn] {
		return
	}
	cp := *pr
	cp.Attached = append([]string(nil), pr.Attached...)
	cp.Inline = map[string]string{}
	for k, v := range pr.Inline {
		cp.Inline[k] = v
	}
	cp.Keys = append([]awsremediate.AccessKey(nil), pr.Keys...)
	if _, done := a.stale[arn]; !done {
		a.stale[arn] = &cp
	}
}

/* --------------------------------- writes --------------------------------- */

// Writer is the fake's remediation session (what the fake assumer returns).
type Writer struct {
	A       *Account
	Session string
}

func (w Writer) ctx(ctx context.Context) context.Context { return WithSession(ctx, w.Session) }

func (w Writer) DetachPolicy(ctx context.Context, p awsremediate.Principal, policyARN string) error {
	a := w.A
	a.mu.Lock()
	defer a.mu.Unlock()
	pr, arn, err := a.principal(p)
	if err != nil {
		return err
	}
	if err := a.authorise(w.ctx(ctx), iamAction(p, "DetachRolePolicy", "DetachUserPolicy"), arn,
		tagCtx(pr.Tags, map[string]string{"iam:PolicyARN": policyARN})); err != nil {
		return err
	}
	a.snapshot(arn, pr)
	for i, x := range pr.Attached {
		if x == policyARN {
			pr.Attached = append(pr.Attached[:i], pr.Attached[i+1:]...)
			return nil
		}
	}
	return apiErr{code: "NoSuchEntity", msg: "policy not attached"}
}

func (w Writer) AttachPolicy(ctx context.Context, p awsremediate.Principal, policyARN string) error {
	a := w.A
	a.mu.Lock()
	defer a.mu.Unlock()
	pr, arn, err := a.principal(p)
	if err != nil {
		return err
	}
	if err := a.authorise(w.ctx(ctx), iamAction(p, "AttachRolePolicy", "AttachUserPolicy"), arn,
		tagCtx(pr.Tags, map[string]string{"iam:PolicyARN": policyARN})); err != nil {
		return err
	}
	if a.Policies[policyARN] == nil {
		return apiErr{code: "NoSuchEntity", msg: "policy not found"}
	}
	a.snapshot(arn, pr)
	pr.Attached = append(pr.Attached, policyARN)
	return nil
}

func (w Writer) CreatePolicy(ctx context.Context, path, name, document string, tags map[string]string) (string, error) {
	a := w.A
	a.mu.Lock()
	defer a.mu.Unlock()
	arn := a.PolicyARN(path, name)
	if err := a.authorise(w.ctx(ctx), "iam:CreatePolicy", arn, nil); err != nil {
		return "", err
	}
	if a.Policies[arn] != nil {
		return "", apiErr{code: "EntityAlreadyExists", msg: "exists"}
	}
	p := &Policy{ARN: arn, Tags: tags, Docs: map[string]string{}}
	p.add(document, true, a.Now())
	a.Policies[arn] = p
	return arn, nil
}

func (w Writer) PutInlinePolicy(ctx context.Context, p awsremediate.Principal, name, document string) error {
	a := w.A
	a.mu.Lock()
	defer a.mu.Unlock()
	pr, arn, err := a.principal(p)
	if err != nil {
		return err
	}
	if err := a.authorise(w.ctx(ctx), iamAction(p, "PutRolePolicy", "PutUserPolicy"), arn, tagCtx(pr.Tags, nil)); err != nil {
		return err
	}
	a.snapshot(arn, pr)
	pr.Inline[name] = document
	return nil
}

func (w Writer) DeleteInlinePolicy(ctx context.Context, p awsremediate.Principal, name string) error {
	a := w.A
	a.mu.Lock()
	defer a.mu.Unlock()
	pr, arn, err := a.principal(p)
	if err != nil {
		return err
	}
	if err := a.authorise(w.ctx(ctx), iamAction(p, "DeleteRolePolicy", "DeleteUserPolicy"), arn, tagCtx(pr.Tags, nil)); err != nil {
		return err
	}
	if _, ok := pr.Inline[name]; !ok {
		return apiErr{code: "NoSuchEntity", msg: "no such inline policy"}
	}
	a.snapshot(arn, pr)
	delete(pr.Inline, name)
	return nil
}

func (w Writer) CreatePolicyVersion(ctx context.Context, policyARN, document string, setDefault bool) (string, error) {
	a := w.A
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.Policies[policyARN]
	var tags map[string]string
	if p != nil {
		tags = p.Tags
	}
	if err := a.authorise(w.ctx(ctx), "iam:CreatePolicyVersion", policyARN, tagCtx(tags, nil)); err != nil {
		return "", err
	}
	if p == nil {
		return "", apiErr{code: "NoSuchEntity", msg: "policy not found"}
	}
	if len(p.Versions) >= 5 {
		return "", apiErr{code: "LimitExceeded", msg: "a policy can have at most 5 versions"}
	}
	if a.LieOnRead[policyARN] {
		if _, done := a.staleP[policyARN]; !done {
			cp := *p
			cp.Versions = append([]awsremediate.PolicyVersion(nil), p.Versions...)
			cp.Docs = map[string]string{}
			for k, v := range p.Docs {
				cp.Docs[k] = v
			}
			a.staleP[policyARN] = &cp
		}
	}
	return p.add(document, setDefault, a.Now()), nil
}

func (w Writer) DeletePolicyVersion(ctx context.Context, policyARN, versionID string) error {
	a := w.A
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.Policies[policyARN]
	var tags map[string]string
	if p != nil {
		tags = p.Tags
	}
	if err := a.authorise(w.ctx(ctx), "iam:DeletePolicyVersion", policyARN, tagCtx(tags, nil)); err != nil {
		return err
	}
	if p == nil {
		return apiErr{code: "NoSuchEntity", msg: "policy not found"}
	}
	for i, v := range p.Versions {
		if v.ID == versionID {
			if v.IsDefault {
				return apiErr{code: "DeleteConflict", msg: "cannot delete the default version"}
			}
			p.Versions = append(p.Versions[:i], p.Versions[i+1:]...)
			delete(p.Docs, versionID)
			return nil
		}
	}
	return apiErr{code: "NoSuchEntity", msg: "version not found"}
}

// Leaked is every secret value the fake ever generated for a key (a test
// asserts none of them reaches a row, an event or a log).
var (
	leakedMu sync.Mutex
	leaked   []string
)

// GeneratedSecrets returns the key secrets the fakes generated.
func GeneratedSecrets() []string {
	leakedMu.Lock()
	defer leakedMu.Unlock()
	return append([]string(nil), leaked...)
}

func (w Writer) CreateAccessKey(ctx context.Context, user string) (awsremediate.NewKey, error) {
	a := w.A
	a.mu.Lock()
	defer a.mu.Unlock()
	p := awsremediate.Principal{Kind: awsremediate.PrincipalUser, Name: user}
	pr, arn, err := a.principal(p)
	if err != nil {
		return awsremediate.NewKey{}, err
	}
	if err := a.authorise(w.ctx(ctx), "iam:CreateAccessKey", arn, tagCtx(pr.Tags, nil)); err != nil {
		return awsremediate.NewKey{}, err
	}
	if len(pr.Keys) >= 2 {
		return awsremediate.NewKey{}, apiErr{code: "LimitExceeded", msg: "two keys already"}
	}
	a.snapshot(arn, pr)
	a.keyN++
	id := fmt.Sprintf("AKIANEWKEY%010d", a.keyN)
	secret := fmt.Sprintf("SuperSecretKeyMaterial%dDoNotLeak%d", a.keyN, a.Now().UnixNano())
	leakedMu.Lock()
	leaked = append(leaked, secret)
	leakedMu.Unlock()
	pr.Keys = append(pr.Keys, awsremediate.AccessKey{ID: id, Active: true})
	return awsremediate.NewAccessKey(id, secret), nil
}

func (w Writer) UpdateAccessKey(ctx context.Context, user, keyID string, active bool) error {
	a := w.A
	a.mu.Lock()
	defer a.mu.Unlock()
	pr, arn, err := a.principal(awsremediate.Principal{Kind: awsremediate.PrincipalUser, Name: user})
	if err != nil {
		return err
	}
	if err := a.authorise(w.ctx(ctx), "iam:UpdateAccessKey", arn, tagCtx(pr.Tags, nil)); err != nil {
		return err
	}
	a.snapshot(arn, pr)
	for i := range pr.Keys {
		if pr.Keys[i].ID == keyID {
			pr.Keys[i].Active = active
			return nil
		}
	}
	return apiErr{code: "NoSuchEntity", msg: "key not found"}
}

func (w Writer) DeleteAccessKey(ctx context.Context, user, keyID string) error {
	a := w.A
	a.mu.Lock()
	defer a.mu.Unlock()
	pr, arn, err := a.principal(awsremediate.Principal{Kind: awsremediate.PrincipalUser, Name: user})
	if err != nil {
		return err
	}
	if err := a.authorise(w.ctx(ctx), "iam:DeleteAccessKey", arn, tagCtx(pr.Tags, nil)); err != nil {
		return err
	}
	for i := range pr.Keys {
		if pr.Keys[i].ID == keyID {
			pr.Keys = append(pr.Keys[:i], pr.Keys[i+1:]...)
			return nil
		}
	}
	return apiErr{code: "NoSuchEntity", msg: "key not found"}
}

func (w Writer) RotateSecret(ctx context.Context, secretARN string) (string, error) {
	a := w.A
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.Secrets[secretARN]
	var tags map[string]string
	if s != nil {
		tags = s.Tags
	}
	if err := a.authorise(w.ctx(ctx), "secretsmanager:RotateSecret", secretARN, tagCtx(tags, nil)); err != nil {
		return "", err
	}
	if s == nil {
		return "", apiErr{code: "ResourceNotFoundException", msg: "secret not found"}
	}
	if !s.RotationEnabled {
		return "", apiErr{code: "InvalidRequestException", msg: "rotation is not configured"}
	}
	s.next++
	s.Current = fmt.Sprintf("ver-%d", s.next)
	s.Values[s.Current] = "rotated-by-its-own-function"
	return s.Current, nil
}

func (w Writer) PutSecretValue(ctx context.Context, secretARN, value string) (string, error) {
	a := w.A
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.Secrets[secretARN]
	var tags map[string]string
	if s != nil {
		tags = s.Tags
	}
	if err := a.authorise(w.ctx(ctx), "secretsmanager:PutSecretValue", secretARN, tagCtx(tags, nil)); err != nil {
		return "", err
	}
	if s == nil {
		return "", apiErr{code: "ResourceNotFoundException", msg: "secret not found"}
	}
	s.next++
	s.Current = fmt.Sprintf("ver-%d", s.next)
	s.Values[s.Current] = value
	return s.Current, nil
}

/* --------------------------------- reads ---------------------------------- */

func (a *Account) readPrincipal(p awsremediate.Principal) (*Principal, error) {
	pr, arn, err := a.principal(p)
	if err != nil {
		return nil, err
	}
	if st := a.stale[arn]; st != nil {
		return st, nil
	}
	return pr, nil
}

func (a *Account) ListAttachedPolicies(_ context.Context, p awsremediate.Principal) ([]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	pr, err := a.readPrincipal(p)
	if err != nil {
		return nil, err
	}
	out := append([]string(nil), pr.Attached...)
	sort.Strings(out)
	return out, nil
}

func (a *Account) GetInlinePolicy(_ context.Context, p awsremediate.Principal, name string) (string, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	pr, err := a.readPrincipal(p)
	if err != nil {
		return "", false, err
	}
	d, ok := pr.Inline[name]
	return d, ok, nil
}

func (a *Account) readPolicy(arn string) (*Policy, error) {
	if p := a.staleP[arn]; p != nil {
		return p, nil
	}
	p := a.Policies[arn]
	if p == nil {
		return nil, apiErr{code: "NoSuchEntity", msg: "policy not found"}
	}
	return p, nil
}

func (a *Account) GetDefaultPolicyVersion(_ context.Context, arn string) (string, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, err := a.readPolicy(arn)
	if err != nil {
		return "", "", err
	}
	v, d := p.Default()
	return v, d, nil
}

func (a *Account) ListPolicyVersions(_ context.Context, arn string) ([]awsremediate.PolicyVersion, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, err := a.readPolicy(arn)
	if err != nil {
		return nil, err
	}
	return append([]awsremediate.PolicyVersion(nil), p.Versions...), nil
}

func (a *Account) GetPolicyVersion(_ context.Context, arn, versionID string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, err := a.readPolicy(arn)
	if err != nil {
		return "", err
	}
	d, ok := p.Docs[versionID]
	if !ok {
		return "", apiErr{code: "NoSuchEntity", msg: "version not found"}
	}
	return d, nil
}

func (a *Account) PolicyExists(_ context.Context, arn string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Policies[arn] != nil, nil
}

func (a *Account) ListAccessKeys(_ context.Context, user string) ([]awsremediate.AccessKey, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	pr, err := a.readPrincipal(awsremediate.Principal{Kind: awsremediate.PrincipalUser, Name: user})
	if err != nil {
		return nil, err
	}
	return append([]awsremediate.AccessKey(nil), pr.Keys...), nil
}

func (a *Account) DescribeSecret(_ context.Context, arn string) (*awsremediate.SecretInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.Secrets[arn]
	if s == nil {
		return nil, apiErr{code: "ResourceNotFoundException", msg: "secret not found"}
	}
	return &awsremediate.SecretInfo{ARN: s.ARN, Name: strings.TrimSuffix(s.ARN[strings.LastIndex(s.ARN, ":")+1:], "-AbCdEf"),
		RotationEnabled: s.RotationEnabled, CurrentVersion: s.Current, Tags: s.Tags}, nil
}

// Session returns the account as one remediation's Account: reads through
// the fake account, writes recorded under session.
func (a *Account) Session(session string) awsremediate.Account {
	return awsremediate.Join(a, Writer{A: a, Session: session})
}

// Count is how many calls of action the fake answered (allowed or not).
func (a *Account) Count(action string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, c := range a.Calls {
		if c.Action == action {
			n++
		}
	}
	return n
}

// Succeeded lists the allowed calls (the CloudTrail an evidence test feeds).
func (a *Account) Succeeded() []Call {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []Call
	for _, c := range a.Calls {
		if c.Err == "" {
			out = append(out, c)
		}
	}
	return out
}
