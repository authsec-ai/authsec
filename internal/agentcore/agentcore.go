// Package agentcore pushes AuthSec's compiled runtime allow-lists to an
// Amazon Bedrock AgentCore policy engine as Cedar policies, reads them back,
// and reads a gateway's policy-engine configuration (Phase 3 R3,
// SPEC-iga-phase3-policy.md §12.4; requirements R-01, R-04).
//
// UNVERIFIED. The live client is written against the aws-sdk-go-v2
// bedrockagentcorecontrol types in this module (CreatePolicy, UpdatePolicy,
// DeletePolicy, ListPolicies, GetGateway; types.PolicyDefinitionMemberCedar,
// types.GatewayPolicyEngineConfiguration). It has never been run against an
// AWS account: §12.4's lab contract 1 (the AgentCore policy API surface) is
// not established, so the Cedar entity shapes (igagov.CompileCedar), the
// validation mode, eventual consistency of ListPolicies after a write, and
// the IAM permissions a writer needs are all unproven. Nothing in this
// package claims enforcement: coverage is decided by the service from a
// recorded routing proof (DECISION R3-11).
package agentcore

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"

	"github.com/authsec-ai/authsec/internal/igagov"
)

// Policy is one policy in an engine, as AuthSec reads it.
type Policy struct {
	PolicyID  string `json:"policy_id"`
	Name      string `json:"name"`
	Statement string `json:"statement"`
	Status    string `json:"status"`
	Mode      string `json:"enforcement_mode,omitempty"`
}

// Gateway is a gateway's policy-engine configuration.
type Gateway struct {
	GatewayID       string `json:"gateway_id"`
	PolicyEngineARN string `json:"policy_engine_arn"`
	// Mode is LOG_ONLY or ENFORCE ("" when no engine is attached).
	Mode string `json:"mode"`
}

// Client is the AgentCore surface R3 uses.
type Client interface {
	ListPolicies(ctx context.Context, engineID string) ([]Policy, error)
	CreatePolicy(ctx context.Context, engineID, name, statement, description string) (Policy, error)
	UpdatePolicy(ctx context.Context, engineID, policyID, statement string) (Policy, error)
	DeletePolicy(ctx context.Context, engineID, policyID string) error
	GetGateway(ctx context.Context, gatewayID string) (Gateway, error)
}

// ControlAPI is the subset of *bedrockagentcorecontrol.Client the live
// client calls.
type ControlAPI interface {
	ListPolicies(ctx context.Context, in *bedrockagentcorecontrol.ListPoliciesInput, opts ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListPoliciesOutput, error)
	CreatePolicy(ctx context.Context, in *bedrockagentcorecontrol.CreatePolicyInput, opts ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.CreatePolicyOutput, error)
	UpdatePolicy(ctx context.Context, in *bedrockagentcorecontrol.UpdatePolicyInput, opts ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.UpdatePolicyOutput, error)
	DeletePolicy(ctx context.Context, in *bedrockagentcorecontrol.DeletePolicyInput, opts ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.DeletePolicyOutput, error)
	GetGateway(ctx context.Context, in *bedrockagentcorecontrol.GetGatewayInput, opts ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetGatewayOutput, error)
}

// Live is the AWS client (UNVERIFIED, see the package comment).
type Live struct{ api ControlAPI }

// NewLive wraps a bedrockagentcorecontrol client.
func NewLive(api ControlAPI) *Live { return &Live{api: api} }

// NewLiveFromConfig builds the live client from an AWS config.
func NewLiveFromConfig(cfg aws.Config) *Live {
	return NewLive(bedrockagentcorecontrol.NewFromConfig(cfg))
}

const maxPages = 50

func cedarOf(d types.PolicyDefinition) string {
	if c, ok := d.(*types.PolicyDefinitionMemberCedar); ok {
		return aws.ToString(c.Value.Statement)
	}
	return ""
}

// ListPolicies pages through the engine's policies.
func (l *Live) ListPolicies(ctx context.Context, engineID string) ([]Policy, error) {
	var out []Policy
	var next *string
	for page := 0; page < maxPages; page++ {
		resp, err := l.api.ListPolicies(ctx, &bedrockagentcorecontrol.ListPoliciesInput{
			PolicyEngineId: aws.String(engineID), NextToken: next, MaxResults: aws.Int32(100)})
		if err != nil {
			return nil, fmt.Errorf("bedrock-agentcore:ListPolicies: %w", err)
		}
		for _, p := range resp.Policies {
			out = append(out, Policy{PolicyID: aws.ToString(p.PolicyId), Name: aws.ToString(p.Name),
				Statement: cedarOf(p.Definition), Status: string(p.Status), Mode: string(p.EnforcementMode)})
		}
		if resp.NextToken == nil || aws.ToString(resp.NextToken) == "" {
			return out, nil
		}
		next = resp.NextToken
	}
	return nil, errors.New("bedrock-agentcore:ListPolicies: too many pages")
}

// CreatePolicy creates one Cedar policy, ACTIVE, failing on any analyzer
// finding (FAIL_ON_ANY_FINDINGS).
func (l *Live) CreatePolicy(ctx context.Context, engineID, name, statement, description string) (Policy, error) {
	resp, err := l.api.CreatePolicy(ctx, &bedrockagentcorecontrol.CreatePolicyInput{
		PolicyEngineId:  aws.String(engineID),
		Name:            aws.String(name),
		Description:     aws.String(description),
		Definition:      &types.PolicyDefinitionMemberCedar{Value: types.CedarPolicy{Statement: aws.String(statement)}},
		EnforcementMode: types.EnforcementModeActive,
		ValidationMode:  types.PolicyValidationModeFailOnAnyFindings,
		ClientToken:     aws.String(clientToken(engineID, name, statement)),
	})
	if err != nil {
		return Policy{}, fmt.Errorf("bedrock-agentcore:CreatePolicy %s: %w", name, err)
	}
	return Policy{PolicyID: aws.ToString(resp.PolicyId), Name: aws.ToString(resp.Name), Statement: cedarOf(resp.Definition),
		Status: string(resp.Status), Mode: string(resp.EnforcementMode)}, nil
}

// UpdatePolicy replaces a policy's statement.
func (l *Live) UpdatePolicy(ctx context.Context, engineID, policyID, statement string) (Policy, error) {
	resp, err := l.api.UpdatePolicy(ctx, &bedrockagentcorecontrol.UpdatePolicyInput{
		PolicyEngineId: aws.String(engineID),
		PolicyId:       aws.String(policyID),
		Definition:     &types.PolicyDefinitionMemberCedar{Value: types.CedarPolicy{Statement: aws.String(statement)}},
		ValidationMode: types.PolicyValidationModeFailOnAnyFindings,
	})
	if err != nil {
		return Policy{}, fmt.Errorf("bedrock-agentcore:UpdatePolicy %s: %w", policyID, err)
	}
	return Policy{PolicyID: aws.ToString(resp.PolicyId), Name: aws.ToString(resp.Name), Statement: cedarOf(resp.Definition),
		Status: string(resp.Status), Mode: string(resp.EnforcementMode)}, nil
}

// DeletePolicy deletes one policy.
func (l *Live) DeletePolicy(ctx context.Context, engineID, policyID string) error {
	if _, err := l.api.DeletePolicy(ctx, &bedrockagentcorecontrol.DeletePolicyInput{
		PolicyEngineId: aws.String(engineID), PolicyId: aws.String(policyID)}); err != nil {
		return fmt.Errorf("bedrock-agentcore:DeletePolicy %s: %w", policyID, err)
	}
	return nil
}

// GetGateway reads the gateway's policy-engine configuration.
func (l *Live) GetGateway(ctx context.Context, gatewayID string) (Gateway, error) {
	resp, err := l.api.GetGateway(ctx, &bedrockagentcorecontrol.GetGatewayInput{GatewayIdentifier: aws.String(gatewayID)})
	if err != nil {
		return Gateway{}, fmt.Errorf("bedrock-agentcore:GetGateway %s: %w", gatewayID, err)
	}
	g := Gateway{GatewayID: aws.ToString(resp.GatewayId)}
	if c := resp.PolicyEngineConfiguration; c != nil {
		g.PolicyEngineARN, g.Mode = aws.ToString(c.Arn), string(c.Mode)
	}
	return g, nil
}

// clientToken makes CreatePolicy idempotent for the same content (<= 64
// chars, as the AWS client tokens are).
func clientToken(parts ...string) string {
	h := igagov.ContentHash([]byte(strings.Join(parts, "\x1f")))
	return strings.TrimPrefix(h, "sha256:")[:48]
}

/* --------------------------------- reconcile -------------------------------- */

// PushResult is what one push did.
type PushResult struct {
	Created []string `json:"created"`
	Updated []string `json:"updated"`
	Deleted []string `json:"deleted"`
	Kept    []string `json:"kept"`
	Remote  []Policy `json:"remote"`
}

// Push makes the engine's AuthSec-owned policies of one AuthSec policy (names
// starting prefix) equal to desired: create the missing, update the changed,
// delete the ones no longer allow-listed. Policies without the prefix are the
// customer's and never touched.
func Push(ctx context.Context, c Client, engineID, prefix, description string, desired []igagov.CedarPolicy) (*PushResult, error) {
	remote, err := c.ListPolicies(ctx, engineID)
	if err != nil {
		return nil, err
	}
	have := map[string]Policy{}
	for _, p := range remote {
		if strings.HasPrefix(p.Name, prefix) {
			have[p.Name] = p
		}
	}
	res := &PushResult{Created: []string{}, Updated: []string{}, Deleted: []string{}, Kept: []string{}}
	want := map[string]bool{}
	for _, d := range desired {
		want[d.Name] = true
		p, ok := have[d.Name]
		switch {
		case !ok:
			if _, err := c.CreatePolicy(ctx, engineID, d.Name, d.Statement, description); err != nil {
				return res, err
			}
			res.Created = append(res.Created, d.Name)
		case normalize(p.Statement) != normalize(d.Statement):
			if _, err := c.UpdatePolicy(ctx, engineID, p.PolicyID, d.Statement); err != nil {
				return res, err
			}
			res.Updated = append(res.Updated, d.Name)
		default:
			res.Kept = append(res.Kept, d.Name)
		}
	}
	names := make([]string, 0, len(have))
	for n := range have {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if !want[n] {
			if err := c.DeletePolicy(ctx, engineID, have[n].PolicyID); err != nil {
				return res, err
			}
			res.Deleted = append(res.Deleted, n)
		}
	}
	return res, nil
}

// Readback compares the engine's AuthSec-owned policies of one AuthSec policy
// with desired; it reports the differences ("" each when equal).
func Readback(ctx context.Context, c Client, engineID, prefix string, desired []igagov.CedarPolicy) (bool, []Policy, []string, error) {
	remote, err := c.ListPolicies(ctx, engineID)
	if err != nil {
		return false, nil, nil, err
	}
	owned := []Policy{}
	have := map[string]Policy{}
	for _, p := range remote {
		if strings.HasPrefix(p.Name, prefix) {
			owned = append(owned, p)
			have[p.Name] = p
		}
	}
	var diffs []string
	want := map[string]bool{}
	for _, d := range desired {
		want[d.Name] = true
		p, ok := have[d.Name]
		switch {
		case !ok:
			diffs = append(diffs, "missing "+d.Name)
		case normalize(p.Statement) != normalize(d.Statement):
			diffs = append(diffs, "changed "+d.Name)
		case p.Status != "" && p.Status != string(types.PolicyStatusActive):
			diffs = append(diffs, "not active "+d.Name+" ("+p.Status+")")
		case p.Mode != "" && p.Mode != string(types.EnforcementModeActive):
			diffs = append(diffs, "log only "+d.Name)
		}
	}
	for n := range have {
		if !want[n] {
			diffs = append(diffs, "unexpected "+n)
		}
	}
	sort.Strings(diffs)
	return len(diffs) == 0, owned, diffs, nil
}

func normalize(s string) string { return strings.Join(strings.Fields(s), " ") }

/* ------------------------------------ fake ---------------------------------- */

// Fake is an in-memory engine and gateway set (tests and local runs).
type Fake struct {
	mu       sync.Mutex
	seq      int
	Engines  map[string]map[string]Policy
	Gateways map[string]Gateway
	// Fail makes every call return this error when set.
	Fail error
}

// NewFake builds an empty fake.
func NewFake() *Fake {
	return &Fake{Engines: map[string]map[string]Policy{}, Gateways: map[string]Gateway{}}
}

func (f *Fake) engine(id string) map[string]Policy {
	e, ok := f.Engines[id]
	if !ok {
		e = map[string]Policy{}
		f.Engines[id] = e
	}
	return e
}

// ListPolicies implements Client.
func (f *Fake) ListPolicies(_ context.Context, engineID string) ([]Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail != nil {
		return nil, f.Fail
	}
	var out []Policy
	for _, p := range f.engine(engineID) {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// CreatePolicy implements Client.
func (f *Fake) CreatePolicy(_ context.Context, engineID, name, statement, _ string) (Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail != nil {
		return Policy{}, f.Fail
	}
	e := f.engine(engineID)
	for _, p := range e {
		if p.Name == name {
			return Policy{}, fmt.Errorf("ConflictException: policy %s exists", name)
		}
	}
	f.seq++
	p := Policy{PolicyID: fmt.Sprintf("%s-%010d", name, f.seq), Name: name, Statement: statement,
		Status: string(types.PolicyStatusActive), Mode: string(types.EnforcementModeActive)}
	e[p.PolicyID] = p
	return p, nil
}

// UpdatePolicy implements Client.
func (f *Fake) UpdatePolicy(_ context.Context, engineID, policyID, statement string) (Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail != nil {
		return Policy{}, f.Fail
	}
	e := f.engine(engineID)
	p, ok := e[policyID]
	if !ok {
		return Policy{}, fmt.Errorf("ResourceNotFoundException: %s", policyID)
	}
	p.Statement = statement
	e[policyID] = p
	return p, nil
}

// DeletePolicy implements Client.
func (f *Fake) DeletePolicy(_ context.Context, engineID, policyID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail != nil {
		return f.Fail
	}
	delete(f.engine(engineID), policyID)
	return nil
}

// GetGateway implements Client.
func (f *Fake) GetGateway(_ context.Context, gatewayID string) (Gateway, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail != nil {
		return Gateway{}, f.Fail
	}
	g, ok := f.Gateways[gatewayID]
	if !ok {
		return Gateway{}, fmt.Errorf("ResourceNotFoundException: gateway %s", gatewayID)
	}
	return g, nil
}
