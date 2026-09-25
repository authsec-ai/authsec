package awsdiscovery

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
)

// AWS's own managed agent surfaces: Bedrock Agents and Bedrock AgentCore
// runtimes.
//
// These are the only workloads in this package that AWS itself calls agents, so
// they are the least ambiguous rows the discovery writes -- unlike a Lambda
// function, which may or may not be one. They still land in cloud_workload
// rather than in an agent table, for the reason migration 015's header gives:
// discovery records what it observed and leaves the agent judgement to the
// ticket that owns it.
//
// Both surfaces need two calls each, and for the same reason: the list response
// does not carry the execution role, which is the entire point of discovering
// them. An agent whose role we cannot resolve tells us nothing about what it
// can reach.
//
// Prompt text and agent instructions are never read. ListAgents/GetAgent can
// return an agent's instruction, and this file does not copy it into any
// struct: it is the customer's prompt content, not identity metadata.

// BedrockAgentAPI is the slice of the Bedrock Agent client this package uses.
type BedrockAgentAPI interface {
	ListAgents(ctx context.Context, in *bedrockagent.ListAgentsInput, opts ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentsOutput, error)
	GetAgent(ctx context.Context, in *bedrockagent.GetAgentInput, opts ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentOutput, error)
}

// AgentCoreAPI is the slice of the Bedrock AgentCore control client this
// package uses.
type AgentCoreAPI interface {
	ListAgentRuntimes(ctx context.Context, in *bedrockagentcorecontrol.ListAgentRuntimesInput, opts ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListAgentRuntimesOutput, error)
	GetAgentRuntime(ctx context.Context, in *bedrockagentcorecontrol.GetAgentRuntimeInput, opts ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error)

	// ListGateways/GetGateway/ListGatewayTargets are the agent tool-path
	// segment: a Gateway is what turns a Lambda (or another backend) into an
	// MCP tool an agent can call, and a Target is one such exposed backend.
	// Granted in the role template from the start; this file is the first
	// caller.
	ListGateways(ctx context.Context, in *bedrockagentcorecontrol.ListGatewaysInput, opts ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewaysOutput, error)
	GetGateway(ctx context.Context, in *bedrockagentcorecontrol.GetGatewayInput, opts ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetGatewayOutput, error)
	ListGatewayTargets(ctx context.Context, in *bedrockagentcorecontrol.ListGatewayTargetsInput, opts ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewayTargetsOutput, error)

	// ListWorkloadIdentities: AgentCore's own principal for a runtime or tool,
	// separate from IAM. Recorded as evidence only (see
	// AWSWorkloadScanner.scanRegion) rather than as a reconciled cloud_identity
	// row -- it is discovered by the workload scanner, which runs after IAM
	// scanning has already reconciled cloud_identity for this generation, and
	// writing into that table from here would have every workload identity
	// deleted and recreated on every single scan.
	ListWorkloadIdentities(ctx context.Context, in *bedrockagentcorecontrol.ListWorkloadIdentitiesInput, opts ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListWorkloadIdentitiesOutput, error)

	// ListOauth2CredentialProviders/ListApiKeyCredentialProviders: the
	// credential providers an agent uses to call OUT to a third-party API --
	// Google, Slack, an arbitrary OAuth2 vendor, or a bare API key. List-only,
	// same as ListWorkloadIdentities: only a name, an ARN and a vendor come
	// back, never a secret value, never the credential a provider holds.
	// Granted in the role template from the start; this file is the first
	// caller.
	ListOauth2CredentialProviders(ctx context.Context, in *bedrockagentcorecontrol.ListOauth2CredentialProvidersInput, opts ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListOauth2CredentialProvidersOutput, error)
	ListApiKeyCredentialProviders(ctx context.Context, in *bedrockagentcorecontrol.ListApiKeyCredentialProvidersInput, opts ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListApiKeyCredentialProvidersOutput, error)
}

// NewBedrockAgentClient builds a real Bedrock Agent client.
func NewBedrockAgentClient(cfg aws.Config) BedrockAgentAPI {
	return bedrockagent.NewFromConfig(cfg)
}

// NewAgentCoreClient builds a real Bedrock AgentCore control client.
func NewAgentCoreClient(cfg aws.Config) AgentCoreAPI {
	return bedrockagentcorecontrol.NewFromConfig(cfg)
}

// BedrockReader reads one region's managed agents.
//
// Each client is optional. AgentCore is not available in every region Bedrock
// is, so a nil client or a denied read on one must not cost the other.
type BedrockReader struct {
	agents    BedrockAgentAPI
	agentCore AgentCoreAPI

	// The scope a constructed ARN is built in (WithScope). Without it a row
	// whose detail call failed keeps its bare id, and the graph constructs the
	// ARN from the connector instead.
	partition, region, account string
}

// NewBedrockReader constructs a reader over the given clients.
func NewBedrockReader(a BedrockAgentAPI, c AgentCoreAPI) *BedrockReader {
	return &BedrockReader{agents: a, agentCore: c}
}

// WithScope names the partition, region and account this reader's region
// belongs to, so an agent or gateway whose detail call failed is still keyed
// by its ARN -- constructed, deterministically, in the connector's partition --
// rather than by a bare id that changes the object's key on a transient
// failure (§1.3, E7).
func (r *BedrockReader) WithScope(partition, region, account string) *BedrockReader {
	r.partition, r.region, r.account = partition, region, account
	return r
}

func (r *BedrockReader) arn(runtimeKind, id string) string {
	return WorkloadARN(r.partition, runtimeKind, r.region, r.account, id)
}

// Agents lists every Bedrock agent in the region and resolves each one's
// execution role.
//
// GetAgent is a second call per agent and is not avoidable: the list summary
// carries the id, name and status but not AgentResourceRoleArn, which is the
// role the agent acts as and the only thing that ties it to a set of
// permissions.
func (r *BedrockReader) Agents(ctx context.Context) ([]Workload, error) {
	if r.agents == nil {
		return nil, nil
	}
	var out []Workload
	var next *string
	details := NewItemFailures("agents could not be read in detail", true)
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: bedrock agents", errTooManyPages)
		}
		resp, err := r.agents.ListAgents(ctx, &bedrockagent.ListAgentsInput{NextToken: next})
		if err != nil {
			return out, listErr("bedrock:ListAgents", err)
		}
		for _, summary := range resp.AgentSummaries {
			w, ok := r.agentDetail(ctx, summary, details)
			if !ok {
				continue
			}
			out = append(out, w)
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, details.Err(nil)
		}
		next = resp.NextToken
	}
}

// agentDetail resolves the execution role and foundation model.
//
// A detail call that fails KEEPS the agent -- AWS listed it, so it exists --
// under its ARN, CONSTRUCTED in the connector's partition, so a transient
// GetAgent failure never changes the object's key (§1.3, E7). Its status comes
// from the summary; its role and model are unknown this run and it is marked
// DetailIncomplete, so nothing downstream writes "no execution role" (D-53).
// The failure is counted, which makes bedrock-agents:<region> partial rather
// than silently reached.
func (r *BedrockReader) agentDetail(
	ctx context.Context, summary bedrockagenttypes.AgentSummary, details *ItemFailures,
) (Workload, bool) {
	agentID := aws.ToString(summary.AgentId)
	if agentID == "" {
		return Workload{}, false
	}
	details.Attempt()
	built := Workload{
		RuntimeKind: "bedrock_agent",
		NativeID:    r.arn("bedrock_agent", agentID),
		Name:        aws.ToString(summary.AgentName),
		Status:      string(summary.AgentStatus),
		SourceAPI:   "bedrock:ListAgents",
	}

	detail, err := r.agents.GetAgent(ctx, &bedrockagent.GetAgentInput{AgentId: aws.String(agentID)})
	if err == nil && detail.Agent == nil {
		err = fmt.Errorf("GetAgent returned no agent for %s", agentID)
	}
	if err != nil {
		details.Fail(agentID, "bedrock:GetAgent", err)
		built.DetailIncomplete = true
		built.DetailError = DetailErrorOf("bedrock:GetAgent", err)
		return built, true
	}
	a := detail.Agent
	// Prefer the ARN AWS returned: it is globally unique, where an agent id is
	// only unique within a region. The constructed one above is the same
	// string for a normal agent (unit-tested), so the key does not move.
	if arn := aws.ToString(a.AgentArn); arn != "" {
		built.NativeID = arn
	}
	built.RoleARN = aws.ToString(a.AgentResourceRoleArn)
	built.FoundationModel = aws.ToString(a.FoundationModel)
	if s := string(a.AgentStatus); s != "" {
		built.Status = s
	}
	built.SourceAPI = "bedrock:GetAgent"
	// a.Instruction is deliberately not read -- see this file's header.
	return built, true
}

// AgentRuntimes lists every AgentCore runtime in the region and resolves each
// one's role.
//
// Same two-call shape as Agents, and for the same reason: ListAgentRuntimes
// returns the runtime's identity and version but not its RoleArn.
func (r *BedrockReader) AgentRuntimes(ctx context.Context) ([]Workload, error) {
	if r.agentCore == nil {
		return nil, nil
	}
	var out []Workload
	var next *string
	details := NewItemFailures("runtimes could not be read in detail", true)
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: agentcore runtimes", errTooManyPages)
		}
		resp, err := r.agentCore.ListAgentRuntimes(ctx, &bedrockagentcorecontrol.ListAgentRuntimesInput{
			NextToken: next,
		})
		if err != nil {
			return out, listErr("bedrock-agentcore:ListAgentRuntimes", err)
		}
		for _, rt := range resp.AgentRuntimes {
			id := aws.ToString(rt.AgentRuntimeId)
			native := aws.ToString(rt.AgentRuntimeArn)
			if native == "" {
				native = r.arn("bedrock_agentcore_runtime", id)
			}
			if native == "" {
				continue
			}
			details.Attempt()
			// Status is on the list item (§1.4: "ARN, name, status"); the
			// detail call's own value, when it succeeds, is fresher.
			w := Workload{
				RuntimeKind: "bedrock_agentcore_runtime",
				NativeID:    native,
				Name:        aws.ToString(rt.AgentRuntimeName),
				Status:      string(rt.Status),
				SourceAPI:   "bedrock-agentcore:ListAgentRuntimes",
			}
			r.runtimeDetail(ctx, id, &w, details)
			out = append(out, w)
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, details.Err(nil)
		}
		next = resp.NextToken
	}
}

// runtimeDetail resolves one runtime's role and status. A failure keeps the
// runtime -- it was listed -- marked DetailIncomplete (role unknown, never
// "none", D-53), and is counted, same rule as agentDetail.
func (r *BedrockReader) runtimeDetail(ctx context.Context, runtimeID string, w *Workload, details *ItemFailures) {
	var err error
	var detail *bedrockagentcorecontrol.GetAgentRuntimeOutput
	if runtimeID == "" {
		err = fmt.Errorf("ListAgentRuntimes returned no runtime id for %s", w.NativeID)
	} else {
		detail, err = r.agentCore.GetAgentRuntime(ctx, &bedrockagentcorecontrol.GetAgentRuntimeInput{
			AgentRuntimeId: aws.String(runtimeID),
		})
	}
	if err != nil {
		details.Fail(w.NativeID, "bedrock-agentcore:GetAgentRuntime", err)
		w.DetailIncomplete = true
		w.DetailError = DetailErrorOf("bedrock-agentcore:GetAgentRuntime", err)
		return
	}
	w.RoleARN = aws.ToString(detail.RoleArn)
	if s := string(detail.Status); s != "" {
		w.Status = s
	}
	w.SourceAPI = "bedrock-agentcore:GetAgentRuntime"
}

// GatewayTarget is one backend a Gateway exposes as an MCP tool. An ATTRIBUTE
// of the gateway (§1.4: "targets are attributes, not objects"), carried on the
// gateway's own workload row and recorded as evidence under it: a target has
// no identity of its own to attribute it to, and its backing tool is not
// collected (GetGatewayTarget is never called, §1.2).
type GatewayTarget struct {
	GatewayNativeID string
	TargetID        string
	Name            string
	Status          string
	// Type is the provider's target type, verbatim: LAMBDA, MCP_SERVER,
	// OPEN_API_SCHEMA, SMITHY_MODEL, ... (§1.4 "each target's id, name, status
	// and type").
	Type string
}

// Gateways lists every AgentCore Gateway in the region, resolves each one's
// execution role, and lists its targets.
//
// Same two-call shape as Agents/AgentRuntimes: ListGateways omits the role,
// which is the entire reason to discover a gateway at all.
func (r *BedrockReader) Gateways(ctx context.Context) ([]Workload, []GatewayTarget, error) {
	if r.agentCore == nil {
		return nil, nil, nil
	}
	var workloads []Workload
	var targets []GatewayTarget
	var next *string
	details := NewItemFailures("gateways could not be read in detail", true)
	for page := 0; ; page++ {
		if page >= maxPages {
			return workloads, targets, fmt.Errorf("%w: agentcore gateways", errTooManyPages)
		}
		resp, err := r.agentCore.ListGateways(ctx, &bedrockagentcorecontrol.ListGatewaysInput{NextToken: next})
		if err != nil {
			return workloads, targets, listErr("bedrock-agentcore:ListGateways", err)
		}
		for _, summary := range resp.Items {
			id := aws.ToString(summary.GatewayId)
			if id == "" {
				continue
			}
			details.Attempt()
			// GatewaySummary carries no ARN, so the key starts CONSTRUCTED --
			// the same string GetGateway returns for a normal gateway -- and a
			// failed GetGateway cannot move it (§1.3).
			w := Workload{
				RuntimeKind: "bedrock_agentcore_gateway",
				NativeID:    r.arn("bedrock_agentcore_gateway", id),
				Name:        aws.ToString(summary.Name),
				Status:      string(summary.Status),
				SourceAPI:   "bedrock-agentcore:ListGateways",
			}
			detail, gerr := r.agentCore.GetGateway(ctx,
				&bedrockagentcorecontrol.GetGatewayInput{GatewayIdentifier: summary.GatewayId})
			if gerr != nil {
				// Role unknown this run, never "none" (D-53). Counted: until
				// the role template grants GetGateway (T2.4) this is every
				// gateway, and the surface must say so rather than read reached.
				details.Fail(id, "bedrock-agentcore:GetGateway", gerr)
				w.DetailIncomplete = true
				w.DetailError = DetailErrorOf("bedrock-agentcore:GetGateway", gerr)
			} else {
				if arn := aws.ToString(detail.GatewayArn); arn != "" {
					w.NativeID = arn
				}
				w.RoleARN = aws.ToString(detail.RoleArn)
				if s := string(detail.Status); s != "" {
					w.Status = s
				}
				w.SourceAPI = "bedrock-agentcore:GetGateway"
			}
			gwTargets, terr := r.gatewayTargets(ctx, id, w.NativeID)
			if terr != nil {
				details.Fail(id, "bedrock-agentcore:ListGatewayTargets", terr)
				w.TargetsIncomplete = true
			}
			w.Targets = gwTargets
			workloads = append(workloads, w)
			targets = append(targets, gwTargets...)
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return workloads, targets, details.Err(nil)
		}
		next = resp.NextToken
	}
}

// gatewayTargets lists one gateway's targets. A failure costs only this
// gateway's targets, never the gateway row itself or any other gateway's --
// but it is RETURNED, not swallowed: a target list cut short is not the
// gateway's whole list, and must not read as one.
func (r *BedrockReader) gatewayTargets(ctx context.Context, gatewayID, gatewayNativeID string) ([]GatewayTarget, error) {
	var out []GatewayTarget
	var next *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: gateway targets", errTooManyPages)
		}
		resp, err := r.agentCore.ListGatewayTargets(ctx, &bedrockagentcorecontrol.ListGatewayTargetsInput{
			GatewayIdentifier: aws.String(gatewayID), NextToken: next,
		})
		if err != nil {
			return out, err
		}
		for _, t := range resp.Items {
			out = append(out, GatewayTarget{
				GatewayNativeID: gatewayNativeID,
				TargetID:        aws.ToString(t.TargetId),
				Name:            aws.ToString(t.Name),
				Status:          string(t.Status),
				Type:            string(t.TargetType),
			})
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, nil
		}
		next = resp.NextToken
	}
}

// WorkloadIdentity is AgentCore's own principal for a runtime or tool --
// distinct from an IAM role, and carrying no role of its own to resolve. See
// the AgentCoreAPI.ListWorkloadIdentities comment for why this is recorded as
// evidence rather than a cloud_identity row.
type WorkloadIdentity struct {
	NativeID string
	Name     string
}

// WorkloadIdentities lists every AgentCore workload identity in the region.
func (r *BedrockReader) WorkloadIdentities(ctx context.Context) ([]WorkloadIdentity, error) {
	if r.agentCore == nil {
		return nil, nil
	}
	var out []WorkloadIdentity
	var next *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: agentcore workload identities", errTooManyPages)
		}
		resp, err := r.agentCore.ListWorkloadIdentities(ctx,
			&bedrockagentcorecontrol.ListWorkloadIdentitiesInput{NextToken: next})
		if err != nil {
			return out, listErr("bedrock-agentcore:ListWorkloadIdentities", err)
		}
		for _, wi := range resp.WorkloadIdentities {
			out = append(out, WorkloadIdentity{
				NativeID: aws.ToString(wi.WorkloadIdentityArn),
				Name:     aws.ToString(wi.Name),
			})
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, nil
		}
		next = resp.NextToken
	}
}

// CredentialProvider is one credential provider an agent can use to call OUT
// to a third-party API -- never a value, only enough to say the provider
// exists and what it is for. Kind is "oauth2" or "api_key", matching which
// of the two list calls found it; there is no reconciled table for either,
// so like WorkloadIdentity this is recorded as evidence only.
type CredentialProvider struct {
	Kind      string
	SourceAPI string
	NativeID  string
	Name      string
	Vendor    string
}

// CredentialProviders lists every OAuth2 and API-key credential provider in
// the region. A failure on one kind does not withhold the other -- they come
// from two independent AWS calls, so an account with no OAuth2 providers
// configured (a common, unremarkable state) must not suppress API-key
// evidence that read just fine, and vice versa.
func (r *BedrockReader) CredentialProviders(ctx context.Context) ([]CredentialProvider, error) {
	if r.agentCore == nil {
		return nil, nil
	}
	var out []CredentialProvider
	var firstErr error

	var oauthNext *string
	for page := 0; ; page++ {
		if page >= maxPages {
			firstErr = fmt.Errorf("%w: oauth2 credential providers", errTooManyPages)
			break
		}
		resp, err := r.agentCore.ListOauth2CredentialProviders(ctx,
			&bedrockagentcorecontrol.ListOauth2CredentialProvidersInput{NextToken: oauthNext})
		if err != nil {
			firstErr = listErr("bedrock-agentcore:ListOauth2CredentialProviders", err)
			break
		}
		for _, p := range resp.CredentialProviders {
			out = append(out, CredentialProvider{
				Kind:      "oauth2",
				SourceAPI: "bedrock-agentcore:ListOauth2CredentialProviders",
				NativeID:  aws.ToString(p.CredentialProviderArn),
				Name:      aws.ToString(p.Name),
				Vendor:    string(p.CredentialProviderVendor),
			})
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}
		oauthNext = resp.NextToken
	}

	var apiKeyNext *string
	for page := 0; ; page++ {
		if page >= maxPages {
			if firstErr == nil {
				firstErr = fmt.Errorf("%w: api key credential providers", errTooManyPages)
			}
			break
		}
		resp, err := r.agentCore.ListApiKeyCredentialProviders(ctx,
			&bedrockagentcorecontrol.ListApiKeyCredentialProvidersInput{NextToken: apiKeyNext})
		if err != nil {
			if firstErr == nil {
				firstErr = listErr("bedrock-agentcore:ListApiKeyCredentialProviders", err)
			}
			break
		}
		for _, p := range resp.CredentialProviders {
			out = append(out, CredentialProvider{
				Kind:      "api_key",
				SourceAPI: "bedrock-agentcore:ListApiKeyCredentialProviders",
				NativeID:  aws.ToString(p.CredentialProviderArn),
				Name:      aws.ToString(p.Name),
			})
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}
		apiKeyNext = resp.NextToken
	}

	return out, firstErr
}
