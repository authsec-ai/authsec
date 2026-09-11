package awsdiscovery

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
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
}

// NewBedrockReader constructs a reader over the given clients.
func NewBedrockReader(a BedrockAgentAPI, c AgentCoreAPI) *BedrockReader {
	return &BedrockReader{agents: a, agentCore: c}
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
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: bedrock agents", errTooManyPages)
		}
		resp, err := r.agents.ListAgents(ctx, &bedrockagent.ListAgentsInput{NextToken: next})
		if err != nil {
			return out, classify(err)
		}
		for _, summary := range resp.AgentSummaries {
			w, ok := r.agentDetail(ctx, aws.ToString(summary.AgentId), aws.ToString(summary.AgentName))
			if !ok {
				continue
			}
			out = append(out, w)
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, nil
		}
		next = resp.NextToken
	}
}

// agentDetail resolves the execution role and foundation model.
//
// A detail call that fails degrades to the summary rather than dropping the
// agent: an agent AWS listed exists, and recording it unattributed is better
// than reporting an account as having no agents.
func (r *BedrockReader) agentDetail(ctx context.Context, agentID, agentName string) (Workload, bool) {
	if agentID == "" {
		return Workload{}, false
	}
	built := Workload{
		RuntimeKind: "bedrock_agent",
		NativeID:    agentID,
		Name:        agentName,
	}

	detail, err := r.agents.GetAgent(ctx, &bedrockagent.GetAgentInput{AgentId: aws.String(agentID)})
	if err != nil || detail.Agent == nil {
		return built, true
	}
	a := detail.Agent
	// Prefer the ARN as the native id once we have it: it is globally unique,
	// where an agent id is only unique within a region.
	if arn := aws.ToString(a.AgentArn); arn != "" {
		built.NativeID = arn
	}
	built.RoleARN = aws.ToString(a.AgentResourceRoleArn)
	built.FoundationModel = aws.ToString(a.FoundationModel)
	built.Status = string(a.AgentStatus)
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
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: agentcore runtimes", errTooManyPages)
		}
		resp, err := r.agentCore.ListAgentRuntimes(ctx, &bedrockagentcorecontrol.ListAgentRuntimesInput{
			NextToken: next,
		})
		if err != nil {
			return out, classify(err)
		}
		for _, rt := range resp.AgentRuntimes {
			w := Workload{
				RuntimeKind: "bedrock_agentcore_runtime",
				NativeID:    aws.ToString(rt.AgentRuntimeArn),
				Name:        aws.ToString(rt.AgentRuntimeName),
			}
			if role, ok := r.runtimeRole(ctx, aws.ToString(rt.AgentRuntimeId)); ok {
				w.RoleARN = role
			}
			out = append(out, w)
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, nil
		}
		next = resp.NextToken
	}
}

// runtimeRole resolves one runtime's role. A failure leaves the runtime
// unattributed rather than dropping it, same rule as agentDetail.
func (r *BedrockReader) runtimeRole(ctx context.Context, runtimeID string) (string, bool) {
	if runtimeID == "" {
		return "", false
	}
	detail, err := r.agentCore.GetAgentRuntime(ctx, &bedrockagentcorecontrol.GetAgentRuntimeInput{
		AgentRuntimeId: aws.String(runtimeID),
	})
	if err != nil {
		return "", false
	}
	return aws.ToString(detail.RoleArn), true
}
