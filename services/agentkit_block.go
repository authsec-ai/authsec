package services

// Blocking one resource for one agent from the console (right-click "block"):
// a deny rule added to the agent's policy as a new version. The document is
// edited as a YAML tree, so the comments and order people wrote are kept.

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// What a console block names.
const (
	AgentKitBlockHost    = "host"    // a host name, or *.example.com
	AgentKitBlockCIDR    = "cidr"    // an address or range
	AgentKitBlockPath    = "path"    // a file or directory
	AgentKitBlockCommand = "command" // a command pattern
	AgentKitBlockMCP     = "mcp"     // an MCP server name
)

// AgentKitBlock is one resource to deny.
type AgentKitBlock struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	// Port narrows a host or cidr block to one port (0: every port).
	Port int `json:"port,omitempty"`
}

func (b AgentKitBlock) check() error {
	v := strings.TrimSpace(b.Value)
	if v == "" || len(v) > 500 || strings.ContainsAny(v, "\n\r\x00") {
		return fmt.Errorf("%w: value must be one line of at most 500 characters", ErrAgentKitPolicyInvalid)
	}
	if b.Port < 0 || b.Port > 65535 {
		return fmt.Errorf("%w: port must be 0-65535", ErrAgentKitPolicyInvalid)
	}
	switch b.Type {
	case AgentKitBlockHost:
		h := strings.TrimPrefix(v, "*.")
		if strings.ContainsAny(h, " /:*") || h == "" {
			return fmt.Errorf("%w: host must be a name such as api.example.com or *.example.com", ErrAgentKitPolicyInvalid)
		}
	case AgentKitBlockCIDR:
		if net.ParseIP(v) == nil {
			if _, _, err := net.ParseCIDR(v); err != nil {
				return fmt.Errorf("%w: cidr must be an address or a range such as 10.0.0.0/8", ErrAgentKitPolicyInvalid)
			}
		}
	case AgentKitBlockPath:
		if !strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "~") && !strings.HasPrefix(v, "{home}") && !strings.HasPrefix(v, "{project}") {
			return fmt.Errorf("%w: path must be absolute, or start with ~, {home} or {project}", ErrAgentKitPolicyInvalid)
		}
	case AgentKitBlockCommand, AgentKitBlockMCP:
	default:
		return fmt.Errorf("%w: type must be host, cidr, path, command or mcp", ErrAgentKitPolicyInvalid)
	}
	if b.Port != 0 && b.Type != AgentKitBlockHost && b.Type != AgentKitBlockCIDR {
		return fmt.Errorf("%w: port applies to host and cidr only", ErrAgentKitPolicyInvalid)
	}
	return nil
}

// newAgentKitPolicy is the policy an agent gets when it has none and the
// workspace has no default: everything allowed, so the one block added is
// the only thing it changes, enforced.
func newAgentKitPolicy(agentID string) string {
	return "apiVersion: authsec.ai/v1\nkind: AgentPolicy\nagent:\n  id: " + strconv.Quote(agentID) +
		"\nmode: enforce\nnetwork:\n  default: allow\ncommands:\n  default: allow\nmcp_servers:\n  default: allow\n"
}

func yamlMapGet(m *yaml.Node, key string, create bool) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	if !create {
		return nil
	}
	k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	v := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	m.Content = append(m.Content, k, v)
	return v
}

func yamlStr(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}

// addDeny appends the block to the document's deny list for its type, unless
// an equal rule is already there. It returns the new document and whether it
// changed.
func addDeny(doc string, b AgentKitBlock) (string, bool, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(doc), &root); err != nil {
		return "", false, fmt.Errorf("%w: not YAML: %v", ErrAgentKitPolicyInvalid, err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return "", false, fmt.Errorf("%w: document is not a mapping", ErrAgentKitPolicyInvalid)
	}
	top := root.Content[0]
	section, item := "", (*yaml.Node)(nil)
	v := strings.TrimSpace(b.Value)
	switch b.Type {
	case AgentKitBlockHost, AgentKitBlockCIDR:
		section = "network"
		item = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Style: yaml.FlowStyle}
		item.Content = append(item.Content, yamlStr(b.Type), yamlStr(v))
		if b.Port != 0 {
			item.Content = append(item.Content, yamlStr("port"),
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(b.Port)})
		}
	case AgentKitBlockPath:
		section, item = "filesystem", yamlStr(v)
	case AgentKitBlockCommand:
		section, item = "commands", yamlStr(v)
	case AgentKitBlockMCP:
		section, item = "mcp_servers", yamlStr(v)
	}
	sec := yamlMapGet(top, section, true)
	if sec.Kind != yaml.MappingNode {
		return "", false, fmt.Errorf("%w: %s is not a mapping", ErrAgentKitPolicyInvalid, section)
	}
	deny := yamlMapGet(sec, "deny", false)
	if deny == nil || (deny.Kind == yaml.ScalarNode && deny.Tag == "!!null") {
		if deny == nil {
			sec.Content = append(sec.Content, yamlStr("deny"), &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"})
			deny = sec.Content[len(sec.Content)-1]
		} else {
			*deny = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		}
	}
	if deny.Kind != yaml.SequenceNode {
		return "", false, fmt.Errorf("%w: %s.deny is not a list", ErrAgentKitPolicyInvalid, section)
	}
	for _, have := range deny.Content {
		if sameRule(have, item) {
			return doc, false, nil
		}
	}
	deny.Content = append(deny.Content, item)
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return "", false, err
	}
	_ = enc.Close()
	return out.String(), true, nil
}

func sameRule(a, b *yaml.Node) bool {
	if a.Kind != b.Kind {
		return false
	}
	if a.Kind == yaml.ScalarNode {
		return a.Value == b.Value
	}
	if a.Kind != yaml.MappingNode {
		return false
	}
	flat := func(n *yaml.Node) map[string]string {
		m := map[string]string{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			m[n.Content[i].Value] = n.Content[i+1].Value
		}
		return m
	}
	fa, fb := flat(a), flat(b)
	if fa["port"] == "0" {
		delete(fa, "port")
	}
	if len(fa) != len(fb) {
		return false
	}
	for k, v := range fb {
		if fa[k] != v {
			return false
		}
	}
	return true
}

// AgentKitBlockResult is what a block did.
type AgentKitBlockResult struct {
	Policy  *models.AgentKitPolicy `json:"policy"`
	Created bool                   `json:"created"`
	// From is where the new version started: "own" (the agent's policy),
	// "default" (the workspace's * policy, copied for this agent) or "new".
	From string `json:"from"`
	// Enforced is false when the policy is in monitor mode: the rule is
	// logged, not enforced, until the mode is enforce.
	Enforced bool `json:"enforced"`
}

// BlockResource denies one resource to one agent as a new policy version.
// An agent without a policy of its own gets a copy of the workspace's "*"
// policy (so the block does not drop that policy's other rules), or a new
// allow-everything policy in enforce mode.
func (s *AgentKit) BlockResource(ctx context.Context, ws uuid.UUID, agentID string, b AgentKitBlock, by *uuid.UUID) (*AgentKitBlockResult, error) {
	if !ValidAgentKitAgentID(agentID) {
		return nil, fmt.Errorf("%w: invalid agent id", ErrAgentKitPolicyInvalid)
	}
	if err := b.check(); err != nil {
		return nil, err
	}
	latest, err := s.LatestPolicies(ctx, ws)
	if err != nil {
		return nil, err
	}
	var own, def *models.AgentKitPolicy
	for i := range latest {
		switch latest[i].AgentID {
		case agentID:
			own = &latest[i]
		case "*":
			def = &latest[i]
		}
	}
	res := &AgentKitBlockResult{}
	base, doc := 0, ""
	switch {
	case own != nil:
		res.From, base, doc = "own", own.Version, own.Document
	case def != nil && agentID != "*":
		res.From, doc = "default", def.Document
		if doc, err = setAgentID(doc, agentID); err != nil {
			return nil, err
		}
	default:
		res.From, doc = "new", newAgentKitPolicy(agentID)
	}
	next, _, err := addDeny(doc, b)
	if err != nil {
		return nil, err
	}
	comment := fmt.Sprintf("console: block %s %s", b.Type, strings.TrimSpace(b.Value))
	if b.Port != 0 {
		comment += ":" + strconv.Itoa(b.Port)
	}
	row, created, err := s.PutPolicy(ctx, ws, agentID, next, clip(comment, agentKitMaxCommentLen), &base, by)
	if err != nil {
		return nil, err
	}
	res.Policy, res.Created = row, created
	var head agentKitPolicyHead
	_ = yaml.Unmarshal([]byte(row.Document), &head)
	res.Enforced = head.Mode == "enforce"
	return res, nil
}

// setAgentID points a copied document at another agent.
func setAgentID(doc, agentID string) (string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(doc), &root); err != nil || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return "", fmt.Errorf("%w: the default policy is not a YAML mapping", ErrAgentKitPolicyInvalid)
	}
	agent := yamlMapGet(root.Content[0], "agent", true)
	if agent.Kind != yaml.MappingNode {
		return "", fmt.Errorf("%w: agent is not a mapping", ErrAgentKitPolicyInvalid)
	}
	id := yamlMapGet(agent, "id", false)
	if id == nil {
		agent.Content = append(agent.Content, yamlStr("id"), yamlStr(agentID))
	} else {
		*id = *yamlStr(agentID)
	}
	if name := yamlMapGet(agent, "name", false); name != nil {
		*name = *yamlStr(agentID)
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return "", err
	}
	_ = enc.Close()
	return out.String(), nil
}
