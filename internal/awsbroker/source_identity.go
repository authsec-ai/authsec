package awsbroker

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// SourceIdentity names the human AND the agent behind a brokered session
// (SecOps C7): "authsec-<human 24 hex>-a<agent 12 hex>".
//
// The format before SecOps W2 was "authsec-<human 24 hex>" (no agent): a
// session opened then still carries it, and is told apart from a newer one
// by the missing "-a" part. SourceIdentity persists across role chaining and
// cannot be changed by the session's holder, so a deny conditioned on it
// (agentcontain.SourceIdentityDocument) stops one agent on a shared role.
// The agent part is a hash: SourceIdentity is at most 64 characters of
// [\w+=,.@-], and an agent's client id or SPIFFE id is neither.
const SourceIdentityPrefix = "authsec-"

// AgentTagMaxLen is the longest authsec-agent session tag value (a session
// tag value is at most 256 characters).
const AgentTagMaxLen = 256

// AgentTag is the agent's authsec-agent session tag value: its reference
// (client id, else SPIFFE id) cut to AgentTagMaxLen.
func AgentTag(agentRef string) string {
	if len(agentRef) > AgentTagMaxLen {
		return agentRef[:AgentTagMaxLen]
	}
	return agentRef
}

// AgentSourcePart is the agent part of the SourceIdentity: "a" and the first
// 12 hex characters of sha256(AgentTag(agentRef)).
func AgentSourcePart(agentRef string) string {
	sum := sha256.Sum256([]byte(AgentTag(agentRef)))
	return "a" + hex.EncodeToString(sum[:])[:12]
}

// BrokerSourceIdentity is the SourceIdentity of a session the broker opens
// for humanUserID (any uuid form) and the agent.
func BrokerSourceIdentity(humanUserID, agentRef string) string {
	human := strings.ReplaceAll(humanUserID, "-", "")
	if len(human) > 24 {
		human = human[:24]
	}
	id := SourceIdentityPrefix + human
	if strings.TrimSpace(agentRef) != "" {
		id += "-" + AgentSourcePart(agentRef)
	}
	return id
}

// AgentSourcePattern is the aws:SourceIdentity StringLike pattern that
// matches every broker session of the agent, whoever the human is.
func AgentSourcePattern(agentRef string) string {
	return SourceIdentityPrefix + "*-" + AgentSourcePart(agentRef)
}
