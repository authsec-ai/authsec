package awsdiscovery

import (
	_ "embed"
)

// Agent runtime visibility templates (SPEC-agent-runtime-visibility.md §5.4
// as amended in §10, and §5.6). Static and embedded: what the customer
// deploys is exactly what this build ships, and nothing is rendered into
// them. The services package serves them (services/agent_runtime_templates.go).

// AgentRuntimeTemplateVersion is the version of every template below. Must
// match each YAML's Metadata.AuthSec.TemplateVersion and TemplateVersion
// output, and the audit document's template_version; the template test
// checks all of them.
const AgentRuntimeTemplateVersion = "2026-11-05"

// AgentEventStreamTemplate is the CloudFormation stack that streams the
// CloudTrail events of one account and region to the AuthSec ingest endpoint
// (§5.6): an optional trail, the EventBridge rule, connection (API key) and
// API destination, and the invoke role.
//
//go:embed authsec-agent-event-stream.yaml
var AgentEventStreamTemplate string

// ModelAccessSCPTemplate is the tag-gated model access template, deny mode,
// as a service control policy (AWS Organizations).
//
//go:embed authsec-model-access-scp.yaml
var ModelAccessSCPTemplate string

// ModelAccessRCPTemplate is the tag guard of the tag-gated template, deny
// mode, as a resource control policy (AWS Organizations): it refuses the
// authsec:agent session tag on role assumption by any caller, which the SCP
// (in-organization callers only) and the policy form cannot. Deployed with
// the SCP form; it gates no model call itself.
//
//go:embed authsec-model-access-rcp.yaml
var ModelAccessRCPTemplate string

// ModelAccessPolicyTemplate is the tag-gated model access template, deny
// mode, without Organizations: an AuthSec-owned deny policy under
// /authsec-gate/ (outside the enforcement role's /authsec/ reach) attached
// to chosen roles (never a permissions boundary, §10).
//
//go:embed authsec-model-access-policy.yaml
var ModelAccessPolicyTemplate string

// ModelAccessAuditDocument is the audit mode of the tag-gated template: no
// deny, a description of what deny mode would refuse, and a tagging guide.
//
//go:embed authsec-model-access-audit.json
var ModelAccessAuditDocument []byte

// Published file names of the templates.
const (
	AgentEventStreamTemplateFile  = "authsec-agent-event-stream.yaml"
	ModelAccessSCPTemplateFile    = "authsec-model-access-scp.yaml"
	ModelAccessRCPTemplateFile    = "authsec-model-access-rcp.yaml"
	ModelAccessPolicyTemplateFile = "authsec-model-access-policy.yaml"
)
