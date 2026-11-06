package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
)

// The templates of agent runtime visibility on AWS: the event stream stack
// (SPEC-agent-runtime-visibility.md §5.6) and the tag-gated model access
// template (§5.4 as amended in §10). Static and embedded
// (internal/awsdiscovery/agent_runtime_embed.go); nothing secret is rendered
// into them. What is per connector -- the endpoint, the connector id -- is
// handed over as CloudFormation parameters, and the event secret only ever in
// the response that created it.

// CFNParameter is one stack parameter, in the shape `aws cloudformation
// create-stack --parameters file://...` reads.
type CFNParameter struct {
	ParameterKey   string `json:"ParameterKey"`
	ParameterValue string `json:"ParameterValue"`
}

// EventStreamSecretPlaceholder stands for the event secret in parameters
// returned anywhere but the create/rotate response.
const EventStreamSecretPlaceholder = "<the aev_ secret shown once when the stream was turned on or rotated>"

// EventStreamSecretInResponse stands for the event secret in the
// create/rotate response's parameters: the secret itself is in data.secret
// and in no other field (lab 2026-11-05: printing the parameters leaked it a
// second time).
const EventStreamSecretInResponse = "<the secret in data.secret; shown once>"

// EventStreamStackParameters are the AuthSec-filled parameters of the event
// stream stack for one connector. EventSecret is never the secret: it is
// placeholder, or EventStreamSecretPlaceholder when placeholder is "".
func EventStreamStackParameters(endpointURL, placeholder string, connectorID uuid.UUID) []CFNParameter {
	if placeholder == "" {
		placeholder = EventStreamSecretPlaceholder
	}
	return []CFNParameter{
		{ParameterKey: "EndpointUrl", ParameterValue: endpointURL},
		{ParameterKey: "EventSecret", ParameterValue: placeholder},
		{ParameterKey: "ConnectorId", ParameterValue: connectorID.String()},
		{ParameterKey: "CreateTrail", ParameterValue: "false"},
	}
}

// EventStreamNotes is what a person deploying the stream must know. Shown with
// the template and in the create/rotate response.
func EventStreamNotes() []string {
	return []string{
		"Deploy the stack in every region to watch (a StackSet works) and in us-east-1, where IAM, STS and other global-service events arrive.",
		"A CloudTrail trail must log management events (read and write) in each region: set CreateTrail=true in ONE region's stack (the trail is multi-region), or keep your own trail.",
		"Read-only calls such as Converse, InvokeModel and GetSecretValue reach EventBridge only because the rule's state is ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS.",
		"Data events (Bedrock agents runtime, bedrock-mantle, AgentCore, S3) are off by default and charged by CloudTrail per event; S3 object events can be the largest cost. On your own trail, add the selectors yourself.",
		"The bedrock-mantle event source and data resource type are UNVERIFIED: the stack takes both as parameters.",
		"EventBridge sends one event per request with the secret in the " + AgentEventSecretHeader + " header, waits 5 seconds for a reply and retries for up to 24 hours on 429 and 5xx.",
		"EventBridge also charges per API destination invocation; KMS and S3 management events can be numerous.",
		"Rotating the secret in AuthSec stops the stream until the stack's EventSecret parameter is updated; revoking it stops the stream.",
		"Polling during scans stays on as the backstop for management events.",
	}
}

// EventStreamTemplateDoc is GET .../event-stream/template.
type EventStreamTemplateDoc struct {
	TemplateVersion string         `json:"template_version"`
	FileName        string         `json:"file_name"`
	Template        string         `json:"template"`
	Parameters      []CFNParameter `json:"parameters"`
	Notes           []string       `json:"notes"`
}

// EventStreamTemplate returns the stack with the connector's parameters (the
// secret as a placeholder).
func EventStreamTemplate(connectorID uuid.UUID) EventStreamTemplateDoc {
	return EventStreamTemplateDoc{
		TemplateVersion: awsdiscovery.AgentRuntimeTemplateVersion,
		FileName:        awsdiscovery.AgentEventStreamTemplateFile,
		Template:        awsdiscovery.AgentEventStreamTemplate,
		Parameters:      EventStreamStackParameters(AgentEventIngestURL(), "", connectorID),
		Notes:           EventStreamNotes(),
	}
}

/* --------------------------- tag-gated model access ----------------------- */

// Model access template modes and forms.
const (
	ModelAccessModeAudit = "audit"
	ModelAccessModeDeny  = "deny"
	// ModelAccessFormSCP: a service control policy (AWS Organizations).
	ModelAccessFormSCP = "scp"
	// ModelAccessFormPolicy: an AuthSec-owned deny policy under /authsec/
	// attached to chosen roles. There is no permissions-boundary form (§10).
	ModelAccessFormPolicy = "policy"
)

// ErrModelAccessParam is an unknown mode or form.
var ErrModelAccessParam = errors.New("mode must be audit or deny, and form scp or policy")

// ModelAccessTemplateDoc is GET /authsec/discovery/aws/templates/model-access.
// Deny mode carries a CloudFormation template; audit mode carries no template
// and no deny, only the audit document.
type ModelAccessTemplateDoc struct {
	TemplateVersion string `json:"template_version"`
	Mode            string `json:"mode"`
	Form            string `json:"form"`
	// Denies says whether deploying this changes what principals may do.
	Denies     bool     `json:"denies"`
	FileName   string   `json:"file_name,omitempty"`
	Template   string   `json:"template,omitempty"`
	Parameters []string `json:"parameters,omitempty"`
	// Audit is the audit document (audit mode only).
	Audit json.RawMessage `json:"audit,omitempty"`
	Notes []string        `json:"notes"`
}

// ModelAccessTemplate returns the tag-gated model access template for a mode
// and form. "" means audit and scp: the safe first step.
func ModelAccessTemplate(mode, form string) (ModelAccessTemplateDoc, error) {
	mode, form = strings.ToLower(strings.TrimSpace(mode)), strings.ToLower(strings.TrimSpace(form))
	if mode == "" {
		mode = ModelAccessModeAudit
	}
	if form == "" {
		form = ModelAccessFormSCP
	}
	if (mode != ModelAccessModeAudit && mode != ModelAccessModeDeny) ||
		(form != ModelAccessFormSCP && form != ModelAccessFormPolicy) {
		return ModelAccessTemplateDoc{}, ErrModelAccessParam
	}
	doc := ModelAccessTemplateDoc{TemplateVersion: awsdiscovery.AgentRuntimeTemplateVersion, Mode: mode, Form: form}
	if mode == ModelAccessModeAudit {
		audit, err := modelAccessAudit(form)
		if err != nil {
			return ModelAccessTemplateDoc{}, err
		}
		doc.Audit = audit
		doc.Notes = []string{
			"Audit mode deploys nothing and refuses nothing.",
			fmt.Sprintf("When every agent is tagged, deploy mode=deny&form=%s.", form),
		}
		return doc, nil
	}
	doc.Denies = true
	switch form {
	case ModelAccessFormSCP:
		doc.FileName = awsdiscovery.ModelAccessSCPTemplateFile
		doc.Template = awsdiscovery.ModelAccessSCPTemplate
		doc.Parameters = []string{"TargetIds", "AdminPrincipalArns", "PolicyName"}
		doc.Notes = []string{
			"Deploy in the Organizations management account (or a delegated policy administrator). SCPs do not apply to the management account or to service-linked roles.",
			"Untagged principals in the targeted accounts are refused Bedrock model calls; the refusals appear in AuthSec as refused model calls.",
			"Only AdminPrincipalArns may set or remove the authsec:agent tag, including as a session tag; list your pipeline and CloudFormation roles that tag agent roles.",
			"The bedrock-mantle action prefix is UNVERIFIED.",
		}
	case ModelAccessFormPolicy:
		doc.FileName = awsdiscovery.ModelAccessPolicyTemplateFile
		doc.Template = awsdiscovery.ModelAccessPolicyTemplate
		doc.Parameters = []string{"RoleNames", "AdminPrincipalArns", "PolicySuffix"}
		doc.Notes = []string{
			"A deny policy under /authsec/ attached to the roles you name, never a permissions boundary. AuthSec's enforcement role (template v2) may attach and detach it.",
			"It covers only the roles it is attached to, and it cannot stop another principal from tagging a gated role: the SCP form is stronger.",
			"The bedrock-mantle action prefix is UNVERIFIED.",
		}
	}
	return doc, nil
}

// modelAccessAudit is the embedded audit document with the form filled in and
// the form's "affected" entry picked out.
func modelAccessAudit(form string) (json.RawMessage, error) {
	var m map[string]any
	if err := json.Unmarshal(awsdiscovery.ModelAccessAuditDocument, &m); err != nil {
		return nil, fmt.Errorf("model access audit document: %w", err)
	}
	m["form"] = form
	if aff, ok := m["affected"].(map[string]any); ok {
		m["affected"] = aff[form]
	}
	m["deny_template"] = "GET /authsec/discovery/aws/templates/model-access?mode=deny&form=" + form
	return json.Marshal(m)
}
