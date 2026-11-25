package awsdiscovery

import (
	_ "embed"
	"sync"
)

// The remediation stack (SPEC-secops-backend-upgrade.md W8, decision 2): a
// SEPARATE, customer-consented CloudFormation stack, distinct from the
// read-only discovery stack and from the enforcement stack, whose role can
// carry out the remediations a person approved in AuthSec -- remove a grant,
// rotate an IAM user's key through a tagged handover secret, start a
// configured Secrets Manager rotation, block a retired agent's identity --
// and never read a secret value. It has its own template, TemplateVersion,
// ExternalId and binding (cloud_remediation_binding). A workspace has none
// until the customer deploys it; until then every remediation is a prepared
// change or a pull request (services/agent_remediation*.go).
//
// This file is the adapter half: the template and its names. The binding
// is services/agent_remediation_binding.go.

// RemediationCloudFormationTemplate is the remediation stack's template.
//
//go:embed authsec-aws-remediation-role.yaml
var RemediationCloudFormationTemplate string

// RemediationTemplateVersion identifies the remediation permission set. It
// must match the template's Metadata.AuthSec.TemplateVersion and its
// TemplateVersion output (the template test checks both).
const RemediationTemplateVersion = "2026-11-25"

// remediationTemplateFile is the published object name of the template.
const remediationTemplateFile = "authsec-aws-remediation-role.yaml"

// Names the remediation template derives from its NameSuffix parameter.
func RemediationStackName(suffix string) string { return "AuthSec-Remediation-" + suffix }
func RemediationRoleName(suffix string) string  { return "AuthSecRemediation-" + suffix }

// RemediationPolicyPath is the IAM path of every policy the remediation role
// creates (an AuthSec deny for a retired agent's identity).
const RemediationPolicyPath = "/authsec/remediation/"

// RemediationKeyHandoverTag is the tag a customer puts on a Secrets Manager
// secret to let AuthSec write a rotated access key into it (and no other).
const RemediationKeyHandoverTag = "authsec:key-handover"

// RemediationTemplateURL returns the published remediation template URL, or
// "" without a base URL.
func (c CallbackConfig) RemediationTemplateURL() string {
	if c.TemplateBaseURL == "" {
		return ""
	}
	return c.TemplateBaseURL + "/aws/remediation/" + RemediationTemplateVersion + "/" + remediationTemplateFile
}

var (
	remediationParamsOnce     sync.Once
	remediationDeclaredParams map[string]struct{}
	remediationNoEchoParams   map[string]struct{}
)

// RemediationQuickCreateURL builds a Quick Create link for the remediation
// template, with the same checks as the discovery and enforcement links
// (commercial partition, https template, valid stack name, every parameter
// declared by the embedded template and none NoEcho).
func RemediationQuickCreateURL(region, templateURL, stackName string, params map[string]string) (string, error) {
	remediationParamsOnce.Do(func() {
		remediationDeclaredParams, remediationNoEchoParams = scanTemplateParameters(RemediationCloudFormationTemplate)
	})
	return buildQuickCreateURL(region, templateURL, stackName, params, remediationDeclaredParams, remediationNoEchoParams)
}
