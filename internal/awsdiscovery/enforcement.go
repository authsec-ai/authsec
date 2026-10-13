package awsdiscovery

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// The enforcement stack (SPEC-iga-phase3-policy.md §3.6, T3.09): a SEPARATE,
// customer-consented CloudFormation stack, distinct from the read-only
// discovery stack, whose role can only create, version, attach and remove
// AuthSec-owned permissions boundaries under /authsec/. It has its own
// template, its own TemplateVersion, its own ExternalId and its own custom
// resource type, Custom::AuthSecEnforcementRegistration, which reaches AuthSec
// through the SAME callback topics and queue as the discovery Quick Create
// (cfn_callback.go) and is told apart by its resource type.
//
// This file is the adapter half, like the discovery template's: the template,
// its names and the shape of its callback. What AuthSec does with a callback
// (the binding) is services/cloud_enforcement_binding_service.go.

// EnforcementCloudFormationTemplate is the enforcement stack's template.
//
//go:embed authsec-aws-enforcement-role.yaml
var EnforcementCloudFormationTemplate string

// EnforcementTemplateVersion identifies the enforcement permission set (§3.6
// "template v1"). Must match the template's Metadata.AuthSec.TemplateVersion,
// the TemplateVersion output and the registration resource's property; the
// template test checks all three. Independent of TemplateVersion (discovery).
const EnforcementTemplateVersion = "2026-10-07"

// EnforcementCloudFormationTemplateV2 is the enforcement stack's template v2
// (SPEC-iga-phase3-policy.md §12.3, release R2): template v1 plus temporary
// grants and session revocation (attach/detach of AuthSec policies,
// DECISION R2-14) and, behind the EnableLambdaSplit parameter, direct Lambda
// execution-role splits (DECISION R2-15). Issued for new bindings only while
// IGA_POLICY_R2 is on; v1 stays the template of every existing binding.
//
//go:embed authsec-aws-enforcement-role-v2.yaml
var EnforcementCloudFormationTemplateV2 string

// EnforcementTemplateVersionV2 identifies enforcement template v2. Must match
// the v2 template's Metadata.AuthSec.TemplateVersion, its TemplateVersion
// output and its registration resource's property.
const EnforcementTemplateVersionV2 = "2026-10-13"

// enforcementTemplateFileV1 and enforcementTemplateFileV2 are the published
// object names of the two templates.
const (
	enforcementTemplateFileV1 = "authsec-aws-enforcement-role.yaml"
	enforcementTemplateFileV2 = "authsec-aws-enforcement-role-v2.yaml"
)

// IsEnforcementTemplateV2 reports whether a binding's template_version is
// template v2 (the R2 permission set).
func IsEnforcementTemplateV2(v string) bool { return v == EnforcementTemplateVersionV2 }

// KnownEnforcementTemplateVersion reports whether a callback's TemplateVersion
// is one this build issued (v1 or v2). A stack from an unknown version is
// refused at the callback rather than recorded, because the binding's
// template_version is what an operator reads to know which permission set a
// stack holds.
func KnownEnforcementTemplateVersion(v string) bool {
	return v == EnforcementTemplateVersion || v == EnforcementTemplateVersionV2
}

// The enforcement callback resource, as the template declares it.
const (
	EnforcementRegistrationLogicalID    = "AuthSecEnforcementRegistration"
	EnforcementRegistrationResourceType = "Custom::AuthSecEnforcementRegistration"
)

// Names the enforcement template derives from its NameSuffix parameter (§3.6).
func EnforcementStackName(suffix string) string { return "AuthSec-Enforcement-" + suffix }
func EnforcementRoleName(suffix string) string  { return "AuthSecEnforcement-" + suffix }
func EnforcementSelfTestRoleName(suffix string) string {
	return "AuthSecEnforcementSelfTest-" + suffix
}

// enforcementSuffixPattern is the template's NameSuffix AllowedPattern.
var enforcementSuffixPattern = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// ValidEnforcementSuffix reports whether s is a NameSuffix the template accepts.
func ValidEnforcementSuffix(s string) bool { return enforcementSuffixPattern.MatchString(s) }

// RoleNameFromARN returns the role name (the last path segment) and the path
// of an IAM role ARN.
func RoleNameFromARN(arn string) (name, path string, err error) {
	m := roleARNPattern.FindStringSubmatch(strings.TrimSpace(arn))
	if m == nil {
		return "", "", fmt.Errorf("%q is not an IAM role ARN", arn)
	}
	rest := m[3]
	i := strings.LastIndex(rest, "/")
	if i < 0 {
		return rest, "/", nil
	}
	return rest[i+1:], "/" + rest[:i+1], nil
}

// EnforcementRegistrationProperties are the ResourceProperties the
// enforcement template sends. ServiceToken and ServiceTimeout arrive too and
// are ignored.
type EnforcementRegistrationProperties struct {
	RoleArn         string `json:"RoleArn"`
	SelfTestRoleArn string `json:"SelfTestRoleArn"`
	ExternalID      string `json:"ExternalId"`
	AccountID       string `json:"AccountId"`
	TemplateVersion string `json:"TemplateVersion"`
}

// EnforcementCFNRequest is a custom-resource request for the enforcement
// registration resource. The envelope fields are CFNRequest's.
type EnforcementCFNRequest struct {
	CFNRequest
	Properties EnforcementRegistrationProperties
}

// CFNResourceKind peeks at a custom-resource request's resource type and
// logical id without validating anything else, so the callback consumer can
// route a message to the discovery or the enforcement handler. Unparseable
// input returns empty strings; the handler that receives it rejects it.
func CFNResourceKind(message string) (resourceType, logicalID string) {
	var peek struct {
		ResourceType      string `json:"ResourceType"`
		LogicalResourceID string `json:"LogicalResourceId"`
	}
	if json.Unmarshal([]byte(message), &peek) != nil {
		return "", ""
	}
	return peek.ResourceType, peek.LogicalResourceID
}

// IsEnforcementRegistration reports whether a request names the enforcement
// registration resource (both the type and the logical id must match).
func IsEnforcementRegistration(message string) bool {
	rt, lid := CFNResourceKind(message)
	return rt == EnforcementRegistrationResourceType && lid == EnforcementRegistrationLogicalID
}

// ParseEnforcementCFNRequest decodes and shape-checks a request for the
// enforcement registration resource. Like ParseCFNRequest, nothing it returns
// is trusted beyond its shape: the topic accepts publishes from any account.
func ParseEnforcementCFNRequest(message string) (*EnforcementCFNRequest, error) {
	var raw struct {
		RequestType        string                            `json:"RequestType"`
		RequestID          string                            `json:"RequestId"`
		StackID            string                            `json:"StackId"`
		ResponseURL        string                            `json:"ResponseURL"`
		ResourceType       string                            `json:"ResourceType"`
		LogicalResourceID  string                            `json:"LogicalResourceId"`
		PhysicalResourceID string                            `json:"PhysicalResourceId"`
		ResourceProperties EnforcementRegistrationProperties `json:"ResourceProperties"`
	}
	if err := json.Unmarshal([]byte(message), &raw); err != nil {
		return nil, fmt.Errorf("%w: request: %v", ErrMalformedCallback, err)
	}
	switch raw.RequestType {
	case CFNRequestCreate, CFNRequestUpdate, CFNRequestDelete:
	default:
		return nil, fmt.Errorf("%w: unknown RequestType %q", ErrMalformedCallback, raw.RequestType)
	}
	if raw.LogicalResourceID != EnforcementRegistrationLogicalID || raw.ResourceType != EnforcementRegistrationResourceType {
		return nil, fmt.Errorf("%w: not the %s resource", ErrMalformedCallback, EnforcementRegistrationLogicalID)
	}
	if raw.RequestID == "" || raw.StackID == "" || raw.ResponseURL == "" {
		return nil, fmt.Errorf("%w: missing RequestId, StackId or ResponseURL", ErrMalformedCallback)
	}
	return &EnforcementCFNRequest{
		CFNRequest: CFNRequest{
			RequestType: raw.RequestType, RequestID: raw.RequestID, StackID: raw.StackID,
			ResponseURL: raw.ResponseURL, ResourceType: raw.ResourceType,
			LogicalResourceID: raw.LogicalResourceID, PhysicalResourceID: raw.PhysicalResourceID,
		},
		Properties: raw.ResourceProperties,
	}, nil
}

// EnforcementTemplateURLFor returns the published enforcement template URL.
//
// DECISION (T3.09): only the base URL is used. TemplateURLOverrides name the
// discovery template's object per region and say nothing about where the
// enforcement template lives; a deployment that serves templates only through
// overrides has no enforcement Quick Create (the manual path still works).
func (c CallbackConfig) EnforcementTemplateURLFor() string {
	if c.TemplateBaseURL == "" {
		return ""
	}
	return c.TemplateBaseURL + "/aws/enforcement/" + EnforcementTemplateVersion + "/" + enforcementTemplateFileV1
}

// EnforcementTemplateURLForVersion is EnforcementTemplateURLFor for a given
// template version: .../aws/enforcement/<version>/<file>, the v1 file name
// for v1 (exactly EnforcementTemplateURLFor) and
// authsec-aws-enforcement-role-v2.yaml for v2. An unknown version, or no base
// URL, is "".
func (c CallbackConfig) EnforcementTemplateURLForVersion(v string) string {
	switch {
	case c.TemplateBaseURL == "":
		return ""
	case v == EnforcementTemplateVersion:
		return c.EnforcementTemplateURLFor()
	case v == EnforcementTemplateVersionV2:
		return c.TemplateBaseURL + "/aws/enforcement/" + EnforcementTemplateVersionV2 + "/" + enforcementTemplateFileV2
	default:
		return ""
	}
}

var (
	enforcementParamsOnce     sync.Once
	enforcementDeclaredParams map[string]struct{}
	enforcementNoEchoParams   map[string]struct{}
)

// EnforcementQuickCreateURL builds a Quick Create link for the enforcement
// template, with the same checks QuickCreateURL applies to the discovery one
// (commercial partition, https template, valid stack name, every parameter
// declared by the embedded enforcement template and none NoEcho).
func EnforcementQuickCreateURL(region, templateURL, stackName string, params map[string]string) (string, error) {
	enforcementParamsOnce.Do(func() {
		enforcementDeclaredParams, enforcementNoEchoParams = scanTemplateParameters(EnforcementCloudFormationTemplate)
	})
	return buildQuickCreateURL(region, templateURL, stackName, params, enforcementDeclaredParams, enforcementNoEchoParams)
}

var (
	enforcementV2ParamsOnce     sync.Once
	enforcementV2DeclaredParams map[string]struct{}
	enforcementV2NoEchoParams   map[string]struct{}
)

// EnforcementQuickCreateURLForVersion is EnforcementQuickCreateURL for a
// given template version: the parameters are checked against THAT version's
// embedded template (v2 declares EnableLambdaSplit, v1 does not). v1 is
// exactly EnforcementQuickCreateURL; an unknown version is an error.
func EnforcementQuickCreateURLForVersion(version, region, templateURL, stackName string, params map[string]string) (string, error) {
	switch version {
	case EnforcementTemplateVersion:
		return EnforcementQuickCreateURL(region, templateURL, stackName, params)
	case EnforcementTemplateVersionV2:
		enforcementV2ParamsOnce.Do(func() {
			enforcementV2DeclaredParams, enforcementV2NoEchoParams = scanTemplateParameters(EnforcementCloudFormationTemplateV2)
		})
		return buildQuickCreateURL(region, templateURL, stackName, params, enforcementV2DeclaredParams, enforcementV2NoEchoParams)
	default:
		return "", fmt.Errorf("unknown enforcement template version %q", version)
	}
}
