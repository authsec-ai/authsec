package awsdiscovery_test

import (
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
)

// W8 (decision 2): the remediation stack's template, asserted structurally
// and simulated. Every statement is compared against an explicit table, so a
// widening, a dropped condition or a new statement fails here; then the
// requests a remediation makes -- and the ones it must never be able to
// make -- are simulated against the template's own policy.

func remediationTemplate(t *testing.T) map[string]any {
	t.Helper()
	tpl, err := enforcetest.ParseTemplate(awsdiscovery.RemediationCloudFormationTemplate)
	if err != nil {
		t.Fatalf("parse the remediation template: %v", err)
	}
	return tpl
}

type remStatement struct {
	Effect    string
	Action    []string
	Resource  []string
	Condition map[string]map[string]string
}

const (
	remRole = "sub:arn:${AWS::Partition}:iam::${AWS::AccountId}:role/*"
	remUser = "sub:arn:${AWS::Partition}:iam::${AWS::AccountId}:user/*"
	remSec  = "sub:arn:${AWS::Partition}:secretsmanager:*:${AWS::AccountId}:secret:*"
)

var remExpected = map[string]remStatement{
	"ManageRemediationPolicies": {Effect: "Allow", Action: []string{"iam:CreatePolicy", "iam:DeletePolicy", "iam:TagPolicy"},
		Resource: []string{"sub:arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/authsec/remediation/*"}},
	"AttachRemediationPolicies": {Effect: "Allow",
		Action:   []string{"iam:AttachRolePolicy", "iam:AttachUserPolicy", "iam:DetachRolePolicy", "iam:DetachUserPolicy"},
		Resource: []string{remRole, remUser},
		Condition: map[string]map[string]string{"ArnLike": {
			"iam:PolicyARN": "sub:arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/authsec/remediation/*"}}},
	"DetachCustomerPolicies": {Effect: "Allow", Action: []string{"iam:DetachRolePolicy", "iam:DetachUserPolicy"},
		Resource: []string{remRole, remUser},
		Condition: map[string]map[string]string{"ArnNotLike": {
			"iam:PolicyARN": "sub:arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/authsec/*"}}},
	"VersionCustomerManagedPolicies": {Effect: "Allow",
		Action:   []string{"iam:CreatePolicyVersion", "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion"},
		Resource: []string{"sub:arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/*"}},
	"RewriteInlinePolicies": {Effect: "Allow",
		Action:   []string{"iam:DeleteRolePolicy", "iam:DeleteUserPolicy", "iam:PutRolePolicy", "iam:PutUserPolicy"},
		Resource: []string{remRole, remUser}},
	"RotateUserAccessKeys": {Effect: "Allow",
		Action:   []string{"iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:ListAccessKeys", "iam:UpdateAccessKey"},
		Resource: []string{remUser}},
	"HandOverKeysThroughTaggedSecrets": {Effect: "Allow", Action: []string{"secretsmanager:PutSecretValue"},
		Resource:  []string{remSec},
		Condition: map[string]map[string]string{"StringEquals": {"aws:ResourceTag/authsec:key-handover": "true"}}},
	"StartSecretRotation": {Effect: "Allow", Action: []string{"secretsmanager:DescribeSecret", "secretsmanager:RotateSecret"},
		Resource: []string{remSec}},
	"TagRemediatedPrincipals": {Effect: "Allow", Action: []string{"iam:TagRole", "iam:TagUser"},
		Resource:  []string{remRole, remUser},
		Condition: map[string]map[string]string{"ForAllValues:StringLike": {"aws:TagKeys": "authsec:remediation*"}}},
	"NeverReadSecretValues": {Effect: "Deny", Action: []string{"secretsmanager:BatchGetSecretValue", "secretsmanager:GetSecretValue"},
		Resource: []string{"*"}},
	"DenyAuthSecPolicyVersions": {Effect: "Deny",
		Action:   []string{"iam:CreatePolicyVersion", "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion"},
		Resource: []string{"sub:arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/authsec/*"}},
	"ProtectServiceRoles": {Effect: "Deny",
		Action: []string{"iam:AttachRolePolicy", "iam:DeleteRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePolicy", "iam:TagRole"},
		Resource: []string{"sub:arn:${AWS::Partition}:iam::${AWS::AccountId}:role/aws-reserved/*",
			"sub:arn:${AWS::Partition}:iam::${AWS::AccountId}:role/aws-service-role/*"}},
	"ProtectAuthSecPrincipals": {Effect: "Deny",
		Action: []string{"iam:AttachRolePolicy", "iam:AttachUserPolicy", "iam:CreateAccessKey", "iam:DeleteAccessKey",
			"iam:DeleteRolePolicy", "iam:DeleteUserPolicy", "iam:DetachRolePolicy", "iam:DetachUserPolicy", "iam:PutRolePolicy",
			"iam:PutUserPolicy", "iam:TagRole", "iam:TagUser", "iam:UpdateAccessKey"},
		Resource:  []string{"*"},
		Condition: map[string]map[string]string{"StringEquals": {"aws:ResourceTag/ManagedBy": "AuthSec"}}},
	"ProtectTaggedResources": {Effect: "Deny",
		Action: []string{"iam:AttachRolePolicy", "iam:AttachUserPolicy", "iam:CreateAccessKey", "iam:CreatePolicyVersion",
			"iam:DeleteAccessKey", "iam:DeletePolicyVersion", "iam:DeleteRolePolicy", "iam:DeleteUserPolicy", "iam:DetachRolePolicy",
			"iam:DetachUserPolicy", "iam:PutRolePolicy", "iam:PutUserPolicy", "iam:SetDefaultPolicyVersion", "iam:TagRole",
			"iam:TagUser", "iam:UpdateAccessKey", "secretsmanager:PutSecretValue", "secretsmanager:RotateSecret"},
		Resource:  []string{"*"},
		Condition: map[string]map[string]string{"StringEquals": {"aws:ResourceTag/authsec:protected": "true"}}},
}

func TestRemediationTemplatePermissionsExact(t *testing.T) {
	tpl := remediationTemplate(t)
	pols, _ := enforcetest.Dig(tpl, "Resources", "AuthSecRemediationRole", "Properties", "Policies").([]any)
	if len(pols) != 1 {
		t.Fatalf("the remediation role has %d inline policies, want 1", len(pols))
	}
	if enforcetest.Dig(tpl, "Resources", "AuthSecRemediationRole", "Properties", "ManagedPolicyArns") != nil {
		t.Fatal("the remediation role must have no managed policies")
	}
	raw, _ := enforcetest.Dig(pols[0], "PolicyDocument", "Statement").([]any)
	seen := map[string]bool{}
	for _, r := range raw {
		m := r.(map[string]any)
		sid, _ := m["Sid"].(string)
		want, ok := remExpected[sid]
		if !ok {
			t.Errorf("unexpected statement %q", sid)
			continue
		}
		seen[sid] = true
		got := remStatement{Effect: sv(m["Effect"]), Action: svList(m["Action"]), Resource: svList(m["Resource"])}
		if c, ok := m["Condition"].(map[string]any); ok {
			got.Condition = map[string]map[string]string{}
			for op, kv := range c {
				got.Condition[op] = map[string]string{}
				for k, v := range kv.(map[string]any) {
					got.Condition[op][k] = sv(v)
				}
			}
		}
		sort.Strings(want.Action)
		sort.Strings(want.Resource)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("statement %s:\n got  %+v\n want %+v", sid, got, want)
		}
	}
	for sid := range remExpected {
		if !seen[sid] {
			t.Errorf("statement %s missing", sid)
		}
	}
}

func TestRemediationTemplateTrustAndVersion(t *testing.T) {
	tpl := remediationTemplate(t)
	if v := enforcetest.Dig(tpl, "Metadata", "AuthSec", "TemplateVersion"); v != awsdiscovery.RemediationTemplateVersion {
		t.Errorf("Metadata TemplateVersion = %v, want %s", v, awsdiscovery.RemediationTemplateVersion)
	}
	if v := enforcetest.Dig(tpl, "Outputs", "TemplateVersion", "Value"); v != awsdiscovery.RemediationTemplateVersion {
		t.Errorf("Outputs TemplateVersion = %v", v)
	}
	if v := enforcetest.Dig(tpl, "Metadata", "AuthSec", "Kind"); v != "remediation" {
		t.Errorf("Kind = %v", v)
	}
	trust, _ := enforcetest.Dig(tpl, "Resources", "AuthSecRemediationRole", "Properties", "AssumeRolePolicyDocument", "Statement").([]any)
	if len(trust) != 1 {
		t.Fatalf("trust has %d statements, want 1", len(trust))
	}
	if got := sv(enforcetest.Dig(trust[0], "Condition", "StringEquals", "sts:ExternalId")); got != "ref:ExternalId" {
		t.Errorf("trust ExternalId condition = %s", got)
	}
	if got := sv(enforcetest.Dig(trust[0], "Principal", "AWS")); got != "ref:AuthSecPrincipalArn" {
		t.Errorf("trust principal = %s", got)
	}
	if got := sv(enforcetest.Dig(tpl, "Resources", "AuthSecRemediationRole", "Properties", "RoleName")); got != "sub:AuthSecRemediation-${NameSuffix}" {
		t.Errorf("RoleName = %s", got)
	}
	if awsdiscovery.RemediationRoleName("abc") != "AuthSecRemediation-abc" {
		t.Error("RemediationRoleName")
	}
	// The role is tagged ManagedBy=AuthSec: the discovery and enforcement
	// stacks' protections keep it out of their reach, and its own keeps it
	// out of a remediation's.
	if tags := tagMap(enforcetest.Dig(tpl, "Resources", "AuthSecRemediationRole", "Properties", "Tags")); tags["ManagedBy"] != "AuthSec" {
		t.Errorf("tags = %v", tags)
	}
	// Separate from enforcement and discovery.
	if strings.Contains(awsdiscovery.RemediationCloudFormationTemplate, "AuthSecEnforcementRole") {
		t.Error("the remediation template names the enforcement role")
	}
}

func TestRemediationTemplateSimulated(t *testing.T) {
	const acct = "111122223333"
	p, err := enforcetest.RolePolicy(remediationTemplate(t), "AuthSecRemediationRole", acct)
	if err != nil {
		t.Fatal(err)
	}
	role := func(path string) string { return "arn:aws:iam::" + acct + ":role" + path }
	user := func(name string) string { return "arn:aws:iam::" + acct + ":user/" + name }
	pol := func(path string) string { return "arn:aws:iam::" + acct + ":policy" + path }
	sec := "arn:aws:secretsmanager:us-east-1:" + acct + ":secret:agent-key-AbCdEf"
	cases := []struct {
		name    string
		req     enforcetest.Request
		allowed bool
		by      string
	}{
		{"detach a customer policy from a role", enforcetest.Request{Action: "iam:DetachRolePolicy", Resource: role("/agent-role"),
			Context: map[string]string{"iam:PolicyARN": pol("/S3FullAccessCustom")}}, true, "DetachCustomerPolicies"},
		{"detach an AWS managed policy", enforcetest.Request{Action: "iam:DetachRolePolicy", Resource: role("/agent-role"),
			Context: map[string]string{"iam:PolicyARN": "arn:aws:iam::aws:policy/AdministratorAccess"}}, true, "DetachCustomerPolicies"},
		{"detach an AuthSec containment policy", enforcetest.Request{Action: "iam:DetachRolePolicy", Resource: role("/agent-role"),
			Context: map[string]string{"iam:PolicyARN": pol("/authsec/AuthSecContain-AROA1-abcd1234")}}, false, ""},
		{"detach an AuthSec remediation deny (undo a retire)", enforcetest.Request{Action: "iam:DetachRolePolicy", Resource: role("/agent-role"),
			Context: map[string]string{"iam:PolicyARN": pol("/authsec/remediation/AuthSecRetire-AROA1-abcd1234")}}, true, "AttachRemediationPolicies"},
		{"attach an AuthSec remediation deny", enforcetest.Request{Action: "iam:AttachRolePolicy", Resource: role("/agent-role"),
			Context: map[string]string{"iam:PolicyARN": pol("/authsec/remediation/AuthSecRetire-AROA1-abcd1234")}}, true, "AttachRemediationPolicies"},
		{"attach any other policy", enforcetest.Request{Action: "iam:AttachRolePolicy", Resource: role("/agent-role"),
			Context: map[string]string{"iam:PolicyARN": "arn:aws:iam::aws:policy/AdministratorAccess"}}, false, ""},
		{"attach a deny to a user", enforcetest.Request{Action: "iam:AttachUserPolicy", Resource: user("bot"),
			Context: map[string]string{"iam:PolicyARN": pol("/authsec/remediation/AuthSecRetire-AIDA1-abcd1234")}}, true, "AttachRemediationPolicies"},
		{"create a remediation policy", enforcetest.Request{Action: "iam:CreatePolicy", Resource: pol("/authsec/remediation/AuthSecRetire-x")}, true, "ManageRemediationPolicies"},
		{"create a policy elsewhere", enforcetest.Request{Action: "iam:CreatePolicy", Resource: pol("/Admin")}, false, ""},
		{"version a customer policy", enforcetest.Request{Action: "iam:CreatePolicyVersion", Resource: pol("/S3FullAccessCustom")}, true, "VersionCustomerManagedPolicies"},
		{"version an AuthSec policy", enforcetest.Request{Action: "iam:CreatePolicyVersion", Resource: pol("/authsec/AuthSecAccess-AROA1-p-v1")}, false, "DenyAuthSecPolicyVersions"},
		{"version a protected policy", enforcetest.Request{Action: "iam:CreatePolicyVersion", Resource: pol("/Crown"),
			Context: map[string]string{"aws:ResourceTag/authsec:protected": "true"}}, false, "ProtectTaggedResources"},
		{"rewrite an inline policy", enforcetest.Request{Action: "iam:PutRolePolicy", Resource: role("/agent-role")}, true, "RewriteInlinePolicies"},
		{"rewrite a service-linked role", enforcetest.Request{Action: "iam:PutRolePolicy", Resource: role("/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS")}, false, "ProtectServiceRoles"},
		{"rewrite an AuthSec role", enforcetest.Request{Action: "iam:DeleteRolePolicy", Resource: role("/AuthSecEnforcement-x"),
			Context: map[string]string{"aws:ResourceTag/ManagedBy": "AuthSec"}}, false, "ProtectAuthSecPrincipals"},
		{"rewrite a protected role", enforcetest.Request{Action: "iam:PutRolePolicy", Resource: role("/payments"),
			Context: map[string]string{"aws:ResourceTag/authsec:protected": "true"}}, false, "ProtectTaggedResources"},
		{"create a user key", enforcetest.Request{Action: "iam:CreateAccessKey", Resource: user("bot")}, true, "RotateUserAccessKeys"},
		{"deactivate a user key", enforcetest.Request{Action: "iam:UpdateAccessKey", Resource: user("bot")}, true, "RotateUserAccessKeys"},
		{"create a key for a protected user", enforcetest.Request{Action: "iam:CreateAccessKey", Resource: user("breakglass"),
			Context: map[string]string{"aws:ResourceTag/authsec:protected": "true"}}, false, "ProtectTaggedResources"},
		{"hand a key over into a tagged secret", enforcetest.Request{Action: "secretsmanager:PutSecretValue", Resource: sec,
			Context: map[string]string{"aws:ResourceTag/authsec:key-handover": "true"}}, true, "HandOverKeysThroughTaggedSecrets"},
		{"write any other secret", enforcetest.Request{Action: "secretsmanager:PutSecretValue", Resource: sec}, false, ""},
		{"read a secret value", enforcetest.Request{Action: "secretsmanager:GetSecretValue", Resource: sec}, false, "NeverReadSecretValues"},
		{"read secret values in bulk", enforcetest.Request{Action: "secretsmanager:BatchGetSecretValue", Resource: "*"}, false, "NeverReadSecretValues"},
		{"start a rotation", enforcetest.Request{Action: "secretsmanager:RotateSecret", Resource: sec}, true, "StartSecretRotation"},
		{"rotate a protected secret", enforcetest.Request{Action: "secretsmanager:RotateSecret", Resource: sec,
			Context: map[string]string{"aws:ResourceTag/authsec:protected": "true"}}, false, "ProtectTaggedResources"},
		{"tag a role with the remediation id", enforcetest.Request{Action: "iam:TagRole", Resource: role("/agent-role"),
			Context: map[string]string{"aws:TagKeys": "authsec:remediation"}}, true, "TagRemediatedPrincipals"},
		{"tag a role with another key", enforcetest.Request{Action: "iam:TagRole", Resource: role("/agent-role"),
			Context: map[string]string{"aws:TagKeys": "authsec:remediation,owner"}}, false, ""},
		{"change a trust policy", enforcetest.Request{Action: "iam:UpdateAssumeRolePolicy", Resource: role("/agent-role")}, false, ""},
		{"delete a role", enforcetest.Request{Action: "iam:DeleteRole", Resource: role("/agent-role")}, false, ""},
		{"read a role", enforcetest.Request{Action: "iam:GetRole", Resource: role("/agent-role")}, false, ""},
		{"assume another role", enforcetest.Request{Action: "sts:AssumeRole", Resource: role("/Admin")}, false, ""},
	}
	for _, c := range cases {
		d := p.Evaluate(c.req)
		if d.Allowed != c.allowed || d.By != c.by {
			t.Errorf("%s: allowed=%v by %q, want allowed=%v by %q", c.name, d.Allowed, d.By, c.allowed, c.by)
		}
	}
	// No statement allows reading anything but secret metadata and the
	// user's key list.
	for _, a := range p.AllowedActions() {
		if strings.Contains(a, "Get") || strings.Contains(a, "*") {
			t.Errorf("allowed action %s reads or is a wildcard", a)
		}
	}
}

func TestRemediationQuickCreateURL(t *testing.T) {
	const tplURL = "https://bucket.s3.us-east-1.amazonaws.com/aws/remediation/v/authsec-aws-remediation-role.yaml"
	link, err := awsdiscovery.RemediationQuickCreateURL("us-east-1", tplURL, awsdiscovery.RemediationStackName("abc123"),
		map[string]string{"AuthSecPrincipalArn": "arn:aws:iam::111111111111:role/AuthSec", "ExternalId": strings.Repeat("r", 40),
			"NameSuffix": "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := url.Parse(link); err != nil || !strings.Contains(link, "param_NameSuffix=abc123") ||
		!strings.Contains(link, "stackName=AuthSec-Remediation-abc123") {
		t.Fatalf("link %s: %v", link, err)
	}
	if _, err := awsdiscovery.RemediationQuickCreateURL("us-east-1", tplURL, "AuthSec-Remediation-x",
		map[string]string{"CallbackTopicArn": "x"}); err == nil {
		t.Error("an undeclared parameter was accepted")
	}
	if (awsdiscovery.CallbackConfig{TemplateBaseURL: "https://t.example"}).RemediationTemplateURL() !=
		"https://t.example/aws/remediation/"+awsdiscovery.RemediationTemplateVersion+"/authsec-aws-remediation-role.yaml" {
		t.Error("RemediationTemplateURL")
	}
}
