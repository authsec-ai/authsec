package awsdiscovery_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
)

// T3.09 (SPEC-iga-phase3-policy.md §3.1, §3.6, A11, A22): the enforcement
// stack's template, asserted structurally. Every statement of the enforcement
// role's policy is compared against an explicit expected table -- actions,
// resources and conditions -- so any widening, any dropped condition and any
// new statement fails here, and then the restrictions §3.6 relies on are
// asserted one by one with their own names, and simulated against the
// requests A11 forces.
//
// Safeguards (mutation-checked): the ArnLike iam:PermissionsBoundary condition
// on PutRolePermissionsBoundary and on DeleteRolePermissionsBoundary; the
// /authsec/ policy path; the path and tag denies; the self-test role not
// tagged ManagedBy.

const subPrefix = "sub:"

// sv is a template value as a comparable string: a plain string as itself, a
// !Sub as "sub:<pattern>", a !Ref as "ref:<name>".
func sv(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		if s, ok := t["Fn::Sub"].(string); ok {
			return subPrefix + s
		}
		if s, ok := t["Ref"].(string); ok {
			return "ref:" + s
		}
		if a, ok := t["Fn::GetAtt"].([]any); ok && len(a) == 2 {
			return fmt.Sprintf("getatt:%v.%v", a[0], a[1])
		}
	case bool:
		return fmt.Sprint(t)
	case int:
		return fmt.Sprint(t)
	}
	b, _ := json.Marshal(v)
	return "?" + string(b)
}

func svList(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			out = append(out, sv(x))
		}
		sort.Strings(out)
		return out
	default:
		return []string{sv(v)}
	}
}

type expStatement struct {
	Effect    string
	Action    []string
	Resource  []string
	Condition map[string]map[string]string // op -> key -> value (single value each)
}

const (
	authsecPolicies = subPrefix + "arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/authsec/*"
	anyRole         = subPrefix + "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/*"
)

// expectedEnforcementPolicy is §3.6's "Enforcement role policy (template v1),
// complete", statement by statement.
var expectedEnforcementPolicy = map[string]expStatement{
	"ManageAuthSecPolicies": {
		Effect: "Allow",
		Action: []string{"iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicy",
			"iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:TagPolicy"},
		Resource: []string{authsecPolicies},
	},
	"AttachOnlyAuthSecBoundaries": {
		Effect: "Allow", Action: []string{"iam:PutRolePermissionsBoundary"}, Resource: []string{anyRole},
		Condition: map[string]map[string]string{"ArnLike": {"iam:PermissionsBoundary": authsecPolicies}},
	},
	"DetachOnlyAuthSecBoundaries": {
		Effect: "Allow", Action: []string{"iam:DeleteRolePermissionsBoundary"}, Resource: []string{anyRole},
		Condition: map[string]map[string]string{"ArnLike": {"iam:PermissionsBoundary": authsecPolicies}},
	},
	"ProtectServiceRoles": {
		Effect: "Deny", Action: []string{"iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary"},
		Resource: []string{
			subPrefix + "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/aws-reserved/*",
			subPrefix + "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/aws-service-role/*",
		},
	},
	"ProtectAuthSecRoles": {
		Effect: "Deny", Action: []string{"iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary"},
		Resource:  []string{"*"},
		Condition: map[string]map[string]string{"StringEquals": {"aws:ResourceTag/ManagedBy": "AuthSec"}},
	},
	"ProtectTaggedRoles": {
		Effect: "Deny", Action: []string{"iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary"},
		Resource:  []string{"*"},
		Condition: map[string]map[string]string{"StringEquals": {"aws:ResourceTag/authsec:protected": "true"}},
	},
}

func enforcementTemplate(t *testing.T) map[string]any {
	t.Helper()
	tpl, err := enforcetest.ParseTemplate(awsdiscovery.EnforcementCloudFormationTemplate)
	if err != nil {
		t.Fatalf("parse the enforcement template: %v", err)
	}
	return tpl
}

func enforcementStatements(t *testing.T, tpl map[string]any) []map[string]any {
	t.Helper()
	pols, _ := enforcetest.Dig(tpl, "Resources", "AuthSecEnforcementRole", "Properties", "Policies").([]any)
	if len(pols) != 1 {
		t.Fatalf("the enforcement role has %d inline policies, want exactly 1", len(pols))
	}
	if v := enforcetest.Dig(pols[0], "PolicyDocument", "Version"); v != "2012-10-17" {
		t.Fatalf("policy Version = %v", v)
	}
	raw, _ := enforcetest.Dig(pols[0], "PolicyDocument", "Statement").([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("statement %v is not a mapping", r)
		}
		out = append(out, m)
	}
	return out
}

// The template has exactly the resources and parameters §3.6 names.
func TestP3EnfTemplateShape(t *testing.T) {
	tpl := enforcementTemplate(t)
	if v := tpl["AWSTemplateFormatVersion"]; v != "2010-09-09" {
		t.Fatalf("AWSTemplateFormatVersion = %v", v)
	}
	res, _ := tpl["Resources"].(map[string]any)
	got := map[string]string{}
	for name, r := range res {
		got[name] = sv(enforcetest.Dig(r, "Type"))
	}
	want := map[string]string{
		"AuthSecEnforcementRole":         "AWS::IAM::Role",
		"AuthSecEnforcementSelfTestRole": "AWS::IAM::Role",
		"AuthSecEnforcementRegistration": awsdiscovery.EnforcementRegistrationResourceType,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resources = %v, want exactly %v", got, want)
	}
	params, _ := tpl["Parameters"].(map[string]any)
	var names []string
	for n, p := range params {
		names = append(names, n)
		if ne := enforcetest.Dig(p, "NoEcho"); ne != nil {
			t.Errorf("parameter %s is NoEcho (%v): Quick Create would ignore it", n, ne)
		}
	}
	sort.Strings(names)
	if want := []string{"AuthSecPrincipalArn", "CallbackTopicArn", "ExternalId", "NameSuffix"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("parameters = %v, want %v", names, want)
	}
	if p := sv(enforcetest.Dig(params, "NameSuffix", "AllowedPattern")); p != "^[a-z0-9]{1,16}$" {
		t.Fatalf("NameSuffix AllowedPattern = %q", p)
	}
	for _, s := range []string{"a", "x7k2m9qp", "0123456789abcdef"} {
		if !awsdiscovery.ValidEnforcementSuffix(s) {
			t.Errorf("suffix %q refused", s)
		}
	}
	for _, s := range []string{"", "UPPER", "with-dash", "0123456789abcdefg"} {
		if awsdiscovery.ValidEnforcementSuffix(s) {
			t.Errorf("suffix %q accepted", s)
		}
	}
	if c := sv(enforcetest.Dig(tpl, "Conditions", "HasCallback")); !strings.Contains(c, "Fn::Not") {
		t.Fatalf("HasCallback = %v", c)
	}
}

// Every statement of the enforcement role's policy equals the expected table:
// same Sids, effects, action sets, resources and conditions; nothing more.
func TestP3EnfTemplatePermissionsExact(t *testing.T) {
	tpl := enforcementTemplate(t)
	sts := enforcementStatements(t, tpl)
	seen := map[string]bool{}
	for _, st := range sts {
		sid, _ := st["Sid"].(string)
		exp, ok := expectedEnforcementPolicy[sid]
		if !ok {
			t.Errorf("unexpected statement %q: %v", sid, st)
			continue
		}
		if seen[sid] {
			t.Errorf("statement %q appears twice", sid)
		}
		seen[sid] = true
		for k := range st {
			switch k {
			case "Sid", "Effect", "Action", "Resource", "Condition":
			default:
				t.Errorf("%s: unexpected element %s (NotAction/NotResource/Principal are never used here)", sid, k)
			}
		}
		if st["Effect"] != exp.Effect {
			t.Errorf("%s: Effect %v, want %s", sid, st["Effect"], exp.Effect)
		}
		if got := svList(st["Action"]); !reflect.DeepEqual(got, exp.Action) {
			t.Errorf("%s: Action %v, want %v", sid, got, exp.Action)
		}
		if got := svList(st["Resource"]); !reflect.DeepEqual(got, exp.Resource) {
			t.Errorf("%s: Resource %v, want %v", sid, got, exp.Resource)
		}
		gotCond := map[string]map[string]string{}
		if c, ok := st["Condition"].(map[string]any); ok {
			for op, kv := range c {
				gotCond[op] = map[string]string{}
				for key, val := range kv.(map[string]any) {
					gotCond[op][key] = sv(val)
				}
			}
		}
		wantCond := exp.Condition
		if wantCond == nil {
			wantCond = map[string]map[string]string{}
		}
		if !reflect.DeepEqual(gotCond, wantCond) {
			t.Errorf("%s: Condition %v, want %v", sid, gotCond, wantCond)
		}
	}
	for sid := range expectedEnforcementPolicy {
		if !seen[sid] {
			t.Errorf("statement %q is missing", sid)
		}
	}
	role := enforcetest.Dig(tpl, "Resources", "AuthSecEnforcementRole", "Properties")
	for _, k := range []string{"ManagedPolicyArns", "PermissionsBoundary", "Path"} {
		if enforcetest.Dig(role, k) != nil {
			t.Errorf("the enforcement role sets %s: the inline policy must be its only grant", k)
		}
	}
}

// The restrictions §3.6 and §3.1 rely on, each asserted on its own.
func TestP3EnfTemplateRestrictions(t *testing.T) {
	tpl := enforcementTemplate(t)
	sts := enforcementStatements(t, tpl)
	boundaryActions := map[string]bool{"iam:PutRolePermissionsBoundary": true, "iam:DeleteRolePermissionsBoundary": true}
	policyActions := map[string]bool{"iam:CreatePolicy": true, "iam:TagPolicy": true, "iam:CreatePolicyVersion": true,
		"iam:DeletePolicyVersion": true, "iam:SetDefaultPolicyVersion": true, "iam:DeletePolicy": true}

	var allowed []string
	denied := map[string][]string{} // action -> resources/conditions of denies
	for _, st := range sts {
		sid, _ := st["Sid"].(string)
		actions := svList(st["Action"])
		resources := svList(st["Resource"])
		switch st["Effect"] {
		case "Allow":
			for _, a := range actions {
				allowed = append(allowed, a)
				if strings.ContainsAny(a, "*?") {
					t.Errorf("%s: wildcard action %q", sid, a)
				}
				// Reads nothing (§3.5).
				for _, verb := range []string{":Get", ":List", ":Describe", ":Simulate", ":Generate"} {
					if strings.Contains(a, verb) {
						t.Errorf("%s: the enforcement role may read (%s); it must read nothing", sid, a)
					}
				}
				switch {
				case policyActions[a]:
					// Policy writes only under /authsec/.
					if !reflect.DeepEqual(resources, []string{authsecPolicies}) {
						t.Errorf("%s: %s on %v, want only %s", sid, a, resources, authsecPolicies)
					}
				case boundaryActions[a]:
					// Attach and detach only when the boundary is an AuthSec policy.
					cond, _ := st["Condition"].(map[string]any)
					if got := sv(enforcetest.Dig(cond, "ArnLike", "iam:PermissionsBoundary")); got != authsecPolicies {
						t.Errorf("%s: %s is not conditioned on ArnLike iam:PermissionsBoundary = %s (got %q)",
							sid, a, authsecPolicies, got)
					}
					if len(cond) != 1 {
						t.Errorf("%s: unexpected extra condition operators %v", sid, cond)
					}
				default:
					t.Errorf("%s: action %s is outside §3.5's enforcement set", sid, a)
				}
			}
		case "Deny":
			cond, _ := json.Marshal(st["Condition"])
			for _, a := range actions {
				denied[a] = append(denied[a], strings.Join(resources, ",")+"|"+string(cond))
			}
		default:
			t.Errorf("%s: Effect %v", sid, st["Effect"])
		}
	}
	sort.Strings(allowed)
	if want := []string{"iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicy", "iam:DeletePolicyVersion",
		"iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary", "iam:SetDefaultPolicyVersion",
		"iam:TagPolicy"}; !reflect.DeepEqual(allowed, want) {
		t.Errorf("allowed actions = %v, want exactly §3.5's %v", allowed, want)
	}
	// Protection by PATH and TAG, for both boundary actions.
	for a := range boundaryActions {
		all := strings.Join(denied[a], "\n")
		for _, must := range []string{"role/aws-service-role/*", "role/aws-reserved/*",
			`"aws:ResourceTag/ManagedBy":"AuthSec"`, `"aws:ResourceTag/authsec:protected":"true"`} {
			if !strings.Contains(all, must) {
				t.Errorf("%s is not denied for %s", a, must)
			}
		}
	}
	// Never by name: no statement names a role, and no condition keys on a
	// name or an id.
	raw, _ := json.Marshal(sts)
	for _, bad := range []string{"AuthSecCloudDiscovery", "AuthSecEnforcement", "aws:userid", "aws:username",
		"iam:ResourceName", "role/AuthSec"} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("the enforcement policy names %q: protection must be by path and tag, never by name", bad)
		}
	}
}

// Trust, tags and the self-test role.
func TestP3EnfTemplateRolesAndTrust(t *testing.T) {
	tpl := enforcementTemplate(t)
	role := enforcetest.Dig(tpl, "Resources", "AuthSecEnforcementRole", "Properties")
	trust, _ := enforcetest.Dig(role, "AssumeRolePolicyDocument", "Statement").([]any)
	if len(trust) != 1 {
		t.Fatalf("enforcement trust has %d statements, want 1", len(trust))
	}
	tr := trust[0]
	if enforcetest.Dig(tr, "Effect") != "Allow" || sv(enforcetest.Dig(tr, "Principal", "AWS")) != "ref:AuthSecPrincipalArn" ||
		sv(enforcetest.Dig(tr, "Action")) != "sts:AssumeRole" ||
		sv(enforcetest.Dig(tr, "Condition", "StringEquals", "sts:ExternalId")) != "ref:ExternalId" {
		t.Fatalf("enforcement trust = %v, want AuthSecPrincipalArn with StringEquals sts:ExternalId", tr)
	}
	if n := sv(enforcetest.Dig(role, "RoleName")); n != subPrefix+"AuthSecEnforcement-${NameSuffix}" {
		t.Errorf("enforcement RoleName = %q", n)
	}
	if tags := tagMap(enforcetest.Dig(role, "Tags")); tags["ManagedBy"] != "AuthSec" {
		t.Errorf("enforcement role tags = %v, want ManagedBy=AuthSec (it must protect itself)", tags)
	}

	st := enforcetest.Dig(tpl, "Resources", "AuthSecEnforcementSelfTestRole", "Properties")
	if n := sv(enforcetest.Dig(st, "RoleName")); n != subPrefix+"AuthSecEnforcementSelfTest-${NameSuffix}" {
		t.Errorf("self-test RoleName = %q", n)
	}
	tags := tagMap(enforcetest.Dig(st, "Tags"))
	if tags["authsec:selftest"] != "true" {
		t.Errorf("self-test role tags = %v, want authsec:selftest=true", tags)
	}
	if _, ok := tags["ManagedBy"]; ok {
		t.Errorf("the self-test role is tagged ManagedBy: ProtectAuthSecRoles would deny every probe")
	}
	if _, ok := tags["authsec:protected"]; ok {
		t.Errorf("the self-test role is tagged authsec:protected")
	}
	if p := enforcetest.Dig(st, "Path"); p != nil {
		t.Errorf("the self-test role sets Path %v: it must sit at / (outside the protected paths)", p)
	}
	if enforcetest.Dig(st, "ManagedPolicyArns") != nil {
		t.Errorf("the self-test role has managed policies; it must grant nothing")
	}
	pols, _ := enforcetest.Dig(st, "Policies").([]any)
	if len(pols) != 1 {
		t.Fatalf("self-test role inline policies = %d, want 1 (deny everything)", len(pols))
	}
	only, _ := enforcetest.Dig(pols[0], "PolicyDocument", "Statement").([]any)
	if len(only) != 1 || enforcetest.Dig(only[0], "Effect") != "Deny" || sv(enforcetest.Dig(only[0], "Action")) != "*" ||
		sv(enforcetest.Dig(only[0], "Resource")) != "*" {
		t.Fatalf("self-test role policy = %v, want a single Deny * on *", only)
	}
	strust, _ := enforcetest.Dig(st, "AssumeRolePolicyDocument", "Statement").([]any)
	if len(strust) != 1 || sv(enforcetest.Dig(strust[0], "Principal", "AWS")) != subPrefix+"arn:${AWS::Partition}:iam::${AWS::AccountId}:root" {
		t.Fatalf("self-test trust = %v, want only this account", strust)
	}
}

func tagMap(v any) map[string]string {
	out := map[string]string{}
	list, _ := v.([]any)
	for _, x := range list {
		out[sv(enforcetest.Dig(x, "Key"))] = sv(enforcetest.Dig(x, "Value"))
	}
	return out
}

// The registration custom resource and the template version.
func TestP3EnfTemplateRegistrationAndVersion(t *testing.T) {
	tpl := enforcementTemplate(t)
	reg := enforcetest.Dig(tpl, "Resources", awsdiscovery.EnforcementRegistrationLogicalID)
	if reg == nil {
		t.Fatalf("no %s resource", awsdiscovery.EnforcementRegistrationLogicalID)
	}
	if enforcetest.Dig(reg, "Condition") != "HasCallback" {
		t.Errorf("registration Condition = %v, want HasCallback (manual deploys create no callback)", enforcetest.Dig(reg, "Condition"))
	}
	props := enforcetest.Dig(reg, "Properties")
	want := map[string]string{
		"ServiceToken": "ref:CallbackTopicArn", "ServiceTimeout": "600",
		"RoleArn": "getatt:AuthSecEnforcementRole.Arn", "SelfTestRoleArn": "getatt:AuthSecEnforcementSelfTestRole.Arn",
		"ExternalId": "ref:ExternalId", "AccountId": "ref:AWS::AccountId",
		"TemplateVersion": awsdiscovery.EnforcementTemplateVersion,
	}
	got := map[string]string{}
	for k, v := range props.(map[string]any) {
		got[k] = sv(v)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("registration properties = %v, want %v", got, want)
	}
	if v := enforcetest.Dig(tpl, "Metadata", "AuthSec", "TemplateVersion"); v != awsdiscovery.EnforcementTemplateVersion {
		t.Errorf("Metadata.AuthSec.TemplateVersion = %v, want %s", v, awsdiscovery.EnforcementTemplateVersion)
	}
	if v := enforcetest.Dig(tpl, "Outputs", "TemplateVersion", "Value"); v != awsdiscovery.EnforcementTemplateVersion {
		t.Errorf("Outputs.TemplateVersion = %v, want %s", v, awsdiscovery.EnforcementTemplateVersion)
	}
	for _, o := range []string{"RoleArn", "SelfTestRoleArn", "AccountId", "TemplateVersion"} {
		if enforcetest.Dig(tpl, "Outputs", o) == nil {
			t.Errorf("output %s missing (the manual path pastes RoleArn and SelfTestRoleArn back)", o)
		}
	}
}

// A11 and §3.6, simulated against the template's own policy: the requests a
// forced attempt would make, and which statement decides each.
func TestP3EnfTemplateSimulatedDecisions(t *testing.T) {
	const acct = "429418377036"
	p, err := enforcetest.EnforcementPolicy(enforcementTemplate(t), acct)
	if err != nil {
		t.Fatal(err)
	}
	authsec := "arn:aws:iam::" + acct + ":policy/authsec/AuthSecBoundary-AROAEXAMPLE"
	customer := "arn:aws:iam::" + acct + ":policy/CustomerBoundary"
	role := func(path string) string { return "arn:aws:iam::" + acct + ":role" + path }
	cases := []struct {
		name     string
		req      enforcetest.Request
		allowed  bool
		decideBy string
	}{
		{"create an AuthSec policy", enforcetest.Request{Action: "iam:CreatePolicy", Resource: authsec}, true, "ManageAuthSecPolicies"},
		{"create a policy outside /authsec/", enforcetest.Request{Action: "iam:CreatePolicy", Resource: customer}, false, ""},
		{"version a customer policy", enforcetest.Request{Action: "iam:CreatePolicyVersion", Resource: customer}, false, ""},
		{"delete a customer policy", enforcetest.Request{Action: "iam:DeletePolicy", Resource: customer}, false, ""},
		{"read a role", enforcetest.Request{Action: "iam:GetRole", Resource: role("/LabRightSizeRole")}, false, ""},
		{"attach an AuthSec boundary to a workload role",
			enforcetest.Request{Action: "iam:PutRolePermissionsBoundary", Resource: role("/LabRightSizeRole"),
				Context: map[string]string{"iam:PermissionsBoundary": authsec}}, true, "AttachOnlyAuthSecBoundaries"},
		{"attach a foreign (AWS managed) boundary",
			enforcetest.Request{Action: "iam:PutRolePermissionsBoundary", Resource: role("/LabRightSizeRole"),
				Context: map[string]string{"iam:PermissionsBoundary": "arn:aws:iam::aws:policy/ReadOnlyAccess"}}, false, ""},
		{"attach a customer boundary",
			enforcetest.Request{Action: "iam:PutRolePermissionsBoundary", Resource: role("/LabRightSizeRole"),
				Context: map[string]string{"iam:PermissionsBoundary": customer}}, false, ""},
		{"A11 service-linked role (by path)",
			enforcetest.Request{Action: "iam:PutRolePermissionsBoundary", Resource: role("/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS"),
				Context: map[string]string{"iam:PermissionsBoundary": authsec}}, false, "ProtectServiceRoles"},
		{"A11 AWS reserved (SSO) role",
			enforcetest.Request{Action: "iam:DeleteRolePermissionsBoundary", Resource: role("/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin"),
				Context: map[string]string{"iam:PermissionsBoundary": authsec}}, false, "ProtectServiceRoles"},
		{"A11 ManagedBy=AuthSec role with a customer name",
			enforcetest.Request{Action: "iam:PutRolePermissionsBoundary", Resource: role("/payments-reader"),
				Context: map[string]string{"iam:PermissionsBoundary": authsec, "aws:ResourceTag/ManagedBy": "AuthSec"}}, false, "ProtectAuthSecRoles"},
		{"A11 authsec:protected role",
			enforcetest.Request{Action: "iam:PutRolePermissionsBoundary", Resource: role("/LabRightSizeRole"),
				Context: map[string]string{"iam:PermissionsBoundary": authsec, "aws:ResourceTag/authsec:protected": "true"}}, false, "ProtectTaggedRoles"},
		{"a role NAMED like AuthSec's but untagged is not protected by its name",
			enforcetest.Request{Action: "iam:PutRolePermissionsBoundary", Resource: role("/AuthSecCloudDiscovery"),
				Context: map[string]string{"iam:PermissionsBoundary": authsec}}, true, "AttachOnlyAuthSecBoundaries"},
		{"detach an AuthSec boundary",
			enforcetest.Request{Action: "iam:DeleteRolePermissionsBoundary", Resource: role("/LabRightSizeRole"),
				Context: map[string]string{"iam:PermissionsBoundary": authsec}}, true, "DetachOnlyAuthSecBoundaries"},
		{"detach a customer's own boundary",
			enforcetest.Request{Action: "iam:DeleteRolePermissionsBoundary", Resource: role("/LabRightSizeRole"),
				Context: map[string]string{"iam:PermissionsBoundary": customer}}, false, ""},
		{"detach when the key is absent", enforcetest.Request{Action: "iam:DeleteRolePermissionsBoundary", Resource: role("/LabRightSizeRole")}, false, ""},
		{"assume another role", enforcetest.Request{Action: "sts:AssumeRole", Resource: role("/Admin")}, false, ""},
	}
	for _, c := range cases {
		d := p.Evaluate(c.req)
		if d.Allowed != c.allowed || d.By != c.decideBy {
			t.Errorf("%s: allowed=%v by %q, want allowed=%v by %q", c.name, d.Allowed, d.By, c.allowed, c.decideBy)
		}
	}
}

// The enforcement Quick Create link is checked against the ENFORCEMENT
// template's parameters, not the discovery template's.
func TestP3EnfQuickCreateURL(t *testing.T) {
	const tplURL = "https://bucket.s3.us-east-1.amazonaws.com/aws/enforcement/v/authsec-aws-enforcement-role.yaml"
	link, err := awsdiscovery.EnforcementQuickCreateURL("us-east-1", tplURL, awsdiscovery.EnforcementStackName("abc123"),
		map[string]string{"AuthSecPrincipalArn": "arn:aws:iam::111111111111:role/AuthSec", "ExternalId": strings.Repeat("e", 40),
			"CallbackTopicArn": "arn:aws:sns:us-east-1:111111111111:cb", "NameSuffix": "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	frag := link[strings.Index(link, "?templateURL")+1:]
	q, err := url.ParseQuery(frag)
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("stackName") != "AuthSec-Enforcement-abc123" || q.Get("param_NameSuffix") != "abc123" || q.Get("templateURL") != tplURL {
		t.Fatalf("link = %s", link)
	}
	// RoleName is a discovery parameter; the enforcement template has none.
	if _, err := awsdiscovery.EnforcementQuickCreateURL("us-east-1", tplURL, "AuthSec-Enforcement-x",
		map[string]string{"RoleName": "x"}); err == nil {
		t.Fatal("a parameter the enforcement template does not declare was accepted")
	}
	cfg, err := awsdiscovery.ParseCallbackConfig(`{"us-east-1":"arn:aws:sns:us-east-1:111111111111:cb"}`,
		"https://sqs.us-east-1.amazonaws.com/111111111111/q", "https://bucket.s3.us-east-1.amazonaws.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if u := cfg.EnforcementTemplateURLFor(); u != "https://bucket.s3.us-east-1.amazonaws.com/aws/enforcement/"+
		awsdiscovery.EnforcementTemplateVersion+"/authsec-aws-enforcement-role.yaml" {
		t.Fatalf("enforcement template URL = %s", u)
	}
}

// The two custom resources are never confused: each parser accepts only its
// own resource.
func TestP3EnfCallbackParsing(t *testing.T) {
	msg := func(rt, lid string) string {
		b, _ := json.Marshal(map[string]any{
			"RequestType": "Create", "RequestId": "r1", "ResponseURL": "https://x", "ResourceType": rt, "LogicalResourceId": lid,
			"StackId": "arn:aws:cloudformation:us-east-1:222222222222:stack/AuthSec-Enforcement-x/1",
			"ResourceProperties": map[string]string{"RoleArn": "arn:aws:iam::222222222222:role/AuthSecEnforcement-x",
				"SelfTestRoleArn": "arn:aws:iam::222222222222:role/AuthSecEnforcementSelfTest-x", "ExternalId": "e",
				"AccountId": "222222222222", "TemplateVersion": awsdiscovery.EnforcementTemplateVersion},
		})
		return string(b)
	}
	enf := msg(awsdiscovery.EnforcementRegistrationResourceType, awsdiscovery.EnforcementRegistrationLogicalID)
	disc := msg(awsdiscovery.RegistrationResourceType, awsdiscovery.RegistrationLogicalID)
	if !awsdiscovery.IsEnforcementRegistration(enf) || awsdiscovery.IsEnforcementRegistration(disc) {
		t.Fatal("IsEnforcementRegistration misroutes")
	}
	// The type alone is not enough: the logical id must match too.
	if awsdiscovery.IsEnforcementRegistration(msg(awsdiscovery.EnforcementRegistrationResourceType, "Other")) {
		t.Fatal("a different logical id was routed as the enforcement resource")
	}
	req, err := awsdiscovery.ParseEnforcementCFNRequest(enf)
	if err != nil || req.Properties.SelfTestRoleArn == "" || req.Properties.TemplateVersion != awsdiscovery.EnforcementTemplateVersion {
		t.Fatalf("parse enforcement: %v %+v", err, req)
	}
	if _, err := awsdiscovery.ParseEnforcementCFNRequest(disc); err == nil {
		t.Fatal("the enforcement parser accepted the discovery resource")
	}
	if _, err := awsdiscovery.ParseCFNRequest(enf); err == nil {
		t.Fatal("the discovery parser accepted the enforcement resource")
	}
	name, path, err := awsdiscovery.RoleNameFromARN("arn:aws:iam::222222222222:role/team/a/AuthSecEnforcementSelfTest-x")
	if err != nil || name != "AuthSecEnforcementSelfTest-x" || path != "/team/a/" {
		t.Fatalf("RoleNameFromARN = %q %q %v", name, path, err)
	}
}

// cfn-lint, when available: AUTHSEC_CFN_LINT names the binary (the T3.09
// gate runs it from a scratch venv). Absent, the structural tests above are
// the validation.
func TestP3EnfTemplateCfnLint(t *testing.T) {
	bin := os.Getenv("AUTHSEC_CFN_LINT")
	if bin == "" {
		t.Skip("AUTHSEC_CFN_LINT not set; cfn-lint not run (structural tests still apply)")
	}
	path, err := filepath.Abs("authsec-aws-enforcement-role.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, path).CombinedOutput()
	if err != nil {
		t.Fatalf("cfn-lint: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("cfn-lint reported:\n%s", out)
	}
}
