// Package enforcetest is test support for the enforcement stack: a
// CloudFormation YAML reader that keeps intrinsic functions, a small IAM
// policy simulator, and a fake IAM whose every decision is made by simulating
// the enforcement role's REAL policy, read from the template.
//
// The point of the fake is the link it makes: a self-test classification test
// runs against whatever the template says, so removing a statement or a
// condition from the template changes the self-test's result the way it would
// in AWS (A22), instead of a hand-written fake agreeing with itself.
//
// The simulator is an approximation of IAM policy evaluation, deliberately
// small: explicit Deny wins, then any Allow, else implicit deny; Action and
// Resource globs (* and ?); the condition operators the enforcement template
// uses (ArnLike, ArnEquals, StringEquals, StringLike), a missing key making a
// condition false. It is not a substitute for the Stage A lab self-test
// (docs/flows/aws-enforcement-stage-a-selftest.md), which is what proves AWS
// evaluates the template this way.
package enforcetest

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseTemplate reads a CloudFormation YAML template into plain Go values
// (map[string]any, []any, string, bool, int, float64), with every short-form
// intrinsic converted to its long form: !Sub x -> {"Fn::Sub": x}, !Ref x ->
// {"Ref": x}, !GetAtt A.B -> {"Fn::GetAtt": ["A","B"]}, and so on.
func ParseTemplate(src string) (map[string]any, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		return nil, err
	}
	if len(root.Content) != 1 {
		return nil, fmt.Errorf("template is not one YAML document")
	}
	v, err := convert(root.Content[0])
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("template is not a mapping")
	}
	return m, nil
}

var shortForms = map[string]string{
	"!Ref": "Ref", "!Sub": "Fn::Sub", "!GetAtt": "Fn::GetAtt", "!Not": "Fn::Not",
	"!Equals": "Fn::Equals", "!If": "Fn::If", "!Join": "Fn::Join", "!And": "Fn::And",
	"!Or": "Fn::Or", "!Select": "Fn::Select", "!Split": "Fn::Split", "!Condition": "Condition",
}

func convert(n *yaml.Node) (any, error) {
	if fn, ok := shortForms[n.Tag]; ok {
		cp := *n
		cp.Tag = ""
		cp.Style &^= yaml.TaggedStyle
		inner, err := convertPlain(&cp)
		if err != nil {
			return nil, err
		}
		if fn == "Fn::GetAtt" {
			if s, ok := inner.(string); ok {
				a, b, _ := strings.Cut(s, ".")
				inner = []any{a, b}
			}
		}
		return map[string]any{fn: inner}, nil
	}
	if strings.HasPrefix(n.Tag, "!") && !strings.HasPrefix(n.Tag, "!!") {
		return nil, fmt.Errorf("line %d: unknown tag %s", n.Line, n.Tag)
	}
	return convertPlain(n)
}

func convertPlain(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.ScalarNode:
		var v any
		// Decode a copy with no custom tag so yaml resolves the scalar type.
		cp := *n
		if strings.HasPrefix(cp.Tag, "!") && !strings.HasPrefix(cp.Tag, "!!") {
			cp.Tag = ""
		}
		if err := cp.Decode(&v); err != nil {
			return nil, err
		}
		return v, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := convert(c)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if _, dup := out[k]; dup {
				return nil, fmt.Errorf("line %d: duplicate key %q", n.Content[i].Line, k)
			}
			v, err := convert(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case yaml.AliasNode:
		return convert(n.Alias)
	}
	return nil, fmt.Errorf("line %d: unsupported YAML node", n.Line)
}

// Resolve substitutes the intrinsics a policy document uses: Fn::Sub over
// ${AWS::Partition}, ${AWS::AccountId} and parameters, Ref to parameters and
// pseudo parameters. Anything else is returned unchanged.
func Resolve(v any, params map[string]string) any {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 1 {
			if s, ok := t["Fn::Sub"].(string); ok {
				return subPattern.ReplaceAllStringFunc(s, func(m string) string {
					name := m[2 : len(m)-1]
					if val, ok := params[name]; ok {
						return val
					}
					return m
				})
			}
			if s, ok := t["Ref"].(string); ok {
				if val, ok := params[s]; ok {
					return val
				}
			}
		}
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = Resolve(x, params)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = Resolve(x, params)
		}
		return out
	}
	return v
}

var subPattern = regexp.MustCompile(`\$\{[A-Za-z0-9:]+\}`)

// Dig walks a parsed template by keys (map) and indexes (int).
func Dig(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			v = m[k]
		case int:
			s, ok := v.([]any)
			if !ok || k < 0 || k >= len(s) {
				return nil
			}
			v = s[k]
		}
	}
	return v
}

// EnforcementPolicy returns the enforcement role's inline policy statements,
// resolved for one account in the commercial partition. It fails unless the
// role has exactly one inline policy and no managed policies, so a template
// that grants anything outside its inline document cannot pass as simulated.
func EnforcementPolicy(template map[string]any, account string) (Policy, error) {
	role := Dig(template, "Resources", "AuthSecEnforcementRole", "Properties")
	if role == nil {
		return Policy{}, fmt.Errorf("no AuthSecEnforcementRole")
	}
	if Dig(role, "ManagedPolicyArns") != nil || Dig(role, "PermissionsBoundary") != nil {
		return Policy{}, fmt.Errorf("the enforcement role must have no managed policies and no boundary")
	}
	pols, _ := Dig(role, "Policies").([]any)
	if len(pols) != 1 {
		return Policy{}, fmt.Errorf("the enforcement role must have exactly one inline policy, has %d", len(pols))
	}
	doc := Resolve(Dig(pols[0], "PolicyDocument"), map[string]string{
		"AWS::Partition": "aws", "AWS::AccountId": account,
	})
	return PolicyFromDocument(doc)
}
