package iacpr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// CloudFormation templates (YAML or JSON), read as yaml.v3 node trees so a
// change keeps the template's order, short-form tags (!Ref, !GetAtt) and,
// for YAML, its comments. A JSON template is written back as JSON.

type cfnTemplate struct {
	Path      string
	JSON      bool
	Root      *yaml.Node // the document's top mapping
	Resources *yaml.Node // the Resources mapping (nil when absent)
	Transform bool
}

func parseCFN(path, src string) (*cfnTemplate, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: not a CloudFormation template", path)
	}
	t := &cfnTemplate{Path: path, Root: doc.Content[0], JSON: strings.HasPrefix(strings.TrimSpace(src), "{")}
	t.Resources = mapGet(t.Root, "Resources")
	t.Transform = mapGet(t.Root, "Transform") != nil
	return t, nil
}

// isCFNTemplate: a YAML/JSON file with AWSTemplateFormatVersion or a
// Resources mapping whose entries have a Type.
func isCFNTemplate(src string) bool {
	var doc yaml.Node
	if yaml.Unmarshal([]byte(src), &doc) != nil || doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return false
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return false
	}
	if mapGet(root, "AWSTemplateFormatVersion") != nil {
		return true
	}
	res := mapGet(root, "Resources")
	if res == nil || res.Kind != yaml.MappingNode {
		return false
	}
	for i := 1; i < len(res.Content); i += 2 {
		if mapGet(res.Content[i], "Type") != nil {
			return true
		}
	}
	return false
}

func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func mapSet(m *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = v
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
}

func mapDelete(m *yaml.Node, key string) bool {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return true
		}
	}
	return false
}

// cfnResource is one entry of Resources.
type cfnResource struct {
	LogicalID string
	Type      string
	Node      *yaml.Node // the resource mapping
	Props     *yaml.Node // Properties (may be nil)
}

func (t *cfnTemplate) resources() []cfnResource {
	var out []cfnResource
	if t.Resources == nil || t.Resources.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(t.Resources.Content); i += 2 {
		n := t.Resources.Content[i+1]
		typ := ""
		if tn := mapGet(n, "Type"); tn != nil {
			typ = tn.Value
		}
		out = append(out, cfnResource{LogicalID: t.Resources.Content[i].Value, Type: typ, Node: n, Props: mapGet(n, "Properties")})
	}
	return out
}

// cfnScalar is a plain literal string (not an intrinsic).
func cfnScalar(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode || strings.HasPrefix(n.Tag, "!") && n.Tag != "!!str" {
		return "", false
	}
	return n.Value, true
}

// cfnRefTarget is the logical id a !Ref / {"Ref": X} / !GetAtt X.Attr names.
func cfnRefTarget(n *yaml.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	switch {
	case n.Kind == yaml.ScalarNode && n.Tag == "!Ref":
		return n.Value, true
	case n.Kind == yaml.ScalarNode && n.Tag == "!GetAtt":
		return strings.SplitN(n.Value, ".", 2)[0], true
	case n.Kind == yaml.SequenceNode && n.Tag == "!GetAtt" && len(n.Content) > 0:
		return n.Content[0].Value, true
	case n.Kind == yaml.MappingNode && len(n.Content) == 2:
		switch n.Content[0].Value {
		case "Ref":
			return n.Content[1].Value, true
		case "Fn::GetAtt":
			v := n.Content[1]
			if v.Kind == yaml.SequenceNode && len(v.Content) > 0 {
				return v.Content[0].Value, true
			}
			if v.Kind == yaml.ScalarNode {
				return strings.SplitN(v.Value, ".", 2)[0], true
			}
		}
	}
	return "", false
}

// cfnLiteral converts a node to a Go value; any intrinsic is not literal.
func cfnLiteral(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.ScalarNode:
		if strings.HasPrefix(n.Tag, "!") && !strings.HasPrefix(n.Tag, "!!") {
			return nil, errNotLiteral
		}
		var v any
		if err := n.Decode(&v); err != nil {
			return nil, err
		}
		return v, nil
	case yaml.SequenceNode:
		if strings.HasPrefix(n.Tag, "!") && !strings.HasPrefix(n.Tag, "!!") {
			return nil, errNotLiteral
		}
		out := []any{}
		for _, c := range n.Content {
			v, err := cfnLiteral(c)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		if strings.HasPrefix(n.Tag, "!") && !strings.HasPrefix(n.Tag, "!!") {
			return nil, errNotLiteral
		}
		out := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if k == "Ref" || strings.HasPrefix(k, "Fn::") {
				return nil, errNotLiteral
			}
			v, err := cfnLiteral(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case yaml.AliasNode:
		return cfnLiteral(n.Alias)
	}
	return nil, errNotLiteral
}

// cfnDocumentNode builds a node tree for a canonical JSON document. The
// Version value is kept a string ("2012-10-17" must not become a date).
func cfnDocumentNode(canonical string) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(canonical), &doc); err != nil {
		return nil, err
	}
	n := doc.Content[0]
	clearStyle(n)
	return n, nil
}

func clearStyle(n *yaml.Node) {
	n.Style = 0
	if n.Kind == yaml.ScalarNode && n.Tag == "!!str" {
		// keep strings that look like other types quoted
		var probe any
		if yaml.Unmarshal([]byte(n.Value), &probe) == nil {
			if _, isStr := probe.(string); !isStr {
				n.Style = yaml.DoubleQuotedStyle
			}
		}
	}
	for _, c := range n.Content {
		clearStyle(c)
	}
}

func cfnRefNode(logicalID string, jsonForm bool) *yaml.Node {
	if jsonForm {
		return &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "Ref"}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: logicalID}}}
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!Ref", Value: logicalID}
}

func strNode(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }

// render writes the template back in its own syntax.
func (t *cfnTemplate) render() (string, error) {
	if t.JSON {
		var b bytes.Buffer
		if err := nodeJSON(&b, t.Root, ""); err != nil {
			return "", err
		}
		b.WriteString("\n")
		return b.String(), nil
	}
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{t.Root}}); err != nil {
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	return b.String(), nil
}

// nodeJSON writes a node tree as indented JSON, keeping key order.
func nodeJSON(b *bytes.Buffer, n *yaml.Node, indent string) error {
	switch n.Kind {
	case yaml.MappingNode:
		if len(n.Content) == 0 {
			b.WriteString("{}")
			return nil
		}
		b.WriteString("{\n")
		for i := 0; i+1 < len(n.Content); i += 2 {
			b.WriteString(indent + "  " + strconv.Quote(n.Content[i].Value) + ": ")
			if err := nodeJSON(b, n.Content[i+1], indent+"  "); err != nil {
				return err
			}
			if i+2 < len(n.Content) {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(indent + "}")
	case yaml.SequenceNode:
		if len(n.Content) == 0 {
			b.WriteString("[]")
			return nil
		}
		b.WriteString("[\n")
		for i, c := range n.Content {
			b.WriteString(indent + "  ")
			if err := nodeJSON(b, c, indent+"  "); err != nil {
				return err
			}
			if i+1 < len(n.Content) {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(indent + "]")
	case yaml.ScalarNode:
		var v any
		if n.Tag == "!!str" || n.Style == yaml.DoubleQuotedStyle || n.Style == yaml.SingleQuotedStyle {
			v = n.Value
		} else if err := n.Decode(&v); err != nil {
			return err
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		b.Write(raw)
	case yaml.AliasNode:
		return nodeJSON(b, n.Alias, indent)
	default:
		return fmt.Errorf("unsupported node kind %d", n.Kind)
	}
	return nil
}
