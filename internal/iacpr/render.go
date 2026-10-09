// Package iacpr renders an approved plan as a change to the customer's
// infrastructure-as-code (SPEC-iga-phase3-policy.md §8.11, §11; T3.17) and
// opens it as a pull request through the GitHub App (github.go).
//
// The supported-form matrix of §8.11 is decided here, at compile time, by
// rendering the plan against the mapped source: a form AuthSec cannot locate
// and change mechanically is a Fallback (delivery export) with its reason,
// never discovered after a PR is opened. Rendering is pure: the source files,
// the plan and the archived documents are inputs.
//
// What is rendered is driven by the plan's classifier FACTS (§2.8), the same
// table the verifier classifies against, so the PR changes exactly what
// AuthSec will later recognise in AWS:
//
//   - role_boundary before -> after: the role's permissions_boundary
//     (Terraform) / PermissionsBoundary (CloudFormation) is set, re-pointed or
//     removed;
//   - policy_document absent -> hash: a policy resource is added;
//     hash -> absent: removed; hash -> hash: its document replaced
//     (structure-preserving narrowing has already happened in the compiler,
//     §3.4 -- Sids, conditions and Deny statements are in the document);
//   - workload_binding / new_role (§11): the dedicated role is added with the
//     source role's trust policy, the same managed policies by ARN, copies of
//     its inline policies and its boundary, and the subject's binding moves.
package iacpr

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/authsec-ai/authsec/internal/igagov"
)

// Source formats (053 iga_gov_iac_source.format).
const (
	FormatTerraform      = "terraform"
	FormatCloudFormation = "cloudformation"
)

// Fallback reasons (§8.11 supported-form matrix).
const (
	ReasonFormUnsupported = "iac_form_unsupported"
	ReasonGeneratedSource = "iac_generated_source"
	ReasonRoleNotFound    = "iac_role_not_found"
	ReasonRoleAmbiguous   = "iac_role_ambiguous"
	// ReasonSourceDiffers: the mapped source no longer says what was
	// approved (the trust policy, an inline policy or the boundary of the
	// role being copied differs from the plan's archived documents). AuthSec
	// never renders an unapproved document; at deploy time this blocks the
	// deployment (iac_form_changed) for a new plan.
	ReasonSourceDiffers = "iac_source_differs"
	// ReasonDocumentNotArchived: a document the plan names is not archived
	// (a plan compiled before documents were archived); re-propose.
	ReasonDocumentNotArchived = "iac_document_not_archived"
)

// Fallback is why a plan cannot be delivered as a PR from its mapped
// source; the plan is delivered as export instead, with this reason.
type Fallback struct {
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

func (f *Fallback) Error() string { return f.Reason + ": " + f.Detail }

func fallback(reason, format string, args ...any) error {
	return &Fallback{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// AsFallback returns the fallback an error carries, or nil.
func AsFallback(err error) *Fallback {
	var f *Fallback
	if errors.As(err, &f) {
		return f
	}
	return nil
}

// RoleMatch is iga_gov_iac_source.role_match: explicit rules naming the
// resource address (Terraform) or logical id (CloudFormation) of a role.
// Roles without a rule are located by their literal name.
//
// DECISION (T3.17): the spec names "role_match rules" without a shape; a
// rule is {role_name, resource}, role_name exact or with one trailing '*'.
type RoleMatch struct {
	Rules []RoleRule `json:"rules,omitempty"`
}

// RoleRule maps a role name to a resource.
type RoleRule struct {
	RoleName string `json:"role_name"`
	Resource string `json:"resource"`
}

// ParseRoleMatch reads and validates a role_match value.
func ParseRoleMatch(raw []byte) (RoleMatch, error) {
	var m RoleMatch
	if len(raw) == 0 || string(raw) == "null" {
		return m, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return RoleMatch{}, fmt.Errorf("role_match: %w", err)
	}
	for i, r := range m.Rules {
		if r.RoleName == "" || r.Resource == "" {
			return RoleMatch{}, fmt.Errorf("role_match.rules[%d]: role_name and resource are required", i)
		}
		if strings.Count(r.RoleName, "*") > 1 || (strings.Contains(r.RoleName, "*") && !strings.HasSuffix(r.RoleName, "*")) {
			return RoleMatch{}, fmt.Errorf("role_match.rules[%d]: only one trailing * is allowed", i)
		}
	}
	return m, nil
}

func (m RoleMatch) resourceFor(roleName string) string {
	for _, r := range m.Rules {
		if r.RoleName == roleName || (strings.HasSuffix(r.RoleName, "*") && strings.HasPrefix(roleName, strings.TrimSuffix(r.RoleName, "*"))) {
			return r.Resource
		}
	}
	return ""
}

// Source is one mapped IaC source (iga_gov_iac_source).
type Source struct {
	Format    string
	Directory string
	RoleMatch RoleMatch
}

// RoleTarget is the control's role.
type RoleTarget struct {
	Name      string
	ARN       string
	RoleID    string
	AccountID string
	Partition string
}

func (r RoleTarget) partition() string {
	if r.Partition != "" {
		return r.Partition
	}
	return "aws"
}

// Request is one rendering.
type Request struct {
	Source Source
	// Files are the mapped directory's files, by repository path.
	Files map[string]string
	Role  RoleTarget
	Plan  igagov.Plan
	// Documents are archived documents by hash (desired, before, earlier).
	Documents map[string]string
	// DeploymentID replaces igagov.DeploymentPlaceholder in tags; empty at
	// compile time.
	DeploymentID string
	// KeepNewRole: a split_revert whose new role now has other consumers
	// restores the binding only and leaves the role (§11).
	KeepNewRole bool
}

// FileChange is one file of the change.
type FileChange struct {
	Path   string `json:"path"`
	Before string `json:"-"`
	After  string `json:"after"`
	New    bool   `json:"new,omitempty"`
}

// Change is the rendered change.
type Change struct {
	Format   string       `json:"format"`
	Location string       `json:"location"`
	Files    []FileChange `json:"files"`
	Summary  []string     `json:"summary"`
}

// Empty reports whether the change edits nothing (the state is already in
// place in the source).
func (c *Change) Empty() bool { return len(c.Files) == 0 }

// Render renders req.Plan against the mapped source. A form that cannot be
// changed mechanically is a *Fallback error (AsFallback).
func Render(req Request) (*Change, error) {
	if gen := generatedSource(req.Files); gen != "" {
		return nil, fallback(ReasonGeneratedSource, "%s", gen)
	}
	switch req.Source.Format {
	case FormatTerraform:
		return renderTerraform(req)
	case FormatCloudFormation:
		return renderCFN(req)
	}
	return nil, fmt.Errorf("iacpr: unknown format %q", req.Source.Format)
}

// generatedSource names a generator whose output AuthSec must not edit
// (§8.11: CDK, Pulumi, Terragrunt, SAM transforms, CloudFormation macros).
func generatedSource(files map[string]string) string {
	for _, p := range sortedKeys(files) {
		base := path.Base(p)
		switch {
		case base == "cdk.json" || strings.Contains(files[p], `"aws:cdk:path"`):
			return "AWS CDK source (" + p + ")"
		case base == "Pulumi.yaml" || (strings.HasPrefix(base, "Pulumi.") && strings.HasSuffix(base, ".yaml")):
			return "Pulumi project (" + p + ")"
		case base == "terragrunt.hcl":
			return "Terragrunt configuration (" + p + ")"
		}
	}
	return ""
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

/* ----------------------------- plan reading ------------------------------- */

type planFacts struct {
	boundary       *igagov.Fact
	docs           []igagov.Fact // policy_document facts
	binding        *igagov.Fact
	newRole        *igagov.Fact
	createTags     map[string]map[string]string // policy ARN -> CreatePolicy tags
	tagUpdates     map[string]map[string]string // policy ARN -> TagPolicy tags
	createRole     *igagov.Op
	attach         []string
	inline         []string
	newBoundary    string
	bindSteps      []string
	deleteRoleCond bool
}

func readPlan(p igagov.Plan, deploymentID string) planFacts {
	pf := planFacts{createTags: map[string]map[string]string{}, tagUpdates: map[string]map[string]string{}}
	for i := range p.Facts {
		f := p.Facts[i]
		switch f.Kind {
		case igagov.FactRoleBoundary:
			pf.boundary = &f
		case igagov.FactPolicyDocument:
			pf.docs = append(pf.docs, f)
		case igagov.FactBinding:
			pf.binding = &f
		case igagov.FactNewRole:
			pf.newRole = &f
		}
	}
	subst := func(tags map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range tags {
			if v == igagov.DeploymentPlaceholder {
				v = deploymentID
				if v == "" {
					v = igagov.DeploymentPlaceholder
				}
			}
			out[k] = v
		}
		return out
	}
	for i := range p.Ops {
		op := p.Ops[i]
		switch op.Op {
		case igagov.OpCreatePolicy:
			pf.createTags[op.PolicyARN] = subst(op.Tags)
		case igagov.OpTagPolicy:
			pf.tagUpdates[op.PolicyARN] = subst(op.Tags)
		case igagov.OpCreateRole:
			o := op
			pf.createRole = &o
		case igagov.OpAttachRolePolicy:
			pf.attach = append(pf.attach, op.PolicyARN)
		case igagov.OpPutRolePolicy:
			pf.inline = append(pf.inline, op.InlineName)
		case igagov.OpPutRolePermissionsBoundary:
			if op.RoleARN != "" {
				pf.newBoundary = op.PolicyARN
			}
		case igagov.OpBindSubject:
			pf.bindSteps = op.Steps
		case igagov.OpDeleteRole:
			pf.deleteRoleCond = op.OnlyIfUnused
		}
	}
	return pf
}

// policyName / policyPath split a customer-managed policy ARN.
func policyNamePath(arn string) (name, p string) {
	i := strings.Index(arn, ":policy")
	if i < 0 {
		return "", ""
	}
	full := arn[i+len(":policy"):]
	j := strings.LastIndex(full, "/")
	return full[j+1:], full[:j+1]
}

func roleNameOf(arn string) string {
	i := strings.LastIndex(arn, "/")
	if i < 0 {
		return arn
	}
	return arn[i+1:]
}

// archived is an approved document of the plan by hash; a missing one is a
// fallback (the change cannot be rendered from approved texts), never a
// re-read of the repository.
func (r Request) archived(hash, what string) (string, error) {
	d, ok := r.Documents[hash]
	if !ok {
		return "", fallback(ReasonDocumentNotArchived, "%s (%s) is not archived with the plan", what, hash)
	}
	return d, nil
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (r Request) doc(hash string) (string, error) {
	d, ok := r.Documents[hash]
	if !ok {
		return "", fmt.Errorf("iacpr: document %s is not archived", hash)
	}
	return d, nil
}

/* -------------------------------- Terraform -------------------------------- */

type tfSource struct {
	req     Request
	files   map[string]string
	blocks  []*tfBlock
	edits   map[string][]edit
	appends map[string][]string
	sum     []string
}

func loadTerraform(req Request) (*tfSource, error) {
	s := &tfSource{req: req, files: map[string]string{}, edits: map[string][]edit{}, appends: map[string][]string{}}
	for _, p := range sortedKeys(req.Files) {
		if !strings.HasSuffix(p, ".tf") {
			continue
		}
		bs, err := parseTerraform(p, req.Files[p])
		if err != nil {
			return nil, fallback(ReasonFormUnsupported, "%v", err)
		}
		s.files[p] = req.Files[p]
		s.blocks = append(s.blocks, bs...)
	}
	if len(s.files) == 0 {
		return nil, fallback(ReasonRoleNotFound, "no Terraform files in %s", req.Source.Directory)
	}
	return s, nil
}

func (s *tfSource) resources(typ string) []*tfBlock {
	var out []*tfBlock
	for _, b := range s.blocks {
		if b.Type == "resource" && len(b.Labels) == 2 && b.Labels[0] == typ {
			out = append(out, b)
		}
	}
	return out
}

func (s *tfSource) byAddress(addr string) *tfBlock {
	for _, b := range s.blocks {
		if b.address() == addr {
			return b
		}
	}
	return nil
}

func (s *tfSource) text(b *tfBlock) string { return s.files[b.File][b.Start:b.End] }

func iterated(b *tfBlock) bool { return b.attr("for_each") != nil || b.attr("count") != nil }

// locateRole finds the role's aws_iam_role block (§8.11 row 1).
func (s *tfSource) locateRole(name string) (*tfBlock, error) {
	if addr := s.req.Source.RoleMatch.resourceFor(name); addr != "" {
		b := s.byAddress(addr)
		if b == nil {
			return nil, fallback(ReasonRoleNotFound, "role_match names %s, which is not in %s", addr, s.req.Source.Directory)
		}
		if b.Type != "resource" || b.Labels[0] != "aws_iam_role" {
			return nil, fallback(ReasonFormUnsupported, "role_match names %s, which is not an aws_iam_role resource", addr)
		}
		if iterated(b) {
			return nil, fallback(ReasonFormUnsupported, "%s uses for_each/count", addr)
		}
		return b, nil
	}
	var found []*tfBlock
	quoted := strconv.Quote(name)
	var inModule, inIterated, nonLiteral []string
	for _, b := range s.resources("aws_iam_role") {
		if a := b.attr("name"); a != nil {
			if v, ok := literalString(a.Raw); ok {
				if v == name {
					if iterated(b) {
						inIterated = append(inIterated, b.address())
						continue
					}
					found = append(found, b)
				}
				continue
			}
		}
		if strings.Contains(s.text(b), quoted) || iterated(b) && strings.Contains(s.text(b), name) {
			nonLiteral = append(nonLiteral, b.address())
		}
	}
	for _, b := range s.blocks {
		if b.Type == "module" && strings.Contains(s.text(b), name) {
			src := ""
			if a := b.attr("source"); a != nil {
				src, _ = literalString(a.Raw)
			}
			inModule = append(inModule, b.address()+" (source "+src+")")
		}
	}
	switch {
	case len(found) == 1 && len(inModule) == 0:
		return found[0], nil
	case len(found) > 1 || (len(found) == 1 && len(inModule) > 0):
		var addrs []string
		for _, b := range found {
			addrs = append(addrs, b.address())
		}
		return nil, fallback(ReasonRoleAmbiguous, "role %s is defined more than once: %s", name, strings.Join(append(addrs, inModule...), ", "))
	case len(inModule) > 0:
		return nil, fallback(ReasonFormUnsupported, "role %s is defined inside a module: %s", name, strings.Join(inModule, ", "))
	case len(inIterated) > 0:
		return nil, fallback(ReasonFormUnsupported, "role %s is created with for_each/count: %s", name, strings.Join(inIterated, ", "))
	case len(nonLiteral) > 0:
		return nil, fallback(ReasonFormUnsupported, "role %s has a computed name: %s", name, strings.Join(nonLiteral, ", "))
	}
	return nil, fallback(ReasonRoleNotFound, "no aws_iam_role named %s in %s", name, s.req.Source.Directory)
}

// tfPolicy is an indexed aws_iam_policy resource.
type tfPolicy struct {
	block *tfBlock
	arn   string
}

func (s *tfSource) policies() map[string]tfPolicy {
	out := map[string]tfPolicy{}
	for _, b := range s.resources("aws_iam_policy") {
		if iterated(b) {
			continue
		}
		na := b.attr("name")
		if na == nil {
			continue
		}
		name, ok := literalString(na.Raw)
		if !ok {
			continue
		}
		p := "/"
		if pa := b.attr("path"); pa != nil {
			if v, ok := literalString(pa.Raw); ok {
				p = v
			} else {
				continue
			}
		}
		arn := "arn:" + s.req.Role.partition() + ":iam::" + s.req.Role.AccountID + ":policy" + p + name
		out[arn] = tfPolicy{block: b, arn: arn}
	}
	return out
}

// refPolicy resolves an expression naming a policy ARN: a reference to an
// indexed aws_iam_policy, or a literal ARN.
func refPolicy(raw string, pols map[string]tfPolicy) (string, bool) {
	raw = strings.TrimSpace(raw)
	if v, ok := literalString(raw); ok {
		return v, true
	}
	for arn, p := range pols {
		if raw == p.block.address()+".arn" || raw == p.block.address()+".id" {
			return arn, true
		}
	}
	return "", false
}

func (s *tfSource) edit(file string, e edit) { s.edits[file] = append(s.edits[file], e) }

func (s *tfSource) setAttr(b *tfBlock, name, value string) {
	if a := b.attr(name); a != nil {
		s.edit(b.File, edit{a.ValStart, a.ValEnd, value})
		return
	}
	indent := lineIndent(s.files[b.File], b.Close) + "  "
	ls := strings.LastIndexByte(s.files[b.File][:b.Close], '\n') + 1
	s.edit(b.File, edit{ls, ls, indent + name + " = " + value + "\n"})
}

func (s *tfSource) removeAttr(b *tfBlock, name string) {
	if a := b.attr(name); a != nil {
		s.edit(b.File, edit{a.LineStart, a.LineEnd, ""})
	}
}

func (s *tfSource) removeBlock(b *tfBlock) { s.edit(b.File, edit{b.Start, b.End, ""}) }

func (s *tfSource) appendTo(file, text string) { s.appends[file] = append(s.appends[file], text) }

func (s *tfSource) result(location string) (*Change, error) {
	ch := &Change{Format: FormatTerraform, Location: location, Files: []FileChange{}, Summary: s.sum}
	for _, p := range sortedKeys(s.files) {
		es, as := s.edits[p], s.appends[p]
		if len(es) == 0 && len(as) == 0 {
			continue
		}
		out, err := applyEdits(s.files[p], es)
		if err != nil {
			return nil, err
		}
		for _, a := range as {
			if !strings.HasSuffix(out, "\n") {
				out += "\n"
			}
			out += "\n" + a
		}
		if out != s.files[p] {
			ch.Files = append(ch.Files, FileChange{Path: p, Before: s.files[p], After: out})
		}
	}
	return ch, nil
}

func (s *tfSource) policyBlock(name, p, canonical string, tags map[string]string) (string, error) {
	expr, err := jsonencodeExpr(canonical, "  ")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "resource \"aws_iam_policy\" %q {\n", tfName(name))
	fmt.Fprintf(&b, "  name   = %s\n", strconv.Quote(name))
	fmt.Fprintf(&b, "  path   = %s\n", strconv.Quote(p))
	fmt.Fprintf(&b, "  policy = %s\n", expr)
	if len(tags) > 0 {
		fmt.Fprintf(&b, "  tags = %s\n", tfTags(tags, "  "))
	}
	b.WriteString("}\n")
	return b.String(), nil
}

func renderTerraform(req Request) (*Change, error) {
	s, err := loadTerraform(req)
	if err != nil {
		return nil, err
	}
	if req.Plan.Kind == igagov.PlanSplit || req.Plan.Kind == igagov.PlanSplitRevert {
		return s.renderSplit()
	}
	role, err := s.locateRole(req.Role.Name)
	if err != nil {
		return nil, err
	}
	pf := readPlan(req.Plan, req.DeploymentID)
	pols := s.policies()
	added := map[string]string{} // ARN -> address of a policy resource this change adds

	// Policy documents.
	for _, f := range pf.docs {
		if !f.Changes() {
			continue
		}
		name, p := policyNamePath(f.Subject)
		cur, inSource := pols[f.Subject]
		switch {
		case f.Before == igagov.ValueAbsent:
			if inSource {
				return nil, fallback(ReasonFormUnsupported, "%s already declares %s", cur.block.address(), f.Subject)
			}
			doc, err := req.doc(f.After)
			if err != nil {
				return nil, err
			}
			blk, err := s.policyBlock(name, p, doc, pf.createTags[f.Subject])
			if err != nil {
				return nil, err
			}
			s.appendTo(role.File, blk)
			added[f.Subject] = "aws_iam_policy." + tfName(name)
			s.sum = append(s.sum, "add aws_iam_policy."+tfName(name)+" ("+f.Subject+")")
		case f.After == igagov.ValueAbsent:
			if !inSource {
				return nil, fallback(ReasonFormUnsupported, "policy %s is not declared in %s", f.Subject, req.Source.Directory)
			}
			s.removeBlock(cur.block)
			s.sum = append(s.sum, "remove "+cur.block.address())
		default:
			if !inSource {
				return nil, fallback(ReasonFormUnsupported, "policy %s is not declared in %s", f.Subject, req.Source.Directory)
			}
			pa := cur.block.attr("policy")
			if pa == nil {
				return nil, fallback(ReasonFormUnsupported, "%s has no policy attribute", cur.block.address())
			}
			text, form, err := policyDocument(pa.Raw)
			if err != nil {
				return nil, fallback(ReasonFormUnsupported, "%s's document is not a literal jsonencode, heredoc or string (data sources and variables are not edited)", cur.block.address())
			}
			if h, err := igagov.DocumentHash(text); err != nil || h != f.Before {
				return nil, fallback(ReasonFormUnsupported, "%s's document in the source differs from the one in AWS", cur.block.address())
			}
			doc, err := req.doc(f.After)
			if err != nil {
				return nil, err
			}
			var expr string
			if form == docHeredoc {
				expr, err = heredocExpr(doc, pa.Raw)
			} else {
				expr, err = jsonencodeExpr(doc, lineIndent(s.files[cur.block.File], pa.ValStart))
			}
			if err != nil {
				return nil, err
			}
			s.edit(cur.block.File, edit{pa.ValStart, pa.ValEnd, expr})
			s.sum = append(s.sum, "replace the document of "+cur.block.address())
		}
	}
	for arn, tags := range pf.tagUpdates {
		cur, ok := pols[arn]
		if !ok {
			continue
		}
		merged := map[string]string{}
		if ta := cur.block.attr("tags"); ta != nil {
			v, err := parseLiteral(ta.Raw)
			if err != nil {
				continue // computed tags: left as written (tags are not a classified fact)
			}
			if m, ok := v.(map[string]any); ok {
				for k, x := range m {
					if xs, ok := x.(string); ok {
						merged[k] = xs
					}
				}
			}
		}
		for k, v := range tags {
			merged[k] = v
		}
		s.setAttr(cur.block, "tags", tfTags(merged, lineIndent(s.files[cur.block.File], cur.block.Open)+"  "))
	}

	// The role's boundary.
	if pf.boundary != nil {
		before, after := pf.boundary.Before, pf.boundary.After
		if a := role.attr("permissions_boundary"); a != nil {
			got, ok := refPolicy(a.Raw, pols)
			if !ok {
				return nil, fallback(ReasonFormUnsupported, "%s.permissions_boundary is computed (%s)", role.address(), strings.TrimSpace(a.Raw))
			}
			if got != before {
				return nil, fallback(ReasonFormUnsupported, "%s.permissions_boundary in the source is %s, AWS has %s", role.address(), got, before)
			}
		} else if before != igagov.ValueNone {
			return nil, fallback(ReasonFormUnsupported, "%s sets no permissions_boundary but AWS has %s", role.address(), before)
		}
		if before != after {
			if after == igagov.ValueNone {
				s.removeAttr(role, "permissions_boundary")
				s.sum = append(s.sum, "remove permissions_boundary from "+role.address())
			} else {
				expr := strconv.Quote(after)
				if addr, ok := added[after]; ok {
					expr = addr + ".arn"
				} else if p, ok := pols[after]; ok {
					expr = p.block.address() + ".arn"
				}
				s.setAttr(role, "permissions_boundary", expr)
				s.sum = append(s.sum, "set "+role.address()+".permissions_boundary = "+expr)
			}
		}
	}
	return s.result(role.File + ": " + role.address())
}

/* ------------------------- Terraform: dedicated identity ------------------- */

// refersTo reports whether an expression references the role block (any
// attribute) or names the role's ARN / name literally.
func refersTo(raw string, role *tfBlock, arn, name string) bool {
	raw = strings.TrimSpace(raw)
	if role != nil && strings.HasPrefix(raw, role.address()+".") {
		return true
	}
	v, ok := literalString(raw)
	return ok && (v == arn || v == name)
}

func (s *tfSource) renderSplit() (*Change, error) {
	req := s.req
	d := req.Plan.Diff.Split
	if d == nil {
		return nil, fmt.Errorf("iacpr: split plan without split detail")
	}
	pf := readPlan(req.Plan, req.DeploymentID)
	srcName, newName := roleNameOf(d.SourceRoleARN), roleNameOf(d.NewRoleARN)
	src, err := s.locateRole(srcName)
	if err != nil {
		return nil, err
	}
	newTF := tfName(newName)
	if req.Plan.Kind == igagov.PlanSplit {
		if pf.createRole == nil {
			return nil, fmt.Errorf("iacpr: split plan without CreateRole")
		}
		var nr *tfBlock
		for _, b := range s.resources("aws_iam_role") {
			if a := b.attr("name"); a != nil {
				if v, ok := literalString(a.Raw); ok && v == newName {
					nr = b
				}
			}
		}
		if nr != nil {
			return nil, fallback(ReasonFormUnsupported, "%s already declares role %s", nr.address(), newName)
		}
		// Everything the new role is made of comes from the APPROVED plan and
		// its archived documents (§11; review P1-12): the source is read only
		// to locate things and to check it still says what was approved. A
		// source that differs is never rendered (iac_source_differs; at
		// deploy time the deployment is blocked as iac_form_changed).
		trustDoc, err := req.archived(pf.createRole.TrustPolicyHash, "the trust policy")
		if err != nil {
			return nil, err
		}
		trust := src.attr("assume_role_policy")
		if trust == nil {
			return nil, fallback(ReasonFormUnsupported, "%s has no assume_role_policy", src.address())
		}
		if text, _, err := policyDocument(trust.Raw); err == nil {
			if h, err := igagov.DocumentHash(text); err != nil || h != pf.createRole.TrustPolicyHash {
				return nil, fallback(ReasonSourceDiffers, "the trust policy of %s in the source differs from the approved one (%s)",
					src.address(), pf.createRole.TrustPolicyHash)
			}
		}
		pols := s.policies()
		boundaryExpr := ""
		pb := src.attr("permissions_boundary")
		switch {
		case pf.newBoundary == "" && pb != nil:
			return nil, fallback(ReasonSourceDiffers, "%s sets a permissions_boundary; the approved role has none", src.address())
		case pf.newBoundary != "" && pb == nil:
			return nil, fallback(ReasonSourceDiffers, "%s sets no permissions_boundary; the approved role has %s", src.address(), pf.newBoundary)
		case pb != nil:
			if got, ok := refPolicy(pb.Raw, pols); ok {
				if got != pf.newBoundary {
					return nil, fallback(ReasonSourceDiffers, "%s.permissions_boundary is %s in the source; the approved boundary is %s",
						src.address(), got, pf.newBoundary)
				}
				boundaryExpr = strings.TrimSpace(pb.Raw)
			} else {
				boundaryExpr = strconv.Quote(pf.newBoundary)
			}
		}
		// The source's inline policies must be exactly the approved ones.
		srcInline := map[string]string{} // name -> literal document ("" = not literal)
		for _, ib := range src.nested("inline_policy") {
			na := ib.attr("name")
			nm := ""
			if na != nil {
				nm, _ = literalString(na.Raw)
			}
			if nm == "" {
				return nil, fallback(ReasonFormUnsupported, "an inline_policy of %s has a computed name", src.address())
			}
			srcInline[nm] = ""
			if pa := ib.attr("policy"); pa != nil {
				if text, _, err := policyDocument(pa.Raw); err == nil {
					srcInline[nm] = text
				}
			}
		}
		for _, rp := range s.resources("aws_iam_role_policy") {
			ra := rp.attr("role")
			if ra == nil || !refersTo(ra.Raw, src, d.SourceRoleARN, srcName) {
				continue
			}
			nm := ""
			if na := rp.attr("name"); na != nil {
				nm, _ = literalString(na.Raw)
			}
			if nm == "" {
				return nil, fallback(ReasonFormUnsupported, "%s has a computed name", rp.address())
			}
			srcInline[nm] = ""
			if pa := rp.attr("policy"); pa != nil {
				if text, _, err := policyDocument(pa.Raw); err == nil {
					srcInline[nm] = text
				}
			}
		}
		approved := map[string]string{} // name -> hash
		for _, op := range req.Plan.Ops {
			if op.Op == igagov.OpPutRolePolicy {
				approved[op.InlineName] = op.DocumentHash
			}
		}
		for nm := range srcInline {
			if _, ok := approved[nm]; !ok {
				return nil, fallback(ReasonSourceDiffers, "inline policy %s of %s is in the source but not in the approved role", nm, srcName)
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "# Dedicated identity for %s, split from %s by AuthSec: the same identity policies\n",
			strings.Join(d.Subjects(), ", "), srcName)
		b.WriteString("# (trust policy, managed policies by ARN, inline policy copies and permissions boundary)\n")
		fmt.Fprintf(&b, "# as approved in plan %s. Access granted to %s by name elsewhere does not follow.\n", req.Plan.PlanHash, srcName)
		fmt.Fprintf(&b, "resource \"aws_iam_role\" %q {\n", newTF)
		fmt.Fprintf(&b, "  name = %s\n", strconv.Quote(newName))
		fmt.Fprintf(&b, "  path = %s\n", strconv.Quote(pf.createRole.Path))
		te, err := jsonencodeExpr(trustDoc, "  ")
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "  assume_role_policy = %s\n", te)
		if boundaryExpr != "" {
			fmt.Fprintf(&b, "  permissions_boundary = %s\n", boundaryExpr)
		}
		if len(pf.createRole.Tags) > 0 {
			fmt.Fprintf(&b, "  tags = %s\n", tfTags(pf.createRole.Tags, "  "))
		}
		names := make([]string, 0, len(approved))
		for nm := range approved {
			names = append(names, nm)
		}
		sort.Strings(names)
		for _, nm := range names {
			doc, err := req.archived(approved[nm], "inline policy "+nm)
			if err != nil {
				return nil, err
			}
			cur, ok := srcInline[nm]
			if !ok {
				return nil, fallback(ReasonSourceDiffers, "inline policy %s of %s is not declared in %s", nm, srcName, req.Source.Directory)
			}
			if cur != "" {
				if h, err := igagov.DocumentHash(cur); err != nil || h != approved[nm] {
					return nil, fallback(ReasonSourceDiffers, "inline policy %s of %s in the source differs from the approved one", nm, srcName)
				}
			}
			ie, err := jsonencodeExpr(doc, "    ")
			if err != nil {
				return nil, err
			}
			fmt.Fprintf(&b, "  inline_policy {\n    name   = %s\n    policy = %s\n  }\n", strconv.Quote(nm), ie)
		}
		b.WriteString("}\n")
		var extra []string
		for i, arn := range pf.attach {
			extra = append(extra, fmt.Sprintf("resource \"aws_iam_role_policy_attachment\" %q {\n  role       = aws_iam_role.%s.name\n  policy_arn = %s\n}\n",
				fmt.Sprintf("%s_%d", newTF, i+1), newTF, strconv.Quote(arn)))
		}
		s.appendTo(src.File, b.String())
		for _, e := range extra {
			s.appendTo(src.File, e)
		}
		s.sum = append(s.sum, "add aws_iam_role."+newTF+" with "+strconv.Itoa(len(pf.attach))+" managed policies by ARN and "+
			strconv.Itoa(len(approved))+" inline policy copies, from the approved documents")
		if err := s.moveBinding(d, src, nil, srcName, newName, newTF); err != nil {
			return nil, err
		}
		return s.result(src.File + ": " + src.address() + " -> aws_iam_role." + newTF)
	}

	// split_revert: the binding back to the source role, the added resources
	// removed (unless the new role has other consumers now).
	var nr *tfBlock
	for _, b := range s.resources("aws_iam_role") {
		if a := b.attr("name"); a != nil {
			if v, ok := literalString(a.Raw); ok && v == newName {
				nr = b
			}
		}
	}
	if nr == nil {
		return nil, fallback(ReasonRoleNotFound, "the dedicated role %s is not declared in %s", newName, req.Source.Directory)
	}
	if err := s.moveBinding(d, nr, src, newName, srcName, ""); err != nil {
		return nil, err
	}
	if !req.KeepNewRole {
		s.removeBlock(nr)
		for _, typ := range []string{"aws_iam_role_policy_attachment", "aws_iam_role_policy", "aws_iam_instance_profile"} {
			for _, b := range s.resources(typ) {
				if ra := b.attr("role"); ra != nil && refersTo(ra.Raw, nr, d.NewRoleARN, newName) {
					s.removeBlock(b)
				}
			}
		}
		s.sum = append(s.sum, "remove "+nr.address()+" and the resources added for it")
	} else {
		s.sum = append(s.sum, "keep "+nr.address()+": other workloads run as it now")
	}
	return s.result(nr.File + ": " + nr.address() + " -> " + src.address())
}

// moveBinding re-points the subject's binding from role `from` to the role
// `to` (a block, or the new role's resource name toTF when it is added in
// this change).
func (s *tfSource) moveBinding(d *igagov.SplitDetail, from, to *tfBlock, fromName, toName, toTF string) error {
	fromARN := d.SourceRoleARN
	if to != nil {
		fromARN = d.NewRoleARN
	}
	roleRef := func(attr string) string {
		if to != nil {
			return to.address() + "." + attr
		}
		return "aws_iam_role." + toTF + "." + attr
	}
	subject := d.SubjectARN
	last := subject[strings.LastIndexAny(subject, "/:")+1:]
	switch d.SubjectKind {
	case igagov.SubjectECSService:
		// §11: every ECS service running a source-role revision of the family
		// is a subject; the task definition's task_role_arn changes (a new
		// revision) and each service moves to it. A task definition shared
		// with a service that is not a subject would move that service too.
		subjects := map[string]bool{}
		for _, a := range d.Subjects() {
			subjects[a[strings.LastIndexAny(a, "/:")+1:]] = true
		}
		svcName := func(b *tfBlock) string {
			if a := b.attr("name"); a != nil {
				v, _ := literalString(a.Raw)
				return v
			}
			return ""
		}
		tds := map[string]*tfBlock{}
		var order []string
		for _, name := range sortedSet(subjects) {
			var svc *tfBlock
			for _, b := range s.resources("aws_ecs_service") {
				if svcName(b) == name {
					svc = b
				}
			}
			if svc == nil {
				return fallback(ReasonRoleNotFound, "ECS service %s is not declared in %s", name, s.req.Source.Directory)
			}
			ta := svc.attr("task_definition")
			if ta == nil {
				return fallback(ReasonFormUnsupported, "%s has no task_definition", svc.address())
			}
			var td *tfBlock
			for _, b := range s.resources("aws_ecs_task_definition") {
				if strings.HasPrefix(strings.TrimSpace(ta.Raw), b.address()+".") {
					td = b
				}
			}
			if td == nil {
				return fallback(ReasonFormUnsupported, "%s.task_definition is not a task definition declared in the source", svc.address())
			}
			if _, ok := tds[td.address()]; !ok {
				order = append(order, td.address())
			}
			tds[td.address()] = td
		}
		for _, b := range s.resources("aws_ecs_service") {
			if subjects[svcName(b)] {
				continue
			}
			if a := b.attr("task_definition"); a != nil {
				for _, td := range tds {
					if strings.HasPrefix(strings.TrimSpace(a.Raw), td.address()+".") {
						return fallback(ReasonFormUnsupported, "%s is also used by %s, which is not a subject of this change", td.address(), b.address())
					}
				}
			}
		}
		for _, addr := range order {
			td := tds[addr]
			ra := td.attr("task_role_arn")
			if ra == nil || !refersTo(ra.Raw, from, fromARN, fromName) {
				return fallback(ReasonFormUnsupported, "%s.task_role_arn does not name %s", td.address(), fromName)
			}
			s.edit(td.File, edit{ra.ValStart, ra.ValEnd, roleRef("arn")})
			s.sum = append(s.sum, "set "+td.address()+".task_role_arn to "+toName+" (a new task-definition revision; services "+
				strings.Join(sortedSet(subjects), ", ")+" move to it)")
		}
	case igagov.SubjectLambdaFunction:
		var fn *tfBlock
		for _, b := range s.resources("aws_lambda_function") {
			if a := b.attr("function_name"); a != nil {
				if v, ok := literalString(a.Raw); ok && v == last {
					fn = b
				}
			}
		}
		if fn == nil {
			return fallback(ReasonRoleNotFound, "Lambda function %s is not declared in %s", last, s.req.Source.Directory)
		}
		ra := fn.attr("role")
		if ra == nil || !refersTo(ra.Raw, from, fromARN, fromName) {
			return fallback(ReasonFormUnsupported, "%s.role does not name %s", fn.address(), fromName)
		}
		for _, al := range s.resources("aws_lambda_alias") {
			fa := al.attr("function_name")
			if fa == nil || !strings.HasPrefix(strings.TrimSpace(fa.Raw), fn.address()+".") {
				continue
			}
			va := al.attr("function_version")
			if va == nil || strings.TrimSpace(va.Raw) != fn.address()+".version" {
				return fallback(ReasonFormUnsupported, "%s pins a version; it would not move to the new version", al.address())
			}
		}
		s.edit(fn.File, edit{ra.ValStart, ra.ValEnd, roleRef("arn")})
		if pa := fn.attr("publish"); pa == nil || strings.TrimSpace(pa.Raw) != "true" {
			s.setAttr(fn, "publish", "true")
		}
		s.sum = append(s.sum, "set "+fn.address()+".role to "+toName+", publish a new version; its aliases move to it")
	case igagov.SubjectEC2ASG:
		var asg *tfBlock
		for _, b := range s.resources("aws_autoscaling_group") {
			if a := b.attr("name"); a != nil {
				if v, ok := literalString(a.Raw); ok && v == last {
					asg = b
				}
			}
		}
		if asg == nil {
			return fallback(ReasonRoleNotFound, "Auto Scaling group %s is not declared in %s", last, s.req.Source.Directory)
		}
		var ltRef string
		for _, n := range asg.nested("launch_template") {
			for _, k := range []string{"id", "name"} {
				if a := n.attr(k); a != nil {
					ltRef = strings.TrimSpace(a.Raw)
				}
			}
		}
		var lt *tfBlock
		for _, b := range s.resources("aws_launch_template") {
			if strings.HasPrefix(ltRef, b.address()+".") {
				lt = b
			}
		}
		if lt == nil {
			return fallback(ReasonFormUnsupported, "%s does not use a launch template declared in the source", asg.address())
		}
		for _, b := range s.resources("aws_autoscaling_group") {
			if b == asg {
				continue
			}
			for _, n := range b.nested("launch_template") {
				for _, k := range []string{"id", "name"} {
					if a := n.attr(k); a != nil && strings.HasPrefix(strings.TrimSpace(a.Raw), lt.address()+".") {
						return fallback(ReasonFormUnsupported, "%s is also used by %s", lt.address(), b.address())
					}
				}
			}
		}
		var ip *tfBlock
		for _, n := range lt.nested("iam_instance_profile") {
			ip = n
		}
		if ip == nil {
			return fallback(ReasonFormUnsupported, "%s has no iam_instance_profile", lt.address())
		}
		var profAttr *tfAttr
		var kind string
		for _, k := range []string{"name", "arn"} {
			if a := ip.attr(k); a != nil {
				profAttr, kind = a, k
			}
		}
		var prof *tfBlock
		for _, b := range s.resources("aws_iam_instance_profile") {
			if profAttr != nil && strings.HasPrefix(strings.TrimSpace(profAttr.Raw), b.address()+".") {
				prof = b
			}
		}
		if prof == nil {
			return fallback(ReasonFormUnsupported, "%s's instance profile is not declared in the source", lt.address())
		}
		if to == nil { // split: a new profile for the new role
			if pr := prof.attr("role"); pr == nil || !refersTo(pr.Raw, from, fromARN, fromName) {
				return fallback(ReasonFormUnsupported, "%s does not hold %s", prof.address(), fromName)
			}
			s.appendTo(lt.File, fmt.Sprintf("resource \"aws_iam_instance_profile\" %q {\n  name = %s\n  role = aws_iam_role.%s.name\n}\n",
				toTF, strconv.Quote(toName), toTF))
			s.edit(lt.File, edit{profAttr.ValStart, profAttr.ValEnd, "aws_iam_instance_profile." + toTF + "." + kind})
		} else { // revert: back to the source role's profile
			var srcProf *tfBlock
			for _, b := range s.resources("aws_iam_instance_profile") {
				if pr := b.attr("role"); pr != nil && refersTo(pr.Raw, to, d.SourceRoleARN, toName) {
					srcProf = b
				}
			}
			if srcProf == nil {
				return fallback(ReasonFormUnsupported, "no instance profile of %s is declared in the source", toName)
			}
			s.edit(lt.File, edit{profAttr.ValStart, profAttr.ValEnd, srcProf.address() + "." + kind})
		}
		if len(asg.nested("instance_refresh")) == 0 {
			ls := strings.LastIndexByte(s.files[asg.File][:asg.Close], '\n') + 1
			ind := lineIndent(s.files[asg.File], asg.Close) + "  "
			s.edit(asg.File, edit{ls, ls, ind + "instance_refresh {\n" + ind + "  strategy = \"Rolling\"\n" + ind + "}\n"})
		}
		s.sum = append(s.sum, "move "+lt.address()+" to the instance profile of "+toName+" and refresh "+asg.address()+"'s instances")
	default:
		return fallback(ReasonFormUnsupported, "a %s subject cannot be located in source by its id", d.SubjectKind)
	}
	return nil
}

/* ----------------------------- CloudFormation ------------------------------ */

func renderCFN(req Request) (*Change, error) {
	ts, err := loadCFN(req)
	if err != nil {
		return nil, err
	}
	if req.Plan.Kind == igagov.PlanSplit || req.Plan.Kind == igagov.PlanSplitRevert {
		return renderCFNSplit(req, ts)
	}
	t, hr, err := locateCFNRole(req, ts, req.Role.Name)
	if err != nil {
		return nil, err
	}
	h := struct {
		t *cfnTemplate
		r cfnResource
	}{t, hr}
	pf := readPlan(req.Plan, req.DeploymentID)
	pols := map[string]cfnResource{}
	for _, r := range t.resources() {
		if r.Type != "AWS::IAM::ManagedPolicy" {
			continue
		}
		n, ok := cfnScalar(mapGet(r.Props, "ManagedPolicyName"))
		if !ok {
			continue
		}
		p := "/"
		if pn := mapGet(r.Props, "Path"); pn != nil {
			if p, ok = cfnScalar(pn); !ok {
				continue
			}
		}
		pols["arn:"+req.Role.partition()+":iam::"+req.Role.AccountID+":policy"+p+n] = r
	}
	var sum []string
	added := map[string]string{}
	for _, f := range pf.docs {
		if !f.Changes() {
			continue
		}
		pname, ppath := policyNamePath(f.Subject)
		cur, inSource := pols[f.Subject]
		switch {
		case f.Before == igagov.ValueAbsent:
			if len(pf.createTags[f.Subject]) > 0 {
				// DECISION (T3.17): AWS::IAM::ManagedPolicy takes no Tags,
				// so a new AuthSec-owned boundary (recognised by its tags,
				// §3.2) cannot be declared in CloudFormation.
				return nil, fallback(ReasonFormUnsupported, "AWS::IAM::ManagedPolicy cannot carry the AuthSec tags %s needs", f.Subject)
			}
			if inSource {
				return nil, fallback(ReasonFormUnsupported, "%s already declares %s", cur.LogicalID, f.Subject)
			}
			doc, err := req.doc(f.After)
			if err != nil {
				return nil, err
			}
			dn, err := cfnDocumentNode(doc)
			if err != nil {
				return nil, err
			}
			id := cfnLogicalID(pname)
			props := &yaml.Node{Kind: yaml.MappingNode}
			mapSet(props, "ManagedPolicyName", strNode(pname))
			mapSet(props, "Path", strNode(ppath))
			mapSet(props, "PolicyDocument", dn)
			res := &yaml.Node{Kind: yaml.MappingNode}
			mapSet(res, "Type", strNode("AWS::IAM::ManagedPolicy"))
			mapSet(res, "Properties", props)
			mapSet(t.Resources, id, res)
			added[f.Subject] = id
			sum = append(sum, "add "+id+" ("+f.Subject+")")
		case f.After == igagov.ValueAbsent:
			if !inSource {
				return nil, fallback(ReasonFormUnsupported, "policy %s is not declared in %s", f.Subject, t.Path)
			}
			mapDelete(t.Resources, cur.LogicalID)
			sum = append(sum, "remove "+cur.LogicalID)
		default:
			if !inSource {
				return nil, fallback(ReasonFormUnsupported, "policy %s is not declared in %s", f.Subject, t.Path)
			}
			dn := mapGet(cur.Props, "PolicyDocument")
			v, err := func() (any, error) {
				if dn == nil {
					return nil, errNotLiteral
				}
				return cfnLiteral(dn)
			}()
			if err != nil {
				return nil, fallback(ReasonFormUnsupported, "%s.PolicyDocument is not literal", cur.LogicalID)
			}
			raw, _ := json.Marshal(v)
			if hh, err := igagov.DocumentHash(string(raw)); err != nil || hh != f.Before {
				return nil, fallback(ReasonFormUnsupported, "%s's document in the source differs from the one in AWS", cur.LogicalID)
			}
			doc, err := req.doc(f.After)
			if err != nil {
				return nil, err
			}
			nn, err := cfnDocumentNode(doc)
			if err != nil {
				return nil, err
			}
			mapSet(cur.Props, "PolicyDocument", nn)
			sum = append(sum, "replace "+cur.LogicalID+".PolicyDocument")
		}
	}
	if pf.boundary != nil {
		before, after := pf.boundary.Before, pf.boundary.After
		pb := mapGet(h.r.Props, "PermissionsBoundary")
		got := igagov.ValueNone
		if pb != nil {
			if v, ok := cfnScalar(pb); ok {
				got = v
			} else if id, ok := cfnRefTarget(pb); ok {
				got = ""
				for arn, r := range pols {
					if r.LogicalID == id {
						got = arn
					}
				}
				if got == "" {
					return nil, fallback(ReasonFormUnsupported, "%s.PermissionsBoundary references %s, which is not a ManagedPolicy with a literal name", h.r.LogicalID, id)
				}
			} else {
				return nil, fallback(ReasonFormUnsupported, "%s.PermissionsBoundary is computed", h.r.LogicalID)
			}
		}
		if got != before {
			return nil, fallback(ReasonFormUnsupported, "%s.PermissionsBoundary in the source is %s, AWS has %s", h.r.LogicalID, got, before)
		}
		if before != after {
			if after == igagov.ValueNone {
				mapDelete(h.r.Props, "PermissionsBoundary")
				sum = append(sum, "remove "+h.r.LogicalID+".PermissionsBoundary")
			} else {
				var n *yaml.Node
				if id, ok := added[after]; ok {
					n = cfnRefNode(id, t.JSON)
				} else if r, ok := pols[after]; ok {
					n = cfnRefNode(r.LogicalID, t.JSON)
				} else {
					n = strNode(after)
				}
				if h.r.Props == nil {
					return nil, fallback(ReasonFormUnsupported, "%s has no Properties", h.r.LogicalID)
				}
				mapSet(h.r.Props, "PermissionsBoundary", n)
				sum = append(sum, "set "+h.r.LogicalID+".PermissionsBoundary to "+after)
			}
		}
	}
	ch := &Change{Format: FormatCloudFormation, Location: t.Path + ": " + h.r.LogicalID, Files: []FileChange{}, Summary: sum}
	if len(sum) == 0 {
		return ch, nil
	}
	out, err := t.render()
	if err != nil {
		return nil, err
	}
	ch.Files = append(ch.Files, FileChange{Path: t.Path, Before: req.Files[t.Path], After: out})
	return ch, nil
}

// cfnLogicalID makes an alphanumeric logical id.
func cfnLogicalID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "AuthSecPolicy"
	}
	return b.String()
}
