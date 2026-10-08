package igagov

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// simAccount is a test-only model of the IAM objects R1a plans touch:
// roles with a boundary, managed policies with a default document, a version
// count, tags and permissions-policy attachments. It executes plan ops the
// way §8.5 describes AWS answering them, so compiled plans can be applied,
// undone and classified end to end without AWS.

type simPolicy struct {
	arn, path, name string
	tags            map[string]string
	doc             string // default version's document text
	versions        int
	permUsers       []AttachedEntity // permissions-policy attachments
}

type simAccount struct {
	part, acct string
	roles      map[string]*LiveRole // by RoleId
	policies   map[string]*simPolicy
}

func newSim() *simAccount {
	return &simAccount{part: "aws", acct: acct, roles: map[string]*LiveRole{}, policies: map[string]*simPolicy{}}
}

func (s *simAccount) addRole(r LiveRole) *LiveRole {
	rr := r
	if rr.Tags == nil {
		rr.Tags = map[string]string{}
	}
	s.roles[rr.RoleID] = &rr
	return &rr
}

func (s *simAccount) addPolicy(arn, doc string, tags map[string]string, versions int) *simPolicy {
	i := strings.Index(arn, ":policy")
	rest := arn[i+len(":policy"):]
	j := strings.LastIndex(rest, "/")
	p := &simPolicy{arn: arn, path: rest[:j+1], name: rest[j+1:], tags: map[string]string{}, doc: doc, versions: versions}
	for k, v := range tags {
		p.tags[k] = v
	}
	s.policies[arn] = p
	return p
}

func (s *simAccount) attachments(arn string) []AttachedEntity {
	var out []AttachedEntity
	for _, r := range s.roles {
		if r.BoundaryARN == arn {
			out = append(out, AttachedEntity{Kind: "role", ID: r.RoleID, Name: r.Name, Usage: UsageBoundary})
		}
	}
	if p := s.policies[arn]; p != nil {
		out = append(out, p.permUsers...)
	}
	return ArtifactStateFacts{RoleID: "x", AttachmentSet: out}.Normalized().AttachmentSet
}

// read is a discovery-role read of a role: the role, every policy in the
// account, and the extra ARNs (absent ones as NoSuchEntity).
func (s *simAccount) read(roleID string, extra ...string) LiveRead {
	lr := LiveRead{ReadAt: readAt, Policies: map[string]*LivePolicy{}}
	if r, ok := s.roles[roleID]; ok {
		cp := *r
		cp.Tags = map[string]string{}
		for k, v := range r.Tags {
			cp.Tags[k] = v
		}
		lr.Role = &cp
	}
	for arn, p := range s.policies {
		tags := map[string]string{}
		for k, v := range p.tags {
			tags[k] = v
		}
		lr.Policies[arn] = &LivePolicy{ARN: arn, Path: p.path, Name: p.name, Tags: tags, DefaultDocument: p.doc,
			VersionCount: p.versions, AttachmentSet: s.attachments(arn)}
	}
	for _, a := range extra {
		if _, ok := lr.Policies[a]; !ok {
			lr.Policies[a] = nil
		}
	}
	return lr
}

// readFor reads everything a plan's facts name.
func (s *simAccount) readFor(roleID string, p Plan) LiveRead {
	return s.read(roleID, p.PoliciesToRead()...)
}

// exec runs one op as AWS would, returning the AWS error code ("" = ok).
func (s *simAccount) exec(roleID string, op Op, docs map[string]string) string {
	role := s.roles[roleID]
	switch op.Op {
	case OpCreatePolicy:
		if _, ok := s.policies[op.PolicyARN]; ok {
			return "EntityAlreadyExists"
		}
		doc, ok := docs[op.DocumentHash]
		if !ok {
			panic("sim: no document " + op.DocumentHash)
		}
		tags := map[string]string{}
		for k, v := range op.Tags {
			tags[k] = strings.ReplaceAll(v, DeploymentPlaceholder, "dep-1")
		}
		s.addPolicy(op.PolicyARN, doc, tags, 1)
	case OpCreatePolicyVersion:
		p := s.policies[op.PolicyARN]
		if p == nil {
			return "NoSuchEntity"
		}
		if p.versions >= MaxPolicyVersions {
			return "LimitExceeded"
		}
		doc, ok := docs[op.DocumentHash]
		if !ok {
			panic("sim: no document " + op.DocumentHash)
		}
		p.doc, p.versions = doc, p.versions+1
	case OpDeletePolicyVersion:
		p := s.policies[op.PolicyARN]
		if p == nil {
			return "NoSuchEntity"
		}
		switch op.Select {
		case SelectAllNonDefault:
			p.versions = 1
		case SelectOldestNonDefault:
			if p.versions >= op.IfVersionsAtLeast && p.versions > 1 {
				p.versions--
			}
		}
	case OpTagPolicy:
		p := s.policies[op.PolicyARN]
		if p == nil {
			return "NoSuchEntity"
		}
		for k, v := range op.Tags {
			p.tags[k] = strings.ReplaceAll(v, DeploymentPlaceholder, "dep-1")
		}
	case OpDeletePolicy:
		p := s.policies[op.PolicyARN]
		if p == nil {
			return "NoSuchEntity"
		}
		if len(s.attachments(op.PolicyARN)) > 0 || p.versions > 1 {
			return "DeleteConflict"
		}
		delete(s.policies, op.PolicyARN)
	case OpPutRolePermissionsBoundary:
		if role == nil {
			return "NoSuchEntity"
		}
		if s.policies[op.PolicyARN] == nil {
			return "NoSuchEntity"
		}
		role.BoundaryARN = op.PolicyARN
	case OpDeleteRolePermissionsBoundary:
		if role == nil {
			return "NoSuchEntity"
		}
		role.BoundaryARN = ""
	default:
		panic("sim: op " + op.Op)
	}
	return ""
}

func planDocs(ps ...Plan) map[string]string {
	out := map[string]string{}
	for _, p := range ps {
		for _, d := range p.Documents {
			out[d.Hash] = d.Canonical
		}
	}
	return out
}

// run executes ops[from:to) and fails the test on any AWS error.
func (s *simAccount) run(t testing.TB, roleID string, p Plan, from, to int, docs map[string]string) {
	t.Helper()
	for i := from; i < to; i++ {
		if code := s.exec(roleID, p.Ops[i], docs); code != "" {
			t.Fatalf("op %d %s: %s", i, p.Ops[i].Op, code)
		}
	}
}

// snapshot is a comparable view of every policy and role boundary.
func (s *simAccount) snapshot() string {
	var parts []string
	for _, r := range s.roles {
		parts = append(parts, "role "+r.RoleID+" -> "+r.BoundaryARN)
	}
	for arn, p := range s.policies {
		h, _ := DocumentHash(p.doc)
		parts = append(parts, fmt.Sprintf("policy %s %s users=%s", arn, h, usersValue(s.attachments(arn))))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

var readAt = time.Date(2026, 10, 1, 13, 0, 0, 0, time.UTC)
