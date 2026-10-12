package awsenforce

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/igagov"
)

// Discovery-role reads (SPEC-iga-phase3-policy.md §3.5: "Live preconditions
// ... Readback after a write, drift checks — Discovery role"). The
// enforcement role can read nothing; every read the executor makes —
// precondition, the check before each op, the recognition after an error
// answer, version-selector resolution and readback — goes through
// DiscoveryIAM, built from the connector's discovery session.

// DiscoveryIAM is the read slice of IAM the discovery role has (SecurityAudit
// covers it). A missing entity is an error with code NoSuchEntity
// (IsNoSuchEntity). The live implementation is NewLiveDiscoveryIAM; tests use
// enforcetest.FakeAWS.Discovery.
type DiscoveryIAM interface {
	GetRole(ctx context.Context, roleName string) (*RoleInfo, error)
	ListAttachedRolePolicies(ctx context.Context, roleName string) ([]string, error)
	ListRolePolicies(ctx context.Context, roleName string) ([]string, error)
	GetRolePolicy(ctx context.Context, roleName, policyName string) (string, error)
	GetPolicy(ctx context.Context, policyARN string) (*PolicyInfo, error)
	GetPolicyVersion(ctx context.Context, policyARN, versionID string) (string, error)
	ListPolicyVersions(ctx context.Context, policyARN string) ([]PolicyVersionInfo, error)
	// ListEntitiesForPolicy returns every entity using the policy, with
	// every usage type (permissions policy and permissions boundary).
	ListEntitiesForPolicy(ctx context.Context, policyARN string) ([]igagov.AttachedEntity, error)
}

// RoleInfo is GetRole's answer.
type RoleInfo struct {
	RoleID string
	ARN    string
	Name   string
	Path   string
	Tags   map[string]string
	// BoundaryARN is the role's permissions boundary ("" = none).
	BoundaryARN string
	// TrustDocument is the assume-role policy as AWS returns it.
	TrustDocument string
}

// PolicyInfo is GetPolicy's answer.
type PolicyInfo struct {
	ARN              string
	Path             string
	Name             string
	Tags             map[string]string
	DefaultVersionID string
}

// PolicyVersionInfo is one entry of ListPolicyVersions.
type PolicyVersionInfo struct {
	VersionID  string
	IsDefault  bool
	CreateDate time.Time
}

// IsNoSuchEntity reports an AWS NoSuchEntity answer.
func IsNoSuchEntity(err error) bool { return ErrorCode(err) == "NoSuchEntity" }

// ReadDetail is what a read saw beyond igagov.LiveRead: each policy's
// default version id (for the ledger's aws_version_id).
type ReadDetail struct {
	DefaultVersion map[string]string
}

// PolicyARNsFor lists every policy a plan's classification and recovery need
// read: the policies of its facts (Plan.PoliciesToRead), its desired and
// replaced boundaries, every policy an op names, and the role's current
// boundary when known.
func PolicyARNsFor(p igagov.Plan, roleBoundary string) []string {
	set := map[string]bool{}
	for _, a := range p.PoliciesToRead() {
		set[a] = true
	}
	for _, a := range []*string{p.DesiredBoundaryARN, p.ReplacedBoundaryARN} {
		if a != nil && *a != "" {
			set[*a] = true
		}
	}
	for _, op := range p.Ops {
		if op.PolicyARN != "" {
			set[op.PolicyARN] = true
		}
	}
	if roleBoundary != "" {
		set[roleBoundary] = true
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// ReadForPlan is one discovery-role read for a plan of the role named
// roleName (§3.5, §8.5): GetRole (RoleId continuity, path, tags, boundary,
// trust policy), its attached and inline policies with canonical document
// hashes, and every policy PolicyARNsFor names plus the role's live boundary.
// A role that returns NoSuchEntity is LiveRead.Role == nil (the classifier
// reports role_gone); a policy that returns NoSuchEntity is a nil entry.
func ReadForPlan(ctx context.Context, r DiscoveryIAM, roleName string, p igagov.Plan, now time.Time) (igagov.LiveRead, ReadDetail, error) {
	live := igagov.LiveRead{ReadAt: now.UTC(), Policies: map[string]*igagov.LivePolicy{}}
	detail := ReadDetail{DefaultVersion: map[string]string{}}
	role, err := ReadRole(ctx, r, roleName)
	if err != nil {
		return igagov.LiveRead{}, ReadDetail{}, err
	}
	live.Role = role
	boundary := ""
	if role != nil {
		boundary = role.BoundaryARN
	}
	for _, arn := range PolicyARNsFor(p, boundary) {
		lp, ver, err := ReadPolicy(ctx, r, arn)
		if err != nil {
			return igagov.LiveRead{}, ReadDetail{}, err
		}
		live.Policies[arn] = lp
		if lp != nil {
			detail.DefaultVersion[arn] = ver
		}
	}
	return live, detail, nil
}

// ReadRole reads a role with its own permission policies; nil when the role
// returns NoSuchEntity.
func ReadRole(ctx context.Context, r DiscoveryIAM, roleName string) (*igagov.LiveRole, error) {
	info, err := r.GetRole(ctx, roleName)
	if IsNoSuchEntity(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetRole %s: %w", roleName, err)
	}
	acct, part := arnAccount(info.ARN)
	role := &igagov.LiveRole{RoleID: info.RoleID, ARN: info.ARN, Name: info.Name, Path: info.Path, AccountID: acct,
		Partition: part, Tags: copyTags(info.Tags), BoundaryARN: info.BoundaryARN,
		ManagedPolicies: []igagov.PolicyRef{}, InlinePolicies: []igagov.PolicyRef{}, Documents: map[string]string{}}
	if info.TrustDocument != "" {
		if c, h, err := igagov.CanonicalDocument(info.TrustDocument); err == nil {
			role.TrustPolicyHash = h
			role.Documents[h] = string(c)
		}
	}
	attached, err := r.ListAttachedRolePolicies(ctx, roleName)
	if err != nil {
		return nil, fmt.Errorf("ListAttachedRolePolicies %s: %w", roleName, err)
	}
	for _, arn := range attached {
		pi, err := r.GetPolicy(ctx, arn)
		if err != nil {
			return nil, fmt.Errorf("GetPolicy %s: %w", arn, err)
		}
		doc, err := r.GetPolicyVersion(ctx, arn, pi.DefaultVersionID)
		if err != nil {
			return nil, fmt.Errorf("GetPolicyVersion %s %s: %w", arn, pi.DefaultVersionID, err)
		}
		h, err := igagov.DocumentHash(doc)
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", arn, err)
		}
		role.ManagedPolicies = append(role.ManagedPolicies, igagov.PolicyRef{Ref: arn, DocumentHash: h})
	}
	names, err := r.ListRolePolicies(ctx, roleName)
	if err != nil {
		return nil, fmt.Errorf("ListRolePolicies %s: %w", roleName, err)
	}
	for _, n := range names {
		doc, err := r.GetRolePolicy(ctx, roleName, n)
		if err != nil {
			return nil, fmt.Errorf("GetRolePolicy %s %s: %w", roleName, n, err)
		}
		c, h, err := igagov.CanonicalDocument(doc)
		if err != nil {
			return nil, fmt.Errorf("inline policy %s: %w", n, err)
		}
		role.Documents[h] = string(c)
		role.InlinePolicies = append(role.InlinePolicies, igagov.PolicyRef{Ref: n, DocumentHash: h})
	}
	return role, nil
}

// ReadPolicy reads one managed policy: GetPolicy (path, name, tags, default
// version), its default document, the number of versions, and its full
// attachment set. NoSuchEntity is (nil, "", nil).
func ReadPolicy(ctx context.Context, r DiscoveryIAM, arn string) (*igagov.LivePolicy, string, error) {
	pi, err := r.GetPolicy(ctx, arn)
	if IsNoSuchEntity(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("GetPolicy %s: %w", arn, err)
	}
	doc, err := r.GetPolicyVersion(ctx, arn, pi.DefaultVersionID)
	if IsNoSuchEntity(err) {
		return nil, "", nil // deleted between the two calls
	}
	if err != nil {
		return nil, "", fmt.Errorf("GetPolicyVersion %s %s: %w", arn, pi.DefaultVersionID, err)
	}
	versions, err := r.ListPolicyVersions(ctx, arn)
	if IsNoSuchEntity(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("ListPolicyVersions %s: %w", arn, err)
	}
	set, err := r.ListEntitiesForPolicy(ctx, arn)
	if IsNoSuchEntity(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("ListEntitiesForPolicy %s: %w", arn, err)
	}
	if set == nil {
		set = []igagov.AttachedEntity{}
	}
	return &igagov.LivePolicy{ARN: arn, Path: pi.Path, Name: pi.Name, Tags: copyTags(pi.Tags), DefaultDocument: doc,
		VersionCount: len(versions), AttachmentSet: set}, pi.DefaultVersionID, nil
}

// VersionToDelete is one version a DeletePolicyVersion selector chose, with
// its document as read (the executor archives it in iga_gov_document before
// the delete is prepared, §3.2 / §8.5).
type VersionToDelete struct {
	VersionID string
	Document  string
}

// ErrNotDeletable: the selector chose a version that is the default (the
// read changed under the selector) or the op is not a version delete.
var ErrNotDeletable = errors.New("awsenforce: version selector cannot be resolved")

// ResolveVersionSelector resolves a DeletePolicyVersion op of a plan against
// a FRESH read of the policy's versions (DECISION D46):
//
//	oldest_non_default  the oldest non-default version, only when the policy
//	                    has at least IfVersionsAtLeast versions (else none:
//	                    the prune is not needed, which also makes a re-sent
//	                    prune a no-op)
//	all_non_default     every non-default version, oldest first (before
//	                    DeletePolicy)
//
// A policy that returns NoSuchEntity has no versions to delete. Each chosen
// version's document is read so the caller can archive it first.
func ResolveVersionSelector(ctx context.Context, r DiscoveryIAM, op igagov.Op) ([]VersionToDelete, error) {
	if op.Op != igagov.OpDeletePolicyVersion {
		return nil, fmt.Errorf("%w: %s is not DeletePolicyVersion", ErrNotDeletable, op.Op)
	}
	versions, err := r.ListPolicyVersions(ctx, op.PolicyARN)
	if IsNoSuchEntity(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ListPolicyVersions %s: %w", op.PolicyARN, err)
	}
	var nonDefault []PolicyVersionInfo
	for _, v := range versions {
		if !v.IsDefault {
			nonDefault = append(nonDefault, v)
		}
	}
	sort.SliceStable(nonDefault, func(i, j int) bool {
		a, b := nonDefault[i], nonDefault[j]
		if !a.CreateDate.Equal(b.CreateDate) {
			return a.CreateDate.Before(b.CreateDate)
		}
		return versionNumber(a.VersionID) < versionNumber(b.VersionID)
	})
	var chosen []PolicyVersionInfo
	switch op.Select {
	case igagov.SelectOldestNonDefault:
		if op.IfVersionsAtLeast > 0 && len(versions) < op.IfVersionsAtLeast {
			return nil, nil
		}
		if len(nonDefault) > 0 {
			chosen = nonDefault[:1]
		}
	case igagov.SelectAllNonDefault:
		chosen = nonDefault
	default:
		return nil, fmt.Errorf("%w: unknown selector %q", ErrNotDeletable, op.Select)
	}
	out := make([]VersionToDelete, 0, len(chosen))
	for _, v := range chosen {
		doc, err := r.GetPolicyVersion(ctx, op.PolicyARN, v.VersionID)
		if IsNoSuchEntity(err) {
			continue // already gone
		}
		if err != nil {
			return nil, fmt.Errorf("GetPolicyVersion %s %s: %w", op.PolicyARN, v.VersionID, err)
		}
		out = append(out, VersionToDelete{VersionID: v.VersionID, Document: doc})
	}
	return out, nil
}

// versionNumber orders "v12" after "v3".
func versionNumber(id string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(strings.ToLower(id), "v"))
	if err != nil {
		return 1 << 30
	}
	return n
}

// arnAccount returns an ARN's account and partition.
func arnAccount(arn string) (account, partition string) {
	p := strings.SplitN(arn, ":", 6)
	if len(p) < 5 {
		return "", ""
	}
	return p[4], p[1]
}

func copyTags(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
