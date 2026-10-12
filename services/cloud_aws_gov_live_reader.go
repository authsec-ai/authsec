package services

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/igagov"
)

// GovAWSLiveReader is the compiler's discovery-role live read (LiveReader,
// SPEC-iga-phase3-policy.md §3.5, §8.3) over T3.10's reads: the connector's
// discovery role (IGAGovAWS.DiscoveryIAM -- AWSEnforcementAccess in
// production, a fake account's discovery view in tests), then
// awsenforce.ReadRole (GetRole, attached + inline policies with document
// hashes) and awsenforce.ReadPolicy (GetPolicy, default document,
// ListPolicyVersions, ListEntitiesForPolicy of every usage type) -- the same
// functions the deploy executor reads through, so compile and deploy see
// AWS identically.
//
// Contract (LiveReader): Role is nil when GetRole answers NoSuchEntity; the
// role's live boundary and every PolicyARNs entry are keys of Policies (nil
// value = NoSuchEntity); ReadAt is when the read finished; the reader never
// filters on RoleID (the compiler compares incarnations); any error -- the
// connector unusable, an AWS error, a role answered from another account --
// fails the whole read, never a partial one.
type GovAWSLiveReader struct {
	aws IGAGovAWS
	now func() time.Time
}

// NewGovAWSLiveReader builds the reader over the executor's AWS access.
func NewGovAWSLiveReader(aws IGAGovAWS) *GovAWSLiveReader {
	return &GovAWSLiveReader{aws: aws, now: time.Now}
}

// WithClock replaces the clock (tests).
func (r *GovAWSLiveReader) WithClock(now func() time.Time) *GovAWSLiveReader {
	r.now = now
	return r
}

// ReadRole implements LiveReader.
func (r *GovAWSLiveReader) ReadRole(ctx context.Context, req LiveReadRequest) (igagov.LiveRead, error) {
	name := roleNameOfARN(req.RoleARN)
	if name == "" || !strings.Contains(req.RoleARN, ":role/") {
		return igagov.LiveRead{}, fmt.Errorf("live read: %q is not a role ARN", req.RoleARN)
	}
	disc, err := r.aws.DiscoveryIAM(ctx, req.WorkspaceID, req.ConnectorID)
	if err != nil {
		return igagov.LiveRead{}, fmt.Errorf("live read: discovery role: %w", err)
	}
	role, err := awsenforce.ReadRole(ctx, disc, name)
	if err != nil {
		return igagov.LiveRead{}, fmt.Errorf("live read: %w", err)
	}
	// DECISION (p3-wire, item 1): GetRole is by NAME in the connector's
	// account; an answer from another account means the request named the
	// wrong connector, which is a failed read, never a role to compile.
	if role != nil && req.AccountID != "" && role.AccountID != "" && role.AccountID != req.AccountID {
		return igagov.LiveRead{}, fmt.Errorf("live read: role %s answered from account %s, not %s", name, role.AccountID, req.AccountID)
	}
	set := map[string]bool{}
	for _, a := range req.PolicyARNs {
		if a != "" {
			set[a] = true
		}
	}
	if role != nil && role.BoundaryARN != "" {
		set[role.BoundaryARN] = true
	}
	arns := make([]string, 0, len(set))
	for a := range set {
		arns = append(arns, a)
	}
	sort.Strings(arns)
	live := igagov.LiveRead{Role: role, Policies: make(map[string]*igagov.LivePolicy, len(arns))}
	for _, a := range arns {
		lp, _, err := awsenforce.ReadPolicy(ctx, disc, a)
		if err != nil {
			return igagov.LiveRead{}, fmt.Errorf("live read: %w", err)
		}
		live.Policies[a] = lp
	}
	live.ReadAt = r.now().UTC()
	return live, nil
}
