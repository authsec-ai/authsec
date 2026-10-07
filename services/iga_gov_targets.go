package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Target resolution and evidence bundles (SPEC-iga-phase3-policy.md §2.11,
// §2.12, §7.2; T3.06b). Both run OUTSIDE the pipeline barrier and read only
// by key -- iga_identity_accounts.immutable_key (RoleId), the ARN's source
// key, or a graph object id -- and the relationship tables, with no list
// cap: a role beyond the inventory's 10,000-row cap or the first page of any
// list resolves exactly like one on the first page (A54).

// MaxTargetKeys bounds one resolve request (§7.2).
const MaxTargetKeys = 50

// Resolve statuses (§7.2).
const (
	TargetResolved     = "resolved"
	TargetNotFound     = "not_found"
	TargetAmbiguous    = "ambiguous"
	TargetNotSupported = "not_supported"
)

// TargetKey is one provider-qualified identity key (§7.2): AWS by
// (account_id, role_arn) or role_id, any graph object by object_id, and the
// Kubernetes ServiceAccount keys, which are not supported in R1a.
type TargetKey struct {
	Provider       string `json:"provider,omitempty"`
	AccountID      string `json:"account_id,omitempty"`
	RoleARN        string `json:"role_arn,omitempty"`
	RoleID         string `json:"role_id,omitempty"`
	ObjectID       string `json:"object_id,omitempty"`
	ClusterUID     string `json:"cluster_uid,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	ServiceAccount string `json:"service_account,omitempty"`
	UID            string `json:"uid,omitempty"`
}

// ResolvedIdentity is the identity incarnation a key resolved to.
type ResolvedIdentity struct {
	ID         uuid.UUID         `json:"id"`
	RoleID     string            `json:"role_id"`
	ARN        string            `json:"arn"`
	Name       string            `json:"name"`
	Path       string            `json:"path"`
	Tags       map[string]string `json:"tags"`
	AccountID  string            `json:"account_id"`
	Kind       string            `json:"kind"`
	Continuity string            `json:"continuity"`
}

// ControlRef is the live control on the role, if any.
type ControlRef struct {
	ID       uuid.UUID `json:"id"`
	PolicyID uuid.UUID `json:"policy_id"`
	State    string    `json:"state"`
}

// UnresolvedConsumer is a workload that names the role as its execution
// role but whose edge could not be resolved (iga_workload
// execution_role_state not_in_scan / not_in_inventory).
type UnresolvedConsumer struct {
	WorkloadID uuid.UUID `json:"workload_id"`
	Name       string    `json:"name"`
	State      string    `json:"state"`
}

// TargetEvidence is the evidence trust a plan for the role would rest on
// (the source of a bundle built now, §2.11).
type TargetEvidence struct {
	Trust                     string     `json:"trust"`
	TrustReasons              []string   `json:"trust_reasons"`
	PublishedRev              *int64     `json:"published_rev"`
	FreshnessHours            *int       `json:"freshness_hours"`
	ResourcePolicyCoverage    string     `json:"resource_policy_coverage"`
	ConnectorID               *uuid.UUID `json:"connector_id"`
	ConnectorRun              *string    `json:"connector_run"`
	ActivityReportGeneratedAt *string    `json:"activity_report_generated_at"`
}

// TargetContext names the graph object a key resolved THROUGH (an edge or a
// workload is context, never the target itself, §2.12).
type TargetContext struct {
	ObjectKind string    `json:"object_kind"`
	ObjectID   uuid.UUID `json:"object_id"`
}

// ResolvedTarget is the answer for one key.
type ResolvedTarget struct {
	Key                 TargetKey            `json:"key"`
	Status              string               `json:"status"`
	Reason              string               `json:"reason,omitempty"`
	Prerequisite        string               `json:"prerequisite,omitempty"`
	Candidates          []uuid.UUID          `json:"candidates,omitempty"`
	Context             *TargetContext       `json:"context,omitempty"`
	Identity            *ResolvedIdentity    `json:"identity"`
	Eligible            bool                 `json:"eligible"`
	IneligibleReasons   []string             `json:"ineligible_reasons"`
	Control             *ControlRef          `json:"control"`
	Consumers           []ConsumerView       `json:"consumers"`
	ConsumersUnresolved int                  `json:"consumers_unresolved"`
	UnresolvedConsumers []UnresolvedConsumer `json:"unresolved_consumers"`
	Owners              []OwnerView          `json:"owners"`
	Evidence            *TargetEvidence      `json:"evidence"`
}

// GovTargets is the target resolver and evidence bundle builder.
type GovTargets struct {
	db     *gorm.DB
	repo   repositories.IGAGovEvaluationRepository
	events repositories.IGAGovEventRepository
	now    func() time.Time
	rules  igagov.TrustRules
}

// NewGovTargets builds the resolver/builder.
func NewGovTargets(db *gorm.DB) *GovTargets {
	return &GovTargets{db: db, repo: repositories.NewIGAGovEvaluationRepository(),
		events: repositories.NewIGAGovEventRepository(db), now: time.Now, rules: igagov.DefaultTrustRules()}
}

// WithClock sets the build clock (tests).
func (g *GovTargets) WithClock(now func() time.Time) *GovTargets { g.now = now; return g }

// ValidateTargetKeys checks the request shape: 1..50 keys, each exactly one
// form.
func ValidateTargetKeys(keys []TargetKey) error {
	if len(keys) == 0 || len(keys) > MaxTargetKeys {
		return GovBadParam("keys", fmt.Sprintf("Send 1 to %d keys.", MaxTargetKeys))
	}
	for i, k := range keys {
		forms := 0
		if k.ObjectID != "" {
			forms++
		}
		if k.RoleARN != "" || k.AccountID != "" {
			forms++
		}
		if k.RoleID != "" {
			forms++
		}
		if k.ClusterUID != "" || k.Namespace != "" || k.ServiceAccount != "" || k.UID != "" {
			forms++
		}
		if forms != 1 {
			return GovBadParam(fmt.Sprintf("keys[%d]", i),
				"Each key is exactly one of {provider, account_id, role_arn}, {provider, role_id}, {object_id} or a Kubernetes ServiceAccount key.")
		}
		switch k.Provider {
		case "", "aws", "k8s":
		default:
			return GovBadParam(fmt.Sprintf("keys[%d].provider", i), fmt.Sprintf("Unknown provider %q.", k.Provider))
		}
		if (k.RoleARN != "" || k.AccountID != "") && (k.RoleARN == "" || k.AccountID == "") {
			return GovBadParam(fmt.Sprintf("keys[%d]", i), "An ARN key needs both account_id and role_arn.")
		}
		if k.ObjectID != "" {
			if _, err := uuid.Parse(k.ObjectID); err != nil {
				return GovBadParam(fmt.Sprintf("keys[%d].object_id", i), "object_id must be a uuid.")
			}
		}
	}
	return nil
}

// notSupportedK8s is the R1a answer for every Kubernetes key (§2.12, A53c).
func notSupportedK8s(k TargetKey) ResolvedTarget {
	return ResolvedTarget{Key: k, Status: TargetNotSupported, Prerequisite: "K-1",
		Reason:            "Kubernetes is not supported for policy in R1a: it needs an authenticated, ordered RBAC ingest (K-1).",
		IneligibleReasons: []string{"provider_not_supported:K-1"}, Consumers: []ConsumerView{},
		UnresolvedConsumers: []UnresolvedConsumer{}, Owners: []OwnerView{}}
}

func emptyTarget(k TargetKey, status, reason string) ResolvedTarget {
	return ResolvedTarget{Key: k, Status: status, Reason: reason, IneligibleReasons: []string{},
		Consumers: []ConsumerView{}, UnresolvedConsumers: []UnresolvedConsumer{}, Owners: []OwnerView{}}
}

type identityRow struct {
	ID            uuid.UUID
	Provider      string
	AccountKind   string
	DisplayName   string
	SourceKey     string
	ImmutableKey  string
	Continuity    string
	Lifecycle     string
	ProviderAttrs json.RawMessage
}

const identityCols = `id, provider, account_kind, display_name, source_key, immutable_key, continuity, lifecycle, provider_attrs`

// Resolve answers every key (§2.12). Keys are validated by the caller.
func (g *GovTargets) Resolve(ctx context.Context, ws uuid.UUID, keys []TargetKey) ([]ResolvedTarget, error) {
	db := g.db.WithContext(ctx)
	out := make([]ResolvedTarget, 0, len(keys))
	for _, k := range keys {
		if k.Provider == "k8s" || k.ClusterUID != "" || k.Namespace != "" || k.ServiceAccount != "" || k.UID != "" {
			out = append(out, notSupportedK8s(k))
			continue
		}
		var rows []identityRow
		var ctxObj *TargetContext
		var err error
		switch {
		case k.RoleARN != "":
			if govARNField(k.RoleARN, 4) != k.AccountID {
				out = append(out, emptyTarget(k, TargetNotFound, "account_mismatch"))
				continue
			}
			err = db.Raw(`SELECT `+identityCols+` FROM iga_identity_accounts
			               WHERE workspace_id = ? AND provider = 'aws' AND source_key = ? AND lifecycle = 'active'`,
				ws, igagraph.IdentityARNKey(k.RoleARN)).Scan(&rows).Error
		case k.RoleID != "":
			err = db.Raw(`SELECT `+identityCols+` FROM iga_identity_accounts
			               WHERE workspace_id = ? AND provider = 'aws' AND immutable_key = ? AND lifecycle = 'active'`,
				ws, k.RoleID).Scan(&rows).Error
		default:
			var res ResolvedTarget
			var done bool
			rows, ctxObj, res, done, err = g.resolveObject(db, ws, k)
			if err == nil && done {
				out = append(out, res)
				continue
			}
		}
		if err != nil {
			return nil, err
		}
		switch len(rows) {
		case 0:
			out = append(out, emptyTarget(k, TargetNotFound, "no_live_identity"))
			continue
		case 1:
		default:
			t := emptyTarget(k, TargetAmbiguous, "several_live_identities")
			for _, r := range rows {
				t.Candidates = append(t.Candidates, r.ID)
			}
			out = append(out, t)
			continue
		}
		row := rows[0]
		if row.Provider == "k8s" {
			out = append(out, notSupportedK8s(k))
			continue
		}
		if row.Provider != "aws" {
			out = append(out, emptyTarget(k, TargetNotSupported, "provider_not_supported:"+row.Provider))
			continue
		}
		if row.Lifecycle != models.IGALifecycleActive {
			out = append(out, emptyTarget(k, TargetNotFound, "identity_retired"))
			continue
		}
		t, err := g.describe(ctx, db, ws, k, row)
		if err != nil {
			return nil, err
		}
		t.Context = ctxObj
		out = append(out, t)
	}
	return out, nil
}

// resolveObject resolves a graph object id to its holder identity: an
// identity is itself; a workload runs as exactly one role (several:
// ambiguous); a relationship's target, an assignment's holder and a grant's
// subject are the holder. Another workspace's id is not found.
func (g *GovTargets) resolveObject(db *gorm.DB, ws uuid.UUID, k TargetKey) ([]identityRow, *TargetContext, ResolvedTarget, bool, error) {
	id := uuid.MustParse(k.ObjectID)
	var rows []identityRow
	if err := db.Raw(`SELECT `+identityCols+` FROM iga_identity_accounts WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&rows).Error; err != nil {
		return nil, nil, ResolvedTarget{}, false, err
	}
	if len(rows) == 1 {
		return rows, nil, ResolvedTarget{}, false, nil
	}
	var wl []struct {
		Provider string
	}
	if err := db.Raw(`SELECT provider FROM iga_workload WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&wl).Error; err != nil {
		return nil, nil, ResolvedTarget{}, false, err
	}
	if len(wl) == 1 {
		if wl[0].Provider == "k8s" {
			return nil, nil, notSupportedK8s(k), true, nil
		}
		ctx := &TargetContext{ObjectKind: "workload", ObjectID: id}
		err := db.Raw(`SELECT DISTINCT `+prefixed("i", identityCols)+` FROM iga_relationship r
		                JOIN iga_identity_accounts i ON i.workspace_id = r.workspace_id AND i.id = r.target_identity_account_id
		               WHERE r.workspace_id = ? AND r.source_workload_id = ? AND r.state <> 'ended'
		                 AND r.relationship_type IN ('executes_as','task_execution_role') AND i.lifecycle = 'active'`,
			ws, id).Scan(&rows).Error
		if err == nil && len(rows) == 0 {
			t := emptyTarget(k, TargetNotFound, "workload_runs_as_no_role")
			t.Context = ctx
			return nil, nil, t, true, nil
		}
		return rows, ctx, ResolvedTarget{}, false, err
	}
	for _, edge := range []struct {
		kind, table, col string
	}{
		{"relationship", "iga_relationship", "target_identity_account_id"},
		{"assignment", "iga_policy_assignment", "holder_identity_account_id"},
		{"grant", "iga_access_edges", "subject_identity_account_id"},
	} {
		if err := db.Raw(`SELECT `+prefixed("i", identityCols)+` FROM `+edge.table+` e
		                   JOIN iga_identity_accounts i ON i.workspace_id = e.workspace_id AND i.id = e.`+edge.col+`
		                  WHERE e.workspace_id = ? AND e.id = ?`, ws, id).Scan(&rows).Error; err != nil {
			return nil, nil, ResolvedTarget{}, false, err
		}
		if len(rows) > 0 {
			return rows, &TargetContext{ObjectKind: edge.kind, ObjectID: id}, ResolvedTarget{}, false, nil
		}
	}
	return nil, nil, ResolvedTarget{}, false, nil
}

func prefixed(alias, cols string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = alias + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

type roleAttrs struct {
	Path     string            `json:"path"`
	Tags     map[string]string `json:"tags"`
	Boundary string            `json:"permissions_boundary_arn"`
}

// RoleIneligibility lists why a role cannot be targeted in R1a (§2.2, §3.1,
// A11): not a role, no immutable RoleId, service-linked or reserved,
// authsec:protected, or AuthSec's own (ManagedBy=AuthSec). Empty: eligible.
// The compiler adds the reasons only a live read can give (document size,
// a recreated RoleId).
func RoleIneligibility(kind, continuity, roleID, path string, tags map[string]string) []string {
	out := []string{}
	if kind != models.CloudIdentityIAMRole {
		out = append(out, "not_a_role")
	}
	if continuity != igagraph.ContinuityImmutable || roleID == "" {
		out = append(out, "no_immutable_role_id")
	}
	switch {
	case strings.HasPrefix(path, "/aws-service-role/"):
		out = append(out, "service_linked_role")
	case strings.HasPrefix(path, "/aws-reserved/"):
		out = append(out, "aws_reserved_role")
	}
	for k, v := range tags {
		if strings.EqualFold(k, "authsec:protected") && !strings.EqualFold(v, "false") {
			out = append(out, "authsec_protected")
		}
	}
	if tags["ManagedBy"] == "AuthSec" {
		out = append(out, "authsec_managed_role")
	}
	sort.Strings(out)
	return out
}

func (g *GovTargets) describe(ctx context.Context, db *gorm.DB, ws uuid.UUID, k TargetKey, row identityRow) (ResolvedTarget, error) {
	var attrs roleAttrs
	_ = json.Unmarshal(row.ProviderAttrs, &attrs)
	arn := nativeOfSourceKey(row.SourceKey)
	if attrs.Tags == nil {
		attrs.Tags = map[string]string{}
	}
	t := ResolvedTarget{Key: k, Status: TargetResolved,
		Identity: &ResolvedIdentity{ID: row.ID, RoleID: row.ImmutableKey, ARN: arn, Name: row.DisplayName, Path: attrs.Path,
			Tags: attrs.Tags, AccountID: govARNField(arn, 4), Kind: row.AccountKind, Continuity: row.Continuity},
		UnresolvedConsumers: []UnresolvedConsumer{}}
	t.IneligibleReasons = RoleIneligibility(row.AccountKind, row.Continuity, row.ImmutableKey, attrs.Path, attrs.Tags)
	t.Eligible = len(t.IneligibleReasons) == 0
	var err error
	if t.Consumers, err = consumersOf(db, ws, row.ID); err != nil {
		return t, err
	}
	if t.UnresolvedConsumers, err = unresolvedConsumersOf(db, ws, arn); err != nil {
		return t, err
	}
	t.ConsumersUnresolved = len(t.UnresolvedConsumers)
	if t.Owners, err = ownersOf(db, ws, row.ID, t.Consumers); err != nil {
		return t, err
	}
	if row.ImmutableKey != "" {
		var cs []ControlRef
		if err := db.Raw(`SELECT id, policy_id, state FROM iga_gov_control
		                   WHERE workspace_id = ? AND account_id = ? AND role_id = ? AND state <> 'removed'`,
			ws, govARNField(arn, 4), row.ImmutableKey).Scan(&cs).Error; err != nil {
			return t, err
		}
		if len(cs) == 1 {
			t.Control = &cs[0]
		}
	}
	if row.AccountKind == models.CloudIdentityIAMRole && row.ImmutableKey != "" {
		b, src, err := g.build(ctx, ws, row.ID, nil)
		switch {
		case err == nil:
			ev := &TargetEvidence{Trust: b.Trust, TrustReasons: b.TrustReasons, PublishedRev: &src.Rev,
				ResourcePolicyCoverage: src.ResourcePolicyCoverage, ConnectorID: uuidPtr(src.ConnectorID),
				ConnectorRun: nilIfEmptyStr(src.ConnectorRun), ActivityReportGeneratedAt: src.ActivityReportGeneratedAt}
			fh := src.FreshnessHours
			ev.FreshnessHours = &fh
			t.Evidence = ev
		case errors.Is(err, ErrNoCompleteEvaluation), errors.Is(err, errRoleNotEvaluated):
			t.Evidence = &TargetEvidence{Trust: igagov.TrustUntrusted, TrustReasons: []string{reasonOf(err)},
				ResourcePolicyCoverage: igagov.CoverageNotCollected}
		default:
			return t, err
		}
	}
	return t, nil
}

func nilIfEmptyStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func reasonOf(err error) string {
	switch {
	case errors.Is(err, ErrNoCompleteEvaluation):
		return "no_complete_evaluation"
	case errors.Is(err, errRoleNotEvaluated):
		return "role_not_in_latest_evaluation"
	}
	return err.Error()
}

// unresolvedConsumersOf lists active workloads that name the role ARN as
// their execution role without a resolved edge.
func unresolvedConsumersOf(db *gorm.DB, ws uuid.UUID, arn string) ([]UnresolvedConsumer, error) {
	out := []UnresolvedConsumer{}
	if arn == "" {
		return out, nil
	}
	err := db.Raw(`SELECT id AS workload_id, display_name AS name, execution_role_state AS state FROM iga_workload
	                WHERE workspace_id = ? AND lifecycle = 'active' AND execution_role_arn = ?
	                  AND execution_role_state IN ('not_in_scan','not_in_inventory')
	                ORDER BY display_name, id`, ws, arn).Scan(&out).Error
	return out, err
}

/* ---------------------------- evidence bundles ----------------------------- */

// ErrNoCompleteEvaluation: no evaluation has completed, so there is no
// evidence to build a bundle from.
var ErrNoCompleteEvaluation = errors.New("no complete evaluation")

var errRoleNotEvaluated = errors.New("the role is not in the latest complete evaluation")

// StoredBundle is a built and persisted evidence bundle.
type StoredBundle struct {
	ID           uuid.UUID
	Hash         string
	Trust        string
	TrustReasons []string
	Facts        igagov.BundleFacts
	GapRefs      []igagov.GapRef
	// Created is false when an identical bundle (same hash) already existed.
	Created bool
}

// UntrustedError is §7.12's 422 evidence_untrusted for an untrusted bundle,
// naming each source and reason with the Connections remedy (A53a); nil
// when the bundle is trusted or partial.
func (b StoredBundle) UntrustedError() *GovError {
	if b.Trust != igagov.TrustUntrusted {
		return nil
	}
	var sources []map[string]any
	for _, s := range b.Facts.Sources {
		if s.Trust != igagov.TrustUntrusted {
			continue
		}
		remedy := "/iga/connections"
		if s.ConnectorID != "" {
			remedy += "/" + s.ConnectorID + "/coverage"
		}
		sources = append(sources, map[string]any{"kind": s.Kind, "rev": s.Rev, "connector_id": s.ConnectorID,
			"connector_run": s.ConnectorRun, "reasons": s.TrustReasons, "freshness_hours": s.FreshnessHours, "remedy": remedy})
	}
	return govErr(http.StatusUnprocessableEntity, "evidence_untrusted",
		"The evidence for this role is not trustworthy enough to compile a change.",
		map[string]any{"sources": sources, "reasons": b.TrustReasons})
}

// BuildEvidenceBundle builds the bundle a plan for this role would be
// compiled from (§2.11) -- from the latest complete evaluation and the role
// connector's run named in its manifest -- and persists it insert-once (the
// 050 trigger re-verifies the hash; an identical bundle is reused). The
// actor is recorded on the evidence_bundle_created event.
func (g *GovTargets) BuildEvidenceBundle(ctx context.Context, ws, identity uuid.UUID, removed []string, actorKind, actorID string) (*StoredBundle, error) {
	b, _, err := g.build(ctx, ws, identity, removed)
	if err != nil {
		return nil, err
	}
	sb := &StoredBundle{Hash: b.Hash, Trust: b.Trust, TrustReasons: b.TrustReasons, Facts: b.Facts, GapRefs: b.GapRefs}
	err = g.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var ids []uuid.UUID
		if err := tx.Raw(`INSERT INTO iga_gov_evidence_bundle (workspace_id, provider, trust, bundle_hash, canonical, facts)
		                   VALUES (?, 'aws', ?, ?, ?, ?::jsonb)
		                   ON CONFLICT (workspace_id, bundle_hash) DO NOTHING RETURNING id`,
			ws, b.Trust, b.Hash, string(b.Canonical), string(b.Canonical)).Scan(&ids).Error; err != nil {
			return err
		}
		if len(ids) == 1 {
			sb.ID, sb.Created = ids[0], true
			payload, _ := json.Marshal(map[string]any{"bundle_id": ids[0], "bundle_hash": b.Hash, "trust": b.Trust,
				"identity_account_id": identity, "role_id": b.Facts.Target.RoleID, "removed_services": b.Facts.RemovedServices})
			return g.events.AppendTx(tx, &models.IGAGovEvent{WorkspaceID: ws, Event: "evidence_bundle_created",
				ActorKind: actorKind, ActorID: actorID, Payload: payload})
		}
		return tx.Raw(`SELECT id FROM iga_gov_evidence_bundle WHERE workspace_id = ? AND bundle_hash = ?`, ws, b.Hash).
			Scan(&sb.ID).Error
	})
	if err != nil {
		return nil, err
	}
	return sb, nil
}

// build gathers one role's bundle input at the latest complete evaluation:
// the role and its grants AS OF that revision's publication time (graph
// rows carry their validity intervals), consumers as of the same time, the
// owners, the FROZEN activity evidence of that evaluation, and the route
// analyses of the role connector's run (immutable observations, §3.9).
func (g *GovTargets) build(ctx context.Context, ws, identity uuid.UUID, removed []string) (igagov.Bundle, igagov.BundleSource, error) {
	db := g.db.WithContext(ctx)
	lc, err := g.repo.LatestComplete(db, ws)
	if err != nil {
		return igagov.Bundle{}, igagov.BundleSource{}, err
	}
	if lc == nil {
		return igagov.Bundle{}, igagov.BundleSource{}, ErrNoCompleteEvaluation
	}
	gs, err := loadGovSnapshot(ctx, g.db, ws, lc.Rev, &identity)
	if err != nil {
		return igagov.Bundle{}, igagov.BundleSource{}, err
	}
	if len(gs.Snap.Roles) != 1 {
		return igagov.Bundle{}, igagov.BundleSource{}, errRoleNotEvaluated
	}
	role := gs.Snap.Roles[0]
	at := gs.Snap.EvaluatedAt
	runID := gs.Snap.Manifest[role.PartitionKey]
	run, hasRun := gs.Snap.Runs[runID]
	if role.PartitionKey == "" || !hasRun {
		runID = ""
	}

	// Frozen activity evidence at the evaluated revision.
	var evRows []models.IGAGovActivityEvidence
	if err := db.Where("workspace_id = ? AND rev = ? AND identity_account_id = ?", ws, lc.Rev, identity).
		Order("service").Find(&evRows).Error; err != nil {
		return igagov.Bundle{}, igagov.BundleSource{}, err
	}
	consumers, err := consumersAsOf(db, ws, identity, at)
	if err != nil {
		return igagov.Bundle{}, igagov.BundleSource{}, err
	}
	window := bundleWindow(gs, consumers)
	var activity []igagov.BundleActivity
	var reportAt *time.Time
	for _, e := range evRows {
		if e.State != igagov.EvidenceCollected || e.ReportGeneratedAt == nil {
			activity = append(activity, igagov.BundleActivity{Service: e.Service, State: igagov.EvidenceNotCollected,
				GrantAgeBasis: igagov.GrantAgeUnknown})
			continue
		}
		if reportAt == nil || e.ReportGeneratedAt.After(*reportAt) {
			t := e.ReportGeneratedAt.UTC()
			reportAt = &t
		}
		activity = append(activity, igagov.ActivityFromQualification(requalify(e, role.CreatedAt, window, at)))
	}

	// Grants: the live identity statements at the evaluated revision.
	var grants []igagov.BundleGrant
	live := map[string]igagov.PolicyAssignment{}
	for _, a := range role.Assignments {
		if a.Kind == igagov.AssignBoundary {
			continue
		}
		for _, iv := range a.Intervals {
			if !at.Before(iv.From) && (iv.To == nil || at.Before(*iv.To)) {
				live[a.PolicyKey] = a
			}
		}
	}
	for _, sr := range role.Statements {
		a, ok := live[sr.PolicyKey]
		if !ok || at.Before(sr.From) || (sr.To != nil && !at.Before(*sr.To)) || sr.Statement.Effect != igagov.EffectAllow {
			continue
		}
		grants = append(grants, igagov.BundleGrant{PolicyARN: a.PolicyARN, AssignmentKind: a.Kind, StatementKey: sr.StatementKey,
			StatementHash: sr.Hash, Services: sr.Statement.ExplicitNamespaces()})
	}
	var impact []igagov.ImpactConsumer
	for _, c := range consumers {
		impact = append(impact, igagov.ImpactConsumer{WorkloadID: c.WorkloadID.String(), Relationship: c.Relationship})
	}
	unresolved, err := unresolvedConsumersOf(db, ws, role.ARN)
	if err != nil {
		return igagov.Bundle{}, igagov.BundleSource{}, err
	}
	owners, err := ownersOf(db, ws, identity, consumers)
	if err != nil {
		return igagov.Bundle{}, igagov.BundleSource{}, err
	}
	var ownerIDs []string
	for _, o := range owners {
		ownerIDs = append(ownerIDs, o.UserID.String())
	}

	src := igagov.BundleSourceInput{Kind: igagov.SourceAWSPublication, Rev: lc.Rev, PublishedAt: at,
		ConnectorID: role.ConnectorID, ConnectorRun: runID,
		// DECISION E7: an AWS publication is authenticated (the connector's
		// discovery role, assumed with its external id) and ordered (the
		// projector's generation watermark refuses an older run).
		Authenticated: true, Ordered: true, ActivityReportGeneratedAt: reportAt,
		ResourcePolicyCoverage: igagov.CoverageNotCollected}
	var analyses []igagov.RouteAnalysis
	if hasRun && runID != "" {
		src.ResourcePolicyCoverage = igagov.SummarizeCoverage(run.ResourcePolicy, run.EnabledRegions)
		if run.ResourcePolicy != nil {
			src.ResourcePolicyRun = runID
		}
		ref := igagov.RoleRef{RoleID: role.RoleID, ARN: role.ARN, Name: role.Name, AccountID: role.AccountID, Partition: role.Partition}
		for _, svc := range removed {
			analyses = append(analyses, igagov.AnalyzeRoutes(svc, ref, run.ResourcePolicy, run.EnabledRegions))
		}
	} else {
		for _, svc := range removed {
			analyses = append(analyses, igagov.AnalyzeRoutes(svc, igagov.RoleRef{}, nil, nil))
		}
	}
	b, err := igagov.BuildBundle(igagov.BundleInput{
		BuiltAt: g.now().UTC().Truncate(time.Microsecond), Sources: []igagov.BundleSourceInput{src},
		Target:          igagov.BundleTarget{AccountID: role.AccountID, RoleID: role.RoleID, RoleARN: role.ARN},
		RemovedServices: removed, Grants: grants, Consumers: impact, ConsumersUnresolved: len(unresolved),
		Owners: ownerIDs, Activity: activity, RouteAnalyses: analyses,
	}, g.rules)
	if err != nil {
		return igagov.Bundle{}, igagov.BundleSource{}, err
	}
	return b, b.Facts.Sources[0], nil
}

// consumersAsOf is consumersOf at a past instant, by the relationships'
// validity intervals.
func consumersAsOf(db *gorm.DB, ws, identity uuid.UUID, at time.Time) ([]ConsumerView, error) {
	out := []ConsumerView{}
	err := db.Raw(`SELECT DISTINCT w.id AS workload_id, w.display_name AS name, w.runtime_kind, r.relationship_type AS relationship
	                 FROM iga_relationship r
	                 JOIN iga_workload w ON w.workspace_id = r.workspace_id AND w.id = r.source_workload_id
	                WHERE r.workspace_id = ? AND r.target_identity_account_id = ?
	                  AND r.relationship_type IN ('executes_as','task_execution_role')
	                  AND r.valid_from <= ? AND (r.valid_to IS NULL OR r.valid_to > ?)
	                ORDER BY 2, 1, 4`, ws, identity, at, at).Scan(&out).Error
	return out, err
}

// bundleWindow is the evaluator's window for the role: the longest enabled
// unused_window rule matching a consumer, else the workspace default.
func bundleWindow(gs *govSnapshot, consumers []ConsumerView) int {
	best := 0
	byID := map[string]igagov.WorkloadSnapshot{}
	var ids []string
	for _, c := range consumers {
		ids = append(ids, c.WorkloadID.String())
	}
	for _, w := range gs.Snap.Workloads {
		byID[w.ID] = w
	}
	for _, rule := range gs.Snap.Rules {
		if !rule.Enabled || rule.Kind != igagov.RuleUnusedWindow {
			continue
		}
		for _, id := range ids {
			w := byID[id]
			if scopeMatches(rule.Scope, w) && rule.WindowDays > best {
				best = rule.WindowDays
			}
		}
	}
	if best > 0 {
		return igagov.ClampWindowDays(best)
	}
	return igagov.ClampWindowDays(gs.Snap.DefaultWindowDays)
}

func scopeMatches(s igagov.RuleScope, w igagov.WorkloadSnapshot) bool {
	in := func(list []string, v string) bool {
		if len(list) == 0 {
			return true
		}
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	return in(s.RuntimeKinds, w.RuntimeKind) && in(s.Stages, w.Stage) && in(s.Classifications, w.Classification)
}

// requalify re-derives a service's §2.6 qualification from its FROZEN
// evidence row (DECISION E8): the row keeps the report time, last attempt,
// tracking start and the verified grant start with its basis, which is
// exactly what Qualify needs once the grant path is reduced to that one
// interval (open-start for predates_observation, none for unknown).
func requalify(e models.IGAGovActivityEvidence, roleCreated time.Time, window int, at time.Time) igagov.Qualification {
	in := igagov.QualifyInput{Service: e.Service, ReportGeneratedAt: e.ReportGeneratedAt.UTC(),
		LastAuthenticatedAt: utcPtr(e.LastAuthenticatedAt), RoleCreatedAt: roleCreated, RequestedWindowDays: window, At: at,
		TrackingFrom: utcPtr(e.TrackingFrom), TrackingReason: e.Reason}
	switch e.GrantAgeBasis {
	case igagov.GrantAgeObservedSinceChange:
		if e.GrantObservedSince != nil {
			in.Paths = []igagov.GrantPath{{Key: "frozen", Components: [][]igagov.Interval{{{From: e.GrantObservedSince.UTC()}}}}}
		}
	case igagov.GrantAgePredatesObservation:
		in.Paths = []igagov.GrantPath{{Key: "frozen", Components: [][]igagov.Interval{{{From: time.Unix(0, 0).UTC(), OpenStart: true}}}}}
	}
	return igagov.Qualify(in)
}
