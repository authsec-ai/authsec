package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Access policies (decision, Aditya, 2026-10-13; brief "access policies, and
// no ownership"): the workspace admin picks an S3 bucket and roles from
// Discovery, chooses Block or Allow and a time window, and presses Apply.
// There is no approver step and no ownership.
//
//	iga_gov_policy (family time_bound)  name, purpose = reason, lifecycle
//	  └ iga_gov_access_policy_version    immutable intent; one 'applied'
//	      └ iga_gov_temp_grant rows       one per role: an AuthSec-owned
//	                                      /authsec/AuthSecAccess-<RoleId>-
//	                                      <policy 8hex>-v<no> attached to it
//
// A deployment row starts approved (decided_by = the admin) and runs on the
// existing temp_grant job (r2AccessKind): create, attach, read back, verify
// every 10 minutes, re-apply when detached or deleted outside AuthSec,
// detach and delete at the end. Its aws:CurrentTime conditions make the
// policy inert outside the window even if AuthSec is down; a start time is
// therefore deployed at once, inert until it begins.
//
// Edit makes a new version whose rows deploy alongside the old ones; the old
// rows end (superseded) only once every new row is verified, so a block
// never has a gap. Pause removes the policy from AWS; Resume deploys the
// current version again; End removes it for good (lifecycle archived).

// Access-policy events.
const (
	GovEventAccessCreated   = "access_policy.created"
	GovEventAccessApplied   = "access_policy.applied"
	GovEventAccessConfirmed = "access_policy.confirmed"
	GovEventAccessEdited    = "access_policy.edited"
	GovEventAccessPaused    = "access_policy.paused"
	GovEventAccessResumed   = "access_policy.resumed"
	GovEventAccessEnded     = "access_policy.ended"
	GovEventAccessExpired   = "access_policy.expired"
	GovEventAccessRemoved   = "access_policy.removed"
	GovEventAccessDrifted   = "access_policy.drifted"
	GovEventAccessReapplied = "access_policy.reapplied"
	GovEventAccessFailed    = "access_policy.failed"
	GovEventAccessUnknown   = "access_policy.outcome_unknown"
)

// Access-policy error codes.
const (
	GovCodeAccessInvalid        = "access_policy_invalid"
	GovCodeRoleNotInAccount     = "role_not_in_account"
	GovCodeRolePolicyQuota      = "role_policy_quota"
	GovCodeResourceNotFound     = "resource_not_found"
	GovCodeResourceNotSupported = "resource_not_supported"
	GovCodeBindingMissing       = "binding_missing"
	GovCodePolicyEnded          = "policy_ended"
	GovCodeNameTaken            = "name_taken"
	GovCodeAccessUnavailable    = "access_policies_unavailable"
	GovCodePolicyBusy           = "policy_busy"
	GovCodePolicyNotActive      = "policy_not_active"
)

// Access-policy statuses (the UI's).
const (
	AccessStatusApplying  = "applying"
	AccessStatusFailed    = "failed"
	AccessStatusDrift     = "drift"
	AccessStatusScheduled = "scheduled"
	AccessStatusActive    = "active"
	AccessStatusPaused    = "paused"
	AccessStatusEnded     = "ended"
)

const (
	accessEndPaused     = "paused"
	accessEndEnded      = "ended"
	accessEndSuperseded = "superseded"
	// IAM's default quota of managed policies attached to a role.
	accessAttachedQuota = 10
	accessMaxList       = 1000
)

/* ---------------------------------------------------------------------------- */
/*                                   Gate                                       */
/* ---------------------------------------------------------------------------- */

// accessSchema caches the 137 verification (re-tried at most every minute).
var accessSchema struct {
	sync.Mutex
	ok     bool
	reason string
	at     time.Time
}

// VerifyAccessPolicySchema checks the 137 objects access policies need.
func VerifyAccessPolicySchema(db *gorm.DB) error {
	var missing []string
	ok, err := repositories.HasRelation(db, "iga_gov_access_policy_version")
	if err != nil {
		return fmt.Errorf("access-policy schema verification could not run: %w", err)
	}
	if !ok {
		missing = append(missing, "iga_gov_access_policy_version")
	}
	want := []string{"iga_gov_temp_grant.iga_gov_tg_access_chk", "iga_gov_temp_grant.iga_gov_tg_effect_chk",
		"iga_gov_temp_grant.iga_gov_tg_version_fk"}
	have, err := repositories.ValidatedConstraints(db, want)
	if err != nil {
		return fmt.Errorf("access-policy schema verification could not run: %w", err)
	}
	missing = append(missing, absentNames(want, have, "constraint ")...)
	if len(missing) > 0 {
		return fmt.Errorf("access policies need migration 137; missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

// AccessPoliciesStatus is policy.access_policies of /capabilities: the R2
// gate (IGA_POLICY_R2, no new flag) and the 137 schema.
func AccessPoliciesStatus(db *gorm.DB) (bool, string) {
	if !PolicyR2On() {
		_, reason := PolicyR2GateState().Status()
		if reason == "" {
			reason = PolicyR2Env + " is off"
		}
		return false, reason
	}
	accessSchema.Lock()
	defer accessSchema.Unlock()
	if !accessSchema.ok && time.Since(accessSchema.at) > time.Minute {
		accessSchema.at = time.Now()
		if err := VerifyAccessPolicySchema(db); err != nil {
			accessSchema.reason = err.Error()
		} else {
			accessSchema.ok, accessSchema.reason = true, ""
		}
	}
	return accessSchema.ok, accessSchema.reason
}

func (s *GovAccess) require() error {
	// TENANT-EXEMPT: the 137 schema check reads the Postgres catalog only.
	if ok, reason := AccessPoliciesStatus(s.db); !ok {
		return govErr(http.StatusServiceUnavailable, GovCodeAccessUnavailable, "Access policies are not available on this server.",
			map[string]any{"reason": reason})
	}
	return nil
}

/* ---------------------------------------------------------------------------- */
/*                                 Service                                      */
/* ---------------------------------------------------------------------------- */

// GovAccess is the access-policy service. Every statement runs in a
// transaction under row-level security for the token's workspace
// (tenancy.InWorkspace / InWorkspaceRead) or the job's (run.InTx).
type GovAccess struct {
	db  *gorm.DB
	r2  *GovR2
	now func() time.Time
	// attached counts the managed policies attached to a role (the quota
	// check); nil reads through the discovery role.
	attached func(ctx context.Context, ws, connector uuid.UUID, roleARN string) (int, error)
}

// NewGovAccess builds the service.
func NewGovAccess(db *gorm.DB) *GovAccess {
	return &GovAccess{db: db, r2: NewGovR2(db), now: time.Now}
}

// WithAttachedCounter replaces the quota read (tests).
func (s *GovAccess) WithAttachedCounter(f func(ctx context.Context, ws, connector uuid.UUID, roleARN string) (int, error)) *GovAccess {
	s.attached = f
	return s
}

// AccessPolicyRequest is POST / and POST /:id/versions.
type AccessPolicyRequest struct {
	igagov.AccessIntent
	Name          string `json:"name"`
	Reason        string `json:"reason"`
	BaseVersionNo int    `json:"base_version_no,omitempty"`
}

// AccessReasonRequest is pause / resume / end.
type AccessReasonRequest struct {
	Reason string `json:"reason"`
}

// Views.
type (
	AccessUserRef struct {
		ID   uuid.UUID `json:"id"`
		Name string    `json:"name"`
	}
	AccessWorkloadRef struct {
		ID   uuid.UUID `json:"id"`
		Name string    `json:"name"`
		Kind string    `json:"kind"`
	}
	AccessResourceView struct {
		ResourceID string `json:"resource_id"`
		// Service: s3 | dynamodb | ssm. Name: the bucket, the table, or the
		// SSM parameter name or path (as the ARN writes it after "parameter/").
		Service string `json:"service"`
		Name    string `json:"name"`
		ARN     string `json:"arn"`
		// Bucket: the S3 bucket (empty for other services; kept for the v1 UI).
		Bucket    string `json:"bucket"`
		Prefix    string `json:"prefix"`
		Region    string `json:"region"`
		AccountID string `json:"account_id"`
	}
	AccessRoleView struct {
		IdentityAccountID uuid.UUID           `json:"identity_account_id"`
		Name              string              `json:"name"`
		ARN               string              `json:"arn"`
		AccountID         string              `json:"account_id"`
		UsedBy            []AccessWorkloadRef `json:"used_by"`
	}
	AccessDeploymentView struct {
		IdentityAccountID uuid.UUID  `json:"identity_account_id"`
		RoleName          string     `json:"role_name"`
		VersionNo         int        `json:"version_no"`
		State             string     `json:"state"`
		AWSPolicyARN      string     `json:"aws_policy_arn"`
		DocumentHash      string     `json:"document_hash"`
		DeployedAt        *time.Time `json:"deployed_at"`
		VerifiedAt        *time.Time `json:"verified_at"`
		LastReadbackAt    *time.Time `json:"last_readback_at"`
		Drift             string     `json:"drift"`
		Error             string     `json:"error"`
		EndReason         string     `json:"end_reason,omitempty"`
	}
	AccessDocumentView struct {
		IdentityAccountID uuid.UUID       `json:"identity_account_id"`
		RoleName          string          `json:"role_name,omitempty"`
		PolicyName        string          `json:"policy_name,omitempty"`
		Document          json.RawMessage `json:"document"`
	}
	AccessVersionView struct {
		VersionNo  int           `json:"version_no"`
		CreatedBy  AccessUserRef `json:"created_by"`
		CreatedAt  time.Time     `json:"created_at"`
		IntentHash string        `json:"intent_hash"`
		Status     string        `json:"status"`
	}
	// AccessPolicyView is the list item; the detail adds deployments,
	// documents and versions.
	AccessPolicyView struct {
		ID           uuid.UUID          `json:"id"`
		Name         string             `json:"name"`
		Reason       string             `json:"reason"`
		Effect       string             `json:"effect"`
		Access       []string           `json:"access"`
		StartsAt     *time.Time         `json:"starts_at"`
		EndsAt       *time.Time         `json:"ends_at"`
		Status       string             `json:"status"`
		StatusReason string             `json:"status_reason"`
		VersionNo    int                `json:"version_no"`
		Lifecycle    string             `json:"lifecycle"`
		CreatedBy    AccessUserRef      `json:"created_by"`
		CreatedAt    time.Time          `json:"created_at"`
		UpdatedAt    time.Time          `json:"updated_at"`
		EndedAt      *time.Time         `json:"ended_at"`
		EndReason    string             `json:"end_reason"`
		Resource     AccessResourceView `json:"resource"`
		Roles        []AccessRoleView   `json:"roles"`

		Deployments []AccessDeploymentView `json:"deployments,omitempty"`
		Documents   []AccessDocumentView   `json:"documents,omitempty"`
		Versions    []AccessVersionView    `json:"versions,omitempty"`
	}
	// AccessIssue is one preview warning or blocker.
	AccessIssue struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Field   string `json:"field,omitempty"`
	}
	// AccessPreview is POST /preview: nothing is stored.
	AccessPreview struct {
		Sentence     string               `json:"sentence"`
		Documents    []AccessDocumentView `json:"documents"`
		AlsoAffected []AccessAlsoAffected `json:"also_affected"`
		Warnings     []AccessIssue        `json:"warnings"`
		Blockers     []AccessIssue        `json:"blockers"`
	}
	AccessAlsoAffected struct {
		IdentityAccountID uuid.UUID           `json:"identity_account_id"`
		Workloads         []AccessWorkloadRef `json:"workloads"`
	}
)

// accessPlan is a resolved intent.
type accessPlan struct {
	intent   igagov.AccessIntent
	hash     string
	target   igagov.AccessTarget
	resource AccessResourceView
	roles    []*r2Role
	doc      []byte
	docHash  string
	actions  []string
	res      []string
	usedBy   map[uuid.UUID][]AccessWorkloadRef
	warnings []AccessIssue
}

func accessFieldErr(err error) error {
	var fe *igagov.AccessFieldError
	if errors.As(err, &fe) {
		return govUnprocessable(GovCodeAccessInvalid, fe.Message, map[string]any{"field": fe.Field})
	}
	return err
}

// plan resolves the intent in the token's workspace. strict: binding and
// quota refusals are errors (create, edit, resume); otherwise the caller
// turns them into preview blockers.
func (s *GovAccess) plan(ctx context.Context, ws uuid.UUID, in igagov.AccessIntent, now time.Time) (*accessPlan, error) {
	norm, err := igagov.NormalizeAccessIntent(in, now)
	if err != nil {
		return nil, accessFieldErr(err)
	}
	p := &accessPlan{intent: norm}
	if p.hash, err = igagov.AccessIntentHash(norm); err != nil {
		return nil, err
	}
	// The bucket: a Discovery resource of this workspace naming an S3
	// bucket, and the accounts whose scans name it (an S3 ARN names no
	// account).
	var rows []models.IGAResource
	var seenBy []uuid.UUID
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(db *gorm.DB) error {
		if err := db.Where("workspace_id = ? AND id = ?", ws, norm.Resource.ResourceID).Limit(1).Find(&rows).Error; err != nil {
			return err
		}
		return db.Table("iga_object_support").Where("workspace_id = ? AND resource_id = ? AND state = ? AND connector_id IS NOT NULL",
			ws, norm.Resource.ResourceID, "current").Distinct().Pluck("connector_id", &seenBy).Error
	}); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, govErr(http.StatusNotFound, GovCodeResourceNotFound, "No such resource in this workspace.",
			map[string]any{"field": "resource.resource_id"})
	}
	t, ok := igagov.ParseAccessResourceARN(rows[0].DisplayName)
	if !ok || rows[0].Provider != models.ProviderAWS {
		return nil, govUnprocessable(GovCodeResourceNotSupported, "Only S3 buckets, DynamoDB tables and SSM parameters are supported.",
			map[string]any{"field": "resource.resource_id", "resource_kind": rows[0].ResourceKind})
	}
	if err := igagov.ValidateAccessTarget(norm, t); err != nil {
		return nil, accessFieldErr(err)
	}
	t.Prefix = norm.Resource.Prefix
	p.target = t
	p.resource = accessResourceView(norm.Resource.ResourceID, t)

	seen := map[uuid.UUID]bool{}
	for _, c := range seenBy {
		seen[c] = true
	}
	for i, r := range norm.Roles {
		role, err := s.r2.resolveRole(ctx, ws, GovR2RoleKey{IdentityAccountID: r.IdentityAccountID})
		if err != nil {
			var ge *GovError
			if errors.As(err, &ge) {
				if ge.Detail == nil {
					ge.Detail = map[string]any{}
				}
				ge.Detail["field"] = fmt.Sprintf("roles[%d].identity_account_id", i)
			}
			return nil, err
		}
		// An S3 ARN names no account: the bucket must have been seen in the
		// role's account. A table or parameter ARN names its account.
		switch {
		case t.Service == igagov.AccessServiceS3 && !seen[role.Connector]:
			return nil, govUnprocessable(GovCodeRoleNotInAccount,
				"AuthSec has not seen this bucket in the role's AWS account "+role.Identity.AccountID+".",
				map[string]any{"field": fmt.Sprintf("roles[%d].identity_account_id", i), "account_id": role.Identity.AccountID})
		case t.Service != igagov.AccessServiceS3 && role.Identity.AccountID != t.Account:
			return nil, govUnprocessable(GovCodeRoleNotInAccount,
				"The "+t.Display()+" is in AWS account "+t.Account+"; the role is in "+role.Identity.AccountID+".",
				map[string]any{"field": fmt.Sprintf("roles[%d].identity_account_id", i), "account_id": role.Identity.AccountID})
		}
		p.roles = append(p.roles, role)
	}
	if len(p.roles) > 0 && p.resource.AccountID == "" {
		p.resource.AccountID = p.roles[0].Identity.AccountID
	}

	end := norm.EndsAt
	if end == nil {
		end = &igagov.AccessNoEnd
	}
	p.doc, p.docHash, p.actions, p.res, err = igagov.AccessDocument(norm.Effect, norm.Access, t, norm.StartsAt, end)
	if err != nil {
		return nil, govUnprocessable(GovCodeAccessInvalid, err.Error(), nil)
	}
	if norm.Effect == igagov.AccessEffectAllow {
		if esc := igagov.GrantEscalations(p.actions, p.res); len(esc) > 0 {
			return nil, govUnprocessable(GovCodeAccessInvalid, "These actions can escalate privilege.",
				map[string]any{"field": "access", "escalations": esc})
		}
	}
	if p.usedBy, err = s.usedBy(ctx, ws, p.roleIDs()); err != nil {
		return nil, err
	}
	if norm.Effect == igagov.AccessEffectAllow && t.Service == igagov.AccessServiceS3 {
		p.warnings = append(p.warnings, AccessIssue{Code: "allow_needs_bucket_policy",
			Message: "If the bucket is in another AWS account, its bucket policy must allow the role as well."})
	}
	if t.Service == igagov.AccessServiceSSM && !t.IsPath() {
		p.warnings = append(p.warnings, AccessIssue{Code: "ssm_path_reads",
			Message: "Reading a parent path (GetParametersByPath) is authorised on that path, not on this parameter, so it is not covered."})
	}
	p.warnings = append(p.warnings, AccessIssue{Code: "other_paths",
		Message: "This changes only the chosen roles. Other roles, users, groups and resource policies (bucket or table policies) are unchanged."})
	return p, nil
}

// accessResourceView describes the target for the UI.
func accessResourceView(resourceID string, t igagov.AccessTarget) AccessResourceView {
	v := AccessResourceView{ResourceID: resourceID, Service: t.Service, Name: t.Name, ARN: t.ResourceARN(), Prefix: t.Prefix,
		Region: t.Region, AccountID: t.Account}
	if t.Service == igagov.AccessServiceS3 {
		v.Bucket = t.Name
	}
	return v
}

func (p *accessPlan) roleIDs() []uuid.UUID {
	out := make([]uuid.UUID, 0, len(p.roles))
	for _, r := range p.roles {
		out = append(out, r.Identity.ID)
	}
	return out
}

// usedBy lists the workloads that run as each role (Discovery's used-by).
func (s *GovAccess) usedBy(ctx context.Context, ws uuid.UUID, ids []uuid.UUID) (map[uuid.UUID][]AccessWorkloadRef, error) {
	var out map[uuid.UUID][]AccessWorkloadRef
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		out, err = usedByTx(tx, ws, ids)
		return err
	})
	return out, err
}

func usedByTx(tx *gorm.DB, ws uuid.UUID, ids []uuid.UUID) (map[uuid.UUID][]AccessWorkloadRef, error) {
	out := map[uuid.UUID][]AccessWorkloadRef{}
	for _, id := range ids {
		out[id] = []AccessWorkloadRef{}
	}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []struct {
		TargetIdentityAccountID uuid.UUID
		ID                      uuid.UUID
		DisplayName             string
		RuntimeKind             string
	}
	if err := tx.Table("iga_relationship AS r").
		Select("r.target_identity_account_id, w.id, w.display_name, w.runtime_kind").
		Joins("JOIN iga_workload AS w ON w.workspace_id = r.workspace_id AND w.id = r.source_workload_id").
		Where("r.workspace_id = ? AND r.target_identity_account_id IN ? AND r.relationship_type IN ? AND r.state = ?",
			ws, ids, []string{models.RelTypeExecutesAs, models.RelTypeTaskExecutionRole}, "current").
		Order("w.display_name").Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.TargetIdentityAccountID] = append(out[r.TargetIdentityAccountID], AccessWorkloadRef{ID: r.ID, Name: r.DisplayName, Kind: r.RuntimeKind})
	}
	return out, nil
}

// accessBindingErr maps the v2 binding refusals onto the access-policy codes.
func accessBindingErr(err error) error {
	var ge *GovError
	if !errors.As(err, &ge) {
		return err
	}
	code := ge.Code
	switch ge.Code {
	case GovCodeEnforcementNotEnabled:
		code = GovCodeBindingMissing
	case GovCodeBindingCapabilityGone:
		code = GovCodeBindingNotVerifiedR2
	}
	return govErr(ge.Status, code, ge.Message, ge.Detail)
}

// checks runs the binding (v2, verified, grants capability) and quota
// checks of every role; extra is the slots an edit needs beside the old
// version's policy (1 per role).
func (s *GovAccess) checks(ctx context.Context, ws uuid.UUID, p *accessPlan) []error {
	var errs []error
	done := map[uuid.UUID]bool{}
	for _, r := range p.roles {
		if !done[r.Connector] {
			done[r.Connector] = true
			if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
				return RequireEnforcementV2(ctx, tx, ws, r.Connector, EnforcementFeatureGrants)
			}); err != nil {
				errs = append(errs, accessBindingErr(err))
			}
		}
	}
	for i, r := range p.roles {
		n, err := s.attachedCount(ctx, ws, r.Connector, r.Identity.ARN)
		if err != nil {
			p.warnings = append(p.warnings, AccessIssue{Code: "quota_unchecked",
				Message: "AuthSec could not read how many policies " + r.Identity.Name + " has attached: " + err.Error()})
			continue
		}
		if n >= accessAttachedQuota {
			errs = append(errs, govUnprocessable(GovCodeRolePolicyQuota,
				fmt.Sprintf("%s already has %d managed policies attached, the IAM limit.", r.Identity.Name, n),
				map[string]any{"field": fmt.Sprintf("roles[%d].identity_account_id", i), "attached": n}))
		}
	}
	return errs
}

func (s *GovAccess) attachedCount(ctx context.Context, ws, connector uuid.UUID, roleARN string) (int, error) {
	if s.attached != nil {
		return s.attached(ctx, ws, connector, roleARN)
	}
	env := r2Env()
	if env.AWS == nil {
		return 0, errors.New("AWS access is not configured")
	}
	disc, err := env.AWS.DiscoveryIAM(ctx, ws, connector)
	if err != nil {
		return 0, err
	}
	role, err := awsenforce.ReadRole(ctx, disc, roleNameOfARN(roleARN))
	if err != nil {
		return 0, err
	}
	if role == nil {
		return 0, errors.New("the role was not found in AWS")
	}
	return len(role.ManagedPolicies), nil
}

func issueOf(err error) AccessIssue {
	var ge *GovError
	if errors.As(err, &ge) {
		f, _ := ge.Detail["field"].(string)
		return AccessIssue{Code: ge.Code, Message: ge.Message, Field: f}
	}
	return AccessIssue{Code: "internal", Message: err.Error()}
}

// Preview is POST /preview: the sentence, the documents, the workloads each
// role runs, warnings and blockers. Nothing is stored.
func (s *GovAccess) Preview(ctx context.Context, ws uuid.UUID, in igagov.AccessIntent) (*AccessPreview, error) {
	if err := s.require(); err != nil {
		return nil, err
	}
	out := &AccessPreview{Documents: []AccessDocumentView{}, AlsoAffected: []AccessAlsoAffected{}, Warnings: []AccessIssue{}, Blockers: []AccessIssue{}}
	p, err := s.plan(ctx, ws, in, s.now())
	if err != nil {
		var ge *GovError
		if errors.As(err, &ge) && ge.Status < 500 {
			out.Blockers = append(out.Blockers, issueOf(err))
			return out, nil
		}
		return nil, err
	}
	for _, e := range s.checks(ctx, ws, p) {
		out.Blockers = append(out.Blockers, issueOf(e))
	}
	names := make([]string, 0, len(p.roles))
	for _, r := range p.roles {
		names = append(names, r.Identity.Name)
		out.Documents = append(out.Documents, AccessDocumentView{IdentityAccountID: r.Identity.ID, RoleName: r.Identity.Name,
			PolicyName: igagov.AccessPolicyName(r.Identity.RoleID, "00000000-0000-0000-0000-000000000000", 1), Document: p.doc})
		out.AlsoAffected = append(out.AlsoAffected, AccessAlsoAffected{IdentityAccountID: r.Identity.ID, Workloads: p.usedBy[r.Identity.ID]})
	}
	out.Sentence = igagov.AccessSentence(p.intent, p.target, names)
	out.Warnings = append(out.Warnings, p.warnings...)
	return out, nil
}

func accessNameReason(name, reason string) (string, string, error) {
	name, reason = strings.TrimSpace(name), strings.TrimSpace(reason)
	if name == "" || len([]rune(name)) > igagov.MaxAccessNameChars {
		return "", "", govUnprocessable(GovCodeAccessInvalid, "A name of 1 to 200 characters is required.", map[string]any{"field": "name"})
	}
	if reason == "" {
		return "", "", govUnprocessable(GovCodeAccessInvalid, "A reason is required.", map[string]any{"field": "reason"})
	}
	return name, reason, nil
}

// deployTx writes one approved deployment row per role of the version and
// queues its job.
func (s *GovAccess) deployTx(tx *gorm.DB, ws, actor, policyID uuid.UUID, v *models.IGAGovAccessPolicyVersion, p *accessPlan, reason string, now time.Time) error {
	if err := archiveDocumentTx(tx, ws, string(p.doc), p.docHash); err != nil {
		return err
	}
	exp := igagov.AccessNoEnd
	if p.intent.EndsAt != nil {
		exp = *p.intent.EndsAt
	}
	effect := "allow"
	if p.intent.Effect == igagov.AccessEffectBlock {
		effect = "deny"
	}
	acts, _ := json.Marshal(p.actions)
	res, _ := json.Marshal(p.res)
	for _, r := range p.roles {
		name := igagov.AccessPolicyName(r.Identity.RoleID, policyID.String(), v.VersionNo)
		h, err := igagov.AccessDeploymentHash(r.Identity.RoleID, r.Identity.AccountID, v.ID.String(), p.docHash)
		if err != nil {
			return err
		}
		pid, vid, decided := policyID, v.ID, actor
		row := models.IGAGovTempGrant{ID: uuid.New(), WorkspaceID: ws, ConnectorID: r.Connector, IdentityAccountID: r.Identity.ID,
			AccountID: r.Identity.AccountID, RoleID: r.Identity.RoleID, RoleARN: r.Identity.ARN, Actions: acts, Resources: res,
			Escalations: json.RawMessage(`[]`), Reason: reason, ExpiresAt: exp, PolicyName: name,
			PolicyARN: igagov.GrantPolicyARN(arnPartition(r.Identity.ARN), r.Identity.AccountID, name), DocumentHash: p.docHash,
			RequestHash: h, RequestKey: "access:" + v.ID.String() + ":" + r.Identity.RoleID, State: models.R2StateApproved,
			RequestedBy: actor, DecidedBy: &decided, DecidedAt: &now, DecisionReason: "applied by a workspace admin",
			ApprovedRequestHash: &h, Ops: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now,
			Effect: effect, PolicyID: &pid, VersionID: &vid, StartsAt: p.intent.StartsAt}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		if err := r2EnqueueTx(tx, ws, r2GrantKind, row.ID, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *GovAccess) event(tx *gorm.DB, ws uuid.UUID, name string, actor uuid.UUID, policyID uuid.UUID, versionID *uuid.UUID, payload map[string]any) error {
	kind, id := userActor(actor)
	pid := policyID
	return appendGovEvent(tx, ws, name, kind, id, govEventRefs{PolicyID: &pid, VersionID: versionID}, payload)
}

// Create is POST / (governance:enforce): validate, resolve, check the
// binding and the quota, then write the policy, version 1 and its
// deployments, and queue them. The admin's apply is the decision.
func (s *GovAccess) Create(ctx context.Context, ws, actor uuid.UUID, req AccessPolicyRequest) (*AccessPolicyView, error) {
	if err := s.require(); err != nil {
		return nil, err
	}
	name, reason, err := accessNameReason(req.Name, req.Reason)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC().Truncate(time.Second)
	p, err := s.plan(ctx, ws, req.AccessIntent, now)
	if err != nil {
		return nil, err
	}
	if errs := s.checks(ctx, ws, p); len(errs) > 0 {
		return nil, errs[0]
	}
	intent, _ := json.Marshal(p.intent)
	pol := models.IGAGovPolicy{ID: uuid.New(), WorkspaceID: ws, Name: name, Purpose: reason, Family: "time_bound", Provider: "aws",
		Lifecycle: "active", CreatedBy: actor, CreatedAt: now, UpdatedAt: now}
	v := models.IGAGovAccessPolicyVersion{ID: uuid.New(), WorkspaceID: ws, PolicyID: pol.ID, VersionNo: 1, Intent: intent,
		IntentHash: p.hash, Status: models.AccessVersionApplied, CreatedBy: actor, CreatedAt: now, StatusChangedAt: now}
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := tx.Create(&pol).Error; err != nil {
			if isUniqueViolation(err, "iga_gov_policy_workspace_id_name_key") {
				return govConflict(GovCodeNameTaken, "A policy with that name already exists.", map[string]any{"field": "name"})
			}
			return err
		}
		if err := tx.Create(&v).Error; err != nil {
			return err
		}
		if err := s.event(tx, ws, GovEventAccessCreated, actor, pol.ID, &v.ID, map[string]any{"name": name, "reason": reason,
			"intent": p.intent, "intent_hash": p.hash}); err != nil {
			return err
		}
		if err := s.deployTx(tx, ws, actor, pol.ID, &v, p, reason, now); err != nil {
			return err
		}
		return s.event(tx, ws, GovEventAccessApplied, actor, pol.ID, &v.ID, map[string]any{"version_no": 1, "roles": len(p.roles),
			"document_hash": p.docHash})
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, ws, pol.ID)
}

// loadPolicy is one access policy of ws (another workspace's, another
// family's or a missing one is 404).
func (s *GovAccess) loadPolicy(db *gorm.DB, ws, id uuid.UUID, lock bool) (*models.IGAGovPolicy, error) {
	q := db.Where("workspace_id = ? AND id = ? AND family = ?", ws, id, "time_bound")
	if lock {
		q = q.Clauses(lockForUpdate())
	}
	var rows []models.IGAGovPolicy
	if err := q.Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

// policy is loadPolicy in its own read-only workspace transaction.
func (s *GovAccess) policy(ctx context.Context, ws, id uuid.UUID) (*models.IGAGovPolicy, error) {
	var out *models.IGAGovPolicy
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		out, err = s.loadPolicy(tx, ws, id, false)
		return err
	})
	return out, err
}

func (s *GovAccess) currentVersion(db *gorm.DB, ws, policyID uuid.UUID) (*models.IGAGovAccessPolicyVersion, error) {
	var rows []models.IGAGovAccessPolicyVersion
	if err := db.Where("workspace_id = ? AND policy_id = ? AND status = ?", ws, policyID, models.AccessVersionApplied).
		Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

// liveStates are a deployment row's states while its policy may be on AWS.
var accessLiveStates = []string{models.R2StateApproved, models.R2StateDeploying, models.R2StateActive,
	models.R2StateOutcomeUnknown, models.R2StateExpiring}

// endRowsTx ends every live deployment of the policy (all versions, or all
// but keep): approved rows end at once (never deployed), the others are
// detached and deleted by their job.
func endRowsTx(tx *gorm.DB, ws, policyID uuid.UUID, keep *uuid.UUID, reason string, actor *uuid.UUID, now time.Time) (int, error) {
	q := tx.Where("workspace_id = ? AND policy_id = ? AND state IN ?", ws, policyID, accessLiveStates)
	if keep != nil {
		q = q.Where("version_id <> ?", *keep)
	}
	var rows []models.IGAGovTempGrant
	if err := q.Clauses(lockForUpdate()).Find(&rows).Error; err != nil {
		return 0, err
	}
	n := 0
	for _, g := range rows {
		set := map[string]any{"end_reason": reason, "ended_by": actor, "updated_at": now}
		switch g.State {
		case models.R2StateApproved:
			set["state"], set["ended_at"] = models.R2StateRevoked, now
		case models.R2StateExpiring:
			continue // already ending
		default:
			set["state"] = models.R2StateExpiring
		}
		if err := tx.Model(&models.IGAGovTempGrant{}).Where("workspace_id = ? AND id = ? AND state = ?", ws, g.ID, g.State).
			Updates(set).Error; err != nil {
			return n, err
		}
		if set["state"] == models.R2StateExpiring {
			if err := r2EnqueueTx(tx, ws, r2GrantKind, g.ID, now); err != nil {
				return n, err
			}
		}
		n++
	}
	return n, nil
}

// accessAfterActiveTx runs when a deployment row turned active: once every
// row of the current version is active, the older versions' rows end
// (superseded). Called in the job's transaction.
func accessAfterActiveTx(tx *gorm.DB, ws, rowID uuid.UUID) error {
	var g models.IGAGovTempGrant
	if err := tx.Where("workspace_id = ? AND id = ?", ws, rowID).Take(&g).Error; err != nil {
		return err
	}
	if g.PolicyID == nil || g.VersionID == nil {
		return nil
	}
	var v []models.IGAGovAccessPolicyVersion
	if err := tx.Where("workspace_id = ? AND id = ? AND status = ?", ws, *g.VersionID, models.AccessVersionApplied).
		Limit(1).Find(&v).Error; err != nil || len(v) == 0 {
		return err
	}
	var pending int64
	if err := tx.Model(&models.IGAGovTempGrant{}).Where("workspace_id = ? AND policy_id = ? AND version_id = ? AND state <> ?",
		ws, *g.PolicyID, *g.VersionID, models.R2StateActive).Count(&pending).Error; err != nil {
		return err
	}
	if pending > 0 {
		return nil
	}
	_, err := endRowsTx(tx, ws, *g.PolicyID, g.VersionID, accessEndSuperseded, nil, time.Now().UTC())
	return err
}

// Edit is POST /:id/versions (governance:enforce): a new version, deployed
// beside the current one, which ends once the new one is verified.
func (s *GovAccess) Edit(ctx context.Context, ws, actor, id uuid.UUID, req AccessPolicyRequest) (*AccessPolicyView, error) {
	if err := s.require(); err != nil {
		return nil, err
	}
	name, reason, err := accessNameReason(req.Name, req.Reason)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC().Truncate(time.Second)
	pol, err := s.policy(ctx, ws, id)
	if err != nil {
		return nil, err
	}
	if pol.Lifecycle == "archived" {
		return nil, govConflict(GovCodePolicyEnded, "This policy has ended; create a new one.", nil)
	}
	p, err := s.plan(ctx, ws, req.AccessIntent, now)
	if err != nil {
		return nil, err
	}
	if pol.Lifecycle == "active" {
		if errs := s.checks(ctx, ws, p); len(errs) > 0 {
			return nil, errs[0]
		}
	}
	intent, _ := json.Marshal(p.intent)
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		pol, err := s.loadPolicy(tx, ws, id, true)
		if err != nil {
			return err
		}
		if pol.Lifecycle == "archived" {
			return govConflict(GovCodePolicyEnded, "This policy has ended; create a new one.", nil)
		}
		cur, err := s.currentVersion(tx, ws, id)
		if err != nil {
			return err
		}
		if req.BaseVersionNo != cur.VersionNo {
			return govConflict(GovCodeVersionConflict, "The policy changed since you opened it.",
				map[string]any{"field": "base_version_no", "current_version_no": cur.VersionNo})
		}
		if err := tx.Model(&models.IGAGovAccessPolicyVersion{}).Where("workspace_id = ? AND id = ? AND status = ?", ws, cur.ID, models.AccessVersionApplied).
			Updates(map[string]any{"status": models.AccessVersionSuperseded, "status_changed_at": now}).Error; err != nil {
			return err
		}
		v := models.IGAGovAccessPolicyVersion{ID: uuid.New(), WorkspaceID: ws, PolicyID: id, VersionNo: cur.VersionNo + 1, Intent: intent,
			IntentHash: p.hash, Status: models.AccessVersionApplied, CreatedBy: actor, CreatedAt: now, StatusChangedAt: now}
		if err := tx.Create(&v).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.IGAGovPolicy{}).Where("workspace_id = ? AND id = ?", ws, id).
			Updates(map[string]any{"name": name, "purpose": reason, "updated_at": now}).Error; err != nil {
			if isUniqueViolation(err, "iga_gov_policy_workspace_id_name_key") {
				return govConflict(GovCodeNameTaken, "A policy with that name already exists.", map[string]any{"field": "name"})
			}
			return err
		}
		if err := s.event(tx, ws, GovEventAccessEdited, actor, id, &v.ID, map[string]any{"from_version_no": cur.VersionNo,
			"version_no": v.VersionNo, "name": name, "reason": reason, "intent": p.intent, "intent_hash": p.hash}); err != nil {
			return err
		}
		if pol.Lifecycle != "active" {
			return nil // paused: Resume deploys the current version
		}
		if err := s.deployTx(tx, ws, actor, id, &v, p, reason, now); err != nil {
			return err
		}
		return s.event(tx, ws, GovEventAccessApplied, actor, id, &v.ID, map[string]any{"version_no": v.VersionNo, "roles": len(p.roles),
			"document_hash": p.docHash})
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, ws, id)
}

// Pause is POST /:id/pause: the policy is removed from AWS for every role.
func (s *GovAccess) Pause(ctx context.Context, ws, actor, id uuid.UUID, req AccessReasonRequest) (*AccessPolicyView, error) {
	return s.stop(ctx, ws, actor, id, req, "paused")
}

// End is POST /:id/end: removed from AWS for good; the record is kept.
func (s *GovAccess) End(ctx context.Context, ws, actor, id uuid.UUID, req AccessReasonRequest) (*AccessPolicyView, error) {
	return s.stop(ctx, ws, actor, id, req, "archived")
}

func (s *GovAccess) stop(ctx context.Context, ws, actor, id uuid.UUID, req AccessReasonRequest, to string) (*AccessPolicyView, error) {
	if err := s.require(); err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return nil, govUnprocessable(GovCodeAccessInvalid, "A reason is required.", map[string]any{"field": "reason"})
	}
	now := s.now().UTC()
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		pol, err := s.loadPolicy(tx, ws, id, true)
		if err != nil {
			return err
		}
		switch {
		case pol.Lifecycle == "archived":
			return govConflict(GovCodePolicyEnded, "This policy has already ended.", nil)
		case to == "paused" && pol.Lifecycle != "active":
			return govConflict(GovCodePolicyNotActive, "Only an active policy can be paused.", map[string]any{"lifecycle": pol.Lifecycle})
		}
		endReason, name := accessEndPaused, GovEventAccessPaused
		if to == "archived" {
			endReason, name = accessEndEnded, GovEventAccessEnded
		}
		n, err := endRowsTx(tx, ws, id, nil, endReason, &actor, now)
		if err != nil {
			return err
		}
		if err := tx.Model(&models.IGAGovPolicy{}).Where("workspace_id = ? AND id = ?", ws, id).
			Updates(map[string]any{"lifecycle": to, "updated_at": now}).Error; err != nil {
			return err
		}
		return s.event(tx, ws, name, actor, id, nil, map[string]any{"reason": reason, "deployments_ending": n})
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, ws, id)
}

// Resume is POST /:id/resume: the current version is deployed again, once
// the paused policy is off AWS.
func (s *GovAccess) Resume(ctx context.Context, ws, actor, id uuid.UUID, req AccessReasonRequest) (*AccessPolicyView, error) {
	if err := s.require(); err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return nil, govUnprocessable(GovCodeAccessInvalid, "A reason is required.", map[string]any{"field": "reason"})
	}
	now := s.now().UTC().Truncate(time.Second)
	pol, err := s.policy(ctx, ws, id)
	if err != nil {
		return nil, err
	}
	switch pol.Lifecycle {
	case "archived":
		return nil, govConflict(GovCodePolicyEnded, "This policy has ended; create a new one.", nil)
	case "active":
		return nil, govConflict(GovCodePolicyNotActive, "The policy is not paused.", map[string]any{"lifecycle": pol.Lifecycle})
	}
	var cur *models.IGAGovAccessPolicyVersion
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		cur, err = s.currentVersion(tx, ws, id)
		return err
	}); err != nil {
		return nil, err
	}
	var in igagov.AccessIntent
	if err := json.Unmarshal(cur.Intent, &in); err != nil {
		return nil, err
	}
	if in.EndsAt != nil && !in.EndsAt.After(now.Add(igagov.MinAccessWindow)) {
		return nil, govUnprocessable(GovCodeAccessInvalid, "The policy's window has ended; edit it to set a new one.", map[string]any{"field": "ends_at"})
	}
	if in.StartsAt != nil && in.StartsAt.Before(now) {
		in.StartsAt = nil // already started; NormalizeAccessIntent refuses a past start
	}
	p, err := s.plan(ctx, ws, in, now)
	if err != nil {
		return nil, err
	}
	if errs := s.checks(ctx, ws, p); len(errs) > 0 {
		return nil, errs[0]
	}
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		pol, err := s.loadPolicy(tx, ws, id, true)
		if err != nil {
			return err
		}
		if pol.Lifecycle != "paused" {
			return govConflict(GovCodePolicyNotActive, "The policy is not paused.", map[string]any{"lifecycle": pol.Lifecycle})
		}
		var live int64
		if err := tx.Model(&models.IGAGovTempGrant{}).Where("workspace_id = ? AND policy_id = ? AND state IN ?", ws, id, accessLiveStates).
			Count(&live).Error; err != nil {
			return err
		}
		if live > 0 {
			return govConflict(GovCodePolicyBusy, "AuthSec is still removing the paused policy from AWS; try again in a minute.", nil)
		}
		cur, err := s.currentVersion(tx, ws, id)
		if err != nil {
			return err
		}
		if err := tx.Model(&models.IGAGovPolicy{}).Where("workspace_id = ? AND id = ?", ws, id).
			Updates(map[string]any{"lifecycle": "active", "updated_at": now}).Error; err != nil {
			return err
		}
		if err := s.deployTx(tx, ws, actor, id, cur, p, pol.Purpose, now); err != nil {
			return err
		}
		return s.event(tx, ws, GovEventAccessResumed, actor, id, &cur.ID, map[string]any{"reason": reason, "version_no": cur.VersionNo})
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, ws, id)
}

/* ---------------------------------------------------------------------------- */
/*                                   Reads                                      */
/* ---------------------------------------------------------------------------- */

// accessBundle is one policy's rows.
type accessBundle struct {
	pol      models.IGAGovPolicy
	versions []models.IGAGovAccessPolicyVersion
	rows     []models.IGAGovTempGrant
}

func (s *GovAccess) bundles(ctx context.Context, ws uuid.UUID, ids []uuid.UUID, q string) ([]*accessBundle, error) {
	out := []*accessBundle{}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(db *gorm.DB) error {
		var err error
		out, err = loadAccessBundles(db, ws, ids, q)
		return err
	})
	return out, err
}

// loadAccessBundles reads the policies, versions and deployments (in the
// caller's workspace transaction).
func loadAccessBundles(db *gorm.DB, ws uuid.UUID, ids []uuid.UUID, q string) ([]*accessBundle, error) {
	pq := db.Where("workspace_id = ? AND family = ?", ws, "time_bound")
	if ids != nil {
		pq = pq.Where("id IN ?", ids)
	}
	if q = strings.TrimSpace(q); q != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(q) + "%"
		pq = pq.Where("(name ILIKE ? OR purpose ILIKE ?)", like, like)
	}
	var pols []models.IGAGovPolicy
	if err := pq.Order("created_at DESC, id DESC").Limit(accessMaxList).Find(&pols).Error; err != nil {
		return nil, err
	}
	out := make([]*accessBundle, 0, len(pols))
	if len(pols) == 0 {
		return out, nil
	}
	pids := make([]uuid.UUID, 0, len(pols))
	by := map[uuid.UUID]*accessBundle{}
	for _, p := range pols {
		b := &accessBundle{pol: p}
		out = append(out, b)
		by[p.ID] = b
		pids = append(pids, p.ID)
	}
	var vers []models.IGAGovAccessPolicyVersion
	if err := db.Where("workspace_id = ? AND policy_id IN ?", ws, pids).Order("version_no").Find(&vers).Error; err != nil {
		return nil, err
	}
	for _, v := range vers {
		by[v.PolicyID].versions = append(by[v.PolicyID].versions, v)
	}
	var rows []models.IGAGovTempGrant
	if err := db.Where("workspace_id = ? AND policy_id IN ?", ws, pids).Order("created_at").Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		by[*r.PolicyID].rows = append(by[*r.PolicyID].rows, r)
	}
	return out, nil
}

func (b *accessBundle) current() (*models.IGAGovAccessPolicyVersion, igagov.AccessIntent) {
	var in igagov.AccessIntent
	for i := len(b.versions) - 1; i >= 0; i-- {
		if b.versions[i].Status == models.AccessVersionApplied {
			_ = json.Unmarshal(b.versions[i].Intent, &in)
			return &b.versions[i], in
		}
	}
	return nil, in
}

func accessTerminal(state string) bool {
	switch state {
	case models.R2StateExpired, models.R2StateRevoked, models.R2StateFailed, models.R2StateRejected, models.R2StateCancelled:
		return true
	}
	return false
}

// status works out the UI status from the lifecycle, the current version's
// deployments and the window.
func accessStatus(b *accessBundle, now time.Time) (status, reason, endReason string, endedAt *time.Time) {
	cur, in := b.current()
	latestEnd := func(rows []models.IGAGovTempGrant) *time.Time {
		var t *time.Time
		for _, r := range rows {
			if r.EndedAt != nil && (t == nil || r.EndedAt.After(*t)) {
				t = r.EndedAt
			}
		}
		return t
	}
	removing := false
	for _, r := range b.rows {
		if !accessTerminal(r.State) {
			removing = removing || r.EndReason != ""
		}
	}
	switch b.pol.Lifecycle {
	case "archived":
		t := latestEnd(b.rows)
		if t == nil {
			u := b.pol.UpdatedAt
			t = &u
		}
		reason = ""
		if removing {
			reason = "removing from AWS"
		}
		return AccessStatusEnded, reason, accessEndEnded, t
	case "paused":
		if removing {
			return AccessStatusPaused, "removing from AWS", "", nil
		}
		return AccessStatusPaused, "", "", nil
	}
	var rows []models.IGAGovTempGrant
	if cur != nil {
		for _, r := range b.rows {
			if r.VersionID != nil && *r.VersionID == cur.ID {
				rows = append(rows, r)
			}
		}
	}
	if len(rows) == 0 {
		return AccessStatusFailed, "no deployment exists for the current version", "", nil
	}
	// The newest generation of rows (a Resume deploys the version again).
	gen := map[string]models.IGAGovTempGrant{}
	for _, r := range rows {
		gen[r.RoleID] = r
	}
	var failed, applying, drift []string
	allEnded, expired := true, true
	for _, r := range gen {
		switch r.State {
		case models.R2StateFailed:
			failed = append(failed, r.RoleARN+": "+r.StateReason)
		case models.R2StateApproved, models.R2StateDeploying, models.R2StateOutcomeUnknown:
			applying = append(applying, r.RoleARN)
		case models.R2StateActive:
			if r.Drift != "" && r.Drift != R2ReasonAttachedElsewhere {
				drift = append(drift, r.RoleARN+": "+r.Drift)
			}
		}
		if !accessTerminal(r.State) {
			allEnded = false
		}
		if r.EndReason != r2EndReasonExpired && r.EndReason != r2EndReasonNeverDeployed {
			expired = false
		}
	}
	sort.Strings(failed)
	sort.Strings(applying)
	sort.Strings(drift)
	ended := in.EndsAt != nil && !now.Before(*in.EndsAt)
	switch {
	case allEnded && (expired || ended):
		return AccessStatusEnded, "", r2EndReasonExpired, latestEnd(rows)
	case len(failed) > 0:
		return AccessStatusFailed, strings.Join(failed, "; "), "", nil
	case ended:
		return AccessStatusEnded, "removing from AWS", r2EndReasonExpired, nil
	case len(applying) > 0:
		return AccessStatusApplying, "applying to " + strings.Join(applying, ", "), "", nil
	case len(drift) > 0:
		return AccessStatusDrift, strings.Join(drift, "; "), "", nil
	case in.StartsAt != nil && now.Before(*in.StartsAt):
		return AccessStatusScheduled, "", "", nil
	}
	return AccessStatusActive, "", "", nil
}

// views builds the views of bundles; detail adds deployments, documents and
// versions.
func (s *GovAccess) views(ctx context.Context, ws uuid.UUID, bs []*accessBundle, detail bool) ([]AccessPolicyView, error) {
	now := s.now().UTC()
	var out []AccessPolicyView
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(db *gorm.DB) error {
		var err error
		out, err = s.viewsTx(ctx, db, ws, bs, detail, now)
		return err
	})
	return out, err
}

func (s *GovAccess) viewsTx(ctx context.Context, db *gorm.DB, ws uuid.UUID, bs []*accessBundle, detail bool, now time.Time) ([]AccessPolicyView, error) {
	// Names: creators (members) and role identities.
	var users []uuid.UUID
	idents := map[uuid.UUID]bool{}
	for _, b := range bs {
		users = append(users, b.pol.CreatedBy)
		for _, v := range b.versions {
			users = append(users, v.CreatedBy)
		}
		_, in := b.current()
		for _, r := range in.Roles {
			if id, err := uuid.Parse(r.IdentityAccountID); err == nil {
				idents[id] = true
			}
		}
	}
	members, err := WorkspaceMemberDirectory{}.ActiveMembers(db, ws, users)
	if err != nil {
		return nil, err
	}
	nameOf := func(u uuid.UUID) AccessUserRef {
		m := members[u]
		n := m.Name
		if n == "" {
			n = m.Email
		}
		return AccessUserRef{ID: u, Name: n}
	}
	ids := make([]uuid.UUID, 0, len(idents))
	for id := range idents {
		ids = append(ids, id)
	}
	type identRow struct {
		ID          uuid.UUID
		DisplayName string
	}
	var irows []identRow
	if len(ids) > 0 {
		if err := db.Table("iga_identity_accounts").Select("id, display_name").Where("workspace_id = ? AND id IN ?", ws, ids).
			Scan(&irows).Error; err != nil {
			return nil, err
		}
	}
	identName := map[uuid.UUID]string{}
	for _, r := range irows {
		identName[r.ID] = r.DisplayName
	}
	usedBy, err := usedByTx(db, ws, ids)
	if err != nil {
		return nil, err
	}
	// Bucket ARNs of the resources.
	resIDs := map[string]bool{}
	for _, b := range bs {
		_, in := b.current()
		resIDs[in.Resource.ResourceID] = true
	}
	var rids []string
	for id := range resIDs {
		if id != "" {
			rids = append(rids, id)
		}
	}
	var resRows []models.IGAResource
	if len(rids) > 0 {
		if err := db.Where("workspace_id = ? AND id IN ?", ws, rids).Find(&resRows).Error; err != nil {
			return nil, err
		}
	}
	resARN := map[string]string{}
	for _, r := range resRows {
		resARN[r.ID.String()] = r.DisplayName
	}

	out := make([]AccessPolicyView, 0, len(bs))
	for _, b := range bs {
		cur, in := b.current()
		v := AccessPolicyView{ID: b.pol.ID, Name: b.pol.Name, Reason: b.pol.Purpose, Effect: in.Effect, Access: in.Access,
			StartsAt: in.StartsAt, EndsAt: in.EndsAt, Lifecycle: b.pol.Lifecycle, CreatedBy: nameOf(b.pol.CreatedBy),
			CreatedAt: b.pol.CreatedAt, UpdatedAt: b.pol.UpdatedAt, Roles: []AccessRoleView{}}
		if v.Access == nil {
			v.Access = []string{}
		}
		if cur != nil {
			v.VersionNo = cur.VersionNo
		}
		v.Status, v.StatusReason, v.EndReason, v.EndedAt = accessStatus(b, now)
		v.Resource = AccessResourceView{ResourceID: in.Resource.ResourceID, Prefix: in.Resource.Prefix}
		if t, ok := igagov.ParseAccessResourceARN(resARN[in.Resource.ResourceID]); ok {
			t.Prefix = in.Resource.Prefix
			v.Resource = accessResourceView(in.Resource.ResourceID, t)
		}
		// Roles: the intent's, with the ARN and account from its deployments.
		arnOf := map[uuid.UUID]models.IGAGovTempGrant{}
		for _, r := range b.rows {
			arnOf[r.IdentityAccountID] = r
		}
		for _, r := range in.Roles {
			id, _ := uuid.Parse(r.IdentityAccountID)
			rv := AccessRoleView{IdentityAccountID: id, Name: identName[id], UsedBy: usedBy[id]}
			if rv.UsedBy == nil {
				rv.UsedBy = []AccessWorkloadRef{}
			}
			if g, ok := arnOf[id]; ok {
				rv.ARN, rv.AccountID = g.RoleARN, g.AccountID
				if rv.Name == "" {
					rv.Name = roleNameOfARN(g.RoleARN)
				}
			}
			if v.Resource.AccountID == "" {
				v.Resource.AccountID = rv.AccountID
			}
			v.Roles = append(v.Roles, rv)
		}
		if detail {
			verNo := map[uuid.UUID]int{}
			v.Versions = []AccessVersionView{}
			for i := len(b.versions) - 1; i >= 0; i-- {
				x := b.versions[i]
				verNo[x.ID] = x.VersionNo
				v.Versions = append(v.Versions, AccessVersionView{VersionNo: x.VersionNo, CreatedBy: nameOf(x.CreatedBy),
					CreatedAt: x.CreatedAt, IntentHash: x.IntentHash, Status: x.Status})
			}
			v.Deployments = []AccessDeploymentView{}
			v.Documents = []AccessDocumentView{}
			docs := map[string]json.RawMessage{}
			for i := len(b.rows) - 1; i >= 0; i-- {
				r := b.rows[i]
				name := identName[r.IdentityAccountID]
				if name == "" {
					name = roleNameOfARN(r.RoleARN)
				}
				errText := ""
				if r.State == models.R2StateFailed || r.State == models.R2StateOutcomeUnknown {
					errText = r.StateReason
				}
				no := 0
				if r.VersionID != nil {
					no = verNo[*r.VersionID]
				}
				v.Deployments = append(v.Deployments, AccessDeploymentView{IdentityAccountID: r.IdentityAccountID, RoleName: name,
					VersionNo: no, State: r.State, AWSPolicyARN: r.PolicyARN, DocumentHash: r.DocumentHash, DeployedAt: r.DeployedAt,
					VerifiedAt: r.VerifiedAt, LastReadbackAt: r.LastReadbackAt, Drift: r.Drift, Error: errText, EndReason: r.EndReason})
				if cur != nil && r.VersionID != nil && *r.VersionID == cur.ID {
					if _, ok := docs[r.DocumentHash]; !ok {
						text, err := r2Document(db, ws, r.DocumentHash)
						if err != nil {
							return nil, err
						}
						docs[r.DocumentHash] = json.RawMessage(text)
					}
					v.Documents = append(v.Documents, AccessDocumentView{IdentityAccountID: r.IdentityAccountID, RoleName: name,
						PolicyName: r.PolicyName, Document: docs[r.DocumentHash]})
				}
			}
			v.Documents = dedupeDocs(v.Documents)
		}
		out = append(out, v)
	}
	return out, nil
}

// dedupeDocs keeps one document per role (the newest generation first).
func dedupeDocs(in []AccessDocumentView) []AccessDocumentView {
	seen := map[uuid.UUID]bool{}
	out := make([]AccessDocumentView, 0, len(in))
	for _, d := range in {
		if !seen[d.IdentityAccountID] {
			seen[d.IdentityAccountID] = true
			out = append(out, d)
		}
	}
	return out
}

// Get is GET /:id (404 across workspaces and families).
func (s *GovAccess) Get(ctx context.Context, ws, id uuid.UUID) (*AccessPolicyView, error) {
	if _, err := s.policy(ctx, ws, id); err != nil {
		return nil, err
	}
	bs, err := s.bundles(ctx, ws, []uuid.UUID{id}, "")
	if err != nil {
		return nil, err
	}
	if len(bs) == 0 {
		return nil, GovNotFound()
	}
	vs, err := s.views(ctx, ws, bs, true)
	if err != nil {
		return nil, err
	}
	return &vs[0], nil
}

// AccessListQuery is GET /.
type AccessListQuery struct {
	Status, Effect, Q, ResourceID, IdentityAccountID, Cursor string
	Limit                                                    int
}

// List is GET / (newest first; filters on status, effect, q, resource and
// role; an opaque offset cursor).
func (s *GovAccess) List(ctx context.Context, ws uuid.UUID, q AccessListQuery) ([]AccessPolicyView, string, error) {
	if q.Limit <= 0 || q.Limit > MaxGovPage {
		q.Limit = 50
	}
	off := 0
	if q.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(q.Cursor)
		if err == nil {
			off, err = strconv.Atoi(strings.TrimPrefix(string(raw), "o:"))
		}
		if err != nil || off < 0 {
			return nil, "", GovBadParam("cursor", "Malformed cursor.")
		}
	}
	bs, err := s.bundles(ctx, ws, nil, q.Q)
	if err != nil {
		return nil, "", err
	}
	vs, err := s.views(ctx, ws, bs, false)
	if err != nil {
		return nil, "", err
	}
	effect := strings.ToLower(strings.TrimSpace(q.Effect))
	filtered := make([]AccessPolicyView, 0, len(vs))
	for _, v := range vs {
		if q.Status != "" && v.Status != q.Status {
			continue
		}
		if effect != "" && v.Effect != effect {
			continue
		}
		if q.ResourceID != "" && !strings.EqualFold(v.Resource.ResourceID, q.ResourceID) {
			continue
		}
		if q.IdentityAccountID != "" {
			hit := false
			for _, r := range v.Roles {
				hit = hit || strings.EqualFold(r.IdentityAccountID.String(), q.IdentityAccountID)
			}
			if !hit {
				continue
			}
		}
		filtered = append(filtered, v)
	}
	if off > len(filtered) {
		off = len(filtered)
	}
	end := off + q.Limit
	next := ""
	if end < len(filtered) {
		next = base64.RawURLEncoding.EncodeToString([]byte("o:" + strconv.Itoa(end)))
	} else {
		end = len(filtered)
	}
	return filtered[off:end], next, nil
}

// AccessEventView is one history row.
type AccessEventView struct {
	ID         int64           `json:"id"`
	OccurredAt time.Time       `json:"occurred_at"`
	Event      string          `json:"event"`
	ActorKind  string          `json:"actor_kind"`
	ActorID    string          `json:"actor_id"`
	Payload    json.RawMessage `json:"payload"`
}

// Events is GET /:id/events (newest first, at most 500).
func (s *GovAccess) Events(ctx context.Context, ws, id uuid.UUID) ([]AccessEventView, error) {
	var rows []models.IGAGovEvent
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(db *gorm.DB) error {
		if _, err := s.loadPolicy(db, ws, id, false); err != nil {
			return err
		}
		return db.Where("workspace_id = ? AND policy_id = ? AND event LIKE ?", ws, id, "access_policy.%").
			Order("id DESC").Limit(500).Find(&rows).Error
	}); err != nil {
		return nil, err
	}
	out := make([]AccessEventView, 0, len(rows))
	for _, r := range rows {
		out = append(out, AccessEventView{ID: r.ID, OccurredAt: r.OccurredAt, Event: r.Event, ActorKind: r.ActorKind,
			ActorID: r.ActorID, Payload: json.RawMessage(r.Payload)})
	}
	return out, nil
}

// accessRow is an access deployment row for the R2 engine.
func accessRow(g *models.IGAGovTempGrant) r2Row {
	row := grantRow(g)
	row.Kind = r2AccessKind
	row.Extra = map[string]string{}
	if g.PolicyID != nil {
		row.Extra[igagov.TagAccessPolicy] = g.PolicyID.String()
	}
	if g.VersionID != nil {
		row.Extra[igagov.TagAccessVersion] = g.VersionID.String()
	}
	return row
}
