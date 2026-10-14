package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
)

// The R2 attached-policy engine (SPEC-iga-phase3-policy.md §12.3; DECISION
// R2-8, R2-11, R2-14): temporary grants and session revocations are both an
// AuthSec-owned managed policy under /authsec/, created and ATTACHED to one
// role, later detached and deleted. One engine converges a row to "present"
// (the policy exists with the approved document, AuthSec's tags, attached to
// the role's current incarnation) or "absent" (not attached to the role, and
// deleted unless another entity uses it), reusing R1a's pieces: the
// discovery-role reads (awsenforce.ReadRole / ReadPolicy, §3.5), the
// enforcement session of the binding (AWSEnforcementAccess, session name
// authsec-enforce-<row 16hex>), the archived documents (iga_gov_document,
// §2.11), igagov's response classification (§8.5), and the job fence (§8.1).
//
// DECISION R2-17 (write-ahead for R2): R1a's attempt log is keyed on
// iga_gov_deployment, which R2 rows are not. Each R2 row carries its own
// write-ahead marker: pending_op is set, fenced, immediately BEFORE an AWS
// write and cleared with its definitive answer. A marker a later run finds
// means "may have been sent": that run waits until settle_after (dispatch +
// 15 minutes, past the request-signature and session lifetimes, as §8.1),
// then re-reads AWS. Every R2 op is recognisable from a read (CreatePolicy:
// our tagged policy with the approved document; Attach / Detach: the role's
// attachment list; DeletePolicy: NoSuchEntity), so one fresh read after
// settle decides, and the engine continues from what AWS shows -- an op is
// never re-sent blindly. A no-answer is an explicit outcome_unknown state
// that holds the row until then (E-03).
//
// DECISION R2-18: drift is never auto-reconciled (§8.8): a present row whose
// policy was detached, deleted, edited or attached to another entity is
// reported (drift column, event) and keeps its state; at expiry / removal
// the engine still detaches it from this role, and leaves a policy another
// entity uses in place (it cannot change that entity without review).

// r2Kind is one of the two R2 row kinds.
type r2Kind struct {
	Name     string // temporary_grant | session_revocation
	Table    string
	Job      string
	TagKey   string // authsec:grant | authsec:revocation
	IDKey    string // event payload key
	Feature  string // enforcement v2 feature
	Notice   string // iga_gov_notification subject kind
	EndLabel string
	// Event names of the lifecycle steps.
	EvActive, EvEnded, EvFailed, EvUnknown, EvDrifted string
	// Reapply: an active row whose policy was detached or deleted outside
	// AuthSec is put back (access policies); otherwise drift is only
	// reported (DECISION R2-18).
	Reapply bool
}

var (
	r2GrantKind = r2Kind{Name: "temporary_grant", Table: "iga_gov_temp_grant", Job: "temp_grant", TagKey: igagov.TagGrant,
		IDKey: "grant_id", Feature: EnforcementFeatureGrants, Notice: GovNoticeTemporaryGrant,
		EvActive: GovEventGrantActive, EvEnded: GovEventGrantEnded, EvFailed: GovEventGrantFailed,
		EvUnknown: GovEventGrantUnknown, EvDrifted: GovEventGrantDrifted}
	r2RevokeKind = r2Kind{Name: "session_revocation", Table: "iga_gov_session_revocation", Job: "session_revoke",
		TagKey: "authsec:revocation", IDKey: "revocation_id", Feature: EnforcementFeatureRevoke, Notice: GovNoticeSessionRevocation,
		EvActive: GovEventRevocationActive, EvEnded: GovEventRevocationEnded, EvFailed: GovEventRevocationFailed,
		EvUnknown: GovEventRevocationUnk, EvDrifted: GovEventRevocationDrift}
	// An access policy's deployment: a temp_grant row with a policy_id, run by
	// the same temp_grant job (iga_gov_access_policy.go).
	r2AccessKind = r2Kind{Name: "access_policy", Table: "iga_gov_temp_grant", Job: "temp_grant", TagKey: igagov.TagAccessDeployment,
		IDKey: "deployment_id", Feature: EnforcementFeatureGrants, Notice: GovNoticeTemporaryGrant,
		EvActive: GovEventAccessConfirmed, EvEnded: GovEventAccessRemoved, EvFailed: GovEventAccessFailed,
		EvUnknown: GovEventAccessUnknown, EvDrifted: GovEventAccessDrifted, Reapply: true}
)

// R2 notice subjects (061 widened iga_gov_notification.subject_kind).
const (
	GovNoticeTemporaryGrant    = "temporary_grant"
	GovNoticeSessionRevocation = "session_revocation"
	GovNoticeTimeBound         = "time_bound"
)

// r2Row is what the engine needs of either row kind.
type r2Row struct {
	Kind         r2Kind
	ID           uuid.UUID
	WorkspaceID  uuid.UUID
	ConnectorID  uuid.UUID
	AccountID    string
	RoleID       string
	RoleARN      string
	PolicyName   string
	PolicyARN    string
	DocumentHash string
	Due          time.Time // expires_at / remove_after
	PendingOp    string
	SettleAfter  *time.Time
	// Extra tags on the policy (an access policy's policy and version).
	Extra map[string]string
}

// r2Outcome is what one converge run established.
type r2Outcome struct {
	Done       bool
	Fail       string // a terminal reason
	FailDetail string
	Unknown    bool
	SettleAt   time.Time
	RetryAfter time.Duration
	Drift      string
	Ops        []map[string]any
	Readback   map[string]any
}

// R2 engine reasons.
const (
	R2ReasonRoleGone          = "role_gone"
	R2ReasonOwnedElsewhere    = "artifact_owned_elsewhere"
	R2ReasonDocumentChanged   = "document_changed"
	R2ReasonAttachedElsewhere = "artifact_attached_elsewhere"
	R2ReasonDetached          = "detached_outside_authsec"
	R2ReasonDeleted           = "artifact_deleted"
	R2ReasonBindingPartial    = "binding_partial"
	R2ReasonQuota             = "attached_policy_quota"
	R2ReasonNotV2             = "binding_template_v1"
	r2SettleWindow            = 15 * time.Minute
	r2MaxSteps                = 6
)

// r2Env is the deployment environment (GovDeployEnv) R2 shares with R1a.
func r2Env() GovDeployEnv {
	e := currentGovDeployEnv()
	if e.BindingState == nil {
		e.BindingState = e.Binding
	}
	return e
}

// r2Live is one discovery read of the row's role and policy.
type r2Live struct {
	Role     *igagov.LiveRole
	Policy   *igagov.LivePolicy
	DocHash  string
	Attached bool
	Ours     bool
	Others   []igagov.AttachedEntity
}

func (r r2Row) tags() map[string]string {
	t := map[string]string{igagov.TagManagedBy: igagov.TagManagedByValue, igagov.TagWorkspace: GovWorkspaceRef(r.WorkspaceID),
		r.Kind.TagKey: r.ID.String(), igagov.TagExpiresAt: igagov.AWSTime(r.Due)}
	if r.Due.Equal(igagov.AccessNoEnd) {
		t[igagov.TagExpiresAt] = "none"
	}
	for k, v := range r.Extra {
		t[k] = v
	}
	return t
}

func (r r2Row) read(ctx context.Context, disc awsenforce.DiscoveryIAM) (*r2Live, error) {
	role, err := awsenforce.ReadRole(ctx, disc, roleNameOfARN(r.RoleARN))
	if err != nil {
		return nil, err
	}
	pol, _, err := awsenforce.ReadPolicy(ctx, disc, r.PolicyARN)
	if err != nil {
		return nil, err
	}
	l := &r2Live{Role: role, Policy: pol}
	if role != nil && role.RoleID == r.RoleID {
		for _, m := range role.ManagedPolicies {
			if m.Ref == r.PolicyARN {
				l.Attached = true
			}
		}
	}
	if pol != nil {
		if h, err := pol.DocumentHash(); err == nil {
			l.DocHash = h
		}
		l.Ours = pol.Tags[igagov.TagManagedBy] == igagov.TagManagedByValue && pol.Tags[r.Kind.TagKey] == r.ID.String() &&
			pol.Tags[igagov.TagWorkspace] == GovWorkspaceRef(r.WorkspaceID)
		for _, e := range pol.AttachmentSet {
			if !(e.Kind == "role" && e.ID == r.RoleID && e.Usage == igagov.UsagePermissions) {
				l.Others = append(l.Others, e)
			}
		}
	}
	return l, nil
}

func (l *r2Live) summary() map[string]any {
	out := map[string]any{"role_present": l.Role != nil, "policy_present": l.Policy != nil, "attached": l.Attached,
		"document_hash": l.DocHash, "owned_by_this_row": l.Ours, "other_users": len(l.Others)}
	if l.Role != nil {
		out["role_id"] = l.Role.RoleID
	}
	return out
}

// markPending is the write-ahead marker (DECISION R2-17), fenced.
func (r r2Row) markPending(ctx context.Context, run *PolicyJobRun, op string, now time.Time) error {
	settle := now.Add(r2SettleWindow)
	return run.InTx(ctx, func(tx *gorm.DB) error {
		return tx.Table(r.Kind.Table).Where("workspace_id = ? AND id = ?", r.WorkspaceID, r.ID).
			Updates(map[string]any{"pending_op": op, "pending_op_at": now, "settle_after": settle, "updated_at": now}).Error
	})
}

func (r r2Row) clearPending(ctx context.Context, run *PolicyJobRun, rec map[string]any) error {
	return run.InTx(ctx, func(tx *gorm.DB) error {
		up := map[string]any{"pending_op": "", "pending_op_at": nil, "settle_after": nil, "updated_at": time.Now()}
		if rec != nil {
			raw, _ := json.Marshal([]map[string]any{rec})
			up["ops"] = gorm.Expr("ops || ?::jsonb", string(raw))
		}
		return tx.Table(r.Kind.Table).Where("workspace_id = ? AND id = ?", r.WorkspaceID, r.ID).Updates(up).Error
	})
}

// document is the approved document's canonical text (iga_gov_document).
func r2Document(db *gorm.DB, ws uuid.UUID, hash string) (string, error) {
	var rows []models.IGAGovDocument
	if err := db.Where("workspace_id = ? AND document_hash = ?", ws, hash).Limit(1).Find(&rows).Error; err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("document %s is not archived", hash)
	}
	return rows[0].Canonical, nil
}

// converge drives the row toward present or absent (see the file comment).
func (r r2Row) converge(ctx context.Context, run *PolicyJobRun, present bool) (*r2Outcome, error) {
	out := &r2Outcome{Readback: map[string]any{}}
	env := r2Env()
	if env.AWS == nil {
		return &r2Outcome{RetryAfter: 5 * time.Minute, FailDetail: "AWS enforcement access is not configured"}, nil
	}
	now := time.Now().UTC()
	if r.PendingOp != "" && r.SettleAfter != nil && now.Before(*r.SettleAfter) {
		return &r2Outcome{Unknown: true, SettleAt: *r.SettleAfter, RetryAfter: r.SettleAfter.Sub(now)}, nil
	}
	var disc awsenforce.DiscoveryIAM
	if err := run.External(ctx, 0, func(ctx context.Context) error {
		var err error
		disc, err = env.AWS.DiscoveryIAM(ctx, r.WorkspaceID, r.ConnectorID)
		return err
	}); err != nil {
		if isLeaseErr(err) {
			return nil, err
		}
		return &r2Outcome{RetryAfter: time.Minute, FailDetail: "discovery unavailable: " + err.Error()}, nil
	}
	var enf awsenforce.IAMv2
	for step := 0; step < r2MaxSteps; step++ {
		var live *r2Live
		if err := run.External(ctx, 0, func(ctx context.Context) error {
			var err error
			live, err = r.read(ctx, disc)
			return err
		}); err != nil {
			if isLeaseErr(err) {
				return nil, err
			}
			return &r2Outcome{RetryAfter: time.Minute, FailDetail: "discovery read failed: " + err.Error()}, nil
		}
		if r.PendingOp != "" {
			// After settle_after: the fresh read decides (DECISION R2-17).
			if err := r.clearPending(ctx, run, map[string]any{"op": r.PendingOp, "outcome": "resolved_by_read", "read": live.summary(),
				"at": now}); err != nil {
				return nil, err
			}
			r.PendingOp = ""
		}
		out.Readback = live.summary()
		roleOK := live.Role != nil && live.Role.RoleID == r.RoleID
		if live.Policy != nil && !live.Ours {
			out.Fail, out.FailDetail = R2ReasonOwnedElsewhere, r.PolicyARN+" exists and is not this row's policy"
			return out, nil
		}
		docOK := live.Policy != nil && live.DocHash == r.DocumentHash
		var op string
		switch {
		case present && !roleOK:
			out.Fail, out.FailDetail = R2ReasonRoleGone, "role "+r.RoleARN+" is gone or was recreated"
			return out, nil
		case present && live.Policy == nil:
			op = "CreatePolicy"
		case present && !docOK:
			out.Fail, out.FailDetail = R2ReasonDocumentChanged, r.PolicyARN+" has a default document AuthSec did not write"
			return out, nil
		case present && !live.Attached:
			op = "AttachRolePolicy"
		case present:
			if len(live.Others) > 0 {
				out.Drift = R2ReasonAttachedElsewhere
			}
			out.Done = true
			return out, nil
		case live.Attached && roleOK:
			op = "DetachRolePolicy"
		case live.Policy != nil && len(live.Others) > 0:
			// Another entity uses it: detached from this role only, kept.
			out.Drift, out.Done = R2ReasonAttachedElsewhere, true
			return out, nil
		case live.Policy != nil && live.Policy.VersionCount > 1:
			out.Fail, out.FailDetail = R2ReasonDocumentChanged, r.PolicyARN+" has versions AuthSec did not create; delete it by hand"
			return out, nil
		case live.Policy != nil:
			op = "DeletePolicy"
		default:
			out.Done = true
			return out, nil
		}
		if enf == nil {
			if err := run.External(ctx, 0, func(ctx context.Context) error {
				c, err := env.AWS.EnforcementIAM(ctx, r.WorkspaceID, r.ConnectorID, r.ID)
				if err != nil {
					return err
				}
				v2, ok := awsenforce.AsIAMv2(c)
				if !ok {
					return errR2NotV2
				}
				enf = v2
				return nil
			}); err != nil {
				if isLeaseErr(err) {
					return nil, err
				}
				if errors.Is(err, errR2NotV2) {
					out.Fail, out.FailDetail = R2ReasonNotV2, "the enforcement client has no template v2 operations"
					return out, nil
				}
				return &r2Outcome{RetryAfter: 2 * time.Minute, FailDetail: "enforcement session: " + err.Error()}, nil
			}
		}
		doc := ""
		if op == "CreatePolicy" {
			if err := run.ReadTx(ctx, func(tx *gorm.DB) error {
				var err error
				doc, err = r2Document(tx, r.WorkspaceID, r.DocumentHash)
				return err
			}); err != nil {
				out.Fail, out.FailDetail = DeployReasonDocumentMissing, err.Error()
				return out, nil
			}
		}
		if chk := env.BindingState; chk != nil {
			if err := chk(ctx, r.WorkspaceID, r.ConnectorID); err != nil {
				out.Fail, out.FailDetail = R2ReasonBindingPartial, err.Error()
				return out, nil
			}
		}
		at := time.Now().UTC()
		if err := r.markPending(ctx, run, op, at); err != nil {
			return nil, err
		}
		var resp awsenforce.Response
		callErr := run.External(ctx, 0, func(ctx context.Context) error {
			ctx, requestID := awsenforce.WithRequestIDRecorder(ctx)
			var err error
			name := roleNameOfARN(r.RoleARN)
			switch op {
			case "CreatePolicy":
				_, err = enf.CreatePolicy(ctx, awsenforce.CreatePolicyInput{Path: igagov.AuthSecPolicyPath, Name: r.PolicyName, Document: doc, Tags: r.tags()})
			case "AttachRolePolicy":
				err = enf.AttachRolePolicy(ctx, name, r.PolicyARN)
			case "DetachRolePolicy":
				err = enf.DetachRolePolicy(ctx, name, r.PolicyARN)
			case "DeletePolicy":
				err = enf.DeletePolicy(ctx, r.PolicyARN)
			}
			resp = awsenforce.ClassifyCallError(err)
			if resp.RequestID == "" {
				resp.RequestID = requestID()
			}
			return nil
		})
		if callErr != nil {
			// Lease lost or short: the marker stays; the next run waits for
			// settle_after and reads (DECISION R2-17).
			return nil, callErr
		}
		rec := map[string]any{"op": op, "at": at, "request_id": resp.RequestID, "error_code": resp.ErrorCode}
		out.Ops = append(out.Ops, rec)
		switch resp.Kind {
		case igagov.RespOK:
			rec["outcome"] = "ok"
			if err := r.clearPending(ctx, run, rec); err != nil {
				return nil, err
			}
		case igagov.RespNoAnswer:
			out.Unknown, out.SettleAt = true, at.Add(r2SettleWindow)
			out.RetryAfter = r2SettleWindow
			return out, nil
		default:
			rec["outcome"] = "error"
			if err := r.clearPending(ctx, run, rec); err != nil {
				return nil, err
			}
			code := resp.ErrorCode
			switch {
			case code == "EntityAlreadyExists" || code == "NoSuchEntity" || code == "DeleteConflict":
				// Recognised by the next read.
			case awsenforce.IsAccessDenied(resp.Err):
				out.Fail, out.FailDetail = R2ReasonBindingPartial, op+" was denied: "+resp.Message
				return out, nil
			case code == "LimitExceeded" && strings.Contains(strings.ToLower(resp.Message), "quota"):
				out.Fail, out.FailDetail = R2ReasonQuota, resp.Message
				return out, nil
			case code == "Throttling" || code == "LimitExceeded":
				out.RetryAfter = time.Minute
				return out, nil
			default:
				out.Fail, out.FailDetail = code, op+": "+resp.Message
				return out, nil
			}
		}
	}
	out.RetryAfter = time.Minute
	return out, nil
}

var errR2NotV2 = errors.New("not a template v2 client")

// verifyPresent is the read-only drift check of an active row (§8.8, R2-18).
func (r r2Row) verifyPresent(ctx context.Context, run *PolicyJobRun) (drift string, read map[string]any, err error) {
	env := r2Env()
	if env.AWS == nil {
		return "", nil, PolicyJobRetryLater(5*time.Minute, "AWS access is not configured")
	}
	var live *r2Live
	if err := run.External(ctx, 0, func(ctx context.Context) error {
		disc, err := env.AWS.DiscoveryIAM(ctx, r.WorkspaceID, r.ConnectorID)
		if err != nil {
			return err
		}
		live, err = r.read(ctx, disc)
		return err
	}); err != nil {
		if isLeaseErr(err) {
			return "", nil, err
		}
		return "", nil, PolicyJobRetryLater(time.Minute, "discovery read failed: "+err.Error())
	}
	switch {
	case live.Role == nil || live.Role.RoleID != r.RoleID:
		drift = R2ReasonRoleGone
	case live.Policy == nil:
		drift = R2ReasonDeleted
	case !live.Ours || live.DocHash != r.DocumentHash:
		drift = R2ReasonDocumentChanged
	case !live.Attached:
		drift = R2ReasonDetached
	case len(live.Others) > 0:
		drift = R2ReasonAttachedElsewhere
	}
	return drift, live.summary(), nil
}

// r2BindingGate is the binding check before a row deploys: the R1a binding
// gate (verified, self-test younger than an hour, re-run otherwise) and the
// template v2 capabilities of the row's feature (DECISION R2-16). The
// binding gate may call AWS, so the capability read is its own short read
// under RLS for the job's workspace, after it.
func r2BindingGate(ctx context.Context, run *PolicyJobRun, ws, connectorID uuid.UUID, feature string) error {
	if ws != run.Job.WorkspaceID {
		return fmt.Errorf("r2 binding gate: workspace %s is not the job's %s", ws, run.Job.WorkspaceID)
	}
	if g := r2Env().Binding; g != nil {
		if err := g(ctx, ws, connectorID); err != nil {
			return err
		}
	}
	return run.ReadTx(ctx, func(tx *gorm.DB) error {
		return RequireEnforcementV2(ctx, tx, ws, connectorID, feature)
	})
}

// errCode is the code of a GovError / EnforcementError, else its text.
func errCode(err error) (string, string) {
	var ge *GovError
	var ee *EnforcementError
	switch {
	case errors.As(err, &ge):
		return ge.Code, ge.Message
	case errors.As(err, &ee):
		return ee.Code, ee.Message
	}
	return DepReasonBindingUnavailable, err.Error()
}
