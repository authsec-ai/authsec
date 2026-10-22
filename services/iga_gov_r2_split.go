package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
)

// Direct (J3) execution of a dedicated-identity split for a Lambda function
// (R2 piece 4; SPEC §11, §12.3; DECISION R2-13, R2-15, R2-20). The split and
// split_revert plans are §11's, compiled by igagov.CompileSplit with
// delivery direct (only for a Lambda subject under /authsec/split/, no
// boundary, no aliases). The deployment, its approval, the write-ahead
// attempt log (§8.1), unknown-outcome resolution, verification and drift
// are R1a's; only the ops are new, executed here with the enforcement
// template v2 session:
//
//	CreateRole          iam:CreateRole (path /authsec/split/, trust policy and
//	                    tags from the plan; AuthSec's ownership tags)
//	AttachRolePolicy    the source role's managed policies, by ARN
//	PutRolePolicy       copies of its inline policies (archived documents)
//	BindSubject         lambda:UpdateFunctionConfiguration Role = the new role
//	                    ($LATEST; iam:PassRole to lambda.amazonaws.com)
//	DeleteRole (revert) detach, delete inline, delete -- only if nothing else
//	                    runs as the role (OnlyIfUnused)
//
// DECISION R2-20: every op is recognised from a discovery read before it is
// sent (the role and its policies by GetRole / ListAttachedRolePolicies /
// GetRolePolicy, the function's role by lambda:GetFunctionConfiguration
// through the migration-evidence reader), so a re-run after a crash continues
// where AWS is. The deployment stays `applying` after its last op until the
// same classifier the IaC path uses (§2.8, igagov.Classify with the
// migration evidence of §11) sees the after-state -- the function on the new
// role, with the publication that shows it -- and only then becomes
// applied_unverified; a split is never verified by elapsed time.

func isDirectSplit(d models.IGAGovDeployment, p igagov.Plan) bool {
	return d.Delivery == igagov.DeliveryDirect && (p.Kind == igagov.PlanSplit || p.Kind == igagov.PlanSplitRevert) && p.Diff.Split != nil
}

// r2SplitReader reads a direct split's role and function state.
type r2SplitReader struct {
	disc awsenforce.DiscoveryIAM
	mig  awsdiscovery.MigrationClients
}

func (s *GovDeployments) r2SplitReaders(ctx context.Context, run *PolicyJobRun, ws uuid.UUID, ctl models.IGAGovControl, p igagov.Plan) (*r2SplitReader, error) {
	env := s.envNow()
	if env.AWS == nil {
		return nil, PolicyJobRetryLater(5*time.Minute, "AWS access is not configured")
	}
	out := &r2SplitReader{}
	err := run.External(ctx, 0, func(ctx context.Context) error {
		var err error
		if out.disc, err = env.AWS.DiscoveryIAM(ctx, ws, ctl.ConnectorID); err != nil {
			return err
		}
		mf := DefaultGovMigrationClients()
		if mf == nil {
			return fmt.Errorf("migration evidence reads are not configured")
		}
		out.mig, err = mf(ctx, ws, ctl.ConnectorID, subjectRegion(p.Diff.Split.SubjectARN))
		return err
	})
	if err != nil {
		if isLeaseErr(err) {
			return nil, err
		}
		return nil, PolicyJobRetryLater(time.Minute, "discovery unavailable: "+err.Error())
	}
	return out, nil
}

func lambdaName(arn string) string { return arn[strings.LastIndex(arn, ":")+1:] }

func (r *r2SplitReader) functionRole(ctx context.Context, functionARN string) (string, error) {
	st, ev := awsdiscovery.NewMigrationEvidenceReader(subjectRegion(functionARN), r.mig).LambdaFunction(ctx, lambdaName(functionARN))
	if st.LatestRole == "" && !ev.Complete() {
		return "", fmt.Errorf("lambda:GetFunctionConfiguration %s could not be read", functionARN)
	}
	return st.LatestRole, nil
}

// opDone recognises an op from a fresh read (DECISION R2-20). skip reports a
// DeleteRole that must not run because something else runs as the role.
func (s *GovDeployments) r2SplitOpDone(ctx context.Context, r *r2SplitReader, run *PolicyJobRun, ws uuid.UUID, ctl models.IGAGovControl,
	op igagov.Op) (done bool, conflict string, newRole *igagov.LiveRole, err error) {
	name := roleNameOfARN(op.RoleARN)
	switch op.Op {
	case igagov.OpCreateRole, igagov.OpAttachRolePolicy, igagov.OpPutRolePolicy, igagov.OpDeleteRole:
		if newRole, err = awsenforce.ReadRole(ctx, r.disc, name); err != nil {
			return false, "", nil, err
		}
	}
	switch op.Op {
	case igagov.OpCreateRole:
		if newRole == nil {
			return false, "", nil, nil
		}
		if newRole.Tags[igagov.TagSplitControl] != ctl.ID.String() {
			return false, igagov.RefuseNewRoleNameInUse + ": " + op.RoleARN, newRole, nil
		}
		return true, "", newRole, nil
	case igagov.OpAttachRolePolicy:
		if newRole == nil {
			return false, "the new role is missing", nil, nil
		}
		for _, m := range newRole.ManagedPolicies {
			if m.Ref == op.PolicyARN {
				return true, "", newRole, nil
			}
		}
		return false, "", newRole, nil
	case igagov.OpPutRolePolicy:
		if newRole == nil {
			return false, "the new role is missing", nil, nil
		}
		for _, ip := range newRole.InlinePolicies {
			if ip.Ref == op.InlineName {
				return ip.DocumentHash == op.DocumentHash, "", newRole, nil
			}
		}
		return false, "", newRole, nil
	case igagov.OpBindSubject:
		role, err := r.functionRole(ctx, op.SubjectARN)
		if err != nil {
			return false, "", nil, err
		}
		return role == op.RoleARN, "", nil, nil
	case igagov.OpDeleteRole:
		if newRole == nil {
			return true, "", nil, nil
		}
		var keys []string
		if err := runRead(ctx, run, func(tx *gorm.DB) error {
			var err error
			keys, err = workloadsExecutingAsARN(tx, ws, op.RoleARN)
			return err
		}); err != nil {
			return false, "", nil, err
		}
		if len(keys) > 0 && op.OnlyIfUnused {
			// §11: the revert restores the binding only and leaves the role.
			return true, "", newRole, nil
		}
		return false, "", newRole, nil
	}
	return false, "op " + op.Op + " is not executed directly", nil, nil
}

// r2ExecuteSplit is the deploy job's AWS step for a direct split.
func (s *GovDeployments) r2ExecuteSplit(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment, plan igagov.Plan) error {
	ws := d.WorkspaceID
	if ws != run.Job.WorkspaceID {
		return PolicyJobAbandon("the deployment is not in the job's workspace")
	}
	if !PolicyR2On() {
		return s.block(ctx, run, &d, GovCodeR2Unavailable, "Direct Lambda isolation needs R2 to be available.", nil, nil)
	}
	var ctl *models.IGAGovControl
	var v2err error
	if err := runRead(ctx, run, func(tx *gorm.DB) error {
		var err error
		if ctl, err = s.loadControl(tx, ws, d.ControlID); err != nil {
			return err
		}
		v2err = RequireEnforcementV2(ctx, tx, ws, ctl.ConnectorID, EnforcementFeatureLambdaSplit)
		var ge *GovError
		if v2err != nil && !errors.As(v2err, &ge) {
			return v2err // a database error
		}
		return nil
	}); err != nil {
		return err
	}
	if err := v2err; err != nil {
		code, msg := errCode(err)
		return s.block(ctx, run, &d, code, msg, nil, nil)
	}
	rec, err := s.attempts.Recover(ctx, run, ws, d.ID)
	if err != nil {
		return err
	}
	switch rec.Action {
	case RecoveryOutcomeUnknown:
		return s.applyOutcome(ctx, run, d, plan, &DeployOutcome{Result: DeployOutcomeUnknown, Reason: DeployReasonNoAnswer, SettleAfter: rec.SettleAfter})
	case RecoveryHold:
		return s.applyOutcome(ctx, run, d, plan, &DeployOutcome{Result: DeployHold, Reason: DeployReasonUnknownPending, SettleAfter: rec.SettleAfter})
	}
	rd, err := s.r2SplitReaders(ctx, run, ws, *ctl, plan)
	if err != nil {
		return err
	}
	env := s.envNow()
	var enf awsenforce.IAMv2
	var records []DeployOpRecord
	for k, op := range plan.Ops {
		var done bool
		var conflict string
		var newRole *igagov.LiveRole
		if err := run.External(ctx, 0, func(ctx context.Context) error {
			var err error
			done, conflict, newRole, err = s.r2SplitOpDone(ctx, rd, run, ws, *ctl, op)
			return err
		}); err != nil {
			if isLeaseErr(err) {
				return err
			}
			return PolicyJobRetryLater(time.Minute, "discovery read failed: "+err.Error())
		}
		if conflict != "" {
			return s.block(ctx, run, &d, igagov.ConflictPlanChanged, conflict, map[string]any{"op_seq": k, "op": op.Op}, nil)
		}
		if done {
			records = append(records, DeployOpRecord{OpSeq: k, Operation: op.Op, Outcome: AttemptOutcomeRecognisedDone, Basis: OpBasisLiveRead})
			continue
		}
		if enf == nil {
			if err := run.External(ctx, 0, func(ctx context.Context) error {
				c, err := env.AWS.EnforcementIAM(ctx, ws, ctl.ConnectorID, d.ID)
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
					return err
				}
				code, msg := errCode(err)
				return s.block(ctx, run, &d, code, msg, nil, nil)
			}
		}
		var calls []r2SplitCall
		err := runRead(ctx, run, func(tx *gorm.DB) error {
			var err error
			calls, err = s.r2SplitCalls(tx, ws, op, newRole)
			return err
		})
		if err != nil {
			return s.stop(ctx, run, &d, models.GovDeployFailed, DeployReasonDocumentMissing, err.Error(), nil, nil)
		}
		for i, c := range calls {
			reqHash, err := igagov.HashCanonicalTagged("authsec.igagov.r2.split_call.v1", struct {
				Op     igagov.Op `json:"op"`
				Call   string    `json:"call"`
				Target string    `json:"target"`
				Dep    string    `json:"deployment_id"`
			}{op, c.name, c.target, d.ID.String()})
			if err != nil {
				return err
			}
			c := c
			var answer awsenforce.Response
			res, err := s.attempts.ExecuteChecked(ctx, run, AttemptRequest{WorkspaceID: ws, DeploymentID: d.ID, OpSeq: k*100 + i,
				Operation: op.Op + ":" + c.name, RequestHash: reqHash, DocumentHash: c.docHash},
				func(ctx context.Context) error {
					if env.BindingState == nil {
						return nil
					}
					return env.BindingState(ctx, ws, ctl.ConnectorID)
				},
				func(ctx context.Context) (AttemptAnswer, error) {
					ctx, requestID := awsenforce.WithRequestIDRecorder(ctx)
					answer = awsenforce.ClassifyCallError(c.call(ctx, enf))
					if answer.RequestID == "" {
						answer.RequestID = requestID()
					}
					if answer.Kind == igagov.RespNoAnswer {
						return AttemptAnswer{}, answer.Err
					}
					return AttemptAnswer{Outcome: r2SplitOutcome(c.name, answer), RequestID: answer.RequestID,
						ErrorCode: answer.ErrorCode, ErrorMessage: answer.Message}, nil
				})
			if err != nil {
				code, msg := errCode(err)
				if strings.Contains(err.Error(), ErrDispatchRefused.Error()) {
					return s.block(ctx, run, &d, code, msg, nil, nil)
				}
				return err
			}
			if res.Unknown {
				return s.applyOutcome(ctx, run, d, plan, &DeployOutcome{Result: DeployOutcomeUnknown, Reason: DeployReasonNoAnswer,
					SettleAfter: res.SettleAfter, Attempt: &res.Attempt})
			}
			aid := res.Attempt.ID
			records = append(records, DeployOpRecord{OpSeq: k*100 + i, Operation: op.Op + ":" + c.name, Outcome: res.Answer.Outcome,
				Basis: OpBasisAttempt, AttemptID: &aid, AttemptNo: res.Attempt.AttemptNo, RequestID: res.Answer.RequestID, ErrorCode: res.Answer.ErrorCode})
			switch res.Answer.Outcome {
			case AttemptOutcomeRetryable:
				return PolicyJobRetryLater(time.Minute, op.Op+": "+res.Answer.ErrorCode)
			case AttemptOutcomeTerminal:
				reason := res.Answer.ErrorCode
				if awsenforce.IsAccessDenied(answer.Err) {
					reason = R2ReasonBindingPartial
				}
				return s.stop(ctx, run, &d, models.GovDeployFailed, reason, op.Op+": "+res.Answer.ErrorMessage, nil, nil)
			}
		}
	}
	return s.r2SplitReadback(ctx, run, d, plan, *ctl, records)
}

// r2SplitOutcome classifies an answered call (§8.5): recognisable answers
// are recognised_done, throttling and Lambda's update-in-progress conflict
// are retryable, anything else terminal.
func r2SplitOutcome(call string, r awsenforce.Response) string {
	if r.Kind == igagov.RespOK {
		return AttemptOutcomeOK
	}
	switch r.ErrorCode {
	case "NoSuchEntity":
		if strings.HasPrefix(call, "Detach") || strings.HasPrefix(call, "Delete") {
			return AttemptOutcomeRecognisedDone
		}
	case "Throttling", "TooManyRequestsException", "ResourceConflictException":
		return AttemptOutcomeRetryable
	}
	return AttemptOutcomeTerminal
}

type r2SplitCall struct {
	name, target, docHash string
	call                  func(ctx context.Context, c awsenforce.IAMv2) error
}

// r2SplitCalls are the native calls of one op. A DeleteRole is several:
// detach every managed policy, delete every inline policy, delete the role.
func (s *GovDeployments) r2SplitCalls(db *gorm.DB, ws uuid.UUID, op igagov.Op, newRole *igagov.LiveRole) ([]r2SplitCall, error) {
	name := roleNameOfARN(op.RoleARN)
	switch op.Op {
	case igagov.OpCreateRole:
		trust, err := r2Document(db, ws, op.TrustPolicyHash)
		if err != nil {
			return nil, err
		}
		path := op.Path
		return []r2SplitCall{{name: "CreateRole", target: op.RoleARN, docHash: op.TrustPolicyHash,
			call: func(ctx context.Context, c awsenforce.IAMv2) error {
				_, err := c.CreateRole(ctx, awsenforce.CreateRoleInput{Name: name, Path: path, TrustDocument: trust,
					Description: "AuthSec dedicated identity (direct Lambda isolation)", Tags: op.Tags})
				return err
			}}}, nil
	case igagov.OpAttachRolePolicy:
		return []r2SplitCall{{name: "AttachRolePolicy", target: op.PolicyARN,
			call: func(ctx context.Context, c awsenforce.IAMv2) error {
				return c.AttachRolePolicy(ctx, name, op.PolicyARN)
			}}}, nil
	case igagov.OpPutRolePolicy:
		doc, err := r2Document(db, ws, op.DocumentHash)
		if err != nil {
			return nil, err
		}
		return []r2SplitCall{{name: "PutRolePolicy", target: op.InlineName, docHash: op.DocumentHash,
			call: func(ctx context.Context, c awsenforce.IAMv2) error {
				return c.PutRolePolicy(ctx, name, op.InlineName, doc)
			}}}, nil
	case igagov.OpBindSubject:
		return []r2SplitCall{{name: "UpdateFunctionConfiguration", target: op.SubjectARN,
			call: func(ctx context.Context, c awsenforce.IAMv2) error {
				return c.UpdateFunctionRole(ctx, op.SubjectARN, op.RoleARN)
			}}}, nil
	case igagov.OpDeleteRole:
		var out []r2SplitCall
		if newRole != nil {
			for _, m := range newRole.ManagedPolicies {
				arn := m.Ref
				out = append(out, r2SplitCall{name: "DetachRolePolicy", target: arn,
					call: func(ctx context.Context, c awsenforce.IAMv2) error { return c.DetachRolePolicy(ctx, name, arn) }})
			}
			for _, ip := range newRole.InlinePolicies {
				pn := ip.Ref
				out = append(out, r2SplitCall{name: "DeleteRolePolicy", target: pn,
					call: func(ctx context.Context, c awsenforce.IAMv2) error { return c.DeleteRolePolicy(ctx, name, pn) }})
			}
		}
		out = append(out, r2SplitCall{name: "DeleteRole", target: op.RoleARN,
			call: func(ctx context.Context, c awsenforce.IAMv2) error { return c.DeleteRole(ctx, name) }})
		return out, nil
	}
	return nil, fmt.Errorf("op %s is not executed directly", op.Op)
}

// r2SplitLive is the classifier's read of a split (§2.8, §11): the source
// role, the new role, and every subject's binding from the migration
// evidence (which also records the migration rows), as the IaC path reads
// it. Shared by the deploy readback, verify and drift for direct splits.
func (s *GovDeployments) r2SplitLive(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment, plan igagov.Plan,
	ctl models.IGAGovControl) (igagov.LiveRead, error) {
	iac, x, err := s.r2SplitIaC(ctx, run, d)
	if err != nil {
		return igagov.LiveRead{}, err
	}
	r := DefaultGovLiveReader()
	if r == nil {
		return igagov.LiveRead{}, PolicyJobRetryLater(5*time.Minute, "live reads are not configured")
	}
	var live igagov.LiveRead
	nr := plan.Diff.Split.NewRoleARN
	if err := run.External(ctx, 0, func(ctx context.Context) error {
		var err error
		live, err = r.ReadRole(ctx, LiveReadRequest{WorkspaceID: d.WorkspaceID, ConnectorID: ctl.ConnectorID, AccountID: ctl.AccountID,
			RoleARN: ctl.RoleARN, RoleID: ctl.RoleID, PolicyARNs: awsenforce.PolicyARNsFor(plan, "")})
		if err != nil {
			return err
		}
		nl, err := r.ReadRole(ctx, LiveReadRequest{WorkspaceID: d.WorkspaceID, ConnectorID: ctl.ConnectorID, AccountID: ctl.AccountID, RoleARN: nr})
		if err != nil {
			return err
		}
		live.Roles = map[string]*igagov.LiveRole{nr: nl.Role}
		return nil
	}); err != nil {
		if isLeaseErr(err) {
			return igagov.LiveRead{}, err
		}
		return igagov.LiveRead{}, PolicyJobRetryLater(time.Minute, "discovery read failed: "+err.Error())
	}
	newRoleID := ""
	if l := live.Roles[nr]; l != nil {
		newRoleID = l.RoleID
	}
	_, bindings, err := iac.checkMigrations(ctx, run, d.WorkspaceID, x, newRoleID)
	if err != nil {
		return igagov.LiveRead{}, err
	}
	live.Bindings = bindings
	return live, nil
}

// r2SplitIaC is the IaC delivery's view of a direct split's deployment,
// loaded under row-level security for the job's workspace. The delivery is
// built on the job's handle only to reach its migration-evidence and ledger
// steps, which run on the job's own transactions (InTx), never on it.
func (s *GovDeployments) r2SplitIaC(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment) (*GovIaCDelivery, *iacDep, error) {
	if d.WorkspaceID != run.Job.WorkspaceID {
		return nil, nil, PolicyJobAbandon("the deployment is not in the job's workspace")
	}
	iac := NewGovIaCDelivery(run.DB(), nil, ProcessGovLiveReader())
	var x *iacDep
	err := runRead(ctx, run, func(tx *gorm.DB) error {
		var err error
		x, err = iac.load(tx, d.WorkspaceID, d.ID)
		return err
	})
	return iac, x, err
}

// r2SplitReadback: every op is done; applied_unverified only once the
// classifier sees the after-state (DECISION R2-20), else the deployment
// stays applying and the job looks again in 10 minutes.
func (s *GovDeployments) r2SplitReadback(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment, plan igagov.Plan,
	ctl models.IGAGovControl, records []DeployOpRecord) error {
	live, err := s.r2SplitLive(ctx, run, d, plan, ctl)
	if err != nil {
		return err
	}
	cl, err := igagov.Classify(plan, live)
	if err != nil {
		return err
	}
	if cl.Class == igagov.ClassConflict {
		return s.block(ctx, run, &d, cl.Reason, "the live state conflicts with the split", nil, &cl)
	}
	if cl.Class != igagov.ClassAfter {
		_ = run.InTx(ctx, func(tx *gorm.DB) error {
			return tx.Model(&models.IGAGovDeployment{}).Where("workspace_id = ? AND id = ? AND state = ?", d.WorkspaceID, d.ID, models.GovDeployApplying).
				Updates(map[string]any{"state_reason": fmt.Sprintf("every op is done; awaiting migration evidence (%d of %d facts visible)",
					cl.Visible, cl.Total), "updated_at": time.Now().UTC()}).Error
		})
		return PolicyJobRetryLater(DefaultVerifyEvery, "awaiting the migration evidence of the split")
	}
	iac, x, err := s.r2SplitIaC(ctx, run, d)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	if err := run.InTx(ctx, func(tx *gorm.DB) error {
		if err := iac.recordLedgerTx(tx, d.WorkspaceID, x, now); err != nil {
			return err
		}
		// AuthSec made these changes itself (J3).
		return tx.Model(&models.IGAGovArtifact{}).Where("workspace_id = ? AND control_id = ? AND last_deployment_id = ? AND kind IN ?",
			d.WorkspaceID, ctl.ID, d.ID, []string{"dedicated_role", "workload_binding"}).
			Update("owned_by", ArtifactOwnedDirect).Error
	}); err != nil {
		return err
	}
	return s.applyOutcome(ctx, run, d, plan, &DeployOutcome{Result: DeployApplied, Ops: records, Last: &cl,
		Readback: &DeployReadback{Reads: []igagov.Classification{cl}, ReadAt: now}})
}

// r2ResolveSplitUnknown is §8.1 step 2 for a direct split (DECISION R2-20):
// after settle_after one fresh read recognises the unknown op (done:
// applied; otherwise not_applied, and the deploy job re-reads and continues
// -- every op is idempotent or recognisable, so nothing is applied twice).
func (s *GovDeployments) r2ResolveSplitUnknown(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment, plan igagov.Plan) error {
	ws := d.WorkspaceID
	if ws != run.Job.WorkspaceID {
		return PolicyJobAbandon("the deployment is not in the job's workspace")
	}
	var att *models.IGAGovAttempt
	var ctl *models.IGAGovControl
	if err := runRead(ctx, run, func(tx *gorm.DB) error {
		var err error
		if att, err = s.attempts.OpenAttempt(tx, ws, d.ID); err != nil || att == nil {
			return err
		}
		ctl, err = s.loadControl(tx, ws, d.ControlID)
		return err
	}); err != nil {
		return err
	}
	if att == nil {
		return run.InTx(ctx, func(tx *gorm.DB) error { return s.rereadWithoutAttemptTx(tx, d) })
	}
	k := att.OpSeq / 100
	if k < 0 || k >= len(plan.Ops) {
		return fmt.Errorf("unknown attempt op_seq %d is outside the plan", att.OpSeq)
	}
	rd, err := s.r2SplitReaders(ctx, run, ws, *ctl, plan)
	if err != nil {
		return err
	}
	var done bool
	if err := run.External(ctx, 0, func(ctx context.Context) error {
		var err error
		done, _, _, err = s.r2SplitOpDone(ctx, rd, run, ws, *ctl, plan.Ops[k])
		return err
	}); err != nil {
		if isLeaseErr(err) {
			return err
		}
		return PolicyJobRetryLater(time.Minute, "unknown-outcome read failed: "+err.Error())
	}
	res := AttemptResolvedNotApplied
	if done {
		res = AttemptResolvedApplied
	}
	if err := s.attempts.ResolveUnknown(ctx, run, att, res); err != nil {
		return err
	}
	return run.InTx(ctx, func(tx *gorm.DB) error { return enqueueJobTx(tx, ws, "deploy", d.ID, s.now()) })
}
