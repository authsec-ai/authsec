package agentcontain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/igagov"
)

// The step engine. Every change is one step with its exact before-state,
// recorded BEFORE the AWS write (write-ahead, the caller persists the step
// between Before and Apply). Every write is a set-to-value AWS accepts
// repeatedly (concurrency n, desired count n, suspended flags, key status,
// attach, create-or-recognise), so a re-run after a crash re-applies a
// pending step instead of guessing whether the first attempt landed, and
// never re-reads the before-state of a step it already recorded.

// ErrNotFound is what an AWS adapter returns when the object does not exist.
var ErrNotFound = errors.New("not found")

// ErrDenied is what an AWS adapter returns for an authorisation refusal.
var ErrDenied = errors.New("access denied")

// Principal is the IAM entity a policy is attached to.
type Principal struct {
	Kind     string // iam_role | iam_user
	Name     string
	UniqueID string
}

// PolicyRead is the discovery role's read of an AuthSec policy.
type PolicyRead struct {
	Exists       bool
	Tags         map[string]string
	DocumentHash string
	// AttachedToPrincipal: attached to the principal (its current
	// incarnation, matched by unique id when the read names it).
	AttachedToPrincipal bool
	// OtherEntities counts every other entity using it.
	OtherEntities int
}

// Suspended is Application Auto Scaling's SuspendedState.
type Suspended struct {
	DynamicIn  bool `json:"dynamic_scaling_in_suspended"`
	DynamicOut bool `json:"dynamic_scaling_out_suspended"`
	Scheduled  bool `json:"scheduled_scaling_suspended"`
}

// All reports whether every kind of scaling is suspended.
func (s Suspended) All() bool { return s.DynamicIn && s.DynamicOut && s.Scheduled }

// ScalableTarget is an ECS service's registered scalable target.
type ScalableTarget struct {
	Suspended   Suspended
	MinCapacity int32
	MaxCapacity int32
}

// AccessKey is one access key of an IAM user.
type AccessKey struct {
	ID     string
	Active bool
}

// AWS is what containment does in one account: the enforcement role's
// writes (template v2, plus EnableWorkloadContainment for the workload and
// IAM-user calls), its reads of what it may change, and the discovery role's
// IAM policy reads. Not-found answers are ErrNotFound (or nil from a
// Describe/Read), refusals ErrDenied (or an AWS AccessDenied error).
type AWS interface {
	GetFunctionConcurrency(ctx context.Context, functionARN string) (*int32, error)
	PutFunctionConcurrency(ctx context.Context, functionARN string, n int32) error
	DeleteFunctionConcurrency(ctx context.Context, functionARN string) error

	DescribeService(ctx context.Context, clusterARN, serviceARN string) (*ECSService, error)
	SetServiceDesiredCount(ctx context.Context, clusterARN, serviceARN string, n int32) error

	DescribeScalableTarget(ctx context.Context, region, resourceID string) (*ScalableTarget, error)
	SetScalableTargetSuspended(ctx context.Context, region, resourceID string, s Suspended) error

	CreatePolicy(ctx context.Context, name, document string, tags map[string]string) (string, error)
	DeletePolicy(ctx context.Context, policyARN string) error
	AttachPolicy(ctx context.Context, p Principal, policyARN string) error
	DetachPolicy(ctx context.Context, p Principal, policyARN string) error
	ReadPolicy(ctx context.Context, policyARN string, p Principal) (*PolicyRead, error)

	ListAccessKeys(ctx context.Context, userName string) ([]AccessKey, error)
	SetAccessKeyStatus(ctx context.Context, userName, keyID string, active bool) error
}

// Step is one change (agent_containment_step), as the engine sees it.
type Step struct {
	ID     uuid.UUID
	Seq    int
	Kind   string
	Target string
	Region string
	// Cluster is the ECS cluster ARN of an ecs_desired step (kept in Before).
	Cluster string
	Before  json.RawMessage
	After   json.RawMessage
	State   string
	Error   string
	// RestoreAfter defers the restore (the session revocation, P3-3).
	RestoreAfter *time.Time
	AppliedAt    *time.Time
	RestoredAt   *time.Time
}

// The before/after documents.
type (
	LambdaBefore struct {
		// Reserved is the function's reserved concurrency; nil = unreserved.
		Reserved *int32 `json:"reserved"`
	}
	ECSBefore struct {
		ClusterARN   string `json:"cluster_arn"`
		DesiredCount int32  `json:"desired_count"`
	}
	ScalingBefore struct {
		Registered bool      `json:"registered"`
		Suspended  Suspended `json:"suspended"`
	}
	PolicyBefore struct {
		PolicyARN  string `json:"policy_arn"`
		PolicyName string `json:"policy_name"`
		// Existed / Attached are what AWS showed before the step: always
		// false for a policy AuthSec creates for this containment.
		Existed  bool `json:"existed"`
		Attached bool `json:"attached"`
	}
	KeyBefore struct {
		UserName string `json:"user_name"`
		Status   string `json:"status"` // Active
	}
)

// Run is one containment's identity and documents, what the engine needs.
type Run struct {
	ContainmentID uuid.UUID
	WorkspaceRef  string // authsec:workspace tag value
	Level         string
	Subject       Subject
	// Cutoff is the session revocation's aws:TokenIssueTime cutoff: the
	// containment's request time (R2-12: never earlier than the request).
	Cutoff time.Time
	Now    func() time.Time
}

func (r Run) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r Run) principal() Principal {
	return Principal{Kind: r.Subject.Kind, Name: r.Subject.Name, UniqueID: r.Subject.UniqueID}
}

func (r Run) partition() string {
	if r.Subject.Partition != "" {
		return r.Subject.Partition
	}
	return "aws"
}

// IAMSteps are the IAM steps of a level (identity / model), before the
// access-key steps of a user, which are read live (AccessKeySteps).
func (r Run) IAMSteps() []Step {
	var out []Step
	switch r.Level {
	case LevelIdentity, LevelModel:
		name := ContainPolicyName(r.Subject.UniqueID, r.ContainmentID)
		out = append(out, Step{Kind: StepIAMPolicy, Target: PolicyARN(r.partition(), r.Subject.AccountID, name)})
		if r.Level == LevelIdentity && r.Subject.Kind == IdentityRole {
			rname := RevokePolicyName(r.Subject.UniqueID, r.ContainmentID)
			ra := RevokeRemoveAfter(r.Cutoff)
			out = append(out, Step{Kind: StepSessionRevoke, Target: PolicyARN(r.partition(), r.Subject.AccountID, rname), RestoreAfter: &ra})
		}
	}
	return out
}

// WorkloadSteps are the steps of the workload level, from the preview's plan.
func WorkloadSteps(opt *LevelOption) []Step {
	if opt == nil {
		return nil
	}
	var out []Step
	for _, ps := range opt.Steps {
		switch ps.Kind {
		case StepLambdaConcurrency, StepECSAutoscaling, StepECSDesired:
			out = append(out, Step{Kind: ps.Kind, Target: ps.Target, Region: ps.Region, Cluster: ps.Cluster})
		}
	}
	return out
}

// AccessKeySteps lists the user's Active keys as steps (DECISION P3-4).
// Keys already Inactive are not recorded: release must never activate them.
func AccessKeySteps(ctx context.Context, aws AWS, userName string) ([]Step, error) {
	keys, err := aws.ListAccessKeys(ctx, userName)
	if err != nil {
		return nil, err
	}
	var out []Step
	for _, k := range keys {
		if k.Active {
			b, _ := json.Marshal(KeyBefore{UserName: userName, Status: "Active"})
			out = append(out, Step{Kind: StepAccessKey, Target: k.ID, Before: b})
		}
	}
	return out, nil
}

// Engine applies, reads back and restores steps of one run.
type Engine struct {
	AWS AWS
	Run Run
}

// StepError is a definitive refusal of one step (recorded on the step,
// state failed / restore_failed); any other error is transient (retry).
type StepError struct {
	Code    string
	Message string
}

func (e *StepError) Error() string { return e.Code + ": " + e.Message }

func refused(code, format string, a ...any) error {
	return &StepError{Code: code, Message: fmt.Sprintf(format, a...)}
}

// Denied reports an authorisation refusal from any adapter.
func Denied(err error) bool { return errors.Is(err, ErrDenied) || awsenforce.IsAccessDenied(err) }

func notFound(err error) bool {
	if errors.Is(err, ErrNotFound) {
		return true
	}
	switch awsenforce.ErrorCode(err) {
	case "NoSuchEntity", "ResourceNotFoundException", "ServiceNotFoundException", "ClusterNotFoundException", "ObjectNotFoundException":
		return true
	}
	return false
}

func deniedErr(op, target string, err error) error {
	return refused("access_denied", "%s on %s was refused by AWS (the resource may be tagged authsec:protected=true, or the enforcement stack lacks the permission): %v", op, target, err)
}

// Before reads the exact before-state of a step that has none recorded yet.
// A target that no longer exists makes the step skipped (nothing to change).
func (e *Engine) Before(ctx context.Context, st *Step) (skip bool, err error) {
	switch st.Kind {
	case StepLambdaConcurrency:
		n, err := e.AWS.GetFunctionConcurrency(ctx, st.Target)
		if notFound(err) {
			st.Error = "the function no longer exists"
			return true, nil
		}
		if err != nil {
			if Denied(err) {
				return false, deniedErr("GetFunctionConcurrency", st.Target, err)
			}
			return false, err
		}
		st.Before, _ = json.Marshal(LambdaBefore{Reserved: n})
	case StepECSDesired:
		s, err := e.AWS.DescribeService(ctx, st.Cluster, st.Target)
		if err != nil && !notFound(err) {
			if Denied(err) {
				return false, deniedErr("DescribeServices", st.Target, err)
			}
			return false, err
		}
		if s == nil {
			st.Error = "the service no longer exists"
			return true, nil
		}
		st.Before, _ = json.Marshal(ECSBefore{ClusterARN: st.Cluster, DesiredCount: s.DesiredCount})
	case StepECSAutoscaling:
		t, err := e.AWS.DescribeScalableTarget(ctx, st.Region, st.Target)
		if err != nil && !notFound(err) {
			if Denied(err) {
				return false, deniedErr("DescribeScalableTargets", st.Target, err)
			}
			return false, err
		}
		if t == nil {
			st.Before, _ = json.Marshal(ScalingBefore{Registered: false})
			st.Error = "the service has no scalable target: nothing to suspend"
			return true, nil
		}
		st.Before, _ = json.Marshal(ScalingBefore{Registered: true, Suspended: t.Suspended})
	case StepIAMPolicy, StepSessionRevoke:
		r, err := e.AWS.ReadPolicy(ctx, st.Target, e.Run.principal())
		if err != nil {
			return false, err
		}
		if r != nil && r.Exists && !e.ours(r) {
			return false, refused("artifact_owned_elsewhere", "%s exists and is not this containment's policy", st.Target)
		}
		st.Before, _ = json.Marshal(PolicyBefore{PolicyARN: st.Target, PolicyName: IdentityNameOf(st.Target),
			Existed: r != nil && r.Exists, Attached: r != nil && r.AttachedToPrincipal})
	case StepAccessKey:
		if len(st.Before) == 0 {
			return false, fmt.Errorf("access key step %s has no before-state", st.Target)
		}
	default:
		return false, fmt.Errorf("unknown step kind %q", st.Kind)
	}
	return false, nil
}

func (e *Engine) tags(level string) map[string]string {
	return map[string]string{
		igagov.TagManagedBy: igagov.TagManagedByValue, igagov.TagWorkspace: e.Run.WorkspaceRef,
		TagContainment: e.Run.ContainmentID.String(), TagContainmentLevel: level,
	}
}

func (e *Engine) ours(r *PolicyRead) bool {
	return r.Tags[igagov.TagManagedBy] == igagov.TagManagedByValue && r.Tags[TagContainment] == e.Run.ContainmentID.String() &&
		r.Tags[igagov.TagWorkspace] == e.Run.WorkspaceRef
}

// document is the step's policy document and hash.
func (e *Engine) document(st *Step) (string, string, error) {
	switch {
	case st.Kind == StepSessionRevoke:
		return RevokeDocument(e.Run.Cutoff)
	case e.Run.Level == LevelModel:
		return DenyModelDocument()
	default:
		return DenyAllDocument()
	}
}

// Apply makes the step's change and reads it back. It returns the step's new
// state (applied); a *StepError is a definitive refusal (the caller records
// failed); any other error is transient (the step stays pending).
func (e *Engine) Apply(ctx context.Context, st *Step) error {
	switch st.Kind {
	case StepLambdaConcurrency:
		if err := e.AWS.PutFunctionConcurrency(ctx, st.Target, 0); err != nil {
			return e.writeErr("PutFunctionConcurrency", st, err)
		}
		n, err := e.AWS.GetFunctionConcurrency(ctx, st.Target)
		if err != nil {
			return err
		}
		if n == nil || *n != 0 {
			return fmt.Errorf("readback: %s reserved concurrency is %s, not 0", st.Target, fmtReserved(n))
		}
		st.After, _ = json.Marshal(LambdaBefore{Reserved: n})
	case StepECSAutoscaling:
		var b ScalingBefore
		_ = json.Unmarshal(st.Before, &b)
		if !b.Registered {
			return nil
		}
		all := Suspended{DynamicIn: true, DynamicOut: true, Scheduled: true}
		if err := e.AWS.SetScalableTargetSuspended(ctx, st.Region, st.Target, all); err != nil {
			return e.writeErr("RegisterScalableTarget", st, err)
		}
		t, err := e.AWS.DescribeScalableTarget(ctx, st.Region, st.Target)
		if err != nil {
			return err
		}
		if t == nil || !t.Suspended.All() {
			return fmt.Errorf("readback: %s scaling is not suspended", st.Target)
		}
		st.After, _ = json.Marshal(ScalingBefore{Registered: true, Suspended: t.Suspended})
	case StepECSDesired:
		cl := st.Cluster
		if cl == "" {
			var b ECSBefore
			_ = json.Unmarshal(st.Before, &b)
			cl = b.ClusterARN
		}
		if err := e.AWS.SetServiceDesiredCount(ctx, cl, st.Target, 0); err != nil {
			return e.writeErr("UpdateService", st, err)
		}
		s, err := e.AWS.DescribeService(ctx, cl, st.Target)
		if err != nil {
			return err
		}
		if s == nil || s.DesiredCount != 0 {
			return fmt.Errorf("readback: %s desired count is not 0", st.Target)
		}
		st.After, _ = json.Marshal(ECSBefore{ClusterARN: cl, DesiredCount: s.DesiredCount})
	case StepIAMPolicy, StepSessionRevoke:
		return e.applyPolicy(ctx, st)
	case StepAccessKey:
		var b KeyBefore
		_ = json.Unmarshal(st.Before, &b)
		if err := e.AWS.SetAccessKeyStatus(ctx, b.UserName, st.Target, false); err != nil {
			return e.writeErr("UpdateAccessKey", st, err)
		}
		keys, err := e.AWS.ListAccessKeys(ctx, b.UserName)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if k.ID == st.Target && k.Active {
				return fmt.Errorf("readback: access key %s is still Active", st.Target)
			}
		}
		st.After, _ = json.Marshal(KeyBefore{UserName: b.UserName, Status: "Inactive"})
	default:
		return fmt.Errorf("unknown step kind %q", st.Kind)
	}
	return nil
}

func fmtReserved(n *int32) string {
	if n == nil {
		return "unreserved"
	}
	return fmt.Sprint(*n)
}

func (e *Engine) writeErr(op string, st *Step, err error) error {
	switch {
	case Denied(err):
		return deniedErr(op, st.Target, err)
	case notFound(err):
		return refused("target_gone", "%s: %s no longer exists", op, st.Target)
	}
	return err
}

func (e *Engine) applyPolicy(ctx context.Context, st *Step) error {
	p := e.Run.principal()
	doc, hash, err := e.document(st)
	if err != nil {
		return err
	}
	level := e.Run.Level
	if st.Kind == StepSessionRevoke {
		level = "session_revoke"
	}
	for i := 0; i < 3; i++ {
		r, err := e.AWS.ReadPolicy(ctx, st.Target, p)
		if err != nil {
			return err
		}
		switch {
		case r == nil || !r.Exists:
			_, cerr := e.AWS.CreatePolicy(ctx, IdentityNameOf(st.Target), doc, e.tags(level))
			if cerr != nil && awsenforce.ErrorCode(cerr) != "EntityAlreadyExists" {
				return e.writeErr("CreatePolicy", st, cerr)
			}
			continue
		case !e.ours(r):
			return refused("artifact_owned_elsewhere", "%s exists and is not this containment's policy", st.Target)
		case r.DocumentHash != "" && r.DocumentHash != hash:
			return refused("document_changed", "%s has a document AuthSec did not write", st.Target)
		case !r.AttachedToPrincipal:
			if aerr := e.AWS.AttachPolicy(ctx, p, st.Target); aerr != nil {
				if awsenforce.ErrorCode(aerr) == "LimitExceeded" {
					return refused("attached_policy_quota", "%s has the most managed policies IAM allows: %v", p.Name, aerr)
				}
				return e.writeErr("Attach policy", st, aerr)
			}
			continue
		default:
			st.After, _ = json.Marshal(map[string]any{"policy_arn": st.Target, "attached": true, "document_hash": hash,
				"other_entities": r.OtherEntities})
			return nil
		}
	}
	return fmt.Errorf("readback: %s is not attached to %s yet", st.Target, p.Name)
}

// Restore puts the step's before-state back and reads it back. Steps that
// changed nothing (skipped, failed) are restored trivially.
func (e *Engine) Restore(ctx context.Context, st *Step) error {
	switch st.State {
	case StepSkipped, StepFailed, StepRestored:
		return nil
	}
	if len(st.Before) == 0 {
		// Never recorded, so never applied.
		return nil
	}
	switch st.Kind {
	case StepLambdaConcurrency:
		var b LambdaBefore
		if err := json.Unmarshal(st.Before, &b); err != nil {
			return err
		}
		var err error
		if b.Reserved == nil {
			err = e.AWS.DeleteFunctionConcurrency(ctx, st.Target)
		} else {
			err = e.AWS.PutFunctionConcurrency(ctx, st.Target, *b.Reserved)
		}
		if notFound(err) {
			st.Error = "the function no longer exists; nothing to restore"
			return nil
		}
		if err != nil {
			return e.writeErr("restore concurrency", st, err)
		}
		n, err := e.AWS.GetFunctionConcurrency(ctx, st.Target)
		if err != nil {
			return err
		}
		if !sameReserved(n, b.Reserved) {
			return fmt.Errorf("readback: %s reserved concurrency is %s, want %s", st.Target, fmtReserved(n), fmtReserved(b.Reserved))
		}
	case StepECSAutoscaling:
		var b ScalingBefore
		if err := json.Unmarshal(st.Before, &b); err != nil {
			return err
		}
		if !b.Registered {
			return nil
		}
		err := e.AWS.SetScalableTargetSuspended(ctx, st.Region, st.Target, b.Suspended)
		if notFound(err) {
			st.Error = "the scalable target no longer exists; nothing to restore"
			return nil
		}
		if err != nil {
			return e.writeErr("restore scaling", st, err)
		}
		t, err := e.AWS.DescribeScalableTarget(ctx, st.Region, st.Target)
		if err != nil {
			return err
		}
		if t != nil && t.Suspended != b.Suspended {
			return fmt.Errorf("readback: %s suspended state is not the recorded one", st.Target)
		}
	case StepECSDesired:
		var b ECSBefore
		if err := json.Unmarshal(st.Before, &b); err != nil {
			return err
		}
		err := e.AWS.SetServiceDesiredCount(ctx, b.ClusterARN, st.Target, b.DesiredCount)
		if notFound(err) {
			st.Error = "the service no longer exists; nothing to restore"
			return nil
		}
		if err != nil {
			return e.writeErr("restore desired count", st, err)
		}
		s, err := e.AWS.DescribeService(ctx, b.ClusterARN, st.Target)
		if err != nil {
			return err
		}
		if s != nil && s.DesiredCount != b.DesiredCount {
			return fmt.Errorf("readback: %s desired count is %d, want %d", st.Target, s.DesiredCount, b.DesiredCount)
		}
	case StepIAMPolicy, StepSessionRevoke:
		return e.restorePolicy(ctx, st)
	case StepAccessKey:
		var b KeyBefore
		if err := json.Unmarshal(st.Before, &b); err != nil {
			return err
		}
		if b.Status != "Active" {
			return nil
		}
		err := e.AWS.SetAccessKeyStatus(ctx, b.UserName, st.Target, true)
		if notFound(err) {
			st.Error = "the access key no longer exists; nothing to restore"
			return nil
		}
		if err != nil {
			return e.writeErr("reactivate access key", st, err)
		}
	default:
		return fmt.Errorf("unknown step kind %q", st.Kind)
	}
	return nil
}

func sameReserved(a, b *int32) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (e *Engine) restorePolicy(ctx context.Context, st *Step) error {
	p := e.Run.principal()
	for i := 0; i < 3; i++ {
		r, err := e.AWS.ReadPolicy(ctx, st.Target, p)
		if err != nil {
			return err
		}
		switch {
		case r == nil || !r.Exists:
			return nil
		case !e.ours(r):
			// Not this containment's: nothing of ours to remove.
			st.Error = st.Target + " is not this containment's policy; left in place"
			return nil
		case r.AttachedToPrincipal:
			if err := e.AWS.DetachPolicy(ctx, p, st.Target); err != nil && !notFound(err) {
				return e.writeErr("Detach policy", st, err)
			}
			continue
		case r.OtherEntities > 0:
			// Detached from the identity; someone attached it elsewhere: kept.
			st.Error = st.Target + " is attached to another entity as well; AuthSec detached it from " + p.Name + " and left it in place"
			return nil
		default:
			if err := e.AWS.DeletePolicy(ctx, st.Target); err != nil && !notFound(err) {
				return e.writeErr("DeletePolicy", st, err)
			}
			continue
		}
	}
	return fmt.Errorf("readback: %s is still present", st.Target)
}

// Readback re-reads an applied step and reports whether its change is still
// in place (drift), without changing anything.
func (e *Engine) Readback(ctx context.Context, st *Step) (inPlace bool, detail string, err error) {
	switch st.Kind {
	case StepLambdaConcurrency:
		n, err := e.AWS.GetFunctionConcurrency(ctx, st.Target)
		if err != nil {
			return false, "", err
		}
		return n != nil && *n == 0, "reserved concurrency " + fmtReserved(n), nil
	case StepECSDesired:
		var b ECSBefore
		_ = json.Unmarshal(st.Before, &b)
		s, err := e.AWS.DescribeService(ctx, b.ClusterARN, st.Target)
		if err != nil {
			return false, "", err
		}
		if s == nil {
			return false, "service gone", nil
		}
		return s.DesiredCount == 0, fmt.Sprintf("desired count %d", s.DesiredCount), nil
	case StepECSAutoscaling:
		t, err := e.AWS.DescribeScalableTarget(ctx, st.Region, st.Target)
		if err != nil {
			return false, "", err
		}
		return t != nil && t.Suspended.All(), "scaling suspended", nil
	case StepIAMPolicy, StepSessionRevoke:
		r, err := e.AWS.ReadPolicy(ctx, st.Target, e.Run.principal())
		if err != nil {
			return false, "", err
		}
		return r != nil && r.Exists && r.AttachedToPrincipal, "policy attached", nil
	case StepAccessKey:
		var b KeyBefore
		_ = json.Unmarshal(st.Before, &b)
		keys, err := e.AWS.ListAccessKeys(ctx, b.UserName)
		if err != nil {
			return false, "", err
		}
		for _, k := range keys {
			if k.ID == st.Target {
				return !k.Active, "key status", nil
			}
		}
		return true, "key deleted", nil
	}
	return false, "", fmt.Errorf("unknown step kind %q", st.Kind)
}

// Outcome is the containment state its steps make (after a contain run).
func Outcome(steps []Step) string {
	applied, failed, pending := 0, 0, 0
	for _, s := range steps {
		switch s.State {
		case StepApplied:
			applied++
		case StepFailed:
			failed++
		case StepPending:
			pending++
		}
	}
	switch {
	case pending > 0:
		return StateContaining
	case applied == 0:
		return StateFailed
	case failed > 0:
		return StatePartial
	}
	return StateContained
}

// ReleaseDone reports whether every step is restored except deferred ones
// not yet due, and the earliest deferred restore time.
func ReleaseDone(steps []Step, now time.Time) (done bool, next *time.Time) {
	done = true
	for _, s := range steps {
		switch s.State {
		case StepRestored, StepSkipped, StepFailed:
			continue
		}
		if s.RestoreAfter != nil && now.Before(*s.RestoreAfter) {
			if next == nil || s.RestoreAfter.Before(*next) {
				t := *s.RestoreAfter
				next = &t
			}
			continue
		}
		done = false
	}
	return done, next
}
