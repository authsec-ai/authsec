// Package agentcontain is agent containment on AWS (SPEC-agent-runtime-
// visibility.md §5.8 and §10, phase P3): the blast-radius preview, the three
// containment levels and the steps each one changes, the documents AuthSec
// attaches, the step engine that applies and restores each step against an
// AWS interface, and the behavioural verification rule.
//
// It is pure apart from the AWS interface it is handed: no database, no
// process state. services/agent_runtime_contain*.go stores containments and
// their steps, runs them on the policy job worker and builds the live AWS
// adapter (internal/awsenforce/contain*.go) from the account's enforcement
// credential, exactly as access policies and R2 do.
//
// Decisions (binding, spec §10): Q4 -- workload containment needs the
// enforcement stack's opt-in parameter EnableWorkloadContainment; identity
// and model containment need nothing beyond template v2. Q6 -- there is no
// human approval: a containment runs as soon as it is requested. §5.8 change
// -- the preview states the side effects of each level.
//
// DECISION P3-1: a containment's subject is one AWS identity of the
// workspace (cloud_identity: an IAM role or an IAM user), optionally narrowed
// to some of the workloads that run as it. Containment works for any AWS
// identity, labelled or not; the label (agentruntime.Resolver) is shown when
// one is installed.
//
// DECISION P3-2: one live containment per (workspace, identity, level). To
// change which workloads a workload-level containment covers, release it and
// contain again.
//
// DECISION P3-3: identity-level containment of a role also attaches R2's
// session revocation (deny when aws:TokenIssueTime is before the request
// time; igagov.RevokeSessionsDocument). While contained it is subsumed by the
// deny-all policy; its purpose is AFTER release: sessions issued before the
// containment (possibly held by whoever misused the agent) stay refused until
// igagov.RevocationRemoveAfter (12 h + 1 h), then AuthSec removes it. Release
// therefore restores everything at once except this one step, whose restore
// is deferred to that time and recorded (restore_after).
//
// DECISION P3-4: an IAM user has no sessions to revoke by issue time that the
// deny-all does not already cover, so identity level on a user is the deny-all
// policy attached to the user plus every Active access key set Inactive
// (recorded; release reactivates only those keys). Attaching a policy to a
// USER (iam:AttachUserPolicy) and changing keys are not in template v2: they
// come with EnableWorkloadContainment, so containing an IAM user at any level
// needs the parameter.
//
// DECISION P3-5: model level denies bedrock:* plus the AgentCore invoke
// actions and the bedrock-mantle namespace (UNVERIFIED: the mantle endpoint's
// IAM namespace is not confirmed; IAM accepts an unknown service prefix in a
// policy, so the statement is harmless if the name is wrong -- verify in the
// lab, spec §5.1).
package agentcontain

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
)

// Levels (spec §5.8).
const (
	LevelWorkload = "workload"
	LevelIdentity = "identity"
	LevelModel    = "model"
)

// Levels lists the levels from narrowest to broadest.
var Levels = []string{LevelWorkload, LevelModel, LevelIdentity}

// ValidLevel reports whether l is a level.
func ValidLevel(l string) bool {
	for _, x := range Levels {
		if x == l {
			return true
		}
	}
	return false
}

// Containment states (spec §5.8): previewed -> containing -> contained |
// partially_contained | failed -> releasing -> released.
const (
	StatePreviewed  = "previewed"
	StateContaining = "containing"
	StateContained  = "contained"
	StatePartial    = "partially_contained"
	StateFailed     = "failed"
	StateReleasing  = "releasing"
	StateReleased   = "released"
)

// LiveStates are the states that hold the (workspace, identity, level) slot.
var LiveStates = []string{StatePreviewed, StateContaining, StateContained, StatePartial, StateReleasing}

// ReleasableStates are the states a release may start from.
var ReleasableStates = []string{StatePreviewed, StateContaining, StateContained, StatePartial}

// Step kinds (agent_containment_step.kind).
const (
	StepLambdaConcurrency = "lambda_concurrency"
	StepECSDesired        = "ecs_desired"
	StepECSAutoscaling    = "ecs_autoscaling"
	StepIAMPolicy         = "iam_policy"
	StepSessionRevoke     = "session_revoke"
	StepAccessKey         = "access_key"
)

// Step states. A step row is written BEFORE its AWS write (pending, with the
// exact before-state), so a crash between the write and its answer leaves a
// row that release restores whatever happened.
const (
	StepPending       = "pending"
	StepApplied       = "applied"
	StepSkipped       = "skipped" // nothing to change (no scalable target, key already inactive)
	StepFailed        = "failed"  // AWS refused the change; nothing was changed
	StepRestoring     = "restoring"
	StepRestored      = "restored"
	StepRestoreFailed = "restore_failed" // retried by the job; never terminal
)

// Identity kinds (cloud_identity.kind).
const (
	IdentityRole = "iam_role"
	IdentityUser = "iam_user"
)

// Workload kinds the preview distinguishes (cloud_workload.runtime_kind, plus
// the EKS service accounts read from cloud_assume_edge).
const (
	WorkloadLambda     = "lambda_function"
	WorkloadECSTaskDef = "ecs_task_definition"
	WorkloadEC2        = "ec2_instance"
	WorkloadEKSPod     = "eks_service_account"
)

// Refusal codes (preview and create).
const (
	RefuseServiceLinkedRole   = "service_linked_role"
	RefuseReservedRole        = "aws_reserved_role"
	RefuseAuthSecOwned        = "authsec_owned"
	RefuseProtected           = "protected"
	RefuseIdentityKind        = "identity_kind_not_supported"
	RefuseNoWorkloads         = "no_workloads_selected"
	RefuseWorkloadNotOffered  = "workload_level_not_offered"
	RefuseWorkloadNotOnRole   = "workload_not_on_identity"
	RefuseWorkloadUnavailable = "workload_containment_unavailable"
	RefuseUserNeedsParameter  = "iam_user_needs_workload_containment"
	RefuseNoECSService        = "no_ecs_service"
	RefuseBindingUnavailable  = "binding_unavailable"
	RefuseIAMUserModelOnly    = "iam_user_workload_level"
	RefuseIdentityUnknown     = "identity_detail_incomplete"
)

// Side-effect codes (spec §10, §5.8 change).
const (
	EffectEventSourceMappings = "lambda_event_source_mappings_continue"
	EffectRunTaskNotStopped   = "ecs_run_task_not_stopped"
	EffectAutoScalingSuspend  = "application_autoscaling_suspended"
	EffectSharedRole          = "shared_role_stops_all"
	EffectSessionsRevoked     = "sessions_revoked_after_release"
	EffectAccessKeysInactive  = "access_keys_deactivated"
	EffectModelOnly           = "model_calls_only"
	EffectInFlight            = "in_flight_not_interrupted"
)

// Tags.
const (
	TagContainment      = "authsec:containment"
	TagContainmentLevel = "authsec:containment-level"
	TagProtected        = igagov.RoleTagProtected // authsec:protected
)

// Document Sids and names.
const (
	ContainPolicyPrefix = "AuthSecContain-"
	SidDenyAll          = "AuthSecContainDenyAll"
	SidDenyModel        = "AuthSecContainDenyModel"
)

// ModelActions are what model-level containment denies (DECISION P3-5).
var ModelActions = []string{
	"bedrock:*",
	"bedrock-agentcore:InvokeAgentRuntime",
	"bedrock-agentcore:InvokeGateway",
	// UNVERIFIED namespace (spec §5.1): the OpenAI/Anthropic-compatible endpoint.
	"bedrock-mantle:*",
}

// Refusal is one reason a level (or the whole request) cannot run.
type Refusal struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// WorkloadID names the workload the refusal is about, when it is one.
	WorkloadID *uuid.UUID `json:"workload_id,omitempty"`
}

// SideEffect is something a level does not stop, or does besides stopping.
type SideEffect struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Short is the 8-hex id suffix AuthSec puts in a policy name.
func Short(id uuid.UUID) string { return strings.ReplaceAll(id.String(), "-", "")[:8] }

// ContainPolicyName is /authsec/AuthSecContain-<RoleId or AIDA id>-<containment 8hex>.
func ContainPolicyName(uniqueID string, containmentID uuid.UUID) string {
	return ContainPolicyPrefix + uniqueID + "-" + Short(containmentID)
}

// PolicyARN is an AuthSec policy's ARN in the account.
func PolicyARN(partition, account, name string) string {
	return igagov.GrantPolicyARN(partition, account, name)
}

// DenyAllDocument is identity level: Deny "*" on "*".
func DenyAllDocument() (string, string, error) {
	return canonical(map[string]any{
		"Version": igagov.PolicyVersion20121017,
		"Statement": []any{map[string]any{
			"Sid": SidDenyAll, "Effect": igagov.EffectDeny, "Action": "*", "Resource": "*",
		}},
	})
}

// DenyModelDocument is model level: Deny the model actions on "*".
func DenyModelDocument() (string, string, error) {
	acts := append([]string(nil), ModelActions...)
	sort.Strings(acts)
	return canonical(map[string]any{
		"Version": igagov.PolicyVersion20121017,
		"Statement": []any{map[string]any{
			"Sid": SidDenyModel, "Effect": igagov.EffectDeny, "Action": acts, "Resource": "*",
		}},
	})
}

// RevokeDocument is R2's session revocation (DECISION P3-3), with the
// containment's request time as the cutoff.
func RevokeDocument(cutoff time.Time) (string, string, error) {
	b, h, err := igagov.RevokeSessionsDocument(cutoff)
	return string(b), h, err
}

// RevokePolicyName is R2's revocation policy name for the containment.
func RevokePolicyName(uniqueID string, containmentID uuid.UUID) string {
	return igagov.RevokePolicyName(uniqueID, containmentID.String())
}

// RevokeRemoveAfter is when the deferred revocation restore is due (R2-12:
// the IAM maximum role session lifetime plus one hour after the cutoff).
func RevokeRemoveAfter(cutoff time.Time) time.Time { return igagov.RevocationRemoveAfter(cutoff, 0) }

func canonical(v any) (string, string, error) {
	b, err := igagov.CanonicalizeValue(v)
	if err != nil {
		return "", "", err
	}
	return string(b), igagov.ContentHash(b), nil
}

// ARN helpers.

// ARNParts splits arn:<partition>:<service>:<region>:<account>:<resource>.
func ARNParts(arn string) (partition, service, region, account, resource string, ok bool) {
	p := strings.SplitN(arn, ":", 6)
	if len(p) != 6 || p[0] != "arn" {
		return "", "", "", "", "", false
	}
	return p[1], p[2], p[3], p[4], p[5], true
}

// IdentityPathOf is the IAM path of a role or user ARN ("/" when none).
func IdentityPathOf(arn string) string {
	_, _, _, _, res, ok := ARNParts(arn)
	if !ok {
		return ""
	}
	i := strings.Index(res, "/")
	j := strings.LastIndex(res, "/")
	if i < 0 || i == j {
		return "/"
	}
	return res[i : j+1]
}

// IdentityNameOf is the name of a role or user ARN.
func IdentityNameOf(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

// LambdaRegion is a function ARN's region.
func LambdaRegion(functionARN string) string {
	_, svc, region, _, res, ok := ARNParts(functionARN)
	if !ok || svc != "lambda" || !strings.HasPrefix(res, "function:") {
		return ""
	}
	return region
}

// LambdaName is a function ARN's name (no qualifier).
func LambdaName(functionARN string) string {
	_, _, _, _, res, ok := ARNParts(functionARN)
	if !ok {
		return ""
	}
	parts := strings.Split(res, ":")
	if len(parts) >= 2 && parts[0] == "function" {
		return parts[1]
	}
	return ""
}

// ECSServiceParts reads cluster and service names from a service ARN
// (arn:...:ecs:<region>:<account>:service/<cluster>/<service>, or the old
// service/<service> form, whose cluster comes from the cluster ARN).
func ECSServiceParts(serviceARN, clusterARN string) (region, cluster, service string, ok bool) {
	_, svc, reg, _, res, okA := ARNParts(serviceARN)
	if !okA || svc != "ecs" || !strings.HasPrefix(res, "service/") {
		return "", "", "", false
	}
	rest := strings.TrimPrefix(res, "service/")
	if i := strings.Index(rest, "/"); i >= 0 {
		return reg, rest[:i], rest[i+1:], true
	}
	_, _, _, _, cres, okC := ARNParts(clusterARN)
	if !okC || !strings.HasPrefix(cres, "cluster/") {
		return "", "", "", false
	}
	return reg, strings.TrimPrefix(cres, "cluster/"), rest, true
}

// ECSScalableResourceID is Application Auto Scaling's ResourceId of an ECS
// service: service/<cluster name>/<service name>.
func ECSScalableResourceID(cluster, service string) string {
	return "service/" + cluster + "/" + service
}

// TaskDefinitionFamily is a task definition ARN's family (no revision).
func TaskDefinitionFamily(taskDefARN string) string {
	_, _, _, _, res, ok := ARNParts(taskDefARN)
	if !ok {
		res = taskDefARN
	}
	res = strings.TrimPrefix(res, "task-definition/")
	if i := strings.LastIndex(res, ":"); i >= 0 {
		res = res[:i]
	}
	return res
}

// Protected reports whether tags carry authsec:protected=true.
func Protected(tags map[string]string) bool {
	return strings.EqualFold(strings.TrimSpace(tags[TagProtected]), "true")
}

func refusalf(code, format string, a ...any) Refusal {
	return Refusal{Code: code, Message: fmt.Sprintf(format, a...)}
}
