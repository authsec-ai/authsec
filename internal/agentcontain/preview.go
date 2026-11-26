package agentcontain

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Subject is the identity a containment is about, as the workspace's
// inventory (cloud_identity) and, when installed, the agent runtime resolver
// describe it.
type Subject struct {
	IdentityID  uuid.UUID         `json:"identity_id"`
	ConnectorID uuid.UUID         `json:"connector_id"`
	Kind        string            `json:"kind"` // iam_role | iam_user
	ARN         string            `json:"arn"`
	Name        string            `json:"name"`
	UniqueID    string            `json:"unique_id"` // AROA... / AIDA...
	Path        string            `json:"path"`
	AccountID   string            `json:"account_id"`
	Partition   string            `json:"partition"`
	Tags        map[string]string `json:"tags,omitempty"`
	// Label is agentruntime's label (ai_workload, suggested_agent, agent),
	// "" when unknown or no resolver is installed.
	Label string `json:"label"`
}

// ECSService is one ECS service running a task definition family.
type ECSService struct {
	ClusterARN     string            `json:"cluster_arn"`
	ServiceARN     string            `json:"service_arn"`
	TaskDefinition string            `json:"task_definition"`
	DesiredCount   int32             `json:"desired_count"`
	RunningCount   int32             `json:"running_count"`
	Tags           map[string]string `json:"tags,omitempty"`
}

// Workload is compute that runs as the subject.
type Workload struct {
	ID       uuid.UUID         `json:"id"`
	Kind     string            `json:"kind"`
	NativeID string            `json:"native_id"`
	Name     string            `json:"name"`
	Region   string            `json:"region"`
	Tags     map[string]string `json:"tags,omitempty"`
	// Via is how it runs as the identity: runs_as (cloud_workload.identity_id),
	// irsa, or eks_pod_identity (cloud_assume_edge).
	Via string `json:"via"`
	// ECSServices are the services running this task definition's family
	// (read live through the discovery role for a selected ECS workload).
	ECSServices []ECSService `json:"ecs_services,omitempty"`
	// ECSServicesRead is false when the services could not be read.
	ECSServicesRead bool `json:"ecs_services_read"`
	// TagsRead is true when the function's tags were read live (Tags is then
	// authoritative); a Lambda function whose tags could not be read is
	// refused, because authsec:protected cannot be checked.
	TagsRead bool `json:"tags_read"`
	// EventSourceMappings is the Lambda function's event source mapping
	// count, -1 when unread.
	EventSourceMappings int `json:"event_source_mappings"`
}

// ServiceUse is one AWS service the identity used recently: an Access
// Advisor row (service_last_accessed) or CloudTrail model-call evidence.
type ServiceUse struct {
	Service    string     `json:"service"`
	Source     string     `json:"source"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Calls      int        `json:"calls,omitempty"`
}

// PlannedStep is a change a level makes (the steps the job will record).
type PlannedStep struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Region string `json:"region,omitempty"`
	// Cluster is the ECS cluster ARN of an ecs_desired step.
	Cluster string `json:"cluster,omitempty"`
	// Detail says what the step does, in words.
	Detail string `json:"detail"`
}

// WorkloadRef names a workload in a level's lists.
type WorkloadRef struct {
	ID   uuid.UUID `json:"id"`
	Kind string    `json:"kind"`
	Name string    `json:"name"`
}

// LevelOption is what one level would do.
type LevelOption struct {
	Level   string `json:"level"`
	Offered bool   `json:"offered"`
	// Refusals are why it is not offered (empty when offered).
	Refusals []Refusal `json:"refusals"`
	// Stops lists the workloads it stops; AlsoStops the ones the person did
	// not select (shared role).
	Stops     []WorkloadRef `json:"stops"`
	AlsoStops []WorkloadRef `json:"also_stops"`
	// Summary is the sentence of what stops.
	Summary     string        `json:"summary"`
	SideEffects []SideEffect  `json:"side_effects"`
	Steps       []PlannedStep `json:"steps"`
}

// Capability is what the account's enforcement binding can do.
type Capability struct {
	// Binding: a verified template v2 binding able to create, attach and
	// detach AuthSec policies (identity and model levels on roles).
	Binding       bool   `json:"binding"`
	BindingReason string `json:"binding_reason,omitempty"`
	// Workload: the stack's EnableWorkloadContainment parameter, proven by
	// the self-test (workload level; IAM users at every level).
	Workload       bool   `json:"workload"`
	WorkloadReason string `json:"workload_reason,omitempty"`
}

// PreviewInput is everything BuildPreview reads.
type PreviewInput struct {
	Subject   Subject
	Workloads []Workload  // every workload running as the subject
	Selected  []uuid.UUID // the workloads a workload-level containment would stop
	Usage     []ServiceUse
	Cap       Capability
	// ContainmentID names the policies in the steps (uuid.Nil in a preview:
	// names then show <id>).
	ContainmentID uuid.UUID
	Now           time.Time
}

// Preview is the blast radius (spec §5.8 "preview -- blast radius first").
type Preview struct {
	Subject        Subject       `json:"subject"`
	Workloads      []Workload    `json:"workloads"`
	Selected       []uuid.UUID   `json:"selected"`
	SharedRole     bool          `json:"shared_role"`
	RecentServices []ServiceUse  `json:"recent_services"`
	Levels         []LevelOption `json:"levels"`
	// Refusals apply to every level (the identity itself cannot be changed).
	Refusals []Refusal `json:"refusals"`
	Warnings []string  `json:"warnings"`
	Capability
}

// Level returns the option for l, or nil.
func (p *Preview) Level(l string) *LevelOption {
	for i := range p.Levels {
		if p.Levels[i].Level == l {
			return &p.Levels[i]
		}
	}
	return nil
}

// identityRefusals are the refusals of changing the identity's IAM itself
// (identity and model levels): service-linked and AWS reserved roles,
// AuthSec's own roles, authsec:protected.
func identityRefusals(s Subject) []Refusal {
	var out []Refusal
	path := s.Path
	if path == "" {
		path = IdentityPathOf(s.ARN)
	}
	switch {
	case strings.HasPrefix(path, "/aws-service-role/"):
		out = append(out, refusalf(RefuseServiceLinkedRole,
			"%s is a service-linked role: AWS does not let any policy be attached to it, so it cannot be contained at the identity or model level. Contain the workloads instead, or the service that owns the role.", s.Name))
	case strings.HasPrefix(path, "/aws-reserved/"):
		out = append(out, refusalf(RefuseReservedRole, "%s is an AWS reserved role (IAM Identity Center); AuthSec does not change it.", s.Name))
	}
	if s.Tags["ManagedBy"] == "AuthSec" {
		out = append(out, refusalf(RefuseAuthSecOwned, "%s is one of AuthSec's own roles.", s.Name))
	}
	if Protected(s.Tags) {
		out = append(out, refusalf(RefuseProtected, "%s is tagged authsec:protected=true; AuthSec never changes it.", s.Name))
	}
	if strings.TrimSpace(s.UniqueID) == "" {
		out = append(out, refusalf(RefuseIdentityUnknown,
			"The last scan could not read %s's AWS unique id, so AuthSec cannot tell this identity from one recreated under the same name; scan the account again.", s.Name))
	}
	return out
}

func refOf(w Workload) WorkloadRef { return WorkloadRef{ID: w.ID, Kind: w.Kind, Name: w.Name} }

// BuildPreview computes the blast radius and what each level does. It reads
// nothing: the caller supplies the inventory, the live ECS reads and the
// binding's capability.
func BuildPreview(in PreviewInput) Preview {
	p := Preview{Subject: in.Subject, Workloads: in.Workloads, Selected: in.Selected, Capability: in.Cap,
		RecentServices: sortedUsage(in.Usage), Refusals: []Refusal{}, Warnings: []string{}}
	if p.Workloads == nil {
		p.Workloads = []Workload{}
	}
	if p.Selected == nil {
		p.Selected = []uuid.UUID{}
	}
	p.SharedRole = len(in.Workloads) > 1
	if in.Subject.Kind != IdentityRole && in.Subject.Kind != IdentityUser {
		p.Refusals = append(p.Refusals, refusalf(RefuseIdentityKind, "Only IAM roles and IAM users can be contained (this identity is %s).", in.Subject.Kind))
	}
	if in.Subject.Label == "" {
		p.Warnings = append(p.Warnings, "AuthSec has not labelled this identity as an AI workload or agent; containment works for any identity of the workspace.")
	}
	if !in.Cap.Binding {
		p.Warnings = append(p.Warnings, "The account's enforcement binding is not ready: "+nonEmpty(in.Cap.BindingReason, "not verified")+".")
	}
	idRef := identityRefusals(in.Subject)

	p.Levels = []LevelOption{
		workloadLevel(in, idRef),
		modelLevel(in, idRef),
		identityLevel(in, idRef),
	}
	if len(p.Refusals) > 0 {
		for i := range p.Levels {
			p.Levels[i].Offered = false
			p.Levels[i].Refusals = append(append([]Refusal(nil), p.Refusals...), p.Levels[i].Refusals...)
		}
	}
	return p
}

func nonEmpty(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

func sortedUsage(in []ServiceUse) []ServiceUse {
	out := append([]ServiceUse{}, in...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.LastUsedAt == nil && b.LastUsedAt != nil:
			return false
		case a.LastUsedAt != nil && b.LastUsedAt == nil:
			return true
		case a.LastUsedAt != nil && b.LastUsedAt != nil && !a.LastUsedAt.Equal(*b.LastUsedAt):
			return a.LastUsedAt.After(*b.LastUsedAt)
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		return a.Source < b.Source
	})
	return out
}

// workloadLevel: zero Lambda concurrency and ECS desired count 0 (with its
// Application Auto Scaling suspended) on the SELECTED workloads only.
func workloadLevel(in PreviewInput, idRef []Refusal) LevelOption {
	o := LevelOption{Level: LevelWorkload, Refusals: []Refusal{}, Stops: []WorkloadRef{}, AlsoStops: []WorkloadRef{},
		SideEffects: []SideEffect{}, Steps: []PlannedStep{}}
	if in.Subject.Kind == IdentityUser {
		o.Refusals = append(o.Refusals, refusalf(RefuseIAMUserModelOnly,
			"%s is an IAM user: no workload runs as it that AuthSec can stop; contain it at the identity or model level.", in.Subject.Name))
	}
	if !in.Cap.Workload {
		o.Refusals = append(o.Refusals, Refusal{Code: RefuseWorkloadUnavailable, Message: "Workload containment is not available for this account: " +
			nonEmpty(in.Cap.WorkloadReason, "the enforcement stack was deployed without EnableWorkloadContainment=true") + "."})
	}
	byID := map[uuid.UUID]Workload{}
	for _, w := range in.Workloads {
		byID[w.ID] = w
	}
	if len(in.Selected) == 0 {
		o.Refusals = append(o.Refusals, Refusal{Code: RefuseNoWorkloads, Message: "Choose the workloads to stop (workload_ids)."})
	}

	hasLambda, hasECS := false, false
	for _, id := range in.Selected {
		id := id
		w, ok := byID[id]
		if !ok {
			o.Refusals = append(o.Refusals, Refusal{Code: RefuseWorkloadNotOnRole, WorkloadID: &id,
				Message: "This workload does not run as " + in.Subject.Name + "."})
			continue
		}

		switch w.Kind {
		case WorkloadLambda:
			if !w.TagsRead {
				o.Refusals = append(o.Refusals, Refusal{Code: RefuseTagsUnread, WorkloadID: &id,
					Message: "The tags of " + w.Name + " could not be read, so AuthSec cannot check authsec:protected; preview again."})
				continue
			}
			if Protected(w.Tags) {
				o.Refusals = append(o.Refusals, Refusal{Code: RefuseProtected, WorkloadID: &id,
					Message: w.Name + " is tagged authsec:protected=true; AuthSec never changes it."})
				continue
			}
			hasLambda = true
			o.Stops = append(o.Stops, refOf(w))
			o.Steps = append(o.Steps, PlannedStep{Kind: StepLambdaConcurrency, Target: w.NativeID, Region: LambdaRegion(w.NativeID),
				Detail: "Set " + w.Name + "'s reserved concurrency to 0 (the current setting is recorded and restored on release)."})
			if w.EventSourceMappings > 0 {
				o.SideEffects = append(o.SideEffects, SideEffect{Code: EffectEventSourceMappings, Message: fmt.Sprintf(
					"%s has %d event source mapping(s); they keep polling. Zero concurrency throttles every invocation, so queue messages are retried and may go to a dead-letter queue or be dropped when their retention ends.",
					w.Name, w.EventSourceMappings)})
			}
		case WorkloadECSTaskDef:
			if !w.ECSServicesRead {
				o.Refusals = append(o.Refusals, Refusal{Code: RefuseNoECSService, WorkloadID: &id,
					Message: "The ECS services running " + w.Name + " could not be read; preview again."})
				continue
			}
			if len(w.ECSServices) == 0 {
				o.Refusals = append(o.Refusals, Refusal{Code: RefuseNoECSService, WorkloadID: &id,
					Message: "No ECS service runs " + w.Name + "; tasks started with RunTask cannot be stopped by a desired count. Contain the identity instead."})
				continue
			}
			var protected []string
			var services []ECSService
			for _, s := range w.ECSServices {
				if Protected(s.Tags) {
					protected = append(protected, s.ServiceARN)
					continue
				}
				services = append(services, s)
			}
			if len(protected) > 0 {
				o.Refusals = append(o.Refusals, Refusal{Code: RefuseProtected, WorkloadID: &id,
					Message: "ECS service(s) " + strings.Join(protected, ", ") + " are tagged authsec:protected=true; AuthSec never changes them."})
				continue
			}
			hasECS = true
			o.Stops = append(o.Stops, refOf(w))
			for _, s := range services {
				region, cluster, svc, ok := ECSServiceParts(s.ServiceARN, s.ClusterARN)
				if !ok {
					continue
				}
				o.Steps = append(o.Steps,
					PlannedStep{Kind: StepECSAutoscaling, Target: ECSScalableResourceID(cluster, svc), Region: region,
						Detail: "Suspend Application Auto Scaling of " + svc + " (dynamic and scheduled scaling), if it is registered, so it cannot raise the desired count again."},
					PlannedStep{Kind: StepECSDesired, Target: s.ServiceARN, Region: region, Cluster: s.ClusterARN,
						Detail: fmt.Sprintf("Set %s's desired count to 0 (it is %d; recorded and restored on release).", svc, s.DesiredCount)})
			}
		case WorkloadEC2, WorkloadEKSPod:
			o.Refusals = append(o.Refusals, Refusal{Code: RefuseWorkloadNotOffered, WorkloadID: &id,
				Message: w.Name + " is " + kindWords(w.Kind) + ": AWS offers no per-workload stop AuthSec can apply and restore exactly. Contain the identity (or the model use) instead."})
		default:
			o.Refusals = append(o.Refusals, Refusal{Code: RefuseWorkloadNotOffered, WorkloadID: &id,
				Message: w.Name + " is " + kindWords(w.Kind) + ": workload containment covers Lambda functions and ECS services only."})
		}
	}
	// AlsoStops stays empty: the workload level stops ONLY what was selected.
	if hasLambda {
		o.SideEffects = append(o.SideEffects, SideEffect{Code: EffectEventSourceMappings,
			Message: "Zero reserved concurrency does not stop event source mappings (SQS, Kinesis, DynamoDB streams): messages are retried and may dead-letter. Invocations already running finish."})
	}
	if hasECS {
		o.SideEffects = append(o.SideEffects,
			SideEffect{Code: EffectRunTaskNotStopped, Message: "Desired count 0 stops the service's tasks; tasks started with RunTask (standalone or scheduled) are not stopped."},
			SideEffect{Code: EffectAutoScalingSuspend, Message: "Application Auto Scaling of each service is suspended while contained and restored on release."})
	}
	o.Summary = fmt.Sprintf("Stops %d selected workload(s) only; the other workloads on %s keep running.", len(o.Stops), in.Subject.Name)
	o.Offered = len(o.Refusals) == 0 && len(o.Stops) > 0
	if len(o.Stops) == 0 && len(o.Refusals) == 0 {
		o.Refusals = append(o.Refusals, Refusal{Code: RefuseNoWorkloads, Message: "Nothing selected can be stopped at the workload level."})
	}
	_ = idRef // the workload level changes the workloads, not the identity's IAM
	return o
}

// identityLevel: the deny-all policy (plus R2's revocation on a role, or the
// access keys on a user).
func identityLevel(in PreviewInput, idRef []Refusal) LevelOption {
	o := LevelOption{Level: LevelIdentity, Refusals: append([]Refusal{}, idRef...), Stops: []WorkloadRef{}, AlsoStops: []WorkloadRef{},
		SideEffects: []SideEffect{}, Steps: []PlannedStep{}}
	userOrBinding(&o, in)
	sel := map[uuid.UUID]bool{}
	for _, id := range in.Selected {
		sel[id] = true
	}
	for _, w := range in.Workloads {
		o.Stops = append(o.Stops, refOf(w))
		if len(in.Selected) > 0 && !sel[w.ID] {
			o.AlsoStops = append(o.AlsoStops, refOf(w))
		}
	}
	name := policyNameOrPlaceholder(in.Subject.UniqueID, in.ContainmentID)
	o.Steps = append(o.Steps, PlannedStep{Kind: StepIAMPolicy, Target: name,
		Detail: "Create the AuthSec-owned policy /authsec/" + name + " denying every action, and attach it to " + in.Subject.Name + "."})
	switch in.Subject.Kind {
	case IdentityRole:
		rname := revokeNameOrPlaceholder(in.Subject.UniqueID, in.ContainmentID)
		o.Steps = append(o.Steps, PlannedStep{Kind: StepSessionRevoke, Target: rname,
			Detail: "Attach R2's session revocation /authsec/" + rname + ": sessions issued before the containment stay refused until 13 hours after it, also after release."})
		o.SideEffects = append(o.SideEffects, SideEffect{Code: EffectSessionsRevoked,
			Message: "Sessions issued before the containment stay refused after release until 13 hours after the containment (R2 session revocation); new sessions work again at release."})
	case IdentityUser:
		o.Steps = append(o.Steps, PlannedStep{Kind: StepAccessKey, Target: in.Subject.Name,
			Detail: "Set every Active access key of " + in.Subject.Name + " Inactive (recorded; release reactivates only those keys)."})
		o.SideEffects = append(o.SideEffects, SideEffect{Code: EffectAccessKeysInactive,
			Message: "Every Active access key of the user is deactivated: anything else using those keys stops too."})
	}
	if len(in.Workloads) > 1 {
		o.SideEffects = append(o.SideEffects, SideEffect{Code: EffectSharedRole, Message: fmt.Sprintf(
			"%s is shared by %d workloads: identity containment stops every one of them. Prefer the workload level when only some misbehave.",
			in.Subject.Name, len(in.Workloads))})
	}
	o.SideEffects = append(o.SideEffects, SideEffect{Code: EffectInFlight,
		Message: "A call already authorised (a long-running request, a pre-signed URL) is not interrupted; IAM changes take a few seconds to apply everywhere."})
	o.Summary = fmt.Sprintf("Stops every call by %s, so every workload running as it (%d).", in.Subject.Name, len(in.Workloads))
	o.Offered = len(o.Refusals) == 0
	return o
}

// modelLevel: deny the model actions only.
func modelLevel(in PreviewInput, idRef []Refusal) LevelOption {
	o := LevelOption{Level: LevelModel, Refusals: append([]Refusal{}, idRef...), Stops: []WorkloadRef{}, AlsoStops: []WorkloadRef{},
		SideEffects: []SideEffect{}, Steps: []PlannedStep{}}
	userOrBinding(&o, in)
	name := policyNameOrPlaceholder(in.Subject.UniqueID, in.ContainmentID)
	o.Steps = append(o.Steps, PlannedStep{Kind: StepIAMPolicy, Target: name,
		Detail: "Create the AuthSec-owned policy /authsec/" + name + " denying " + strings.Join(ModelActions, ", ") + ", and attach it to " + in.Subject.Name + "."})
	o.SideEffects = append(o.SideEffects, SideEffect{Code: EffectModelOnly,
		Message: "Only model calls (Bedrock, AgentCore invoke) are refused; everything else the identity does keeps working. Calls to a model provider outside AWS are not affected."})
	if len(in.Workloads) > 1 {
		o.SideEffects = append(o.SideEffects, SideEffect{Code: EffectSharedRole, Message: fmt.Sprintf(
			"%s is shared by %d workloads: every one of them loses model access.", in.Subject.Name, len(in.Workloads))})
	}
	for _, w := range in.Workloads {
		o.Stops = append(o.Stops, refOf(w))
	}
	o.Summary = "Stops model use by " + in.Subject.Name + "; its other access is unchanged."
	o.Offered = len(o.Refusals) == 0
	return o
}

func userOrBinding(o *LevelOption, in PreviewInput) {
	if !in.Cap.Binding {
		o.Refusals = append(o.Refusals, Refusal{Code: RefuseBindingUnavailable,
			Message: "AuthSec cannot change IAM in this account: " + nonEmpty(in.Cap.BindingReason, "the enforcement binding is not verified on template v2") + "."})
	}
	if in.Subject.Kind == IdentityUser && !in.Cap.Workload {
		o.Refusals = append(o.Refusals, Refusal{Code: RefuseUserNeedsParameter,
			Message: "Containing an IAM user attaches a policy to the user and deactivates its keys, which the enforcement stack allows only with EnableWorkloadContainment=true: " +
				nonEmpty(in.Cap.WorkloadReason, "the parameter is not set") + "."})
	}
}

func policyNameOrPlaceholder(uniqueID string, id uuid.UUID) string {
	if id == uuid.Nil {
		return ContainPolicyPrefix + uniqueID + "-<id>"
	}
	return ContainPolicyName(uniqueID, id)
}

func revokeNameOrPlaceholder(uniqueID string, id uuid.UUID) string {
	if id == uuid.Nil {
		return "AuthSecRevokeOlderSessions-" + uniqueID + "-<id>"
	}
	return RevokePolicyName(uniqueID, id)
}

func kindWords(k string) string {
	switch k {
	case WorkloadEC2:
		return "an EC2 instance"
	case WorkloadEKSPod:
		return "an EKS pod (IRSA / Pod Identity)"
	case WorkloadAssumer:
		return "a principal the role's trust policy lets assume it (not compute AuthSec can stop)"
	case WorkloadLambda:
		return "a Lambda function"
	case WorkloadECSTaskDef:
		return "an ECS task definition"
	case "bedrock_agent":
		return "a Bedrock agent"
	case "bedrock_agentcore_runtime":
		return "an AgentCore runtime"
	case "bedrock_agentcore_gateway":
		return "an AgentCore gateway"
	}
	return "a " + k
}
