// Package providers normalizes collector and directory facts into a projection
// plan. It does not open a database. The writer in services assigns ids.
package providers

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Object is one source object. Native and Attrs are the collector shape.
// Raw is the stored payload, used for the AD inventory shape.
type Object struct {
	Ref         string
	Kind        string
	Recognition string
	Native      map[string]any
	Attrs       map[string]any
	Raw         json.RawMessage
}

// Observation is one stored fact. Preview observations are not existence.
type Observation struct {
	ID          uuid.UUID
	Kind        string
	SubjectRef  string
	IdentityRef string
	ResourceRef string
	Runtime     map[string]any
	ObservedAt  time.Time
	Outcome     string
	Attribution string
	Preview     bool
}

// Input is one collector or directory pass.
type Input struct {
	Provider     string
	EstateID     string
	Objects      []Object
	Observations []Observation
}

// Identity is a canonical account the writer upserts.
type Identity struct {
	SourceKey    string
	ImmutableKey string
	Continuity   string
	Provider     string
	Kind         string
	Name         string
	State        string
	Backing      string
	Attrs        json.RawMessage
	DN           string
	Ref          string
}

// Workload is a canonical runtime.
type Workload struct {
	SourceKey    string
	ImmutableKey string
	Continuity   string
	Provider     string
	RuntimeKind  string
	Name         string
	Attrs        json.RawMessage
	Ref          string
	// DeclaredAWSRole is an annotation. It does not create an AWS identity
	// and it does not create can_assume.
	DeclaredAWSRole string
}

// Resource is a file, endpoint, secret reference or Kubernetes object.
type Resource struct {
	SourceKey       string
	Provider        string
	Kind            string
	Name            string
	ReferenceStatus string
	NativeKind      string
	Metadata        json.RawMessage
	Attrs           json.RawMessage
	Ref             string
}

// Policy is a native policy. It is not an AuthSec guardrail.
type Policy struct {
	SourceKey    string
	ImmutableKey string
	Continuity   string
	Provider     string
	Kind         string
	Name         string
	RightsSchema string
	Document     json.RawMessage
	Partial      bool
}

// Statement is one native rule. Kubernetes grants are partial and unknown.
type Statement struct {
	SourceKey   string
	PolicyKey   string
	NativeKind  string
	Rights      json.RawMessage
	Partial     bool
	EffectAllow bool
}

// Assignment is a policy holder. ScopeKind namespace keeps a RoleBinding to
// a ClusterRole namespaced.
type Assignment struct {
	SourceKey    string
	PolicyKey    string
	HolderKey    string
	Kind         string
	ScopeKind    string
	NamespaceUID string
	BindingUID   string
}

// Grant is an Allow edge. Constraints do not produce one.
type Grant struct {
	SourceKey     string
	AssignmentKey string
	StatementKey  string
	HolderKey     string
	Calculation   string
	Conclusion    string
}

// Relationship is executes_as (declared) or member_of.
type Relationship struct {
	SourceKey      string
	Type           string
	Basis          string
	DerivationRule string
	FromWorkload   string
	FromIdentity   string
	ToIdentity     string
}

// Runtime is one process or container execution.
type Runtime struct {
	SourceKey   string
	WorkloadKey string
	Kind        string
	Incarnation string
	ObservedAt  time.Time
	Observation uuid.UUID
}

// Binding is an observed runtime identity. A container UID uses kind container_uid.
type Binding struct {
	RuntimeKey  string
	IdentityKey string
	Kind        string
	Observation uuid.UUID
	From        time.Time
}

// Observed is one access fact.
type Observed struct {
	WorkloadKey string
	RuntimeKey  string
	IdentityKey string
	ResourceKey string
	Observation uuid.UUID
	Action      string
	Outcome     string
	Attribution string
	ObservedAt  time.Time
}

// PolicyBinding attaches a constraint to a workload. It is not a grant.
type PolicyBinding struct {
	SourceKey   string
	WorkloadKey string
	PolicyKey   string
	Kind        string
	Observation uuid.UUID
}

// ResourceBinding is a declared mount, secret ref or service dependency.
type ResourceBinding struct {
	SourceKey   string
	WorkloadKey string
	ResourceKey string
	Kind        string
	Observation uuid.UUID
}

// Skipped is one object that could not be keyed. The rest of the pass still
// projects. A skipped object must not be treated as absent.
type Skipped struct {
	Kind   string
	Ref    string
	Reason string
}

// Plan is the projection input. Keys are source keys, not row ids.
type Plan struct {
	Identities       []Identity
	Workloads        []Workload
	Resources        []Resource
	Policies         []Policy
	Statements       []Statement
	Assignments      []Assignment
	Grants           []Grant
	Relationships    []Relationship
	Runtimes         []Runtime
	Bindings         []Binding
	Observed         []Observed
	PolicyBindings   []PolicyBinding
	ResourceBindings []ResourceBinding
	Unresolved       []string
	Skipped          []Skipped
}

// Normalize builds a plan for linux, kubernetes or ad. Unknown native
// attributes are ignored. A provider does not project another provider's kinds.
func Normalize(in Input) (*Plan, error) {
	switch in.Provider {
	case "linux":
		return normalizeLinux(in)
	case "kubernetes":
		return normalizeKubernetes(in)
	case "ad":
		return normalizeAD(in)
	default:
		return &Plan{}, nil
	}
}

func skipObject(p *Plan, o Object, err error) {
	if err == nil {
		return
	}
	ref := o.Ref
	if ref == "" {
		ref = o.Recognition
	}
	p.Skipped = append(p.Skipped, Skipped{Kind: o.Kind, Ref: ref, Reason: err.Error()})
}

func str(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	return asString(m[k])
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return ""
		}
		if t == math.Trunc(t) && t <= math.MaxInt64 && t >= math.MinInt64 {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case json.Number:
		return strings.TrimSpace(t.String())
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func nested(m map[string]any, k string) map[string]any {
	if m == nil {
		return nil
	}
	switch t := m[k].(type) {
	case map[string]any:
		return t
	default:
		return nil
	}
}

func list(m map[string]any, k string) []any {
	if m == nil {
		return nil
	}
	t, _ := m[k].([]any)
	return t
}

func stringList(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s := asString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}

func mustJSON(v any) json.RawMessage {
	if v == nil {
		return json.RawMessage(`{}`)
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) == 0 {
		return json.RawMessage(`{}`)
	}
	return b
}

// displayAttrs drops secret-shaped keys. The stored document is display only.
func displayAttrs(native, attrs map[string]any) json.RawMessage {
	out := map[string]any{}
	copyPublic(out, native)
	copyPublic(out, attrs)
	if len(out) == 0 {
		return json.RawMessage(`{}`)
	}
	return mustJSON(out)
}

func copyPublic(dst, src map[string]any) {
	for k, v := range src {
		if secretKey(k) {
			continue
		}
		dst[k] = v
	}
}

func secretKey(k string) bool {
	switch strings.ToLower(k) {
	case "value", "secret", "password", "token", "bearer", "unicodepwd",
		"msds-managedpassword", "env", "args", "arguments":
		return true
	default:
		return false
	}
}

func outcome(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "attempted", "success", "denied", "unknown":
		return strings.ToLower(strings.TrimSpace(s))
	case "":
		return "unknown"
	default:
		return "unknown"
	}
}

// KnownKind reports an object type this provider projects. Anything else
// stays on the support-only path.
func KnownKind(provider, kind string) bool {
	switch provider {
	case "linux":
		switch kind {
		case "linux.systemd_workload", "linux.process_group", "linux.local_account",
			"linux.local_group", "linux.file", "network.endpoint", "secret.reference":
			return true
		default:
			return false
		}
	case "kubernetes":
		switch kind {
		case "k8s.workload", "k8s.pod", "k8s.service_account", "k8s.role", "k8s.cluster_role",
			"k8s.role_binding", "k8s.cluster_role_binding", "k8s.service", "k8s.pvc", "k8s.pv",
			"k8s.network_policy", "secret.reference":
			return true
		default:
			return false
		}
	case "ad":
		switch strings.ToLower(kind) {
		case "user", "group", "computer", "msds-managedserviceaccount", "msds-groupmanagedserviceaccount",
			"ad_user", "ad_group", "ad_computer", "ad_managed_service_account":
			return true
		default:
			return false
		}
	default:
		return false
	}
}
