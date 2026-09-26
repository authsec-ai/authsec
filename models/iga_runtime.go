package models

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// K8sRights is a Kubernetes RBAC rule. It is not models.NativeRights.
// nonResourceURLs and resourceNames keep their original meaning.
type K8sRights struct {
	APIGroups       []string `json:"api_groups,omitempty"`
	Resources       []string `json:"resources,omitempty"`
	Verbs           []string `json:"verbs,omitempty"`
	ResourceNames   []string `json:"resource_names,omitempty"`
	NonResourceURLs []string `json:"non_resource_urls,omitempty"`
}

// POSIXRights is a POSIX ACL entry. It is not an AWS grant.
type POSIXRights struct {
	Path  string   `json:"path,omitempty"`
	Entry string   `json:"entry,omitempty"`
	Perms []string `json:"perms,omitempty"`
}

// Rights schemas stored on iga_policy.rights_schema.
const (
	RightsK8sRBAC       = "k8s_rbac"
	RightsPOSIXACL      = "posix_acl"
	RightsSystemd       = "systemd"
	RightsLSM           = "lsm"
	RightsNftables      = "nftables"
	RightsNetworkPolicy = "network_policy"
)

// CheckProviderKind rejects a provider/kind pair the database would reject.
// Other providers are not closed here.
func CheckProviderKind(provider, kind string) error {
	ok := true
	switch provider {
	case ProviderLinux:
		ok = kind == AccountKindLocalUser || kind == AccountKindLocalGroup
	case ProviderKubernetes:
		ok = kind == AccountKindK8sSA || kind == AccountKindK8sGroup
	case ProviderAD:
		ok = kind == AccountKindADUser || kind == AccountKindADGroup ||
			kind == AccountKindADComputer || kind == AccountKindADManagedSA
	}
	if !ok {
		return fmt.Errorf("provider %s does not admit account kind %s", provider, kind)
	}
	return nil
}

// IGARuntimeInstance is one process or container execution of a workload.
type IGARuntimeInstance struct {
	ID                   uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID          uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	WorkloadID           uuid.UUID       `json:"workload_id" gorm:"type:uuid;not null"`
	EstateScopeID        *uuid.UUID      `json:"estate_scope_id,omitempty" gorm:"type:uuid"`
	RuntimeKey           string          `json:"runtime_key" gorm:"not null"`
	RuntimeKind          string          `json:"runtime_kind" gorm:"not null"`
	BootOrPodIncarnation string          `json:"boot_or_pod_incarnation" gorm:"not null;default:''"`
	ParentRuntimeID      *uuid.UUID      `json:"parent_runtime_id,omitempty" gorm:"type:uuid"`
	StartedAt            *time.Time      `json:"started_at,omitempty"`
	EndedAt              *time.Time      `json:"ended_at,omitempty"`
	LastObservedAt       time.Time       `json:"last_observed_at" gorm:"not null"`
	NativeAttributes     json.RawMessage `json:"native_attributes" gorm:"type:jsonb;not null;default:'{}'"`
}

func (IGARuntimeInstance) TableName() string { return "iga_runtime_instances" }

// IGAObservedAccess is an attempt or a success. It is not a grant.
// RuntimeInstanceID must be an instance of WorkloadID. The database rejects
// a mismatch and a cross-workspace reference.
type IGAObservedAccess struct {
	ID                uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	WorkloadID        uuid.UUID  `json:"workload_id" gorm:"type:uuid;not null"`
	RuntimeInstanceID uuid.UUID  `json:"runtime_instance_id" gorm:"type:uuid;not null"`
	IdentityAccountID *uuid.UUID `json:"identity_account_id,omitempty" gorm:"type:uuid"`
	ResourceID        uuid.UUID  `json:"resource_id" gorm:"type:uuid;not null"`
	ObservationID     uuid.UUID  `json:"observation_id" gorm:"type:uuid;not null"`
	Action            string     `json:"action" gorm:"not null"`
	Outcome           string     `json:"outcome" gorm:"not null"`
	ObservedAt        time.Time  `json:"observed_at" gorm:"not null"`
	Attribution       string     `json:"attribution" gorm:"not null;default:''"`
}

func (IGAObservedAccess) TableName() string { return "iga_observed_access" }

// NewObservedAccess refuses a row that does not name both the workload and
// the runtime instance, or an outcome outside the closed set.
func NewObservedAccess(workspace, workload, runtime, resource, observation uuid.UUID, action, outcome, attribution string, at time.Time) (*IGAObservedAccess, error) {
	if workspace == uuid.Nil || workload == uuid.Nil || runtime == uuid.Nil || resource == uuid.Nil || observation == uuid.Nil {
		return nil, fmt.Errorf("observed access requires workspace, workload, runtime, resource and observation")
	}
	switch outcome {
	case "attempted", "success", "denied", "unknown":
	default:
		return nil, fmt.Errorf("observed access outcome %q", outcome)
	}
	if action == "" {
		return nil, fmt.Errorf("observed access requires an action")
	}
	return &IGAObservedAccess{
		WorkspaceID: workspace, WorkloadID: workload, RuntimeInstanceID: runtime,
		ResourceID: resource, ObservationID: observation,
		Action: action, Outcome: outcome, Attribution: attribution, ObservedAt: at,
	}, nil
}
