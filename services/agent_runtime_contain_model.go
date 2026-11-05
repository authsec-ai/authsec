package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Agent containment (SPEC-agent-runtime-visibility.md §5.8, §10; phase P3):
// the rows (migration 151), the event vocabulary it writes, and the schema
// check its routes and /capabilities report. The flow is
// agent_runtime_contain.go (API), agent_runtime_contain_job.go (the
// agent_contain job), agent_runtime_contain_aws.go (the account's AWS
// clients) and agent_runtime_contain_verify.go (behavioural verification).

// AgentContainment is one row of agent_containment.
type AgentContainment struct {
	ID                 uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID        uuid.UUID       `json:"-" gorm:"type:uuid;not null"`
	ConnectorID        uuid.UUID       `json:"connector_id" gorm:"type:uuid;not null"`
	IdentityID         uuid.UUID       `json:"identity_id" gorm:"type:uuid;not null"`
	IdentityKind       string          `json:"identity_kind" gorm:"not null"`
	IdentityARN        string          `json:"identity_arn" gorm:"column:identity_arn;not null"`
	UniqueID           string          `json:"unique_id" gorm:"column:unique_id;not null;default:''"`
	WorkloadIDs        pq.StringArray  `json:"workload_ids" gorm:"column:workload_ids;type:uuid[];not null;default:'{}'"`
	Level              string          `json:"level" gorm:"not null"`
	State              string          `json:"state" gorm:"not null;default:'previewed'"`
	StateReason        string          `json:"state_reason" gorm:"not null;default:''"`
	Reason             string          `json:"reason" gorm:"not null"`
	ReleaseReason      string          `json:"release_reason" gorm:"not null;default:''"`
	Effective          *bool           `json:"effective"`
	Verification       json.RawMessage `json:"verification" gorm:"type:jsonb;not null;default:'{}'"`
	CreatedBy          uuid.UUID       `json:"created_by" gorm:"type:uuid;not null"`
	ContainedAt        *time.Time      `json:"contained_at"`
	VerifiedAt         *time.Time      `json:"verified_at"`
	ReleaseRequestedAt *time.Time      `json:"release_requested_at"`
	ReleasedAt         *time.Time      `json:"released_at"`
	ReleasedBy         *uuid.UUID      `json:"released_by" gorm:"type:uuid"`
	PendingRestoreAt   *time.Time      `json:"pending_restore_at"`
	Preview            json.RawMessage `json:"preview" gorm:"type:jsonb;not null;default:'{}'"`
	CreatedAt          time.Time       `json:"created_at" gorm:"not null;default:now()"`
	UpdatedAt          time.Time       `json:"updated_at" gorm:"not null;default:now()"`
}

// TableName pins agent_containment.
func (AgentContainment) TableName() string { return "agent_containment" }

// AgentContainmentStep is one row of agent_containment_step.
type AgentContainmentStep struct {
	ID            uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID   uuid.UUID       `json:"-" gorm:"type:uuid;not null"`
	ContainmentID uuid.UUID       `json:"containment_id" gorm:"type:uuid;not null"`
	Seq           int             `json:"seq" gorm:"not null"`
	Kind          string          `json:"kind" gorm:"not null"`
	Target        string          `json:"target" gorm:"not null"`
	Region        string          `json:"region" gorm:"not null;default:''"`
	Before        json.RawMessage `json:"before" gorm:"column:before;type:jsonb;not null;default:'{}'"`
	After         json.RawMessage `json:"after" gorm:"column:after;type:jsonb;not null;default:'{}'"`
	State         string          `json:"state" gorm:"not null;default:'pending'"`
	Error         string          `json:"error" gorm:"not null;default:''"`
	RestoreAfter  *time.Time      `json:"restore_after"`
	AppliedAt     *time.Time      `json:"applied_at"`
	RestoredAt    *time.Time      `json:"restored_at"`
	CreatedAt     time.Time       `json:"created_at" gorm:"not null;default:now()"`
	UpdatedAt     time.Time       `json:"updated_at" gorm:"not null;default:now()"`
}

// TableName pins agent_containment_step.
func (AgentContainmentStep) TableName() string { return "agent_containment_step" }

// engineStep is the row as the engine sees it.
func (s AgentContainmentStep) engineStep() agentcontain.Step {
	st := agentcontain.Step{ID: s.ID, Seq: s.Seq, Kind: s.Kind, Target: s.Target, Region: s.Region, State: s.State, Error: s.Error,
		RestoreAfter: s.RestoreAfter, AppliedAt: s.AppliedAt, RestoredAt: s.RestoredAt}
	if len(s.Before) > 0 && string(s.Before) != "{}" {
		st.Before = append(json.RawMessage(nil), s.Before...)
		var b agentcontain.ECSBefore
		if s.Kind == agentcontain.StepECSDesired && json.Unmarshal(s.Before, &b) == nil {
			st.Cluster = b.ClusterARN
		}
	}
	if len(s.After) > 0 && string(s.After) != "{}" {
		st.After = append(json.RawMessage(nil), s.After...)
	}
	return st
}

// GovJobAgentContain is the policy job kind that runs a containment (151
// widens iga_gov_job_kind_check; repositories.GovJobKinds lists it).
const GovJobAgentContain = repositories.GovJobAgentContain

// Event names (iga_gov_event), category agent_containment. Dotted
// <object>.<verb> as T3.20 decided for new names.
const (
	GovEventContainmentRequested       = "containment.requested"
	GovEventContainmentStarted         = "containment.started"
	GovEventContainmentStepApplied     = "containment.step_applied"
	GovEventContainmentStepFailed      = "containment.step_failed"
	GovEventContainmentContained       = "containment.contained"
	GovEventContainmentPartial         = "containment.partially_contained"
	GovEventContainmentFailed          = "containment.failed"
	GovEventContainmentVerified        = "containment.verified"
	GovEventContainmentNotEffective    = "containment.not_effective"
	GovEventContainmentUnverifiable    = "containment.unverifiable"
	GovEventContainmentDrifted         = "containment.drifted"
	GovEventContainmentReleaseReq      = "containment.release_requested"
	GovEventContainmentStepRestored    = "containment.step_restored"
	GovEventContainmentReleased        = "containment.released"
	GovEventContainmentRevocationEnded = "containment.revocation_removed"
)

// GovCatAgentContainment is the Logs category of containment events.
const GovCatAgentContainment = "agent_containment"

// GovObjContainment is the events API object kind (payload containment_id).
const GovObjContainment = "agent_containment"

// The vocabulary entries are appended here rather than in
// iga_gov_event_vocabulary.go so the parallel agent-runtime packages do not
// edit one shared literal; the vocabulary test reads the slice at run time.
func init() {
	GovEventVocabulary = append(GovEventVocabulary,
		GovEventKind{GovEventContainmentRequested, GovCatAgentContainment, GovObjContainment, "An agent containment was requested (identity, level, reason, blast-radius preview); no approval (spec §10 Q6)."},
		GovEventKind{GovEventContainmentStarted, GovCatAgentContainment, GovObjContainment, "AuthSec started applying a containment through the account's enforcement role."},
		GovEventKind{GovEventContainmentStepApplied, GovCatAgentContainment, GovObjContainment, "One containment change was applied and read back (its before-state recorded first)."},
		GovEventKind{GovEventContainmentStepFailed, GovCatAgentContainment, GovObjContainment, "AWS refused one containment change; nothing was changed by it."},
		GovEventKind{GovEventContainmentContained, GovCatAgentContainment, GovObjContainment, "Every containment change is in place and read back."},
		GovEventKind{GovEventContainmentPartial, GovCatAgentContainment, GovObjContainment, "Some containment changes are in place; others were refused."},
		GovEventKind{GovEventContainmentFailed, GovCatAgentContainment, GovObjContainment, "No containment change could be applied."},
		GovEventKind{GovEventContainmentVerified, GovCatAgentContainment, GovObjContainment, "No successful call by the contained identity was seen after the grace period."},
		GovEventKind{GovEventContainmentUnverifiable, GovCatAgentContainment, GovObjContainment, "The containment's effect cannot be confirmed from CloudTrail (no events received since it, or its workloads cannot be told apart); it is neither verified nor not effective."},
		GovEventKind{GovEventContainmentNotEffective, GovCatAgentContainment, GovObjContainment, "A successful call by the contained identity after the grace period: the containment is not effective (events attached)."},
		GovEventKind{GovEventContainmentDrifted, GovCatAgentContainment, GovObjContainment, "A containment change was undone outside AuthSec (read back while contained)."},
		GovEventKind{GovEventContainmentReleaseReq, GovCatAgentContainment, GovObjContainment, "Release of a containment was requested (with a reason)."},
		GovEventKind{GovEventContainmentStepRestored, GovCatAgentContainment, GovObjContainment, "One containment change was restored to its recorded before-state."},
		GovEventKind{GovEventContainmentReleased, GovCatAgentContainment, GovObjContainment, "Every containment change was restored (a session revocation may stay until its time)."},
		GovEventKind{GovEventContainmentRevocationEnded, GovCatAgentContainment, GovObjContainment, "The session revocation kept after release was removed at its time."},
	)
	govEventObjectFilters[GovObjContainment] = struct{ column, payloadKey string }{payloadKey: "containment_id"}
}

// AgentContainSchemaHead is the migration containment needs.
const AgentContainSchemaHead = "152"

var agentContainSchema struct {
	sync.Mutex
	ok     bool
	reason string
	at     time.Time
}

// VerifyAgentContainSchema checks 151's objects and 152's index.
func VerifyAgentContainSchema(db *gorm.DB) error {
	var missing []string
	for _, rel := range []string{"agent_containment", "agent_containment_step", "uq_agent_containment_live", "uq_agent_containment_step_live_target"} {
		ok, err := repositories.HasRelation(db, rel)
		if err != nil {
			return fmt.Errorf("agent containment schema verification could not run: %w", err)
		}
		if !ok {
			missing = append(missing, rel)
		}
	}
	ok, err := repositories.ConstraintAdmits(db, "iga_gov_job", "iga_gov_job_kind_check", GovJobAgentContain)
	if err != nil {
		return fmt.Errorf("agent containment schema verification could not run: %w", err)
	}
	if !ok {
		missing = append(missing, "constraint iga_gov_job.iga_gov_job_kind_check admitting "+GovJobAgentContain)
	}
	if len(missing) > 0 {
		return fmt.Errorf("agent containment needs migration %s; missing: %s", AgentContainSchemaHead, strings.Join(missing, ", "))
	}
	return nil
}

// agentContainSchemaStatus is the cached 151 verification (re-tried at most
// every minute until it passes).
func agentContainSchemaStatus(db *gorm.DB) (bool, string) {
	agentContainSchema.Lock()
	defer agentContainSchema.Unlock()
	if !agentContainSchema.ok && time.Since(agentContainSchema.at) > time.Minute {
		agentContainSchema.at = time.Now()
		if err := VerifyAgentContainSchema(db); err != nil {
			agentContainSchema.reason = err.Error()
		} else {
			agentContainSchema.ok, agentContainSchema.reason = true, ""
		}
	}
	if !agentContainSchema.ok && agentContainSchema.reason == "" {
		return false, "the agent containment schema (" + AgentContainSchemaHead + ") has not been verified yet"
	}
	return agentContainSchema.ok, agentContainSchema.reason
}

// AgentContainStatus is whether containment can run on this server: R2 (its
// session revocation and template v2 bindings, which also needs the policy
// gate the job worker runs under), the deployment environment (AWS access
// through the enforcement role) and migration 151.
func AgentContainStatus(db *gorm.DB) (bool, string) {
	if !PolicyR2On() {
		_, reason := PolicyR2GateState().Status()
		if reason == "" {
			reason = "R2 is not available"
		}
		return false, "agent containment runs on the policy job worker and R2: " + reason
	}
	if ok, why := GovEnforcementAvailable(); !ok && agentContainAccessInstalled() == nil {
		return false, why
	}
	return agentContainSchemaStatus(db)
}

// GovCodeContainUnavailable is the 503 every containment route answers
// while AgentContainStatus is false.
const GovCodeContainUnavailable = "agent_containment_unavailable"

// RequireAgentContain is nil while containment can run, else the 503.
func RequireAgentContain(db *gorm.DB) error {
	if ok, reason := AgentContainStatus(db); !ok {
		return govErr(http.StatusServiceUnavailable, GovCodeContainUnavailable, "Agent containment is not available on this server.",
			map[string]any{"reason": reason})
	}
	return nil
}
