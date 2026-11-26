package services

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Behavioural verification (spec §5.8): the agentruntime.EventSink
// "agent_contain_verify". The CloudTrail poller and the event-stream ingest
// hand it every normalised event of a connector; for each containment of
// that connector that is in place, a successful call by the contained
// identity after contained_at + agentcontain.VerifyGrace marks it not
// effective (effective=false) with the events (agentcontain.Late, DECISION
// P3-6). Idempotent by event id: the poller and the stream deliver the same
// event, and it is recorded once. Every statement runs under RLS for the
// events' workspace.

// AgentContainVerifySinkName is the sink's registered name.
const AgentContainVerifySinkName = "agent_contain_verify"

type agentContainVerifySink struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAgentContainVerifySink builds the sink.
func NewAgentContainVerifySink(db *gorm.DB) agentruntime.EventSink {
	return &agentContainVerifySink{db: db, now: time.Now}
}

// RegisterAgentContainVerifySink registers the sink (cmd/main.go).
func RegisterAgentContainVerifySink(db *gorm.DB) {
	agentruntime.RegisterSink(NewAgentContainVerifySink(db))
}

func (s *agentContainVerifySink) Name() string { return AgentContainVerifySinkName }

// containVerification is agent_containment.verification.
type containVerification struct {
	LateEvents []agentcontain.LateEvent `json:"late_events,omitempty"`
}

// containedOf is the verifier's view of one containment.
func containedOf(r AgentContainment) agentcontain.Contained {
	c := agentcontain.Contained{ID: r.ID, Level: r.Level, IdentityARN: r.IdentityARN, UniqueID: r.UniqueID}
	if r.ContainedAt != nil {
		c.ContainedAt = *r.ContainedAt
	}
	if r.Level == agentcontain.LevelWorkload {
		var p agentcontain.Preview
		_ = json.Unmarshal(r.Preview, &p)
		sel := map[uuid.UUID]bool{}
		for _, id := range p.Selected {
			sel[id] = true
		}
		all := len(p.Workloads) > 0
		for _, w := range p.Workloads {
			if !sel[w.ID] {
				all = false
				continue
			}
			if w.Kind == agentcontain.WorkloadLambda && w.Name != "" {
				c.SessionNames = append(c.SessionNames, w.Name)
			}
		}
		c.Dedicated = all
	}
	return c
}

// Process implements agentruntime.EventSink.
func (s *agentContainVerifySink) Process(ctx context.Context, ws, connectorID uuid.UUID, events []agentruntime.Event) error {
	if len(events) == 0 || ws == uuid.Nil {
		return nil
	}
	ok := false
	for _, e := range events {
		if e.IsAPICall() && e.ErrorCode == "" {
			ok = true
			break
		}
	}
	if !ok {
		return nil
	}
	// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only.
	if ready, _ := agentContainSchemaStatus(s.db); !ready {
		return nil
	}
	return tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var rows []AgentContainment
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("workspace_id = ? AND connector_id = ? AND state IN ? AND contained_at IS NOT NULL", ws, connectorID,
				[]string{agentcontain.StateContained, agentcontain.StatePartial}).Find(&rows).Error; err != nil {
			return err
		}
		for _, r := range rows {
			late := agentcontain.Late(containedOf(r), events)
			if len(late) == 0 {
				continue
			}
			var v containVerification
			_ = json.Unmarshal(r.Verification, &v)
			merged, changed := agentcontain.MergeLate(v.LateEvents, late)
			if !changed {
				continue
			}
			raw, err := json.Marshal(map[string]any{"late_events": merged})
			if err != nil {
				return err
			}
			first := r.Effective == nil || *r.Effective
			if err := tx.Model(&AgentContainment{}).Where("workspace_id = ? AND id = ?", ws, r.ID).
				Updates(map[string]any{"effective": false, "verification": gorm.Expr("verification || ?::jsonb", string(raw)),
					"updated_at": s.now().UTC()}).Error; err != nil {
				return err
			}
			weak := true
			for _, e := range late {
				weak = weak && e.Weak
			}
			if err := appendGovEvent(tx, ws, GovEventContainmentNotEffective, models.GovActorSystem, AgentContainVerifySinkName, govEventRefs{},
				map[string]any{"containment_id": r.ID, "level": r.Level, "identity_arn": r.IdentityARN, "events": late,
					"first": first, "weak_evidence_only": weak}); err != nil {
				return err
			}
		}
		return nil
	})
}
