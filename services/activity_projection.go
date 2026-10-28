package services

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/internal/igagraph/providers"
	"github.com/authsec-ai/authsec/models"
)

// ActivityProjector indexes collector observations into the iga_runtime_activity
// table. Each observation becomes one activity row with an auto-incrementing
// activity_sequence for cursor-based catch-up reads.
type ActivityProjector struct {
	db *gorm.DB
}

// NewActivityProjector constructs the projector.
func NewActivityProjector(db *gorm.DB) *ActivityProjector {
	return &ActivityProjector{db: db}
}

// Ingest projects a batch of observations into the activity index. For each
// observation it creates an activity row with resolved IDs. Idempotency is
// enforced by the (workspace, collector, event_id) unique index via upsert.
// The activity_sequence BIGSERIAL auto-increments within the same transaction.
func (p *ActivityProjector) Ingest(
	ctx context.Context,
	workspaceID, collectorID, batchID uuid.UUID,
	observations []providers.Observation,
	objects []providers.Object,
) error {
	if len(observations) == 0 {
		return nil
	}

	// Build an object lookup by ref for resolving subject/resource refs.
	objByRef := make(map[string]*providers.Object, len(objects))
	for i := range objects {
		if objects[i].Ref != "" {
			objByRef[objects[i].Ref] = &objects[i]
		}
	}

	now := time.Now().UTC()
	activities := make([]models.IGARuntimeActivity, 0, len(observations))

	for _, obs := range observations {
		eventID := obs.ID.String()
		if eventID == "" || eventID == "00000000-0000-0000-0000-000000000000" {
			eventID = uuid.New().String()
		}

		row := models.IGARuntimeActivity{
			WorkspaceID: workspaceID,
			ActionID:    uuid.New(),
			CollectorID: collectorID,
			BatchID:     batchID,
			EventID:     eventID,
			EventFamily: classifyEventFamily(obs),
			Outcome:     normalizeOutcome(obs.Outcome),
			Attribution: obs.Attribution,
			ObservedAt:  obs.ObservedAt,
			ReceivedAt:  now,
			IndexedAt:   now,
			Count:       1,
			MappingStatus: models.MappingStatusUnmapped,
		}

		// Fill action detail fields from the observation.
		if obs.ActionDetail != nil {
			ad := obs.ActionDetail
			row.Operation = ad.Operation
			row.Phase = ad.Phase
			row.Result = ad.Result
			row.Source = obs.Source
			if ad.Count > 0 {
				row.Count = int(ad.Count)
			}
			if ad.Aggregation != "" {
				row.Aggregation = ad.Aggregation
			}
		} else {
			row.Operation = obs.Kind
			row.Source = obs.Source
		}

		// Build provenance from observation metadata.
		prov := buildProvenance(obs)
		if prov != nil {
			row.Provenance = prov
		}

		activities = append(activities, row)
	}

	// Upsert all activities in a single transaction. On conflict by
	// (workspace_id, collector_id, event_id) update the mutable fields.
	return p.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for i := range activities {
			if err := tx.Clauses(clause.OnConflict{
				Columns: []clause.Column{
					{Name: "workspace_id"},
					{Name: "collector_id"},
					{Name: "event_id"},
				},
				DoUpdates: clause.AssignmentColumns([]string{
					"batch_id", "outcome", "phase", "result",
					"operation", "source", "attribution", "provenance",
					"count", "aggregation", "indexed_at", "activity_version",
				}),
			}).Create(&activities[i]).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// EnrichIdentity updates a single activity row with a resolved identity
// account ID and bumps the activity_version. This is the late-enrichment
// path: when identity resolution completes after initial ingest.
func (p *ActivityProjector) EnrichIdentity(
	ctx context.Context,
	workspaceID, activityID, identityID uuid.UUID,
) error {
	return p.db.WithContext(ctx).
		Model(&models.IGARuntimeActivity{}).
		Where("workspace_id = ? AND id = ?", workspaceID, activityID).
		Updates(map[string]any{
			"identity_account_id": identityID,
			"mapping_status":     models.MappingStatusMapped,
			"activity_version":   gorm.Expr("activity_version + 1"),
			"indexed_at":         time.Now().UTC(),
		}).Error
}

// classifyEventFamily determines the event family from the observation.
func classifyEventFamily(obs providers.Observation) string {
	if obs.ActionDetail != nil {
		op := obs.ActionDetail.Operation
		switch {
		case op == "policy.apply" || op == "policy.remove" || op == "policy.reload":
			return models.EventFamilyEnforcementLifecycle
		case op == "policy.change" || op == "policy.create" || op == "policy.delete":
			return models.EventFamilyAdminPolicyChange
		case op == "approval.grant" || op == "approval.deny" || op == "approval.request":
			return models.EventFamilyApproval
		}
	}
	return models.EventFamilyRuntimeOperation
}

// normalizeOutcome maps observation outcomes to the canonical set.
func normalizeOutcome(s string) string {
	switch s {
	case "attempted", "success", "denied", "unknown":
		return s
	case "":
		return "unknown"
	default:
		return "unknown"
	}
}

// buildProvenance extracts provenance metadata from an observation as a JSONB
// document. Returns nil when there is nothing to store.
func buildProvenance(obs providers.Observation) json.RawMessage {
	prov := map[string]any{}
	if obs.ActionDetail != nil {
		if obs.ActionDetail.PolicyDecision != "" {
			prov["policy_decision"] = obs.ActionDetail.PolicyDecision
		}
		if obs.ActionDetail.OperationID != "" {
			prov["operation_id"] = obs.ActionDetail.OperationID
		}
		if obs.ActionDetail.Errno != 0 {
			prov["errno"] = obs.ActionDetail.Errno
		}
		if obs.ActionDetail.ExecutableDigest != "" {
			prov["executable_digest"] = obs.ActionDetail.ExecutableDigest
		}
		if obs.ActionDetail.SourceSequence != 0 {
			prov["source_sequence"] = obs.ActionDetail.SourceSequence
		}
	}
	if len(prov) == 0 {
		return nil
	}
	b, err := json.Marshal(prov)
	if err != nil {
		return nil
	}
	return b
}
