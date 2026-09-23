package igagraph

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// attachEvidence links every projected edge to the observations THIS run
// confirmed (§4.8), joined on the typed subject and subject_native_id -- never
// on a cloud_* row id, because an observation outlives the row it describes.
//
//	grant, assignment        the policy version's observation AND the holder's
//	executes_as,
//	task_execution_role      the workload's own observation
//	member_of                the user's observation (it lists the group)
//	can_assume               the role's observation (it is the read of the
//	                         trust document); pod identity: the association's
//	                         observation (PodIdentitySubjectKey)
//
// EVERY PROJECTED EDGE NEEDS EVIDENCE, COUNTED PER EDGE, NOT PER CLASS. A
// per-class count passes with one evidenced edge and ten thousand bare ones.
// An edge whose observation cannot be found is still written -- the
// configuration was read -- and counted in EvidenceMissing; the gate asserts
// zero.
func (p *Projector) attachEvidence(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	ws := snap.Run.WorkspaceID
	link := func(kind string, n int, fn func(obsID uuid.UUID) error, refs ...SubjectRef) error {
		found := 0
		for _, ref := range refs {
			for _, obsID := range snap.ConfirmedBy[ref] {
				if err := fn(obsID); err != nil {
					return err
				}
				found++
			}
		}
		if found == 0 {
			p.EvidenceMissing[kind] += n
		}
		return nil
	}

	for _, g := range r.grants {
		g := g
		if err := link("grant", 1, func(obs uuid.UUID) error {
			return p.repo.LinkAccessEdgeEvidence(tx, ws, g.ID, obs, "supports")
		}, SubjectRef{Kind: "policy", NativeID: g.PolicyNative},
			SubjectRef{Kind: "identity", NativeID: g.HolderNative}); err != nil {
			return fmt.Errorf("link grant evidence: %w", err)
		}
	}
	for _, a := range r.assignRefs {
		a := a
		if err := link("assignment", 1, func(obs uuid.UUID) error {
			return p.repo.LinkAssignmentEvidence(tx, ws, a.ID, obs, "supports")
		}, SubjectRef{Kind: "identity", NativeID: a.HolderNative},
			SubjectRef{Kind: "policy", NativeID: a.PolicyNative}); err != nil {
			return fmt.Errorf("link assignment evidence: %w", err)
		}
	}
	for kind, rels := range map[string][]relRef{
		"executes_as": r.executes, "member_of": r.memberOf, "can_assume": r.canAssume,
	} {
		for _, rel := range rels {
			rel := rel
			if err := link(kind, 1, func(obs uuid.UUID) error {
				return p.repo.LinkRelationshipEvidence(tx, ws, rel.ID, obs, "supports")
			}, SubjectRef{Kind: rel.SubjectKind, NativeID: rel.SubjectNativ}); err != nil {
				return fmt.Errorf("link %s evidence: %w", kind, err)
			}
		}
	}
	return nil
}

// recordState writes the per-partition watermark. reconciled=false until the
// Reconciler commits, so a pass interrupted between projection and
// reconciliation is visible as exactly that and gets redone (§2.8).
func (p *Projector) recordState(tx *gorm.DB, snap *Snapshot, reconciled bool) error {
	for _, part := range Partitions(snap) {
		if err := p.repo.UpsertProjectionState(tx, &models.IGAProjectionState{
			WorkspaceID:      snap.Run.WorkspaceID,
			EstateScopeID:    snap.ScopeID,
			ConnectorID:      part.ConnectorID,
			ObjectClass:      part.Class,
			RelationshipType: part.RelationshipType,
			PartitionKey:     part.Key(),
			LastRunID:        snap.Run.ID,
			LastGeneration:   int64(snap.Generation),
			CoverageState:    part.CoverageSummary(snap),
			Reconciled:       reconciled,
		}); err != nil {
			return fmt.Errorf("record projection state %s: %w", part.Key(), err)
		}
	}
	return nil
}

// EventLog is the lifecycle history this projection writes (036): every
// first_seen, retired and restored transition, stamped with the revision and
// the run. Appended by the node passes and by reconciliation, flushed in the
// same transaction -- the node row alone cannot say when or why after it has
// been overwritten.
type EventLog struct {
	ws     uuid.UUID
	rev    int64
	run    uuid.UUID
	at     time.Time
	events []models.IGALifecycleEvent
}

// NewEventLog starts a log for one projection.
func NewEventLog(ws uuid.UUID, rev int64, run uuid.UUID, at time.Time) *EventLog {
	return &EventLog{ws: ws, rev: rev, run: run, at: at}
}

func (l *EventLog) add(event, reason, class string, id uuid.UUID) {
	if l == nil {
		return
	}
	e := models.IGALifecycleEvent{
		WorkspaceID: l.ws, Rev: l.rev, ScanRunID: l.run, OccurredAt: l.at,
		Event: event, Reason: reason,
	}
	if e.SetObject(class, id) {
		l.events = append(l.events, e)
	}
}

// FirstSeen records an insert.
func (l *EventLog) FirstSeen(class string, id uuid.UUID) {
	l.add(models.LifecycleFirstSeen, "", class, id)
}

// Retired records a retirement with its reason.
func (l *EventLog) Retired(class string, id uuid.UUID, reason string) {
	l.add(models.LifecycleRetired, reason, class, id)
}

// Restored records a restoration.
func (l *EventLog) Restored(class string, id uuid.UUID) {
	l.add(models.LifecycleRestored, "", class, id)
}

// Len reports how many events are pending.
func (l *EventLog) Len() int {
	if l == nil {
		return 0
	}
	return len(l.events)
}

// Flush writes every pending event in the caller's transaction.
func (l *EventLog) Flush(tx *gorm.DB, repo GraphWriter) error {
	if l == nil || len(l.events) == 0 {
		return nil
	}
	if err := repo.InsertLifecycleEvents(tx, l.events); err != nil {
		return fmt.Errorf("write lifecycle events: %w", err)
	}
	l.events = nil
	return nil
}
