package services

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// SecOps W2 (SPEC-secops-backend-upgrade.md P2, P3, P4, P13, decision 4):
// holds, release by a second person, the proof state, narrowing, and the
// gateway deny list. Every statement runs in a transaction under row-level
// security for the token's (or job's) workspace; another workspace's
// containment, hold or request is 404.
//
//	POST /containments/:id/holds                         {case_id}   add a hold (tier 1)
//	POST /containments/:id/holds/:case/release           {reason}    tier 3: a release request
//	POST /containments/:id/release                       {reason}    tier 3; 409 held_by_cases while held
//	POST /containments/:id/release-requests/:rid/approve {reason}    a DIFFERENT user with governance:approve
//	POST /containments/:id/release-requests/:rid/reject  {reason}    the requester withdraws, or an approver rejects
//	POST /containments/:id/release-requests/:rid/review  {note}      review of a break-glass release
//	POST /containments/:id/narrow                        {level, target?, workload_ids?, reason}
//
// DECISION W2-1 (second person): releasing is tier 3. A release request is
// applied only when a user other than its author who holds governance:approve
// approves it. When no such user exists in the workspace (a single admin),
// the request is applied alone as break-glass: recorded, alerted
// (containment.release_break_glass) and due for review by another person
// within 24 hours (review_due_at).
//
// DECISION W2-2 (holds): a containment with holds is released only when its
// last active hold is released; releasing a hold is the tier-3 request
// above. A containment no case holds (rows written before W2) is released by
// the same tier-3 request with no case.
//
// DECISION W2-3 (narrow): a narrower stop is a new containment linked by
// narrowed_from that takes over the wider one's active holds. The wider one
// is released automatically, without a request, only once the narrower one
// is proven; until then both hold.

// AgentContainmentHold is one row of agent_containment_hold.
type AgentContainmentHold struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID  `json:"-" gorm:"type:uuid;not null"`
	ContainmentID    uuid.UUID  `json:"containment_id" gorm:"type:uuid;not null"`
	CaseID           uuid.UUID  `json:"case_id" gorm:"type:uuid;not null"`
	State            string     `json:"state" gorm:"not null;default:'active'"`
	HeldBy           uuid.UUID  `json:"held_by" gorm:"type:uuid;not null"`
	HeldAt           time.Time  `json:"held_at" gorm:"not null"`
	ReleasedBy       *uuid.UUID `json:"released_by" gorm:"type:uuid"`
	ReleasedAt       *time.Time `json:"released_at"`
	ReleaseReason    string     `json:"release_reason" gorm:"not null;default:''"`
	ReleaseRequestID *uuid.UUID `json:"release_request_id" gorm:"type:uuid"`
}

// TableName pins agent_containment_hold.
func (AgentContainmentHold) TableName() string { return "agent_containment_hold" }

// AgentContainmentReleaseRequest is one row of agent_containment_release_request.
type AgentContainmentReleaseRequest struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID    uuid.UUID  `json:"-" gorm:"type:uuid;not null"`
	ContainmentID  uuid.UUID  `json:"containment_id" gorm:"type:uuid;not null"`
	CaseID         *uuid.UUID `json:"case_id" gorm:"type:uuid"`
	Reason         string     `json:"reason" gorm:"not null"`
	State          string     `json:"state" gorm:"not null;default:'pending'"`
	RequestedBy    uuid.UUID  `json:"requested_by" gorm:"type:uuid;not null"`
	RequestedAt    time.Time  `json:"requested_at" gorm:"not null"`
	DecidedBy      *uuid.UUID `json:"decided_by" gorm:"type:uuid"`
	DecidedAt      *time.Time `json:"decided_at"`
	DecisionReason string     `json:"decision_reason" gorm:"not null;default:''"`
	BreakGlass     bool       `json:"break_glass" gorm:"not null;default:false"`
	ReviewDueAt    *time.Time `json:"review_due_at"`
	ReviewedBy     *uuid.UUID `json:"reviewed_by" gorm:"type:uuid"`
	ReviewedAt     *time.Time `json:"reviewed_at"`
	ReviewNote     string     `json:"review_note" gorm:"not null;default:''"`
}

// TableName pins agent_containment_release_request.
func (AgentContainmentReleaseRequest) TableName() string { return "agent_containment_release_request" }

// Hold, request and proof vocabulary.
const (
	HoldActive   = "active"
	HoldReleased = "released"

	ReleaseRequestPending   = "pending"
	ReleaseRequestApproved  = "approved"
	ReleaseRequestRejected  = "rejected"
	ReleaseRequestWithdrawn = "withdrawn"

	// BreakGlassReviewWithin is when a break-glass release must be reviewed.
	BreakGlassReviewWithin = 24 * time.Hour
)

// Error codes.
const (
	GovCodeHeldByCases          = "held_by_cases"
	GovCodeHoldExists           = "hold_exists"
	GovCodeHoldNotFound         = "hold_not_found"
	GovCodeCaseNotFound         = "case_not_found"
	GovCodeReleasePending       = "release_request_pending"
	GovCodeReleaseNotPending    = "release_request_not_pending"
	GovCodeSecondPersonRequired = "second_person_required"
	GovCodeNotNarrower          = "not_narrower"
	GovCodeProbeNotPossible     = "probe_not_possible"
)

// Events.
const (
	GovEventContainmentHoldAdded       = "containment.hold_added"
	GovEventContainmentHoldReleased    = "containment.hold_released"
	GovEventContainmentReleaseAsked    = "containment.release_approval_requested"
	GovEventContainmentReleaseApproved = "containment.release_approved"
	GovEventContainmentReleaseRejected = "containment.release_rejected"
	GovEventContainmentBreakGlass      = "containment.release_break_glass"
	GovEventContainmentReleaseReviewed = "containment.release_reviewed"
	GovEventContainmentProofState      = "containment.proof_state"
	GovEventContainmentNarrowed        = "containment.narrowed"
	GovEventContainmentNarrowReleased  = "containment.narrowed_released"
	GovEventContainmentProbe           = "containment.probe"
	// GovEventAgentAskNeeded: a stop AuthSec cannot write (platform level)
	// must be asked of someone. TODO(W4): agent_ask delivers it.
	GovEventAgentAskNeeded = "agent.ask_needed"
)

func init() {
	GovEventVocabulary = append(GovEventVocabulary,
		GovEventKind{GovEventContainmentHoldAdded, GovCatAgentContainment, GovObjContainment, "A case now holds the containment: it is released only when its last hold is."},
		GovEventKind{GovEventContainmentHoldReleased, GovCatAgentContainment, GovObjContainment, "A case's hold on the containment was released (approved by a second person, or break-glass)."},
		GovEventKind{GovEventContainmentReleaseAsked, GovCatAgentContainment, GovObjContainment, "A release (of a hold, or of a containment no case holds) waits for a second person with governance:approve."},
		GovEventKind{GovEventContainmentReleaseApproved, GovCatAgentContainment, GovObjContainment, "A second person approved a containment release request."},
		GovEventKind{GovEventContainmentReleaseRejected, GovCatAgentContainment, GovObjContainment, "A containment release request was rejected by an approver or withdrawn by its author."},
		GovEventKind{GovEventContainmentBreakGlass, GovCatAgentContainment, GovObjContainment, "No other user may approve, so a release was applied alone (break-glass); another person must review it within 24 hours."},
		GovEventKind{GovEventContainmentReleaseReviewed, GovCatAgentContainment, GovObjContainment, "Another person reviewed a break-glass release."},
		GovEventKind{GovEventContainmentProofState, GovCatAgentContainment, GovObjContainment, "The containment's proof state changed (requested, applied, proven, unproven, cannot_verify, kept)."},
		GovEventKind{GovEventContainmentNarrowed, GovCatAgentContainment, GovObjContainment, "A narrower stop was requested in place of this containment; the wider one is released once the narrower one is proven."},
		GovEventKind{GovEventContainmentNarrowReleased, GovCatAgentContainment, GovObjContainment, "The narrower stop was proven, so the wider containment it replaces is being released."},
		GovEventKind{GovEventContainmentProbe, GovCatAgentContainment, GovObjContainment, "AuthSec made a harmless call with its own brokered credentials as the contained identity; a refusal naming the containment's policy proves it."},
		GovEventKind{GovEventAgentAskNeeded, GovCatAgentContainment, GovObjContainment, "A stop AuthSec cannot write itself (a platform) was recorded and must be asked of whoever administers it."},
	)
}

/* ---------------------------------- cases ---------------------------------- */

// ContainCaseChecker says whether a case exists in the workspace. W3 owns
// agent_case; until it merges, the table may be absent.
type ContainCaseChecker interface {
	CaseExists(tx *gorm.DB, ws, caseID uuid.UUID) (bool, error)
}

var containCases struct {
	sync.RWMutex
	c ContainCaseChecker
}

// SetContainCaseChecker installs the case check (tests) and returns a
// function restoring the previous one; nil restores the table check.
func SetContainCaseChecker(c ContainCaseChecker) (restore func()) {
	containCases.Lock()
	prev := containCases.c
	containCases.c = c
	containCases.Unlock()
	return func() { SetContainCaseChecker(prev) }
}

func currentContainCases() ContainCaseChecker {
	containCases.RLock()
	defer containCases.RUnlock()
	if containCases.c != nil {
		return containCases.c
	}
	return agentCaseTable{}
}

// agentCaseTable reads agent_case when it exists. Without it (W3 not merged)
// a case cannot be checked: the hold is allowed, with a warning logged once.
type agentCaseTable struct{}

var agentCaseWarnOnce sync.Once

func (agentCaseTable) CaseExists(tx *gorm.DB, ws, caseID uuid.UUID) (bool, error) {
	ok, err := repositories.HasRelation(tx, "agent_case")
	if err != nil {
		return false, err
	}
	if !ok {
		agentCaseWarnOnce.Do(func() {
			log.Printf("[containment] agent_case does not exist yet (W3): containment holds are accepted without checking the case")
		})
		return true, nil
	}
	var n int64
	if err := tx.Table("agent_case").Where("workspace_id = ? AND id = ?", ws, caseID).Count(&n).Error; err != nil {
		return false, err
	}
	return n > 0, nil
}

// requireCaseTx is 404 case_not_found for a case ws does not have.
func requireCaseTx(tx *gorm.DB, ws, caseID uuid.UUID) error {
	ok, err := currentContainCases().CaseExists(tx, ws, caseID)
	if err != nil {
		return err
	}
	if !ok {
		return govErr(http.StatusNotFound, GovCodeCaseNotFound, "No such case.", map[string]any{"case_id": caseID})
	}
	return nil
}

/* ---------------------------------- holds ---------------------------------- */

func addHoldTx(tx *gorm.DB, ws, containmentID, caseID, actor uuid.UUID, now time.Time) error {
	h := AgentContainmentHold{ID: uuid.New(), WorkspaceID: ws, ContainmentID: containmentID, CaseID: caseID, State: HoldActive,
		HeldBy: actor, HeldAt: now}
	if err := tx.Create(&h).Error; err != nil {
		if isUniqueViolation(err, "uq_agent_containment_hold_active") {
			return govConflict(GovCodeHoldExists, "This case already holds the containment.", map[string]any{"case_id": caseID})
		}
		return err
	}
	kind, aid := userActor(actor)
	return appendGovEvent(tx, ws, GovEventContainmentHoldAdded, kind, aid, govEventRefs{}, map[string]any{
		"containment_id": containmentID, "case_id": caseID, "hold_id": h.ID})
}

// copyHoldsTx gives the narrower containment the wider one's active holds.
func copyHoldsTx(tx *gorm.DB, ws, from, to, actor uuid.UUID, now time.Time) error {
	var hs []AgentContainmentHold
	if err := tx.Where("workspace_id = ? AND containment_id = ? AND state = ?", ws, from, HoldActive).Order("held_at, id").Find(&hs).Error; err != nil {
		return err
	}
	for _, h := range hs {
		if err := addHoldTx(tx, ws, to, h.CaseID, actor, now); err != nil {
			return err
		}
	}
	return nil
}

func activeHoldsTx(tx *gorm.DB, ws, containmentID uuid.UUID) ([]AgentContainmentHold, error) {
	var hs []AgentContainmentHold
	err := tx.Where("workspace_id = ? AND containment_id = ? AND state = ?", ws, containmentID, HoldActive).Order("held_at, id").Find(&hs).Error
	return hs, err
}

func liveContainment(state string) bool {
	for _, s := range agentcontain.ReleasableStates {
		if s == state {
			return true
		}
	}
	return false
}

// AgentContainHoldRequest is POST /containments/:id/holds.
type AgentContainHoldRequest struct {
	CaseID string `json:"case_id"`
}

// AddHold is POST /containments/:id/holds: another case holds the stop.
func (s *AgentContain) AddHold(ctx context.Context, ws, actor, id uuid.UUID, req AgentContainHoldRequest) (*AgentContainmentView, error) {
	// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only.
	if err := RequireAgentContain(s.db); err != nil {
		return nil, err
	}
	caseID, err := uuid.Parse(strings.TrimSpace(req.CaseID))
	if err != nil {
		return nil, GovBadParam("case_id", "case_id must be a uuid.")
	}
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		row, err := loadContainment(tx, ws, id, true)
		if err != nil {
			return err
		}
		if !liveContainment(row.State) {
			return govConflict(GovCodeNotReleasable, "Only a live containment can be held (state "+row.State+").", map[string]any{"state": row.State})
		}
		if err := requireCaseTx(tx, ws, caseID); err != nil {
			return err
		}
		return addHoldTx(tx, ws, id, caseID, actor, s.now().UTC())
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, ws, id)
}

/* ----------------------------- release requests ---------------------------- */

// AgentContainReleaseOutcome is what a release request answers: the request
// and the containment after it.
type AgentContainReleaseOutcome struct {
	Request     AgentContainmentReleaseRequest `json:"release_request"`
	Containment AgentContainmentView           `json:"containment"`
	// Applied: the release took effect now (approved, or break-glass).
	Applied bool `json:"applied"`
}

// AgentContainDecisionRequest is approve / reject / review.
type AgentContainDecisionRequest struct {
	Reason string `json:"reason"`
}

func containReason(raw, what string) (string, error) {
	r := strings.TrimSpace(raw)
	if r == "" {
		return "", GovBadParam("reason", "A "+what+" needs a reason.")
	}
	if len(r) > MaxContainReason {
		return "", GovBadParam("reason", "reason is too long.")
	}
	return r, nil
}

// Release is POST /containments/:id/release: a tier-3 release request for a
// containment no case holds (409 held_by_cases otherwise).
func (s *AgentContain) Release(ctx context.Context, ws, actor, id uuid.UUID, req AgentContainReleaseRequest) (*AgentContainReleaseOutcome, error) {
	return s.RequestRelease(ctx, ws, actor, id, nil, req.Reason)
}

// ReleaseHold is POST /containments/:id/holds/:case/release.
func (s *AgentContain) ReleaseHold(ctx context.Context, ws, actor, id, caseID uuid.UUID, req AgentContainReleaseRequest) (*AgentContainReleaseOutcome, error) {
	return s.RequestRelease(ctx, ws, actor, id, &caseID, req.Reason)
}

// RequestRelease records a release request (of one case's hold, or of the
// containment when caseID is nil) and applies it at once only as
// break-glass (no other approver in the workspace).
func (s *AgentContain) RequestRelease(ctx context.Context, ws, actor, id uuid.UUID, caseID *uuid.UUID, rawReason string) (*AgentContainReleaseOutcome, error) {
	// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only.
	if err := RequireAgentContain(s.db); err != nil {
		return nil, err
	}
	reason, err := containReason(rawReason, "release")
	if err != nil {
		return nil, err
	}
	out := &AgentContainReleaseOutcome{}
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		row, err := loadContainment(tx, ws, id, true)
		if err != nil {
			return err
		}
		if !liveContainment(row.State) {
			return govConflict(GovCodeNotReleasable, "This containment cannot be released in state "+row.State+".", map[string]any{"state": row.State})
		}
		holds, err := activeHoldsTx(tx, ws, id)
		if err != nil {
			return err
		}
		if caseID == nil && len(holds) > 0 {
			cases := make([]uuid.UUID, 0, len(holds))
			for _, h := range holds {
				cases = append(cases, h.CaseID)
			}
			return govConflict(GovCodeHeldByCases, "Cases hold this containment: release each case's hold instead.",
				map[string]any{"case_ids": cases})
		}
		if caseID != nil {
			found := false
			for _, h := range holds {
				found = found || h.CaseID == *caseID
			}
			if !found {
				return govErr(http.StatusNotFound, GovCodeHoldNotFound, "This case does not hold the containment.", map[string]any{"case_id": *caseID})
			}
		}
		now := s.now().UTC()
		rr := AgentContainmentReleaseRequest{ID: uuid.New(), WorkspaceID: ws, ContainmentID: id, CaseID: caseID, Reason: reason,
			State: ReleaseRequestPending, RequestedBy: actor, RequestedAt: now}
		approvers, err := WorkspaceUsersHoldingPermission(tx, ws, "governance", "approve")
		if err != nil {
			return err
		}
		others := 0
		for _, u := range approvers {
			if u != actor {
				others++
			}
		}
		breakGlass := others == 0
		if breakGlass {
			due := now.Add(BreakGlassReviewWithin)
			rr.State, rr.DecidedBy, rr.DecidedAt, rr.BreakGlass, rr.ReviewDueAt = ReleaseRequestApproved, &actor, &now, true, &due
			rr.DecisionReason = "break-glass: no other user in the workspace holds governance:approve"
		}
		if err := tx.Create(&rr).Error; err != nil {
			if isUniqueViolation(err, "uq_agent_containment_release_request_pending") {
				return govConflict(GovCodeReleasePending, "A release request for this is already waiting for approval.", nil)
			}
			return err
		}
		kind, aid := userActor(actor)
		pl := map[string]any{"containment_id": id, "release_request_id": rr.ID, "case_id": caseID, "reason": reason}
		if !breakGlass {
			pl["approvers"] = others
			if err := appendGovEvent(tx, ws, GovEventContainmentReleaseAsked, kind, aid, govEventRefs{}, pl); err != nil {
				return err
			}
		} else {
			pl["review_due_at"] = rr.ReviewDueAt
			pl["note"] = "Applied alone: no other user may approve. Another person must review it within 24 hours."
			if err := appendGovEvent(tx, ws, GovEventContainmentBreakGlass, kind, aid, govEventRefs{}, pl); err != nil {
				return err
			}
			if err := s.applyReleaseTx(tx, ws, actor, row, &rr, now); err != nil {
				return err
			}
			out.Applied = true
		}
		out.Request = rr
		return nil
	})
	if err != nil {
		return nil, err
	}
	v, err := s.Get(ctx, ws, id)
	if err != nil {
		return nil, err
	}
	out.Containment = *v
	return out, nil
}

// applyReleaseTx applies an approved request: the case's hold is released,
// and the containment starts releasing when no active hold is left.
func (s *AgentContain) applyReleaseTx(tx *gorm.DB, ws, actor uuid.UUID, row *AgentContainment, rr *AgentContainmentReleaseRequest, now time.Time) error {
	kind, aid := userActor(actor)
	if rr.CaseID != nil {
		res := tx.Model(&AgentContainmentHold{}).Where("workspace_id = ? AND containment_id = ? AND case_id = ? AND state = ?",
			ws, row.ID, *rr.CaseID, HoldActive).Updates(map[string]any{"state": HoldReleased, "released_by": actor, "released_at": now,
			"release_reason": rr.Reason, "release_request_id": rr.ID})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return govErr(http.StatusNotFound, GovCodeHoldNotFound, "This case no longer holds the containment.", map[string]any{"case_id": *rr.CaseID})
		}
		if err := appendGovEvent(tx, ws, GovEventContainmentHoldReleased, kind, aid, govEventRefs{}, map[string]any{
			"containment_id": row.ID, "case_id": *rr.CaseID, "release_request_id": rr.ID, "requested_by": rr.RequestedBy,
			"break_glass": rr.BreakGlass}); err != nil {
			return err
		}
	}
	holds, err := activeHoldsTx(tx, ws, row.ID)
	if err != nil {
		return err
	}
	if len(holds) > 0 {
		if rr.CaseID == nil {
			return govConflict(GovCodeHeldByCases, "A case now holds this containment: release each case's hold instead.", nil)
		}
		return nil // other cases still hold it
	}
	return startReleaseTx(tx, ws, actor, row, rr.Reason, now)
}

// startReleaseTx moves a live containment to releasing and pulls its job
// forward.
func startReleaseTx(tx *gorm.DB, ws, actor uuid.UUID, row *AgentContainment, reason string, now time.Time) error {
	if !liveContainment(row.State) {
		return govConflict(GovCodeNotReleasable, "This containment cannot be released in state "+row.State+".", map[string]any{"state": row.State})
	}
	set := map[string]any{"state": agentcontain.StateReleasing, "release_reason": reason, "release_requested_at": now, "updated_at": now}
	if actor != uuid.Nil {
		set["released_by"] = actor
	}
	res := tx.Model(&AgentContainment{}).Where("workspace_id = ? AND id = ? AND state = ?", ws, row.ID, row.State).Updates(set)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return govConflict(GovCodeNotReleasable, "The containment changed meanwhile; read it again.", nil)
	}
	kind, aid := userActor(actor)
	if actor == uuid.Nil {
		kind, aid = models.GovActorSystem, "policy-worker"
	}
	if err := appendGovEvent(tx, ws, GovEventContainmentReleaseReq, kind, aid, govEventRefs{}, map[string]any{
		"containment_id": row.ID, "from": row.State, "reason": reason}); err != nil {
		return err
	}
	return enqueueContainTx(tx, ws, row.ID, now)
}

func loadReleaseRequestTx(tx *gorm.DB, ws, id, rid uuid.UUID) (*AgentContainmentReleaseRequest, error) {
	var rows []AgentContainmentReleaseRequest
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("workspace_id = ? AND containment_id = ? AND id = ?", ws, id, rid).
		Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

// requireApproverTx: the actor is not the author and holds governance:approve.
func requireApproverTx(tx *gorm.DB, ws, actor uuid.UUID, rr *AgentContainmentReleaseRequest) error {
	if actor == rr.RequestedBy {
		return govErr(http.StatusForbidden, GovCodeSecondPersonRequired, "A release must be approved by someone other than the person who asked for it.", nil)
	}
	ok, err := WorkspaceUserHoldsPermission(tx, ws, actor, "governance", "approve")
	if err != nil {
		return err
	}
	if !ok {
		return GovForbidden("governance:approve is required to approve a containment release.")
	}
	return nil
}

// ApproveRelease is POST /containments/:id/release-requests/:rid/approve.
func (s *AgentContain) ApproveRelease(ctx context.Context, ws, actor, id, rid uuid.UUID, req AgentContainDecisionRequest) (*AgentContainReleaseOutcome, error) {
	// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only.
	if err := RequireAgentContain(s.db); err != nil {
		return nil, err
	}
	out := &AgentContainReleaseOutcome{}
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		row, err := loadContainment(tx, ws, id, true)
		if err != nil {
			return err
		}
		rr, err := loadReleaseRequestTx(tx, ws, id, rid)
		if err != nil {
			return err
		}
		if rr.State != ReleaseRequestPending {
			return govConflict(GovCodeReleaseNotPending, "This release request is "+rr.State+".", map[string]any{"state": rr.State})
		}
		if err := requireApproverTx(tx, ws, actor, rr); err != nil {
			return err
		}
		now := s.now().UTC()
		res := tx.Model(&AgentContainmentReleaseRequest{}).Where("workspace_id = ? AND id = ? AND state = ?", ws, rid, ReleaseRequestPending).
			Updates(map[string]any{"state": ReleaseRequestApproved, "decided_by": actor, "decided_at": now,
				"decision_reason": strings.TrimSpace(req.Reason)})
		if res.Error != nil {
			return res.Error
		}
		rr.State, rr.DecidedBy, rr.DecidedAt, rr.DecisionReason = ReleaseRequestApproved, &actor, &now, strings.TrimSpace(req.Reason)
		kind, aid := userActor(actor)
		if err := appendGovEvent(tx, ws, GovEventContainmentReleaseApproved, kind, aid, govEventRefs{}, map[string]any{
			"containment_id": id, "release_request_id": rid, "case_id": rr.CaseID, "requested_by": rr.RequestedBy}); err != nil {
			return err
		}
		if err := s.applyReleaseTx(tx, ws, actor, row, rr, now); err != nil {
			return err
		}
		out.Request, out.Applied = *rr, true
		return nil
	})
	if err != nil {
		return nil, err
	}
	v, err := s.Get(ctx, ws, id)
	if err != nil {
		return nil, err
	}
	out.Containment = *v
	return out, nil
}

// RejectRelease is POST /containments/:id/release-requests/:rid/reject: the
// author withdraws it, or an approver rejects it.
func (s *AgentContain) RejectRelease(ctx context.Context, ws, actor, id, rid uuid.UUID, req AgentContainDecisionRequest) (*AgentContainmentReleaseRequest, error) {
	// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only.
	if err := RequireAgentContain(s.db); err != nil {
		return nil, err
	}
	var out *AgentContainmentReleaseRequest
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		rr, err := loadReleaseRequestTx(tx, ws, id, rid)
		if err != nil {
			return err
		}
		if rr.State != ReleaseRequestPending {
			return govConflict(GovCodeReleaseNotPending, "This release request is "+rr.State+".", map[string]any{"state": rr.State})
		}
		state := ReleaseRequestWithdrawn
		if actor != rr.RequestedBy {
			if err := requireApproverTx(tx, ws, actor, rr); err != nil {
				return err
			}
			state = ReleaseRequestRejected
		}
		now := s.now().UTC()
		if err := tx.Model(&AgentContainmentReleaseRequest{}).Where("workspace_id = ? AND id = ?", ws, rid).
			Updates(map[string]any{"state": state, "decided_by": actor, "decided_at": now, "decision_reason": strings.TrimSpace(req.Reason)}).Error; err != nil {
			return err
		}
		rr.State, rr.DecidedBy, rr.DecidedAt, rr.DecisionReason = state, &actor, &now, strings.TrimSpace(req.Reason)
		kind, aid := userActor(actor)
		out = rr
		return appendGovEvent(tx, ws, GovEventContainmentReleaseRejected, kind, aid, govEventRefs{}, map[string]any{
			"containment_id": id, "release_request_id": rid, "state": state})
	})
	return out, err
}

// ReviewRelease is POST /containments/:id/release-requests/:rid/review: a
// person other than the author reviews a break-glass release.
func (s *AgentContain) ReviewRelease(ctx context.Context, ws, actor, id, rid uuid.UUID, req AgentContainDecisionRequest) (*AgentContainmentReleaseRequest, error) {
	// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only.
	if err := RequireAgentContain(s.db); err != nil {
		return nil, err
	}
	var out *AgentContainmentReleaseRequest
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		rr, err := loadReleaseRequestTx(tx, ws, id, rid)
		if err != nil {
			return err
		}
		if !rr.BreakGlass || rr.ReviewedAt != nil {
			return govConflict(GovCodeReleaseNotPending, "Only an unreviewed break-glass release is reviewed.", nil)
		}
		if err := requireApproverTx(tx, ws, actor, rr); err != nil {
			return err
		}
		now := s.now().UTC()
		note := strings.TrimSpace(req.Reason)
		if err := tx.Model(&AgentContainmentReleaseRequest{}).Where("workspace_id = ? AND id = ?", ws, rid).
			Updates(map[string]any{"reviewed_by": actor, "reviewed_at": now, "review_note": note}).Error; err != nil {
			return err
		}
		rr.ReviewedBy, rr.ReviewedAt, rr.ReviewNote = &actor, &now, note
		kind, aid := userActor(actor)
		out = rr
		return appendGovEvent(tx, ws, GovEventContainmentReleaseReviewed, kind, aid, govEventRefs{}, map[string]any{
			"containment_id": id, "release_request_id": rid, "note": note})
	})
	return out, err
}

/* ---------------------------------- proof ---------------------------------- */

// containProofInput is the proof state's inputs from a row and its steps.
func containProofInput(tx *gorm.DB, row *AgentContainment, now time.Time) (agentcontain.ProofInput, error) {
	in := agentcontain.ProofInput{Level: row.Level, State: row.State, Effective: row.Effective, Verified: row.VerifiedAt != nil,
		TokenExpiry: row.TokenExpiryAt, Now: now}
	var v struct {
		Unverifiable *struct {
			Final bool `json:"final"`
		} `json:"unverifiable"`
	}
	_ = json.Unmarshal(row.Verification, &v)
	if v.Unverifiable != nil {
		in.Unverifiable, in.UnverifiableFinal = true, v.Unverifiable.Final
	}
	if row.State == agentcontain.StateReleased {
		in.Kept = row.PendingRestoreAt != nil
		if !in.Kept {
			steps, err := loadSteps(tx, row.WorkspaceID, row.ID)
			if err != nil {
				return in, err
			}
			for _, s := range steps {
				in.Kept = in.Kept || agentcontain.KeyRotationRequired(s.engineStep())
			}
		}
	}
	return in, nil
}

// refreshContainProofTx recomputes the proof state (agentcontain.ProofStateOf)
// and, when the containment has just been proven and it narrows a wider one,
// releases the wider one (DECISION W2-3).
func refreshContainProofTx(tx *gorm.DB, ws, id uuid.UUID, now time.Time) error {
	row, err := loadContainment(tx, ws, id, false)
	if err != nil {
		return err
	}
	in, err := containProofInput(tx, row, now)
	if err != nil {
		return err
	}
	ps := agentcontain.ProofStateOf(in)
	if ps == row.ProofState {
		return nil
	}
	res := tx.Model(&AgentContainment{}).Where("workspace_id = ? AND id = ? AND proof_state = ?", ws, id, row.ProofState).
		Updates(map[string]any{"proof_state": ps, "updated_at": now})
	if res.Error != nil || res.RowsAffected == 0 {
		return res.Error
	}
	if err := appendGovEvent(tx, ws, GovEventContainmentProofState, models.GovActorSystem, "policy-worker", govEventRefs{}, map[string]any{
		"containment_id": id, "from": row.ProofState, "to": ps, "level": row.Level}); err != nil {
		return err
	}
	if ps == agentcontain.ProofProven && row.NarrowedFrom != nil {
		return releaseWiderTx(tx, ws, *row.NarrowedFrom, id, now)
	}
	return nil
}

// releaseWiderTx releases the wider containment a proven narrower one
// replaces: its holds (taken over by the narrower one) and then itself.
func releaseWiderTx(tx *gorm.DB, ws, wider, narrower uuid.UUID, now time.Time) error {
	w, err := loadContainment(tx, ws, wider, true)
	if err != nil {
		return err
	}
	if !liveContainment(w.State) {
		return nil
	}
	reason := "narrowed to containment " + narrower.String() + ", which is proven"
	if err := tx.Model(&AgentContainmentHold{}).Where("workspace_id = ? AND containment_id = ? AND state = ?", ws, wider, HoldActive).
		Updates(map[string]any{"state": HoldReleased, "released_at": now, "release_reason": reason}).Error; err != nil {
		return err
	}
	if err := appendGovEvent(tx, ws, GovEventContainmentNarrowReleased, models.GovActorSystem, "policy-worker", govEventRefs{}, map[string]any{
		"containment_id": wider, "narrowed_to": narrower}); err != nil {
		return err
	}
	return startReleaseTx(tx, ws, uuid.Nil, w, reason, now)
}

/* ---------------------------------- narrow --------------------------------- */

// AgentContainNarrowRequest is POST /containments/:id/narrow.
type AgentContainNarrowRequest struct {
	Level       string   `json:"level"`
	Target      string   `json:"target"`
	WorkloadIDs []string `json:"workload_ids"`
	Reason      string   `json:"reason"`
}

// Narrow is POST /containments/:id/narrow: the narrower stop as a new
// containment on the same identity, linked by narrowed_from (DECISION W2-3).
func (s *AgentContain) Narrow(ctx context.Context, ws, actor, id uuid.UUID, req AgentContainNarrowRequest) (*AgentContainmentView, error) {
	// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only.
	if err := RequireAgentContain(s.db); err != nil {
		return nil, err
	}
	var wider *AgentContainment
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		wider, err = loadContainment(tx, ws, id, false)
		return err
	}); err != nil {
		return nil, err
	}
	if !liveContainment(wider.State) || wider.State == agentcontain.StateRequested {
		return nil, govConflict(GovCodeNotReleasable, "Only a live containment can be narrowed (state "+wider.State+").", map[string]any{"state": wider.State})
	}
	if ok, why := agentcontain.Narrower(wider.Level, wider.IdentityKind, strings.TrimSpace(req.Level)); !ok {
		return nil, govUnprocessable(GovCodeNotNarrower, why+".", map[string]any{"from": wider.Level, "to": req.Level})
	}
	out, err := s.contain(ctx, ws, actor, AgentContainRequest{IdentityID: wider.IdentityID.String(), WorkloadIDs: req.WorkloadIDs,
		Level: req.Level, Reason: req.Reason, Target: req.Target}, &wider.ID)
	if err != nil {
		return nil, err
	}
	if err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		kind, aid := userActor(actor)
		return appendGovEvent(tx, ws, GovEventContainmentNarrowed, kind, aid, govEventRefs{}, map[string]any{
			"containment_id": id, "narrower_id": out.ID, "from": wider.Level, "to": out.Level,
			"note": "The wider containment is released automatically once the narrower one is proven."})
	}); err != nil {
		return nil, err
	}
	return out, nil
}

/* --------------------------------- gateway --------------------------------- */

// GatewayStop is one live gateway-level containment: the gateway must refuse
// the subject at once (F5 pushes these to the gateway in its hints).
type GatewayStop struct {
	ContainmentID uuid.UUID `json:"containment_id"`
	SubjectID     string    `json:"subject_id"`
	IdentityID    uuid.UUID `json:"identity_id"`
	Since         time.Time `json:"since"`
}

// ActiveGatewayStops lists ws's live gateway stops (every state but failed
// and released: a stop being released still refuses until it is released).
func ActiveGatewayStops(ctx context.Context, db *gorm.DB, ws uuid.UUID) ([]GatewayStop, error) {
	var rows []AgentContainment
	err := tenancy.InWorkspaceRead(ctx, db, ws, func(tx *gorm.DB) error {
		return tx.Where("workspace_id = ? AND level = ? AND state IN ?", ws, agentcontain.LevelGateway, agentcontain.LiveStates).
			Order("created_at, id").Find(&rows).Error
	})
	if err != nil {
		return nil, err
	}
	out := make([]GatewayStop, 0, len(rows))
	for _, r := range rows {
		out = append(out, GatewayStop{ContainmentID: r.ID, SubjectID: r.Target, IdentityID: r.IdentityID, Since: r.CreatedAt})
	}
	return out, nil
}
