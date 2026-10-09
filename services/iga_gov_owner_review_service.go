package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Owner review (SPEC-iga-phase3-policy.md §7.4, §5 rows 6-7, §2.6, §2.8,
// §3.4, L-14; T3.12; scenarios A5, A10, A23).
//
// When a version's plans compile, the authoring service (T3.11) calls
// OpenReviewTx: one iga_gov_owner_review per version (050 UNIQUE
// version_id) asking every owner of every target role -- the role's own
// owners plus the accountable owners of every live consuming workload,
// resolved by T3.07's ResolveRoleOwners -- to acknowledge, retain a service
// or object. Each owner gets an iga_gov_owner_response row and notices on
// every channel that reaches them (email; Slack through T3.14's registered
// channel) plus the workspace webhook; delivery is the notify job's
// (iga_gov_notify.go).
//
// THE OWNER GATE (L-14: "silence is not consent"). CheckGate is what
// approval (T3.13) and rollout (T3.15) call. It is computed LIVE -- current
// plans, current owners, current responses -- never from the stored
// status alone:
//
//	409 review_incomplete   no review; cancelled; the plans' impact_hash set
//	                        differs from the review's (not yet reopened); a
//	                        target with no reachable owner, or a consumer with
//	                        no accountable owner (missing owner); an owner who
//	                        has not responded (incl. a delivery failure); an
//	                        objection; a retained service (the version that
//	                        keeps it is a new version)
//	409 age_unconfirmed     a removal whose grant age AuthSec has not observed
//	                        (grant_age_basis predates_observation / unknown,
//	                        §2.6) lacks an owner's age confirmation
//	409 route_unconfirmed   a resource-policy route of a removed service
//	                        (§3.4) lacks an owner's route confirmation
//
// An approver's exception (POST /reviews/:id/exception, status excepted)
// lets the version proceed without the missing owners or responses and,
// per §3.4 ("confirmed unused or excepted") and §2.6 ("that confirmation or
// a recorded exception"), without the unconfirmed age and route items. It
// never counts as an acknowledgement (canary choice, §8.6).
//
// REOPEN (§2.8, A23). OpenReviewTx is also the resync: called again for the
// same version -- after a recompilation, a revalidation that changed the
// impact, or by Respond/Remind -- it compares the current forward plans'
// impact_hash set with the review's and the live owners with the response
// rows. A change sets status reopened (exception cleared, new deadline),
// adds response rows ONLY for the owners who are new, notifies only them
// (and the workspace webhook), and keeps every earlier response.
//
// DECISIONS (T3.12):
//   - The review's impact_hashes are the sorted, distinct impact_hash of the
//     version's CURRENT forward plans (apply, remove_control, split): what
//     the owners are asked about. Undo plans are not reviewed separately.
//   - An age item is (target, removed service) for every intent removal
//     whose grant_age_basis is not observed_since_change; a route item is
//     (target, service, route) for every route in the forward plan's
//     impact (§3.4: every listed route needs confirmation, the boundary-
//     limited ones included). Either is satisfied by ANY responding owner of
//     that target; a responder's confirmations apply to every target they
//     own.
//   - Acknowledge does not REQUIRE the confirmations (the console asks for
//     them); the gate reports what is missing as age_unconfirmed /
//     route_unconfirmed (A5), so one owner may acknowledge and another
//     confirm.
//   - Respond is open while the review is open, reopened or complete: an
//     owner may change their answer until an approver acts; a change that
//     blocks moves a complete review back to open.
//   - The deadline is created_at + owner_review_days (calendar days); a
//     reopen sets a new deadline from now. Passing it changes nothing
//     (silence is not consent): it is shown as overdue and approvers may
//     except.
//   - Only ACTIVE members are asked; an owner who is not one is a missing
//     owner. An owner no channel reaches is a delivery failure at once.
//   - The exception may not be granted by the version's author (§2.10
//     separation of duties; 403 self_approval).
//   - Version status is the authoring service's: OpenReviewTx does not move
//     a version to in_review, and retain/object do not supersede it; the
//     GovReviewAuthoringHook does what authoring decides.

// GovReviewAuthoringHook is what owner review needs from the authoring
// service (T3.11 implements it; SetGovReviewAuthoringHook installs it).
// OwnerResponseTx runs in the response's transaction for every retain and
// object response: for retain, create a draft version from the reviewed
// version's intent with the retained services moved to retain (basis owner,
// reason, review_by) and return its id; for object, record the objection on
// the version (e.g. back to draft) and return nil. An error rolls the
// response back.
type GovReviewAuthoringHook interface {
	OwnerResponseTx(tx *gorm.DB, r GovOwnerResponseEvent) (newVersionID *uuid.UUID, err error)
}

// GovOwnerResponseEvent is one retain or object response.
type GovOwnerResponseEvent struct {
	WorkspaceID uuid.UUID
	ReviewID    uuid.UUID
	VersionID   uuid.UUID
	PolicyID    uuid.UUID
	UserID      uuid.UUID
	Response    string
	RetainItems []GovRetainItem
	Comment     string
}

var (
	govReviewHookMu sync.RWMutex
	govReviewHook   GovReviewAuthoringHook
)

// SetGovReviewAuthoringHook installs the authoring hook (T3.11, at startup);
// it returns a function restoring the previous one.
func SetGovReviewAuthoringHook(h GovReviewAuthoringHook) (restore func()) {
	govReviewHookMu.Lock()
	prev := govReviewHook
	govReviewHook = h
	govReviewHookMu.Unlock()
	return func() {
		govReviewHookMu.Lock()
		govReviewHook = prev
		govReviewHookMu.Unlock()
	}
}

func currentGovReviewHook() GovReviewAuthoringHook {
	govReviewHookMu.RLock()
	defer govReviewHookMu.RUnlock()
	return govReviewHook
}

// Review statuses (050) and responses.
const (
	GovReviewOpen      = "open"
	GovReviewComplete  = "complete"
	GovReviewExcepted  = "excepted"
	GovReviewCancelled = "cancelled"
	GovReviewReopened  = "reopened"

	GovResponseAcknowledge = "acknowledge"
	GovResponseRetain      = "retain"
	GovResponseObject      = "object"

	GovDeliveryPending   = "pending"
	GovDeliveryDelivered = "delivered"
	GovDeliveryFailed    = "failed"
)

// Blocker kinds.
const (
	GovBlockMissingOwner   = "missing_owner"
	GovBlockOwnerNotMember = "owner_not_member"
	GovBlockNoResponse     = "no_response"
	GovBlockDelivery       = "delivery_failed"
	GovBlockObjection      = "objection"
	GovBlockRetained       = "retained"
	GovBlockNewOwner       = "new_owner"
	GovBlockImpactChanged  = "impact_changed"
)

// GovRetainItem is one service an owner keeps (§7.4 retain_items).
type GovRetainItem struct {
	Service  string `json:"service"`
	Reason   string `json:"reason"`
	ReviewBy string `json:"review_by"`
}

// GovAgeConfirmation is an owner's "this access was not added recently".
type GovAgeConfirmation struct {
	Service   string `json:"service"`
	Confirmed bool   `json:"confirmed"`
}

// GovRouteConfirmation is an owner's "this route is not used".
type GovRouteConfirmation struct {
	Service   string `json:"service"`
	Route     string `json:"route"`
	Confirmed bool   `json:"confirmed"`
}

// GovReviewOwnerOf is one reason a person is asked: a target role they own
// directly or through a consuming workload.
type GovReviewOwnerOf struct {
	TargetID          uuid.UUID `json:"target_id"`
	IdentityAccountID uuid.UUID `json:"identity_account_id"`
	RoleARN           string    `json:"role_arn"`
	ObjectKind        string    `json:"object_kind"`
	ObjectID          uuid.UUID `json:"object_id"`
	Name              string    `json:"name"`
	Role              string    `json:"role"`
	Source            string    `json:"source"`
}

// GovAgeItem asks owners to confirm a removed service's grant is not new.
type GovAgeItem struct {
	TargetID      uuid.UUID `json:"target_id"`
	Service       string    `json:"service"`
	GrantAgeBasis string    `json:"grant_age_basis"`
}

// GovRouteItem asks owners to confirm a resource-policy route is unused.
type GovRouteItem struct {
	TargetID  uuid.UUID `json:"target_id"`
	Service   string    `json:"service"`
	Route     string    `json:"route"`
	Resource  string    `json:"resource,omitempty"`
	Form      string    `json:"form,omitempty"`
	Region    string    `json:"region,omitempty"`
	Principal string    `json:"principal,omitempty"`
	Effect    string    `json:"effect"`
}

// GovRouteKey names a route for confirmation: its resource ARN, or for an
// unanalysed form "form:<form>[@<region>]".
func GovRouteKey(r igagov.Route) string {
	if r.Resource != "" {
		return r.Resource
	}
	k := "form:" + r.Form
	if r.Region != "" {
		k += "@" + r.Region
	}
	if r.Form == "" && r.Region == "" {
		k = "service:" + r.Service
	}
	return k
}

// GovReviewBlocker is one reason the review cannot complete.
type GovReviewBlocker struct {
	Kind       string     `json:"kind"`
	TargetID   *uuid.UUID `json:"target_id,omitempty"`
	UserID     *uuid.UUID `json:"user_id,omitempty"`
	WorkloadID *uuid.UUID `json:"workload_id,omitempty"`
	Name       string     `json:"name,omitempty"`
	Detail     string     `json:"detail,omitempty"`
	Services   []string   `json:"services,omitempty"`
}

/* ------------------------------- state ------------------------------------ */

type govReviewTarget struct {
	TargetID          uuid.UUID
	ControlID         uuid.UUID
	IdentityAccountID uuid.UUID
	RoleARN           string
	Removed           []igagov.ImpactService
	Retained          []igagov.ImpactService
	Routes            []igagov.Route
	Ownership         *RoleOwnership
}

type govDesiredOwner struct {
	UserID  uuid.UUID
	Email   string
	Name    string
	OwnerOf []GovReviewOwnerOf
}

type govReviewState struct {
	Review    *models.IGAGovOwnerReview
	Version   models.IGAGovPolicyVersion
	Policy    models.IGAGovPolicy
	Removals  map[string]string // intent removals: service -> grant_age_basis
	Targets   []govReviewTarget
	Hashes    []string // current forward plans' impact hashes, sorted distinct
	Owners    []*govDesiredOwner
	ownerIdx  map[uuid.UUID]*govDesiredOwner
	Missing   []GovReviewBlocker
	Responses []models.IGAGovOwnerResponse
	// Excepted are the targets' unused_service findings that carry a
	// finding exception (POST /findings/:id/exception), by identity and
	// service; the gate compares their until with its clock.
	Excepted []govExceptedFinding
}

// govExceptedFinding is one excepted unused_service finding of a target role.
type govExceptedFinding struct {
	FindingID         uuid.UUID
	IdentityAccountID uuid.UUID
	Service           string
	Until             time.Time
	Reason            string
}

func (st *govReviewState) response(user uuid.UUID) *models.IGAGovOwnerResponse {
	for i := range st.Responses {
		if st.Responses[i].UserID == user {
			return &st.Responses[i]
		}
	}
	return nil
}

func (st *govReviewState) owner(user uuid.UUID) *govDesiredOwner { return st.ownerIdx[user] }

// IGAGovOwnerReviewService is §7.4.
type IGAGovOwnerReviewService struct {
	db      *gorm.DB
	owners  *IGAGovOwnershipService
	members WorkspaceMemberDirectory
	hook    GovReviewAuthoringHook
	now     func() time.Time
}

// NewIGAGovOwnerReviewService builds the service over db.
func NewIGAGovOwnerReviewService(db *gorm.DB) *IGAGovOwnerReviewService {
	return &IGAGovOwnerReviewService{db: db, owners: NewIGAGovOwnershipService(db), now: time.Now}
}

// WithAuthoringHook makes this service use h instead of the installed hook.
func (s *IGAGovOwnerReviewService) WithAuthoringHook(h GovReviewAuthoringHook) *IGAGovOwnerReviewService {
	s.hook = h
	return s
}

func (s *IGAGovOwnerReviewService) authoringHook() GovReviewAuthoringHook {
	if s.hook != nil {
		return s.hook
	}
	return currentGovReviewHook()
}

var govForwardPlanKinds = []string{models.GovPlanApply, models.GovPlanRemoveControl, models.GovPlanSplit}

// load reads everything a review decision needs, in db (a transaction when
// lock: the review row is then locked FOR UPDATE).
func (s *IGAGovOwnerReviewService) load(db *gorm.DB, ws, versionID uuid.UUID, lock bool) (*govReviewState, error) {
	st := &govReviewState{ownerIdx: map[uuid.UUID]*govDesiredOwner{}, Removals: map[string]string{}}
	res := db.Where("workspace_id = ? AND id = ?", ws, versionID).Limit(1).Find(&st.Version)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, GovNotFound()
	}
	if err := db.Where("workspace_id = ? AND id = ?", ws, st.Version.PolicyID).Take(&st.Policy).Error; err != nil {
		return nil, err
	}
	// The intent's removals and their grant-age basis (§2.6). Decoded
	// leniently: an intent of another kind simply has none.
	var intent struct {
		Kind   string               `json:"kind"`
		Remove []igagov.RemoveEntry `json:"remove"`
	}
	if json.Unmarshal(st.Version.Intent, &intent) == nil && intent.Kind == igagov.IntentRightSizeServices {
		for _, r := range intent.Remove {
			st.Removals[r.Service] = r.GrantAgeBasis
		}
	}
	var tg []struct {
		TargetID          uuid.UUID
		ControlID         uuid.UUID
		IdentityAccountID uuid.UUID
		RoleARN           string
	}
	if err := db.Raw(`
		SELECT t.id AS target_id, t.control_id, c.identity_account_id, c.role_arn
		  FROM iga_gov_target t
		  JOIN iga_gov_control c ON c.workspace_id = t.workspace_id AND c.id = t.control_id
		 WHERE t.workspace_id = ? AND t.version_id = ?
		 ORDER BY t.created_at, t.id`, ws, versionID).Scan(&tg).Error; err != nil {
		return nil, err
	}
	var plans []models.IGAGovPlan
	if err := db.Where("workspace_id = ? AND version_id = ? AND superseded_at IS NULL AND kind IN ?", ws, versionID, govForwardPlanKinds).
		Order("created_at, id").Find(&plans).Error; err != nil {
		return nil, err
	}
	hashes := map[string]bool{}
	byTarget := map[uuid.UUID][]models.IGAGovPlan{}
	for _, p := range plans {
		hashes[p.ImpactHash] = true
		byTarget[p.TargetID] = append(byTarget[p.TargetID], p)
	}
	for h := range hashes {
		st.Hashes = append(st.Hashes, h)
	}
	sort.Strings(st.Hashes)
	for _, t := range tg {
		rt := govReviewTarget{TargetID: t.TargetID, ControlID: t.ControlID, IdentityAccountID: t.IdentityAccountID, RoleARN: t.RoleARN}
		for _, p := range byTarget[t.TargetID] {
			var im igagov.Impact
			if len(p.Impact) > 0 && json.Unmarshal(p.Impact, &im) == nil {
				rt.Removed = append(rt.Removed, im.Removed...)
				rt.Retained = append(rt.Retained, im.Retained...)
				rt.Routes = append(rt.Routes, im.Routes...)
			}
		}
		ro, err := s.owners.ResolveRoleOwners(db, ws, t.IdentityAccountID)
		if err != nil {
			return nil, err
		}
		rt.Ownership = ro
		st.Targets = append(st.Targets, rt)
	}
	// Desired owners: active members among every target's resolved owners.
	for i := range st.Targets {
		t := &st.Targets[i]
		tid := t.TargetID
		reachable := 0
		for _, r := range t.Ownership.Resolved {
			if !r.Member {
				uid := r.UserID
				st.Missing = append(st.Missing, GovReviewBlocker{Kind: GovBlockOwnerNotMember, TargetID: &tid, UserID: &uid,
					Name: r.Name, Detail: "This owner is not an active member of the workspace and cannot be asked."})
				continue
			}
			reachable++
			o := st.ownerIdx[r.UserID]
			if o == nil {
				o = &govDesiredOwner{UserID: r.UserID, Email: r.Email, Name: r.Name}
				st.ownerIdx[r.UserID] = o
				st.Owners = append(st.Owners, o)
			}
			for _, of := range r.OwnerOf {
				o.OwnerOf = append(o.OwnerOf, GovReviewOwnerOf{TargetID: tid, IdentityAccountID: t.IdentityAccountID, RoleARN: t.RoleARN,
					ObjectKind: of.ObjectKind, ObjectID: of.ObjectID, Name: of.Name, Role: of.Role, Source: of.Source})
			}
		}
		for _, c := range t.Ownership.UnownedConsumers() {
			wl := c.WorkloadID
			st.Missing = append(st.Missing, GovReviewBlocker{Kind: GovBlockMissingOwner, TargetID: &tid, WorkloadID: &wl, Name: c.Name,
				Detail: "This workload runs as the role and has no accountable owner to ask."})
		}
		if reachable == 0 {
			st.Missing = append(st.Missing, GovReviewBlocker{Kind: GovBlockMissingOwner, TargetID: &tid, Name: t.RoleARN,
				Detail: "No owner of this role (or of any workload that runs as it) can be asked."})
		}
	}
	sort.Slice(st.Owners, func(i, j int) bool { return st.Owners[i].UserID.String() < st.Owners[j].UserID.String() })

	// Finding exceptions on the target roles (review fix R1a P2: the owner
	// gate honours them; see govReviewState.exceptedRemovals).
	if len(st.Targets) > 0 {
		ids := make([]uuid.UUID, 0, len(st.Targets))
		for _, t := range st.Targets {
			ids = append(ids, t.IdentityAccountID)
		}
		var ex []struct {
			ID                uuid.UUID
			IdentityAccountID uuid.UUID
			DetailKey         string
			ExceptedUntil     time.Time
			ExceptionReason   string
		}
		if err := db.Raw(`SELECT id, identity_account_id, detail_key, excepted_until, exception_reason
		                    FROM iga_gov_finding
		                   WHERE workspace_id = ? AND kind = ? AND status = 'excepted' AND identity_account_id IN ?
		                   ORDER BY id`, ws, igagov.KindUnusedService, ids).Scan(&ex).Error; err != nil {
			return nil, err
		}
		for _, e := range ex {
			st.Excepted = append(st.Excepted, govExceptedFinding{FindingID: e.ID, IdentityAccountID: e.IdentityAccountID,
				Service: e.DetailKey, Until: e.ExceptedUntil, Reason: e.ExceptionReason})
		}
	}

	q := db.Where("workspace_id = ? AND version_id = ?", ws, versionID).Limit(1)
	if lock {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var reviews []models.IGAGovOwnerReview
	if err := q.Find(&reviews).Error; err != nil {
		return nil, err
	}
	if len(reviews) == 1 {
		st.Review = &reviews[0]
		if err := db.Where("workspace_id = ? AND review_id = ?", ws, st.Review.ID).Order("user_id").Find(&st.Responses).Error; err != nil {
			return nil, err
		}
	}
	return st, nil
}

// reviewVersion returns the version id of a review of this workspace, or
// GovNotFound.
func (s *IGAGovOwnerReviewService) reviewVersion(db *gorm.DB, ws, reviewID uuid.UUID) (uuid.UUID, error) {
	var ids []uuid.UUID
	if err := db.Raw(`SELECT version_id FROM iga_gov_owner_review WHERE workspace_id = ? AND id = ?`, ws, reviewID).Scan(&ids).Error; err != nil {
		return uuid.Nil, err
	}
	if len(ids) == 0 {
		return uuid.Nil, GovNotFound()
	}
	return ids[0], nil
}

/* ------------------------------ requirements ------------------------------ */

func (st *govReviewState) ageItems() []GovAgeItem {
	var out []GovAgeItem
	for _, t := range st.Targets {
		removed := map[string]bool{}
		for _, r := range t.Removed {
			removed[r.Service] = true
		}
		svcs := make([]string, 0, len(st.Removals))
		for svc := range st.Removals {
			svcs = append(svcs, svc)
		}
		sort.Strings(svcs)
		for _, svc := range svcs {
			basis := st.Removals[svc]
			if basis == igagov.GrantAgeObservedSinceChange {
				continue
			}
			if len(removed) > 0 && !removed[svc] {
				continue
			}
			out = append(out, GovAgeItem{TargetID: t.TargetID, Service: svc, GrantAgeBasis: basis})
		}
	}
	return out
}

func (st *govReviewState) routeItems() []GovRouteItem {
	var out []GovRouteItem
	for _, t := range st.Targets {
		seen := map[string]bool{}
		for _, r := range t.Routes {
			k := r.Service + "\x1f" + GovRouteKey(r)
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, GovRouteItem{TargetID: t.TargetID, Service: r.Service, Route: GovRouteKey(r), Resource: r.Resource,
				Form: r.Form, Region: r.Region, Principal: r.Principal, Effect: r.Effect})
		}
	}
	return out
}

func (st *govReviewState) ownsTarget(user, target uuid.UUID) bool {
	o := st.owner(user)
	if o == nil {
		return false
	}
	for _, of := range o.OwnerOf {
		if of.TargetID == target {
			return true
		}
	}
	return false
}

func decodeJSON[T any](raw json.RawMessage) []T {
	var out []T
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

// unconfirmed returns the age and route items no responding owner of their
// target has confirmed.
func (st *govReviewState) unconfirmed() ([]GovAgeItem, []GovRouteItem) {
	type key struct {
		target uuid.UUID
		svc    string
		route  string
	}
	ages, routes := map[key]bool{}, map[key]bool{}
	for _, r := range st.Responses {
		if r.Response == nil || st.owner(r.UserID) == nil {
			continue
		}
		for _, of := range st.owner(r.UserID).OwnerOf {
			for _, a := range decodeJSON[GovAgeConfirmation](r.AgeConfirmations) {
				if a.Confirmed {
					ages[key{of.TargetID, a.Service, ""}] = true
				}
			}
			for _, c := range decodeJSON[GovRouteConfirmation](r.RouteConfirmations) {
				if c.Confirmed {
					routes[key{of.TargetID, c.Service, c.Route}] = true
				}
			}
		}
	}
	var ua []GovAgeItem
	for _, a := range st.ageItems() {
		if !ages[key{a.TargetID, a.Service, ""}] {
			ua = append(ua, a)
		}
	}
	var ur []GovRouteItem
	for _, r := range st.routeItems() {
		if !routes[key{r.TargetID, r.Service, r.Route}] {
			ur = append(ur, r)
		}
	}
	return ua, ur
}

func sameStrings(a, b []string) bool {
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// GovBlockFindingExcepted is the owner gate's reason when a removal meets a
// finding exception.
const GovBlockFindingExcepted = "finding_excepted"

// GovExceptedRemoval is one removal the gate refuses because its finding is
// excepted.
type GovExceptedRemoval struct {
	TargetID  uuid.UUID `json:"target_id"`
	FindingID uuid.UUID `json:"finding_id"`
	Service   string    `json:"service"`
	Until     time.Time `json:"excepted_until"`
	Reason    string    `json:"exception_reason"`
}

// exceptedRemovals lists every (target, removed service) whose role's
// unused_service finding for that service is excepted with an until after
// now. The removed services of a target are its plans' impact removals,
// or the intent's when the impact lists none (as ageItems).
func (st *govReviewState) exceptedRemovals(now time.Time) []GovExceptedRemoval {
	if len(st.Excepted) == 0 {
		return nil
	}
	var out []GovExceptedRemoval
	for _, t := range st.Targets {
		removed := map[string]bool{}
		for _, r := range t.Removed {
			removed[r.Service] = true
		}
		if len(removed) == 0 {
			for svc := range st.Removals {
				removed[svc] = true
			}
		}
		for _, e := range st.Excepted {
			if e.IdentityAccountID == t.IdentityAccountID && removed[e.Service] && e.Until.After(now) {
				out = append(out, GovExceptedRemoval{TargetID: t.TargetID, FindingID: e.FindingID, Service: e.Service,
					Until: e.Until.UTC(), Reason: e.Reason})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TargetID != out[j].TargetID {
			return out[i].TargetID.String() < out[j].TargetID.String()
		}
		return out[i].Service < out[j].Service
	})
	return out
}

// blockers is everything that keeps the review from completing, live.
func (st *govReviewState) blockers() []GovReviewBlocker {
	out := []GovReviewBlocker{}
	if st.Review == nil {
		return out
	}
	if !sameStrings(st.Review.ImpactHashes, st.Hashes) {
		out = append(out, GovReviewBlocker{Kind: GovBlockImpactChanged,
			Detail: "The plans' impact changed since the owners were asked; the review must be reopened."})
	}
	out = append(out, st.Missing...)
	for _, o := range st.Owners {
		uid := o.UserID
		r := st.response(o.UserID)
		switch {
		case r == nil:
			out = append(out, GovReviewBlocker{Kind: GovBlockNewOwner, UserID: &uid, Name: o.Name,
				Detail: "A new owner has not been asked yet."})
		case r.Response == nil && r.Delivery == GovDeliveryFailed:
			out = append(out, GovReviewBlocker{Kind: GovBlockDelivery, UserID: &uid, Name: o.Name,
				Detail: "The review could not be delivered to this owner."})
		case r.Response == nil:
			out = append(out, GovReviewBlocker{Kind: GovBlockNoResponse, UserID: &uid, Name: o.Name})
		case *r.Response == GovResponseObject:
			out = append(out, GovReviewBlocker{Kind: GovBlockObjection, UserID: &uid, Name: o.Name, Detail: r.Comment})
		case *r.Response == GovResponseRetain:
			var svcs []string
			for _, it := range decodeJSON[GovRetainItem](r.RetainItems) {
				svcs = append(svcs, it.Service)
			}
			out = append(out, GovReviewBlocker{Kind: GovBlockRetained, UserID: &uid, Name: o.Name, Services: svcs,
				Detail: "The owner keeps these services; the version that keeps them is a new version."})
		}
	}
	return out
}

/* --------------------------------- gate ----------------------------------- */

func reviewIncomplete(msg string, detail map[string]any) *GovError {
	return govErr(http.StatusConflict, "review_incomplete", msg, detail)
}

// CheckGate is the owner gate for a version (§7.12 review_incomplete,
// age_unconfirmed, route_unconfirmed): nil when approval and rollout may
// proceed as far as owners are concerned. Live: see the file comment.
func (s *IGAGovOwnerReviewService) CheckGate(db *gorm.DB, ws, versionID uuid.UUID) error {
	st, err := s.load(db, ws, versionID, false)
	if err != nil {
		return err
	}
	return st.gate(s.now())
}

func (st *govReviewState) gate(now time.Time) error {
	if st.Review == nil {
		return reviewIncomplete("No owner review exists for this version.", map[string]any{"reason": "no_review"})
	}
	detail := map[string]any{"review_id": st.Review.ID, "status": st.Review.Status,
		"deadline_at": st.Review.DeadlineAt, "overdue": now.After(st.Review.DeadlineAt)}
	if st.Review.Status == GovReviewCancelled {
		detail["reason"] = "cancelled"
		return reviewIncomplete("The owner review was cancelled.", detail)
	}
	if !sameStrings(st.Review.ImpactHashes, st.Hashes) {
		detail["reason"] = GovBlockImpactChanged
		return reviewIncomplete("The plans' impact changed since the owners were asked.", detail)
	}
	// A finding exception is a recorded decision to keep the access until
	// its date (§2.5): a version removing that service is refused until the
	// exception is cleared or the service is retained. Checked before the
	// review exception: an approver's review exception settles missing
	// owners and confirmations, not a decision recorded on the finding.
	if items := st.exceptedRemovals(now); len(items) > 0 {
		detail["reason"] = GovBlockFindingExcepted
		detail["items"] = items
		return reviewIncomplete("The version removes services whose findings carry an exception; clear the exception or retain the service.", detail)
	}
	if st.Review.Status == GovReviewExcepted {
		return nil
	}
	if b := st.blockers(); len(b) > 0 {
		detail["blockers"] = b
		return reviewIncomplete("The owner review is not complete.", detail)
	}
	ua, ur := st.unconfirmed()
	if len(ua) > 0 {
		return govErr(http.StatusConflict, "age_unconfirmed",
			"An owner must confirm that these services were not added recently (AuthSec has not observed how long they have been granted).",
			map[string]any{"review_id": st.Review.ID, "items": ua})
	}
	if len(ur) > 0 {
		return govErr(http.StatusConflict, "route_unconfirmed",
			"An owner must confirm that these resource-policy routes are not used.",
			map[string]any{"review_id": st.Review.ID, "items": ur})
	}
	return nil
}

// GovCanaryAcknowledgement answers §8.6's canary rule for one target: a
// shared role (two or more consuming workloads) may be the canary only when
// every consumer's accountable owners acknowledged in the review; an
// exception does not count.
type GovCanaryAcknowledgement struct {
	Shared       bool        `json:"shared"`
	Acknowledged bool        `json:"acknowledged"`
	Missing      []uuid.UUID `json:"missing_user_ids"`
	Unowned      []uuid.UUID `json:"unowned_workload_ids"`
}

// CanaryAcknowledgement is the canary rule for (version, target) -- what
// T3.15's canary choice calls. Acknowledged is true for a role that is not
// shared.
func (s *IGAGovOwnerReviewService) CanaryAcknowledgement(db *gorm.DB, ws, versionID, targetID uuid.UUID) (*GovCanaryAcknowledgement, error) {
	st, err := s.load(db, ws, versionID, false)
	if err != nil {
		return nil, err
	}
	var t *govReviewTarget
	for i := range st.Targets {
		if st.Targets[i].TargetID == targetID {
			t = &st.Targets[i]
		}
	}
	if t == nil {
		return nil, GovNotFound()
	}
	out := &GovCanaryAcknowledgement{Missing: []uuid.UUID{}, Unowned: []uuid.UUID{}}
	seen := map[uuid.UUID]bool{}
	for _, c := range t.Ownership.Consumers {
		if !seen[c.WorkloadID] {
			seen[c.WorkloadID] = true
		}
	}
	out.Shared = len(seen) >= 2
	if !out.Shared {
		out.Acknowledged = true
		return out, nil
	}
	missing := map[uuid.UUID]bool{}
	for _, c := range t.Ownership.Consumers {
		if len(c.Owners) == 0 {
			out.Unowned = append(out.Unowned, c.WorkloadID)
			continue
		}
		for _, o := range c.Owners {
			r := st.response(o.UserID)
			if r == nil || r.Response == nil || *r.Response != GovResponseAcknowledge || !o.Member {
				if !missing[o.UserID] {
					missing[o.UserID] = true
					out.Missing = append(out.Missing, o.UserID)
				}
			}
		}
	}
	out.Acknowledged = st.Review != nil && st.Review.Status != GovReviewCancelled && len(out.Missing) == 0 && len(out.Unowned) == 0
	return out, nil
}

/* ------------------------------ open / reopen ----------------------------- */

// GovReviewSync is what OpenReviewTx did.
type GovReviewSync struct {
	ReviewID  uuid.UUID   `json:"review_id"`
	Created   bool        `json:"created"`
	Reopened  bool        `json:"reopened"`
	NewOwners []uuid.UUID `json:"new_owner_user_ids"`
	Status    string      `json:"status"`
}

// OpenReviewTx creates the version's owner review, or resyncs it (reopen on
// an impact_hash change or a new owner), in the caller's transaction. T3.11
// calls it after compiling plans (propose); a revalidation that stored a
// new plan calls it too. actor is the person who caused it (uuid.Nil:
// system).
func (s *IGAGovOwnerReviewService) OpenReviewTx(tx *gorm.DB, ws, versionID, actor uuid.UUID) (*GovReviewSync, error) {
	st, err := s.load(tx, ws, versionID, true)
	if err != nil {
		return nil, err
	}
	return s.syncTx(tx, ws, st, actor)
}

// OpenReview is OpenReviewTx in its own transaction.
func (s *IGAGovOwnerReviewService) OpenReview(ctx context.Context, ws, versionID, actor uuid.UUID) (*GovReviewSync, error) {
	var out *GovReviewSync
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		out, err = s.OpenReviewTx(tx, ws, versionID, actor)
		return err
	})
	return out, err
}

func actorOf(actor uuid.UUID) (string, string) {
	if actor == uuid.Nil {
		return models.GovActorSystem, "owner-review"
	}
	return models.GovActorUser, actor.String()
}

func (st *govReviewState) refs() govEventRefs {
	p, v := st.Policy.ID, st.Version.ID
	return govEventRefs{PolicyID: &p, VersionID: &v}
}

func (s *IGAGovOwnerReviewService) deadline(tx *gorm.DB, ws uuid.UUID) (time.Time, error) {
	set, err := repositories.NewIGAGovSettingsRepository(tx).Get(ws)
	if err != nil {
		return time.Time{}, err
	}
	return s.now().Add(time.Duration(set.OwnerReviewDays) * 24 * time.Hour), nil
}

func (s *IGAGovOwnerReviewService) syncTx(tx *gorm.DB, ws uuid.UUID, st *govReviewState, actor uuid.UUID) (*GovReviewSync, error) {
	switch st.Version.Status {
	case "withdrawn", "rejected", "superseded":
		return nil, govErr(http.StatusConflict, "version_not_reviewable",
			"This version is "+st.Version.Status+"; it has no owner review.", map[string]any{"status": st.Version.Status})
	}
	if len(st.Targets) == 0 || len(st.Hashes) == 0 {
		return nil, govErr(http.StatusConflict, "plans_not_compiled",
			"This version has no compiled plans to review.", map[string]any{"version_id": st.Version.ID})
	}
	ak, aid := actorOf(actor)
	out := &GovReviewSync{}
	var newOwners []*govDesiredOwner
	for _, o := range st.Owners {
		if st.response(o.UserID) == nil {
			newOwners = append(newOwners, o)
		}
	}
	if st.Review == nil {
		due, err := s.deadline(tx, ws)
		if err != nil {
			return nil, err
		}
		rv := models.IGAGovOwnerReview{ID: uuid.New(), WorkspaceID: ws, VersionID: st.Version.ID,
			ImpactHashes: pq.StringArray(st.Hashes), Status: GovReviewOpen, DeadlineAt: due}
		if err := tx.Create(&rv).Error; err != nil {
			return nil, err
		}
		st.Review = &rv
		out.Created = true
	} else {
		impactChanged := !sameStrings(st.Review.ImpactHashes, st.Hashes)
		if impactChanged || len(newOwners) > 0 {
			due, err := s.deadline(tx, ws)
			if err != nil {
				return nil, err
			}
			prev := append([]string(nil), st.Review.ImpactHashes...)
			if err := tx.Exec(`UPDATE iga_gov_owner_review SET status = 'reopened', impact_hashes = ?, deadline_at = ?,
				exception_by = NULL, exception_reason = '', closed_at = NULL WHERE workspace_id = ? AND id = ?`,
				pq.StringArray(st.Hashes), due, ws, st.Review.ID).Error; err != nil {
				return nil, err
			}
			reason := "new_owners"
			if impactChanged {
				reason = "impact_changed"
			}
			ids := make([]uuid.UUID, 0, len(newOwners))
			for _, o := range newOwners {
				ids = append(ids, o.UserID)
			}
			if err := appendGovEvent(tx, ws, GovEventReviewReopened, ak, aid, st.refs(), map[string]any{
				"review_id": st.Review.ID, "reason": reason, "previous_status": st.Review.Status,
				"previous_impact_hashes": prev, "impact_hashes": st.Hashes, "new_owner_user_ids": ids,
				"deadline_at": due}); err != nil {
				return nil, err
			}
			st.Review.Status, st.Review.ImpactHashes, st.Review.DeadlineAt = GovReviewReopened, pq.StringArray(st.Hashes), due
			st.Review.ExceptionBy, st.Review.ExceptionReason, st.Review.ClosedAt = nil, "", nil
			out.Reopened = true
		}
	}
	// Existing rows keep their answers; their owner_of follows the live
	// ownership (targets and consumers may have changed).
	for _, o := range st.Owners {
		if r := st.response(o.UserID); r != nil {
			raw, _ := json.Marshal(o.OwnerOf)
			if string(raw) != string(r.OwnerOf) {
				if err := tx.Exec(`UPDATE iga_gov_owner_response SET owner_of = ? WHERE workspace_id = ? AND id = ?`,
					string(raw), ws, r.ID).Error; err != nil {
					return nil, err
				}
				r.OwnerOf = raw
			}
		}
	}
	for _, o := range newOwners {
		raw, _ := json.Marshal(o.OwnerOf)
		r := models.IGAGovOwnerResponse{ID: uuid.New(), WorkspaceID: ws, ReviewID: st.Review.ID, UserID: o.UserID,
			OwnerOf: raw, Delivery: GovDeliveryPending, DeliveryChannels: pq.StringArray{},
			RetainItems: json.RawMessage(`[]`), AgeConfirmations: json.RawMessage(`[]`), RouteConfirmations: json.RawMessage(`[]`)}
		if err := tx.Create(&r).Error; err != nil {
			return nil, err
		}
		st.Responses = append(st.Responses, r)
		out.NewOwners = append(out.NewOwners, o.UserID)
		if err := s.notifyOwnerTx(tx, ws, st.Review.ID, o.UserID, false); err != nil {
			return nil, err
		}
	}
	if out.Created || out.Reopened {
		// Configured is enough to queue the notice; the secret is resolved
		// (and an unreadable one retried) when it is sent.
		if GovWorkspaceWebhookConfigured(tx, ws) {
			if _, err := EnqueueGovNotificationTx(tx, ws, GovNoticeOwnerReview, st.Review.ID, GovChannelWebhook,
				GovRecipientWorkspaceWebhook, true); err != nil {
				return nil, err
			}
		}
	}
	if out.Created {
		if err := appendGovEvent(tx, ws, GovEventReviewOpened, ak, aid, st.refs(), map[string]any{
			"review_id": st.Review.ID, "impact_hashes": st.Hashes, "owner_user_ids": out.NewOwners,
			"missing_owners": st.Missing, "deadline_at": st.Review.DeadlineAt,
			"age_items": len(st.ageItems()), "route_items": len(st.routeItems())}); err != nil {
			return nil, err
		}
	}
	if err := s.settleStatusTx(tx, ws, st, ak, aid); err != nil {
		return nil, err
	}
	out.ReviewID, out.Status = st.Review.ID, st.Review.Status
	return out, nil
}

// notifyOwnerTx enqueues the review's notices to one owner on every channel
// that reaches them. With no channel the owner's delivery fails at once.
func (s *IGAGovOwnerReviewService) notifyOwnerTx(tx *gorm.DB, ws, reviewID, user uuid.UUID, resend bool) error {
	channels := []string{}
	if govChannels(tx, ws).EmailEnabled {
		channels = append(channels, GovChannelEmail)
	}
	for _, ch := range govExtraChannels() {
		ok, err := ch.Reaches(tx, ws, user)
		if err != nil {
			return err
		}
		if ok {
			channels = append(channels, ch.Channel())
		}
	}
	sort.Strings(channels)
	if len(channels) == 0 {
		return tx.Exec(`UPDATE iga_gov_owner_response SET delivery = 'failed'
			WHERE workspace_id = ? AND review_id = ? AND user_id = ? AND delivery <> 'delivered'`, ws, reviewID, user).Error
	}
	for _, ch := range channels {
		if _, err := EnqueueGovNotificationTx(tx, ws, GovNoticeOwnerReview, reviewID, ch, GovUserRecipient(user), resend); err != nil {
			return err
		}
	}
	return nil
}

// settleStatusTx moves open/reopened to complete when nothing blocks, and
// complete back to open when something does.
func (s *IGAGovOwnerReviewService) settleStatusTx(tx *gorm.DB, ws uuid.UUID, st *govReviewState, ak, aid string) error {
	b := st.blockers()
	switch st.Review.Status {
	case GovReviewOpen, GovReviewReopened:
		if len(b) > 0 {
			return nil
		}
		now := s.now()
		// Conditional on the stored status (p3-wire): the authoring hook of a
		// response may have cancelled this review in the same transaction
		// (a retain creates the next version and withdraws this one), and a
		// cancelled review is never reopened or completed here.
		res := tx.Exec(`UPDATE iga_gov_owner_review SET status = 'complete', closed_at = ? WHERE workspace_id = ? AND id = ?
			AND status IN ('open','reopened')`, now, ws, st.Review.ID)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return nil
		}
		st.Review.Status, st.Review.ClosedAt = GovReviewComplete, &now
		ua, ur := st.unconfirmed()
		return appendGovEvent(tx, ws, GovEventReviewCompleted, ak, aid, st.refs(), map[string]any{
			"review_id": st.Review.ID, "owners": len(st.Owners), "age_unconfirmed": len(ua), "route_unconfirmed": len(ur)})
	case GovReviewComplete:
		if len(b) == 0 {
			return nil
		}
		res := tx.Exec(`UPDATE iga_gov_owner_review SET status = 'open', closed_at = NULL WHERE workspace_id = ? AND id = ?
			AND status = 'complete'`, ws, st.Review.ID)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return nil
		}
		st.Review.Status, st.Review.ClosedAt = GovReviewOpen, nil
	}
	return nil
}

/* -------------------------------- respond --------------------------------- */

// GovRespondInput is POST /reviews/:id/respond.
type GovRespondInput struct {
	Response           string                 `json:"response"`
	RetainItems        []GovRetainItem        `json:"retain_items"`
	AgeConfirmations   []GovAgeConfirmation   `json:"age_confirmations"`
	RouteConfirmations []GovRouteConfirmation `json:"route_confirmations"`
	Comment            string                 `json:"comment"`
	// Via is ui (the console), slack (T3.14) or email_link.
	Via string `json:"-"`
}

// GovRespondResult is what Respond did.
type GovRespondResult struct {
	Before       *models.IGAGovOwnerResponse `json:"-"`
	Response     models.IGAGovOwnerResponse  `json:"response"`
	ReviewStatus string                      `json:"review_status"`
	NewVersionID *uuid.UUID                  `json:"new_version_id"`
}

// ErrNotReviewOwner: the caller is not an owner asked in this review.
var ErrNotReviewOwner = errors.New("not an owner in this review")

func reviewClosed(status string) *GovError {
	return govErr(http.StatusConflict, "review_closed", "This owner review is "+status+"; it no longer takes this action.",
		map[string]any{"status": status})
}

// Respond records the caller's answer (§7.4). The caller must be a live
// owner of a subject of the review.
func (s *IGAGovOwnerReviewService) Respond(ctx context.Context, ws, actor, reviewID uuid.UUID, in GovRespondInput) (*GovRespondResult, error) {
	var out *GovRespondResult
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		vid, err := s.reviewVersion(tx, ws, reviewID)
		if err != nil {
			return err
		}
		st, err := s.load(tx, ws, vid, true)
		if err != nil {
			return err
		}
		if st.owner(actor) == nil {
			return ErrNotReviewOwner
		}
		switch st.Review.Status {
		case GovReviewOpen, GovReviewReopened, GovReviewComplete:
		default:
			return reviewClosed(st.Review.Status)
		}
		if _, err := s.syncTx(tx, ws, st, actor); err != nil {
			return err
		}
		if err := st.validateResponse(actor, &in, s.now()); err != nil {
			return err
		}
		r := st.response(actor)
		before := *r
		resp := in.Response
		now := s.now()
		via := in.Via
		if via == "" {
			via = "ui"
		}
		retain, _ := json.Marshal(nonNil(in.RetainItems))
		ages, _ := json.Marshal(nonNil(in.AgeConfirmations))
		routes, _ := json.Marshal(nonNil(in.RouteConfirmations))
		if err := tx.Exec(`UPDATE iga_gov_owner_response SET response = ?, retain_items = ?, age_confirmations = ?,
			route_confirmations = ?, comment = ?, responded_at = ?, responded_via = ? WHERE workspace_id = ? AND id = ?`,
			resp, string(retain), string(ages), string(routes), strings.TrimSpace(in.Comment), now, via, ws, r.ID).Error; err != nil {
			return err
		}
		r.Response, r.RetainItems, r.AgeConfirmations, r.RouteConfirmations = &resp, retain, ages, routes
		r.Comment, r.RespondedAt, r.RespondedVia = strings.TrimSpace(in.Comment), &now, &via
		var newVersion *uuid.UUID
		if resp == GovResponseRetain || resp == GovResponseObject {
			if h := s.authoringHook(); h != nil {
				newVersion, err = h.OwnerResponseTx(tx, GovOwnerResponseEvent{WorkspaceID: ws, ReviewID: st.Review.ID,
					VersionID: st.Version.ID, PolicyID: st.Policy.ID, UserID: actor, Response: resp,
					RetainItems: in.RetainItems, Comment: strings.TrimSpace(in.Comment)})
				if err != nil {
					return err
				}
			}
		}
		payload := map[string]any{"review_id": st.Review.ID, "response": resp, "via": via,
			"age_confirmations": len(in.AgeConfirmations), "route_confirmations": len(in.RouteConfirmations),
			"previous_response": before.Response, "authoring_hook": s.authoringHook() != nil}
		if len(in.RetainItems) > 0 {
			svcs := make([]string, 0, len(in.RetainItems))
			for _, it := range in.RetainItems {
				svcs = append(svcs, it.Service)
			}
			payload["retained_services"] = svcs
		}
		if newVersion != nil {
			payload["new_version_id"] = *newVersion
		}
		ak, aid := actorOf(actor)
		if via == "slack" {
			ak = models.GovActorSlackUser
		}
		if err := appendGovEvent(tx, ws, GovEventReviewResponded, ak, aid, st.refs(), payload); err != nil {
			return err
		}
		if err := s.settleStatusTx(tx, ws, st, ak, aid); err != nil {
			return err
		}
		out = &GovRespondResult{Before: &before, Response: *r, ReviewStatus: st.Review.Status, NewVersionID: newVersion}
		return nil
	})
	return out, err
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func (st *govReviewState) validateResponse(actor uuid.UUID, in *GovRespondInput, now time.Time) error {
	switch in.Response {
	case GovResponseAcknowledge, GovResponseRetain, GovResponseObject:
	default:
		return GovBadParam("response", "response must be acknowledge, retain or object.")
	}
	owned := map[uuid.UUID]bool{}
	for _, of := range st.owner(actor).OwnerOf {
		owned[of.TargetID] = true
	}
	removed := map[string]bool{}
	for _, t := range st.Targets {
		if !owned[t.TargetID] {
			continue
		}
		for _, r := range t.Removed {
			removed[r.Service] = true
		}
		if len(t.Removed) == 0 {
			for svc := range st.Removals {
				removed[svc] = true
			}
		}
	}
	ageAsk := map[string]bool{}
	for _, a := range st.ageItems() {
		if owned[a.TargetID] {
			ageAsk[a.Service] = true
		}
	}
	routeAsk := map[string]bool{}
	for _, r := range st.routeItems() {
		if owned[r.TargetID] {
			routeAsk[r.Service+"\x1f"+r.Route] = true
		}
	}
	for i, a := range in.AgeConfirmations {
		f := fmt.Sprintf("age_confirmations[%d]", i)
		if !a.Confirmed {
			return GovBadParam(f+".confirmed", "Only confirmations (confirmed: true) are recorded; keep a service with retain instead.")
		}
		if !ageAsk[a.Service] {
			return GovBadParam(f+".service", "No age confirmation is requested from you for "+a.Service+".")
		}
	}
	for i, c := range in.RouteConfirmations {
		f := fmt.Sprintf("route_confirmations[%d]", i)
		if !c.Confirmed {
			return GovBadParam(f+".confirmed", "Only confirmations (confirmed: true) are recorded; keep a service with retain instead.")
		}
		if !routeAsk[c.Service+"\x1f"+c.Route] {
			return GovBadParam(f+".route", "No confirmation is requested from you for this route.")
		}
	}
	switch in.Response {
	case GovResponseAcknowledge:
		if len(in.RetainItems) > 0 {
			return GovBadParam("retain_items", "retain_items are only accepted with response retain.")
		}
	case GovResponseRetain:
		if len(in.RetainItems) == 0 {
			return GovBadParam("retain_items", "retain needs at least one retain item {service, reason, review_by}.")
		}
		seen := map[string]bool{}
		for i, it := range in.RetainItems {
			f := fmt.Sprintf("retain_items[%d]", i)
			if !removed[it.Service] {
				return GovBadParam(f+".service", it.Service+" is not removed by this version on a role you own.")
			}
			if seen[it.Service] {
				return GovBadParam(f+".service", it.Service+" is listed twice.")
			}
			seen[it.Service] = true
			if strings.TrimSpace(it.Reason) == "" {
				return GovBadParam(f+".reason", "A retained service needs a reason.")
			}
			by, ok := parseReviewBy(it.ReviewBy)
			if !ok || !by.After(now) {
				return GovBadParam(f+".review_by", "review_by must be a future date (YYYY-MM-DD or RFC 3339).")
			}
		}
	case GovResponseObject:
		if len(in.RetainItems) > 0 {
			return GovBadParam("retain_items", "retain_items are only accepted with response retain.")
		}
		if strings.TrimSpace(in.Comment) == "" {
			return GovBadParam("comment", "An objection needs a comment saying what would break.")
		}
	}
	return nil
}

func parseReviewBy(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.Add(24*time.Hour - time.Nanosecond), true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

/* ---------------------------- exception, remind ---------------------------- */

// Except is POST /reviews/:id/exception: an approver lets the version
// proceed without the missing owners or responses. The version's author
// cannot (403 self_approval).
func (s *IGAGovOwnerReviewService) Except(ctx context.Context, ws, actor, reviewID uuid.UUID, reason string) (before, after *models.IGAGovOwnerReview, err error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, nil, GovBadParam("reason", "An exception needs a reason.")
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		vid, err := s.reviewVersion(tx, ws, reviewID)
		if err != nil {
			return err
		}
		st, err := s.load(tx, ws, vid, true)
		if err != nil {
			return err
		}
		if st.Version.CreatedBy == actor {
			return govErr(http.StatusForbidden, "self_approval", "The author of a version cannot grant its review exception.", nil)
		}
		switch st.Review.Status {
		case GovReviewOpen, GovReviewReopened, GovReviewComplete:
		default:
			return reviewClosed(st.Review.Status)
		}
		b := *st.Review
		before = &b
		blockers := st.blockers()
		ua, ur := st.unconfirmed()
		now := s.now()
		if err := tx.Exec(`UPDATE iga_gov_owner_review SET status = 'excepted', exception_by = ?, exception_reason = ?, closed_at = ?
			WHERE workspace_id = ? AND id = ?`, actor, reason, now, ws, st.Review.ID).Error; err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventReviewExcepted, models.GovActorUser, actor.String(), st.refs(), map[string]any{
			"review_id": st.Review.ID, "reason": reason, "previous_status": st.Review.Status, "blockers": blockers,
			"age_unconfirmed": ua, "route_unconfirmed": ur}); err != nil {
			return err
		}
		a := *st.Review
		a.Status, a.ExceptionBy, a.ExceptionReason, a.ClosedAt = GovReviewExcepted, &actor, reason, &now
		after = &a
		return nil
	})
	return before, after, err
}

// Remind is POST /reviews/:id/remind: resync, then re-send the review to
// every owner who has not responded. It returns who was reminded.
func (s *IGAGovOwnerReviewService) Remind(ctx context.Context, ws, actor, reviewID uuid.UUID) ([]uuid.UUID, error) {
	reminded := []uuid.UUID{}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		vid, err := s.reviewVersion(tx, ws, reviewID)
		if err != nil {
			return err
		}
		st, err := s.load(tx, ws, vid, true)
		if err != nil {
			return err
		}
		switch st.Review.Status {
		case GovReviewOpen, GovReviewReopened:
		default:
			return reviewClosed(st.Review.Status)
		}
		sync, err := s.syncTx(tx, ws, st, actor)
		if err != nil {
			return err
		}
		fresh := map[uuid.UUID]bool{}
		for _, u := range sync.NewOwners {
			fresh[u] = true
		}
		for _, o := range st.Owners {
			r := st.response(o.UserID)
			if r == nil || r.Response != nil || fresh[o.UserID] {
				continue
			}
			if r.Delivery == GovDeliveryFailed {
				if err := tx.Exec(`UPDATE iga_gov_owner_response SET delivery = 'pending' WHERE workspace_id = ? AND id = ?`, ws, r.ID).Error; err != nil {
					return err
				}
			}
			if err := s.notifyOwnerTx(tx, ws, st.Review.ID, o.UserID, true); err != nil {
				return err
			}
			reminded = append(reminded, o.UserID)
		}
		return appendGovEvent(tx, ws, GovEventReviewReminded, models.GovActorUser, actor.String(), st.refs(), map[string]any{
			"review_id": st.Review.ID, "reminded_user_ids": reminded, "new_owner_user_ids": sync.NewOwners})
	})
	return reminded, err
}

// CancelReviewTx cancels the version's review (T3.11: withdraw). No review
// is a no-op.
func (s *IGAGovOwnerReviewService) CancelReviewTx(tx *gorm.DB, ws, versionID, actor uuid.UUID, reason string) error {
	st, err := s.load(tx, ws, versionID, true)
	if err != nil || st.Review == nil || st.Review.Status == GovReviewCancelled {
		return err
	}
	now := s.now()
	if err := tx.Exec(`UPDATE iga_gov_owner_review SET status = 'cancelled', exception_by = NULL, exception_reason = '', closed_at = ?
		WHERE workspace_id = ? AND id = ?`, now, ws, st.Review.ID).Error; err != nil {
		return err
	}
	ak, aid := actorOf(actor)
	return appendGovEvent(tx, ws, GovEventReviewCancelled, ak, aid, st.refs(), map[string]any{
		"review_id": st.Review.ID, "reason": reason, "previous_status": st.Review.Status})
}

/* --------------------------------- views ---------------------------------- */

// GovReviewTargetView is one target role of the review.
type GovReviewTargetView struct {
	TargetID          uuid.UUID              `json:"target_id"`
	ControlID         uuid.UUID              `json:"control_id"`
	IdentityAccountID uuid.UUID              `json:"identity_account_id"`
	RoleARN           string                 `json:"role_arn"`
	Removed           []igagov.ImpactService `json:"removed"`
	Retained          []igagov.ImpactService `json:"retained"`
	Consumers         []ConsumerOwners       `json:"consumers"`
}

// GovReviewResponseView is one owner's row.
type GovReviewResponseView struct {
	UserID             uuid.UUID              `json:"user_id"`
	Name               string                 `json:"name"`
	Asked              bool                   `json:"asked"`
	CurrentOwner       bool                   `json:"current_owner"`
	OwnerOf            []GovReviewOwnerOf     `json:"owner_of"`
	Delivery           string                 `json:"delivery"`
	DeliveryChannels   []string               `json:"delivery_channels"`
	Response           *string                `json:"response"`
	RetainItems        []GovRetainItem        `json:"retain_items"`
	AgeConfirmations   []GovAgeConfirmation   `json:"age_confirmations"`
	RouteConfirmations []GovRouteConfirmation `json:"route_confirmations"`
	Comment            string                 `json:"comment"`
	RespondedAt        *time.Time             `json:"responded_at"`
	RespondedVia       *string                `json:"responded_via"`
}

// GovReviewView is GET /reviews/:id.
type GovReviewView struct {
	ID              uuid.UUID               `json:"id"`
	Status          string                  `json:"status"`
	DeadlineAt      time.Time               `json:"deadline_at"`
	Overdue         bool                    `json:"overdue"`
	CreatedAt       time.Time               `json:"created_at"`
	ClosedAt        *time.Time              `json:"closed_at"`
	ExceptionBy     *uuid.UUID              `json:"exception_by"`
	ExceptionReason string                  `json:"exception_reason"`
	ImpactHashes    []string                `json:"impact_hashes"`
	CurrentHashes   []string                `json:"current_impact_hashes"`
	Version         map[string]any          `json:"version"`
	Targets         []GovReviewTargetView   `json:"targets"`
	Requested       map[string]any          `json:"requested"`
	Responses       []GovReviewResponseView `json:"responses"`
	MyResponse      *GovReviewResponseView  `json:"my_response"`
	Blockers        []GovReviewBlocker      `json:"blockers"`
	Gate            map[string]any          `json:"gate"`
	Unconfirmed     map[string]any          `json:"unconfirmed"`
	ViewerIsOwner   bool                    `json:"viewer_is_owner"`
}

// IsOwnerOf reports whether user is a live owner asked in the review
// (route authorization: "owner of a subject").
func (s *IGAGovOwnerReviewService) IsOwnerOf(db *gorm.DB, ws, reviewID, user uuid.UUID) (bool, error) {
	vid, err := s.reviewVersion(db, ws, reviewID)
	if err != nil {
		return false, err
	}
	st, err := s.load(db, ws, vid, false)
	if err != nil {
		return false, err
	}
	return st.owner(user) != nil, nil
}

// View is GET /reviews/:id for viewer (uuid.Nil: no personal response).
func (s *IGAGovOwnerReviewService) View(ctx context.Context, ws, reviewID, viewer uuid.UUID) (*GovReviewView, error) {
	db := s.db.WithContext(ctx)
	vid, err := s.reviewVersion(db, ws, reviewID)
	if err != nil {
		return nil, err
	}
	st, err := s.load(db, ws, vid, false)
	if err != nil {
		return nil, err
	}
	return st.view(viewer, s.now()), nil
}

func (st *govReviewState) view(viewer uuid.UUID, now time.Time) *GovReviewView {
	rv := st.Review
	v := &GovReviewView{ID: rv.ID, Status: rv.Status, DeadlineAt: rv.DeadlineAt, Overdue: now.After(rv.DeadlineAt) && rv.ClosedAt == nil,
		CreatedAt: rv.CreatedAt, ClosedAt: rv.ClosedAt, ExceptionBy: rv.ExceptionBy, ExceptionReason: rv.ExceptionReason,
		ImpactHashes: append([]string{}, rv.ImpactHashes...), CurrentHashes: append([]string{}, st.Hashes...),
		Targets: []GovReviewTargetView{}, Responses: []GovReviewResponseView{}, Blockers: st.blockers()}
	v.Version = map[string]any{"id": st.Version.ID, "policy_id": st.Policy.ID, "policy_name": st.Policy.Name,
		"version_no": st.Version.VersionNo, "status": st.Version.Status, "created_by": st.Version.CreatedBy, "intent_hash": st.Version.IntentHash}
	for _, t := range st.Targets {
		cons := t.Ownership.Consumers
		if cons == nil {
			cons = []ConsumerOwners{}
		}
		v.Targets = append(v.Targets, GovReviewTargetView{TargetID: t.TargetID, ControlID: t.ControlID,
			IdentityAccountID: t.IdentityAccountID, RoleARN: t.RoleARN, Removed: nonNil(t.Removed), Retained: nonNil(t.Retained), Consumers: cons})
	}
	v.Requested = map[string]any{"age_confirmations": nonNil(st.ageItems()), "route_confirmations": nonNil(st.routeItems())}
	ua, ur := st.unconfirmed()
	v.Unconfirmed = map[string]any{"age": nonNil(ua), "routes": nonNil(ur)}
	asked := map[uuid.UUID]bool{}
	for _, r := range st.Responses {
		asked[r.UserID] = true
		o := st.owner(r.UserID)
		rv := GovReviewResponseView{UserID: r.UserID, Asked: true, CurrentOwner: o != nil, Delivery: r.Delivery,
			DeliveryChannels: nonNil([]string(r.DeliveryChannels)), Response: r.Response,
			RetainItems: nonNil(decodeJSON[GovRetainItem](r.RetainItems)), AgeConfirmations: nonNil(decodeJSON[GovAgeConfirmation](r.AgeConfirmations)),
			RouteConfirmations: nonNil(decodeJSON[GovRouteConfirmation](r.RouteConfirmations)), Comment: r.Comment,
			RespondedAt: r.RespondedAt, RespondedVia: r.RespondedVia, OwnerOf: nonNil(decodeJSON[GovReviewOwnerOf](r.OwnerOf))}
		if o != nil {
			rv.Name = o.Name
		}
		v.Responses = append(v.Responses, rv)
		if r.UserID == viewer {
			mine := rv
			v.MyResponse = &mine
		}
	}
	for _, o := range st.Owners {
		if !asked[o.UserID] {
			v.Responses = append(v.Responses, GovReviewResponseView{UserID: o.UserID, Name: o.Name, CurrentOwner: true,
				OwnerOf: o.OwnerOf, Delivery: GovDeliveryPending, DeliveryChannels: []string{}, RetainItems: []GovRetainItem{},
				AgeConfirmations: []GovAgeConfirmation{}, RouteConfirmations: []GovRouteConfirmation{}})
		}
	}
	v.ViewerIsOwner = viewer != uuid.Nil && st.owner(viewer) != nil
	if err := st.gate(now); err != nil {
		var ge *GovError
		if errors.As(err, &ge) {
			v.Gate = map[string]any{"passed": false, "code": ge.Code, "message": ge.Message}
		}
	} else {
		v.Gate = map[string]any{"passed": true}
	}
	return v
}

// GovReviewSummary is one row of GET /reviews.
type GovReviewSummary struct {
	ID              uuid.UUID  `json:"id"`
	VersionID       uuid.UUID  `json:"version_id"`
	PolicyID        uuid.UUID  `json:"policy_id"`
	PolicyName      string     `json:"policy_name"`
	VersionNo       int        `json:"version_no"`
	Status          string     `json:"status"`
	DeadlineAt      time.Time  `json:"deadline_at"`
	Overdue         bool       `json:"overdue"`
	CreatedAt       time.Time  `json:"created_at"`
	ClosedAt        *time.Time `json:"closed_at"`
	OwnersAsked     int        `json:"owners_asked"`
	OwnersResponded int        `json:"owners_responded"`
	MyResponse      *string    `json:"my_response"`
	Asked           bool       `json:"asked"`
}

// GovReviewFilter is GET /reviews' filter.
type GovReviewFilter struct {
	Mine     bool
	Viewer   uuid.UUID
	Statuses []string
}

// List is GET /reviews: newest first, cursor-paged (≤ 200), mine = the
// reviews the viewer was asked in.
func (s *IGAGovOwnerReviewService) List(ctx context.Context, ws uuid.UUID, f GovReviewFilter, cursor string, limit int, key []byte) ([]GovReviewSummary, *string, error) {
	db := s.db.WithContext(ctx)
	if limit <= 0 || limit > MaxGovPage {
		limit = MaxGovPage
	}
	for _, st := range f.Statuses {
		switch st {
		case GovReviewOpen, GovReviewComplete, GovReviewExcepted, GovReviewCancelled, GovReviewReopened:
		default:
			return nil, nil, GovBadParam("status", "status must be open, reopened, complete, excepted or cancelled.")
		}
	}
	sort.Strings(f.Statuses)
	rd := NewGovReader(db, key)
	want := govCursor{Route: "reviews", WS: ws.String(), Q: fmt.Sprintf("mine=%t;viewer=%s;status=%s", f.Mine, f.Viewer, strings.Join(f.Statuses, ","))}
	q := `SELECT r.id, r.version_id, v.policy_id, p.name AS policy_name, v.version_no, r.status, r.deadline_at, r.created_at, r.closed_at,
	             (SELECT count(*) FROM iga_gov_owner_response x WHERE x.review_id = r.id) AS owners_asked,
	             (SELECT count(*) FROM iga_gov_owner_response x WHERE x.review_id = r.id AND x.response IS NOT NULL) AS owners_responded,
	             (SELECT x.response FROM iga_gov_owner_response x WHERE x.review_id = r.id AND x.user_id = ?) AS my_response,
	             EXISTS (SELECT 1 FROM iga_gov_owner_response x WHERE x.review_id = r.id AND x.user_id = ?) AS asked
	        FROM iga_gov_owner_review r
	        JOIN iga_gov_policy_version v ON v.workspace_id = r.workspace_id AND v.id = r.version_id
	        JOIN iga_gov_policy p ON p.workspace_id = v.workspace_id AND p.id = v.policy_id
	       WHERE r.workspace_id = ?`
	args := []any{f.Viewer, f.Viewer, ws}
	if f.Mine {
		q += ` AND EXISTS (SELECT 1 FROM iga_gov_owner_response x WHERE x.review_id = r.id AND x.user_id = ?)`
		args = append(args, f.Viewer)
	}
	if len(f.Statuses) > 0 {
		q += ` AND r.status IN ?`
		args = append(args, f.Statuses)
	}
	if cursor != "" {
		after, err := rd.open(cursor, want)
		if err != nil {
			return nil, nil, err
		}
		parts := strings.SplitN(after, "|", 2)
		ts, err1 := time.Parse(time.RFC3339Nano, parts[0])
		id, err2 := uuid.Parse(parts[len(parts)-1])
		if len(parts) != 2 || err1 != nil || err2 != nil {
			return nil, nil, govErr(http.StatusBadRequest, "cursor_invalid", "The cursor is not valid for this list; restart it.", nil)
		}
		q += ` AND (r.created_at, r.id) < (?, ?)`
		args = append(args, ts, id)
	}
	q += ` ORDER BY r.created_at DESC, r.id DESC LIMIT ?`
	args = append(args, limit+1)
	var rows []GovReviewSummary
	if err := db.Raw(q, args...).Scan(&rows).Error; err != nil {
		return nil, nil, err
	}
	var next *string
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		c := rd.sign(govCursor{Route: want.Route, WS: want.WS, Q: want.Q, After: last.CreatedAt.UTC().Format(time.RFC3339Nano) + "|" + last.ID.String()})
		next = &c
	}
	now := s.now()
	for i := range rows {
		rows[i].Overdue = rows[i].ClosedAt == nil && now.After(rows[i].DeadlineAt)
	}
	if rows == nil {
		rows = []GovReviewSummary{}
	}
	return rows, next, nil
}

/* --------------------------- notices and delivery -------------------------- */

func init() {
	RegisterGovNoticeSubject(GovNoticeOwnerReview, GovNoticeSubject{
		Render: renderOwnerReviewNotice,
		OnSent: func(tx *gorm.DB, n *models.IGAGovNotification, user *uuid.UUID) error {
			if user == nil {
				return nil
			}
			return tx.Exec(`UPDATE iga_gov_owner_response
				SET delivery = 'delivered',
				    delivery_channels = CASE WHEN ?::text = ANY(delivery_channels) THEN delivery_channels
				                             ELSE array_append(delivery_channels, ?::text) END
				WHERE workspace_id = ? AND review_id = ? AND user_id = ?`, n.Channel, n.Channel, n.WorkspaceID, n.SubjectID, *user).Error
		},
		OnDead: func(tx *gorm.DB, n *models.IGAGovNotification, user *uuid.UUID) error {
			if user == nil {
				return nil
			}
			// Failed only when no channel to this owner delivered or is still trying.
			return tx.Exec(`UPDATE iga_gov_owner_response SET delivery = 'failed'
				WHERE workspace_id = ? AND review_id = ? AND user_id = ? AND delivery <> 'delivered'
				  AND NOT EXISTS (SELECT 1 FROM iga_gov_notification o
				                   WHERE o.workspace_id = ? AND o.subject_kind = 'owner_review' AND o.subject_id = ?
				                     AND o.recipient = ? AND o.id <> ? AND o.state IN ('pending','failed','sent'))`,
				n.WorkspaceID, n.SubjectID, *user, n.WorkspaceID, n.SubjectID, n.Recipient, n.ID).Error
		},
	})
}

// govConsoleLink is base + path, or "" when no base URL is configured (a
// dead link reads as a broken product; the legacy warning's rule).
func govConsoleLink(path string) string {
	if config.AppConfig == nil {
		return ""
	}
	base := strings.TrimRight(strings.TrimSpace(config.AppConfig.BaseURL), "/")
	if base == "" {
		return ""
	}
	if !strings.HasPrefix(strings.ToLower(base), "http") {
		base = "https://" + base
	}
	return base + path
}

func roleName(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

func renderOwnerReviewNotice(db *gorm.DB, n *models.IGAGovNotification, user *uuid.UUID) (*GovNotice, error) {
	svc := NewIGAGovOwnerReviewService(db)
	vid, err := svc.reviewVersion(db, n.WorkspaceID, n.SubjectID)
	if err != nil {
		var ge *GovError
		if errors.As(err, &ge) && ge.Status == http.StatusNotFound {
			return nil, GovNotifyPermanent(errors.New("the review no longer exists"))
		}
		return nil, err
	}
	st, err := svc.load(db, n.WorkspaceID, vid, false)
	if err != nil {
		return nil, err
	}
	rv := st.Review
	link := govConsoleLink("/iga/policy/reviews/" + rv.ID.String())
	due := rv.DeadlineAt.UTC()
	if user == nil {
		targets := []map[string]any{}
		for _, t := range st.Targets {
			rm := []string{}
			for _, r := range t.Removed {
				rm = append(rm, r.Service)
			}
			targets = append(targets, map[string]any{"role_arn": t.RoleARN, "removed": rm})
		}
		responded := 0
		for _, r := range st.Responses {
			if r.Response != nil {
				responded++
			}
		}
		doc := map[string]any{"type": "iga.policy.owner_review", "version": 1,
			"workspace_id": n.WorkspaceID.String(), "review_id": rv.ID.String(), "status": rv.Status,
			"policy_id": st.Policy.ID.String(), "policy_name": st.Policy.Name, "version_no": st.Version.VersionNo,
			"deadline_at": due, "targets": targets, "owners_asked": len(st.Responses), "owners_responded": responded}
		if link != "" {
			doc["link"] = link
		}
		return &GovNotice{Webhook: doc, Title: "Owner review: " + st.Policy.Name, Link: link}, nil
	}
	o := st.owner(*user)
	if o == nil {
		return nil, GovNotifyPermanent(errors.New("the recipient is no longer an owner in this review"))
	}
	owned := map[uuid.UUID]bool{}
	var roles, why []string
	seenRole := map[string]bool{}
	for _, of := range o.OwnerOf {
		owned[of.TargetID] = true
		if !seenRole[of.RoleARN] {
			seenRole[of.RoleARN] = true
			roles = append(roles, roleName(of.RoleARN))
		}
		what := of.Name
		if of.ObjectKind == models.GovObjectIdentityAccount || what == "" {
			what = roleName(of.RoleARN)
		}
		why = append(why, fmt.Sprintf("%s (%s %s)", what, of.Role, strings.ReplaceAll(of.ObjectKind, "_", " ")))
	}
	var removed, retained []string
	rmSeen, rtSeen := map[string]bool{}, map[string]bool{}
	for _, t := range st.Targets {
		if !owned[t.TargetID] {
			continue
		}
		for _, r := range t.Removed {
			if !rmSeen[r.Service] {
				rmSeen[r.Service] = true
				removed = append(removed, r.Service)
			}
		}
		for _, r := range t.Retained {
			if !rtSeen[r.Service] {
				rtSeen[r.Service] = true
				retained = append(retained, r.Service)
			}
		}
	}
	var ages []string
	for _, a := range st.ageItems() {
		if owned[a.TargetID] {
			ages = append(ages, a.Service)
		}
	}
	var routes []string
	for _, r := range st.routeItems() {
		if owned[r.TargetID] {
			routes = append(routes, r.Service+" via "+r.Route)
		}
	}
	var b strings.Builder
	name := o.Name
	if name == "" {
		name = "there"
	}
	fmt.Fprintf(&b, "Hello %s,\n\n", name)
	fmt.Fprintf(&b, "Please review a change to %s (policy %q, version %d).\n", strings.Join(roles, ", "), st.Policy.Name, st.Version.VersionNo)
	if len(removed) > 0 {
		fmt.Fprintf(&b, "AuthSec proposes removing: %s.\n", strings.Join(removed, ", "))
	}
	if len(retained) > 0 {
		fmt.Fprintf(&b, "It keeps: %s.\n", strings.Join(retained, ", "))
	}
	fmt.Fprintf(&b, "\nYou are asked because you own: %s.\n", strings.Join(why, "; "))
	if len(ages) > 0 {
		fmt.Fprintf(&b, "\nPlease confirm these were not added recently (they predate AuthSec's first scan):\n")
		for _, a := range ages {
			fmt.Fprintf(&b, "  - %s\n", a)
		}
	}
	if len(routes) > 0 {
		fmt.Fprintf(&b, "\nAWS's report does not cover access granted by resource policies. Please confirm these routes are not used:\n")
		for _, r := range routes {
			fmt.Fprintf(&b, "  - %s\n", r)
		}
	}
	fmt.Fprintf(&b, "\nPlease respond by %s. Silence is not consent: the change cannot proceed without your answer or an approver's recorded exception.\n",
		due.Format(time.RFC1123))
	if link != "" {
		fmt.Fprintf(&b, "\nOpen the review:\n  %s\n", link)
	}
	fmt.Fprintf(&b, "\nReview ID: %s\n\nRegards,\nAuthSec Team\n", rv.ID)
	subject := fmt.Sprintf("Action required: review a change to %s (due %s)", strings.Join(roles, ", "), due.Format("2 Jan 15:04 MST"))
	lines := []string{}
	if len(removed) > 0 {
		lines = append(lines, "Removes "+strings.Join(removed, ", "))
	}
	if len(ages) > 0 {
		lines = append(lines, "Confirm not added recently: "+strings.Join(ages, ", "))
	}
	if len(routes) > 0 {
		lines = append(lines, "Confirm routes unused: "+strings.Join(routes, "; "))
	}
	return &GovNotice{Subject: subject, Text: b.String(), Title: "Review a change to " + strings.Join(roles, ", "),
		Lines: lines, Link: link}, nil
}
