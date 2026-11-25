package services

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Responder groups (SPEC-secops-backend-upgrade.md decision 1, P10;
// migration 181).
//
// An ask about an agent goes to the responder group of its estate scope; any
// accepted member answers. Who decides for agent X (resolveResponder):
//  1. the group holding scope ('agent', X);
//  2. else the group holding one of X's estate scopes, in the order cluster,
//     account, subscription, estate_scope -- the scopes come from X's aliases:
//     a Kubernetes sighting's discovery source (cluster), the AWS connector
//     supporting its workload and an AWS sighting's account (account), an
//     Azure sighting's subscription (subscription), the IGA estate scope of
//     its workload or logical agent (estate_scope);
//  3. else the workspace's default group, created with every workspace admin
//     (EnsureDefaultResponderGroup).
//
// A member is assigned as a candidate and becomes accepted only when they
// accept it themselves. A member may delegate to another workspace member
// until an end date; while it runs the delegate decides in their place. A
// group hands all its scopes over to another group in one step.
//
// Separation: the person who acted is excluded from deciding (decision 1);
// that is the ask's rule (W4) and is not applied here.

// Responder resolution sources.
const (
	ResponderViaAgent        = "agent"
	ResponderViaCluster      = "cluster"
	ResponderViaAccount      = "account"
	ResponderViaSubscription = "subscription"
	ResponderViaEstateScope  = "estate_scope"
	ResponderViaDefault      = "default"
	ResponderViaNone         = "none"
)

// DefaultResponderGroupName is the default group's name.
const DefaultResponderGroupName = "Workspace admins"

// workspaceAdminRoles are the role names a workspace admin holds (the same
// set access-request notices use).
var workspaceAdminRoles = []string{"admin", "administrator", "owner", "super_admin"}

// ResponderGroup is one responder_group with its members and scopes.
type ResponderGroup struct {
	ID          uuid.UUID              `json:"id" gorm:"column:id"`
	Name        string                 `json:"name" gorm:"column:name"`
	Description string                 `json:"description" gorm:"column:description"`
	IsDefault   bool                   `json:"is_default" gorm:"column:is_default"`
	OwnerUserID *uuid.UUID             `json:"owner_user_id" gorm:"column:owner_user_id"`
	CreatedBy   *uuid.UUID             `json:"created_by" gorm:"column:created_by"`
	CreatedAt   time.Time              `json:"created_at" gorm:"column:created_at"`
	UpdatedAt   time.Time              `json:"updated_at" gorm:"column:updated_at"`
	Members     []ResponderGroupMember `json:"members" gorm:"-"`
	Scopes      []ResponderGroupScope  `json:"scopes" gorm:"-"`
}

// ResponderGroupMember is one responder_group_member row.
type ResponderGroupMember struct {
	ID             uuid.UUID  `json:"id" gorm:"column:id"`
	GroupID        uuid.UUID  `json:"group_id" gorm:"column:group_id"`
	UserID         uuid.UUID  `json:"user_id" gorm:"column:user_id"`
	Role           string     `json:"role" gorm:"column:role"`
	State          string     `json:"state" gorm:"column:state"`
	AssignedBy     *uuid.UUID `json:"assigned_by" gorm:"column:assigned_by"`
	AssignedAt     time.Time  `json:"assigned_at" gorm:"column:assigned_at"`
	AcceptedAt     *time.Time `json:"accepted_at" gorm:"column:accepted_at"`
	DelegatedTo    *uuid.UUID `json:"delegated_to" gorm:"column:delegated_to"`
	DelegatedUntil *time.Time `json:"delegated_until" gorm:"column:delegated_until"`
}

// ResponderGroupScope is one responder_group_scope row.
type ResponderGroupScope struct {
	ID        uuid.UUID `json:"id" gorm:"column:id"`
	GroupID   uuid.UUID `json:"group_id" gorm:"column:group_id"`
	ScopeKind string    `json:"scope_kind" gorm:"column:scope_kind"`
	ScopeRef  string    `json:"scope_ref" gorm:"column:scope_ref"`
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at"`
}

// ResponderDecider is one person who decides now.
type ResponderDecider struct {
	UserID uuid.UUID `json:"user_id"`
	Role   string    `json:"role"`
	// OnBehalfOf is the member whose delegation makes UserID a decider.
	OnBehalfOf *uuid.UUID `json:"on_behalf_of,omitempty"`
}

// ResponderResolution says who decides for an agent and why.
type ResponderResolution struct {
	GroupID   *uuid.UUID         `json:"group_id"`
	GroupName string             `json:"group_name"`
	Via       string             `json:"via"`
	ScopeKind string             `json:"scope_kind,omitempty"`
	ScopeRef  string             `json:"scope_ref,omitempty"`
	Deciders  []ResponderDecider `json:"deciders"`
}

var validScopeKinds = map[string]bool{"account": true, "subscription": true, "cluster": true, "agent": true, "estate_scope": true}

// ResponderGroupService serves the responder group routes.
type ResponderGroupService struct{ db *gorm.DB }

// NewResponderGroupService builds the service over db.
func NewResponderGroupService(db *gorm.DB) *ResponderGroupService {
	return &ResponderGroupService{db: db}
}

func (s *ResponderGroupService) inWS(ctx context.Context, ws uuid.UUID, fn func(tx *gorm.DB) error) error {
	return tenancy.InWorkspace(ctx, s.db, ws, fn)
}

/* ------------------------------------------------------------------------- */
/*                                Resolution                                  */
/* ------------------------------------------------------------------------- */

// agentEstateScopes are the agent's estate scopes, in resolution order.
func agentEstateScopes(tx *gorm.DB, ws, agentID uuid.UUID) ([]ResponderGroupScope, error) {
	var rows []struct {
		Kind string
		Ref  string
		Prio int
	}
	err := tx.Raw(`
	  SELECT DISTINCT kind, ref, prio FROM (
	    SELECT 'cluster' AS kind, d.discovery_source_id::text AS ref, 1 AS prio
	      FROM agent_alias a JOIN discovered_agents d ON d.workspace_id = a.workspace_id AND d.id::text = a.source_id
	     WHERE a.workspace_id = ? AND a.agent_id = ? AND a.source_table = 'discovered_agents'
	       AND d.source = 'k8s_webhook' AND d.discovery_source_id IS NOT NULL
	    UNION ALL
	    SELECT CASE WHEN c.scope_kind = 'subscription' THEN 'subscription' ELSE 'account' END, c.scope_id,
	           CASE WHEN c.scope_kind = 'subscription' THEN 3 ELSE 2 END
	      FROM agent_alias a
	      JOIN iga_object_support s ON s.workspace_id = a.workspace_id AND s.workload_id::text = a.source_id
	      JOIN cloud_connector c ON c.workspace_id = s.workspace_id AND c.id = s.connector_id
	     WHERE a.workspace_id = ? AND a.agent_id = ? AND a.source_table = 'iga_workload' AND c.scope_kind IN ('account', 'subscription')
	    UNION ALL
	    SELECT 'account', d.metadata->>'account_id', 2
	      FROM agent_alias a JOIN discovered_agents d ON d.workspace_id = a.workspace_id AND d.id::text = a.source_id
	     WHERE a.workspace_id = ? AND a.agent_id = ? AND a.source_table = 'discovered_agents' AND COALESCE(d.metadata->>'account_id', '') <> ''
	    UNION ALL
	    SELECT 'subscription', d.metadata->>'subscription_id', 3
	      FROM agent_alias a JOIN discovered_agents d ON d.workspace_id = a.workspace_id AND d.id::text = a.source_id
	     WHERE a.workspace_id = ? AND a.agent_id = ? AND a.source_table = 'discovered_agents' AND COALESCE(d.metadata->>'subscription_id', '') <> ''
	    UNION ALL
	    SELECT 'estate_scope', w.estate_scope_id::text, 4
	      FROM agent_alias a JOIN iga_workload w ON w.workspace_id = a.workspace_id AND w.id::text = a.source_id
	     WHERE a.workspace_id = ? AND a.agent_id = ? AND a.source_table = 'iga_workload' AND w.estate_scope_id IS NOT NULL
	    UNION ALL
	    SELECT 'estate_scope', g.estate_scope_id::text, 4
	      FROM agent_alias a JOIN iga_agents g ON g.workspace_id = a.workspace_id AND g.id::text = a.source_id
	     WHERE a.workspace_id = ? AND a.agent_id = ? AND a.source_table = 'iga_agents' AND g.estate_scope_id IS NOT NULL
	  ) x ORDER BY prio, ref`, ws, agentID, ws, agentID, ws, agentID, ws, agentID, ws, agentID, ws, agentID).Scan(&rows).Error
	out := make([]ResponderGroupScope, 0, len(rows))
	for _, r := range rows {
		out = append(out, ResponderGroupScope{ScopeKind: r.Kind, ScopeRef: r.Ref})
	}
	return out, err
}

func groupDeciders(tx *gorm.DB, ws, groupID uuid.UUID, now time.Time) ([]ResponderDecider, error) {
	var ms []ResponderGroupMember
	if err := tx.Raw(`SELECT * FROM responder_group_member WHERE workspace_id = ? AND group_id = ? AND state = 'accepted'
	        ORDER BY role DESC, assigned_at, id`, ws, groupID).Scan(&ms).Error; err != nil {
		return nil, err
	}
	out := []ResponderDecider{}
	for _, m := range ms {
		if m.DelegatedTo != nil && m.DelegatedUntil != nil && m.DelegatedUntil.After(now) {
			id := m.UserID
			out = append(out, ResponderDecider{UserID: *m.DelegatedTo, Role: m.Role, OnBehalfOf: &id})
			continue
		}
		out = append(out, ResponderDecider{UserID: m.UserID, Role: m.Role})
	}
	return out, nil
}

// resolveResponder applies the resolution order for agentID. It never creates
// the default group (reads run read-only); none found is Via "none".
func resolveResponder(tx *gorm.DB, ws, agentID uuid.UUID, now time.Time) (*ResponderResolution, error) {
	type hit struct {
		GroupID uuid.UUID
		Name    string
	}
	find := func(kind, ref string) (*hit, error) {
		var hs []hit
		if err := tx.Raw(`SELECT s.group_id, g.name FROM responder_group_scope s
		        JOIN responder_group g ON g.workspace_id = s.workspace_id AND g.id = s.group_id
		        WHERE s.workspace_id = ? AND s.scope_kind = ? AND s.scope_ref = ?`, ws, kind, ref).Scan(&hs).Error; err != nil {
			return nil, err
		}
		if len(hs) == 0 {
			return nil, nil
		}
		return &hs[0], nil
	}
	out := &ResponderResolution{Via: ResponderViaNone, Deciders: []ResponderDecider{}}
	set := func(h *hit, via, kind, ref string) error {
		id := h.GroupID
		out.GroupID, out.GroupName, out.Via, out.ScopeKind, out.ScopeRef = &id, h.Name, via, kind, ref
		d, err := groupDeciders(tx, ws, id, now)
		out.Deciders = d
		return err
	}
	if h, err := find("agent", agentID.String()); err != nil {
		return nil, err
	} else if h != nil {
		return out, set(h, ResponderViaAgent, "agent", agentID.String())
	}
	scopes, err := agentEstateScopes(tx, ws, agentID)
	if err != nil {
		return nil, err
	}
	for _, sc := range scopes {
		h, err := find(sc.ScopeKind, sc.ScopeRef)
		if err != nil {
			return nil, err
		}
		if h != nil {
			return out, set(h, sc.ScopeKind, sc.ScopeKind, sc.ScopeRef)
		}
	}
	var def []hit
	if err := tx.Raw(`SELECT id AS group_id, name FROM responder_group WHERE workspace_id = ? AND is_default`, ws).Scan(&def).Error; err != nil {
		return nil, err
	}
	if len(def) > 0 {
		return out, set(&def[0], ResponderViaDefault, "", "")
	}
	return out, nil
}

// ensureDefaultResponderGroup creates ws's default group with every active
// workspace admin as an accepted lead, when it does not exist. Admins are
// accepted at creation: holding the admin role is their acceptance of the
// workspace's default responsibility.
func ensureDefaultResponderGroup(tx *gorm.DB, ws uuid.UUID) error {
	var n int64
	if err := tx.Raw(`SELECT count(*) FROM responder_group WHERE workspace_id = ? AND is_default`, ws).Scan(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	var gid []uuid.UUID
	if err := tx.Raw(`INSERT INTO responder_group (workspace_id, name, description, is_default)
	        VALUES (?, ?, 'Decides for every agent no other group covers.', true)
	        ON CONFLICT DO NOTHING RETURNING id`, ws, DefaultResponderGroupName).Scan(&gid).Error; err != nil {
		return err
	}
	if len(gid) == 0 {
		return nil // a group of that name exists already: an admin named one so
	}
	if err := tx.Exec(`INSERT INTO responder_group_member (workspace_id, group_id, user_id, role, state, accepted_at)
	        SELECT DISTINCT m.workspace_id, ?::uuid, m.user_id, 'lead', 'accepted', now()
	          FROM workspace_memberships m JOIN roles r ON r.id = m.role_id
	         WHERE m.workspace_id = ? AND m.status = 'active' AND m.user_id IS NOT NULL AND LOWER(r.name) IN ?
	        ON CONFLICT (workspace_id, group_id, user_id) DO NOTHING`, gid[0], ws, workspaceAdminRoles).Error; err != nil {
		return err
	}
	return appendGovEvent(tx, ws, GovEventResponderGroupCreated, models.GovActorSystem, "", govEventRefs{},
		map[string]any{"group_id": gid[0], "name": DefaultResponderGroupName, "default": true})
}

// EnsureDefaultResponderGroup is ensureDefaultResponderGroup in its own
// transaction.
func EnsureDefaultResponderGroup(ctx context.Context, db *gorm.DB, ws uuid.UUID) error {
	return tenancy.InWorkspace(ctx, db, ws, func(tx *gorm.DB) error { return ensureDefaultResponderGroup(tx, ws) })
}

// ResolveDecider says who decides for an agent (404 for another workspace's),
// creating the default group first when the workspace has none.
func (s *ResponderGroupService) ResolveDecider(ctx context.Context, ws, agentID uuid.UUID) (*ResponderResolution, error) {
	var out *ResponderResolution
	err := s.inWS(ctx, ws, func(tx *gorm.DB) error {
		if _, err := loadAgent(tx, ws, agentID, false); err != nil {
			return err
		}
		if err := ensureDefaultResponderGroup(tx, ws); err != nil {
			return err
		}
		var err error
		out, err = resolveResponder(tx, ws, agentID, time.Now())
		return err
	})
	return out, err
}

/* ------------------------------------------------------------------------- */
/*                                   CRUD                                     */
/* ------------------------------------------------------------------------- */

func loadGroup(tx *gorm.DB, ws, id uuid.UUID, lock bool) (*ResponderGroup, error) {
	q := `SELECT * FROM responder_group WHERE workspace_id = ? AND id = ?`
	if lock {
		q += ` FOR UPDATE`
	}
	var gs []ResponderGroup
	if err := tx.Raw(q, ws, id).Scan(&gs).Error; err != nil {
		return nil, err
	}
	if len(gs) == 0 {
		return nil, GovNotFound()
	}
	g := gs[0]
	if err := tx.Raw(`SELECT * FROM responder_group_member WHERE workspace_id = ? AND group_id = ? ORDER BY assigned_at, id`,
		ws, id).Scan(&g.Members).Error; err != nil {
		return nil, err
	}
	if err := tx.Raw(`SELECT id, group_id, scope_kind, scope_ref, created_at FROM responder_group_scope
	        WHERE workspace_id = ? AND group_id = ? ORDER BY scope_kind, scope_ref`, ws, id).Scan(&g.Scopes).Error; err != nil {
		return nil, err
	}
	if g.Members == nil {
		g.Members = []ResponderGroupMember{}
	}
	if g.Scopes == nil {
		g.Scopes = []ResponderGroupScope{}
	}
	return &g, nil
}

// List lists ws's groups (the default one created first if missing).
func (s *ResponderGroupService) List(ctx context.Context, ws uuid.UUID) ([]ResponderGroup, error) {
	out := []ResponderGroup{}
	err := s.inWS(ctx, ws, func(tx *gorm.DB) error {
		if err := ensureDefaultResponderGroup(tx, ws); err != nil {
			return err
		}
		var ids []uuid.UUID
		if err := tx.Raw(`SELECT id FROM responder_group WHERE workspace_id = ? ORDER BY is_default DESC, name, id`, ws).Scan(&ids).Error; err != nil {
			return err
		}
		for _, id := range ids {
			g, err := loadGroup(tx, ws, id, false)
			if err != nil {
				return err
			}
			out = append(out, *g)
		}
		return nil
	})
	return out, err
}

// Get is one group (404 for another workspace's).
func (s *ResponderGroupService) Get(ctx context.Context, ws, id uuid.UUID) (*ResponderGroup, error) {
	var out *ResponderGroup
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		out, err = loadGroup(tx, ws, id, false)
		return err
	})
	return out, err
}

func checkGroupName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 200 || strings.ContainsRune(name, 0) {
		return "", GovBadParam("name", "name is required (at most 200 characters).")
	}
	return name, nil
}

// Create creates a group.
func (s *ResponderGroupService) Create(ctx context.Context, ws, actor uuid.UUID, name, description string) (*ResponderGroup, error) {
	name, err := checkGroupName(name)
	if err != nil {
		return nil, err
	}
	if utf8.RuneCountInString(description) > 2000 {
		return nil, GovBadParam("description", "description must be at most 2000 characters.")
	}
	var out *ResponderGroup
	err = s.inWS(ctx, ws, func(tx *gorm.DB) error {
		var ids []uuid.UUID
		if err := tx.Raw(`INSERT INTO responder_group (workspace_id, name, description, created_by) VALUES (?, ?, ?, ?)
		        ON CONFLICT (workspace_id, name) DO NOTHING RETURNING id`, ws, name, strings.TrimSpace(description), actor).Scan(&ids).Error; err != nil {
			return err
		}
		if len(ids) == 0 {
			return govConflict("group_name_taken", "A responder group of that name exists.", nil)
		}
		if err := appendGovEvent(tx, ws, GovEventResponderGroupCreated, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"group_id": ids[0], "name": name}); err != nil {
			return err
		}
		out, err = loadGroup(tx, ws, ids[0], false)
		return err
	})
	return out, err
}

// Update renames or re-describes a group.
func (s *ResponderGroupService) Update(ctx context.Context, ws, id, actor uuid.UUID, name, description *string) (*ResponderGroup, error) {
	var out *ResponderGroup
	err := s.inWS(ctx, ws, func(tx *gorm.DB) error {
		g, err := loadGroup(tx, ws, id, true)
		if err != nil {
			return err
		}
		newName, newDesc := g.Name, g.Description
		if name != nil {
			if newName, err = checkGroupName(*name); err != nil {
				return err
			}
		}
		if description != nil {
			if utf8.RuneCountInString(*description) > 2000 {
				return GovBadParam("description", "description must be at most 2000 characters.")
			}
			newDesc = strings.TrimSpace(*description)
		}
		if err := tx.Exec(`UPDATE responder_group SET name = ?, description = ?, updated_at = now() WHERE workspace_id = ? AND id = ?`,
			newName, newDesc, ws, id).Error; err != nil {
			if sqlState(err) == "23505" {
				return govConflict("group_name_taken", "A responder group of that name exists.", nil)
			}
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventResponderGroupUpdated, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"group_id": id, "name": newName}); err != nil {
			return err
		}
		out, err = loadGroup(tx, ws, id, false)
		return err
	})
	return out, err
}

// Delete deletes a group; the default group cannot be deleted, nor a group
// holding scopes (hand them over first).
func (s *ResponderGroupService) Delete(ctx context.Context, ws, id, actor uuid.UUID) error {
	return s.inWS(ctx, ws, func(tx *gorm.DB) error {
		g, err := loadGroup(tx, ws, id, true)
		if err != nil {
			return err
		}
		if g.IsDefault {
			return govConflict("default_group", "The workspace's default responder group cannot be deleted.", nil)
		}
		if len(g.Scopes) > 0 {
			return govConflict("group_has_scopes", "The group still decides for scopes; hand them over first.",
				map[string]any{"scopes": len(g.Scopes)})
		}
		if err := tx.Exec(`DELETE FROM responder_group WHERE workspace_id = ? AND id = ?`, ws, id).Error; err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventResponderGroupDeleted, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"group_id": id, "name": g.Name})
	})
}

// isWorkspaceMember reports whether user holds an active membership of ws.
func isWorkspaceMember(tx *gorm.DB, ws, user uuid.UUID) (bool, error) {
	var n int64
	err := tx.Raw(`SELECT count(*) FROM workspace_memberships WHERE workspace_id = ? AND user_id = ? AND status = 'active'`,
		ws, user).Scan(&n).Error
	return n > 0, err
}

// AddMember assigns a workspace member as a candidate.
func (s *ResponderGroupService) AddMember(ctx context.Context, ws, id, actor, user uuid.UUID, role string) (*ResponderGroup, error) {
	if role == "" {
		role = "member"
	}
	if role != "member" && role != "lead" {
		return nil, GovBadParam("role", "role must be member or lead.")
	}
	var out *ResponderGroup
	err := s.inWS(ctx, ws, func(tx *gorm.DB) error {
		if _, err := loadGroup(tx, ws, id, true); err != nil {
			return err
		}
		ok, err := isWorkspaceMember(tx, ws, user)
		if err != nil {
			return err
		}
		if !ok {
			return GovBadParam("user_id", "user_id names no active member of this workspace.")
		}
		var ids []uuid.UUID
		if err := tx.Raw(`INSERT INTO responder_group_member (workspace_id, group_id, user_id, role, assigned_by)
		        VALUES (?, ?, ?, ?, ?) ON CONFLICT (workspace_id, group_id, user_id) DO NOTHING RETURNING id`,
			ws, id, user, role, actor).Scan(&ids).Error; err != nil {
			return err
		}
		if len(ids) == 0 {
			return govConflict("already_member", "The person is already in the group.", nil)
		}
		if err := appendGovEvent(tx, ws, GovEventResponderMemberAssigned, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"group_id": id, "user_id": user, "role": role}); err != nil {
			return err
		}
		out, err = loadGroup(tx, ws, id, false)
		return err
	})
	return out, err
}

// RemoveMember removes a person from a group.
func (s *ResponderGroupService) RemoveMember(ctx context.Context, ws, id, actor, user uuid.UUID) error {
	return s.inWS(ctx, ws, func(tx *gorm.DB) error {
		if _, err := loadGroup(tx, ws, id, true); err != nil {
			return err
		}
		res := tx.Exec(`DELETE FROM responder_group_member WHERE workspace_id = ? AND group_id = ? AND user_id = ?`, ws, id, user)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return GovNotFound()
		}
		return appendGovEvent(tx, ws, GovEventResponderMemberRemoved, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"group_id": id, "user_id": user})
	})
}

// Accept is the actor accepting their own candidate membership.
func (s *ResponderGroupService) Accept(ctx context.Context, ws, id, actor uuid.UUID) (*ResponderGroup, error) {
	var out *ResponderGroup
	err := s.inWS(ctx, ws, func(tx *gorm.DB) error {
		if _, err := loadGroup(tx, ws, id, true); err != nil {
			return err
		}
		var states []string
		if err := tx.Raw(`SELECT state FROM responder_group_member WHERE workspace_id = ? AND group_id = ? AND user_id = ?`,
			ws, id, actor).Scan(&states).Error; err != nil {
			return err
		}
		if len(states) == 0 {
			return GovForbidden("Only a person assigned to the group can accept it.")
		}
		if states[0] == "accepted" {
			return govConflict("already_accepted", "You have already accepted this group.", nil)
		}
		if err := tx.Exec(`UPDATE responder_group_member SET state = 'accepted', accepted_at = now()
		        WHERE workspace_id = ? AND group_id = ? AND user_id = ?`, ws, id, actor).Error; err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventResponderMemberAccepted, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"group_id": id, "user_id": actor}); err != nil {
			return err
		}
		var err error
		out, err = loadGroup(tx, ws, id, false)
		return err
	})
	return out, err
}

// MaxDelegation bounds a delegation's length.
const MaxDelegation = 366 * 24 * time.Hour

// Delegate hands the actor's accepted membership to another workspace member
// until an end date (nil `to` ends the delegation).
func (s *ResponderGroupService) Delegate(ctx context.Context, ws, id, actor uuid.UUID, to *uuid.UUID, until *time.Time) (*ResponderGroup, error) {
	now := time.Now()
	if to != nil {
		if until == nil || !until.After(now) || until.Sub(now) > MaxDelegation {
			return nil, GovBadParam("until", "until is required: a future time at most a year away.")
		}
		if *to == actor {
			return nil, GovBadParam("delegate_to", "A member cannot delegate to themselves.")
		}
	}
	var out *ResponderGroup
	err := s.inWS(ctx, ws, func(tx *gorm.DB) error {
		if _, err := loadGroup(tx, ws, id, true); err != nil {
			return err
		}
		var states []string
		if err := tx.Raw(`SELECT state FROM responder_group_member WHERE workspace_id = ? AND group_id = ? AND user_id = ?`,
			ws, id, actor).Scan(&states).Error; err != nil {
			return err
		}
		if len(states) == 0 || states[0] != "accepted" {
			return GovForbidden("Only an accepted member of the group can delegate.")
		}
		var untilArg any
		if to != nil {
			ok, err := isWorkspaceMember(tx, ws, *to)
			if err != nil {
				return err
			}
			if !ok {
				return GovBadParam("delegate_to", "delegate_to names no active member of this workspace.")
			}
			untilArg = *until
		}
		if err := tx.Exec(`UPDATE responder_group_member SET delegated_to = ?, delegated_until = ?
		        WHERE workspace_id = ? AND group_id = ? AND user_id = ?`, to, untilArg, ws, id, actor).Error; err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventResponderDelegated, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"group_id": id, "user_id": actor, "delegated_to": to, "until": until}); err != nil {
			return err
		}
		var err error
		out, err = loadGroup(tx, ws, id, false)
		return err
	})
	return out, err
}

// AddScope gives the group an estate scope (409 when another group holds it).
func (s *ResponderGroupService) AddScope(ctx context.Context, ws, id, actor uuid.UUID, kind, ref string) (*ResponderGroup, error) {
	ref = strings.TrimSpace(ref)
	if !validScopeKinds[kind] {
		return nil, GovBadParam("scope_kind", "scope_kind must be one of account, subscription, cluster, agent, estate_scope.")
	}
	if ref == "" || len(ref) > 512 {
		return nil, GovBadParam("scope_ref", "scope_ref is required (at most 512 characters).")
	}
	var out *ResponderGroup
	err := s.inWS(ctx, ws, func(tx *gorm.DB) error {
		if _, err := loadGroup(tx, ws, id, true); err != nil {
			return err
		}
		if kind == "agent" {
			aid, err := uuid.Parse(ref)
			if err != nil {
				return GovBadParam("scope_ref", "an agent scope names an agent id.")
			}
			if _, err := loadAgent(tx, ws, aid, false); err != nil {
				return GovBadParam("scope_ref", "scope_ref names no agent of this workspace.")
			}
			ref = aid.String()
		}
		var ids []uuid.UUID
		if err := tx.Raw(`INSERT INTO responder_group_scope (workspace_id, group_id, scope_kind, scope_ref, created_by)
		        VALUES (?, ?, ?, ?, ?) ON CONFLICT (workspace_id, scope_kind, scope_ref) DO NOTHING RETURNING id`,
			ws, id, kind, ref, actor).Scan(&ids).Error; err != nil {
			return err
		}
		if len(ids) == 0 {
			return govConflict("scope_taken", "Another responder group decides for this scope; hand it over instead.", nil)
		}
		if err := appendGovEvent(tx, ws, GovEventResponderScopeAdded, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"group_id": id, "scope_kind": kind, "scope_ref": ref}); err != nil {
			return err
		}
		var err error
		out, err = loadGroup(tx, ws, id, false)
		return err
	})
	return out, err
}

// RemoveScope takes a scope from the group.
func (s *ResponderGroupService) RemoveScope(ctx context.Context, ws, id, actor, scopeID uuid.UUID) error {
	return s.inWS(ctx, ws, func(tx *gorm.DB) error {
		if _, err := loadGroup(tx, ws, id, true); err != nil {
			return err
		}
		var rows []ResponderGroupScope
		if err := tx.Raw(`DELETE FROM responder_group_scope WHERE workspace_id = ? AND group_id = ? AND id = ?
		        RETURNING id, group_id, scope_kind, scope_ref, created_at`, ws, id, scopeID).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return GovNotFound()
		}
		return appendGovEvent(tx, ws, GovEventResponderScopeRemoved, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"group_id": id, "scope_kind": rows[0].ScopeKind, "scope_ref": rows[0].ScopeRef})
	})
}

// Handover moves every scope of a group to another group of the workspace.
func (s *ResponderGroupService) Handover(ctx context.Context, ws, id, actor, to uuid.UUID) (*ResponderGroup, error) {
	if to == id {
		return nil, GovBadParam("to_group_id", "A group cannot hand over to itself.")
	}
	var out *ResponderGroup
	err := s.inWS(ctx, ws, func(tx *gorm.DB) error {
		if _, err := loadGroup(tx, ws, id, true); err != nil {
			return err
		}
		if _, err := loadGroup(tx, ws, to, true); err != nil {
			var ge *GovError
			if errors.As(err, &ge) && ge.Status == 404 {
				return GovBadParam("to_group_id", "to_group_id names no responder group of this workspace.")
			}
			return err
		}
		res := tx.Exec(`UPDATE responder_group_scope SET group_id = ? WHERE workspace_id = ? AND group_id = ?`, to, ws, id)
		if res.Error != nil {
			return res.Error
		}
		if err := appendGovEvent(tx, ws, GovEventResponderHandover, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"group_id": id, "to_group_id": to, "scopes": res.RowsAffected}); err != nil {
			return err
		}
		var err error
		out, err = loadGroup(tx, ws, to, false)
		return err
	})
	return out, err
}
