package services

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// The directory (SPEC-secops-backend-upgrade.md W7, C10; migration 180).
//
// directory_person is who a person is in the customer's directory: manager,
// status (active, leave, left), contractor, leave dates. Two writers:
//
//   - SCIM (controllers/platform/scim_controller.go): core active and
//     userType, the enterprise extension's manager and employeeType, and
//     AuthSec's own extension's leave dates; DELETE is left.
//   - Microsoft Entra, where an Azure connector reads the directory
//     (azure_identity_discovery.go): manager, accountEnabled,
//     employeeLeaveDateTime, employeeType.
//
// A person becoming left raises agent.ask_needed (reason decider_left) for
// every agent whose responder group they are the only accepted member of
// (and an ask, W4), and writes directory.person_left.

// Directory sources.
const (
	DirectorySourceSCIM  = "scim"
	DirectorySourceEntra = "entra"
	DirectorySourceOkta  = "okta"
)

// Directory statuses.
const (
	DirectoryActive = "active"
	DirectoryLeave  = "leave"
	DirectoryLeft   = "left"
)

// DirectoryPersonInput is one person as a source reports them. Nil pointers
// leave the stored value unchanged on an update (a SCIM PATCH names only what
// changed).
type DirectoryPersonInput struct {
	Source            string
	ExternalID        string
	UserID            *uuid.UUID
	Email             *string
	DisplayName       *string
	ManagerExternalID *string
	Active            *bool
	Contractor        *bool
	EmployeeType      *string
	LeaveFrom         *time.Time
	LeaveTo           *time.Time
	// Deleted: the source removed the person (SCIM DELETE).
	Deleted bool
}

// DirectoryPerson is one directory_person row.
type DirectoryPerson struct {
	ID                uuid.UUID  `json:"id" gorm:"column:id"`
	UserID            *uuid.UUID `json:"user_id" gorm:"column:user_id"`
	Source            string     `json:"source" gorm:"column:source"`
	ExternalID        string     `json:"external_id" gorm:"column:external_id"`
	Email             string     `json:"email" gorm:"column:email"`
	DisplayName       string     `json:"display_name" gorm:"column:display_name"`
	ManagerExternalID string     `json:"manager_external_id" gorm:"column:manager_external_id"`
	ManagerPersonID   *uuid.UUID `json:"manager_person_id" gorm:"column:manager_person_id"`
	Status            string     `json:"status" gorm:"column:status"`
	Contractor        bool       `json:"contractor" gorm:"column:contractor"`
	EmployeeType      string     `json:"employee_type" gorm:"column:employee_type"`
	LeaveFrom         *time.Time `json:"leave_from" gorm:"column:leave_from"`
	LeaveTo           *time.Time `json:"leave_to" gorm:"column:leave_to"`
	LeftAt            *time.Time `json:"left_at" gorm:"column:left_at"`
	SyncedAt          time.Time  `json:"synced_at" gorm:"column:synced_at"`
}

// contractorTypes are employee types that mean a contractor.
var contractorTypes = map[string]bool{"contractor": true, "contingent": true, "contingent worker": true,
	"vendor": true, "consultant": true, "external": true, "temp": true, "temporary": true}

// IsContractorType reports whether an employee/user type names a contractor.
func IsContractorType(t string) bool { return contractorTypes[strings.ToLower(strings.TrimSpace(t))] }

// directoryStatus derives a person's status: removed or inactive outside a
// leave window is left; inside a leave window (inactive or not) is leave.
func directoryStatus(active bool, deleted bool, from, to *time.Time, now time.Time) string {
	if deleted {
		return DirectoryLeft
	}
	onLeave := from != nil && !now.Before(*from) && (to == nil || now.Before(*to))
	switch {
	case onLeave:
		return DirectoryLeave
	case !active:
		return DirectoryLeft
	}
	return DirectoryActive
}

// DirectoryService serves the directory.
type DirectoryService struct{ db *gorm.DB }

// NewDirectoryService builds the service over db.
func NewDirectoryService(db *gorm.DB) *DirectoryService { return &DirectoryService{db: db} }

// Upsert records one person (in its own transaction under ws's row-level
// security) and returns the stored row and how many asks a departure raised.
func (s *DirectoryService) Upsert(ctx context.Context, ws uuid.UUID, in DirectoryPersonInput) (*DirectoryPerson, int, error) {
	var out *DirectoryPerson
	asks := 0
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		out, asks, err = upsertDirectoryPerson(tx, ws, in, time.Now())
		return err
	})
	return out, asks, err
}

func upsertDirectoryPerson(tx *gorm.DB, ws uuid.UUID, in DirectoryPersonInput, now time.Time) (*DirectoryPerson, int, error) {
	switch in.Source {
	case DirectorySourceSCIM, DirectorySourceEntra, DirectorySourceOkta:
	default:
		return nil, 0, fmt.Errorf("directory: unknown source %q", in.Source)
	}
	in.ExternalID = strings.TrimSpace(in.ExternalID)
	if in.ExternalID == "" {
		return nil, 0, fmt.Errorf("directory: external id is required")
	}
	var cur []DirectoryPerson
	if err := tx.Raw(`SELECT * FROM directory_person WHERE workspace_id = ? AND source = ? AND external_id = ? FOR UPDATE`,
		ws, in.Source, in.ExternalID).Scan(&cur).Error; err != nil {
		return nil, 0, err
	}
	p := DirectoryPerson{Source: in.Source, ExternalID: in.ExternalID, Status: DirectoryActive}
	active := true
	if len(cur) > 0 {
		p = cur[0]
		active = p.Status != DirectoryLeft
	}
	prev := p.Status
	if len(cur) == 0 {
		prev = ""
	}
	if in.UserID != nil {
		p.UserID = in.UserID
	}
	if in.Email != nil {
		p.Email = strings.ToLower(strings.TrimSpace(*in.Email))
	}
	if in.DisplayName != nil {
		p.DisplayName = strings.TrimSpace(*in.DisplayName)
	}
	if in.ManagerExternalID != nil {
		p.ManagerExternalID = strings.TrimSpace(*in.ManagerExternalID)
	}
	if in.EmployeeType != nil {
		p.EmployeeType = strings.TrimSpace(*in.EmployeeType)
		if in.Contractor == nil {
			p.Contractor = IsContractorType(p.EmployeeType)
		}
	}
	if in.Contractor != nil {
		p.Contractor = *in.Contractor
	}
	if in.LeaveFrom != nil {
		p.LeaveFrom = in.LeaveFrom
	}
	if in.LeaveTo != nil {
		p.LeaveTo = in.LeaveTo
	}
	if in.Active != nil {
		active = *in.Active
	}
	p.Status = directoryStatus(active, in.Deleted, p.LeaveFrom, p.LeaveTo, now)
	if p.Status == DirectoryLeft {
		if p.LeftAt == nil {
			t := now
			p.LeftAt = &t
		}
	} else {
		p.LeftAt = nil
	}
	// The AuthSec user, when the source did not say: the workspace's user
	// with the same e-mail.
	if p.UserID == nil && p.Email != "" {
		var ids []uuid.UUID
		if err := tx.Raw(`SELECT id FROM users WHERE workspace_id = ? AND LOWER(email) = ? ORDER BY created_at LIMIT 1`,
			ws, p.Email).Scan(&ids).Error; err != nil {
			return nil, 0, err
		}
		if len(ids) > 0 {
			p.UserID = &ids[0]
		}
	}
	// The manager's own row, when the directory has it.
	p.ManagerPersonID = nil
	if p.ManagerExternalID != "" {
		var ids []uuid.UUID
		if err := tx.Raw(`SELECT id FROM directory_person WHERE workspace_id = ? AND source = ? AND external_id = ?`,
			ws, in.Source, p.ManagerExternalID).Scan(&ids).Error; err != nil {
			return nil, 0, err
		}
		if len(ids) > 0 {
			p.ManagerPersonID = &ids[0]
		}
	}
	var rows []DirectoryPerson
	if err := tx.Raw(`INSERT INTO directory_person (workspace_id, user_id, source, external_id, email, display_name,
	          manager_external_id, manager_person_id, status, contractor, employee_type, leave_from, leave_to, left_at, synced_at)
	        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now())
	        ON CONFLICT (workspace_id, source, external_id) DO UPDATE SET user_id = EXCLUDED.user_id, email = EXCLUDED.email,
	          display_name = EXCLUDED.display_name, manager_external_id = EXCLUDED.manager_external_id,
	          manager_person_id = EXCLUDED.manager_person_id, status = EXCLUDED.status, contractor = EXCLUDED.contractor,
	          employee_type = EXCLUDED.employee_type, leave_from = EXCLUDED.leave_from, leave_to = EXCLUDED.leave_to,
	          left_at = EXCLUDED.left_at, synced_at = now(), updated_at = now()
	        RETURNING *`,
		ws, p.UserID, p.Source, p.ExternalID, p.Email, p.DisplayName, p.ManagerExternalID, p.ManagerPersonID, p.Status,
		p.Contractor, p.EmployeeType, p.LeaveFrom, p.LeaveTo, p.LeftAt).Scan(&rows).Error; err != nil {
		return nil, 0, err
	}
	stored := rows[0]
	if stored.Status != DirectoryLeft || prev == DirectoryLeft {
		return &stored, 0, nil
	}
	if err := appendGovEvent(tx, ws, GovEventDirectoryLeft, models.GovActorSystem, "", govEventRefs{},
		map[string]any{"person_id": stored.ID, "user_id": stored.UserID, "source": stored.Source}); err != nil {
		return nil, 0, err
	}
	n, err := raiseLeaverAsks(tx, ws, &stored, now)
	return &stored, n, err
}

// raiseLeaverAsks writes agent.ask_needed for every active agent whose
// responder group (as resolved now) has the leaver as its only accepted
// member, or whose only decider is the leaver through a delegation.
func raiseLeaverAsks(tx *gorm.DB, ws uuid.UUID, p *DirectoryPerson, now time.Time) (int, error) {
	if p.UserID == nil {
		return 0, nil
	}
	user := *p.UserID
	var groups []uuid.UUID
	if err := tx.Raw(`SELECT g.group_id FROM responder_group_member g
	        WHERE g.workspace_id = ? AND g.state = 'accepted' AND (g.user_id = ? OR (g.delegated_to = ? AND g.delegated_until > ?))
	        GROUP BY g.group_id`, ws, user, user, now).Scan(&groups).Error; err != nil {
		return 0, err
	}
	if len(groups) == 0 {
		return 0, nil
	}
	sole := map[uuid.UUID]bool{}
	for _, g := range groups {
		d, err := groupDeciders(tx, ws, g, now)
		if err != nil {
			return 0, err
		}
		only := len(d) > 0
		for _, x := range d {
			if x.UserID != user {
				only = false
			}
		}
		if only {
			sole[g] = true
		}
	}
	if len(sole) == 0 {
		return 0, nil
	}
	var agents []uuid.UUID
	if err := tx.Raw(`SELECT id FROM agent WHERE workspace_id = ? AND state = 'active' ORDER BY id`, ws).Scan(&agents).Error; err != nil {
		return 0, err
	}
	n := 0
	for _, a := range agents {
		res, err := resolveResponder(tx, ws, a, now)
		if err != nil {
			return n, err
		}
		if res.GroupID == nil || !sole[*res.GroupID] {
			continue
		}
		if err := appendGovEvent(tx, ws, GovEventAgentAskNeeded, models.GovActorSystem, "", govEventRefs{},
			map[string]any{"agent_id": a, "reason": AskReasonDeciderLeft,
				"subject": map[string]any{"person_id": p.ID, "user_id": user, "group_id": *res.GroupID}}); err != nil {
			return n, err
		}
		// The leaver never decides the ask about their own departure.
		raiseAgentAskNeeded(tx, ws, a, AskReasonDeciderLeft,
			map[string]any{"person_id": p.ID, "user_id": user, "group_id": *res.GroupID}, user)
		n++
	}
	return n, nil
}

// List lists ws's directory people (status "" = all).
func (s *DirectoryService) List(ctx context.Context, ws uuid.UUID, status string) ([]DirectoryPerson, error) {
	switch status {
	case "", DirectoryActive, DirectoryLeave, DirectoryLeft:
	default:
		return nil, GovBadParam("status", "status must be one of active, leave, left.")
	}
	var out []DirectoryPerson
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := `SELECT * FROM directory_person WHERE workspace_id = ?`
		args := []any{ws}
		if status != "" {
			q += ` AND status = ?`
			args = append(args, status)
		}
		return tx.Raw(q+` ORDER BY email, id LIMIT 1000`, args...).Scan(&out).Error
	})
	if out == nil {
		out = []DirectoryPerson{}
	}
	return out, err
}

/* ------------------------------------------------------------------------- */
/*                                   SCIM                                     */
/* ------------------------------------------------------------------------- */

// DirectoryFromSCIM maps a SCIM user (POST or PUT) to a directory person.
// The external id is the SCIM externalId, else the AuthSec user id.
func DirectoryFromSCIM(in models.SCIMCreateUserInput, userID uuid.UUID) DirectoryPersonInput {
	ext := strings.TrimSpace(in.ExternalID)
	if ext == "" {
		ext = userID.String()
	}
	email := in.GetPrimaryEmail()
	name := in.GetDisplayName()
	active := in.GetActive()
	out := DirectoryPersonInput{Source: DirectorySourceSCIM, ExternalID: ext, UserID: &userID,
		Email: &email, DisplayName: &name, Active: &active}
	etype := in.UserType
	if in.Enterprise != nil {
		mgr := ""
		if in.Enterprise.Manager != nil {
			mgr = in.Enterprise.Manager.Value
		}
		out.ManagerExternalID = &mgr
		if in.Enterprise.EmployeeType != "" {
			etype = in.Enterprise.EmployeeType
		}
	}
	if etype != "" {
		out.EmployeeType = &etype
	}
	if in.AuthSec != nil {
		out.LeaveFrom, out.LeaveTo = in.AuthSec.LeaveFrom, in.AuthSec.LeaveTo
		if in.AuthSec.Contractor != nil {
			out.Contractor = in.AuthSec.Contractor
		}
	}
	return out
}

// DirectoryPatchFromSCIM folds SCIM PATCH operations into a partial
// directory update (nil fields unchanged). ok is false when no operation
// touches a directory attribute.
func DirectoryPatchFromSCIM(ops []models.SCIMPatchOp, externalID string, userID uuid.UUID) (DirectoryPersonInput, bool) {
	ext := strings.TrimSpace(externalID)
	if ext == "" {
		ext = userID.String()
	}
	out := DirectoryPersonInput{Source: DirectorySourceSCIM, ExternalID: ext, UserID: &userID}
	touched := false
	var apply func(path string, v any, remove bool)
	apply = func(path string, v any, remove bool) {
		p := strings.ToLower(strings.TrimSpace(path))
		p = strings.TrimPrefix(p, strings.ToLower(models.SCIMEnterpriseUserSchema)+":")
		switch p {
		case "active":
			b := false
			if !remove {
				switch x := v.(type) {
				case bool:
					b = x
				case string:
					b = strings.EqualFold(x, "true")
				}
			}
			out.Active, touched = &b, true
		case "usertype", "employeetype":
			s, _ := v.(string)
			if remove {
				s = ""
			}
			out.EmployeeType, touched = &s, true
		case "manager", "manager.value":
			s := ""
			if !remove {
				switch x := v.(type) {
				case string:
					s = x
				case map[string]any:
					s, _ = x["value"].(string)
				}
			}
			out.ManagerExternalID, touched = &s, true
		case "displayname":
			if s, ok := v.(string); ok {
				out.DisplayName, touched = &s, true
			}
		case strings.ToLower(models.SCIMEnterpriseUserSchema):
			if m, ok := v.(map[string]any); ok {
				for k, x := range m {
					apply(k, x, remove)
				}
			}
		case "":
			if m, ok := v.(map[string]any); ok {
				for k, x := range m {
					apply(k, x, remove)
				}
			}
		}
	}
	for _, op := range ops {
		switch strings.ToLower(op.Op) {
		case "add", "replace":
			apply(op.Path, op.Value, false)
		case "remove":
			apply(op.Path, nil, true)
		}
	}
	return out, touched
}

/* ------------------------------------------------------------------------- */
/*                                  Entra                                     */
/* ------------------------------------------------------------------------- */

// DirectoryFromEntra maps an Entra user to a directory person.
func DirectoryFromEntra(u azure.DirectoryPerson) DirectoryPersonInput {
	email := u.Mail
	if email == "" {
		email = u.UserPrincipalName
	}
	name := u.DisplayName
	active := u.AccountEnabled == nil || *u.AccountEnabled
	mgr := ""
	if u.Manager != nil {
		mgr = u.Manager.ID
	}
	et := u.EmployeeType
	if et == "" && strings.EqualFold(u.UserType, "guest") {
		et = "guest"
	}
	out := DirectoryPersonInput{Source: DirectorySourceEntra, ExternalID: u.ID, Email: &email, DisplayName: &name,
		Active: &active, ManagerExternalID: &mgr, EmployeeType: &et}
	if u.EmployeeLeaveDateTime != nil {
		// A leave date in the past with the account still enabled is a departure
		// the directory has dated; the status follows the account.
		t := *u.EmployeeLeaveDateTime
		if !t.After(time.Now()) {
			off := false
			out.Active = &off
		}
	}
	return out
}

// SyncEntraDirectory upserts every Entra user of a pass into the directory,
// managers first resolved on a second pass. Errors are per person and logged:
// one unreadable person never stops the rest.
func SyncEntraDirectory(ctx context.Context, db *gorm.DB, ws uuid.UUID, users []azure.DirectoryPerson) (int, error) {
	n := 0
	err := tenancy.InWorkspace(ctx, db, ws, func(tx *gorm.DB) error {
		now := time.Now()
		for pass := 0; pass < 2; pass++ {
			for _, u := range users {
				if u.ID == "" {
					continue
				}
				if _, _, err := upsertDirectoryPerson(tx, ws, DirectoryFromEntra(u), now); err != nil {
					return err
				}
				if pass == 0 {
					n++
				}
			}
		}
		return nil
	})
	return n, err
}

// syncEntraDirectoryBestEffort is the Azure identity pass's hook: it reads the
// directory people (manager, accountEnabled, employeeLeaveDateTime) and
// records them; a failure is logged, never the pass's.
func syncEntraDirectoryBestEffort(ctx context.Context, db *gorm.DB, api *azure.Client, ws uuid.UUID, graphToken string) {
	if db == nil || api == nil {
		return
	}
	people, err := api.ListDirectoryPeople(ctx, graphToken)
	if err != nil {
		log.Printf("[directory] entra directory read for workspace %s: %v", ws, err)
		return
	}
	if _, err := SyncEntraDirectory(ctx, db, ws, people); err != nil {
		log.Printf("[directory] entra directory write for workspace %s: %v", ws, err)
	}
}
