package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/authsec-ai/authsec/internal/directory/adldap"
	"github.com/authsec-ai/authsec/internal/directory/adposture"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// PostureView is one account's D03 evidence. Privileged and AdminCountOrphan
// are JSON null when the read cannot support a negative. No field is a secret.
type PostureView struct {
	ID                      uuid.UUID `json:"id"`
	RunID                   uuid.UUID `json:"run_id"`
	ObjectGUID              string    `json:"object_guid"`
	ObjectSID               string    `json:"object_sid"`
	AccountKind             string    `json:"account_kind"`
	DistinguishedName       string    `json:"distinguished_name"`
	SAMAccountName          string    `json:"sam_account_name"`
	Coverage                string    `json:"coverage"`
	PartialReasons          []string  `json:"partial_reasons"`
	UnconstrainedDelegation bool      `json:"unconstrained_delegation"`
	ConstrainedDelegation   bool      `json:"constrained_delegation"`
	ProtocolTransition      bool      `json:"protocol_transition"`
	DelegationTargets       []string  `json:"delegation_targets"`
	RBCDPrincipals          []string  `json:"rbcd_principals"`
	RBCDAsserted            bool      `json:"rbcd_asserted"`
	Privileged              *bool     `json:"privileged"`
	PrivilegedDirect        bool      `json:"privileged_direct"`
	PrivilegedNested        bool      `json:"privileged_nested"`
	PrivilegedPath          []string  `json:"privileged_path"`
	AdminCount              bool      `json:"admin_count"`
	AdminCountOrphan        *bool     `json:"admin_count_orphan"`
	SensitiveNotDelegated   bool      `json:"sensitive_not_delegated"`
	GMSA                    bool      `json:"gmsa"`
	SMSA                    bool      `json:"smsa"`
	DepthExceeded           bool      `json:"depth_exceeded"`
	AccountDisabled         bool      `json:"account_disabled"`
}

// PosturePage is one page of posture rows for a run in the caller's workspace.
type PosturePage struct {
	Posture    []PostureView `json:"posture"`
	Limit      int           `json:"limit"`
	Offset     int           `json:"offset"`
	NextOffset *int          `json:"next_offset,omitempty"`
}

// savePosture replaces the run's posture rows from the objects that read
// actually returned. scopeComplete is true only when every class read finished.
// A failure rolls the posture rows back; the caller marks the run failed.
func (s *ADInventoryService) savePosture(db *gorm.DB, workspaceID, runID uuid.UUID, domainSID string, objects []adldap.Object, scopeComplete bool, now time.Time) error {
	results := adposture.Evaluate(domainSID, objects, scopeComplete)
	sort.Slice(results, func(i, j int) bool { return results[i].ObjectGUID < results[j].ObjectGUID })
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("workspace_id = ? AND run_id = ?", workspaceID, runID).
			Delete(&models.ADDirectoryPosture{}).Error; err != nil {
			return err
		}
		for _, r := range results {
			row := models.ADDirectoryPosture{
				ID:                      uuid.New(),
				WorkspaceID:             workspaceID,
				RunID:                   runID,
				CreatedAt:               now,
				ObjectGUID:              r.ObjectGUID,
				ObjectSID:               r.ObjectSID,
				AccountKind:             r.AccountKind,
				DistinguishedName:       r.DistinguishedName,
				SAMAccountName:          r.SAMAccountName,
				Coverage:                r.Coverage,
				PartialReasons:          jsonList(r.PartialReasons),
				UnconstrainedDelegation: r.UnconstrainedDelegation,
				ConstrainedDelegation:   r.ConstrainedDelegation,
				ProtocolTransition:      r.ProtocolTransition,
				DelegationTargets:       jsonList(r.DelegationTargets),
				RBCDPrincipals:          jsonList(r.RBCDPrincipals),
				RBCDAsserted:            r.RBCDAsserted,
				Privileged:              r.Privileged,
				PrivilegedDirect:        r.PrivilegedDirect,
				PrivilegedNested:        r.PrivilegedNested,
				PrivilegedPath:          jsonList(r.PrivilegedPath),
				AdminCount:              r.AdminCount,
				AdminCountOrphan:        r.AdminCountOrphan,
				SensitiveNotDelegated:   r.SensitiveNotDelegated,
				GMSA:                    r.GMSA,
				SMSA:                    r.SMSA,
				DepthExceeded:           r.DepthExceeded,
				AccountDisabled:         r.AccountDisabled,
			}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// ListPosture returns a page of posture for one run in this workspace.
// objectGUID limits the page to that object. A run that belongs to another
// workspace is not found.
func (s *ADInventoryService) ListPosture(ctx context.Context, workspaceID, runID uuid.UUID, objectGUID string, limit, offset int) (PosturePage, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	db := s.db().WithContext(ctx)
	var run models.ADInventoryRun
	err := db.Where("id = ? AND workspace_id = ?", runID, workspaceID).First(&run).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return PosturePage{}, fmt.Errorf("not found")
	}
	if err != nil {
		return PosturePage{}, err
	}
	q := db.Where("workspace_id = ? AND run_id = ?", workspaceID, run.ID)
	if objectGUID != "" {
		q = q.Where("object_guid = ?", objectGUID)
	}
	var rows []models.ADDirectoryPosture
	if err := q.Order("object_guid").Limit(limit + 1).Offset(offset).Find(&rows).Error; err != nil {
		return PosturePage{}, err
	}
	next := false
	if len(rows) > limit {
		next = true
		rows = rows[:limit]
	}
	out := make([]PostureView, 0, len(rows))
	for _, row := range rows {
		out = append(out, postureView(row))
	}
	page := PosturePage{Posture: out, Limit: limit, Offset: offset}
	if next {
		n := offset + limit
		page.NextOffset = &n
	}
	return page, nil
}

func postureView(row models.ADDirectoryPosture) PostureView {
	return PostureView{
		ID:                      row.ID,
		RunID:                   row.RunID,
		ObjectGUID:              row.ObjectGUID,
		ObjectSID:               row.ObjectSID,
		AccountKind:             row.AccountKind,
		DistinguishedName:       row.DistinguishedName,
		SAMAccountName:          row.SAMAccountName,
		Coverage:                row.Coverage,
		PartialReasons:          jsonStrings(row.PartialReasons),
		UnconstrainedDelegation: row.UnconstrainedDelegation,
		ConstrainedDelegation:   row.ConstrainedDelegation,
		ProtocolTransition:      row.ProtocolTransition,
		DelegationTargets:       jsonStrings(row.DelegationTargets),
		RBCDPrincipals:          jsonStrings(row.RBCDPrincipals),
		RBCDAsserted:            row.RBCDAsserted,
		Privileged:              row.Privileged,
		PrivilegedDirect:        row.PrivilegedDirect,
		PrivilegedNested:        row.PrivilegedNested,
		PrivilegedPath:          jsonStrings(row.PrivilegedPath),
		AdminCount:              row.AdminCount,
		AdminCountOrphan:        row.AdminCountOrphan,
		SensitiveNotDelegated:   row.SensitiveNotDelegated,
		GMSA:                    row.GMSA,
		SMSA:                    row.SMSA,
		DepthExceeded:           row.DepthExceeded,
		AccountDisabled:         row.AccountDisabled,
	}
}

func jsonList(v []string) datatypes.JSON {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return datatypes.JSON("[]")
	}
	return datatypes.JSON(b)
}

func jsonStrings(raw datatypes.JSON) []string {
	if len(raw) == 0 {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return []string{}
	}
	return out
}
