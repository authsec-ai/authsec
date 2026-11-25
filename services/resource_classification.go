package services

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Resource classification (SPEC-secops-backend-upgrade.md W7, C12, P14;
// migration 179).
//
// A person classifies a cloud_resource: sensitivity (low, med, high), crown
// jewel, data category and residency. The customer's value beats AuthSec's:
// the row's sensitivity_source becomes customer_classification, which no scan
// stamps over (the AWS upsert never refreshes sensitivity; the Azure upsert
// refreshes only heuristic and tag-derived values).
//
// Raising is tier 0 and applies at once. Lowering -- a lower sensitivity,
// crown jewel off, or a data category or residency removed or replaced -- is
// tier 3: it waits in agent_pending_change for a second person holding
// governance:approve (DecidePendingChange).
//
// Tags: a scan that already reads a resource's tags (Azure Resource Graph)
// takes authsec:sensitivity, authsec:crown-jewel, authsec:data-category and
// authsec:residency as provider metadata (ClassificationFromTags). AWS
// resources carry no tags in the inventory today, and no Macie or Purview
// client exists: ExternalClassificationSource is the seam they plug into.

var sensitivityRank = map[string]int{models.SensitivityLow: 0, models.SensitivityMedium: 1, models.SensitivityHigh: 2}

// ResourceClassification is a resource's classification (the PUT body after
// merging with the current values, and a pending change's payload).
type ResourceClassification struct {
	Sensitivity  string `json:"sensitivity"`
	CrownJewel   bool   `json:"crown_jewel"`
	DataCategory string `json:"data_category"`
	Residency    string `json:"residency"`
}

// ResourceClassificationRequest is PUT /resources/:id/classification: every
// field optional (nil keeps the current value), reason required.
type ResourceClassificationRequest struct {
	Sensitivity  *string
	CrownJewel   *bool
	DataCategory *string
	Residency    *string
	Reason       string
}

// ResourceClassificationView is a resource's classification as stored.
type ResourceClassificationView struct {
	ID                uuid.UUID  `json:"id" gorm:"column:id"`
	Kind              string     `json:"kind" gorm:"column:kind"`
	NativeID          string     `json:"native_id" gorm:"column:native_id"`
	Name              string     `json:"name" gorm:"column:name"`
	Sensitivity       string     `json:"sensitivity" gorm:"column:sensitivity"`
	SensitivitySource string     `json:"sensitivity_source" gorm:"column:sensitivity_source"`
	SensitivityReason string     `json:"sensitivity_reason" gorm:"column:sensitivity_reason"`
	CrownJewel        bool       `json:"crown_jewel" gorm:"column:crown_jewel"`
	DataCategory      string     `json:"data_category" gorm:"column:data_category"`
	Residency         string     `json:"residency" gorm:"column:residency"`
	ClassifiedBy      *uuid.UUID `json:"classified_by" gorm:"column:classified_by"`
	ClassifiedAt      *time.Time `json:"classified_at" gorm:"column:classified_at"`
}

// ResourceClassificationResult is either the applied classification or the
// pending change a lowering waits in.
type ResourceClassificationResult struct {
	Applied       *ResourceClassificationView `json:"applied,omitempty"`
	PendingChange *AgentPendingChange         `json:"pending_change,omitempty"`
}

// ResourceClassificationService serves PUT/GET /resources/:id/classification.
type ResourceClassificationService struct{ db *gorm.DB }

// NewResourceClassificationService builds the service over db.
func NewResourceClassificationService(db *gorm.DB) *ResourceClassificationService {
	return &ResourceClassificationService{db: db}
}

func loadResourceClassification(tx *gorm.DB, ws, id uuid.UUID, lock bool) (*ResourceClassificationView, error) {
	q := `SELECT id, kind, native_id, name, sensitivity, sensitivity_source, sensitivity_reason, crown_jewel, data_category,
	             residency, classified_by, classified_at FROM cloud_resource WHERE workspace_id = ? AND id = ?`
	if lock {
		q += ` FOR UPDATE`
	}
	var rows []ResourceClassificationView
	if err := tx.Raw(q, ws, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

// Get returns a resource's classification (404 for another workspace's).
func (s *ResourceClassificationService) Get(ctx context.Context, ws, id uuid.UUID) (*ResourceClassificationView, error) {
	var out *ResourceClassificationView
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		out, err = loadResourceClassification(tx, ws, id, false)
		return err
	})
	return out, err
}

func normLabel(field, v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if utf8.RuneCountInString(v) > 64 || strings.ContainsRune(v, 0) {
		return "", GovBadParam(field, field+" must be at most 64 characters.")
	}
	return v, nil
}

// IsClassificationLowering reports whether next loosens cur (tier 3).
func IsClassificationLowering(cur, next ResourceClassification) bool {
	switch {
	case sensitivityRank[next.Sensitivity] < sensitivityRank[cur.Sensitivity]:
		return true
	case cur.CrownJewel && !next.CrownJewel:
		return true
	case cur.DataCategory != "" && next.DataCategory != cur.DataCategory:
		return true
	case cur.Residency != "" && next.Residency != cur.Residency:
		return true
	}
	return false
}

// Set classifies a resource: raising applies (tier 0), lowering waits for a
// second person (tier 3).
func (s *ResourceClassificationService) Set(ctx context.Context, ws, id, actor uuid.UUID, req ResourceClassificationRequest) (*ResourceClassificationResult, error) {
	reason, err := checkReason("reason", req.Reason, maxAgentReason)
	if err != nil {
		return nil, err
	}
	if req.Sensitivity == nil && req.CrownJewel == nil && req.DataCategory == nil && req.Residency == nil {
		return nil, GovBadParam("body", "name at least one of sensitivity, crown_jewel, data_category, residency.")
	}
	var out ResourceClassificationResult
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		cur, err := loadResourceClassification(tx, ws, id, true)
		if err != nil {
			return err
		}
		c := ResourceClassification{Sensitivity: cur.Sensitivity, CrownJewel: cur.CrownJewel, DataCategory: cur.DataCategory, Residency: cur.Residency}
		next := c
		if req.Sensitivity != nil {
			v := strings.ToLower(strings.TrimSpace(*req.Sensitivity))
			if v == "medium" {
				v = models.SensitivityMedium
			}
			if _, ok := sensitivityRank[v]; !ok {
				return GovBadParam("sensitivity", "sensitivity must be one of low, med, high.")
			}
			next.Sensitivity = v
		}
		if req.CrownJewel != nil {
			next.CrownJewel = *req.CrownJewel
		}
		if req.DataCategory != nil {
			if next.DataCategory, err = normLabel("data_category", *req.DataCategory); err != nil {
				return err
			}
		}
		if req.Residency != nil {
			if next.Residency, err = normLabel("residency", *req.Residency); err != nil {
				return err
			}
		}
		if IsClassificationLowering(c, next) {
			pc, err := createPendingChange(tx, ws, PendingClassificationLower, id, actor, reason, map[string]any{
				"sensitivity": next.Sensitivity, "crown_jewel": next.CrownJewel,
				"data_category": next.DataCategory, "residency": next.Residency,
				"previous": c,
			})
			if err != nil {
				return err
			}
			out.PendingChange = pc
			return nil
		}
		if err := writeResourceClassification(tx, ws, id, next, actor, uuid.Nil, reason); err != nil {
			return err
		}
		out.Applied, err = loadResourceClassification(tx, ws, id, false)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// writeResourceClassification stores a customer classification and its event.
// approver is uuid.Nil for a tier-0 raise.
func writeResourceClassification(tx *gorm.DB, ws, id uuid.UUID, c ResourceClassification, by, approver uuid.UUID, reason string) error {
	if _, err := loadResourceClassification(tx, ws, id, true); err != nil {
		return err
	}
	text := "Classified by a workspace member: " + reason
	if utf8.RuneCountInString(text) > 1000 {
		text = string([]rune(text)[:1000])
	}
	res := tx.Exec(`UPDATE cloud_resource SET sensitivity = ?, sensitivity_source = ?, sensitivity_reason = ?, crown_jewel = ?,
	        data_category = ?, residency = ?, classified_by = ?, classified_at = now(), row_updated_at = now()
	        WHERE workspace_id = ? AND id = ?`,
		c.Sensitivity, models.SensitivityFromCustomer, text, c.CrownJewel, c.DataCategory, c.Residency, by, ws, id)
	if res.Error != nil {
		return res.Error
	}
	payload := map[string]any{"resource_id": id, "sensitivity": c.Sensitivity, "crown_jewel": c.CrownJewel,
		"data_category": c.DataCategory, "residency": c.Residency, "reason": reason}
	actor := by
	if approver != uuid.Nil {
		payload["approved_by"] = approver
		payload["requested_by"] = by
		actor = approver
	}
	return appendGovEvent(tx, ws, GovEventResourceClassified, models.GovActorUser, actor.String(), govEventRefs{}, payload)
}

/* ------------------------------------------------------------------------- */
/*                         Tags, Macie, Purview                               */
/* ------------------------------------------------------------------------- */

// Classification tag keys read from a resource's own tags.
const (
	TagSensitivity  = "authsec:sensitivity"
	TagCrownJewel   = "authsec:crown-jewel"
	TagDataCategory = "authsec:data-category"
	TagResidency    = "authsec:residency"
)

// TagClassification is what a resource's tags say, and the reason text.
type TagClassification struct {
	ResourceClassification
	HasSensitivity bool
	Reason         string
}

// ClassificationFromTags reads the authsec:* classification tags (keys
// case-insensitive). ok is false when no tag is present or none is valid; an
// unreadable value is ignored rather than guessed at.
func ClassificationFromTags(tags map[string]string) (TagClassification, bool) {
	var out TagClassification
	var used []string
	for k, v := range tags {
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.ToLower(strings.TrimSpace(v))
		switch key {
		case TagSensitivity:
			if val == "medium" {
				val = models.SensitivityMedium
			}
			if _, ok := sensitivityRank[val]; ok {
				out.Sensitivity, out.HasSensitivity = val, true
				used = append(used, key+"="+val)
			}
		case TagCrownJewel:
			if b, err := strconv.ParseBool(val); err == nil {
				out.CrownJewel = b
				used = append(used, key+"="+val)
			} else if val == "yes" {
				out.CrownJewel = true
				used = append(used, key+"="+val)
			}
		case TagDataCategory:
			if val != "" && utf8.RuneCountInString(val) <= 64 {
				out.DataCategory = val
				used = append(used, key+"="+val)
			}
		case TagResidency:
			if val != "" && utf8.RuneCountInString(val) <= 64 {
				out.Residency = val
				used = append(used, key+"="+val)
			}
		}
	}
	if len(used) == 0 {
		return out, false
	}
	// Map order is random; the reason must not change between scans.
	sort.Strings(used)
	out.Reason = "Resource tags: " + strings.Join(used, ", ")
	return out, true
}

// ApplyTagClassification sets a scanned resource row's classification from
// its tags (source provider_metadata). It keeps the heuristic sensitivity
// when the tags name none.
func ApplyTagClassification(r *models.CloudResource, tags map[string]string) {
	tc, ok := ClassificationFromTags(tags)
	if !ok {
		return
	}
	if tc.HasSensitivity {
		r.Sensitivity = tc.Sensitivity
		r.SensitivitySource = models.SensitivityFromProvider
		r.SensitivityReason = tc.Reason
	}
	r.CrownJewel, r.DataCategory, r.Residency = tc.CrownJewel, tc.DataCategory, tc.Residency
}

// ErrClassificationSourceUnavailable: the external classifier has no client
// in this build.
var ErrClassificationSourceUnavailable = errors.New("classification source not available in this build")

// ExternalClassification is what a data classifier (Amazon Macie, Microsoft
// Purview) says about one resource.
type ExternalClassification struct {
	NativeID string
	ResourceClassification
	Reason string
}

// ExternalClassificationSource is a data classifier a scan can read.
type ExternalClassificationSource interface {
	Name() string
	Classifications(ctx context.Context, ws, connectorID uuid.UUID) ([]ExternalClassification, error)
}

// MacieClassificationSource is the Amazon Macie seam.
// TODO(W7 follow-up): read Macie's GetFindings/ListClassificationJobs (S3
// sensitive-data findings) with the connector's role once the collection
// template grants macie2:ListFindings and macie2:GetFindings.
type MacieClassificationSource struct{}

func (MacieClassificationSource) Name() string { return "macie" }
func (MacieClassificationSource) Classifications(context.Context, uuid.UUID, uuid.UUID) ([]ExternalClassification, error) {
	return nil, fmt.Errorf("macie: %w", ErrClassificationSourceUnavailable)
}

// PurviewClassificationSource is the Microsoft Purview seam.
// TODO(W7 follow-up): read Purview Data Map classifications for the
// subscription's storage accounts once the Azure consent includes Purview.
type PurviewClassificationSource struct{}

func (PurviewClassificationSource) Name() string { return "purview" }
func (PurviewClassificationSource) Classifications(context.Context, uuid.UUID, uuid.UUID) ([]ExternalClassification, error) {
	return nil, fmt.Errorf("purview: %w", ErrClassificationSourceUnavailable)
}
