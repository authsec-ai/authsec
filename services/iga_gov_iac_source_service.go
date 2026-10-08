package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/iacpr"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// IaC sources (SPEC-iga-phase3-policy.md §1.1 J2, §7.9, §8.11; T3.17): an
// AWS account's mapping to a GitHub repository directory holding the
// Terraform or CloudFormation that defines its roles, with role_match rules.
//
//	GET    /authsec/discovery/aws/connectors/:id/iac-sources        governance:enforce
//	POST   /authsec/discovery/aws/connectors/:id/iac-sources        governance:enforce
//	DELETE /authsec/discovery/aws/connectors/:id/iac-sources/:sid   governance:enforce
//
// The repository channel is an existing GitHub discovery source of the same
// workspace (053's composite FK enforces it), so the GitHub App installation
// the discovery source already uses is the one that opens PRs.
//
// GitHub permission request flow (§1.1 J2: "GitHub App with contents/
// pull-request write on the mapped repository"; the App needs them "only when
// a customer maps an IaC source"): mapping a source merges
// {contents: write, pull_requests: write} into the installation's
// iga_integrations.requested_permissions (version bumped, event
// iac_source.permissions_requested) and answers what is still missing from
// granted_permissions with the remedy -- the installation's owner accepts the
// App's updated permissions on GitHub; the integration's verification
// refreshes granted_permissions. Until both are granted, PR delivery refuses
// with 409 iac_permission_missing (the deployment stays queued and is
// retried); compile-time form decisions only read contents, which discovery
// already has.

// GovIaC error codes.
const (
	GovCodeIaCSourceMissing     = "iac_source_missing"
	GovCodeIaCPermissionMissing = "iac_permission_missing"
	GovCodeIaCSourceInUse       = "iac_source_in_use"
	GovCodeIaCUnavailable       = "iac_unavailable"
)

// GovIaC event names.
const (
	GovEventIaCSourceCreated     = "iac_source.created"
	GovEventIaCSourceDeleted     = "iac_source.deleted"
	GovEventIaCPermissionRequest = "iac_source.permissions_requested"
)

// GovIaCSourceService maps IaC sources.
type GovIaCSourceService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewGovIaCSourceService builds the service.
func NewGovIaCSourceService(db *gorm.DB) *GovIaCSourceService {
	return &GovIaCSourceService{db: db, now: time.Now}
}

// GovIaCSourceInput is POST .../iac-sources.
type GovIaCSourceInput struct {
	Format            string          `json:"format"`
	DiscoverySourceID string          `json:"discovery_source_id"`
	Repository        string          `json:"repository"`
	BaseBranch        string          `json:"base_branch"`
	Directory         string          `json:"directory"`
	RoleMatch         json.RawMessage `json:"role_match"`
}

// GovIaCPermissions is the GitHub permission state of an IaC source's
// installation.
type GovIaCPermissions struct {
	Required  map[string]string `json:"required"`
	Missing   []string          `json:"missing"`
	Requested bool              `json:"requested"`
	State     string            `json:"state"` // granted | pending_grant | integration_missing
	Remedy    string            `json:"remedy,omitempty"`
	URL       string            `json:"url,omitempty"`
}

// GovIaCSourceView is one IaC source with its permission state.
type GovIaCSourceView struct {
	models.IGAGovIaCSource
	Permissions GovIaCPermissions `json:"permissions"`
}

var (
	reIaCRepo   = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	reIaCBranch = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
)

func (s *GovIaCSourceService) connector(db *gorm.DB, ws, connectorID uuid.UUID) error {
	if _, err := LoadIaCConnectorFacts(db, ws, connectorID); err != nil {
		if errors.Is(err, repositories.ErrCloudConnectorNotFound) {
			return GovNotFound()
		}
		return err
	}
	return nil
}

// cleanDirectory validates a repository-relative directory.
func cleanDirectory(d string) (string, bool) {
	d = strings.Trim(strings.TrimSpace(d), "/")
	if len(d) > 500 || strings.Contains(d, "\\") {
		return "", false
	}
	for _, p := range strings.Split(d, "/") {
		if p == ".." || p == "." || (d != "" && p == "") {
			return "", false
		}
	}
	return d, true
}

// List is GET .../iac-sources.
func (s *GovIaCSourceService) List(ctx context.Context, ws, connectorID uuid.UUID) ([]GovIaCSourceView, error) {
	db := s.db.WithContext(ctx)
	if err := s.connector(db, ws, connectorID); err != nil {
		return nil, err
	}
	var rows []models.IGAGovIaCSource
	if err := db.Where("workspace_id = ? AND connector_id = ?", ws, connectorID).Order("created_at, id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]GovIaCSourceView, 0, len(rows))
	for _, r := range rows {
		perm, err := s.permissions(db, ws, r.DiscoverySourceID)
		if err != nil {
			return nil, err
		}
		out = append(out, GovIaCSourceView{IGAGovIaCSource: r, Permissions: perm})
	}
	return out, nil
}

// permissions reads the installation's requested and granted permissions.
func (s *GovIaCSourceService) permissions(db *gorm.DB, ws, discoverySource uuid.UUID) (GovIaCPermissions, error) {
	out := GovIaCPermissions{Required: iacpr.RequiredPermissions, Missing: []string{}}
	ch, err := LoadIaCGitHubChannel(db, ws, discoverySource)
	if err != nil {
		if errors.Is(err, ErrIaCSourceChannelNotFound) {
			out.State = "integration_missing"
			return out, nil
		}
		return out, err
	}
	in, err := loadIaCIntegration(db, ws, ch.IntegrationID)
	if err != nil {
		return out, err
	}
	if in == nil {
		out.State = "integration_missing"
		out.Remedy = "Connect the GitHub App for this discovery source first."
		return out, nil
	}
	req, granted := permMap(in.RequestedPermissions), permMap(in.GrantedPermissions)
	out.Requested = len(iacpr.MissingPermissions(req)) == 0
	out.Missing = iacpr.MissingPermissions(granted)
	if out.Missing == nil {
		out.Missing = []string{}
	}
	if len(out.Missing) == 0 {
		out.State = "granted"
		return out, nil
	}
	out.State = "pending_grant"
	out.Remedy = "Accept the AuthSec GitHub App's updated permissions (" + strings.Join(out.Missing, ", ") +
		") for this installation on GitHub; AuthSec opens pull requests only after they are granted."
	if in.InstallationID != nil && *in.InstallationID != "" {
		host := in.ProviderHost
		if host == "" {
			host = "github.com"
		}
		out.URL = "https://" + host + "/settings/installations/" + *in.InstallationID
	}
	return out, nil
}

func permMap(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil {
		for k, v := range m {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
	}
	return out
}

func loadIaCIntegration(db *gorm.DB, ws uuid.UUID, integrationID string) (*models.IGAIntegration, error) {
	id, err := uuid.Parse(integrationID)
	if err != nil {
		return nil, nil
	}
	var rows []models.IGAIntegration
	if err := db.Where("workspace_id = ? AND id = ?", ws, id).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, nil
	}
	return &rows[0], nil
}

// Create is POST .../iac-sources.
func (s *GovIaCSourceService) Create(ctx context.Context, ws, connectorID, actor uuid.UUID, in GovIaCSourceInput) (*GovIaCSourceView, error) {
	db := s.db.WithContext(ctx)
	if err := s.connector(db, ws, connectorID); err != nil {
		return nil, err
	}
	if in.Format != iacpr.FormatTerraform && in.Format != iacpr.FormatCloudFormation {
		return nil, GovBadParam("format", "format must be terraform or cloudformation.")
	}
	if !reIaCRepo.MatchString(in.Repository) {
		return nil, GovBadParam("repository", "repository must be owner/name.")
	}
	if in.BaseBranch == "" {
		in.BaseBranch = "main"
	}
	if !reIaCBranch.MatchString(in.BaseBranch) || strings.Contains(in.BaseBranch, "..") {
		return nil, GovBadParam("base_branch", "base_branch is not a valid branch name.")
	}
	dir, ok := cleanDirectory(in.Directory)
	if !ok {
		return nil, GovBadParam("directory", "directory must be a repository-relative path without '..'.")
	}
	rm, err := iacpr.ParseRoleMatch(in.RoleMatch)
	if err != nil {
		return nil, GovBadParam("role_match", err.Error())
	}
	rmRaw, _ := json.Marshal(rm)
	dsID, err := uuid.Parse(in.DiscoverySourceID)
	if err != nil {
		return nil, GovBadParam("discovery_source_id", "Must be a uuid.")
	}
	ch, err := LoadIaCGitHubChannel(db, ws, dsID)
	if err != nil {
		if errors.Is(err, ErrIaCSourceChannelNotFound) {
			return nil, govUnprocessable("discovery_source_invalid", "discovery_source_id must name a GitHub repository discovery source of this workspace.",
				map[string]any{"discovery_source_id": dsID})
		}
		return nil, err
	}
	row := models.IGAGovIaCSource{ID: uuid.New(), WorkspaceID: ws, ConnectorID: connectorID, Format: in.Format,
		DiscoverySourceID: dsID, Repository: in.Repository, BaseBranch: in.BaseBranch, Directory: dir, RoleMatch: rmRaw,
		CreatedBy: actor, CreatedAt: s.now().UTC()}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		requested, err := requestIaCPermissionsTx(tx, ws, ch.IntegrationID, s.now())
		if err != nil {
			return err
		}
		refs := govEventRefs{}
		if err := appendGovEvent(tx, ws, GovEventIaCSourceCreated, models.GovActorUser, actor.String(), refs, map[string]any{
			"source_id": row.ID, "connector_id": connectorID, "format": row.Format, "repository": row.Repository,
			"base_branch": row.BaseBranch, "directory": row.Directory, "discovery_source_id": dsID}); err != nil {
			return err
		}
		if requested {
			return appendGovEvent(tx, ws, GovEventIaCPermissionRequest, models.GovActorUser, actor.String(), refs, map[string]any{
				"source_id": row.ID, "integration_id": ch.IntegrationID, "permissions": iacpr.RequiredPermissions})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	perm, err := s.permissions(db, ws, dsID)
	if err != nil {
		return nil, err
	}
	return &GovIaCSourceView{IGAGovIaCSource: row, Permissions: perm}, nil
}

// requestIaCPermissionsTx merges the J2 permissions into the installation's
// requested set; true when it changed.
func requestIaCPermissionsTx(tx *gorm.DB, ws uuid.UUID, integrationID string, now time.Time) (bool, error) {
	in, err := loadIaCIntegration(tx, ws, integrationID)
	if err != nil || in == nil {
		return false, err
	}
	req := map[string]any{}
	_ = json.Unmarshal(in.RequestedPermissions, &req)
	changed := false
	keys := make([]string, 0, len(iacpr.RequiredPermissions))
	for k := range iacpr.RequiredPermissions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if req[k] != iacpr.RequiredPermissions[k] {
			req[k] = iacpr.RequiredPermissions[k]
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	raw, _ := json.Marshal(req)
	res := tx.Model(&models.IGAIntegration{}).Where("workspace_id = ? AND id = ? AND version = ?", ws, in.ID, in.Version).
		Updates(map[string]any{"requested_permissions": json.RawMessage(raw), "version": in.Version + 1, "updated_at": now.UTC()})
	if res.Error != nil {
		return false, res.Error
	}
	if res.RowsAffected != 1 {
		return false, govConflict("version_conflict", "The GitHub integration changed; retry.", nil)
	}
	return true, nil
}

// Delete is DELETE .../iac-sources/:sid. A source with a PR still being
// tracked cannot be removed (409 iac_source_in_use).
func (s *GovIaCSourceService) Delete(ctx context.Context, ws, connectorID, sourceID, actor uuid.UUID) error {
	db := s.db.WithContext(ctx)
	if err := s.connector(db, ws, connectorID); err != nil {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		var row models.IGAGovIaCSource
		err := tx.Where("workspace_id = ? AND connector_id = ? AND id = ?", ws, connectorID, sourceID).Take(&row).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return GovNotFound()
		}
		if err != nil {
			return err
		}
		var n int64
		if err := tx.Model(&models.IGAGovIaCChange{}).Where("workspace_id = ? AND source_id = ?", ws, sourceID).Count(&n).Error; err != nil {
			return err
		}
		if n > 0 {
			return govErr(http.StatusConflict, GovCodeIaCSourceInUse, "Pull requests were opened from this source; it is kept for their record.",
				map[string]any{"changes": n})
		}
		if err := tx.Delete(&models.IGAGovIaCSource{}, "workspace_id = ? AND id = ?", ws, sourceID).Error; err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventIaCSourceDeleted, models.GovActorUser, actor.String(), govEventRefs{}, map[string]any{
			"source_id": sourceID, "connector_id": connectorID, "repository": row.Repository, "directory": row.Directory})
	})
}
