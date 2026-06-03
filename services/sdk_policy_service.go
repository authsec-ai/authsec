package services

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// SDKPolicyService backs the two endpoints the @authsec/sdk runtime calls
// against an MCP-protected Application:
//
//	GET  /authsec/applications/:id/sdk-policy   — read the tool->scope mapping
//	PUT  /authsec/applications/:id/sdk-manifest — publish the SDK's tool list
//
// Both are authenticated with HTTP Basic auth where the credentials are
// (resource_server.id : introspection_secret). NO JWT — the SDK doesn't
// have a user JWT, it has the RS introspection credentials issued at admin
// onboarding time.
type SDKPolicyService struct{}

func NewSDKPolicyService() *SDKPolicyService { return &SDKPolicyService{} }

var (
	ErrSDKBasicAuthMissing = errors.New("missing Basic auth")
	ErrSDKBasicAuthInvalid = errors.New("invalid Basic credentials")
)

// AuthorizeFromBasic parses an Authorization: Basic header, looks up the
// resource_servers row, verifies the password against introspection_secret_hash
// (preferred) or plaintext introspection_secret (legacy), and returns the row
// + the resolved tenant_id.
//
// The Application's id (param :id) must match the row identified by the
// Basic username — otherwise we return ErrSDKBasicAuthInvalid (defence
// against credential reuse across applications).
func (s *SDKPolicyService) AuthorizeFromBasic(authHeader string, applicationID uuid.UUID) (*models.ResourceServer, string, error) {
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return nil, "", ErrSDKBasicAuthMissing
	}
	decoded, err := base64.StdEncoding.DecodeString(authHeader[len(prefix):])
	if err != nil {
		return nil, "", ErrSDKBasicAuthInvalid
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, "", ErrSDKBasicAuthInvalid
	}
	username, password := parts[0], parts[1]

	// Username must be a UUID that names a resource_servers row. Use the
	// master-side resource_server_tenant_index to find which tenant DB has
	// the row, then validate the secret there.
	rsID, err := uuid.Parse(username)
	if err != nil {
		return nil, "", ErrSDKBasicAuthInvalid
	}
	if rsID != applicationID {
		// The credentials are for a different Application. Even if the
		// secret is right, refuse — it's a hint of token reuse.
		return nil, "", ErrSDKBasicAuthInvalid
	}

	var indexRow models.ResourceServerTenantIndex
	if err := config.DB.Where("resource_server_id = ?", rsID).First(&indexRow).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", ErrSDKBasicAuthInvalid
		}
		return nil, "", fmt.Errorf("lookup index: %w", err)
	}
	tenantID := indexRow.TenantID.String()
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, "", fmt.Errorf("get tenant db: %w", err)
	}
	var rs models.ResourceServer
	if err := tenantDB.Where("id = ?", rsID).First(&rs).Error; err != nil {
		return nil, "", ErrSDKBasicAuthInvalid
	}

	// Verify the secret. Prefer the bcrypt hash; fall back to plaintext for
	// pre-rotation rows (which won't have a hash yet).
	if rs.IntrospectionSecretHash != "" {
		if err := bcrypt.CompareHashAndPassword([]byte(rs.IntrospectionSecretHash), []byte(password)); err != nil {
			return nil, "", ErrSDKBasicAuthInvalid
		}
	} else if rs.IntrospectionSecret != "" {
		if rs.IntrospectionSecret != password {
			return nil, "", ErrSDKBasicAuthInvalid
		}
	} else {
		// No secret stored at all — admin must call rotate first.
		return nil, "", ErrSDKBasicAuthInvalid
	}
	return &rs, tenantID, nil
}

// ─────────────────────────────────────────────────────────────────────────
// sdk-policy GET
// ─────────────────────────────────────────────────────────────────────────

// ToolPolicy is one row in the sdk-policy response.
type ToolPolicy struct {
	Name           string   `json:"name"`
	IsPublic       bool     `json:"is_public"`
	RequiredScopes []string `json:"required_scopes"`
}

// SDKPolicyResponse is the JSON shape the SDK's ScopeMatrixClient expects.
// `state` and `policy_complete` follow the dev branch's conventions: when
// `policy_complete=false` the SDK enforces deny-all and clears any cached
// matrix.
type SDKPolicyResponse struct {
	State           string       `json:"state"`
	PolicyComplete  bool         `json:"policy_complete"`
	Reason          string       `json:"reason,omitempty"`
	Generation      int          `json:"generation"`
	ScopesSupported []string     `json:"scopes_supported"`
	ToolPolicy      []ToolPolicy `json:"tool_policy"`
}

// GetSDKPolicy reads the Application's mcp_tools rows and returns the
// scope-mapping payload. `policy_complete` is set to true when:
//   - the RS is in state=ready, AND
//   - there's at least one tool row OR scopes_supported is non-empty
//
// Otherwise the SDK falls back to deny-all per its contract.
func (s *SDKPolicyService) GetSDKPolicy(tenantID string, rs *models.ResourceServer) (*SDKPolicyResponse, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var tools []models.MCPTool
	if err := tenantDB.Where("resource_server_id = ?", rs.ID).
		Order("name ASC").Find(&tools).Error; err != nil {
		return nil, fmt.Errorf("list tools: %w", err)
	}

	policies := make([]ToolPolicy, 0, len(tools))
	for _, t := range tools {
		policies = append(policies, ToolPolicy{
			Name:           t.Name,
			IsPublic:       t.IsPublic,
			RequiredScopes: []string(t.RequiredScopes),
		})
	}

	scopes := []string(rs.ScopesSupported)
	if scopes == nil {
		scopes = []string{}
	}

	// Compute policy_complete + state.
	complete := rs.State == models.RSStateReady && (len(tools) > 0 || len(scopes) > 0)
	reason := ""
	state := rs.State
	if state == "" {
		state = "unknown"
	}
	if !complete {
		switch rs.State {
		case "", "unknown":
			reason = "resource server has no state"
		case models.RSStatePendingScan:
			reason = "resource server has not been activated yet"
		case models.RSStateNeedsSetup:
			reason = "resource server setup is incomplete"
		default:
			if len(tools) == 0 && len(scopes) == 0 {
				reason = "no tools or scopes registered"
			} else {
				reason = "policy not ready"
			}
		}
	}

	return &SDKPolicyResponse{
		State:           state,
		PolicyComplete:  complete,
		Reason:          reason,
		Generation:      rs.ScanGeneration,
		ScopesSupported: scopes,
		ToolPolicy:      policies,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────
// sdk-manifest PUT
// ─────────────────────────────────────────────────────────────────────────

// PublishManifestRequest is the body the SDK sends. The dev branch accepts
// a richer payload with suggested_scopes; we keep the minimum the SDK actually
// emits when configured for the v2 surface.
type PublishManifestRequest struct {
	Generation int             `json:"generation,omitempty"`
	Tools      []ManifestTool  `json:"tools"`
}

// ManifestTool is one tool from the published manifest.
type ManifestTool struct {
	Name           string          `json:"name"`
	Title          string          `json:"title,omitempty"`
	Description    string          `json:"description,omitempty"`
	InputSchema    json.RawMessage `json:"input_schema,omitempty"`
	IsPublic       bool            `json:"is_public,omitempty"`
	RequiredScopes []string        `json:"required_scopes,omitempty"`
}

// PublishManifestResponse is what we return after the upsert.
type PublishManifestResponse struct {
	Accepted   int       `json:"accepted"`
	Removed    int       `json:"removed"`
	Generation int       `json:"generation"`
	PublishedAt time.Time `json:"published_at"`
}

// PublishManifest upserts mcp_tools rows for this Application from the
// SDK's manifest. Tools missing from the manifest are removed if their
// inventory_source is 'sdk_manifest' (admin-created 'manual' rows are
// left alone).
//
// Bumps the RS's `scan_generation` (the SDK uses this to detect that
// admin-side changes are landing in the right order). PHASE3-NOTE: dev
// also emits drift events here; we don't.
func (s *SDKPolicyService) PublishManifest(
	tenantID string,
	rs *models.ResourceServer,
	req PublishManifestRequest,
) (*PublishManifestResponse, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	now := time.Now().UTC()
	accepted := 0
	removed := 0
	keep := make(map[string]struct{}, len(req.Tools))

	txErr := tenantDB.Transaction(func(tx *gorm.DB) error {
		for _, t := range req.Tools {
			if t.Name == "" {
				continue
			}
			keep[t.Name] = struct{}{}
			row := models.MCPTool{
				TenantID:         tenantID,
				ResourceServerID: rs.ID,
				Name:             t.Name,
				Title:            t.Title,
				Description:      t.Description,
				InputSchema:      datatypes.JSON(t.InputSchema),
				IsPublic:         t.IsPublic,
				RequiredScopes:   t.RequiredScopes,
				InventorySource:  "sdk_manifest",
				LastPublishedAt:  &now,
			}
			// Upsert on (resource_server_id, name).
			err := tx.Where("resource_server_id = ? AND name = ?", rs.ID, t.Name).
				Assign(map[string]interface{}{
					"title":             t.Title,
					"description":       t.Description,
					"input_schema":      datatypes.JSON(t.InputSchema),
					"is_public":         t.IsPublic,
					"required_scopes":   row.RequiredScopes,
					"inventory_source":  "sdk_manifest",
					"last_published_at": now,
					"updated_at":        now,
				}).
				FirstOrCreate(&row).Error
			if err != nil {
				return fmt.Errorf("upsert tool %q: %w", t.Name, err)
			}
			accepted++
		}

		// Remove sdk_manifest tools that are no longer in the manifest.
		var stale []models.MCPTool
		if err := tx.Where("resource_server_id = ? AND inventory_source = ?", rs.ID, "sdk_manifest").
			Find(&stale).Error; err != nil {
			return fmt.Errorf("list stale tools: %w", err)
		}
		for _, st := range stale {
			if _, ok := keep[st.Name]; !ok {
				if err := tx.Delete(&st).Error; err != nil {
					return fmt.Errorf("delete stale tool %q: %w", st.Name, err)
				}
				removed++
			}
		}

		// Bump scan_generation. Manifest publish counts as a real generation
		// change so the SDK clients refetch sdk-policy promptly.
		newGen := rs.ScanGeneration + 1
		if req.Generation > newGen {
			newGen = req.Generation
		}
		if err := tx.Model(rs).Updates(map[string]interface{}{
			"scan_generation":           newGen,
			"last_successful_generation": newGen,
			"updated_at":                now,
		}).Error; err != nil {
			return fmt.Errorf("bump scan_generation: %w", err)
		}
		rs.ScanGeneration = newGen
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	return &PublishManifestResponse{
		Accepted:    accepted,
		Removed:     removed,
		Generation:  rs.ScanGeneration,
		PublishedAt: now,
	}, nil
}
