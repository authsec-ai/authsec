// Package controllers — SpireController: SPIRE Headless workload identity platform.
// Ported from spire-headless microservice (registry, attestation, oidc, policy services).
package platform

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	typespb "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// ===== MODELS =====

// SpireWorkload is the GORM model for registered SPIFFE workloads.
type SpireWorkload struct {
	ID          uint       `json:"-" gorm:"primaryKey"`
	SpiffeID    string     `json:"spiffe_id" gorm:"uniqueIndex"`
	Owner       string     `json:"owner"`
	WorkspaceID *uuid.UUID `json:"workspace_id,omitempty" gorm:"type:uuid"` // owner; from the caller's token, never the body (047)
}

func (SpireWorkload) TableName() string { return "spire_workloads" }

// WorkloadEntry is the GORM model for spire_workload_entries (migration
// 120): the workload registration (selectors, parent_id, TTL) SPIRE agents
// look up to attest workloads. Owned by a workspace.
type WorkloadEntry struct {
	ID           uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID  uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	SpiffeID     string          `json:"spiffe_id" gorm:"type:varchar(512);not null"`
	ParentID     string          `json:"parent_id" gorm:"type:varchar(512);not null"`
	Selectors    json.RawMessage `json:"selectors" gorm:"type:jsonb;not null"`
	TTL          int             `json:"ttl" gorm:"default:3600"`
	Admin        bool            `json:"admin" gorm:"default:false"`
	Downstream   bool            `json:"downstream" gorm:"default:false"`
	SpireEntryID *string         `json:"spire_entry_id,omitempty" gorm:"type:varchar(255)"`
	CreatedAt    time.Time       `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt    time.Time       `json:"updated_at" gorm:"autoUpdateTime"`
}

func (WorkloadEntry) TableName() string { return "spire_workload_entries" }

// SpireOIDCToken stores OIDC token metadata for revocation tracking.
type SpireOIDCToken struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	WorkspaceID uuid.UUID `json:"-" gorm:"type:uuid"`
	JWTID       string    `json:"jti" gorm:"column:jwt_id;uniqueIndex"`
	Subject     string    `json:"subject"`
	SPIFFEID    string    `json:"spiffe_id" gorm:"column:spiffe_id"`
	TokenType   string    `json:"token_type"`
	Audience    string    `json:"audience"`
	Scope       string    `json:"scope"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	Revoked     bool      `json:"revoked"`
}

func (SpireOIDCToken) TableName() string { return "spire_oidc_tokens" }

// SpirePolicy represents a policy document.
type SpirePolicy struct {
	ID          uint              `json:"id" gorm:"primaryKey"`
	WorkspaceID uuid.UUID         `json:"-" gorm:"type:uuid"`
	Name        string            `json:"name" gorm:"uniqueIndex"`
	Description string            `json:"description"`
	Version     string            `json:"version"`
	Engine      string            `json:"engine"`
	Rules       []SpirePolicyRule `json:"rules" gorm:"foreignKey:PolicyID;constraint:OnDelete:CASCADE"`
	Metadata    SpirePolicyMeta   `json:"metadata" gorm:"embedded"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Active      bool              `json:"active"`
}

func (SpirePolicy) TableName() string { return "spire_policies" }

// SpirePolicyRule represents individual policy rules.
type SpirePolicyRule struct {
	ID          uint                   `json:"id" gorm:"primaryKey"`
	WorkspaceID uuid.UUID              `json:"-" gorm:"type:uuid"`
	PolicyID    uint                   `json:"policy_id"`
	Name        string                 `json:"name"`
	Effect      string                 `json:"effect"`
	Priority    int                    `json:"priority"`
	Subjects    []SpirePolicySubject   `json:"subjects" gorm:"foreignKey:RuleID;constraint:OnDelete:CASCADE"`
	Resources   []SpirePolicyResource  `json:"resources" gorm:"foreignKey:RuleID;constraint:OnDelete:CASCADE"`
	Actions     []SpirePolicyAction    `json:"actions" gorm:"foreignKey:RuleID;constraint:OnDelete:CASCADE"`
	Conditions  []SpirePolicyCondition `json:"conditions" gorm:"foreignKey:RuleID;constraint:OnDelete:CASCADE"`
	Attributes  map[string]interface{} `json:"attributes" gorm:"serializer:json"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

func (SpirePolicyRule) TableName() string { return "spire_policy_rules" }

// SpirePolicySubject, SpirePolicyResource, SpirePolicyAction, SpirePolicyCondition.
type SpirePolicySubject struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	WorkspaceID uuid.UUID `json:"-" gorm:"type:uuid"`
	RuleID      uint      `json:"rule_id"`
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Pattern     string    `json:"pattern"`
}

func (SpirePolicySubject) TableName() string { return "spire_policy_subjects" }

type SpirePolicyResource struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	WorkspaceID uuid.UUID `json:"-" gorm:"type:uuid"`
	RuleID      uint      `json:"rule_id"`
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Pattern     string    `json:"pattern"`
}

func (SpirePolicyResource) TableName() string { return "spire_policy_resources" }

type SpirePolicyAction struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	WorkspaceID uuid.UUID `json:"-" gorm:"type:uuid"`
	RuleID      uint      `json:"rule_id"`
	Type        string    `json:"type"`
	Value       string    `json:"value"`
}

func (SpirePolicyAction) TableName() string { return "spire_policy_actions" }

type SpirePolicyCondition struct {
	ID          uint                   `json:"id" gorm:"primaryKey"`
	WorkspaceID uuid.UUID              `json:"-" gorm:"type:uuid"`
	RuleID      uint                   `json:"rule_id"`
	Type        string                 `json:"type"`
	Operator    string                 `json:"operator"`
	Key         string                 `json:"key"`
	Value       string                 `json:"value"`
	Metadata    map[string]interface{} `json:"metadata" gorm:"serializer:json"`
}

func (SpirePolicyCondition) TableName() string { return "spire_policy_conditions" }

// SpirePolicyMeta holds policy metadata.
type SpirePolicyMeta struct {
	Author      string            `json:"author"`
	Tags        []string          `json:"tags" gorm:"serializer:json"`
	Labels      map[string]string `json:"labels" gorm:"serializer:json"`
	Annotations map[string]string `json:"annotations" gorm:"serializer:json"`
}

// SpirePolicyEvaluation is the input for policy evaluation.
type SpirePolicyEvaluation struct {
	Subject   string                 `json:"subject" binding:"required"`
	Resource  string                 `json:"resource" binding:"required"`
	Action    string                 `json:"action" binding:"required"`
	Context   map[string]interface{} `json:"context"`
	Timestamp time.Time              `json:"timestamp"`
}

// SpirePolicyResult is the output of policy evaluation.
type SpirePolicyResult struct {
	Decision    string                 `json:"decision"`
	Reason      string                 `json:"reason"`
	MatchedRule *SpirePolicyRule       `json:"matched_rule,omitempty"`
	Context     map[string]interface{} `json:"context"`
	EvaluatedAt time.Time              `json:"evaluated_at"`
	RequestID   string                 `json:"request_id"`
}

// SpireAuditLog stores policy audit entries.
type SpireAuditLog struct {
	ID          uint                   `json:"id" gorm:"primaryKey"`
	RequestID   string                 `json:"request_id"`
	WorkspaceID string                 `json:"workspace_id"`
	Subject     string                 `json:"subject"`
	Resource    string                 `json:"resource"`
	Action      string                 `json:"action"`
	Decision    string                 `json:"decision"`
	Reason      string                 `json:"reason"`
	PolicyID    *uint                  `json:"policy_id,omitempty"`
	RuleID      *uint                  `json:"rule_id,omitempty"`
	Context     map[string]interface{} `json:"context" gorm:"serializer:json"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	Timestamp   time.Time              `json:"timestamp"`
}

func (SpireAuditLog) TableName() string { return "spire_audit_logs" }

// SpireRoleBinding represents RBAC role bindings.
type SpireRoleBinding struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	WorkspaceID uuid.UUID `json:"-" gorm:"type:uuid"`
	Subject     string    `json:"subject"`
	Role        string    `json:"role"`
	Resource    string    `json:"resource"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (SpireRoleBinding) TableName() string { return "spire_role_bindings" }

// SpireAllModels lists all GORM models for AutoMigrate.
var SpireAllModels = []interface{}{
	&SpireWorkload{},
	&SpireOIDCToken{},
	&SpirePolicy{},
	&SpirePolicyRule{},
	&SpirePolicySubject{},
	&SpirePolicyResource{},
	&SpirePolicyAction{},
	&SpirePolicyCondition{},
	&SpireAuditLog{},
	&SpireRoleBinding{},
}

// ===== OIDC TYPES =====

type spireOIDCConfig struct {
	IssuerURL   string
	TokenExpiry time.Duration
}

type spireOIDCProvider struct {
	cfg        *spireOIDCConfig
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
	db         *gorm.DB
}

type spireTokenClaims struct {
	WorkspaceID string                 `json:"workspace_id"`
	Subject     string                 `json:"sub"`
	Issuer      string                 `json:"iss"`
	Audience    []string               `json:"aud"`
	ExpiresAt   int64                  `json:"exp"`
	IssuedAt    int64                  `json:"iat"`
	NotBefore   int64                  `json:"nbf"`
	JWTID       string                 `json:"jti"`
	SPIFFEID    string                 `json:"spiffe_id,omitempty"`
	Claims      map[string]interface{} `json:"claims,omitempty"`
	jwt.RegisteredClaims
}

type spireJWTSVIDClaims struct {
	WorkspaceID string   `json:"workspace_id"`
	Subject     string   `json:"sub"`
	Audience    []string `json:"aud"`
	Issuer      string   `json:"iss"`
	ExpiresAt   int64    `json:"exp"`
	IssuedAt    int64    `json:"iat"`
	NotBefore   int64    `json:"nbf"`
	JWTID       string   `json:"jti"`
	SPIFFEID    string   `json:"spiffe_id"`
	jwt.RegisteredClaims
}

type spireCloudTokenRequest struct {
	Provider     string `json:"provider" binding:"required"`
	Audience     string `json:"audience" binding:"required"`
	Scope        string `json:"scope,omitempty"`
	RoleARN      string `json:"role_arn,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
	ServiceEmail string `json:"service_email,omitempty"`
}

type spireCloudTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int64  `json:"expires_in,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

type spireTokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
}

// ===== CONTROLLER =====

// SpireController is the merged SPIRE headless platform controller.
//
// Every handler acts on the caller's workspace (tenancy.Workspace, set by
// AuthMiddleware) and reads and writes only that workspace's rows; another
// workspace's row is 404. The token-exchange endpoints also verify the
// credential they exchange and require it to belong to the caller's
// workspace. Only OIDC discovery and JWKS are public (AS-081).
type SpireController struct {
	db           *gorm.DB
	entryClient  entryv1.EntryClient
	grpcConn     *grpc.ClientConn
	oidcProvider *spireOIDCProvider
	policyEngine string
	trustDomain  string
}

// sharedSpireController is the singleton used by in-process callers (e.g. clients controller).
var sharedSpireController *SpireController

// SetSharedSpireController stores the singleton so other controllers can create entries in-process.
func SetSharedSpireController(sc *SpireController) { sharedSpireController = sc }

// EmbeddedSpireAvailable reports whether the embedded SPIRE control plane
// (ENABLE_EMBEDDED_SPIRE) is running, which RegisterAgentWorkload needs.
func EmbeddedSpireAvailable() bool { return sharedSpireController != nil }

// workspaceCtx is ctx carrying the workspace, for in-process callers that
// resolved it from a verified token.
func workspaceCtx(ws uuid.UUID) context.Context {
	return tenancy.WithContext(context.Background(), tenancy.Context{WorkspaceID: ws, PrincipalKind: "system", Realm: "spire"})
}

// RegisterAgentWorkload creates a SPIRE workload entry for an AI agent of
// workspaceID, which the caller took from its verified token. It writes
// spire_workloads and spire_workload_entries for that workspace, and a SPIRE
// server entry via gRPC when connected. Returns the full SPIFFE ID.
func RegisterAgentWorkload(workspaceID, clientID, agentType, platform string, selectors map[string]string) (string, error) {
	sc := sharedSpireController
	if sc == nil {
		return "", fmt.Errorf("SPIRE controller not initialized")
	}
	wsUUID, err := uuid.Parse(workspaceID)
	if err != nil {
		return "", fmt.Errorf("invalid workspace_id: %w", err)
	}
	ctx := workspaceCtx(wsUUID)
	scoped, err := tenancy.DBContext(ctx, sc.db)
	if err != nil {
		return "", err
	}

	// The Application of this client, in this workspace only (migration 118
	// legacy_client_id mapping). Backfilled applications get the v4 path
	// spiffe://<td>/workspaces/<ws>/applications/<app>; others keep the
	// legacy /tenants/<ws>/agents/<type>/<client> path.
	var applicationID *uuid.UUID
	if clientUUID, parseErr := uuid.Parse(clientID); parseErr == nil {
		var rs models.ResourceServer
		if err := scoped.Select("id, workspace_id").Where("legacy_client_id = ?", clientUUID).First(&rs).Error; err == nil {
			id := rs.ID
			applicationID = &id
		}
	}

	var spiffeID, parentPath string
	if applicationID != nil {
		spiffeID = fmt.Sprintf("/workspaces/%s/applications/%s", workspaceID, applicationID.String())
		parentPath = fmt.Sprintf("/workspaces/%s", workspaceID)
	} else {
		spiffeID = fmt.Sprintf("/tenants/%s/agents/%s/%s", workspaceID, agentType, clientID)
		parentPath = fmt.Sprintf("/tenants/%s/agent", workspaceID)
	}
	fullSpiffeID := fmt.Sprintf("spiffe://%s%s", sc.trustDomain, spiffeID)
	parentID := fmt.Sprintf("spiffe://%s%s", sc.trustDomain, parentPath)

	// SPIRE selectors from "type:key" -> value pairs.
	var spireSelectors []*typespb.Selector
	for key, value := range selectors {
		parts := strings.SplitN(key, ":", 2)
		selectorKey := ""
		if len(parts) > 1 {
			selectorKey = parts[1]
		}
		spireSelectors = append(spireSelectors, &typespb.Selector{Type: parts[0], Value: fmt.Sprintf("%s:%s", selectorKey, value)})
	}
	if len(spireSelectors) == 0 {
		spireSelectors = []*typespb.Selector{{Type: "k8s", Value: fmt.Sprintf("pod-label:owner:%s", clientID)}}
	}

	selectorMap := map[string]string{
		"authsec:client_id":    clientID,
		"authsec:agent_type":   agentType,
		"authsec:workspace_id": workspaceID,
	}
	for k, v := range selectors {
		if !strings.HasPrefix(k, "authsec:") {
			selectorMap[k] = v
		}
	}
	selectorsJSON, err := json.Marshal(selectorMap)
	if err != nil {
		return "", fmt.Errorf("failed to marshal selectors: %w", err)
	}

	w := SpireWorkload{SpiffeID: spiffeID, Owner: clientID, WorkspaceID: &wsUUID}
	if err := scoped.Create(&w).Error; err != nil {
		return "", fmt.Errorf("failed to save workload record: %w", err)
	}

	entry := WorkloadEntry{
		ID:          uuid.New(),
		WorkspaceID: wsUUID,
		SpiffeID:    fullSpiffeID,
		ParentID:    parentID,
		Selectors:   selectorsJSON,
		TTL:         3600,
	}
	if err := scoped.Create(&entry).Error; err != nil {
		log.Printf("[SPIRE] Warning: failed to save workload entry: %v", err)
	}

	if sc.entryClient != nil {
		gctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := sc.entryClient.BatchCreateEntry(gctx, &entryv1.BatchCreateEntryRequest{
			Entries: []*typespb.Entry{{
				SpiffeId:    &typespb.SPIFFEID{TrustDomain: sc.trustDomain, Path: spiffeID},
				ParentId:    &typespb.SPIFFEID{TrustDomain: sc.trustDomain, Path: parentPath},
				Selectors:   spireSelectors,
				X509SvidTtl: 3600,
				StoreSvid:   true,
			}},
		})
		if err != nil {
			scoped.Where("id = ?", w.ID).Delete(&SpireWorkload{})
			scoped.Where("id = ?", entry.ID).Delete(&WorkloadEntry{})
			return "", fmt.Errorf("SPIRE entry creation failed: %w", err)
		}
	} else {
		log.Printf("[SPIRE] Warning: SPIRE gRPC entryClient is nil — workload entry saved to DB but not registered with SPIRE server. Set SPIRE_SERVER_ADDR to enable.")
	}

	if applicationID != nil {
		identity := models.ApplicationSpiffeIdentity{
			WorkspaceID:   wsUUID,
			ApplicationID: *applicationID,
			SpiffeID:      fullSpiffeID,
			TrustDomain:   sc.trustDomain,
			Selectors:     selectorsJSON,
			Status:        "active",
		}
		if err := scoped.Where("spiffe_id = ?", fullSpiffeID).Assign(identity).FirstOrCreate(&identity).Error; err != nil {
			log.Printf("[SPIRE] Warning: failed to persist application_spiffe_identities row: %v", err)
		}
	}

	log.Printf("[SPIRE] Agent workload registered: spiffe_id=%s workspace=%s client=%s application=%v",
		fullSpiffeID, workspaceID, clientID, applicationID)
	return fullSpiffeID, nil
}

// NewSpireController creates and initialises the SPIRE controller.
func NewSpireController() *SpireController {
	sc := &SpireController{
		db:           config.DB,
		policyEngine: spireGetenv("POLICY_ENGINE", "hybrid"),
		trustDomain:  config.AppConfig.SpiffeTrustDomain,
	}
	if sc.trustDomain == "" {
		sc.trustDomain = spireGetenv("SPIRE_TRUST_DOMAIN", "example.org")
	}

	// SPIRE entry client (optional — degrades gracefully).
	spireAddr := spireGetenv("SPIRE_SERVER_ADDR", "spire-server:8081")
	spiffeSocket := "/run/spire/sockets/workload_api.sock"
	ctx := context.Background()

	var conn *grpc.ClientConn
	var err error
	if _, statErr := os.Stat(spiffeSocket); statErr == nil {
		source, srcErr := workloadapi.NewX509Source(ctx)
		if srcErr == nil {
			tlsCfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
			conn, err = grpc.NewClient(spireAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
			if err != nil {
				log.Printf("[spire] mTLS gRPC connect failed: %v — falling back to insecure", err)
			}
		}
	}
	if conn == nil {
		conn, err = grpc.NewClient(spireAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Printf("[spire] Warning: failed to create SPIRE gRPC client: %v", err)
		}
	}
	if conn != nil {
		sc.grpcConn = conn
		sc.entryClient = entryv1.NewEntryClient(conn)
	}

	issuerURL := config.AppConfig.SpiffeOIDCIssuer
	if issuerURL == "" {
		issuerURL = spireGetenv("OIDC_ISSUER_URL", "https://spire-headless.example.org")
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("[spire] Warning: failed to generate RSA key: %v", err)
	} else {
		sc.oidcProvider = &spireOIDCProvider{
			cfg:        &spireOIDCConfig{IssuerURL: issuerURL, TokenExpiry: time.Hour},
			privateKey: privateKey,
			publicKey:  &privateKey.PublicKey,
			keyID:      uuid.New().String(),
			db:         config.DB,
		}
	}

	if sc.entryClient != nil && spireGetenv("SPIRE_RECONCILE", "true") == "true" {
		go sc.reconcileEntries(context.Background())
	}
	// No default policies are seeded: policies belong to a workspace and
	// each workspace writes its own.
	return sc
}

// reconcileEntries periodically syncs spire_workloads with the SPIRE server.
// It is a platform job over the platform's own SPIRE server, which holds
// every workspace's entries: it reads all workspaces' rows and writes only
// to the SPIRE server, never across workspaces in the database.
func (sc *SpireController) reconcileEntries(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if sc.db == nil || sc.entryClient == nil {
				continue
			}
			var workloads []SpireWorkload
			// TENANT-EXEMPT: platform reconciliation of the shared SPIRE server reads every workspace's workloads.
			if err := sc.db.Find(&workloads).Error; err != nil {
				log.Printf("[spire] reconcile: DB error: %v", err)
				continue
			}
			resp, err := sc.entryClient.ListEntries(ctx, &entryv1.ListEntriesRequest{})
			if err != nil {
				log.Printf("[spire] reconcile: list entries error: %v", err)
				continue
			}
			known := make(map[string]bool, len(workloads))
			spireMap := make(map[string]*typespb.Entry)
			for _, e := range resp.Entries {
				spireMap[e.SpiffeId.Path] = e
			}
			for _, w := range workloads {
				known[w.SpiffeID] = true
				if _, exists := spireMap[w.SpiffeID]; !exists {
					if _, err := sc.entryClient.BatchCreateEntry(ctx, &entryv1.BatchCreateEntryRequest{
						Entries: []*typespb.Entry{spireEntryFromWorkload(w, sc.trustDomain)},
					}); err != nil {
						log.Printf("[spire] reconcile: create entry %s: %v", w.SpiffeID, err)
					}
				}
			}
			for path, e := range spireMap {
				if !known[path] {
					if _, err := sc.entryClient.BatchDeleteEntry(ctx, &entryv1.BatchDeleteEntryRequest{Ids: []string{e.Id}}); err != nil {
						log.Printf("[spire] reconcile: delete stale entry %s: %v", path, err)
					}
				}
			}
		}
	}
}

func spireEntryFromWorkload(w SpireWorkload, trustDomain string) *typespb.Entry {
	return &typespb.Entry{
		SpiffeId:    &typespb.SPIFFEID{TrustDomain: trustDomain, Path: w.SpiffeID},
		Selectors:   []*typespb.Selector{{Type: "k8s", Value: fmt.Sprintf("pod-label:owner:%s", w.Owner)}},
		X509SvidTtl: 3600,
		Downstream:  false,
		Admin:       false,
		StoreSvid:   true,
	}
}

// scopedDB returns the controller's DB restricted to the caller's workspace,
// or answers 401 and returns ok=false.
func (sc *SpireController) scopedDB(c *gin.Context) (*gorm.DB, uuid.UUID, bool) {
	ws, err := tenancy.Workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace context required"})
		return nil, uuid.Nil, false
	}
	db, err := tenancy.DB(c, sc.db)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace context required"})
		return nil, uuid.Nil, false
	}
	return db, ws, true
}

// ===== REGISTRY HANDLERS =====

// RegisterWorkload registers a SPIFFE workload in the caller's workspace.
func (sc *SpireController) RegisterWorkload(c *gin.Context) {
	db, ws, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	var w SpireWorkload
	if err := c.ShouldBindJSON(&w); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	w.ID = 0
	w.WorkspaceID = &ws
	if err := db.Create(&w).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "workload could not be registered (SPIFFE ID in use?)"})
		return
	}
	if sc.entryClient != nil {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		if _, err := sc.entryClient.BatchCreateEntry(ctx, &entryv1.BatchCreateEntryRequest{
			Entries: []*typespb.Entry{spireEntryFromWorkload(w, sc.trustDomain)},
		}); err != nil {
			db.Where("id = ?", w.ID).Delete(&SpireWorkload{})
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("SPIRE entry creation failed: %v", err)})
			return
		}
	}
	c.JSON(http.StatusCreated, w)
}

// findWorkload loads the caller's workload :id; another workspace's is 404.
func (sc *SpireController) findWorkload(c *gin.Context, db *gorm.DB) (*SpireWorkload, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Workload not found"})
		return nil, false
	}
	var w SpireWorkload
	if err := db.Where("id = ?", id).First(&w).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Workload not found"})
		return nil, false
	}
	return &w, true
}

// UpdateWorkload updates the owner of a workload of the caller's workspace.
func (sc *SpireController) UpdateWorkload(c *gin.Context) {
	db, _, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	existing, ok := sc.findWorkload(c, db)
	if !ok {
		return
	}
	var body struct {
		Owner string `json:"owner"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := db.Model(&SpireWorkload{}).Where("id = ?", existing.ID).Update("owner", body.Owner).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	existing.Owner = body.Owner
	if sc.entryClient != nil {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		resp, err := sc.entryClient.ListEntries(ctx, &entryv1.ListEntriesRequest{
			Filter: &entryv1.ListEntriesRequest_Filter{
				BySpiffeId: &typespb.SPIFFEID{TrustDomain: sc.trustDomain, Path: existing.SpiffeID},
			},
		})
		if err == nil && len(resp.Entries) > 0 {
			entry := resp.Entries[0]
			entry.Selectors = []*typespb.Selector{{Type: "k8s", Value: fmt.Sprintf("pod-label:owner:%s", existing.Owner)}}
			_, _ = sc.entryClient.BatchUpdateEntry(ctx, &entryv1.BatchUpdateEntryRequest{Entries: []*typespb.Entry{entry}})
		}
	}
	c.JSON(http.StatusOK, existing)
}

// DeleteWorkload removes a workload of the caller's workspace.
func (sc *SpireController) DeleteWorkload(c *gin.Context) {
	db, _, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	w, ok := sc.findWorkload(c, db)
	if !ok {
		return
	}
	if sc.entryClient != nil {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		resp, err := sc.entryClient.ListEntries(ctx, &entryv1.ListEntriesRequest{
			Filter: &entryv1.ListEntriesRequest_Filter{
				BySpiffeId: &typespb.SPIFFEID{TrustDomain: sc.trustDomain, Path: w.SpiffeID},
			},
		})
		if err == nil && len(resp.Entries) > 0 {
			_, _ = sc.entryClient.BatchDeleteEntry(ctx, &entryv1.BatchDeleteEntryRequest{Ids: []string{resp.Entries[0].Id}})
		}
	}
	if err := db.Where("id = ?", w.ID).Delete(&SpireWorkload{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Workload deleted"})
}

// ListWorkloads lists the caller's workspace's workloads.
func (sc *SpireController) ListWorkloads(c *gin.Context) {
	db, _, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	var workloads []SpireWorkload
	if err := db.Order("id").Find(&workloads).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, workloads)
}

// ===== OIDC HANDLERS =====

// OIDCDiscovery serves the OIDC discovery document.
func (sc *SpireController) OIDCDiscovery(c *gin.Context) {
	p := sc.oidcProvider
	if p == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OIDC provider not initialized"})
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{
		"issuer":                                p.cfg.IssuerURL,
		"authorization_endpoint":                p.cfg.IssuerURL + "/oidc/auth",
		"token_endpoint":                        p.cfg.IssuerURL + "/oidc/token",
		"jwks_uri":                              p.cfg.IssuerURL + "/oidc/jwks",
		"introspection_endpoint":                p.cfg.IssuerURL + "/oidc/introspect",
		"revocation_endpoint":                   p.cfg.IssuerURL + "/oidc/revoke",
		"response_types_supported":              []string{"code", "token", "id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "spiffe"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "spiffe_id", "workspace_id"},
		"grant_types_supported":                 []string{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"},
	})
}

// OIDCJWKSHandler serves the JSON Web Key Set.
func (sc *SpireController) OIDCJWKSHandler(c *gin.Context) {
	p := sc.oidcProvider
	if p == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OIDC provider not initialized"})
		return
	}
	type JWK struct {
		KeyType   string `json:"kty"`
		Algorithm string `json:"alg"`
		Use       string `json:"use"`
		KeyID     string `json:"kid"`
		Modulus   string `json:"n"`
		Exponent  string `json:"e"`
	}
	jwk := JWK{
		KeyType:   "RSA",
		Algorithm: "RS256",
		Use:       "sig",
		KeyID:     p.keyID,
		Modulus:   spireEncodeBase64URL(p.publicKey.N.Bytes()),
		Exponent:  spireEncodeBase64URL(big.NewInt(int64(p.publicKey.E)).Bytes()),
	}
	c.JSON(http.StatusOK, gin.H{"keys": []JWK{jwk}})
}

// callerWorkspace returns the caller's workspace or answers 401.
func callerWorkspace(c *gin.Context) (uuid.UUID, bool) {
	ws, err := tenancy.Workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace context required"})
		return uuid.Nil, false
	}
	return ws, true
}

// OIDCTokenExchange handles RFC 8693 token exchange. The subject token's
// verified workspace claim must be the caller's; the new token is issued
// for that workspace.
func (sc *SpireController) OIDCTokenExchange(c *gin.Context) {
	p := sc.oidcProvider
	if p == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OIDC provider not initialized"})
		return
	}
	ws, ok := callerWorkspace(c)
	if !ok {
		return
	}
	var req struct {
		GrantType        string `json:"grant_type" binding:"required"`
		SubjectToken     string `json:"subject_token" binding:"required"`
		SubjectTokenType string `json:"subject_token_type" binding:"required"`
		Audience         string `json:"audience,omitempty"`
		Scope            string `json:"scope,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	if req.GrantType != "urn:ietf:params:oauth:grant-type:token-exchange" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
		return
	}
	claims, err := p.validateToken(req.SubjectToken)
	if err != nil || claims.WorkspaceID != ws.String() || !p.tokenActive(ws, claims.JWTID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "Invalid subject token"})
		return
	}
	audience := req.Audience
	if audience == "" {
		audience = p.cfg.IssuerURL
	}
	newToken, err := p.createToken(ws, claims.Subject, claims.SPIFFEID, []string{audience}, req.Scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	c.JSON(http.StatusOK, spireTokenExchangeResponse{
		AccessToken:     newToken,
		IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		TokenType:       "Bearer",
		ExpiresIn:       int64(p.cfg.TokenExpiry.Seconds()),
		Scope:           req.Scope,
	})
}

// OIDCIntrospect handles RFC 7662 token introspection. A token of another
// workspace is reported inactive.
func (sc *SpireController) OIDCIntrospect(c *gin.Context) {
	p := sc.oidcProvider
	if p == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OIDC provider not initialized"})
		return
	}
	ws, ok := callerWorkspace(c)
	if !ok {
		return
	}
	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	claims, err := p.validateToken(token)
	if err != nil || claims.WorkspaceID != ws.String() || !p.tokenActive(ws, claims.JWTID) {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"active":       true,
		"sub":          claims.Subject,
		"iss":          claims.Issuer,
		"aud":          claims.Audience,
		"exp":          claims.ExpiresAt,
		"iat":          claims.IssuedAt,
		"jti":          claims.JWTID,
		"spiffe_id":    claims.SPIFFEID,
		"workspace_id": claims.WorkspaceID,
	})
}

// OIDCRevoke handles RFC 7009 token revocation, for the caller's workspace's
// tokens only.
func (sc *SpireController) OIDCRevoke(c *gin.Context) {
	p := sc.oidcProvider
	if p == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OIDC provider not initialized"})
		return
	}
	db, ws, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	claims, err := p.validateToken(token)
	if err != nil || claims.WorkspaceID != ws.String() {
		c.JSON(http.StatusOK, gin.H{})
		return
	}
	db.Model(&SpireOIDCToken{}).Where("jwt_id = ?", claims.JWTID).Update("revoked", true)
	c.JSON(http.StatusOK, gin.H{})
}

// OIDCExchangeSPIFFE exchanged the platform's own X.509 SVID (from the
// local workload API socket) for an OIDC token, for any caller. That is the
// platform's identity, not a workspace's, so it is never handed out.
func (sc *SpireController) OIDCExchangeSPIFFE(c *gin.Context) {
	c.JSON(http.StatusGone, gin.H{
		"error":             "unsupported",
		"error_description": "exchanging the platform's own SVID is not offered; use /oidc/issue/jwt-svid for a workload of your workspace",
	})
}

// OIDCIssueJWTSVID issues a JWT-SVID for a workload registered in the
// caller's workspace (spire_workloads). The SPIFFE ID comes from the
// spiffe_id parameter and must be one of those workloads; it is never taken
// from an X-SPIFFE-ID header.
func (sc *SpireController) OIDCIssueJWTSVID(c *gin.Context) {
	p := sc.oidcProvider
	if p == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OIDC provider not initialized"})
		return
	}
	db, ws, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	spiffeID := c.Query("spiffe_id")
	path := strings.TrimPrefix(spiffeID, "spiffe://"+sc.trustDomain)
	if spiffeID == "" || !strings.HasPrefix(path, "/") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "spiffe_id of a registered workload is required"})
		return
	}
	var w SpireWorkload
	if err := db.Where("spiffe_id = ?", path).First(&w).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Workload not found"})
		return
	}
	audience := c.Query("audience")
	if audience == "" {
		audience = p.cfg.IssuerURL
	}
	full := "spiffe://" + sc.trustDomain + w.SpiffeID
	jwtSVID, err := p.createJWTSVID(ws, full, []string{audience})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	c.JSON(http.StatusOK, spireTokenExchangeResponse{
		AccessToken:     jwtSVID,
		IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		TokenType:       "Bearer",
		ExpiresIn:       int64(p.cfg.TokenExpiry.Seconds()),
	})
}

// exchangedSVID verifies the JWT-SVID a cloud exchange presents (body
// jwt_svid) and requires it to belong to the caller's workspace. It answers
// the error itself and returns ok=false otherwise.
func (sc *SpireController) exchangedSVID(c *gin.Context, presented string) (*spireJWTSVIDClaims, bool) {
	p := sc.oidcProvider
	if p == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OIDC provider not initialized"})
		return nil, false
	}
	ws, ok := callerWorkspace(c)
	if !ok {
		return nil, false
	}
	if presented == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "jwt_svid is required"})
		return nil, false
	}
	claims, err := p.validateJWTSVID(presented)
	if err != nil || claims.WorkspaceID != ws.String() || !p.tokenActive(ws, claims.JWTID) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_grant"})
		return nil, false
	}
	return claims, true
}

// OIDCExchangeCloud exchanges a JWT-SVID of the caller's workspace for a
// cloud provider token.
func (sc *SpireController) OIDCExchangeCloud(c *gin.Context) {
	var req struct {
		spireCloudTokenRequest
		JWTSVID string `json:"jwt_svid"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	claims, ok := sc.exchangedSVID(c, req.JWTSVID)
	if !ok {
		return
	}
	p := sc.oidcProvider
	var resp *spireCloudTokenResponse
	var err error
	switch req.Provider {
	case "aws":
		resp, err = p.exchangeAWSToken(claims, &req.spireCloudTokenRequest)
	case "azure":
		resp, err = p.exchangeAzureToken(claims, &req.spireCloudTokenRequest)
	case "gcp":
		resp, err = p.exchangeGCPToken(claims, &req.spireCloudTokenRequest)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_provider"})
		return
	}
	if err != nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// OIDCExchangeAWS exchanges a JWT-SVID of the caller's workspace for AWS STS credentials.
func (sc *SpireController) OIDCExchangeAWS(c *gin.Context) {
	var req struct {
		RoleARN  string `json:"role_arn" binding:"required"`
		Audience string `json:"audience,omitempty"`
		JWTSVID  string `json:"jwt_svid"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	claims, ok := sc.exchangedSVID(c, req.JWTSVID)
	if !ok {
		return
	}
	if req.Audience == "" {
		req.Audience = "sts.amazonaws.com"
	}
	resp, err := sc.oidcProvider.exchangeAWSToken(claims, &spireCloudTokenRequest{Provider: "aws", Audience: req.Audience, RoleARN: req.RoleARN})
	if err != nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// OIDCExchangeAzure exchanges a JWT-SVID of the caller's workspace for an
// Azure AD token. azure_tenant_id is the Entra directory, not an AuthSec
// workspace.
func (sc *SpireController) OIDCExchangeAzure(c *gin.Context) {
	var req struct {
		AzureTenantID string `json:"azure_tenant_id" binding:"required"`
		ResourceID    string `json:"resource_id,omitempty"`
		Scope         string `json:"scope,omitempty"`
		JWTSVID       string `json:"jwt_svid"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	claims, ok := sc.exchangedSVID(c, req.JWTSVID)
	if !ok {
		return
	}
	if req.ResourceID == "" {
		req.ResourceID = "https://management.azure.com/"
	}
	audience := "https://login.microsoftonline.com/" + url.PathEscape(req.AzureTenantID) + "/v2.0"
	resp, err := sc.oidcProvider.exchangeAzureToken(claims, &spireCloudTokenRequest{Provider: "azure", Audience: audience, ResourceID: req.ResourceID, Scope: req.Scope})
	if err != nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// OIDCExchangeGCP exchanges a JWT-SVID of the caller's workspace for a GCP access token.
func (sc *SpireController) OIDCExchangeGCP(c *gin.Context) {
	var req struct {
		ProjectID    string `json:"project_id" binding:"required"`
		ServiceEmail string `json:"service_email" binding:"required"`
		Scope        string `json:"scope,omitempty"`
		JWTSVID      string `json:"jwt_svid"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	claims, ok := sc.exchangedSVID(c, req.JWTSVID)
	if !ok {
		return
	}
	if req.Scope == "" {
		req.Scope = "https://www.googleapis.com/auth/cloud-platform"
	}
	resp, err := sc.oidcProvider.exchangeGCPToken(claims, &spireCloudTokenRequest{Provider: "gcp", Audience: "https://sts.googleapis.com/", ServiceEmail: req.ServiceEmail, Scope: req.Scope})
	if err != nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// ===== POLICY HANDLERS =====

// stampPolicy gives a policy and all its nested rows the workspace and
// clears any ids from the request, so nothing is written over another row.
func stampPolicy(p *SpirePolicy, ws uuid.UUID) {
	p.ID = 0
	p.WorkspaceID = ws
	for i := range p.Rules {
		r := &p.Rules[i]
		r.ID, r.PolicyID, r.WorkspaceID = 0, 0, ws
		for j := range r.Subjects {
			r.Subjects[j].ID, r.Subjects[j].RuleID, r.Subjects[j].WorkspaceID = 0, 0, ws
		}
		for j := range r.Resources {
			r.Resources[j].ID, r.Resources[j].RuleID, r.Resources[j].WorkspaceID = 0, 0, ws
		}
		for j := range r.Actions {
			r.Actions[j].ID, r.Actions[j].RuleID, r.Actions[j].WorkspaceID = 0, 0, ws
		}
		for j := range r.Conditions {
			r.Conditions[j].ID, r.Conditions[j].RuleID, r.Conditions[j].WorkspaceID = 0, 0, ws
		}
	}
}

func preloadRules(db *gorm.DB) *gorm.DB {
	return db.Preload("Rules.Subjects").Preload("Rules.Resources").Preload("Rules.Actions").Preload("Rules.Conditions")
}

// CreatePolicy creates a policy in the caller's workspace.
func (sc *SpireController) CreatePolicy(c *gin.Context) {
	db, ws, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	var policy SpirePolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := sc.validatePolicy(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	stampPolicy(&policy, ws)
	policy.Version = "1.0"
	policy.Active = true
	policy.Engine = sc.policyEngine
	if err := db.Create(&policy).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "policy could not be created (name in use?)"})
		return
	}
	sc.spireAuditLog(c, "policy.create", policy.Name, "allow", "Policy created", nil)
	c.JSON(http.StatusCreated, policy)
}

// ListPolicies lists the caller's workspace's policies.
func (sc *SpireController) ListPolicies(c *gin.Context) {
	db, _, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	var policies []SpirePolicy
	q := preloadRules(db)
	if name := c.Query("name"); name != "" {
		q = q.Where("name ILIKE ?", "%"+name+"%")
	}
	if engine := c.Query("engine"); engine != "" {
		q = q.Where("engine = ?", engine)
	}
	if active := c.Query("active"); active != "" {
		if v, err := strconv.ParseBool(active); err == nil {
			q = q.Where("active = ?", v)
		}
	}
	if err := q.Find(&policies).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, policies)
}

func policyID(c *gin.Context) (uint64, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return 0, false
	}
	return id, true
}

// GetPolicy returns a policy of the caller's workspace; another's is 404.
func (sc *SpireController) GetPolicy(c *gin.Context) {
	db, _, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	id, ok := policyID(c)
	if !ok {
		return
	}
	var policy SpirePolicy
	if err := preloadRules(db).Where("id = ?", id).First(&policy).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}
	c.JSON(http.StatusOK, policy)
}

// UpdatePolicy replaces a policy of the caller's workspace (its rules are
// rewritten); another workspace's is 404.
func (sc *SpireController) UpdatePolicy(c *gin.Context) {
	ws, ok := callerWorkspace(c)
	if !ok {
		return
	}
	id, ok := policyID(c)
	if !ok {
		return
	}
	var body SpirePolicy
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := sc.validatePolicy(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	stampPolicy(&body, ws)
	var updated SpirePolicy
	err := tenancy.Transaction(c.Request.Context(), sc.db, func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", id).First(&updated).Error; err != nil {
			return tenancy.ErrNotFound
		}
		if err := tx.Model(&SpirePolicy{}).Where("id = ?", id).Updates(map[string]interface{}{
			"name": body.Name, "description": body.Description, "active": body.Active, "updated_at": time.Now(),
		}).Error; err != nil {
			return err
		}
		if err := tx.Where("policy_id = ?", id).Delete(&SpirePolicyRule{}).Error; err != nil {
			return err
		}
		for i := range body.Rules {
			body.Rules[i].PolicyID = uint(id)
			if err := tx.Create(&body.Rules[i]).Error; err != nil {
				return err
			}
		}
		return preloadRules(tx).Where("id = ?", id).First(&updated).Error
	})
	if err != nil {
		if errors.Is(err, tenancy.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "policy could not be updated"})
		return
	}
	sc.spireAuditLog(c, "policy.update", updated.Name, "allow", "Policy updated", nil)
	c.JSON(http.StatusOK, updated)
}

// DeletePolicy removes a policy of the caller's workspace; another's is 404.
func (sc *SpireController) DeletePolicy(c *gin.Context) {
	db, _, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	id, ok := policyID(c)
	if !ok {
		return
	}
	res := db.Where("id = ?", id).Delete(&SpirePolicy{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}
	sc.spireAuditLog(c, "policy.delete", c.Param("id"), "allow", "Policy deleted", nil)
	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted"})
}

// EvaluatePolicy evaluates a request against the caller's workspace's policies.
func (sc *SpireController) EvaluatePolicy(c *gin.Context) {
	db, _, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	var eval SpirePolicyEvaluation
	if err := c.ShouldBindJSON(&eval); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	requestID := uuid.New().String()
	eval.Timestamp = time.Now()
	result := sc.evaluatePolicy(db, &eval, requestID)
	sc.spireAuditLog(c, eval.Action, eval.Resource, result.Decision, result.Reason, &requestID)
	c.JSON(http.StatusOK, result)
}

// BatchEvaluatePolicy evaluates several requests against the caller's
// workspace's policies.
func (sc *SpireController) BatchEvaluatePolicy(c *gin.Context) {
	db, _, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	var evals []SpirePolicyEvaluation
	if err := c.ShouldBindJSON(&evals); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var results []SpirePolicyResult
	for _, eval := range evals {
		requestID := uuid.New().String()
		eval.Timestamp = time.Now()
		result := sc.evaluatePolicy(db, &eval, requestID)
		results = append(results, *result)
		sc.spireAuditLog(c, eval.Action, eval.Resource, result.Decision, result.Reason, &requestID)
	}
	c.JSON(http.StatusOK, gin.H{"results": results})
}

// TestPolicy tests a policy without saving it.
func (sc *SpireController) TestPolicy(c *gin.Context) {
	var req struct {
		Policy     SpirePolicy           `json:"policy"`
		Evaluation SpirePolicyEvaluation `json:"evaluation"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result := &SpirePolicyResult{
		Decision:    "deny",
		Reason:      "No matching rule",
		Context:     req.Evaluation.Context,
		EvaluatedAt: time.Now(),
		RequestID:   uuid.New().String(),
	}
	if decision := sc.evaluatePolicyRules(&req.Policy, &req.Evaluation, result); decision != "" {
		result.Decision = decision
	}
	c.JSON(http.StatusOK, result)
}

// BindRole creates a role binding in the caller's workspace.
func (sc *SpireController) BindRole(c *gin.Context) {
	db, ws, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	var binding SpireRoleBinding
	if err := c.ShouldBindJSON(&binding); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	binding.ID = 0
	binding.WorkspaceID = ws
	if err := db.Create(&binding).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	sc.spireAuditLog(c, "role.bind", binding.Resource, "allow", fmt.Sprintf("Role %s bound to %s", binding.Role, binding.Subject), nil)
	c.JSON(http.StatusCreated, binding)
}

// UnbindRole removes a role binding of the caller's workspace.
func (sc *SpireController) UnbindRole(c *gin.Context) {
	db, _, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	subject, role := c.Query("subject"), c.Query("role")
	if err := db.Where("subject = ? AND role = ?", subject, role).Delete(&SpireRoleBinding{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	sc.spireAuditLog(c, "role.unbind", "", "allow", fmt.Sprintf("Role %s unbound from %s", role, subject), nil)
	c.JSON(http.StatusOK, gin.H{"message": "Role binding removed"})
}

// ListRoleBindings lists the caller's workspace's role bindings.
func (sc *SpireController) ListRoleBindings(c *gin.Context) {
	db, _, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	var bindings []SpireRoleBinding
	q := db.Model(&SpireRoleBinding{})
	if s := c.Query("subject"); s != "" {
		q = q.Where("subject ILIKE ?", "%"+s+"%")
	}
	if r := c.Query("role"); r != "" {
		q = q.Where("role = ?", r)
	}
	if err := q.Find(&bindings).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, bindings)
}

// GetAuditLogs returns paginated audit logs of the caller's workspace.
func (sc *SpireController) GetAuditLogs(c *gin.Context) {
	db, _, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	var logs []SpireAuditLog
	q := db.Model(&SpireAuditLog{}).Order("timestamp DESC")
	if s := c.Query("subject"); s != "" {
		q = q.Where("subject ILIKE ?", "%"+s+"%")
	}
	if a := c.Query("action"); a != "" {
		q = q.Where("action = ?", a)
	}
	if d := c.Query("decision"); d != "" {
		q = q.Where("decision = ?", d)
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 200 {
		limit = 100
	}
	if err := q.Offset((page - 1) * limit).Limit(limit).Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"logs": logs, "page": page, "limit": limit})
}

// ExportAuditLogs exports the caller's workspace's audit logs as JSON,
// bounded by a required time window.
func (sc *SpireController) ExportAuditLogs(c *gin.Context) {
	db, _, ok := sc.scopedDB(c)
	if !ok {
		return
	}
	const maxExportRows = 10000
	from, to := c.Query("from"), c.Query("to")
	if from == "" || to == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "from and to (RFC3339) query params are required"})
		return
	}
	fromTS, err := time.Parse(time.RFC3339, from)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid 'from' timestamp; expected RFC3339"})
		return
	}
	toTS, err := time.Parse(time.RFC3339, to)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid 'to' timestamp; expected RFC3339"})
		return
	}
	var logs []SpireAuditLog
	if err := db.Model(&SpireAuditLog{}).
		Where("timestamp >= ? AND timestamp <= ?", fromTS, toTS).
		Order("timestamp DESC").Limit(maxExportRows).Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Disposition", "attachment; filename=spire-audit-logs.json")
	c.JSON(http.StatusOK, logs)
}

// ===== POLICY ENGINE INTERNALS =====

// evaluatePolicy evaluates against the active policies db (already scoped
// to the caller's workspace) returns.
func (sc *SpireController) evaluatePolicy(db *gorm.DB, eval *SpirePolicyEvaluation, requestID string) *SpirePolicyResult {
	result := &SpirePolicyResult{
		Decision:    "deny",
		Reason:      "No matching policy found",
		Context:     eval.Context,
		EvaluatedAt: time.Now(),
		RequestID:   requestID,
	}
	var policies []SpirePolicy
	preloadRules(db).Where("active = ?", true).Order("created_at ASC").Find(&policies)
	for _, policy := range policies {
		if decision := sc.evaluatePolicyRules(&policy, eval, result); decision != "" {
			result.Decision = decision
			break
		}
	}
	return result
}

func (sc *SpireController) evaluatePolicyRules(policy *SpirePolicy, eval *SpirePolicyEvaluation, result *SpirePolicyResult) string {
	for _, rule := range policy.Rules {
		r := rule
		if sc.matchRule(&r, eval) {
			result.MatchedRule = &r
			result.Reason = fmt.Sprintf("Matched rule '%s' in policy '%s'", rule.Name, policy.Name)
			return rule.Effect
		}
	}
	return ""
}

func (sc *SpireController) matchRule(rule *SpirePolicyRule, eval *SpirePolicyEvaluation) bool {
	if !sc.matchSubjects(rule.Subjects, eval.Subject) {
		return false
	}
	if !sc.matchResources(rule.Resources, eval.Resource) {
		return false
	}
	if !sc.matchActions(rule.Actions, eval.Action) {
		return false
	}
	return sc.matchConditions(rule.Conditions, eval)
}

func (sc *SpireController) matchSubjects(subjects []SpirePolicySubject, subject string) bool {
	if len(subjects) == 0 {
		return true
	}
	for _, s := range subjects {
		if s.Value == subject || s.Value == "*" || spireMatchPattern(s.Pattern, subject) {
			return true
		}
	}
	return false
}

func (sc *SpireController) matchResources(resources []SpirePolicyResource, resource string) bool {
	if len(resources) == 0 {
		return true
	}
	for _, r := range resources {
		if r.Value == resource || r.Value == "*" || spireMatchPattern(r.Pattern, resource) {
			return true
		}
	}
	return false
}

func (sc *SpireController) matchActions(actions []SpirePolicyAction, action string) bool {
	if len(actions) == 0 {
		return true
	}
	for _, a := range actions {
		if a.Value == action || a.Value == "*" {
			return true
		}
	}
	return false
}

func (sc *SpireController) matchConditions(conditions []SpirePolicyCondition, eval *SpirePolicyEvaluation) bool {
	for _, cond := range conditions {
		if !sc.evaluateCondition(&cond, eval) {
			return false
		}
	}
	return true
}

func (sc *SpireController) evaluateCondition(cond *SpirePolicyCondition, eval *SpirePolicyEvaluation) bool {
	switch cond.Type {
	case "time":
		switch cond.Operator {
		case "after":
			if t, err := time.Parse(time.RFC3339, cond.Value); err == nil {
				return eval.Timestamp.After(t)
			}
		case "before":
			if t, err := time.Parse(time.RFC3339, cond.Value); err == nil {
				return eval.Timestamp.Before(t)
			}
		}
		return true
	case "attribute":
		val, exists := eval.Context[cond.Key]
		if !exists {
			return false
		}
		strVal := fmt.Sprintf("%v", val)
		switch cond.Operator {
		case "eq":
			return strVal == cond.Value
		case "ne":
			return strVal != cond.Value
		case "regex":
			if m, err := regexp.MatchString(cond.Value, strVal); err == nil {
				return m
			}
		case "in":
			for _, v := range strings.Split(cond.Value, ",") {
				if strings.TrimSpace(v) == strVal {
					return true
				}
			}
		}
		return false
	}
	return true
}

func (sc *SpireController) validatePolicy(policy *SpirePolicy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	if len(policy.Rules) == 0 {
		return fmt.Errorf("policy must have at least one rule")
	}
	for _, rule := range policy.Rules {
		if rule.Effect != "allow" && rule.Effect != "deny" {
			return fmt.Errorf("rule effect must be 'allow' or 'deny'")
		}
	}
	return nil
}

// spireAuditLog records a policy-engine decision for the caller's workspace.
func (sc *SpireController) spireAuditLog(c *gin.Context, action, resource, decision, reason string, requestID *string) {
	tc, err := tenancy.From(c)
	if err != nil {
		return
	}
	rid := uuid.New().String()
	if requestID != nil {
		rid = *requestID
	}
	sc.db.Create(&SpireAuditLog{
		RequestID: rid, WorkspaceID: tc.WorkspaceID.String(),
		Subject: tc.PrincipalID.String(), Resource: resource,
		Action: action, Decision: decision, Reason: reason,
		Context:   map[string]interface{}{},
		IPAddress: c.ClientIP(), UserAgent: c.GetHeader("User-Agent"),
		Timestamp: time.Now(),
	})
}

// ===== OIDC PROVIDER INTERNALS =====

// tokenActive reports whether the token jti was issued for ws and is not
// revoked.
func (p *spireOIDCProvider) tokenActive(ws uuid.UUID, jti string) bool {
	db, err := tenancy.DBContext(workspaceCtx(ws), p.db)
	if err != nil {
		return false
	}
	var record SpireOIDCToken
	if err := db.Where("jwt_id = ?", jti).First(&record).Error; err != nil {
		return false
	}
	return !record.Revoked
}

func (p *spireOIDCProvider) createToken(ws uuid.UUID, subject, spiffeID string, audience []string, scope string) (string, error) {
	now := time.Now()
	jti := uuid.New().String()
	claims := spireTokenClaims{
		WorkspaceID: ws.String(),
		Subject:     subject,
		Issuer:      p.cfg.IssuerURL,
		Audience:    audience,
		ExpiresAt:   now.Add(p.cfg.TokenExpiry).Unix(),
		IssuedAt:    now.Unix(),
		NotBefore:   now.Unix(),
		JWTID:       jti,
		SPIFFEID:    spiffeID,
		Claims:      map[string]interface{}{"scope": scope},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.keyID
	tokenString, err := token.SignedString(p.privateKey)
	if err != nil {
		return "", err
	}
	if err := p.db.Create(&SpireOIDCToken{
		WorkspaceID: ws, JWTID: jti, Subject: subject, SPIFFEID: spiffeID,
		TokenType: "Bearer", Audience: audience[0], Scope: scope,
		ExpiresAt: time.Unix(claims.ExpiresAt, 0), CreatedAt: now, Revoked: false,
	}).Error; err != nil {
		return "", err
	}
	return tokenString, nil
}

func (p *spireOIDCProvider) validateToken(tokenString string) (*spireTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &spireTokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return p.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*spireTokenClaims); ok && token.Valid && claims.WorkspaceID != "" {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

func (p *spireOIDCProvider) createJWTSVID(ws uuid.UUID, spiffeID string, audience []string) (string, error) {
	now := time.Now()
	jti := uuid.New().String()
	claims := spireJWTSVIDClaims{
		WorkspaceID: ws.String(),
		Subject:     spiffeID, Audience: audience, Issuer: p.cfg.IssuerURL,
		ExpiresAt: now.Add(p.cfg.TokenExpiry).Unix(), IssuedAt: now.Unix(), NotBefore: now.Unix(),
		JWTID: jti, SPIFFEID: spiffeID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.keyID
	token.Header["typ"] = "JWT"
	tokenString, err := token.SignedString(p.privateKey)
	if err != nil {
		return "", err
	}
	if err := p.db.Create(&SpireOIDCToken{
		WorkspaceID: ws, JWTID: jti, Subject: spiffeID, SPIFFEID: spiffeID,
		TokenType: "JWT-SVID", Audience: audience[0],
		ExpiresAt: time.Unix(claims.ExpiresAt, 0), CreatedAt: now, Revoked: false,
	}).Error; err != nil {
		return "", err
	}
	return tokenString, nil
}

func (p *spireOIDCProvider) validateJWTSVID(tokenString string) (*spireJWTSVIDClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &spireJWTSVIDClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return p.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*spireJWTSVIDClaims); ok && token.Valid && claims.WorkspaceID != "" {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid JWT-SVID")
}

func (p *spireOIDCProvider) exchangeAWSToken(claims *spireJWTSVIDClaims, req *spireCloudTokenRequest) (*spireCloudTokenResponse, error) {
	if req.RoleARN == "" {
		return nil, fmt.Errorf("role_arn is required for AWS token exchange")
	}
	// TODO: Implement STS AssumeRoleWithWebIdentity using the validated JWT-SVID.
	return nil, fmt.Errorf("AWS cloud token exchange is not yet implemented — configure STS AssumeRoleWithWebIdentity integration")
}

func (p *spireOIDCProvider) exchangeAzureToken(claims *spireJWTSVIDClaims, req *spireCloudTokenRequest) (*spireCloudTokenResponse, error) {
	// TODO: Implement Azure AD confidential client token exchange using the validated JWT-SVID.
	return nil, fmt.Errorf("Azure cloud token exchange is not yet implemented — configure Azure AD token endpoint integration")
}

func (p *spireOIDCProvider) exchangeGCPToken(claims *spireJWTSVIDClaims, req *spireCloudTokenRequest) (*spireCloudTokenResponse, error) {
	// TODO: Implement GCP STS token exchange using the validated JWT-SVID.
	return nil, fmt.Errorf("GCP cloud token exchange is not yet implemented — configure GCP STS endpoint integration")
}

// ===== HELPERS =====

func spireMatchPattern(pattern, value string) bool {
	if pattern == "" {
		return false
	}
	if m, err := regexp.MatchString(pattern, value); err == nil {
		return m
	}
	return false
}

func spireEncodeBase64URL(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func spireGetenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
