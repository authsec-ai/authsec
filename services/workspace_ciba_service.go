package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/internal/tokens"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// clientContext holds the resolved (workspace_id, resource_server_id, audience)
// for a given OAuth client_id string. Used by the workspace-plane CIBA stack
// to look up workspace when no explicit workspace_id is present in the request.
type clientContext struct {
	WorkspaceID uuid.UUID
	RSID        uuid.UUID
	RSAudience  string
	ClientUUID  uuid.UUID // mcp_oauth_clients.id (UUID PK)
}

// TenantCIBAAuthService handles CIBA authentication for tenant users
type TenantCIBAAuthService struct {
	adminWorkspaceRepo *database.AdminWorkspaceRepository
	pushService        *PushNotificationService
	nativeIssuer       *tokens.NativeIssuer // nil when XAACiba=false
	pollingInterval    int
	requestExpiry      time.Duration
}

// NewTenantCIBAAuthService creates a new tenant CIBA authentication service
func NewTenantCIBAAuthService(
	pushService *PushNotificationService,
) *TenantCIBAAuthService {
	svc := &TenantCIBAAuthService{
		adminWorkspaceRepo: database.NewAdminWorkspaceRepository(config.GetDatabase()),
		pushService:        pushService,
		pollingInterval:    5,
		requestExpiry:      5 * time.Minute,
	}
	if config.AppConfig != nil && config.AppConfig.XAACiba && config.DB != nil {
		issuerURL := config.AppConfig.OAuthBaseURL()
		svc.nativeIssuer = tokens.NewNativeIssuer(config.DB, tokens.NativeKeys(), issuerURL)
	}
	return svc
}

// generateAuthReqID generates a unique authentication request ID
func (s *TenantCIBAAuthService) generateAuthReqID() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// ErrCIBAResourceRequired is returned when a client is approved for more than one
// resource server and the caller did not disambiguate with a `resource` parameter.
// Silently picking the first match would bind the CIBA flow to the wrong RS,
// workspace, and audience — a correctness/security bug — so we fail explicitly.
var ErrCIBAResourceRequired = fmt.Errorf("resource parameter required: client is approved for multiple resource servers")

// lookupClientContext resolves (workspace_id, resource_server_id, resource_uri)
// for a client_id string via mcp_oauth_clients → resource_server_client_registrations → resource_servers.
//
// resourceURI (RFC 8707 `resource`) disambiguates when the client is approved for
// more than one RS:
//   - non-empty → resolve THAT resource and require an approved (rs, client) reg;
//   - empty + exactly one approved reg → use it;
//   - empty + multiple approved regs → ErrCIBAResourceRequired (never guess).
func (s *TenantCIBAAuthService) lookupClientContext(clientIDStr, resourceURI string) (clientContext, error) {
	if config.DB == nil {
		return clientContext{}, fmt.Errorf("database not available")
	}

	// Step 1: resolve mcp_oauth_clients.id from client_id string.
	var oauthClient models.MCPOAuthClient
	if err := config.DB.
		Where("client_id = ?", clientIDStr).
		First(&oauthClient).Error; err != nil {
		return clientContext{}, fmt.Errorf("client not found: %w", err)
	}

	var reg models.ResourceServerClientRegistration

	if resourceURI != "" {
		// Caller specified the target resource — resolve that RS, then require an
		// approved registration binding this client to exactly that RS.
		var rs models.ResourceServer
		if err := config.DB.Where("resource_uri = ?", resourceURI).First(&rs).Error; err != nil {
			return clientContext{}, fmt.Errorf("unknown resource %q: %w", resourceURI, err)
		}
		if err := config.DB.
			Where("oauth_client_id = ? AND resource_server_id = ? AND status = ?",
				oauthClient.ID, rs.ID, models.ClientRegStatusApproved).
			First(&reg).Error; err != nil {
			return clientContext{}, fmt.Errorf("client %s is not approved for resource %q: %w", clientIDStr, resourceURI, err)
		}
		return clientContext{
			WorkspaceID: reg.WorkspaceID,
			RSID:        rs.ID,
			RSAudience:  rs.ResourceURI,
			ClientUUID:  oauthClient.ID,
		}, nil
	}

	// No resource hint: tolerate it only when the client maps to exactly one RS.
	var regs []models.ResourceServerClientRegistration
	if err := config.DB.
		Where("oauth_client_id = ? AND status = ?", oauthClient.ID, models.ClientRegStatusApproved).
		Order("created_at ASC").
		Find(&regs).Error; err != nil {
		return clientContext{}, fmt.Errorf("registration lookup failed for client %s: %w", clientIDStr, err)
	}
	if len(regs) == 0 {
		return clientContext{}, fmt.Errorf("no approved registration for client %s", clientIDStr)
	}
	if len(regs) > 1 {
		return clientContext{}, ErrCIBAResourceRequired
	}
	reg = regs[0]

	var rs models.ResourceServer
	if err := config.DB.
		Where("id = ? AND workspace_id = ?", reg.ResourceServerID, reg.WorkspaceID).
		First(&rs).Error; err != nil {
		return clientContext{}, fmt.Errorf("resource server not found: %w", err)
	}

	return clientContext{
		WorkspaceID: reg.WorkspaceID,
		RSID:        rs.ID,
		RSAudience:  rs.ResourceURI,
		ClientUUID:  oauthClient.ID,
	}, nil
}

// InitiateTenantCIBAAuth initiates CIBA authentication for tenant users
func (s *TenantCIBAAuthService) InitiateTenantCIBAAuth(req *models.TenantCIBAInitiateRequest) (*models.TenantCIBAInitiateResponse, error) {
	// Step 1: Resolve client context (workspace + RS) from client_id + optional
	// resource selector. Ambiguous multi-RS clients without a resource are rejected.
	ctx, err := s.lookupClientContext(req.ClientID, req.Resource)
	if err != nil {
		desc := "Client not found or not mapped to workspace"
		if err == ErrCIBAResourceRequired {
			desc = err.Error()
		}
		return &models.TenantCIBAInitiateResponse{
			Error:            models.TenantCIBAErrorInvalidClient,
			ErrorDescription: desc,
		}, nil
	}

	workspaceUUID := ctx.WorkspaceID
	clientUUID := ctx.ClientUUID

	tenantDB := config.DB

	// Step 2: Look up user in workspace database
	workspaceRepo := database.NewTenantDeviceRepository(tenantDB)
	user, err := workspaceRepo.GetTenantUserByEmail(strings.ToLower(req.Email), clientUUID)
	if err != nil {
		return &models.TenantCIBAInitiateResponse{
			Error:            models.TenantCIBAErrorUserNotFound,
			ErrorDescription: fmt.Sprintf("User not found: %s", req.Email),
		}, nil
	}

	// Step 3: Get user's registered push devices — fan-out: primary device first,
	// then remaining active devices (first-responder-wins per Appendix §6).
	devices, err := workspaceRepo.GetTenantDeviceTokensByUserID(user.ID, workspaceUUID)
	if err != nil || len(devices) == 0 {
		return &models.TenantCIBAInitiateResponse{
			Error:            models.TenantCIBAErrorNoDevice,
			ErrorDescription: "User has no registered push notification devices",
		}, nil
	}

	// Step 4: Generate auth_req_id
	authReqID, err := s.generateAuthReqID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate auth_req_id: %w", err)
	}

	// Default scopes if not provided
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	// Step 5: Create CIBA authentication request
	cibaRequest := &models.TenantCIBAAuthRequest{
		AuthReqID:      authReqID,
		UserID:         user.ID,
		WorkspaceID:    workspaceUUID,
		UserEmail:      strings.ToLower(req.Email),
		ClientID:       &clientUUID,
		DeviceTokenID:  devices[0].ID,
		BindingMessage: req.BindingMessage,
		Scopes:         models.JSONStringArray(scopes),
		Status:         "pending",
	}

	if err := workspaceRepo.CreateTenantCIBAAuthRequest(cibaRequest); err != nil {
		return nil, fmt.Errorf("failed to create CIBA request: %w", err)
	}

	// Step 6: Fan-out push notification to all active devices; first responder wins.
	if s.pushService != nil {
		bindingMessage := req.BindingMessage
		if bindingMessage == "" {
			bindingMessage = "Tap to approve sign-in"
		}
		for _, device := range devices {
			if err := s.pushService.SendAuthRequest(
				device.DeviceToken,
				authReqID,
				bindingMessage,
				strings.ToLower(req.Email),
			); err != nil {
				fmt.Printf("Warning: push notification failed for device %s: %v\n", device.ID, err)
			}
		}
	}

	return &models.TenantCIBAInitiateResponse{
		AuthReqID: authReqID,
		ExpiresIn: int(s.requestExpiry.Seconds()),
		Interval:  s.pollingInterval,
		Message:   "Push notification sent to your registered device",
	}, nil
}

// RespondToTenantCIBA handles user response to CIBA authentication request.
// The atomic conditional update (§6) ensures first-responder-wins: only the
// first call that flips status from pending → approved/denied is authoritative.
func (s *TenantCIBAAuthService) RespondToTenantCIBA(authReqID string, approved bool, biometricVerified bool, userID, workspaceID uuid.UUID) (*models.TenantCIBARespondResponse, error) {
	tenantDB := config.DB
	workspaceRepo := database.NewTenantDeviceRepository(tenantDB)

	// Step 1: Retrieve and validate the CIBA request
	request, err := workspaceRepo.GetTenantCIBAAuthRequestByAuthReqID(authReqID, workspaceID)
	if err != nil {
		return &models.TenantCIBARespondResponse{
			Success: false,
			Message: "Authentication request not found or expired",
		}, nil
	}

	// Step 2: Verify user ownership (caller-identity binding — plan spec (e))
	if request.UserID != userID {
		return &models.TenantCIBARespondResponse{
			Success: false,
			Message: "You are not authorized to respond to this request",
		}, nil
	}

	// Step 3: Fast-path reject for an already-terminal request (cheap, advisory).
	// The authoritative guard is the conditional UPDATE below — never this check.
	if !request.IsPending() {
		return &models.TenantCIBARespondResponse{
			Success: false,
			Message: "Request is no longer pending",
		}, nil
	}

	status := "approved"
	if !approved {
		status = "denied"
	}

	// Step 4: Atomic first-responder-wins transition (Appendix §6). Only the
	// caller that flips pending → status wins; a concurrent responder on another
	// device gets won=false and the recorded outcome, idempotently — no flip,
	// no error.
	won, err := workspaceRepo.UpdateTenantCIBAAuthRequestStatusIf(
		authReqID,
		workspaceID,
		"pending",
		status,
		approved,
		biometricVerified,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update CIBA request: %w", err)
	}
	if !won {
		// Someone else already responded first. Report the recorded terminal
		// outcome rather than pretending this responder set it.
		current, lerr := workspaceRepo.GetTenantCIBAAuthRequestByAuthReqID(authReqID, workspaceID)
		recorded := "responded to"
		if lerr == nil && current != nil {
			recorded = current.Status
		}
		return &models.TenantCIBARespondResponse{
			Success: false,
			Message: fmt.Sprintf("Request was already %s", recorded),
		}, nil
	}

	return &models.TenantCIBARespondResponse{
		Success: true,
		Message: fmt.Sprintf("Authentication %s", status),
	}, nil
}

// PollTenantCIBAToken polls for token completion
func (s *TenantCIBAAuthService) PollTenantCIBAToken(req *models.TenantCIBATokenRequest) (*models.TenantCIBATokenResponse, error) {
	// Resolve client context (workspace + RS) from client_id + optional resource.
	// The resource MUST match what initiate used, else polling could bind a
	// different RS/audience than the one the user approved.
	clientCtx, err := s.lookupClientContext(req.ClientID, req.Resource)
	if err != nil {
		desc := "Client not found or not mapped to workspace"
		if err == ErrCIBAResourceRequired {
			desc = err.Error()
		}
		return &models.TenantCIBATokenResponse{
			Error:            models.TenantCIBAErrorInvalidClient,
			ErrorDescription: desc,
		}, nil
	}

	workspaceUUID := clientCtx.WorkspaceID
	tenantDB := config.DB
	workspaceRepo := database.NewTenantDeviceRepository(tenantDB)

	// Update last polled timestamp asynchronously
	go func() {
		workspaceRepo.UpdateTenantCIBAAuthRequestLastPolled(req.AuthReqID, workspaceUUID)
	}()

	// Retrieve the CIBA request
	request, err := workspaceRepo.GetTenantCIBAAuthRequestByAuthReqID(req.AuthReqID, workspaceUUID)
	if err != nil {
		return &models.TenantCIBATokenResponse{
			Error:            models.TenantCIBAErrorExpiredToken,
			ErrorDescription: "Authentication request not found",
		}, nil
	}

	if request.IsExpired() {
		return &models.TenantCIBATokenResponse{
			Error:            models.TenantCIBAErrorExpiredToken,
			ErrorDescription: "Authentication request has expired",
		}, nil
	}

	if request.Status == "pending" {
		return &models.TenantCIBATokenResponse{
			Error:            models.TenantCIBAErrorAuthorizationPending,
			ErrorDescription: "User has not responded to authentication request",
		}, nil
	}

	if request.Status == "denied" {
		return &models.TenantCIBATokenResponse{
			Error:            models.TenantCIBAErrorAccessDenied,
			ErrorDescription: "User denied the authentication request",
		}, nil
	}

	if request.Status == "approved" {
		// Atomically claim the approved→consumed transition BEFORE minting, so
		// two concurrent polls cannot both issue a token (§6 single-mint). Only
		// the poll that wins the conditional UPDATE proceeds to generate a token.
		won, cerr := workspaceRepo.UpdateTenantCIBAAuthRequestStatusIf(
			req.AuthReqID, workspaceUUID, "approved", "consumed", true, request.BiometricVerified,
		)
		if cerr != nil {
			return nil, fmt.Errorf("failed to consume CIBA request: %w", cerr)
		}
		if !won {
			// A concurrent poll already consumed it — slow poll, don't re-mint.
			return &models.TenantCIBATokenResponse{
				Error:            models.TenantCIBAErrorExpiredToken,
				ErrorDescription: "Authentication request already consumed",
			}, nil
		}

		token, err := s.generateJWTToken(
			request.UserID, workspaceUUID,
			clientCtx.ClientUUID, clientCtx.RSID, clientCtx.RSAudience,
			req.ClientID, request.UserEmail, request.Scopes,
		)
		if err != nil {
			// Minting failed AFTER we claimed approved→consumed. Revert to
			// 'approved' (best-effort) so the next poll can retry rather than
			// permanently stranding the request. Single-mint is preserved: only
			// the goroutine that won the consume can revert it.
			if _, rerr := workspaceRepo.UpdateTenantCIBAAuthRequestStatusIf(
				req.AuthReqID, workspaceUUID, "consumed", "approved", true, request.BiometricVerified,
			); rerr != nil {
				fmt.Printf("Warning: failed to revert CIBA request %s to approved after mint error: %v\n", req.AuthReqID, rerr)
			}
			return nil, fmt.Errorf("failed to generate JWT token: %w", err)
		}

		workspaceRepo.UpdateTenantUserLastLogin(request.UserID)

		ttl := 24 * 60 * 60
		if s.nativeIssuer != nil {
			ttl = 3600 // native CIBA tokens are short-lived (1h)
		}

		return &models.TenantCIBATokenResponse{
			AccessToken: token,
			TokenType:   "Bearer",
			ExpiresIn:   ttl,
			Scope:       strings.Join(request.Scopes, " "),
		}, nil
	}

	return &models.TenantCIBATokenResponse{
		Error:            models.TenantCIBAErrorExpiredToken,
		ErrorDescription: "Invalid request state",
	}, nil
}

// generateJWTToken mints an access token for an approved CIBA request.
// When XAACiba=true it uses the NativeIssuer (RS256, tf=ciba, short-lived,
// introspectable at /oauth/introspect). Otherwise falls back to the HMAC path.
func (s *TenantCIBAAuthService) generateJWTToken(
	userID, workspaceID, clientUUID, rsID uuid.UUID,
	rsAudience, clientIDStr, email string,
	scopes []string,
) (string, error) {
	if s.nativeIssuer != nil {
		claims := tokens.NativeClaims{
			Family:           models.TokenFamilyCIBA,
			WorkspaceID:      workspaceID,
			SubjectType:      "user",
			SubjectID:        userID,
			ClientID:         clientIDStr,
			ResourceServerID: rsID,
			Audience:         rsAudience,
			Scope:            strings.Join(scopes, " "),
			TTL:              1 * time.Hour,
		}
		tokenStr, _, err := s.nativeIssuer.Issue(context.Background(), claims)
		return tokenStr, err
	}

	// Legacy HMAC path (frozen/deprecated when XAACiba=false).
	return config.TokenService.GenerateTenantCIBAToken(
		userID,
		workspaceID,
		clientUUID,
		email,
		scopes,
		24*time.Hour,
	)
}

// RegisterTenantDevice registers a device for push notifications in tenant context
func (s *TenantCIBAAuthService) RegisterTenantDevice(req *models.TenantDeviceTokenRegistrationRequest, userID, workspaceID uuid.UUID) (*models.TenantDeviceTokenRegistrationResponse, error) {
	tenantDB := config.DB
	workspaceRepo := database.NewTenantDeviceRepository(tenantDB)

	existingDevice, err := workspaceRepo.GetTenantDeviceTokenByToken(req.DeviceToken, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("failed to check device token: %w", err)
	}

	if existingDevice != nil {
		existingDevice.DeviceName = req.DeviceName
		existingDevice.DeviceModel = req.DeviceModel
		existingDevice.AppVersion = req.AppVersion
		existingDevice.OSVersion = req.OSVersion
		existingDevice.IsActive = true

		if err := workspaceRepo.UpdateTenantDeviceToken(existingDevice); err != nil {
			return nil, fmt.Errorf("failed to update device token: %w", err)
		}

		return &models.TenantDeviceTokenRegistrationResponse{
			Success:  true,
			DeviceID: existingDevice.ID.String(),
			Message:  "Device updated successfully",
		}, nil
	}

	deviceToken := &models.TenantDeviceToken{
		ID:          uuid.New(),
		UserID:      userID,
		WorkspaceID: workspaceID,
		DeviceToken: req.DeviceToken,
		Platform:    req.Platform,
		DeviceName:  req.DeviceName,
		DeviceModel: req.DeviceModel,
		AppVersion:  req.AppVersion,
		OSVersion:   req.OSVersion,
		IsActive:    true,
	}

	if err := workspaceRepo.CreateTenantDeviceToken(deviceToken); err != nil {
		return nil, fmt.Errorf("failed to register device: %w", err)
	}

	return &models.TenantDeviceTokenRegistrationResponse{
		Success:  true,
		DeviceID: deviceToken.ID.String(),
		Message:  "Device registered successfully",
	}, nil
}
