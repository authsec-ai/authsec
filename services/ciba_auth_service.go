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
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// CIBAAuthService handles CIBA authentication business logic
// Mirrors DeviceAuthService but uses push notifications instead of device codes
type CIBAAuthService struct {
	db              *database.DBConnection
	cibaRepo        *database.CIBAAuthRepository
	userRepo        *database.UserRepository
	workspaceRepo   *database.AdminWorkspaceRepository
	pushService     *PushNotificationService
	pollingInterval int
	requestExpiry   time.Duration
}

// NewCIBAAuthService creates a new CIBA authentication service
func NewCIBAAuthService(
	db *database.DBConnection,
	pushService *PushNotificationService,
) *CIBAAuthService {
	return &CIBAAuthService{
		db:              db,
		cibaRepo:        database.NewCIBAAuthRepository(db),
		userRepo:        database.NewUserRepository(db),
		workspaceRepo:   database.NewAdminWorkspaceRepository(db),
		pushService:     pushService,
		pollingInterval: 5,               // 5 seconds minimum between polls
		requestExpiry:   5 * time.Minute, // Requests expire in 5 minutes
	}
}

// generateAuthReqID generates a unique authentication request ID
func (s *CIBAAuthService) generateAuthReqID() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// InitiateCIBAAuth initiates CIBA authentication flow
// This is like InitiateDeviceFlow but sends push notification instead of returning user_code
func (s *CIBAAuthService) InitiateCIBAAuth(req *models.CIBAInitiateRequest) (*models.CIBAInitiateResponse, error) {
	// Step 1: Resolve the one workspace this request is for, then look the
	// user up inside it only. An email alone never selects a workspace.
	workspaceID, clientID, err := s.resolveRequestWorkspace(req.WorkspaceID, req.ClientID)
	if err != nil {
		return &models.CIBAInitiateResponse{
			Error:            models.CIBAErrorInvalidRequest,
			ErrorDescription: err.Error(),
		}, nil
	}
	user, err := s.userRepo.GetUserByEmailAndTenant(database.WithWorkspace(context.Background(), workspaceID), req.LoginHint)
	if err != nil || user == nil || !user.Active {
		return &models.CIBAInitiateResponse{
			Error:            models.CIBAErrorUserNotFound,
			ErrorDescription: fmt.Sprintf("User not found: %s", req.LoginHint),
		}, nil
	}

	// Step 2: Get user's registered push devices
	wsCtx := database.WithWorkspace(context.Background(), workspaceID)
	devices, err := s.cibaRepo.GetDeviceTokensByUserID(wsCtx, user.ID)
	if err != nil || len(devices) == 0 {
		return &models.CIBAInitiateResponse{
			Error:            models.CIBAErrorNoDevice,
			ErrorDescription: "User has no registered push notification devices",
		}, nil
	}

	// Use first active device
	device := devices[0]

	// Step 3: Generate auth_req_id
	authReqID, err := s.generateAuthReqID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate auth_req_id: %w", err)
	}

	// Default scopes if not provided
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	// Step 5: Create CIBA auth request in database
	authRequest := &models.CIBAAuthRequest{
		ID:             uuid.New(),
		AuthReqID:      authReqID,
		UserID:         user.ID,
		WorkspaceID:    user.WorkspaceID,
		UserEmail:      user.Email,
		ClientID:       clientID,
		DeviceTokenID:  device.ID,
		BindingMessage: req.BindingMessage,
		Scopes:         scopes,
		Status:         "pending",
		ExpiresAt:      time.Now().Add(s.requestExpiry).Unix(),
	}

	if err := s.cibaRepo.CreateCIBAAuthRequest(wsCtx, authRequest); err != nil {
		return nil, fmt.Errorf("failed to create CIBA request: %w", err)
	}

	// Step 6: Send push notification
	bindingMsg := req.BindingMessage
	if bindingMsg == "" {
		bindingMsg = "Authentication request"
	}

	if s.pushService != nil {
		err = s.pushService.SendAuthRequest(
			device.DeviceToken,
			authReqID,
			bindingMsg,
			user.Email,
		)
		if err != nil {
			// Log error but don't fail - request is still valid
			fmt.Printf("Failed to send push notification: %v\n", err)
		} else {
			// Update device last_used
			s.cibaRepo.UpdateDeviceTokenLastUsed(wsCtx, device.ID)
		}
	}

	return &models.CIBAInitiateResponse{
		AuthReqID: authReqID,
		ExpiresIn: int(s.requestExpiry.Seconds()),
		Interval:  s.pollingInterval,
		Message:   "Push notification sent to user's device",
	}, nil
}

// RespondToCIBA handles user's approve/deny response from mobile app.
// responderUserID and responderWorkspaceID are extracted from the caller's JWT
// and must match the challenged user on the request — prevents a different user
// or a user from a foreign workspace from approving.
func (s *CIBAAuthService) RespondToCIBA(req *models.CIBARespondRequest, responderUserID uuid.UUID, responderWorkspaceID uuid.UUID) (*models.CIBARespondResponse, error) {
	// Get CIBA request: only the responder's workspace is searched.
	wsCtx := database.WithWorkspace(context.Background(), responderWorkspaceID)
	authReq, err := s.cibaRepo.GetCIBAAuthRequestByID(wsCtx, req.AuthReqID)
	if err != nil {
		return nil, fmt.Errorf("invalid auth_req_id")
	}

	// Caller-identity binding: only the challenged user may respond.
	if authReq.UserID != responderUserID || authReq.WorkspaceID != responderWorkspaceID {
		return nil, fmt.Errorf("unauthorized: responder identity does not match challenged user")
	}

	// Check if expired. Conditional pending→expired so we never clobber a
	// concurrently-set approved/denied/consumed terminal state.
	if authReq.IsExpired() {
		s.cibaRepo.UpdateCIBAAuthRequestStatusIf(wsCtx, req.AuthReqID, "pending", "expired", false)
		return nil, fmt.Errorf("request expired")
	}

	// Fast-path reject (advisory only; the conditional UPDATE below is authority).
	if authReq.Status != "pending" {
		return nil, fmt.Errorf("request already processed")
	}

	// Update status
	status := "denied"
	message := "Authentication denied"
	if req.Approved {
		status = "approved"
		message = "Authentication approved"
	}

	// Atomic first-responder-wins transition: only the caller that flips
	// pending → status wins; a concurrent responder gets the recorded outcome
	// idempotently (no double-flip).
	won, err := s.cibaRepo.UpdateCIBAAuthRequestStatusIf(wsCtx, req.AuthReqID, "pending", status, req.BiometricVerified)
	if err != nil {
		return nil, fmt.Errorf("failed to update status: %w", err)
	}
	if !won {
		return nil, fmt.Errorf("request already processed")
	}

	return &models.CIBARespondResponse{
		Success: true,
		Message: message,
	}, nil
}

// PollForToken polls for CIBA authentication status and returns token if approved
// This is like PollForToken in DeviceAuthService
func (s *CIBAAuthService) PollForToken(authReqID string, clientIDStr string) (*models.CIBATokenResponse, error) {
	// Get CIBA request by its bearer auth_req_id; its row names the workspace
	// every later statement runs in.
	authReq, err := s.cibaRepo.LookupCIBAAuthRequest(authReqID)
	if err != nil {
		return &models.CIBATokenResponse{
			Error:            models.CIBAErrorExpiredToken,
			ErrorDescription: "Request not found or expired",
		}, nil
	}

	// A request started for a client can only be polled by that client.
	if authReq.ClientID != nil {
		pollClient, cerr := s.lookupClientUUID(clientIDStr)
		if cerr != nil || pollClient != *authReq.ClientID {
			return &models.CIBATokenResponse{
				Error:            models.CIBAErrorInvalidClient,
				ErrorDescription: "client_id does not match the request",
			}, nil
		}
	}

	wsCtx := database.WithWorkspace(context.Background(), authReq.WorkspaceID)

	// Update last polled timestamp
	s.cibaRepo.UpdateLastPolled(wsCtx, authReqID)

	// Check if expired. Conditional pending→expired so a slow poll cannot
	// overwrite an approved/consumed request that a concurrent caller just set.
	if authReq.IsExpired() {
		s.cibaRepo.UpdateCIBAAuthRequestStatusIf(wsCtx, authReqID, "pending", "expired", false)
		return &models.CIBATokenResponse{
			Error:            models.CIBAErrorExpiredToken,
			ErrorDescription: "Request expired",
		}, nil
	}

	// Check status
	switch authReq.Status {
	case "pending":
		// Still waiting for user response
		return &models.CIBATokenResponse{
			Error:            models.CIBAErrorAuthorizationPending,
			ErrorDescription: "User has not responded yet",
		}, nil

	case "denied":
		// User denied
		return &models.CIBATokenResponse{
			Error:            models.CIBAErrorAccessDenied,
			ErrorDescription: "User denied the authentication request",
		}, nil

	case "approved":
		// Atomically claim approved → consumed BEFORE minting so two concurrent
		// polls cannot both issue a token (single-mint, Appendix §6).
		won, cerr := s.cibaRepo.MarkAsConsumedIf(wsCtx, authReqID)
		if cerr != nil {
			return &models.CIBATokenResponse{
				Error:            "server_error",
				ErrorDescription: "Failed to consume request",
			}, nil
		}
		if !won {
			// A concurrent poll already consumed it — don't re-mint.
			return &models.CIBATokenResponse{
				Error:            models.CIBAErrorExpiredToken,
				ErrorDescription: "Request already used",
			}, nil
		}

		// User approved - generate token
		// Get user from tenant database
		user, err := s.userRepo.GetUserByID(wsCtx, authReq.UserID)
		if err != nil {
			// Revert so a retry can mint (best-effort); we own the consume.
			s.cibaRepo.UpdateCIBAAuthRequestStatusIf(wsCtx, authReqID, "consumed", "approved", authReq.BiometricVerified)
			return &models.CIBATokenResponse{
				Error:            "server_error",
				ErrorDescription: "User not found",
			}, nil
		}

		// Get tenant info
		tenant, err := s.workspaceRepo.GetWorkspaceByID(authReq.WorkspaceID.String())
		if err != nil {
			s.cibaRepo.UpdateCIBAAuthRequestStatusIf(wsCtx, authReqID, "consumed", "approved", authReq.BiometricVerified)
			return &models.CIBATokenResponse{
				Error:            "server_error",
				ErrorDescription: "Tenant not found",
			}, nil
		}

		// Generate JWT token (same logic as device flow)
		token, err := s.generateJWTToken(user, tenant, authReq.Scopes)
		if err != nil {
			s.cibaRepo.UpdateCIBAAuthRequestStatusIf(wsCtx, authReqID, "consumed", "approved", authReq.BiometricVerified)
			return &models.CIBATokenResponse{
				Error:            "server_error",
				ErrorDescription: "Failed to generate token",
			}, nil
		}

		return &models.CIBATokenResponse{
			AccessToken: token,
			TokenType:   "Bearer",
			ExpiresIn:   int(cibaSessionLifetime.Seconds()),
			Scope:       strings.Join(authReq.Scopes, " "),
		}, nil

	case "consumed":
		// Token already issued
		return &models.CIBATokenResponse{
			Error:            models.CIBAErrorExpiredToken,
			ErrorDescription: "Request already used",
		}, nil

	case "expired":
		return &models.CIBATokenResponse{
			Error:            models.CIBAErrorExpiredToken,
			ErrorDescription: "Request expired",
		}, nil

	default:
		return &models.CIBATokenResponse{
			Error:            "server_error",
			ErrorDescription: "Unknown status",
		}, nil
	}
}

// RegisterDevice registers a new device for push notifications
func (s *CIBAAuthService) RegisterDevice(userID uuid.UUID, workspaceID uuid.UUID, req *models.DeviceTokenRegistrationRequest) (*models.DeviceTokenRegistrationResponse, error) {
	deviceToken := &models.DeviceToken{
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

	if err := s.cibaRepo.CreateDeviceToken(database.WithWorkspace(context.Background(), workspaceID), deviceToken); err != nil {
		return nil, fmt.Errorf("failed to register device: %w", err)
	}

	return &models.DeviceTokenRegistrationResponse{
		Success:  true,
		DeviceID: deviceToken.ID.String(),
		Message:  "Device registered successfully for push notifications",
	}, nil
}

// cibaSessionLifetime is the lifetime of a token minted by the legacy CIBA
// flow: the normal 24h session, not the year it used to be.
const cibaSessionLifetime = 24 * time.Hour

// resolveRequestWorkspace returns the single active workspace a legacy CIBA
// request is for, from its workspace_id and/or client_id. A client_id must be
// an OAuth client approved in exactly one workspace (or in the named
// workspace_id); when both are given they must agree. Returns the client's
// mcp_oauth_clients.id when a client_id was given.
func (s *CIBAAuthService) resolveRequestWorkspace(workspaceIDStr, clientIDStr string) (uuid.UUID, *uuid.UUID, error) {
	workspaceIDStr = strings.TrimSpace(workspaceIDStr)
	clientIDStr = strings.TrimSpace(clientIDStr)
	if workspaceIDStr == "" && clientIDStr == "" {
		return uuid.Nil, nil, fmt.Errorf("workspace_id or client_id is required")
	}

	var workspaceID uuid.UUID
	if workspaceIDStr != "" {
		id, err := uuid.Parse(workspaceIDStr)
		if err != nil {
			return uuid.Nil, nil, fmt.Errorf("invalid workspace_id")
		}
		workspaceID = id
	}

	var clientUUID *uuid.UUID
	if clientIDStr != "" {
		rows, err := s.db.Query(`
			SELECT DISTINCT c.id, r.workspace_id
			FROM mcp_oauth_clients c
			JOIN resource_server_client_registrations r
			  ON r.oauth_client_id = c.id AND r.status = $2
			WHERE c.client_id = $1`, clientIDStr, models.ClientRegStatusApproved)
		if err != nil {
			return uuid.Nil, nil, fmt.Errorf("client lookup failed")
		}
		defer rows.Close()
		var cid uuid.UUID
		var workspaces []uuid.UUID
		for rows.Next() {
			var ws uuid.UUID
			if err := rows.Scan(&cid, &ws); err != nil {
				return uuid.Nil, nil, fmt.Errorf("client lookup failed")
			}
			workspaces = append(workspaces, ws)
		}
		if err := rows.Err(); err != nil {
			return uuid.Nil, nil, fmt.Errorf("client lookup failed")
		}
		switch {
		case len(workspaces) == 0:
			return uuid.Nil, nil, fmt.Errorf("client_id is not approved in any workspace")
		case workspaceID != uuid.Nil:
			found := false
			for _, ws := range workspaces {
				if ws == workspaceID {
					found = true
					break
				}
			}
			if !found {
				return uuid.Nil, nil, fmt.Errorf("client_id is not approved in workspace_id")
			}
		case len(workspaces) > 1:
			return uuid.Nil, nil, fmt.Errorf("client_id is approved in several workspaces; workspace_id is required")
		default:
			workspaceID = workspaces[0]
		}
		clientUUID = &cid
	}

	var active bool
	if err := s.db.QueryRow(
		`SELECT EXISTS (SELECT 1 FROM workspaces WHERE id = $1 AND COALESCE(status, 'active') = 'active')`,
		workspaceID,
	).Scan(&active); err != nil || !active {
		return uuid.Nil, nil, fmt.Errorf("unknown workspace")
	}
	return workspaceID, clientUUID, nil
}

// lookupClientUUID resolves an OAuth client_id string to mcp_oauth_clients.id.
func (s *CIBAAuthService) lookupClientUUID(clientIDStr string) (uuid.UUID, error) {
	var id uuid.UUID
	if strings.TrimSpace(clientIDStr) == "" {
		return uuid.Nil, fmt.Errorf("client_id is required")
	}
	err := s.db.QueryRow(`SELECT id FROM mcp_oauth_clients WHERE client_id = $1`, strings.TrimSpace(clientIDStr)).Scan(&id)
	return id, err
}

// generateJWTToken generates JWT token (same as DeviceAuthService)
func (s *CIBAAuthService) generateJWTToken(user *models.ExtendedUser, tenant *models.Tenant, scopes []string) (string, error) {
	// Use centralized auth-manager token service
	return config.TokenService.GenerateCIBAToken(
		user.ID,
		tenant.ID,
		user.Email,
		scopes,
		cibaSessionLifetime,
	)
}

// CleanupExpiredRequests runs periodic cleanup
func (s *CIBAAuthService) CleanupExpiredRequests() (int64, error) {
	// Mark expired
	expired, err := s.cibaRepo.ExpireOldRequests()
	if err != nil {
		return 0, fmt.Errorf("failed to expire old requests: %w", err)
	}

	// Delete old ones (older than 24 hours)
	deleted, err := s.cibaRepo.DeleteExpiredRequests(24 * time.Hour)
	if err != nil {
		return expired, fmt.Errorf("failed to delete expired requests: %w", err)
	}

	return expired + deleted, nil
}

// ========================================
// Device Management (Admin APIs)
// ========================================

// GetUserDevices retrieves all registered push devices for a user
func (s *CIBAAuthService) GetUserDevices(userID, workspaceID uuid.UUID) ([]models.DeviceSummary, error) {
	devices, err := s.cibaRepo.GetDeviceTokensByUserID(database.WithWorkspace(context.Background(), workspaceID), userID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve devices: %w", err)
	}

	// Convert to summaries (omit sensitive device token)
	summaries := make([]models.DeviceSummary, len(devices))
	for i, device := range devices {
		summaries[i] = models.DeviceSummary{
			ID:          device.ID.String(),
			DeviceName:  device.DeviceName,
			Platform:    device.Platform,
			DeviceModel: device.DeviceModel,
			AppVersion:  device.AppVersion,
			OSVersion:   device.OSVersion,
			IsActive:    device.IsActive,
			LastUsed:    device.LastUsed,
			CreatedAt:   device.CreatedAt,
		}
	}

	return summaries, nil
}

// DeleteDevice deactivates a user's push notification device
func (s *CIBAAuthService) DeleteDevice(deviceID, userID, workspaceID uuid.UUID) error {
	// Verify device belongs to user and tenant
	wsCtx := database.WithWorkspace(context.Background(), workspaceID)
	device, err := s.cibaRepo.GetDeviceTokenByID(wsCtx, deviceID)
	if err != nil {
		return fmt.Errorf("device not found: %w", err)
	}

	if device.UserID != userID || device.WorkspaceID != workspaceID {
		return fmt.Errorf("device not found or unauthorized")
	}

	// Deactivate device
	if err := s.cibaRepo.DeactivateDeviceToken(wsCtx, deviceID, userID); err != nil {
		return fmt.Errorf("failed to deactivate device: %w", err)
	}

	return nil
}
