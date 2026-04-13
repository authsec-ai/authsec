package models

import "time"

// AuthRequestContext is a short-lived bridge between /oauth/authorize and hmgr login/consent.
// Stored before redirecting to Hydra, recovered in hmgr via PAR request_uri or legacy context_id.
// TTL ~10 minutes, one-time consumption.
//
// Lifecycle:
//  1. /oauth/authorize creates with State as PK plus a server-generated ContextID
//  2. /oauth/authorize pushes the validated request to Hydra via PAR and stores HydraRequestURI
//  3. hmgr GetLoginPageDataHandler parses request_uri from Hydra's request_url and binds via
//     HydraRequestURI; legacy pre-PAR flows may still bind via ContextID for one release cycle
//  3. hmgr ConsentHandler marks ConsentCompleted=true, includes context_id in Hydra session claims
//  4. /oauth/token introspects the access token via Hydra admin, extracts context_id from session,
//     looks up by context_id (requires ConsentCompleted=true, Consumed=false)
//  5. /oauth/token sets Consumed=true after successful exchange
//
// Hard rules:
//   - ContextID is server-generated (uuid), never client-supplied
//   - PAR/request_uri is the canonical login bridge binding key
//   - Token exchange MUST find a valid context or reject — no passthrough on miss
type AuthRequestContext struct {
	State            string    `json:"state" gorm:"type:varchar(255);primary_key"`
	ContextID        string    `json:"context_id" gorm:"type:varchar(255);not null;uniqueIndex"` // Server-generated UUID, used for all binding
	HydraClientID    string    `json:"hydra_client_id" gorm:"type:varchar(255);not null;index"`
	HydraRequestURI  *string   `json:"hydra_request_uri,omitempty" gorm:"type:varchar(512)"`
	ResourceServerID string    `json:"resource_server_id" gorm:"type:uuid;not null"`
	TenantID         string    `json:"tenant_id" gorm:"type:uuid;not null"`
	ResourceURI      string    `json:"resource_uri" gorm:"type:text;not null"`
	RedirectURI      string    `json:"redirect_uri" gorm:"type:text"`
	RequestedScopes  string    `json:"requested_scopes" gorm:"type:text"`
	LoginChallenge   *string   `json:"login_challenge" gorm:"type:text;uniqueIndex"`
	ConsentCompleted bool      `json:"consent_completed" gorm:"default:false"`
	ExpiresAt        time.Time `json:"expires_at" gorm:"not null"`
	Consumed         bool      `json:"consumed" gorm:"default:false"`
	CreatedAt        time.Time `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`
}

func (AuthRequestContext) TableName() string {
	return "auth_request_contexts"
}
