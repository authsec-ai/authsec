package models

import "time"

// TrustedIssuer is an external OAuth/OIDC issuer whose tokens may be accepted
// as the `subject_token` or `actor_token` in an RFC 8693 identity-chaining
// exchange at /authsec/oauth2/token.
//
// This is a NEW model used exclusively by the v2 identity-chaining endpoint.
// The legacy /authsec/spire/oidc/token endpoint does not consult this table.
type TrustedIssuer struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	TenantID    string    `json:"tenant_id" gorm:"index;size:64"`
	Issuer      string    `json:"issuer" gorm:"uniqueIndex:idx_trusted_issuer_per_tenant,priority:2;size:512;not null"`
	JWKSURI     string    `json:"jwks_uri" gorm:"size:512;not null"`
	Audience    string    `json:"audience" gorm:"size:512"`
	MaxChainHop int       `json:"max_chain_hop" gorm:"default:4"`
	Enabled     bool      `json:"enabled" gorm:"default:true"`
	Description string    `json:"description" gorm:"size:1024"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (TrustedIssuer) TableName() string { return "trusted_issuers" }

// ActChainAudit records each successful identity-chain exchange for forensic
// review. One row per hop performed by the v2 endpoint.
type ActChainAudit struct {
	ID               uint      `json:"id" gorm:"primaryKey"`
	JTI              string    `json:"jti" gorm:"uniqueIndex;size:64;not null"`
	TenantID         string    `json:"tenant_id" gorm:"index;size:64"`
	SubjectSub       string    `json:"subject_sub" gorm:"size:256"`
	SubjectIssuer    string    `json:"subject_iss" gorm:"size:512"`
	ActorSub         string    `json:"actor_sub" gorm:"size:256"`
	ActorIssuer      string    `json:"actor_iss" gorm:"size:512"`
	ChainDepth       int       `json:"chain_depth"`
	Resource         string    `json:"resource" gorm:"size:512"`
	Audience         string    `json:"audience" gorm:"size:512"`
	Scope            string    `json:"scope" gorm:"size:1024"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func (ActChainAudit) TableName() string { return "act_chain_audit" }
