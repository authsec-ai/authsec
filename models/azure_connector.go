package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Azure onboarding purposes. The state row's purpose decides which callback
// branch is legal, so a login state cannot be replayed into the consent branch.
const (
	AzureOAuthPurposeLogin   = "login"
	AzureOAuthPurposeConsent = "consent"
)

// AzureConnector is one Entra tenant this workspace has admin-consented into.
//
// It is deliberately NOT a CloudConnector: consent alone proves nothing can be
// read. ARMReaderOK is what says the tenant is actually usable, and it stays
// false until an ARM Reader check passes.
type AzureConnector struct {
	ID          uuid.UUID `json:"id"           gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`

	TenantID    string `json:"tenant_id"              gorm:"type:text;not null"`
	DisplayName string `json:"display_name,omitempty" gorm:"type:text"`
	Domain      string `json:"domain,omitempty"       gorm:"type:text"`

	ConsentedAt *time.Time `json:"consented_at,omitempty" gorm:"type:timestamptz"`

	// false until an ARM Reader check has actually passed. Onboarding is
	// complete when a row exists AND this is true. ARMCheckedAt still being nil
	// is what says a check has never run at all.
	ARMReaderOK  bool       `json:"arm_reader_ok"              gorm:"column:arm_reader_ok;not null;default:false"`
	ARMCheckedAt *time.Time `json:"arm_checked_at,omitempty"   gorm:"column:arm_checked_at;type:timestamptz"`
	ARMLastError string     `json:"arm_last_error,omitempty"   gorm:"column:arm_last_error;type:text"`

	// PrincipalObjectID is the AuthSec service principal's object id inside this
	// tenant. Known only after consent, and required by any role assignment.
	PrincipalObjectID string `json:"principal_object_id,omitempty" gorm:"column:principal_object_id;type:text"`

	// Plane 1. GraphOK is to admin consent what ARMReaderOK is to a role
	// assignment: consent completing while granting nothing is a real state, so
	// it is verified rather than assumed. GraphGrantedRoles keeps the token's
	// roles claim so a missing permission can be named, not just counted.
	GraphOK        bool       `json:"graph_ok"                     gorm:"column:graph_ok;not null;default:false"`
	GraphCheckedAt *time.Time `json:"graph_checked_at,omitempty"   gorm:"column:graph_checked_at;type:timestamptz"`
	GraphLastError string     `json:"graph_last_error,omitempty"   gorm:"column:graph_last_error;type:text"`
	// The default tag is load-bearing, not decoration. The column is
	// text[] NOT NULL DEFAULT '{}', but a nil pq.StringArray is not a Go zero
	// value GORM knows to skip unless a default is declared -- so without this
	// every INSERT sent an explicit NULL and the FIRST consent for any tenant
	// died on the not-null constraint. Existing rows were unaffected, because
	// the upsert path only touches the display columns, which is why it survived
	// a real end-to-end run and only surfaced against an empty table.
	GraphGrantedRoles pq.StringArray `json:"graph_granted_roles"          gorm:"column:graph_granted_roles;type:text[];default:'{}'"`

	CreatedAt time.Time `json:"created_at" gorm:"type:timestamptz;autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"type:timestamptz;autoUpdateTime"`
}

func (AzureConnector) TableName() string { return "azure_connectors" }

// AzureOAuthState is one pending browser redirect.
//
// Every field the callback trusts is read from here rather than from the query
// string Microsoft appends, because the query string is attacker-reachable and
// this row is not.
type AzureOAuthState struct {
	State       string    `json:"-" gorm:"type:text;primaryKey"`
	WorkspaceID uuid.UUID `json:"-" gorm:"type:uuid;not null"`

	Purpose  string `json:"-" gorm:"type:text;not null"`
	TenantID string `json:"-" gorm:"type:text"`

	CreatedBy string    `json:"-" gorm:"type:text"`
	ExpiresAt time.Time `json:"-" gorm:"type:timestamptz;not null"`
	CreatedAt time.Time `json:"-" gorm:"type:timestamptz;autoCreateTime"`
}

func (AzureOAuthState) TableName() string { return "azure_oauth_state" }

// AzureSubscription is one subscription inside one tenant.
//
// It exists as a row rather than a transient listing for two reasons. Reader is
// assigned per scope, so coverage is a per-subscription fact and a single
// tenant-wide boolean would report an all-clear it has not earned. And every
// later discovery object -- a resource, a managed identity, a role assignment --
// hangs off a subscription; without the row there is nothing for the access
// graph to attach to.
//
// The composite foreign key to the connector is deliberate: a subscription id is
// never meaningful without the tenant that owns it.
type AzureSubscription struct {
	ID          uuid.UUID `json:"id"           gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	TenantID    string    `json:"tenant_id"    gorm:"type:text;not null"`

	SubscriptionID string `json:"subscription_id"        gorm:"type:text;not null"`
	DisplayName    string `json:"display_name,omitempty" gorm:"type:text"`

	// Azure's own word: Enabled, Warned, PastDue, Disabled, Deleted.
	State string `json:"state,omitempty" gorm:"type:text"`

	ReaderOK        bool       `json:"reader_ok"                    gorm:"column:reader_ok;not null;default:false"`
	ReaderCheckedAt *time.Time `json:"reader_checked_at,omitempty"  gorm:"column:reader_checked_at;type:timestamptz"`

	// LastSeenAt is when ARM last returned this subscription. A subscription
	// that stops being returned has been removed, moved out of scope, or lost
	// its role assignment -- tellable apart only if the last sighting is kept.
	LastSeenAt time.Time `json:"last_seen_at" gorm:"column:last_seen_at;type:timestamptz"`

	CreatedAt time.Time `json:"created_at" gorm:"type:timestamptz;autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"type:timestamptz;autoUpdateTime"`
}

func (AzureSubscription) TableName() string { return "azure_subscriptions" }
