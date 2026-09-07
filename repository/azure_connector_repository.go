package repositories

import (
	"errors"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrAzureConnectorNotFound is returned when no consented tenant matches the
// workspace. Distinct from gorm.ErrRecordNotFound so callers can map a 404
// without importing GORM.
var ErrAzureConnectorNotFound = errors.New("azure tenant not onboarded")

// ErrAzureStateInvalid covers every reason a callback's state is unusable:
// unknown, already redeemed, or expired. They are one error on purpose — telling
// a caller which of the three it was tells an attacker which states exist.
var ErrAzureStateInvalid = errors.New("invalid or expired state")

// AzureConnectorRepository stores admin-consented Entra tenants and the one-shot
// OAuth state backing the two browser redirects.
//
// Every connector method takes workspaceID and every query filters on it. A
// tenant id is the address of a customer's whole directory; a missing tenant
// predicate here would be a cross-workspace read of exactly what must not leak.
type AzureConnectorRepository interface {
	// UpsertConsent records that admin consent completed for a tenant, keyed on
	// (workspace_id, tenant_id). Re-consenting an existing tenant UPDATES that
	// row and reports created=false.
	//
	// It deliberately does not touch arm_reader_ok or created_at: re-consent
	// does not re-validate ARM, and silently clearing the last ARM verdict would
	// turn a working tenant into an unknown one for no reason.
	UpsertConsent(workspaceID uuid.UUID, tenantID, displayName, domain string) (stored *models.AzureConnector, created bool, err error)

	// SetARMResult records the outcome of an ARM Reader check. reason is stored
	// only when ok is false; a success clears the previous failure.
	SetARMResult(workspaceID uuid.UUID, tenantID string, ok bool, reason string) (*models.AzureConnector, error)

	// SetGraphResult records the outcome of a Microsoft Graph authorisation
	// check: whether the required application permissions are actually granted,
	// and which ones the token carried. Mirrors SetARMResult on the other plane.
	SetGraphResult(workspaceID uuid.UUID, tenantID string, ok bool, granted []string, reason string) (*models.AzureConnector, error)

	// UpsertSubscriptions records the subscriptions ARM returned for a tenant,
	// refreshing last_seen_at. Reader status is NOT touched here -- listing a
	// subscription and being able to read it are different facts, established
	// by different calls.
	UpsertSubscriptions(workspaceID uuid.UUID, tenantID string, subs []models.AzureSubscription) error

	// SetSubscriptionReader records per-scope Reader coverage.
	SetSubscriptionReader(workspaceID uuid.UUID, tenantID string, readable map[string]bool) error

	ListSubscriptions(workspaceID uuid.UUID, tenantID string) ([]models.AzureSubscription, error)

	// SetPrincipalObjectID records the service principal's object id in the
	// customer's tenant. It comes from the oid claim of an app-only token, so it
	// only becomes knowable after consent, and it is what an Azure RBAC role
	// assignment has to name.
	SetPrincipalObjectID(workspaceID uuid.UUID, tenantID, objectID string) error

	Get(workspaceID uuid.UUID, tenantID string) (*models.AzureConnector, error)
	List(workspaceID uuid.UUID) ([]models.AzureConnector, error)

	// ConnectedTenantIDs is the set the tenant listing marks alreadyConnected.
	ConnectedTenantIDs(workspaceID uuid.UUID) (map[string]bool, error)

	// CreateState persists a pending redirect.
	CreateState(st *models.AzureOAuthState) error

	// ConsumeState redeems a state exactly once: the row is deleted whether or
	// not it had expired, so a leaked state cannot be retried.
	ConsumeState(state string) (*models.AzureOAuthState, error)

	// PurgeExpiredStates drops abandoned redirects.
	PurgeExpiredStates() error
}

type azureConnectorRepository struct{ db *gorm.DB }

// NewAzureConnectorRepository constructs the repository.
func NewAzureConnectorRepository(db *gorm.DB) AzureConnectorRepository {
	return &azureConnectorRepository{db: db}
}

func (r *azureConnectorRepository) UpsertConsent(
	workspaceID uuid.UUID, tenantID, displayName, domain string,
) (*models.AzureConnector, bool, error) {
	now := time.Now().UTC()

	var before models.AzureConnector
	existed := r.db.
		Where("workspace_id = ? AND tenant_id = ?", workspaceID, tenantID).
		First(&before).Error == nil

	row := &models.AzureConnector{
		WorkspaceID: workspaceID,
		TenantID:    tenantID,
		DisplayName: displayName,
		Domain:      domain,
		ConsentedAt: &now,
	}

	// COALESCE on the display fields: ARM omits displayName and domains for
	// tenants the signed-in account can see but has no directory read on, and a
	// later consent arriving without them must not erase what an earlier listing
	// already learned.
	assign := map[string]interface{}{
		"consented_at": now,
		"updated_at":   now,
		"display_name": gorm.Expr("COALESCE(NULLIF(EXCLUDED.display_name, ''), azure_connectors.display_name)"),
		"domain":       gorm.Expr("COALESCE(NULLIF(EXCLUDED.domain, ''), azure_connectors.domain)"),
	}

	if err := r.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "workspace_id"}, {Name: "tenant_id"}},
		DoUpdates: clause.Assignments(assign),
	}).Create(row).Error; err != nil {
		return nil, false, err
	}

	stored, err := r.Get(workspaceID, tenantID)
	if err != nil {
		return nil, false, err
	}
	return stored, !existed, nil
}

func (r *azureConnectorRepository) SetARMResult(
	workspaceID uuid.UUID, tenantID string, ok bool, reason string,
) (*models.AzureConnector, error) {
	now := time.Now().UTC()
	if ok {
		reason = ""
	}

	res := r.db.Model(&models.AzureConnector{}).
		Where("workspace_id = ? AND tenant_id = ?", workspaceID, tenantID).
		Updates(map[string]interface{}{
			"arm_reader_ok":  ok,
			"arm_checked_at": now,
			"arm_last_error": reason,
			"updated_at":     now,
		})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, ErrAzureConnectorNotFound
	}
	return r.Get(workspaceID, tenantID)
}

func (r *azureConnectorRepository) SetGraphResult(
	workspaceID uuid.UUID, tenantID string, ok bool, granted []string, reason string,
) (*models.AzureConnector, error) {
	now := time.Now().UTC()
	if ok {
		reason = ""
	}
	if granted == nil {
		granted = []string{}
	}

	res := r.db.Model(&models.AzureConnector{}).
		Where("workspace_id = ? AND tenant_id = ?", workspaceID, tenantID).
		Updates(map[string]interface{}{
			"graph_ok":            ok,
			"graph_checked_at":    now,
			"graph_last_error":    reason,
			"graph_granted_roles": pq.StringArray(granted),
			"updated_at":          now,
		})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, ErrAzureConnectorNotFound
	}
	return r.Get(workspaceID, tenantID)
}

func (r *azureConnectorRepository) UpsertSubscriptions(
	workspaceID uuid.UUID, tenantID string, subs []models.AzureSubscription,
) error {
	if len(subs) == 0 {
		return nil
	}
	now := time.Now().UTC()
	for i := range subs {
		subs[i].WorkspaceID = workspaceID
		subs[i].TenantID = tenantID
		subs[i].LastSeenAt = now
	}

	// reader_ok is deliberately absent from the update set: this records that
	// ARM named the subscription, which is not the same as being able to read
	// it. Overwriting the verdict here would erase a check with a listing.
	return r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "workspace_id"}, {Name: "tenant_id"}, {Name: "subscription_id"},
		},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"display_name": gorm.Expr("COALESCE(NULLIF(EXCLUDED.display_name, ''), azure_subscriptions.display_name)"),
			"state":        gorm.Expr("COALESCE(NULLIF(EXCLUDED.state, ''), azure_subscriptions.state)"),
			"last_seen_at": now,
			"updated_at":   now,
		}),
	}).Create(&subs).Error
}

func (r *azureConnectorRepository) SetSubscriptionReader(
	workspaceID uuid.UUID, tenantID string, readable map[string]bool,
) error {
	now := time.Now().UTC()
	for subID, ok := range readable {
		if err := r.db.Model(&models.AzureSubscription{}).
			Where("workspace_id = ? AND tenant_id = ? AND subscription_id = ?",
				workspaceID, tenantID, subID).
			Updates(map[string]interface{}{
				"reader_ok":         ok,
				"reader_checked_at": now,
				"updated_at":        now,
			}).Error; err != nil {
			return err
		}
	}
	return nil
}

func (r *azureConnectorRepository) ListSubscriptions(
	workspaceID uuid.UUID, tenantID string,
) ([]models.AzureSubscription, error) {
	var rows []models.AzureSubscription
	err := r.db.
		Where("workspace_id = ? AND tenant_id = ?", workspaceID, tenantID).
		Order("display_name, subscription_id").
		Find(&rows).Error
	return rows, err
}

func (r *azureConnectorRepository) SetPrincipalObjectID(
	workspaceID uuid.UUID, tenantID, objectID string,
) error {
	if objectID == "" {
		return nil
	}
	return r.db.Model(&models.AzureConnector{}).
		Where("workspace_id = ? AND tenant_id = ?", workspaceID, tenantID).
		Updates(map[string]interface{}{
			"principal_object_id": objectID,
			"updated_at":          time.Now().UTC(),
		}).Error
}

func (r *azureConnectorRepository) Get(workspaceID uuid.UUID, tenantID string) (*models.AzureConnector, error) {
	var row models.AzureConnector
	err := r.db.
		Where("workspace_id = ? AND tenant_id = ?", workspaceID, tenantID).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAzureConnectorNotFound
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (r *azureConnectorRepository) List(workspaceID uuid.UUID) ([]models.AzureConnector, error) {
	var rows []models.AzureConnector
	err := r.db.
		Where("workspace_id = ?", workspaceID).
		Order("created_at DESC").
		Find(&rows).Error
	return rows, err
}

func (r *azureConnectorRepository) ConnectedTenantIDs(workspaceID uuid.UUID) (map[string]bool, error) {
	var ids []string
	if err := r.db.Model(&models.AzureConnector{}).
		Where("workspace_id = ?", workspaceID).
		Pluck("tenant_id", &ids).Error; err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set, nil
}

func (r *azureConnectorRepository) CreateState(st *models.AzureOAuthState) error {
	return r.db.Create(st).Error
}

func (r *azureConnectorRepository) ConsumeState(state string) (*models.AzureOAuthState, error) {
	if state == "" {
		return nil, ErrAzureStateInvalid
	}

	// DELETE ... RETURNING, so reading the row and spending it are the same
	// statement. A SELECT followed by a DELETE is not one-shot: two callbacks
	// carrying the same state can both pass the SELECT before either DELETE
	// lands, and a replayed consent callback is exactly the thing this row
	// exists to stop. Postgres serialises the delete, so only the caller whose
	// statement removed the row sees RowsAffected == 1.
	var st models.AzureOAuthState
	res := r.db.Clauses(clause.Returning{}).
		Where("state = ?", state).
		Delete(&st)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected != 1 {
		return nil, ErrAzureStateInvalid
	}

	// Expiry is checked after redemption on purpose: a state that arrives late
	// is spent, not retryable.
	if time.Now().After(st.ExpiresAt) {
		return nil, ErrAzureStateInvalid
	}
	return &st, nil
}

func (r *azureConnectorRepository) PurgeExpiredStates() error {
	return r.db.Delete(&models.AzureOAuthState{}, "expires_at < ?", time.Now()).Error
}
