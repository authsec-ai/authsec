package services

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	enrollmentTTL    = 15 * time.Minute
	credentialTTL    = 24 * time.Hour
	rotationOverlap  = 15 * time.Minute
	recoveryGrace    = time.Hour
	rotateSkew       = 5 * time.Minute
	collectorAppHost = "collector.authsec.local"
	collectorAppID   = "authsec-collector"
)

// Sentinel errors the controller maps onto HTTP statuses. Messages stay
// generic at the HTTP layer so a caller cannot probe which tokens exist.
var (
	ErrCollectorUnauthorized = errors.New("collector unauthorized")
	ErrCollectorExpired      = errors.New("collector credential expired")
	ErrCollectorUsed         = errors.New("enrollment token already used")
	ErrCollectorConflict     = errors.New("collector request conflicts with its binding")
	ErrCollectorKind         = errors.New("enrollment kind does not match the token")
	ErrCollectorVersion      = errors.New("collector version conflict")
	ErrCollectorNotFound     = errors.New("collector not found")
	ErrCollectorInvalid      = errors.New("collector request is invalid")
	ErrCollectorScope        = errors.New("collector credential lacks the required scope")
)

// CollectorEnrollmentService issues enrollment tokens and exchanges them for
// a collector identity. Machine-id is never the estate key.
type CollectorEnrollmentService struct {
	db     *gorm.DB
	repo   *repositories.CollectorRepository
	sealer *ResponseSealer
	now    Clock
}

// NewCollectorEnrollmentService constructs the service. clock may be nil.
func NewCollectorEnrollmentService(db *gorm.DB, clock Clock) (*CollectorEnrollmentService, error) {
	sealer, err := NewResponseSealer()
	if err != nil {
		return nil, err
	}
	return &CollectorEnrollmentService{
		db: db, repo: repositories.NewCollectorRepository(db), sealer: sealer, now: clock,
	}, nil
}

// Repository exposes the read side used by middleware.
func (s *CollectorEnrollmentService) Repository() *repositories.CollectorRepository { return s.repo }

// Now returns the service clock.
func (s *CollectorEnrollmentService) Now() time.Time { return s.now.Now() }

// IssueEnrollmentInput is an administrator's request for a one-time token.
type IssueEnrollmentInput struct {
	Kind              string
	EstateScopeKind   string
	EstateScopeID     *uuid.UUID
	EstateDisplayName string
	Namespaces        []string
	CapabilityCeiling json.RawMessage
	ExpiresIn         time.Duration
	CreatedBy         string
}

// IssuedEnrollment is the one-time token. Token is plaintext and is not stored.
type IssuedEnrollment struct {
	EnrollmentID uuid.UUID `json:"enrollment_id"`
	Token        string    `json:"token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// EnrollInput is the collector's enrollment proof.
type EnrollInput struct {
	EnrollmentID uuid.UUID
	PublicKeyB64 string
	Nonce        string
	Kind         string
	Version      string
	NativeHints  map[string]any
	WorkspaceID  *uuid.UUID
	EstateID     *uuid.UUID
	HostID       string
}

// EnrollResult is returned once and, on a same-key retry, returned again.
type EnrollResult struct {
	CollectorID         uuid.UUID `json:"collector_id"`
	DiscoverySourceID   uuid.UUID `json:"discovery_source_id"`
	IntegrationID       uuid.UUID `json:"integration_id"`
	EstateID            uuid.UUID `json:"estate_id"`
	Credential          string    `json:"credential"`
	CredentialExpiresAt time.Time `json:"credential_expires_at"`
	Scopes              []string  `json:"scopes"`
}

// IssueEnrollment mints a single-use token bound to kind and estate scope.
func (s *CollectorEnrollmentService) IssueEnrollment(workspaceID uuid.UUID, in IssueEnrollmentInput) (*IssuedEnrollment, error) {
	if !containsString(models.ValidCollectorKinds(), in.Kind) {
		return nil, fmt.Errorf("%w: kind", ErrCollectorInvalid)
	}
	kind := in.EstateScopeKind
	if kind == "" {
		kind = defaultEstateKind(in.Kind)
	}
	if kind != models.EstateKindHost && kind != models.EstateKindCluster && kind != models.EstateKindNode {
		return nil, fmt.Errorf("%w: estate scope kind", ErrCollectorInvalid)
	}
	for _, ns := range in.Namespaces {
		if strings.TrimSpace(ns) == "" || strings.ContainsAny(ns, " \t\r\n") {
			return nil, fmt.Errorf("%w: namespace", ErrCollectorInvalid)
		}
	}
	ttl := in.ExpiresIn
	if ttl <= 0 {
		ttl = enrollmentTTL
	}
	if ttl > enrollmentTTL {
		return nil, fmt.Errorf("%w: enrollment expiry cannot exceed 15 minutes", ErrCollectorInvalid)
	}
	ceiling := in.CapabilityCeiling
	if len(ceiling) == 0 {
		ceiling = json.RawMessage(`{}`)
	}
	if !json.Valid(ceiling) {
		return nil, fmt.Errorf("%w: capability ceiling", ErrCollectorInvalid)
	}
	if _, err := scopesFromCeiling(ceiling); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCollectorInvalid, err)
	}
	if in.EstateScopeID != nil {
		var n int64
		if err := s.db.Raw(`SELECT count(*) FROM iga_estate_scopes WHERE workspace_id = ? AND id = ?`,
			workspaceID, *in.EstateScopeID).Scan(&n).Error; err != nil {
			return nil, err
		}
		if n != 1 {
			return nil, fmt.Errorf("%w: estate is not in this workspace", ErrCollectorConflict)
		}
	}
	token, err := MintPrefixedToken(PrefixEnrollment)
	if err != nil {
		return nil, err
	}
	now := s.Now()
	row := models.CollectorEnrollment{
		ID:                 uuid.New(),
		WorkspaceID:        workspaceID,
		TokenHash:          HashCollectorSecret(token),
		Kind:               in.Kind,
		EstateScopeID:      in.EstateScopeID,
		EstateScopeKind:    kind,
		EstateDisplayName:  in.EstateDisplayName,
		NamespaceAllowlist: append(models.StringList{}, in.Namespaces...),
		CapabilityCeiling:  ceiling,
		ExpiresAt:          now.Add(ttl),
		CreatedBy:          in.CreatedBy,
		CreatedAt:          now,
	}
	if err := s.db.Create(&row).Error; err != nil {
		return nil, err
	}
	return &IssuedEnrollment{EnrollmentID: row.ID, Token: token, ExpiresAt: row.ExpiresAt}, nil
}

// EnrollmentAcceptable reports whether a presented token may still be attempted.
// A used token stays acceptable through the recovery grace so a lost response
// can be fetched again. An unused expired token cannot.
func EnrollmentAcceptable(en *models.CollectorEnrollment, now time.Time) error {
	if en == nil {
		return ErrCollectorUnauthorized
	}
	if en.UsedAt == nil {
		if !now.Before(en.ExpiresAt) {
			return ErrCollectorExpired
		}
		return nil
	}
	if now.After(en.UsedAt.Add(recoveryGrace)) {
		return ErrCollectorExpired
	}
	return nil
}

// Enroll exchanges a one-time token for a collector. The same installation key
// and nonce returns the original result and does not create a second source.
func (s *CollectorEnrollmentService) Enroll(in EnrollInput) (*EnrollResult, error) {
	if strings.TrimSpace(in.Nonce) == "" {
		return nil, fmt.Errorf("%w: installation nonce is required", ErrCollectorInvalid)
	}
	if in.HostID != "" {
		return nil, fmt.Errorf("%w: host_id is assigned by the server", ErrCollectorConflict)
	}
	pub, err := ParseEd25519PublicKey(in.PublicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCollectorInvalid, err)
	}
	keyHash := RecoveryKeyHash(pub, in.Nonce)
	var result *EnrollResult
	err = s.db.Transaction(func(tx *gorm.DB) error {
		repo := s.repo.With(tx)
		en, err := repo.LockEnrollmentByID(in.EnrollmentID)
		if err != nil {
			return ErrCollectorUnauthorized
		}
		if in.WorkspaceID != nil && *in.WorkspaceID != en.WorkspaceID {
			return ErrCollectorConflict
		}
		if en.UsedAt != nil {
			return s.recover(repo, en, keyHash, &result)
		}
		if !s.Now().Before(en.ExpiresAt) {
			return ErrCollectorExpired
		}
		if in.Kind != "" && in.Kind != en.Kind {
			return ErrCollectorKind
		}
		if in.EstateID != nil {
			if en.EstateScopeID == nil || *en.EstateScopeID != *in.EstateID {
				return fmt.Errorf("%w: estate", ErrCollectorConflict)
			}
		}
		created, err := s.createCollector(tx, en, pub, in)
		if err != nil {
			return err
		}
		blob, err := json.Marshal(created)
		if err != nil {
			return err
		}
		sealed, err := s.sealer.Seal(blob)
		if err != nil {
			return err
		}
		now := s.Now()
		rec := models.CollectorEnrollmentRecovery{
			ID: uuid.New(), WorkspaceID: en.WorkspaceID, EnrollmentID: en.ID,
			KeyHash: keyHash, Ciphertext: sealed, ExpiresAt: now.Add(recoveryGrace), CreatedAt: now,
		}
		if err := tx.Create(&rec).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.CollectorEnrollment{}).
			Where("id = ? AND workspace_id = ?", en.ID, en.WorkspaceID).
			Update("used_at", now).Error; err != nil {
			return err
		}
		result = created
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *CollectorEnrollmentService) recover(repo *repositories.CollectorRepository, en *models.CollectorEnrollment, keyHash string, dest **EnrollResult) error {
	rec, err := repo.FindRecovery(en.ID, keyHash)
	if err != nil {
		if errors.Is(err, repositories.ErrCollectorNotFound) {
			return ErrCollectorUsed
		}
		return err
	}
	if !s.Now().Before(rec.ExpiresAt) {
		return ErrCollectorUsed
	}
	plain, err := s.sealer.Open(rec.Ciphertext)
	if err != nil {
		return ErrCollectorUsed
	}
	var out EnrollResult
	if err := json.Unmarshal(plain, &out); err != nil {
		return err
	}
	*dest = &out
	return nil
}

func (s *CollectorEnrollmentService) createCollector(tx *gorm.DB, en *models.CollectorEnrollment, pub []byte, in EnrollInput) (*EnrollResult, error) {
	now := s.Now()
	keyID := InstallationKeyID(pub)
	scopes, err := scopesFromCeiling(en.CapabilityCeiling)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCollectorInvalid, err)
	}
	estateID, err := s.bindEstate(tx, en, keyID, now)
	if err != nil {
		return nil, err
	}
	collectorID := uuid.New()
	sourceID := uuid.New()
	integrationID := uuid.New()

	scopeJSON, err := json.Marshal(models.ApprovedScope{
		Namespaces:        []string(en.NamespaceAllowlist),
		EstateScopeKind:   en.EstateScopeKind,
		CapabilityCeiling: en.CapabilityCeiling,
		NativeHints:       in.NativeHints,
		BoundNodeName:     hintString(in.NativeHints, "node_name"),
	})
	if err != nil {
		return nil, err
	}
	hints, err := json.Marshal(in.NativeHints)
	if err != nil {
		return nil, err
	}
	if in.NativeHints == nil {
		hints = []byte(`{}`)
	}

	source := models.DiscoverySource{
		ID: sourceID, WorkspaceID: en.WorkspaceID, Kind: en.Kind,
		DisplayName: en.Kind + "-" + collectorID.String(),
		Config:      json.RawMessage(hints),
		Runtime:     json.RawMessage(`{}`),
		Enabled:     true, InstanceID: keyID, SelfRegistered: true,
		AgentVersion: in.Version, CreatedBy: "collector-enrollment",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := tx.Create(&source).Error; err != nil {
		return nil, mapConstraint(err)
	}

	scopeBytes, _ := json.Marshal(scopes)
	instID := collectorID.String()
	integ := models.IGAIntegration{
		ID: integrationID, WorkspaceID: en.WorkspaceID,
		Provider: providerForCollectorKind(en.Kind), ProviderHost: collectorAppHost,
		AppRegistrationID: collectorAppID, InstallationID: &instID,
		CapabilityProfile:    en.CapabilityCeiling,
		RequestedPermissions: scopeBytes, GrantedPermissions: scopeBytes,
		Status: "active", VerifiedAt: &now, Version: 1,
		CreatedBy: "collector-enrollment", CreatedAt: now, UpdatedAt: now,
	}
	if err := tx.Create(&integ).Error; err != nil {
		return nil, mapConstraint(err)
	}

	instance := models.CollectorInstance{
		ID: collectorID, WorkspaceID: en.WorkspaceID,
		DiscoverySourceID: sourceID, EstateScopeID: estateID, IntegrationID: integrationID,
		Kind: en.Kind, InstallationKeyID: keyID, InstallationPublicKey: append([]byte(nil), pub...),
		ApprovedScope: scopeJSON, Version: in.Version, RowVersion: 1,
		Status: models.CollectorStatusActive, LastSeenAt: &now,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := tx.Create(&instance).Error; err != nil {
		return nil, mapConstraint(err)
	}

	binding := models.CollectorIntegration{
		WorkspaceID: en.WorkspaceID, DiscoverySourceID: sourceID,
		IntegrationID: integrationID, CollectorID: collectorID, CreatedAt: now,
	}
	if err := tx.Create(&binding).Error; err != nil {
		return nil, mapConstraint(err)
	}
	if err := insertIntegrationScopes(tx, en, integrationID, estateID, now); err != nil {
		return nil, err
	}

	plain, err := MintPrefixedToken(PrefixCollector)
	if err != nil {
		return nil, err
	}
	cred := models.CollectorCredential{
		ID: uuid.New(), WorkspaceID: en.WorkspaceID, CollectorID: collectorID,
		CredentialHash: HashCollectorSecret(plain), Scopes: scopes,
		ExpiresAt: now.Add(credentialTTL), CreatedAt: now,
	}
	if err := tx.Create(&cred).Error; err != nil {
		return nil, err
	}
	return &EnrollResult{
		CollectorID: collectorID, DiscoverySourceID: sourceID,
		IntegrationID: integrationID, EstateID: estateID,
		Credential: plain, CredentialExpiresAt: cred.ExpiresAt,
		Scopes: []string(scopes),
	}, nil
}

func (s *CollectorEnrollmentService) bindEstate(tx *gorm.DB, en *models.CollectorEnrollment, keyID string, now time.Time) (uuid.UUID, error) {
	if en.EstateScopeID != nil {
		return *en.EstateScopeID, nil
	}
	name := en.EstateDisplayName
	if name == "" {
		name = en.Kind + " " + keyID[:12]
	}
	estate := models.IGAEstateScope{
		ID: uuid.New(), WorkspaceID: en.WorkspaceID, ScopeKind: en.EstateScopeKind,
		SourceKey: "collector-install:" + keyID, DisplayName: name, Stage: "unknown",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := tx.Create(&estate).Error; err != nil {
		return uuid.Nil, mapConstraint(err)
	}
	return estate.ID, nil
}

func insertIntegrationScopes(tx *gorm.DB, en *models.CollectorEnrollment, integrationID, estateID uuid.UUID, now time.Time) error {
	rows := []models.IGAIntegrationScope{{
		ID: uuid.New(), WorkspaceID: en.WorkspaceID, IntegrationID: integrationID,
		EstateScopeID: &estateID, NativeScopeKind: en.EstateScopeKind,
		NativeScopeID: estateID.String(), SelectionState: "selected",
		Filters: json.RawMessage(`{}`), EffectivePermissions: json.RawMessage(`{}`),
		CreatedAt: now, UpdatedAt: now,
	}}
	for _, ns := range en.NamespaceAllowlist {
		id := estateID
		rows = append(rows, models.IGAIntegrationScope{
			ID: uuid.New(), WorkspaceID: en.WorkspaceID, IntegrationID: integrationID,
			EstateScopeID: &id, NativeScopeKind: "namespace", NativeScopeID: ns,
			SelectionState: "selected", Filters: json.RawMessage(`{}`),
			EffectivePermissions: json.RawMessage(`{}`), CreatedAt: now, UpdatedAt: now,
		})
	}
	return tx.Create(&rows).Error
}

// RotateInput is a proof-of-possession rotation.
type RotateInput struct {
	WorkspaceID    uuid.UUID
	CollectorID    uuid.UUID
	CredentialID   uuid.UUID
	CurrentScopes  []string
	Nonce          string
	RequestedAt    time.Time
	RequestedAtRaw string
	NewPublicKey   string
	Signature      string
	Scopes         []string
}

// RotateResult is the replacement credential. The previous one stays valid
// until OverlapUntil, then fails authentication.
type RotateResult struct {
	Credential   string    `json:"credential"`
	ExpiresAt    time.Time `json:"expires_at"`
	OverlapUntil time.Time `json:"overlap_until"`
	Scopes       []string  `json:"scopes"`
}

// Rotate replaces the current credential after the installation key signs the request.
func (s *CollectorEnrollmentService) Rotate(in RotateInput) (*RotateResult, error) {
	if strings.TrimSpace(in.Nonce) == "" {
		return nil, fmt.Errorf("%w: nonce", ErrCollectorInvalid)
	}
	now := s.Now()
	if in.RequestedAt.IsZero() || in.RequestedAt.After(now.Add(rotateSkew)) || now.Sub(in.RequestedAt) > rotateSkew {
		return nil, fmt.Errorf("%w: requested_at is outside the allowed skew", ErrCollectorInvalid)
	}
	signedScopes := canonicalScopes(in.Scopes)
	if len(in.Scopes) > 0 {
		for _, scope := range in.Scopes {
			if !containsString(in.CurrentScopes, scope) {
				return nil, fmt.Errorf("%w: cannot grant %s", ErrCollectorScope, scope)
			}
		}
	}
	storedScopes := append([]string(nil), in.Scopes...)
	if len(storedScopes) == 0 {
		storedScopes = append([]string(nil), in.CurrentScopes...)
	}
	sort.Strings(storedScopes)
	var result *RotateResult
	err := s.db.Transaction(func(tx *gorm.DB) error {
		repo := s.repo.With(tx)
		inst, err := repo.LockInstance(in.WorkspaceID, in.CollectorID)
		if err != nil {
			return ErrCollectorNotFound
		}
		if inst.Status != models.CollectorStatusActive {
			return ErrCollectorUnauthorized
		}
		msgKey := ""
		var newPub []byte
		if strings.TrimSpace(in.NewPublicKey) != "" {
			parsed, err := ParseEd25519PublicKey(in.NewPublicKey)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrCollectorInvalid, err)
			}
			newPub = parsed
			msgKey = encodeStd(parsed)
		}
		sig, err := ParseEd25519Signature(in.Signature)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrCollectorInvalid, err)
		}
		atRaw := in.RequestedAtRaw
		if atRaw == "" {
			atRaw = in.RequestedAt.UTC().Format(time.RFC3339)
		}
		msg := RotateSignedMessage(inst.ID.String(), in.Nonce, atRaw, msgKey, signedScopes)
		if !verifyKey(inst.InstallationPublicKey, msg, sig) {
			return ErrCollectorUnauthorized
		}
		nonceHash := HashCollectorSecret(in.Nonce)
		if err := tx.Exec(`INSERT INTO collector_rotation_nonces
			(workspace_id, collector_id, nonce_hash, used_at) VALUES (?, ?, ?, ?)`,
			in.WorkspaceID, inst.ID, nonceHash, now).Error; err != nil {
			return mapConstraint(err)
		}
		var current models.CollectorCredential
		if err := tx.Where("id = ? AND workspace_id = ? AND collector_id = ?",
			in.CredentialID, in.WorkspaceID, inst.ID).First(&current).Error; err != nil {
			return ErrCollectorUnauthorized
		}
		overlapUntil := now.Add(rotationOverlap)
		if current.ExpiresAt.After(overlapUntil) {
			if err := tx.Model(&models.CollectorCredential{}).
				Where("id = ? AND workspace_id = ?", current.ID, in.WorkspaceID).
				Update("expires_at", overlapUntil).Error; err != nil {
				return err
			}
		} else {
			overlapUntil = current.ExpiresAt
		}
		if newPub != nil {
			keyID := InstallationKeyID(newPub)
			res := tx.Model(&models.CollectorInstance{}).
				Where("id = ? AND workspace_id = ?", inst.ID, inst.WorkspaceID).
				Updates(map[string]any{
					"installation_public_key": newPub,
					"installation_key_id":     keyID,
					"row_version":             inst.RowVersion + 1,
					"updated_at":              now,
				})
			if res.Error != nil {
				return mapConstraint(res.Error)
			}
			if err := tx.Model(&models.DiscoverySource{}).
				Where("id = ? AND workspace_id = ?", inst.DiscoverySourceID, inst.WorkspaceID).
				Update("instance_id", keyID).Error; err != nil {
				return mapConstraint(err)
			}
		} else {
			if err := tx.Model(&models.CollectorInstance{}).
				Where("id = ? AND workspace_id = ?", inst.ID, inst.WorkspaceID).
				Updates(map[string]any{"row_version": inst.RowVersion + 1, "updated_at": now}).Error; err != nil {
				return err
			}
		}
		plain, err := MintPrefixedToken(PrefixCollector)
		if err != nil {
			return err
		}
		pred := current.ID
		next := models.CollectorCredential{
			ID: uuid.New(), WorkspaceID: in.WorkspaceID, CollectorID: inst.ID,
			CredentialHash: HashCollectorSecret(plain), Scopes: models.StringList(storedScopes),
			ExpiresAt: now.Add(credentialTTL), PredecessorID: &pred, CreatedAt: now,
		}
		if err := tx.Create(&next).Error; err != nil {
			return err
		}
		result = &RotateResult{
			Credential: plain, ExpiresAt: next.ExpiresAt, OverlapUntil: overlapUntil, Scopes: storedScopes,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Revoke disables a collector. expectedVersion is the row_version from GET.
func (s *CollectorEnrollmentService) Revoke(workspaceID, id uuid.UUID, expectedVersion int64, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%w: reason is required", ErrCollectorInvalid)
	}
	now := s.Now()
	return s.db.Transaction(func(tx *gorm.DB) error {
		inst, err := s.repo.With(tx).LockInstance(workspaceID, id)
		if err != nil {
			if errors.Is(err, repositories.ErrCollectorNotFound) {
				return ErrCollectorNotFound
			}
			return err
		}
		if inst.RowVersion != expectedVersion {
			return ErrCollectorVersion
		}
		res := tx.Model(&models.CollectorInstance{}).
			Where("id = ? AND workspace_id = ? AND row_version = ?", id, workspaceID, expectedVersion).
			Updates(map[string]any{
				"status": models.CollectorStatusRevoked, "revoked_at": now,
				"revoke_reason": reason, "row_version": expectedVersion + 1, "updated_at": now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return ErrCollectorVersion
		}
		return tx.Model(&models.CollectorCredential{}).
			Where("workspace_id = ? AND collector_id = ? AND revoked_at IS NULL", workspaceID, id).
			Update("revoked_at", now).Error
	})
}

// CollectorView is the human (and collector) read model. It has no credential material.
type CollectorView struct {
	ID                uuid.UUID       `json:"id"`
	Kind              string          `json:"kind"`
	Status            string          `json:"status"`
	RowVersion        int64           `json:"row_version"`
	AgentVersion      string          `json:"agent_version"`
	Health            CollectorHealth `json:"health"`
	Capabilities      json.RawMessage `json:"capabilities"`
	Coverage          []CoverageFact  `json:"coverage"`
	DesiredRevision   *int64          `json:"desired_revision"`
	AppliedRevision   *int64          `json:"applied_revision"`
	DiscoverySourceID uuid.UUID       `json:"discovery_source_id"`
	IntegrationID     uuid.UUID       `json:"integration_id"`
	EstateID          uuid.UUID       `json:"estate_id"`
}

// CollectorHealth is liveness, not a credential.
type CollectorHealth struct {
	Status     string     `json:"status"`
	LastSeenAt *time.Time `json:"last_seen_at"`
}

// CoverageFact is one iga_coverage_states row, or an empty list when none exist.
type CoverageFact struct {
	ObjectClass string `json:"object_class"`
	State       string `json:"state"`
	ReasonCode  string `json:"reason_code"`
}

// Get returns the collector view for a workspace. Other workspaces get not found.
func (s *CollectorEnrollmentService) Get(workspaceID, id uuid.UUID) (*CollectorView, error) {
	inst, err := s.repo.GetInstance(workspaceID, id)
	if err != nil {
		if errors.Is(err, repositories.ErrCollectorNotFound) {
			return nil, ErrCollectorNotFound
		}
		return nil, err
	}
	return s.view(inst)
}

func (s *CollectorEnrollmentService) view(inst *models.CollectorInstance) (*CollectorView, error) {
	var coverage []CoverageFact
	err := s.db.Raw(`SELECT object_class, state, reason_code FROM iga_coverage_states
		WHERE workspace_id = ? AND integration_id = ? ORDER BY object_class`,
		inst.WorkspaceID, inst.IntegrationID).Scan(&coverage).Error
	if err != nil {
		return nil, err
	}
	if coverage == nil {
		coverage = []CoverageFact{}
	}
	caps := inst.ApprovedScope
	if len(caps) == 0 {
		caps = json.RawMessage(`{}`)
	}
	return &CollectorView{
		ID: inst.ID, Kind: inst.Kind, Status: inst.Status, RowVersion: inst.RowVersion,
		AgentVersion: inst.Version,
		Health:       CollectorHealth{Status: inst.Status, LastSeenAt: inst.LastSeenAt},
		Capabilities: caps, Coverage: coverage,
		DiscoverySourceID: inst.DiscoverySourceID, IntegrationID: inst.IntegrationID,
		EstateID: inst.EstateScopeID,
	}, nil
}

// PolicyInputs returns discovered-agent facts that are allowed to feed v2 policy.
// Unverified legacy rows are omitted.
func (s *CollectorEnrollmentService) PolicyInputs(workspaceID uuid.UUID) ([]PolicyEvidence, error) {
	rows, err := s.repo.PolicyEvidenceFromDiscovery(workspaceID)
	if err != nil {
		return nil, err
	}
	in := make([]PolicyEvidence, 0, len(rows))
	for _, row := range rows {
		in = append(in, PolicyEvidence{Name: row.Name, Trust: row.Trust})
	}
	return SelectPolicyInputs(in), nil
}

// SetLegacyIngress sets the per-workspace discovery-ingress switch.
func (s *CollectorEnrollmentService) SetLegacyIngress(workspaceID uuid.UUID, disabled bool, updatedBy string) error {
	return s.repo.SetLegacyIngress(workspaceID, disabled, updatedBy, s.Now())
}

func canonicalScopes(scopes []string) string {
	cp := append([]string(nil), scopes...)
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

func defaultEstateKind(collectorKind string) string {
	switch collectorKind {
	case models.CollectorKindK8s:
		return models.EstateKindCluster
	case models.CollectorKindNode:
		return models.EstateKindNode
	default:
		return models.EstateKindHost
	}
}

func providerForCollectorKind(kind string) string {
	if kind == models.CollectorKindK8s {
		return models.ProviderKubernetes
	}
	return models.ProviderLinux
}

func scopesFromCeiling(raw json.RawMessage) (models.StringList, error) {
	defaults := models.StringList{
		models.CollectorScopeIngest,
		models.CollectorScopePolicyRead,
		models.CollectorScopeReceiptWrite,
	}
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		return defaults, nil
	}
	var doc struct {
		Scopes []string `json:"scopes"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc.Scopes == nil {
		return defaults, nil
	}
	out := make(models.StringList, 0, len(doc.Scopes))
	seen := map[string]bool{}
	for _, scope := range doc.Scopes {
		if !containsString(models.ValidCollectorScopes(), scope) {
			return nil, fmt.Errorf("unknown scope %q", scope)
		}
		if !seen[scope] {
			out = append(out, scope)
			seen[scope] = true
		}
	}
	if len(out) == 0 {
		return nil, errors.New("empty scope list")
	}
	return out, nil
}

func hintString(hints map[string]any, key string) string {
	if hints == nil {
		return ""
	}
	v, _ := hints[key].(string)
	return v
}

func encodeStd(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

func verifyKey(publicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
}

func mapConstraint(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "uq_collector_instances_active_install") ||
		strings.Contains(msg, "discovery_sources_instance_key") ||
		strings.Contains(msg, "collector_rotation_nonces_pkey") ||
		strings.Contains(msg, "duplicate key") {
		return fmt.Errorf("%w: %v", ErrCollectorConflict, err)
	}
	return err
}
