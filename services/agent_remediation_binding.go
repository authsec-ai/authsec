package services

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsremediate"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
)

// The remediation binding (W8, decision 2): the customer-consented
// REMEDIATION role of one connected AWS account (cloud_remediation_binding,
// migration 230). Separate from the discovery and the enforcement roles: its
// own template (authsec-aws-remediation-role.yaml), its own ExternalId (minted
// under its own HMAC domain, kept in Vault, never returned except to the
// person setting it up), its own state. A workspace starts with none, and
// without a VERIFIED binding every remediation of the account is prepared
// (or a pull request), never a write.
//
// Setup is manual (POST /remediations/bindings with the connector, then
// POST /remediations/bindings/:id/verify with the stack's RoleArn output):
// AuthSec assumes the role with the ExternalId and checks the session is in
// the connector's account. A Quick Create callback like enforcement's is a
// follow-up. Every statement runs under row-level security for the
// workspace; another workspace's binding is 404.

// Binding states.
const (
	RemediationBindingPending  = "pending"
	RemediationBindingVerified = "verified"
	RemediationBindingError    = "error"
	RemediationBindingRevoked  = "revoked"
)

// remediationExternalIDDomain separates remediation ExternalIds from the
// discovery and enforcement ones (a value minted for one never verifies for
// another).
const remediationExternalIDDomain = "cloud-remediation"

// Error codes.
const (
	RemCodeBindingExists     = "remediation_binding_exists"
	RemCodeBindingNotPending = "remediation_binding_not_pending"
	RemCodeAssumeFailed      = "remediation_assume_failed"
	RemCodeNotConfigured     = "remediation_not_configured"
	RemCodeWrongAccount      = "remediation_wrong_account"
	RemCodeNoBinding         = "remediation_role_not_connected"
)

// MintRemediationExternalID issues a remediation ExternalId for a workspace:
// `rem<nonce>.<signature>`.
func MintRemediationExternalID(ws uuid.UUID) (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("external id nonce: %w", err)
	}
	nonce := "rem" + hex.EncodeToString(b)
	return nonce + externalIDSeparator + signRemediationExternalID(ws, nonce), nil
}

func signRemediationExternalID(ws uuid.UUID, nonce string) string {
	mac := hmac.New(sha256.New, cloudDiscoveryHMACKey())
	mac.Write([]byte(remediationExternalIDDomain))
	mac.Write([]byte(externalIDSeparator))
	mac.Write([]byte(ws.String()))
	mac.Write([]byte(externalIDSeparator))
	mac.Write([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:32]
}

// VerifyRemediationExternalID checks an ExternalId was issued to this
// workspace FOR REMEDIATION.
func VerifyRemediationExternalID(ws uuid.UUID, ext string) error {
	nonce, sig, ok := strings.Cut(ext, externalIDSeparator)
	if !ok || nonce == "" || sig == "" || !hmac.Equal([]byte(sig), []byte(signRemediationExternalID(ws, nonce))) {
		return ErrExternalIDNotIssued
	}
	return nil
}

// RemediationExternalIDPath is the Vault path of an account's remediation
// ExternalId.
func RemediationExternalIDPath(ws uuid.UUID, account string) string {
	return fmt.Sprintf("kv/data/secret/workspaces/%s/cloud-remediation/aws/%s", ws, account)
}

/* --------------------------------- wiring --------------------------------- */

// RemediationAccess opens one remediation's AWS account: the remediation
// role's session for writes (verified binding, ExternalId from Vault,
// RoleSessionName authsec-remediate-<16hex>, 900 s) joined with the
// discovery role for reads; and the discovery reads alone (planning, and
// the proof of prepared changes).
type RemediationAccess interface {
	Open(ctx context.Context, ws, connectorID, remediationID uuid.UUID) (awsremediate.Account, error)
	Reader(ctx context.Context, ws, connectorID uuid.UUID) (awsremediate.Reader, error)
}

var remediationDeps = struct {
	sync.RWMutex
	vault   vault.VaultClient
	access  RemediationAccess
	assumer awsremediate.Assumer
	cb      awsdiscovery.CallbackConfig
	princ   string
	db      *gorm.DB
}{assumer: awsremediate.LiveAssumer{}}

// SetRemediationAccess installs the AWS access (tests: a fake account); nil
// restores production. It returns the undo.
func SetRemediationAccess(a RemediationAccess) (restore func()) {
	remediationDeps.Lock()
	prev := remediationDeps.access
	remediationDeps.access = a
	remediationDeps.Unlock()
	return func() { SetRemediationAccess(prev) }
}

// SetRemediationAssumer installs how the remediation role is assumed (tests:
// a fake); nil restores the live one. It returns the undo.
func SetRemediationAssumer(a awsremediate.Assumer) (restore func()) {
	remediationDeps.Lock()
	prev := remediationDeps.assumer
	if a == nil {
		a = awsremediate.LiveAssumer{}
	}
	remediationDeps.assumer = a
	remediationDeps.Unlock()
	return func() { SetRemediationAssumer(prev) }
}

// SetRemediationVault installs the Vault client that keeps remediation
// ExternalIds (nil: none). It returns the undo.
func SetRemediationVault(vc vault.VaultClient) (restore func()) {
	remediationDeps.Lock()
	prev := remediationDeps.vault
	remediationDeps.vault = vc
	remediationDeps.Unlock()
	return func() { SetRemediationVault(prev) }
}

func remediationVault() vault.VaultClient {
	remediationDeps.RLock()
	defer remediationDeps.RUnlock()
	return remediationDeps.vault
}

func remediationAssumer() awsremediate.Assumer {
	remediationDeps.RLock()
	defer remediationDeps.RUnlock()
	return remediationDeps.assumer
}

func remediationAccess() RemediationAccess {
	remediationDeps.RLock()
	defer remediationDeps.RUnlock()
	return remediationDeps.access
}

// InstallRemediation wires production: the Vault client (ExternalIds), the
// live AWS access (the discovery role through the onboarding service; the
// remediation role through LiveAssumer), the callback configuration (the
// template URL) and the database the post-approval run and the worker use.
// cmd/main.go calls it once.
func InstallRemediation(db *gorm.DB) {
	remediationDeps.Lock()
	remediationDeps.db = db
	remediationDeps.princ = os.Getenv("AUTHSEC_AWS_DISCOVERY_PRINCIPAL_ARN")
	if cb, err := LoadAWSCallbackConfig(); err == nil {
		remediationDeps.cb = cb
	}
	remediationDeps.Unlock()
	addr, tok := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN")
	if addr == "" || tok == "" {
		log.Printf("[remediation] VAULT_ADDR/VAULT_TOKEN not set: no remediation role can be connected; every remediation is prepared")
		return
	}
	vc, err := vault.NewClient(addr, tok)
	if err != nil {
		log.Printf("[remediation] vault client: %v; every remediation is prepared", err)
		return
	}
	SetRemediationVault(vc)
	if remediationAccess() == nil {
		SetRemediationAccess(&liveRemediationAccess{db: db, onboarding: NewAWSOnboardingService(db, vc)})
	}
}

func remediationDB() *gorm.DB {
	remediationDeps.RLock()
	defer remediationDeps.RUnlock()
	return remediationDeps.db
}

// liveRemediationAccess is production.
type liveRemediationAccess struct {
	db         *gorm.DB
	onboarding *AWSOnboardingService
}

func (l *liveRemediationAccess) Reader(ctx context.Context, ws, connectorID uuid.UUID) (awsremediate.Reader, error) {
	cfg, c, err := l.onboarding.ConfigForConnector(ctx, ws, connectorID, "")
	if err != nil {
		return nil, govErr(http.StatusConflict, EnfCodeDiscoveryUnavailable, "The account's discovery role could not be used.", nil)
	}
	if c == nil || c.Provider != models.CloudProviderAWS || c.Status != models.CloudConnectorActive {
		return nil, govErr(http.StatusConflict, EnfCodeDiscoveryUnavailable, "The account's discovery connector is not active.", nil)
	}
	return awsremediate.NewLiveReader(cfg), nil
}

func (l *liveRemediationAccess) Open(ctx context.Context, ws, connectorID, remediationID uuid.UUID) (awsremediate.Account, error) {
	r, err := l.Reader(ctx, ws, connectorID)
	if err != nil {
		return nil, err
	}
	w, err := AssumeRemediation(ctx, l.db, ws, connectorID, remediationID)
	if err != nil {
		return nil, err
	}
	return awsremediate.Join(r, w), nil
}

// AssumeRemediation assumes the connector's VERIFIED remediation role for
// one remediation (session authsec-remediate-<16hex>) and proves the
// session is in the binding's account. The ExternalId and the credentials
// are never logged or returned.
func AssumeRemediation(ctx context.Context, db *gorm.DB, ws, connectorID, remediationID uuid.UUID) (awsremediate.Writer, error) {
	b, err := liveRemediationBinding(ctx, db, ws, connectorID)
	if err != nil {
		return nil, err
	}
	if b == nil || b.State != RemediationBindingVerified {
		return nil, govConflict(RemCodeNoBinding, "This account has no verified remediation role.", nil)
	}
	ext, err := readRemediationExternalID(b.AuthRef)
	if err != nil {
		return nil, err
	}
	w, id, err := remediationAssumer().AssumeRemediation(ctx, awsremediate.AssumeInput{RoleARN: b.RoleARN, ExternalID: ext,
		Region: "us-east-1", SessionName: awsremediate.SessionName(remediationID.String())})
	if err != nil {
		log.Printf("[remediation] binding %s remediation %s: assume failed", b.ID, remediationID)
		return nil, govConflict(RemCodeAssumeFailed, "The remediation role could not be assumed.", nil)
	}
	if id == nil || id.AccountID != b.AccountRef {
		return nil, govConflict(RemCodeAssumeFailed, "The remediation session is not in the binding's account.", nil)
	}
	return w, nil
}

func readRemediationExternalID(ref string) (string, error) {
	vc := remediationVault()
	if vc == nil || ref == "" {
		return "", govErr(http.StatusServiceUnavailable, RemCodeNotConfigured, "The remediation ExternalId cannot be read (no secrets store).", nil)
	}
	sec, err := vc.ReadSecret(ref)
	if err != nil {
		return "", govErr(http.StatusServiceUnavailable, RemCodeNotConfigured, "The remediation ExternalId could not be read.", nil)
	}
	ext, _ := sec["external_id"].(string)
	if ext == "" {
		return "", govErr(http.StatusServiceUnavailable, RemCodeNotConfigured, "The remediation ExternalId is missing.", nil)
	}
	return ext, nil
}

/* --------------------------------- binding -------------------------------- */

// RemediationBinding is a binding as the API shows it. The ExternalId is
// only in the setup answer, to the person setting it up.
type RemediationBinding struct {
	ID              uuid.UUID  `json:"id" gorm:"column:id"`
	ConnectorID     uuid.UUID  `json:"connector_id" gorm:"column:connector_id"`
	Provider        string     `json:"provider" gorm:"column:provider"`
	AccountRef      string     `json:"account_id" gorm:"column:account_ref"`
	RoleARN         string     `json:"role_arn" gorm:"column:role_arn"`
	AuthRef         string     `json:"-" gorm:"column:auth_ref"`
	TemplateVersion string     `json:"template_version" gorm:"column:template_version"`
	State           string     `json:"state" gorm:"column:state"`
	LastError       string     `json:"last_error" gorm:"column:last_error"`
	ConsentedBy     uuid.UUID  `json:"consented_by" gorm:"column:consented_by"`
	VerifiedAt      *time.Time `json:"verified_at" gorm:"column:verified_at"`
	RevokedAt       *time.Time `json:"revoked_at" gorm:"column:revoked_at"`
	CreatedAt       time.Time  `json:"created_at" gorm:"column:created_at"`
}

const remediationBindingCols = `id, connector_id, provider, account_ref, role_arn, auth_ref, template_version, state, last_error,
	consented_by, verified_at, revoked_at, created_at`

// RemediationSetup is POST /remediations/bindings' answer.
type RemediationSetup struct {
	Binding         RemediationBinding `json:"binding"`
	ExternalID      string             `json:"external_id"`
	StackName       string             `json:"stack_name"`
	RoleName        string             `json:"role_name"`
	TemplateURL     string             `json:"template_url"`
	TemplateVersion string             `json:"template_version"`
	QuickCreateURL  string             `json:"quick_create_url,omitempty"`
	PrincipalARN    string             `json:"authsec_principal_arn,omitempty"`
}

func liveRemediationBinding(ctx context.Context, db *gorm.DB, ws, connectorID uuid.UUID) (*RemediationBinding, error) {
	var rows []RemediationBinding
	err := tenancy.InWorkspaceRead(ctx, db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+remediationBindingCols+` FROM cloud_remediation_binding
		    WHERE workspace_id = ? AND connector_id = ? AND state <> 'revoked' ORDER BY created_at DESC LIMIT 1`, ws, connectorID).Scan(&rows).Error
	})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

// RemediationSuffix is a binding's NameSuffix (8 hex of its id).
func RemediationSuffix(id uuid.UUID) string { return strings.ReplaceAll(id.String(), "-", "")[:8] }

// SetupRemediationBinding opens the remediation setup of an AWS connector:
// a pending binding and its ExternalId (minted once per account, kept in
// Vault). One live binding per connector (409 otherwise).
func SetupRemediationBinding(ctx context.Context, db *gorm.DB, ws, connectorID, actor uuid.UUID) (*RemediationSetup, error) {
	if err := RequireRemediation(db); err != nil {
		return nil, err
	}
	vc := remediationVault()
	if vc == nil {
		return nil, govErr(http.StatusServiceUnavailable, RemCodeNotConfigured, "The secrets store is not configured; a remediation role cannot be connected.", nil)
	}
	var conn models.CloudConnector
	if err := tenancy.InWorkspaceRead(ctx, db, ws, func(tx *gorm.DB) error {
		res := tx.Where("workspace_id = ? AND id = ?", ws, connectorID).Limit(1).Find(&conn)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return GovNotFound()
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if conn.Provider != models.CloudProviderAWS || conn.ScopeKind != "account" {
		return nil, GovBadParam("connector_id", "A remediation role is connected to an AWS account connector.")
	}
	path := RemediationExternalIDPath(ws, conn.ScopeID)
	ext := ""
	if sec, err := vc.ReadSecret(path); err == nil {
		if v, _ := sec["external_id"].(string); v != "" && VerifyRemediationExternalID(ws, v) == nil {
			ext = v
		}
	}
	if ext == "" {
		v, err := MintRemediationExternalID(ws)
		if err != nil {
			return nil, err
		}
		if err := vc.WriteSecret(path, map[string]interface{}{"external_id": v}); err != nil {
			log.Printf("[remediation] workspace %s account %s: storing the remediation external id failed (%T)", ws, conn.ScopeID, err)
			return nil, govErr(http.StatusServiceUnavailable, RemCodeNotConfigured, "The remediation ExternalId could not be stored; try again shortly.", nil)
		}
		ext = v
	}
	var out RemediationBinding
	err := tenancy.InWorkspace(ctx, db, ws, func(tx *gorm.DB) error {
		var rows []RemediationBinding
		err := tx.Raw(`INSERT INTO cloud_remediation_binding (workspace_id, connector_id, provider, account_ref, auth_ref, template_version, consented_by)
		    VALUES (?, ?, 'aws', ?, ?, ?, ?) RETURNING `+remediationBindingCols,
			ws, connectorID, conn.ScopeID, path, awsdiscovery.RemediationTemplateVersion, actor).Scan(&rows).Error
		if isUniqueViolation(err, "uq_cloud_remediation_binding_live") {
			return govConflict(RemCodeBindingExists, "This account already has a remediation binding; revoke it first.", nil)
		}
		if err != nil {
			return err
		}
		out = rows[0]
		return appendGovEvent(tx, ws, GovEventRemediationBindingCreated, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"binding_id": out.ID, "connector_id": connectorID, "account_id": conn.ScopeID})
	})
	if err != nil {
		return nil, err
	}
	remediationDeps.RLock()
	cb, princ := remediationDeps.cb, remediationDeps.princ
	remediationDeps.RUnlock()
	suffix := RemediationSuffix(out.ID)
	s := &RemediationSetup{Binding: out, ExternalID: ext, StackName: awsdiscovery.RemediationStackName(suffix),
		RoleName: awsdiscovery.RemediationRoleName(suffix), TemplateURL: cb.RemediationTemplateURL(),
		TemplateVersion: awsdiscovery.RemediationTemplateVersion, PrincipalARN: princ}
	if s.TemplateURL != "" && princ != "" {
		if link, err := awsdiscovery.RemediationQuickCreateURL("us-east-1", s.TemplateURL, s.StackName,
			map[string]string{"AuthSecPrincipalArn": princ, "ExternalId": ext, "NameSuffix": suffix}); err == nil {
			s.QuickCreateURL = link
		}
	}
	return s, nil
}

// VerifyRemediationBinding binds the stack's RoleArn to a pending (or
// failed) binding: the role must be AuthSecRemediation-<suffix> in the
// connector's account, and AuthSec must assume it with the ExternalId into
// that account. Success makes the binding verified; failure records why.
func VerifyRemediationBinding(ctx context.Context, db *gorm.DB, ws, bindingID, actor uuid.UUID, roleARN string) (*RemediationBinding, error) {
	if err := RequireRemediation(db); err != nil {
		return nil, err
	}
	var b RemediationBinding
	if err := tenancy.InWorkspaceRead(ctx, db, ws, func(tx *gorm.DB) error {
		var rows []RemediationBinding
		if err := tx.Raw(`SELECT `+remediationBindingCols+` FROM cloud_remediation_binding WHERE workspace_id = ? AND id = ?`, ws, bindingID).
			Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return GovNotFound()
		}
		b = rows[0]
		return nil
	}); err != nil {
		return nil, err
	}
	if b.State == RemediationBindingRevoked {
		return nil, govConflict(RemCodeBindingNotPending, "This binding was revoked.", nil)
	}
	roleARN = strings.TrimSpace(roleARN)
	_, account, err := awsdiscovery.ParseRoleARN(roleARN)
	if err != nil {
		return nil, GovBadParam("role_arn", "role_arn must be the stack's RoleArn output (an IAM role ARN).")
	}
	if account != b.AccountRef {
		return nil, govErr(http.StatusUnprocessableEntity, RemCodeWrongAccount, "The role is not in the connector's account.", nil)
	}
	if name, _, _ := awsdiscovery.RoleNameFromARN(roleARN); name != awsdiscovery.RemediationRoleName(RemediationSuffix(b.ID)) {
		return nil, GovBadParam("role_arn", "role_arn must name the role the remediation stack created ("+
			awsdiscovery.RemediationRoleName(RemediationSuffix(b.ID))+").")
	}
	ext, err := readRemediationExternalID(b.AuthRef)
	if err != nil {
		return nil, err
	}
	_, id, aerr := remediationAssumer().AssumeRemediation(ctx, awsremediate.AssumeInput{RoleARN: roleARN, ExternalID: ext,
		Region: "us-east-1", SessionName: "authsec-remediate-verify"})
	state, lastErr, event := RemediationBindingVerified, "", GovEventRemediationBindingVerified
	switch {
	case aerr != nil:
		state, lastErr, event = RemediationBindingError, "The remediation role could not be assumed with the ExternalId.", GovEventRemediationBindingFailed
	case id == nil || id.AccountID != b.AccountRef:
		state, lastErr, event = RemediationBindingError, "The remediation session is not in the connector's account.", GovEventRemediationBindingFailed
	}
	now := time.Now().UTC()
	var out RemediationBinding
	err = tenancy.InWorkspace(ctx, db, ws, func(tx *gorm.DB) error {
		var rows []RemediationBinding
		var verifiedAt *time.Time
		if state == RemediationBindingVerified {
			verifiedAt = &now
		}
		if err := tx.Raw(`UPDATE cloud_remediation_binding SET role_arn = ?, state = ?, last_error = ?, verified_at = ?, updated_at = now()
		    WHERE workspace_id = ? AND id = ? AND state <> 'revoked' RETURNING `+remediationBindingCols,
			roleARN, state, lastErr, verifiedAt, ws, bindingID).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return govConflict(RemCodeBindingNotPending, "This binding was revoked meanwhile.", nil)
		}
		out = rows[0]
		return appendGovEvent(tx, ws, event, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"binding_id": bindingID, "account_id": b.AccountRef, "role_arn": roleARN, "state": state})
	})
	if err != nil {
		return nil, err
	}
	if state != RemediationBindingVerified {
		return &out, govConflict(RemCodeAssumeFailed, lastErr, map[string]any{"binding_id": bindingID})
	}
	return &out, nil
}

// RevokeRemediationBinding ends a binding: every later remediation of the
// account is prepared. The ExternalId stays in Vault (a new setup reuses it,
// as the stack the customer still has expects it) until the customer
// deletes the stack.
func RevokeRemediationBinding(ctx context.Context, db *gorm.DB, ws, bindingID, actor uuid.UUID) (*RemediationBinding, error) {
	if err := RequireRemediation(db); err != nil {
		return nil, err
	}
	var out RemediationBinding
	err := tenancy.InWorkspace(ctx, db, ws, func(tx *gorm.DB) error {
		var rows []RemediationBinding
		if err := tx.Raw(`UPDATE cloud_remediation_binding SET state = 'revoked', revoked_at = now(), updated_at = now()
		    WHERE workspace_id = ? AND id = ? AND state <> 'revoked' RETURNING `+remediationBindingCols, ws, bindingID).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			var n int64
			if err := tx.Raw(`SELECT count(*) FROM cloud_remediation_binding WHERE workspace_id = ? AND id = ?`, ws, bindingID).Scan(&n).Error; err != nil {
				return err
			}
			if n == 0 {
				return GovNotFound()
			}
			return govConflict(RemCodeBindingNotPending, "This binding is already revoked.", nil)
		}
		out = rows[0]
		return appendGovEvent(tx, ws, GovEventRemediationBindingRevoked, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"binding_id": bindingID, "account_id": out.AccountRef})
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// RemediationReadinessAccount is one connector's remediation readiness.
type RemediationReadinessAccount struct {
	ConnectorID  uuid.UUID  `json:"connector_id"`
	Provider     string     `json:"provider"`
	AccountID    string     `json:"account_id"`
	BindingID    *uuid.UUID `json:"binding_id"`
	BindingState string     `json:"binding_state"`
	Ready        bool       `json:"ready"`
	// Mode is what a remediation of this account would be now: write with
	// a verified role, prepared otherwise.
	Mode   string `json:"mode"`
	Reason string `json:"reason"`
}

// RemediationReadiness is GET /remediations/readiness.
type RemediationReadiness struct {
	Available bool                          `json:"available"`
	Reason    string                        `json:"reason"`
	Accounts  []RemediationReadinessAccount `json:"accounts"`
	// Writers is what each kind really does with a verified role.
	Writers map[string]string `json:"writers"`
}

// RemediationWriters describes each kind's writer per provider (also shown
// by /capabilities).
var RemediationWriters = map[string]string{
	"aws":   "write with a verified remediation role; prepared change (or IaC pull request) otherwise",
	"azure": "prepared change only (custom role documented in deploy/remediation/azure-remediation-role.json)",
	"k8s":   "prepared change only (ClusterRole documented in deploy/remediation/k8s-remediation-clusterrole.yaml)",
	"model_provider": "ask: the provider admin key is created in the provider console (no provider write API is used); " +
		"AuthSec stores it through the existing rotate endpoint",
}

// GetRemediationReadiness lists the workspace's AWS accounts with their
// remediation binding.
func GetRemediationReadiness(ctx context.Context, db *gorm.DB, ws uuid.UUID) (*RemediationReadiness, error) {
	out := &RemediationReadiness{Accounts: []RemediationReadinessAccount{}, Writers: RemediationWriters}
	out.Available, out.Reason = RemediationStatus(db)
	if !out.Available {
		return out, nil
	}
	type row struct {
		ID        uuid.UUID
		Provider  string
		ScopeID   string
		BindingID *uuid.UUID
		State     *string
	}
	var rows []row
	err := tenancy.InWorkspaceRead(ctx, db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT c.id, c.provider, c.scope_id, b.id AS binding_id, b.state
		    FROM cloud_connector c
		    LEFT JOIN cloud_remediation_binding b ON b.workspace_id = c.workspace_id AND b.connector_id = c.id AND b.state <> 'revoked'
		   WHERE c.workspace_id = ? AND c.provider = 'aws' AND c.scope_kind = 'account' AND c.status = 'active'
		   ORDER BY c.scope_id`, ws).Scan(&rows).Error
	})
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		a := RemediationReadinessAccount{ConnectorID: r.ID, Provider: r.Provider, AccountID: r.ScopeID, BindingID: r.BindingID,
			BindingState: "none", Mode: RemediationModePrepared, Reason: RemCodeNoBinding}
		if r.State != nil {
			a.BindingState = *r.State
		}
		if a.BindingState == RemediationBindingVerified {
			a.Ready, a.Mode, a.Reason = true, RemediationModeWrite, ""
		}
		out.Accounts = append(out.Accounts, a)
	}
	return out, nil
}

// errNoAccess is the error of an AWS access not installed.
var errNoAccess = errors.New("remediation AWS access is not configured")
