package services

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// The enforcement binding (SPEC-iga-phase3-policy.md §3.5, §3.6, §4.4, §7.9,
// T3.09): the customer-consented enforcement role of one connected AWS
// account, recorded as a cloud_enforcement_binding row.
//
// Lifecycle of a row (state, role_arn):
//
//	StartSession          -> pending, ''           ExternalId ensured in Vault, Quick Create link issued
//	callback / manual     -> verifying, ''         claimed by ONE worker (compare-and-swap)
//	   assume fails        -> error, ''            FAILED to CloudFormation; a new session may restart it
//	   bound               -> verifying, role      the account is bound to this workspace
//	self-test             -> verified | partial | error, role   (§3.6 per-capability result)
//	Revoke                -> revoked               ExternalId deleted from Vault; J3 refused
//
// The session IS the pending row. DECISION (T3.09): the discovery Quick
// Create keeps its sessions in Redis; the enforcement one does not need to,
// because the account is known before the stack exists (the binding belongs
// to an existing connector) and the ExternalId is stable per workspace +
// account. A durable row is what GET .../enforcement and the poll read, it
// survives a restart, and a callback finds its row by the account in the
// StackId plus the ExternalId (HMAC-bound to the workspace, then compared
// with Vault). Single use: only an UNBOUND row accepts a Create; a bound row
// answers a repeat of the same roles SUCCESS and anything else FAILED.

// Enforcement ExternalId domain. DECISION (T3.09): §3.6 says "minted
// separately; never equal to discovery's" and §10 "HMAC-bound like
// discovery's". The signature covers a domain string as well as the
// workspace and nonce, so an enforcement ExternalId never verifies as a
// discovery one and vice versa -- not merely unequal, but unusable in the
// other flow.
const enforcementExternalIDDomain = "cloud-enforcement"

// Timing.
const (
	// enfSessionTTL is how long a Quick Create link stays usable (as
	// discovery's awsOnbSessionTTL). The manual path has no expiry: it is an
	// authenticated governance:enforce call, and the assume proves the role.
	enfSessionTTL = time.Hour
	// enfClaimStale releases a callback/manual claim whose worker died.
	enfClaimStale = 5 * time.Minute
	// enfSelfTestStale releases a self-test whose worker died.
	enfSelfTestStale = 10 * time.Minute
	// EnforcementSelfTestReuse is §3.6's "a cached result younger than 1 hour
	// is reused" before a deployment batch.
	EnforcementSelfTestReuse = time.Hour
)

// Event names written to iga_gov_event by this service.
const (
	EventEnforcementSessionStarted = "enforcement_binding.session_started"
	EventEnforcementBound          = "enforcement_binding.bound"
	EventEnforcementBindFailed     = "enforcement_binding.bind_failed"
	EventEnforcementSelfTest       = "enforcement_binding.self_test"
	EventEnforcementRevoked        = "enforcement_binding.revoked"
)

// Error codes of the §7.9 routes. artifact_owned_elsewhere, binding_partial
// and binding_not_verified are §7.12's; the others are setup-only codes the
// Setup view handles (DECISION, T3.09: §7.12 lists none for binding setup).
const (
	EnfCodeNotFound           = "not_found"
	EnfCodeNotConfigured      = "enforcement_not_configured"
	EnfCodeConnectorRevoked   = "connector_revoked"
	EnfCodeBindingExists      = "binding_exists"
	EnfCodeSessionRequired    = "enforcement_session_required"
	EnfCodeOwnedElsewhere     = "artifact_owned_elsewhere"
	EnfCodeNotBound           = "binding_not_bound"
	EnfCodeSelfTestInProgress = "self_test_in_progress"
	EnfCodeValidation         = "validation_failed"
	EnfCodeAssumeFailed       = "enforcement_assume_failed"
	EnfCodeNotVerified        = "binding_not_verified"
	EnfCodePartial            = "binding_partial"
	EnfCodeUnavailable        = "enforcement_unavailable"
)

// EnforcementError is a refusal with a status and a stable code.
type EnforcementError struct {
	Status  int
	Code    string
	Message string
	Detail  map[string]any
}

func (e *EnforcementError) Error() string { return e.Code + ": " + e.Message }

func enfErr(status int, code, msg string, detail map[string]any) *EnforcementError {
	return &EnforcementError{Status: status, Code: code, Message: msg, Detail: detail}
}

var errEnfClaimLost = errors.New("the binding changed while it was being bound")

// EnforcementActor is who caused a binding change, for iga_gov_event.
type EnforcementActor struct {
	Kind string // user | system | aws
	ID   string
}

// EnforcementBindingService owns the binding: sessions, the callback, the
// manual bind, the self-test and revoke.
type EnforcementBindingService struct {
	db         *gorm.DB
	vault      vault.VaultClient
	connectors repositories.CloudConnectorRepository
	events     repositories.IGAGovEventRepository
	assumer    awsenforce.Assumer
	cfg        awsdiscovery.CallbackConfig
	principal  string

	http          *http.Client
	now           func() time.Time
	sleep         func(ctx context.Context, d time.Duration) error
	// policyGate is the IGA_POLICY gate an enforcement registration Create
	// is processed under (nil: the process-wide gate, read per message).
	policyGate func() *PolicyGate
	templateCheck func(ctx context.Context, templateURL string) error
}

// NewEnforcementBindingService builds the service against real AWS. cfg is
// the Quick Create callback configuration (the enforcement stack reuses its
// topics and queue); principal is AuthSec's AWS principal.
func NewEnforcementBindingService(db *gorm.DB, vc vault.VaultClient, cfg awsdiscovery.CallbackConfig, principal string) *EnforcementBindingService {
	s := &EnforcementBindingService{
		db: db, vault: vc,
		connectors: repositories.NewCloudConnectorRepository(db),
		events:     repositories.NewIGAGovEventRepository(db),
		assumer:    awsenforce.LiveAssumer{},
		cfg:        cfg,
		principal:  strings.TrimSpace(principal),
		http:       awsdiscovery.NewCFNResponseClient(),
		now:        time.Now,
		sleep:      sleepCtx,
	}
	s.templateCheck = newTemplateChecker(func() time.Time { return s.now() })
	return s
}

// WithPolicyGate makes the callback read g instead of the process-wide
// IGA_POLICY gate (tests).
func (s *EnforcementBindingService) WithPolicyGate(g *PolicyGate) *EnforcementBindingService {
	s.policyGate = func() *PolicyGate { return g }
	return s
}

func (s *EnforcementBindingService) gate() *PolicyGate {
	if s.policyGate != nil {
		return s.policyGate()
	}
	return PolicyGateState()
}

// WithAssumer swaps the AWS boundary (tests use a fake).
func (s *EnforcementBindingService) WithAssumer(a awsenforce.Assumer) *EnforcementBindingService {
	s.assumer = a
	return s
}

// WithClock swaps the clock (tests).
func (s *EnforcementBindingService) WithClock(now func() time.Time) *EnforcementBindingService {
	s.now = now
	return s
}

// WithHTTPClient swaps the client CloudFormation answers are PUT with (tests).
func (s *EnforcementBindingService) WithHTTPClient(c *http.Client) *EnforcementBindingService {
	s.http = c
	return s
}

// WithSleep swaps the retry sleep (tests advance a fake clock instead).
func (s *EnforcementBindingService) WithSleep(f func(ctx context.Context, d time.Duration) error) *EnforcementBindingService {
	s.sleep = f
	return s
}

// WithTemplateCheck swaps the published-template HEAD check (tests).
func (s *EnforcementBindingService) WithTemplateCheck(f func(ctx context.Context, templateURL string) error) *EnforcementBindingService {
	s.templateCheck = f
	return s
}

/* ------------------------------- ExternalId ------------------------------- */

// MintEnforcementExternalID issues an enforcement ExternalId for a workspace:
// `enf<nonce>.<signature>`, the signature an HMAC over the enforcement domain,
// the workspace and the nonce.
func MintEnforcementExternalID(workspaceID uuid.UUID) (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("external id nonce: %w", err)
	}
	nonce := "enf" + hex.EncodeToString(b)
	return nonce + externalIDSeparator + signEnforcementExternalID(workspaceID, nonce), nil
}

func signEnforcementExternalID(workspaceID uuid.UUID, nonce string) string {
	mac := hmac.New(sha256.New, cloudDiscoveryHMACKey())
	mac.Write([]byte(enforcementExternalIDDomain))
	mac.Write([]byte(externalIDSeparator))
	mac.Write([]byte(workspaceID.String()))
	mac.Write([]byte(externalIDSeparator))
	mac.Write([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:32]
}

// VerifyEnforcementExternalID checks that an ExternalId was issued to this
// workspace FOR ENFORCEMENT. A discovery ExternalId fails it.
func VerifyEnforcementExternalID(workspaceID uuid.UUID, externalID string) error {
	nonce, sig, ok := strings.Cut(externalID, externalIDSeparator)
	if !ok || nonce == "" || sig == "" {
		return ErrExternalIDNotIssued
	}
	if !hmac.Equal([]byte(sig), []byte(signEnforcementExternalID(workspaceID, nonce))) {
		return ErrExternalIDNotIssued
	}
	return nil
}

// EnforcementExternalIDPath is §3.6's Vault path for one account's
// enforcement ExternalId.
func EnforcementExternalIDPath(workspaceID uuid.UUID, accountID string) string {
	return fmt.Sprintf("kv/data/secret/workspaces/%s/cloud-enforcement/aws/%s", workspaceID, accountID)
}

// ensureExternalID returns the account's enforcement ExternalId, minting and
// storing it on first use. Stable per workspace + account until Revoke
// deletes it, so the manual path and a re-issued link use the same value.
func (s *EnforcementBindingService) ensureExternalID(ws uuid.UUID, accountID, discoveryAuthRef string) (string, string, error) {
	if s.vault == nil {
		return "", "", enfErr(http.StatusServiceUnavailable, EnfCodeNotConfigured,
			"The secrets store is not configured; the enforcement ExternalId cannot be stored.", nil)
	}
	path := EnforcementExternalIDPath(ws, accountID)
	if sec, err := s.vault.ReadSecret(path); err == nil {
		if ext, _ := sec["external_id"].(string); ext != "" && VerifyEnforcementExternalID(ws, ext) == nil {
			return ext, path, nil
		}
	}
	discovery := ""
	if discoveryAuthRef != "" {
		if sec, err := s.vault.ReadSecret(discoveryAuthRef); err == nil {
			discovery, _ = sec["external_id"].(string)
		}
	}
	for i := 0; i < 3; i++ {
		ext, err := MintEnforcementExternalID(ws)
		if err != nil {
			return "", "", err
		}
		if ext == discovery {
			continue // §3.6: never equal to discovery's (the domain makes this unreachable)
		}
		if err := s.vault.WriteSecret(path, map[string]interface{}{"external_id": ext}); err != nil {
			log.Printf("[aws-enf] workspace %s account %s: storing the enforcement external id failed: %v", ws, accountID, err)
			return "", "", enfErr(http.StatusServiceUnavailable, EnfCodeUnavailable,
				"AuthSec could not store the enforcement ExternalId; try again shortly.", nil)
		}
		return ext, path, nil
	}
	return "", "", errors.New("could not mint an enforcement external id distinct from the discovery one")
}

func (s *EnforcementBindingService) readExternalID(b *models.CloudEnforcementBinding) (string, error) {
	if s.vault == nil || b.AuthRef == "" {
		return "", ErrExternalIDUnreadable
	}
	sec, err := s.vault.ReadSecret(b.AuthRef)
	if err != nil {
		log.Printf("[aws-enf] binding %s: reading the enforcement external id failed: %v", b.ID, err)
		return "", ErrExternalIDUnreadable
	}
	ext, _ := sec["external_id"].(string)
	if ext == "" {
		return "", ErrExternalIDUnreadable
	}
	return ext, nil
}

/* --------------------------------- naming --------------------------------- */

// EnforcementSuffix is the NameSuffix of a binding's stack, derived from the
// binding id so it needs no storage: 8 lowercase base32 characters, inside
// the template's ^[a-z0-9]{1,16}$.
func EnforcementSuffix(bindingID uuid.UUID) string {
	h := sha256.Sum256([]byte("authsec-enforcement-stack:" + bindingID.String()))
	return strings.ToLower(base32.StdEncoding.EncodeToString(h[:5]))
}

// expectedSelfTestRole checks that a self-test role ARN is THIS binding's
// stack's self-test role: same account, path /, name
// AuthSecEnforcementSelfTest-<suffix>.
//
// DECISION (T3.09): §3.6 "the self-test never touches a customer role". The
// self-test attaches a deny-everything boundary to the role it is given; a
// manual bind (or an edited stack) naming a production role would otherwise
// point that at a workload. This is a safety check on the self-test target,
// not eligibility (which is by path and tag, §3.1).
func expectedSelfTestRole(b *models.CloudEnforcementBinding, arn string) error {
	partition, account, err := awsdiscovery.ParseRoleARN(arn)
	if err != nil {
		return err
	}
	name, path, err := awsdiscovery.RoleNameFromARN(arn)
	if err != nil {
		return err
	}
	want := awsdiscovery.EnforcementSelfTestRoleName(EnforcementSuffix(b.ID))
	if partition != awsdiscovery.PartitionAWS || account != b.AccountID || path != "/" || name != want {
		return fmt.Errorf("the self-test role must be arn:aws:iam::%s:role/%s (this binding's stack)", b.AccountID, want)
	}
	return nil
}

/* ---------------------------------- views ---------------------------------- */

// EnforcementBindingView is what GET .../enforcement returns.
type EnforcementBindingView struct {
	ConnectorID uuid.UUID `json:"connector_id"`
	AccountID   string    `json:"account_id"`
	// State is the row's state, or "off" when the connector has no live
	// binding. SetupState is the §9.3 S9 wording.
	State                  string                                 `json:"state"`
	SetupState             string                                 `json:"setup_state"`
	BindingID              *uuid.UUID                             `json:"binding_id"`
	RoleARN                string                                 `json:"role_arn,omitempty"`
	SelftestRoleARN        string                                 `json:"selftest_role_arn,omitempty"`
	TemplateVersion        string                                 `json:"template_version,omitempty"`
	CurrentTemplateVersion string                                 `json:"current_template_version"`
	Capabilities           map[string]awsenforce.CapabilityResult `json:"capabilities"`
	Failing                []string                               `json:"failing"`
	LastSelfTestAt         *time.Time                             `json:"last_self_test_at"`
	VerifiedAt             *time.Time                             `json:"verified_at"`
	LastError              string                                 `json:"last_error,omitempty"`
	LastErrorCode          string                                 `json:"last_error_code,omitempty"`
	ConsentedBy            *uuid.UUID                             `json:"consented_by"`
	StackName              string                                 `json:"stack_name,omitempty"`
	CreatedAt              *time.Time                             `json:"created_at"`
	UpdatedAt              *time.Time                             `json:"updated_at"`
}

func bindingCapabilities(b *models.CloudEnforcementBinding) map[string]awsenforce.CapabilityResult {
	out := map[string]awsenforce.CapabilityResult{}
	if b != nil && len(b.Capabilities) > 0 {
		_ = json.Unmarshal(b.Capabilities, &out)
	}
	for _, c := range awsenforce.Capabilities {
		if _, ok := out[c]; !ok {
			out[c] = awsenforce.CapabilityResult{Status: awsenforce.StatusUntested}
		}
	}
	return out
}

// lastSelfTestAt is the newest checked_at among the capabilities a self-test
// writes (assume alone is also written at bind time).
func lastSelfTestAt(b *models.CloudEnforcementBinding) *time.Time {
	var last *time.Time
	for name, r := range bindingCapabilities(b) {
		if name == awsenforce.CapAssume || r.CheckedAt.IsZero() {
			continue
		}
		at := r.CheckedAt
		if last == nil || at.After(*last) {
			last = &at
		}
	}
	return last
}

func setupState(b *models.CloudEnforcementBinding) string {
	switch {
	case b == nil || b.State == models.EnforcementBindingRevoked:
		return "off"
	case b.State == models.EnforcementBindingPending:
		return "waiting_for_stack"
	case b.State == models.EnforcementBindingError && b.RoleARN == "":
		// A failed bind: nothing is bound; the Setup view offers a new launch.
		return "error"
	default:
		return b.State
	}
}

func viewOf(c *models.CloudConnector, b *models.CloudEnforcementBinding) EnforcementBindingView {
	v := EnforcementBindingView{
		ConnectorID: c.ID, AccountID: c.ScopeID, State: "off", SetupState: "off",
		CurrentTemplateVersion: awsdiscovery.EnforcementTemplateVersion,
		Capabilities:           bindingCapabilities(nil),
		Failing:                []string{},
	}
	if b == nil {
		return v
	}
	id, consented, created, updated := b.ID, b.ConsentedBy, b.CreatedAt, b.UpdatedAt
	caps := bindingCapabilities(b)
	rep := awsenforce.Report{Capabilities: caps}
	failing := []string{}
	// A failed bind (error, nothing bound) never ran a self-test: last_error
	// says why, and there are no failing capabilities to list.
	if b.State == models.EnforcementBindingPartial || (b.State == models.EnforcementBindingError && b.RoleARN != "") {
		failing = rep.Failing()
	}
	v.State, v.SetupState, v.BindingID = b.State, setupState(b), &id
	v.RoleARN, v.SelftestRoleARN, v.TemplateVersion = b.RoleARN, b.SelftestRoleARN, b.TemplateVersion
	v.Capabilities, v.Failing, v.LastSelfTestAt, v.VerifiedAt = caps, failing, lastSelfTestAt(b), b.VerifiedAt
	v.LastError, v.LastErrorCode, v.ConsentedBy = b.LastError, b.LastErrorCode, &consented
	v.StackName = awsdiscovery.EnforcementStackName(EnforcementSuffix(b.ID))
	v.CreatedAt, v.UpdatedAt = &created, &updated
	return v
}

/* ------------------------------ row helpers ------------------------------- */

// awsConnector reads a connector of this workspace that is an AWS connector;
// anything else (another workspace's, a GCP one, none) is 404.
func (s *EnforcementBindingService) awsConnector(ws, id uuid.UUID) (*models.CloudConnector, error) {
	c, err := s.connectors.Get(ws, id)
	if errors.Is(err, repositories.ErrCloudConnectorNotFound) || (err == nil && c.Provider != models.CloudProviderAWS) {
		return nil, enfErr(http.StatusNotFound, EnfCodeNotFound, "Connector not found.", nil)
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (s *EnforcementBindingService) liveBinding(db *gorm.DB, ws, connectorID uuid.UUID, lock bool) (*models.CloudEnforcementBinding, error) {
	q := db.Where("workspace_id = ? AND connector_id = ? AND state <> ?", ws, connectorID, models.EnforcementBindingRevoked)
	if lock {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var rows []models.CloudEnforcementBinding
	if err := q.Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// lockAccount serialises binding changes for one AWS account across
// workspaces, so the "bound elsewhere" check and the bind are atomic.
func lockAccount(tx *gorm.DB, accountID string) error {
	return tx.Exec(`SELECT pg_advisory_xact_lock(hashtext(?))`, "cloud_enforcement_binding:"+accountID).Error
}

// boundElsewhere reports whether the account is bound (a live binding with a
// role) to a workspace other than ws.
//
// DECISION (T3.09, A17): two workspaces may connect the same AWS account for
// discovery, but only one may hold an enforcement binding for it: two
// enforcement roles in one account could each rewrite the other workspace's
// /authsec/ policies, and IAM cannot tell them apart. The refusal reuses
// §7.12's artifact_owned_elsewhere (409) and never names the other workspace.
func boundElsewhere(db *gorm.DB, ws uuid.UUID, accountID string) (bool, error) {
	var n int64
	err := db.Model(&models.CloudEnforcementBinding{}).
		Where("account_id = ? AND workspace_id <> ? AND state <> ? AND role_arn <> ''", accountID, ws, models.EnforcementBindingRevoked).
		Count(&n).Error
	return n > 0, err
}

func ownedElsewhereErr() *EnforcementError {
	return enfErr(http.StatusConflict, EnfCodeOwnedElsewhere,
		"This AWS account is already bound for enforcement by another AuthSec workspace.",
		map[string]any{"reason": "account_bound_elsewhere"})
}

func (s *EnforcementBindingService) appendEvent(tx *gorm.DB, ws uuid.UUID, event string, actor EnforcementActor, payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	kind := actor.Kind
	if kind == "" {
		kind = "system"
	}
	return s.events.AppendTx(tx, &models.IGAGovEvent{
		WorkspaceID: ws, Event: event, ActorKind: kind, ActorID: actor.ID, Payload: raw,
	})
}

func bindingPayload(b *models.CloudEnforcementBinding, extra map[string]any) map[string]any {
	p := map[string]any{
		"binding_id": b.ID, "connector_id": b.ConnectorID, "account_id": b.AccountID, "state": b.State,
	}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

/* -------------------------------- sessions -------------------------------- */

// EnforcementSession is a Quick Create (or manual) setup session: the pending
// binding, with what the customer needs to create the stack.
type EnforcementSession struct {
	ID               uuid.UUID               `json:"id"` // = the binding id
	BindingID        uuid.UUID               `json:"binding_id"`
	ConnectorID      uuid.UUID               `json:"connector_id"`
	AccountID        string                  `json:"account_id"`
	Status           string                  `json:"status"` // the binding's setup state
	Code             string                  `json:"code,omitempty"`
	Message          string                  `json:"message,omitempty"`
	ExternalID       string                  `json:"external_id,omitempty"`
	Suffix           string                  `json:"suffix"`
	StackName        string                  `json:"stack_name"`
	RoleName         string                  `json:"role_name"`
	SelfTestRoleName string                  `json:"selftest_role_name"`
	TemplateVersion  string                  `json:"template_version"`
	TemplateURL      string                  `json:"template_url,omitempty"`
	DeploymentRegion string                  `json:"deployment_region,omitempty"`
	Automatic        bool                    `json:"automatic"`
	AutomaticReason  string                  `json:"automatic_reason,omitempty"`
	QuickCreateURL   string                  `json:"quick_create_url,omitempty"`
	StackParameters  map[string]string       `json:"stack_parameters,omitempty"`
	ExpiresAt        time.Time               `json:"expires_at"`
	Binding          *EnforcementBindingView `json:"binding,omitempty"`
}

// StartSession opens (or re-opens) the setup session for a connector: the
// binding row in `pending`, the account's enforcement ExternalId in Vault,
// and -- when automatic setup is configured -- a Quick Create link for the
// enforcement stack. Allowed when the connector has no live binding, or its
// binding is pending or a failed (unbound) attempt; a bound binding is
// `binding_exists` (revoke it first).
func (s *EnforcementBindingService) StartSession(
	ctx context.Context, ws, connectorID, userID uuid.UUID, deploymentRegion string,
) (*EnforcementSession, error) {
	c, err := s.awsConnector(ws, connectorID)
	if err != nil {
		return nil, err
	}
	if c.Status == models.CloudConnectorRevoked {
		return nil, enfErr(http.StatusConflict, EnfCodeConnectorRevoked, "This AWS connection was revoked; reconnect the account first.", nil)
	}
	if s.principal == "" {
		return nil, enfErr(http.StatusServiceUnavailable, EnfCodeNotConfigured,
			"This AuthSec deployment has no AWS principal configured for customer roles to trust.", nil)
	}
	if other, err := boundElsewhere(s.db, ws, c.ScopeID); err != nil {
		return nil, err
	} else if other {
		return nil, ownedElsewhereErr()
	}
	ext, path, err := s.ensureExternalID(ws, c.ScopeID, c.AuthRef)
	if err != nil {
		return nil, err
	}

	var b models.CloudEnforcementBinding
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := lockAccount(tx, c.ScopeID); err != nil {
			return err
		}
		if other, err := boundElsewhere(tx, ws, c.ScopeID); err != nil {
			return err
		} else if other {
			return ownedElsewhereErr()
		}
		live, err := s.liveBinding(tx, ws, connectorID, true)
		if err != nil {
			return err
		}
		switch {
		case live == nil:
			b = models.CloudEnforcementBinding{
				WorkspaceID: ws, ConnectorID: connectorID, AccountID: c.ScopeID, AuthRef: path,
				State: models.EnforcementBindingPending, Capabilities: json.RawMessage(`{}`), ConsentedBy: userID,
			}
			if err := tx.Create(&b).Error; err != nil {
				return err
			}
		case live.RoleARN == "" && (live.State == models.EnforcementBindingPending || live.State == models.EnforcementBindingError):
			if err := tx.Raw(`UPDATE cloud_enforcement_binding
				   SET state = 'pending', consented_by = ?, auth_ref = ?, last_error = '', last_error_code = '',
				       capabilities = '{}', updated_at = now()
				 WHERE workspace_id = ? AND id = ? RETURNING *`, userID, path, ws, live.ID).Scan(&b).Error; err != nil {
				return err
			}
		default:
			return enfErr(http.StatusConflict, EnfCodeBindingExists,
				"This account already has an enforcement binding; revoke it before starting a new one.",
				map[string]any{"state": live.State, "binding_id": live.ID})
		}
		return s.appendEvent(tx, ws, EventEnforcementSessionStarted, EnforcementActor{Kind: "user", ID: userID.String()},
			bindingPayload(&b, map[string]any{"deployment_region": deploymentRegion}))
	})
	if err != nil {
		return nil, err
	}

	sess := s.sessionOf(c, &b, ext)
	s.attachQuickCreate(ctx, sess, deploymentRegion)
	log.Printf("[aws-enf] stage=start outcome=ok binding=%s account=%s automatic=%v", b.ID, b.AccountID, sess.Automatic)
	return sess, nil
}

func (s *EnforcementBindingService) sessionOf(c *models.CloudConnector, b *models.CloudEnforcementBinding, ext string) *EnforcementSession {
	suffix := EnforcementSuffix(b.ID)
	view := viewOf(c, b)
	sess := &EnforcementSession{
		ID: b.ID, BindingID: b.ID, ConnectorID: c.ID, AccountID: b.AccountID, Status: setupState(b),
		Code: b.LastErrorCode, Message: b.LastError, ExternalID: ext, Suffix: suffix,
		StackName: awsdiscovery.EnforcementStackName(suffix), RoleName: awsdiscovery.EnforcementRoleName(suffix),
		SelfTestRoleName: awsdiscovery.EnforcementSelfTestRoleName(suffix),
		TemplateVersion:  awsdiscovery.EnforcementTemplateVersion,
		ExpiresAt:        b.UpdatedAt.Add(enfSessionTTL).UTC(),
		Binding:          &view,
	}
	if ext != "" {
		sess.StackParameters = map[string]string{
			"AuthSecPrincipalArn": s.principal, "ExternalId": ext, "NameSuffix": suffix,
		}
	}
	return sess
}

// attachQuickCreate adds the Quick Create link when automatic setup is
// configured and the published template answers; otherwise the session
// stays manual with the reason.
func (s *EnforcementBindingService) attachQuickCreate(ctx context.Context, sess *EnforcementSession, deploymentRegion string) {
	if !s.cfg.Enabled() {
		sess.AutomaticReason = "Automatic setup is not configured on this deployment; deploy the template and post the role ARNs."
		return
	}
	regions := s.cfg.SupportedDeploymentRegions()
	dr := strings.ToLower(strings.TrimSpace(deploymentRegion))
	if _, ok := s.cfg.TopicFor(dr); !ok {
		dr = regions[0]
		for _, r := range regions {
			if r == "us-east-1" {
				dr = r
			}
		}
	}
	tplURL := s.cfg.EnforcementTemplateURLFor()
	if err := s.templateCheck(ctx, tplURL); err != nil {
		log.Printf("[aws-enf] ALERT stage=start code=template_missing template=%s err=%v", tplURL, err)
		sess.AutomaticReason = "The AuthSec enforcement template for this release is not available right now; use manual setup."
		return
	}
	topic, _ := s.cfg.TopicFor(dr)
	link, err := awsdiscovery.EnforcementQuickCreateURL(dr, tplURL, sess.StackName, map[string]string{
		"AuthSecPrincipalArn": s.principal, "ExternalId": sess.ExternalID, "CallbackTopicArn": topic, "NameSuffix": sess.Suffix,
	})
	if err != nil {
		sess.AutomaticReason = err.Error()
		return
	}
	sess.Automatic, sess.QuickCreateURL, sess.TemplateURL, sess.DeploymentRegion = true, link, tplURL, dr
}

// GetSession polls a session (a binding of this connector, any state). The
// ExternalId is returned only to the user who consented.
func (s *EnforcementBindingService) GetSession(ws, connectorID, sid, userID uuid.UUID) (*EnforcementSession, error) {
	c, err := s.awsConnector(ws, connectorID)
	if err != nil {
		return nil, err
	}
	var rows []models.CloudEnforcementBinding
	if err := s.db.Where("workspace_id = ? AND connector_id = ? AND id = ?", ws, connectorID, sid).Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, enfErr(http.StatusNotFound, EnfCodeNotFound, "Session not found.", nil)
	}
	b := &rows[0]
	ext := ""
	if userID != uuid.Nil && userID == b.ConsentedBy && b.State != models.EnforcementBindingRevoked {
		ext, _ = s.readExternalID(b)
	}
	sess := s.sessionOf(c, b, ext)
	if b.State == models.EnforcementBindingRevoked {
		sess.Status = "revoked"
	} else if b.State == models.EnforcementBindingPending && s.now().After(b.UpdatedAt.Add(enfSessionTTL)) {
		sess.Status, sess.Code = "expired", "aws_onb_unknown_link"
		sess.Message = "This launch link has expired. Start again; a stack deployed by hand can still be bound with its role ARNs."
	}
	return sess, nil
}

// Get returns the connector's binding (or state "off").
func (s *EnforcementBindingService) Get(ws, connectorID uuid.UUID) (*EnforcementBindingView, error) {
	c, err := s.awsConnector(ws, connectorID)
	if err != nil {
		return nil, err
	}
	b, err := s.liveBinding(s.db, ws, connectorID, false)
	if err != nil {
		return nil, err
	}
	v := viewOf(c, b)
	return &v, nil
}

// RequireVerified is the J3 gate (§4.3): nil only when the connector's
// binding is verified; otherwise binding_partial (naming the failing
// capabilities) or binding_not_verified. For the deployment path (T3.10,
// T3.15), which runs EnsureFresh first.
func (s *EnforcementBindingService) RequireVerified(ws, connectorID uuid.UUID) error {
	b, err := s.liveBinding(s.db, ws, connectorID, false)
	if err != nil {
		return err
	}
	switch {
	case b != nil && b.State == models.EnforcementBindingVerified:
		return nil
	case b != nil && b.State == models.EnforcementBindingPartial:
		return enfErr(http.StatusConflict, EnfCodePartial, "The enforcement binding is partial; direct changes are refused.",
			map[string]any{"failing": awsenforce.Report{Capabilities: bindingCapabilities(b)}.Failing()})
	default:
		state := "off"
		if b != nil {
			state = b.State
		}
		return enfErr(http.StatusConflict, EnfCodeNotVerified, "There is no verified enforcement binding for this account.",
			map[string]any{"state": state})
	}
}

// AssumeForDeployment is §4.4 for one deployment run (T3.10): the connector's
// binding must be verified (RequireVerified), the ExternalId is read from
// Vault (the binding's AuthRef, cloud-enforcement path), and the enforcement
// role is assumed with RoleSessionName authsec-enforce-<deployment id 16hex>
// and DurationSeconds 900 (LiveAssumer), the session proven to be in the
// binding's account. The returned client has SDK retries off. It is never
// cached: every call assumes afresh, and neither the ExternalId nor the
// credentials are logged or returned.
func (s *EnforcementBindingService) AssumeForDeployment(ctx context.Context, ws, connectorID, deploymentID uuid.UUID) (awsenforce.IAM, error) {
	if err := s.RequireVerified(ws, connectorID); err != nil {
		return nil, err
	}
	c, err := s.awsConnector(ws, connectorID)
	if err != nil {
		return nil, err
	}
	b, err := s.liveBinding(s.db, ws, connectorID, false)
	if err != nil {
		return nil, err
	}
	if b == nil || b.RoleARN == "" {
		return nil, enfErr(http.StatusConflict, EnfCodeNotBound, "There is no bound enforcement role for this account.", nil)
	}
	ext, err := s.readExternalID(b)
	if err != nil {
		return nil, enfErr(http.StatusServiceUnavailable, EnfCodeUnavailable, "The enforcement ExternalId could not be read.", nil)
	}
	iam, id, err := s.assumer.AssumeEnforcement(ctx, awsenforce.AssumeInput{
		RoleARN: b.RoleARN, ExternalID: ext, Region: s.stsRegion(c), SessionName: awsenforce.DeploymentSessionName(deploymentID),
	})
	if err != nil {
		log.Printf("[aws-enf] binding %s deployment %s: assume failed: %s", b.ID, deploymentID, awsenforce.ErrorCode(err))
		return nil, enfErr(http.StatusConflict, EnfCodeAssumeFailed, "The enforcement role could not be assumed.",
			map[string]any{"error_code": awsenforce.ErrorCode(err)})
	}
	if id == nil || id.AccountID != b.AccountID {
		return nil, enfErr(http.StatusConflict, EnfCodeAssumeFailed, "The enforcement session is not in the binding's account.", nil)
	}
	return iam, nil
}

/* ------------------------------ claim and bind ----------------------------- */

// claimUnbound moves an unbound row to `verifying` for ONE worker. allowError
// lets the manual path retry a failed attempt; a callback may not (its link
// was answered FAILED already).
func (s *EnforcementBindingService) claimUnbound(ws, id uuid.UUID, allowError bool) (*models.CloudEnforcementBinding, error) {
	states := []string{models.EnforcementBindingPending}
	if allowError {
		states = append(states, models.EnforcementBindingError)
	}
	var rows []models.CloudEnforcementBinding
	err := s.db.Raw(`UPDATE cloud_enforcement_binding
		   SET state = 'verifying', updated_at = now()
		 WHERE workspace_id = ? AND id = ? AND role_arn = ''
		   AND (state IN ? OR (state = 'verifying' AND updated_at < ?))
		RETURNING *`, ws, id, states, s.now().Add(-enfClaimStale)).Scan(&rows).Error
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

// releaseClaim returns a claimed row to pending (a transient failure: the
// callback will be redelivered).
func (s *EnforcementBindingService) releaseClaim(b *models.CloudEnforcementBinding) {
	if err := s.db.Exec(`UPDATE cloud_enforcement_binding SET state = 'pending', updated_at = now()
		 WHERE workspace_id = ? AND id = ? AND state = 'verifying' AND role_arn = ''`, b.WorkspaceID, b.ID).Error; err != nil {
		log.Printf("[aws-enf] binding %s: releasing the claim failed: %v", b.ID, err)
	}
}

// markUnbound records a failed bind attempt: `error` with nothing bound.
func (s *EnforcementBindingService) markUnbound(b *models.CloudEnforcementBinding, code, msg string, actor EnforcementActor) {
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var rows []models.CloudEnforcementBinding
		if err := tx.Raw(`UPDATE cloud_enforcement_binding
			   SET state = 'error', role_arn = '', selftest_role_arn = '', last_error = ?, last_error_code = ?, updated_at = now()
			 WHERE workspace_id = ? AND id = ? AND state = 'verifying' AND role_arn = '' RETURNING *`,
			msg, code, b.WorkspaceID, b.ID).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		return s.appendEvent(tx, b.WorkspaceID, EventEnforcementBindFailed, actor,
			bindingPayload(&rows[0], map[string]any{"code": code}))
	})
	if err != nil {
		log.Printf("[aws-enf] binding %s: recording the failed bind failed: %v", b.ID, err)
	}
}

type bindInput struct {
	RoleARN, SelfTestRoleARN, TemplateVersion string
	ConsentedBy                               *uuid.UUID
	Actor                                     EnforcementActor
	Source                                    string // quick_create | manual
	StackID                                   string
}

// bind records the proven roles on the claimed row, atomically with the
// cross-workspace check (under the account lock) and the event.
func (s *EnforcementBindingService) bind(b *models.CloudEnforcementBinding, in bindInput, assumeAt time.Time) (*models.CloudEnforcementBinding, error) {
	caps, _ := json.Marshal(map[string]awsenforce.CapabilityResult{
		awsenforce.CapAssume: {Status: awsenforce.StatusOK, CheckedAt: assumeAt.UTC()},
	})
	var out models.CloudEnforcementBinding
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := lockAccount(tx, b.AccountID); err != nil {
			return err
		}
		if other, err := boundElsewhere(tx, b.WorkspaceID, b.AccountID); err != nil {
			return err
		} else if other {
			return ownedElsewhereErr()
		}
		consented := b.ConsentedBy
		if in.ConsentedBy != nil {
			consented = *in.ConsentedBy
		}
		var rows []models.CloudEnforcementBinding
		if err := tx.Raw(`UPDATE cloud_enforcement_binding
			   SET role_arn = ?, selftest_role_arn = ?, template_version = ?, consented_by = ?,
			       state = 'verifying', capabilities = ?::jsonb, last_error = '', last_error_code = '', updated_at = now()
			 WHERE workspace_id = ? AND id = ? AND state = 'verifying' AND role_arn = '' RETURNING *`,
			in.RoleARN, in.SelfTestRoleARN, in.TemplateVersion, consented, string(caps), b.WorkspaceID, b.ID).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return errEnfClaimLost
		}
		out = rows[0]
		return s.appendEvent(tx, b.WorkspaceID, EventEnforcementBound, in.Actor, bindingPayload(&out, map[string]any{
			"role_arn": in.RoleARN, "selftest_role_arn": in.SelfTestRoleARN, "template_version": in.TemplateVersion,
			"source": in.Source, "stack_id": in.StackID, "consented_by": consented,
		}))
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// BindManual is the manual path (§7.9 POST .../enforcement): the customer
// deployed the template by hand with the session's ExternalId and NameSuffix
// and posts both role ARNs. The role is assumed once (no propagation retry:
// the caller can simply post again), the account bound, and the self-test run
// before answering.
func (s *EnforcementBindingService) BindManual(
	ctx context.Context, ws, connectorID, userID uuid.UUID, roleARN, selfTestRoleARN, templateVersion string,
) (*EnforcementBindingView, error) {
	c, err := s.awsConnector(ws, connectorID)
	if err != nil {
		return nil, err
	}
	if c.Status == models.CloudConnectorRevoked {
		return nil, enfErr(http.StatusConflict, EnfCodeConnectorRevoked, "This AWS connection was revoked; reconnect the account first.", nil)
	}
	if templateVersion == "" {
		templateVersion = awsdiscovery.EnforcementTemplateVersion
	}
	if !awsdiscovery.KnownEnforcementTemplateVersion(templateVersion) {
		return nil, enfErr(http.StatusUnprocessableEntity, EnfCodeValidation, "Unknown enforcement template version.",
			map[string]any{"field": "template_version", "known": []string{awsdiscovery.EnforcementTemplateVersion}})
	}
	live, err := s.liveBinding(s.db, ws, connectorID, false)
	if err != nil {
		return nil, err
	}
	if live == nil {
		return nil, enfErr(http.StatusConflict, EnfCodeSessionRequired,
			"Start an enforcement session first: it issues the ExternalId and the stack's name suffix.", nil)
	}
	if live.RoleARN != "" {
		return nil, enfErr(http.StatusConflict, EnfCodeBindingExists,
			"This account already has an enforcement binding; revoke it before binding new roles.",
			map[string]any{"state": live.State, "binding_id": live.ID})
	}
	roleARN, selfTestRoleARN = strings.TrimSpace(roleARN), strings.TrimSpace(selfTestRoleARN)
	partition, account, err := awsdiscovery.ParseRoleARN(roleARN)
	if err != nil {
		return nil, enfErr(http.StatusUnprocessableEntity, EnfCodeValidation, err.Error(), map[string]any{"field": "role_arn"})
	}
	if partition != awsdiscovery.PartitionAWS || account != c.ScopeID {
		return nil, enfErr(http.StatusUnprocessableEntity, EnfCodeValidation,
			"The enforcement role must be in this connector's account ("+c.ScopeID+", commercial partition).",
			map[string]any{"field": "role_arn"})
	}
	if err := expectedSelfTestRole(live, selfTestRoleARN); err != nil {
		return nil, enfErr(http.StatusUnprocessableEntity, EnfCodeValidation, err.Error(), map[string]any{"field": "selftest_role_arn"})
	}
	actor := EnforcementActor{Kind: "user", ID: userID.String()}
	b, err := s.claimUnbound(ws, live.ID, true)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, enfErr(http.StatusConflict, EnfCodeSelfTestInProgress, "This binding is being set up by another request; try again shortly.", nil)
	}
	if other, err := boundElsewhere(s.db, ws, b.AccountID); err != nil {
		s.releaseClaim(b)
		return nil, err
	} else if other {
		s.markUnbound(b, EnfCodeOwnedElsewhere, ownedElsewhereErr().Message, actor)
		return nil, ownedElsewhereErr()
	}
	ext, err := s.readExternalID(b)
	if err != nil {
		s.releaseClaim(b)
		return nil, enfErr(http.StatusServiceUnavailable, EnfCodeUnavailable, err.Error(), nil)
	}
	_, id, aerr := s.assumer.AssumeEnforcement(ctx, awsenforce.AssumeInput{
		RoleARN: roleARN, ExternalID: ext, Region: s.stsRegion(c), SessionName: awsenforce.SelfTestSessionName(b.ID),
	})
	if aerr == nil && (id == nil || id.AccountID != b.AccountID) {
		aerr = fmt.Errorf("the role resolved to another account")
	}
	if aerr != nil {
		code := awsenforce.ErrorCode(aerr)
		if code == "" {
			code = EnfCodeAssumeFailed
		}
		msg := "AuthSec could not assume the enforcement role with this account's ExternalId: " + aerr.Error()
		s.markUnbound(b, code, msg, actor)
		return nil, enfErr(http.StatusUnprocessableEntity, EnfCodeAssumeFailed,
			"AuthSec could not assume the enforcement role. Check the stack used the ExternalId AuthSec issued.",
			map[string]any{"aws_error_code": code})
	}
	bound, err := s.bind(b, bindInput{RoleARN: roleARN, SelfTestRoleARN: selfTestRoleARN, TemplateVersion: templateVersion,
		ConsentedBy: &userID, Actor: actor, Source: "manual"}, s.now())
	if err != nil {
		var ee *EnforcementError
		if errors.As(err, &ee) && ee.Code == EnfCodeOwnedElsewhere {
			s.markUnbound(b, EnfCodeOwnedElsewhere, ee.Message, actor)
			return nil, ee
		}
		s.releaseClaim(b)
		return nil, err
	}
	final, err := s.runAndRecord(ctx, c, bound, actor)
	if err != nil {
		return nil, err
	}
	v := viewOf(c, final)
	return &v, nil
}

func (s *EnforcementBindingService) stsRegion(c *models.CloudConnector) string {
	if r := awsdiscovery.SigningRegion(c.AWSAttrs().Regions); r != "" {
		return r
	}
	return "us-east-1"
}

/* -------------------------------- self-test -------------------------------- */

// Verify runs the self-test now (§7.9 POST .../verify).
func (s *EnforcementBindingService) Verify(ctx context.Context, ws, connectorID uuid.UUID, actor EnforcementActor) (*EnforcementBindingView, error) {
	c, err := s.awsConnector(ws, connectorID)
	if err != nil {
		return nil, err
	}
	live, err := s.liveBinding(s.db, ws, connectorID, false)
	if err != nil {
		return nil, err
	}
	if live == nil || live.RoleARN == "" {
		return nil, enfErr(http.StatusConflict, EnfCodeNotBound, "There is no bound enforcement role to test for this account.", nil)
	}
	b, err := s.VerifyBinding(ctx, ws, live.ID, actor)
	if err != nil {
		return nil, err
	}
	v := viewOf(c, b)
	return &v, nil
}

// VerifyBinding runs the §3.6 self-test on one bound binding and records the
// per-capability result. For the verify_binding job (every 24 h, T3.08) and
// before a deployment batch (EnsureFresh).
func (s *EnforcementBindingService) VerifyBinding(ctx context.Context, ws, bindingID uuid.UUID, actor EnforcementActor) (*models.CloudEnforcementBinding, error) {
	var rows []models.CloudEnforcementBinding
	err := s.db.Raw(`UPDATE cloud_enforcement_binding
		   SET state = 'verifying', updated_at = now()
		 WHERE workspace_id = ? AND id = ? AND role_arn <> ''
		   AND (state IN ('verified','partial','error') OR (state = 'verifying' AND updated_at < ?))
		RETURNING *`, ws, bindingID, s.now().Add(-enfSelfTestStale)).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		var cur []models.CloudEnforcementBinding
		if err := s.db.Where("workspace_id = ? AND id = ?", ws, bindingID).Limit(1).Find(&cur).Error; err != nil {
			return nil, err
		}
		switch {
		case len(cur) == 0 || cur[0].State == models.EnforcementBindingRevoked:
			return nil, enfErr(http.StatusNotFound, EnfCodeNotFound, "Binding not found.", nil)
		case cur[0].RoleARN == "":
			return nil, enfErr(http.StatusConflict, EnfCodeNotBound, "There is no bound enforcement role to test for this account.", nil)
		default:
			return nil, enfErr(http.StatusConflict, EnfCodeSelfTestInProgress, "A self-test is already running for this binding.", nil)
		}
	}
	c, err := s.connectors.Get(ws, rows[0].ConnectorID)
	if err != nil {
		return nil, err
	}
	return s.runAndRecord(ctx, c, &rows[0], actor)
}

// EnsureFresh returns the binding as is when it is verified and its last
// self-test is younger than maxAge (§3.6: "a cached result younger than 1
// hour is reused"), and re-runs the self-test otherwise.
func (s *EnforcementBindingService) EnsureFresh(ctx context.Context, ws, bindingID uuid.UUID, maxAge time.Duration) (*models.CloudEnforcementBinding, error) {
	var rows []models.CloudEnforcementBinding
	if err := s.db.Where("workspace_id = ? AND id = ?", ws, bindingID).Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 || rows[0].State == models.EnforcementBindingRevoked {
		return nil, enfErr(http.StatusNotFound, EnfCodeNotFound, "Binding not found.", nil)
	}
	if b := &rows[0]; b.State == models.EnforcementBindingVerified {
		if at := lastSelfTestAt(b); at != nil && s.now().Sub(*at) < maxAge {
			return b, nil
		}
	}
	return s.VerifyBinding(ctx, ws, bindingID, EnforcementActor{Kind: "system", ID: "deploy_batch"})
}

// runAndRecord runs the self-test on a row this worker holds in `verifying`
// and writes the result, with its event, in one transaction. A row that left
// `verifying` meanwhile (revoked) keeps its state; the result is discarded.
func (s *EnforcementBindingService) runAndRecord(
	ctx context.Context, c *models.CloudConnector, b *models.CloudEnforcementBinding, actor EnforcementActor,
) (*models.CloudEnforcementBinding, error) {
	var rep awsenforce.Report
	ext, err := s.readExternalID(b)
	if err != nil {
		at := s.now().UTC()
		rep = awsenforce.Report{StartedAt: at, FinishedAt: at, Capabilities: map[string]awsenforce.CapabilityResult{
			awsenforce.CapAssume: {Status: awsenforce.StatusError, ErrorCode: "ExternalIdUnreadable", Message: err.Error(), CheckedAt: at},
		}}
		for _, cp := range awsenforce.Capabilities[1:] {
			rep.Capabilities[cp] = awsenforce.CapabilityResult{Status: awsenforce.StatusUntested, Message: "not run: the role could not be assumed", CheckedAt: at}
		}
	} else if err := expectedSelfTestRole(b, b.SelftestRoleARN); err != nil {
		// Never probe a role that is not this binding's self-test role.
		at := s.now().UTC()
		rep = awsenforce.Report{StartedAt: at, FinishedAt: at, Capabilities: map[string]awsenforce.CapabilityResult{
			awsenforce.CapAssume: {Status: awsenforce.StatusOK, CheckedAt: at},
		}}
		for _, cp := range awsenforce.Capabilities[1:] {
			rep.Capabilities[cp] = awsenforce.CapabilityResult{Status: awsenforce.StatusError, ErrorCode: "InvalidSelfTestRole", Message: err.Error(), CheckedAt: at}
		}
	} else {
		rep = awsenforce.RunSelfTest(ctx, s.assumer, awsenforce.SelfTestInput{
			BindingID: b.ID, AccountID: b.AccountID, Partition: awsdiscovery.PartitionAWS,
			RoleARN: b.RoleARN, SelfTestRoleARN: b.SelftestRoleARN, ExternalID: ext, Region: s.stsRegion(c),
			Now: s.now,
		})
	}
	return s.recordReport(b, rep, actor)
}

func (s *EnforcementBindingService) recordReport(b *models.CloudEnforcementBinding, rep awsenforce.Report, actor EnforcementActor) (*models.CloudEnforcementBinding, error) {
	state := rep.State()
	caps, err := json.Marshal(rep.Capabilities)
	if err != nil {
		return nil, err
	}
	lastErr, lastCode := "", ""
	failing := rep.Failing()
	switch state {
	case awsenforce.StatePartial:
		lastErr = "Direct changes are refused until every check passes. Failing: " + strings.Join(failing, "; ")
		lastCode = EnfCodePartial
	case awsenforce.StateError:
		a := rep.Capabilities[awsenforce.CapAssume]
		lastErr = "AuthSec could not assume the enforcement role: " + a.Message
		lastCode = a.ErrorCode
		if lastCode == "" {
			lastCode = EnfCodeAssumeFailed
		}
	}
	var out models.CloudEnforcementBinding
	err = s.db.Transaction(func(tx *gorm.DB) error {
		var rows []models.CloudEnforcementBinding
		if err := tx.Raw(`UPDATE cloud_enforcement_binding
			   SET state = ?, capabilities = ?::jsonb, last_error = ?, last_error_code = ?,
			       verified_at = CASE WHEN ? THEN now() ELSE verified_at END, updated_at = now()
			 WHERE workspace_id = ? AND id = ? AND state = 'verifying' AND role_arn <> '' RETURNING *`,
			state, string(caps), lastErr, lastCode, state == awsenforce.StateVerified, b.WorkspaceID, b.ID).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			// Revoked (or reclaimed) while the probes ran: keep what is there.
			return tx.Where("workspace_id = ? AND id = ?", b.WorkspaceID, b.ID).First(&out).Error
		}
		out = rows[0]
		return s.appendEvent(tx, b.WorkspaceID, EventEnforcementSelfTest, actor, bindingPayload(&out, map[string]any{
			"failing": failing, "leaked_policy_arn": rep.LeakedPolicyARN,
			"started_at": rep.StartedAt, "finished_at": rep.FinishedAt,
		}))
	})
	if err != nil {
		return nil, err
	}
	log.Printf("[aws-enf] stage=self_test binding=%s state=%s failing=%q leaked=%s", b.ID, out.State, failing, rep.LeakedPolicyARN)
	return &out, nil
}

/* --------------------------------- revoke ---------------------------------- */

// EnforcementArtifact is an AuthSec artifact still in AWS for the account
// (from the iga_gov_artifact ledger).
type EnforcementArtifact struct {
	ID        uuid.UUID `json:"id"`
	ControlID uuid.UUID `json:"control_id"`
	Kind      string    `json:"kind"`
	NativeARN string    `json:"native_arn"`
	State     string    `json:"state"`
}

// EnforcementRevokeResult is what DELETE .../enforcement returns.
type EnforcementRevokeResult struct {
	Binding        EnforcementBindingView `json:"binding"`
	ArtifactsInAWS []EnforcementArtifact  `json:"artifacts_in_aws"`
}

// Revoke ends the binding (§7.9): the row becomes `revoked` (new J3
// deployments are refused), the ExternalId is deleted from Vault after the
// row commits, and the AuthSec boundaries still in AWS are listed so the
// customer knows what remains. Nothing in AWS is changed: the stack is the
// customer's to delete.
func (s *EnforcementBindingService) Revoke(ctx context.Context, ws, connectorID, userID uuid.UUID, reason string) (*EnforcementRevokeResult, error) {
	c, err := s.awsConnector(ws, connectorID)
	if err != nil {
		return nil, err
	}
	var revoked models.CloudEnforcementBinding
	var artifacts []EnforcementArtifact
	err = s.db.Transaction(func(tx *gorm.DB) error {
		live, err := s.liveBinding(tx, ws, connectorID, true)
		if err != nil {
			return err
		}
		if live == nil {
			return enfErr(http.StatusNotFound, EnfCodeNotFound, "This account has no enforcement binding.", nil)
		}
		if err := tx.Raw(`UPDATE cloud_enforcement_binding SET state = 'revoked', updated_at = now()
			 WHERE workspace_id = ? AND id = ? RETURNING *`, ws, live.ID).Scan(&revoked).Error; err != nil {
			return err
		}
		if err := tx.Raw(`SELECT id, control_id, kind, native_arn, state FROM iga_gov_artifact
			 WHERE workspace_id = ? AND owned_by = 'authsec_direct' AND state IN ('intended','present','drifted')
			   AND split_part(native_arn, ':', 5) = ?
			 ORDER BY native_arn`, ws, live.AccountID).Scan(&artifacts).Error; err != nil {
			return err
		}
		arns := make([]string, 0, len(artifacts))
		for _, a := range artifacts {
			arns = append(arns, a.NativeARN)
		}
		return s.appendEvent(tx, ws, EventEnforcementRevoked, EnforcementActor{Kind: "user", ID: userID.String()},
			bindingPayload(&revoked, map[string]any{"previous_state": live.State, "reason": reason, "artifacts_in_aws": arns}))
	})
	if err != nil {
		return nil, err
	}
	if s.vault != nil && revoked.AuthRef != "" {
		if err := s.vault.DeleteSecret(revoked.AuthRef); err != nil {
			log.Printf("[aws-enf] binding %s revoked; deleting its external id failed: %v", revoked.ID, err)
		}
	}
	if artifacts == nil {
		artifacts = []EnforcementArtifact{}
	}
	return &EnforcementRevokeResult{Binding: viewOf(c, &revoked), ArtifactsInAWS: artifacts}, nil
}

/* -------------------------------- callback --------------------------------- */

// HandleEnforcementCallback processes one enforcement registration message
// (Custom::AuthSecEnforcementRegistration). The SQS worker hands it over from
// AWSQuickCreateService.HandleCallbackDelivery after the SNS envelope parsed
// and arrived through one of AuthSec's own topics.
//
// The trust model is the discovery callback's: the topic accepts publishes
// from any AWS account, so nothing in the message is proof. Every shape check
// runs before any AWS call; the ExternalId must be one this workspace was
// issued for enforcement and the one Vault holds for the account; the role is
// assumed with it and the account read back before anything is bound; the
// account must not be bound by another workspace.
func (s *EnforcementBindingService) HandleEnforcementCallback(ctx context.Context, env *awsdiscovery.SNSEnvelope, lastChance bool) CallbackOutcome {
	lg := enfLog{stage: "envelope"}
	req, err := awsdiscovery.ParseEnforcementCFNRequest(env.Message)
	if err != nil {
		lg.emit(CallbackReject.String(), "", err.Error())
		return CallbackReject
	}
	lg.stack, lg.request = req.StackID, req.RequestID
	stack, err := awsdiscovery.ParseStackID(req.StackID)
	if err != nil {
		lg.emit(CallbackReject.String(), "", err.Error())
		return CallbackReject
	}
	lg.account, lg.region = stack.AccountID, stack.Region
	if !awsdiscovery.IsKnownRegion(stack.Region) {
		lg.emit(CallbackReject.String(), "", "stack region is not a known AWS region")
		return CallbackReject
	}
	lg.stage = "response_url"
	target, err := awsdiscovery.ValidateResponseURL(req.ResponseURL, stack.Region)
	if err != nil {
		lg.emit(CallbackReject.String(), "", err.Error())
		return CallbackReject
	}
	switch req.RequestType {
	case awsdiscovery.CFNRequestDelete, awsdiscovery.CFNRequestUpdate:
		// Never destructive, never blocking (as discovery): a Delete must
		// succeed or the customer cannot delete the stack, and a forged one
		// must change nothing. Deleting the stack removes the role, which the
		// next self-test reports (assume: error); revoking is the customer's
		// explicit action in AuthSec.
		lg.stage = strings.ToLower(req.RequestType)
		physical := req.PhysicalResourceID
		if physical == "" {
			physical = "authsec-enforcement-unregistered-" + shortHash(req.StackID)
		}
		out, _ := deliverCFN(ctx, s.http, s.sleep, target, awsdiscovery.NewCFNResponse(&req.CFNRequest, awsdiscovery.CFNStatusSuccess, "", physical))
		lg.emit(out.String(), "", "answered SUCCESS without changes")
		return out
	}
	return s.handleCreate(ctx, env, req, stack, target, lastChance, lg)
}

// enfReasons is what a customer reads in their stack events on FAILED.
var enfReasons = map[string]string{
	AWSOnbCodeUnknownLink:        "This AuthSec enforcement link has expired, or the values AuthSec filled in were changed. Start again in AuthSec.",
	AWSOnbCodeRegionMismatch:     "The stack was created in a different AWS Region than AuthSec's link. Start again in AuthSec.",
	AWSOnbCodeAccountMismatch:    "The roles and the stack are in different AWS accounts, or not in the account AuthSec expected.",
	AWSOnbCodeInvalidRequest:     "The stack sent AuthSec invalid roles. Start again in AuthSec.",
	AWSOnbCodeLinkUsed:           "This AuthSec enforcement link was already used. Start again in AuthSec.",
	AWSOnbCodeAssumeDenied:       "AuthSec could not assume the enforcement role. Check the trust policy and ExternalId were not changed.",
	AWSOnbCodeAuthSecUnavailable: "AuthSec could not complete setup. Try again later.",
	EnfCodeOwnedElsewhere:        "This AWS account is already bound for enforcement by another AuthSec workspace.",
	EnfCodePolicyNotEnabled:      "AuthSec policy enforcement is not enabled on this AuthSec server. Delete this stack and start again in AuthSec once it is.",
}

// EnfCodePolicyNotEnabled answers a registration that arrives while the
// IGA_POLICY switch is off (review fix R1a P2 "gate leaks").
const EnfCodePolicyNotEnabled = "policy_not_enabled"

func (s *EnforcementBindingService) handleCreate(
	ctx context.Context, env *awsdiscovery.SNSEnvelope, req *awsdiscovery.EnforcementCFNRequest,
	stack awsdiscovery.StackRef, target *url.URL, lastChance bool, lg enfLog,
) CallbackOutcome {
	props := req.Properties
	lg.stage = "binding"
	lg.ext = shortHash(props.ExternalID)
	deadline := env.Timestamp.Add(awsCallbackDeadline)
	physical := "authsec-enforcement-unregistered-" + shortHash(req.StackID)
	answer := func(status, code, msg string) CallbackOutcome {
		reason := ""
		if status == awsdiscovery.CFNStatusFailed {
			reason = enfReasons[code]
			if lg.binding != "" {
				reason += " AuthSec ref: " + lg.binding[:8]
			}
		}
		out, _ := deliverCFN(ctx, s.http, s.sleep, target, awsdiscovery.NewCFNResponse(&req.CFNRequest, status, reason, physical))
		lg.emit(out.String(), code, msg)
		return out
	}
	fail := func(code, msg string) CallbackOutcome { return answer(awsdiscovery.CFNStatusFailed, code, msg) }
	transient := func(msg string) CallbackOutcome {
		if !s.now().Before(deadline) || lastChance {
			return fail(AWSOnbCodeAuthSecUnavailable, "final delivery or past deadline: "+msg)
		}
		lg.emit(CallbackRetry.String(), "", msg)
		return CallbackRetry
	}

	// 1. Shape: ExternalId, one region end to end, one account, commercial.
	if awsdiscovery.ValidateExternalID(props.ExternalID) != nil {
		return fail(AWSOnbCodeUnknownLink, "ExternalId missing or malformed")
	}
	if _, topicRegion, err := awsdiscovery.ParseTopicARN(env.TopicArn); err != nil || topicRegion != stack.Region {
		return fail(AWSOnbCodeRegionMismatch, fmt.Sprintf("topic region %s, stack region %s", topicRegion, stack.Region))
	}
	rp, ra, err1 := awsdiscovery.ParseRoleARN(props.RoleArn)
	sp, sa, err2 := awsdiscovery.ParseRoleARN(props.SelfTestRoleArn)
	if err1 != nil || err2 != nil {
		return fail(AWSOnbCodeInvalidRequest, fmt.Sprintf("RoleArn: %v; SelfTestRoleArn: %v", err1, err2))
	}
	if stack.Partition != awsdiscovery.PartitionAWS || rp != awsdiscovery.PartitionAWS || sp != awsdiscovery.PartitionAWS ||
		ra != stack.AccountID || sa != stack.AccountID || (props.AccountID != "" && props.AccountID != stack.AccountID) {
		return fail(AWSOnbCodeAccountMismatch, fmt.Sprintf("stack %s, role %s, self-test role %s, AccountId %s",
			stack.AccountID, ra, sa, props.AccountID))
	}
	if !awsdiscovery.KnownEnforcementTemplateVersion(props.TemplateVersion) {
		return fail(AWSOnbCodeInvalidRequest, "unknown TemplateVersion "+props.TemplateVersion)
	}

	// 1b. The IGA_POLICY gate (§4.3; review fix R1a P2 "gate leaks"). The
	// binding, its Vault path and its events are Phase 3 state: nothing is
	// read or written unless the gate is on. DECISION: switch OFF is an
	// operator's deliberate state, so the Create is REFUSED explicitly
	// (FAILED with policy_not_enabled; the customer deletes the stack and
	// starts again once enabled). Switch ON but not yet available (schema
	// verifying, graph gate not verified) is transient: the message is left
	// for redelivery (CallbackRetry) until the gate verifies, and only the
	// final delivery or the CloudFormation deadline answers FAILED
	// AuthSecUnavailable. Delete and Update never reach here: they are
	// answered SUCCESS without changes whatever the gate says, so a stack
	// can always be deleted.
	if state, reason, _ := s.gate().Status(); state != PolicyOn {
		if state == PolicyOff {
			return fail(EnfCodePolicyNotEnabled, "IGA_POLICY is off: "+reason)
		}
		return transient("policy gate not available: " + reason)
	}

	// 2. The binding, by the account and the ExternalId.
	b, err := s.findByExternalID(stack.AccountID, props.ExternalID)
	if err != nil {
		return transient("binding lookup: " + err.Error())
	}
	if b == nil {
		return fail(AWSOnbCodeUnknownLink, "no binding for this account and ExternalId")
	}
	lg.binding = b.ID.String()
	physical = "authsec-enforcement-" + b.ID.String()
	if b.RoleARN != "" {
		if b.RoleARN == props.RoleArn && b.SelftestRoleARN == props.SelfTestRoleArn {
			return answer(awsdiscovery.CFNStatusSuccess, "", "binding already bound to these roles")
		}
		return fail(AWSOnbCodeLinkUsed, "binding already bound to other roles")
	}
	if b.State == models.EnforcementBindingError {
		return fail(AWSOnbCodeLinkUsed, "this session already failed; a new one must be started")
	}
	if b.State == models.EnforcementBindingPending && s.now().After(b.UpdatedAt.Add(enfSessionTTL)) {
		return fail(AWSOnbCodeUnknownLink, "session expired")
	}
	if err := expectedSelfTestRole(b, props.SelfTestRoleArn); err != nil {
		return fail(AWSOnbCodeInvalidRequest, err.Error())
	}
	claimed, err := s.claimUnbound(b.WorkspaceID, b.ID, false)
	if err != nil {
		return transient("claim: " + err.Error())
	}
	if claimed == nil {
		// Another worker holds it and will answer this same request; never
		// answer here, or a FAILED could overtake its SUCCESS.
		lg.emit(CallbackRetry.String(), "", "binding is being processed by another worker")
		return CallbackRetry
	}
	b = claimed
	actor := EnforcementActor{Kind: "aws", ID: req.StackID}

	// 3. Not bound by another workspace (checked again inside bind).
	if other, err := boundElsewhere(s.db, b.WorkspaceID, b.AccountID); err != nil {
		s.releaseClaim(b)
		return transient("cross-workspace check: " + err.Error())
	} else if other {
		s.markUnbound(b, EnfCodeOwnedElsewhere, enfReasons[EnfCodeOwnedElsewhere], actor)
		return fail(EnfCodeOwnedElsewhere, "account bound by another workspace")
	}

	// 4. Prove the role: AssumeRole with the ExternalId, account read back.
	lg.stage = "assume"
	assumedAt, code, msg := s.assumeWithRetry(ctx, b, props.RoleArn, props.ExternalID, stack.Region, deadline)
	if code != "" {
		s.markUnbound(b, code, msg, actor)
		return fail(code, msg)
	}

	// 5. Bind, atomically with the cross-workspace check and the event.
	lg.stage = "bind"
	bound, err := s.bind(b, bindInput{RoleARN: props.RoleArn, SelfTestRoleARN: props.SelfTestRoleArn,
		TemplateVersion: props.TemplateVersion, Actor: actor, Source: "quick_create", StackID: req.StackID}, assumedAt)
	if err != nil {
		var ee *EnforcementError
		if errors.As(err, &ee) && ee.Code == EnfCodeOwnedElsewhere {
			s.markUnbound(b, EnfCodeOwnedElsewhere, ee.Message, actor)
			return fail(EnfCodeOwnedElsewhere, "account bound by another workspace (at bind)")
		}
		s.releaseClaim(b)
		return transient("bind: " + err.Error())
	}
	s.auditBound(bound, stack, req.StackID)

	// 6. Answer, then self-test: the stack is never held for the probes.
	lg.stage = "respond"
	out := answer(awsdiscovery.CFNStatusSuccess, "", "bound")
	if c, err := s.connectors.Get(bound.WorkspaceID, bound.ConnectorID); err == nil {
		if _, err := s.runAndRecord(ctx, c, bound, EnforcementActor{Kind: "system", ID: "binding_created"}); err != nil {
			log.Printf("[aws-enf] binding %s: recording the first self-test failed: %v", bound.ID, err)
		}
	}
	return out
}

// findByExternalID finds the live binding an enforcement callback belongs to:
// the account from the StackId, then the ExternalId -- first its workspace
// signature (cheap, no Vault call), then an exact constant-time comparison
// with what Vault holds for that binding.
func (s *EnforcementBindingService) findByExternalID(accountID, externalID string) (*models.CloudEnforcementBinding, error) {
	var rows []models.CloudEnforcementBinding
	if err := s.db.Where("account_id = ? AND state <> ?", accountID, models.EnforcementBindingRevoked).
		Order("created_at").Find(&rows).Error; err != nil {
		return nil, err
	}
	for i := range rows {
		b := &rows[i]
		if VerifyEnforcementExternalID(b.WorkspaceID, externalID) != nil {
			continue
		}
		stored, err := s.readExternalID(b)
		if err != nil {
			return nil, err
		}
		if hmac.Equal([]byte(stored), []byte(externalID)) {
			return b, nil
		}
	}
	return nil, nil
}

// assumeWithRetry proves the enforcement role, retrying AccessDenied for IAM
// propagation (a role created seconds ago) and AuthSec-side failures within
// their budgets, never past the moment the answer must go out.
func (s *EnforcementBindingService) assumeWithRetry(
	ctx context.Context, b *models.CloudEnforcementBinding, roleARN, externalID, region string, deadline time.Time,
) (time.Time, string, string) {
	answerBy := deadline.Add(-awsAnswerReserve)
	start := s.now()
	for attempt := 1; ; attempt++ {
		actx, cancel := context.WithDeadline(ctx, answerBy)
		_, id, err := s.assumer.AssumeEnforcement(actx, awsenforce.AssumeInput{
			RoleARN: roleARN, ExternalID: externalID, Region: region, SessionName: awsenforce.SelfTestSessionName(b.ID),
		})
		cancel()
		now := s.now()
		if err == nil {
			if id == nil || id.AccountID != b.AccountID {
				return now, AWSOnbCodeAccountMismatch, "the role resolved to another account"
			}
			return now, "", ""
		}
		budget := awsAuthSecErrorBudget
		code := AWSOnbCodeAuthSecUnavailable
		if awsenforce.IsAccessDenied(err) {
			budget, code = awsIAMPropagationBudget, AWSOnbCodeAssumeDenied
		}
		if now.Sub(start) >= budget || !now.Before(answerBy) {
			return now, code, err.Error()
		}
		wait := retryBackoff(3*time.Second, attempt)
		if left := answerBy.Sub(now); wait > left {
			wait = left
		}
		if err := s.sleep(ctx, wait); err != nil {
			return now, AWSOnbCodeAuthSecUnavailable, err.Error()
		}
	}
}

// auditBound records a callback bind in audit_events, as auditConnected does
// for discovery: there is no HTTP request behind a callback.
func (s *EnforcementBindingService) auditBound(b *models.CloudEnforcementBinding, stack awsdiscovery.StackRef, stackID string) {
	if config.AuditLogger == nil {
		return
	}
	config.AuditLogger.LogAdminAction(b.ID.String(), b.WorkspaceID.String(), b.ConsentedBy.String(),
		"bind_enforcement", "cloud_enforcement_binding", b.ID.String(), "CALLBACK",
		"aws-enforcement-quick-create/"+stack.Region+"/"+stackID, "", "aws-cloudformation", 200, 0, nil,
		map[string]any{"source": "quick_create", "account_id": b.AccountID, "role_arn": b.RoleARN,
			"selftest_role_arn": b.SelftestRoleARN, "template_version": b.TemplateVersion}, "")
}

type enfLog struct {
	stage, binding, stack, request, account, region, ext string
}

func (l enfLog) emit(outcome, code, msg string) {
	alert := ""
	if outcome == CallbackReject.String() || code == AWSOnbCodeAuthSecUnavailable {
		alert = "ALERT "
	}
	log.Printf("[aws-enf] %sstage=%s outcome=%s code=%s binding=%s stack=%s request=%s account=%s region=%s ext=%s msg=%q",
		alert, l.stage, outcome, code, l.binding, l.stack, l.request, l.account, l.region, l.ext, msg)
}
