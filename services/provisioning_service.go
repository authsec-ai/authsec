package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ProvisioningManager turns a claimed agent sighting into a governed principal, and
// takes that authority away again.
//
// THE INVARIANT (PG-2): provisioning is one transaction or it did not happen.
// Identity, the entitlement anchor, the resource-server registration, the role
// binding, the provenance that explains it, and the agent's governance status all
// commit together. A half-provisioned agent is worse than an unprovisioned one,
// because it looks governed.
//
// ONE REVOCATION PATH (PG-6): Deprovision is the only implementation. Certification,
// expiry, leaver, quarantine, and admin revoke all call it, so "revoked" means the
// same thing and produces the same audit shape however it was triggered.
type ProvisioningManager interface {
	// Provision brings a claimed discovered agent under management.
	Provision(workspaceID uuid.UUID, in ProvisionInput) (*ProvisionResult, error)

	// Deprovision removes an agent's authority: bindings, live tokens, registrations,
	// and the paired anchor. Idempotent — safe to call on an already-deprovisioned
	// agent, because every caller may retry.
	Deprovision(workspaceID uuid.UUID, in DeprovisionInput) (*DeprovisionResult, error)

	// GrantEntitlement is the console approval path: approve a registration and
	// optionally bind a role, WITH an expiry and WITH provenance, in one transaction.
	// Both console callers route through here so neither can forget either.
	GrantEntitlement(workspaceID uuid.UUID, in GrantEntitlementInput) (*GrantResult, error)
}

// ProvisionInput is a provisioning decision.
type ProvisionInput struct {
	// DiscoveredAgentID is the claimed sighting being provisioned. Required: this is
	// the only entry point from discovery, and it carries the identity and the
	// accountable owner a claim established.
	DiscoveredAgentID uuid.UUID
	// ResourceServerID is the Application the agent is being given access to.
	ResourceServerID uuid.UUID
	// RoleID is the role to bind. Validated to belong to the RS's workspace.
	RoleID uuid.UUID

	Justification string
	Purpose       string
	// ExpiresAt bounds the grant. Exactly one of ExpiresAt / IsStanding, and a
	// standing grant needs a justification (PG-4).
	ExpiresAt  *time.Time
	IsStanding bool

	// ActingUser is the human making the decision, recorded in provenance.
	ActingUser      *uuid.UUID
	ActingUserLabel string
}

// ProvisionResult reports what was created, so the caller and the console agree.
type ProvisionResult struct {
	DiscoveredAgentID uuid.UUID   `json:"discovered_agent_id"`
	OAuthClientID     uuid.UUID   `json:"oauth_client_id"`
	ClientIDString    string      `json:"client_id"`
	ServiceAccountID  uuid.UUID   `json:"service_account_id"`
	ServiceAccountNew bool        `json:"service_account_created"`
	SpiffeID          string      `json:"spiffe_id,omitempty"`
	RegistrationID    uuid.UUID   `json:"registration_id"`
	RoleBindingID     uuid.UUID   `json:"role_binding_id"`
	ProvenanceIDs     []uuid.UUID `json:"provenance_ids"`
	ExpiresAt         *time.Time  `json:"expires_at,omitempty"`
	IsStanding        bool        `json:"is_standing"`
}

// DeprovisionInput identifies the agent and records why.
type DeprovisionInput struct {
	// One of these. DiscoveredAgentID is the convenient handle from the inventory;
	// OAuthClientID is what the leaver and quarantine paths already hold.
	DiscoveredAgentID *uuid.UUID
	OAuthClientID     *uuid.UUID

	// Via must be one of models.ValidRevokedVia — it records which of the five
	// mechanisms invoked this single path.
	Via    string
	Reason string
	By     *uuid.UUID
}

// DeprovisionResult reports what was actually removed. Returned even when nothing was
// found, so a caller can tell "already clean" from "did work".
type DeprovisionResult struct {
	OAuthClientID           uuid.UUID `json:"oauth_client_id"`
	BindingsRemoved         int       `json:"bindings_removed"`
	TokensRevoked           int       `json:"tokens_revoked"`
	RegistrationsRevoked    int       `json:"registrations_revoked"`
	ProvenanceClosed        int       `json:"provenance_closed"`
	ServiceAccountsDisabled int       `json:"service_accounts_disabled"`
	AlreadyDeprovisioned    bool      `json:"already_deprovisioned"`
	// ResidualBindings is the zero-residual check: bindings still resolvable after
	// the sweep. Non-zero means the de-provision did not fully take, and it is
	// reported rather than swallowed.
	ResidualBindings int `json:"residual_bindings"`
}

type provisioningManager struct {
	db         *gorm.DB
	repo       repositories.GovernanceRepository
	provenance ProvenanceManager
	sod        SoDManager
	oauth      *OAuthASService
}

// NewProvisioningManager constructs a ProvisioningManager.
func NewProvisioningManager(db *gorm.DB, oauth *OAuthASService) ProvisioningManager {
	repo := repositories.NewGovernanceRepository(db)
	return &provisioningManager{
		db:         db,
		repo:       repo,
		provenance: NewProvenanceManager(repo),
		sod:        NewSoDManager(db),
		oauth:      oauth,
	}
}

/* ------------------------------- provision ------------------------------ */

func (m *provisioningManager) Provision(workspaceID uuid.UUID, in ProvisionInput) (*ProvisionResult, error) {
	if in.DiscoveredAgentID == uuid.Nil {
		return nil, errors.New("discovered_agent_id is required: provisioning starts from a claimed sighting")
	}
	if in.ResourceServerID == uuid.Nil || in.RoleID == uuid.Nil {
		return nil, errors.New("resource_server_id and role_id are required")
	}
	// Validate the grant shape up front, before any writes, so a bad request never
	// leaves a partially-built agent behind even in the presence of a later bug.
	if in.IsStanding && strings.TrimSpace(in.Justification) == "" {
		return nil, errors.New("a standing (non-expiring) grant requires a justification: " +
			"permanent access is the audited exception, not the default")
	}
	if in.IsStanding && in.ExpiresAt != nil {
		return nil, errors.New("a standing grant cannot also have an expiry")
	}
	if !in.IsStanding && in.ExpiresAt == nil {
		return nil, errors.New("provide expires_at, or set is_standing with a justification")
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(time.Now()) {
		return nil, fmt.Errorf("expires_at %s is not in the future", in.ExpiresAt.Format(time.RFC3339))
	}

	result := &ProvisionResult{
		DiscoveredAgentID: in.DiscoveredAgentID,
		ExpiresAt:         in.ExpiresAt,
		IsStanding:        in.IsStanding,
	}

	err := m.db.Transaction(func(tx *gorm.DB) error {
		// --- 1. the claimed sighting ---------------------------------------
		var agent models.DiscoveredAgent
		if err := tx.First(&agent, "id = ? AND workspace_id = ?",
			in.DiscoveredAgentID, workspaceID).Error; err != nil {
			return fmt.Errorf("discovered agent not found in this workspace: %w", err)
		}
		// A claim is the human decision that this agent should exist and names who is
		// accountable. Provisioning without one would grant authority nobody asked for.
		if agent.Status != models.DiscoveredAgentRegistered {
			return fmt.Errorf("agent must be claimed before it can be provisioned "+
				"(status is %q, need %q)", agent.Status, models.DiscoveredAgentRegistered)
		}
		// Defence in depth: discovered_agents_registered_chk already makes "claimed but
		// unowned or identity-less" unrepresentable, so these are unreachable today.
		// Kept because they are cheap and because the schema constraint is the kind of
		// thing a future migration relaxes without noticing what depended on it.
		if agent.MatchedClientID == nil {
			return errors.New("claimed agent has no matched_client_id: nothing to provision an identity for")
		}
		if agent.OwnerUserID == nil {
			return errors.New("claimed agent has no owner_user_id: an agent must have an accountable human")
		}

		// --- 2. the identity ------------------------------------------------
		var client models.MCPOAuthClient
		if err := tx.First(&client, "id = ?", *agent.MatchedClientID).Error; err != nil {
			return fmt.Errorf("matched oauth client not found: %w", err)
		}
		result.OAuthClientID = client.ID
		result.ClientIDString = client.ClientID

		// --- 3. the entitlement anchor (PG-1) -------------------------------
		// role_bindings.check_principal allows exactly one of user / group /
		// service_account — an oauth client is NOT a bindable principal. So every
		// provisioned agent gets a paired service account, using the oauth_client_id
		// column that already exists, and entitlements attach to that.
		sa, created, err := m.ensureAnchor(tx, workspaceID, &agent, &client)
		if err != nil {
			return err
		}
		result.ServiceAccountID = sa.ID
		result.ServiceAccountNew = created
		if sa.SpiffeID != nil {
			result.SpiffeID = *sa.SpiffeID
		}

		// --- 3b. SoD preventive check (PG-7) --------------------------------
		// Inside the transaction and BEFORE the binding exists, so a grant that would
		// create a violation is REFUSED rather than created and reported afterwards.
		// The seeded self-modification rule is what stops an agent being handed
		// governance or role-management authority in the first place.
		if err := m.checkSoD(tx, workspaceID, models.ProvenanceSubjectServiceAccount,
			sa.ID, sa.Name, in.RoleID); err != nil {
			return err
		}

		// --- 4. the registration -------------------------------------------
		// ApproveClientRegistrationInTx requires a registration row to exist. A
		// freshly discovered agent has never registered itself, so create one as
		// pending_approval first — provisioning IS the approval.
		regID, err := m.ensureRegistration(tx, workspaceID, in.ResourceServerID, client.ID)
		if err != nil {
			return err
		}
		result.RegistrationID = regID

		// --- 5. approve + bind, with an expiry -----------------------------
		if err := m.oauth.ApproveClientRegistrationInTx(tx, in.ResourceServerID.String(), client.ClientID,
			&ApprovalRoleBinding{
				RoleID:      in.RoleID,
				SubjectType: "service_account",
				SubjectID:   sa.ID,
				ExpiresAt:   in.ExpiresAt,
			}); err != nil {
			return fmt.Errorf("approve registration and bind role: %w", err)
		}

		// Read back the binding the approval created, so provenance points at a real
		// row rather than one we assume exists.
		var binding models.RoleBinding
		if err := tx.Where(`workspace_id = ? AND role_id = ? AND service_account_id = ?
		                     AND scope_type = 'resource_server' AND scope_id = ?`,
			workspaceID, in.RoleID, sa.ID, in.ResourceServerID).First(&binding).Error; err != nil {
			return fmt.Errorf("could not locate the role binding just created: %w", err)
		}
		result.RoleBindingID = binding.ID

		// --- 6. provenance -------------------------------------------------
		rsName, _ := m.resourceServerName(tx, in.ResourceServerID)
		anchor := ""
		if sa.SpiffeID != nil {
			anchor = *sa.SpiffeID
		}

		// The role binding: the entitlement that actually carries authority, and the
		// one that expires.
		bindingProv, err := m.provenance.OpenGrant(tx, workspaceID, OpenGrantInput{
			EntitlementType: models.EntitlementRoleBinding,
			RoleBindingID:   &binding.ID,
			Snapshot: map[string]interface{}{
				"role_id":            in.RoleID.String(),
				"role_name":          binding.RoleName,
				"scope_type":         "resource_server",
				"resource_server_id": in.ResourceServerID.String(),
				"resource_server":    rsName,
				"identity_anchor":    anchor,
				"oauth_client_id":    client.ClientID,
			},
			Label:             fmt.Sprintf("%s on %s", binding.RoleName, rsName),
			SubjectType:       models.ProvenanceSubjectServiceAccount,
			SubjectID:         sa.ID,
			SubjectLabel:      sa.Name,
			Origin:            models.GrantOriginDiscoveryClaim,
			Justification:     in.Justification,
			Purpose:           in.Purpose,
			DiscoveredAgentID: &agent.ID,
			GrantedBy:         in.ActingUser,
			GrantedByLabel:    in.ActingUserLabel,
			ExpiresAt:         in.ExpiresAt,
			IsStanding:        in.IsStanding,
		})
		if err != nil {
			return fmt.Errorf("record role-binding provenance: %w", err)
		}
		result.ProvenanceIDs = append(result.ProvenanceIDs, bindingProv.ID)

		// The registration: the connection itself. Standing on purpose — the agent
		// stays connected to the Application until it is deprovisioned, while its
		// AUTHORITY is what comes and goes on the JIT schedule above.
		regJustification := in.Justification
		if strings.TrimSpace(regJustification) == "" {
			regJustification = fmt.Sprintf("agent connected to %s at provisioning", rsName)
		}
		regProv, err := m.provenance.OpenGrant(tx, workspaceID, OpenGrantInput{
			EntitlementType:      models.EntitlementClientRegistration,
			ClientRegistrationID: &regID,
			Snapshot: map[string]interface{}{
				"resource_server_id": in.ResourceServerID.String(),
				"resource_server":    rsName,
				"oauth_client_id":    client.ClientID,
			},
			Label:             fmt.Sprintf("registration on %s", rsName),
			SubjectType:       models.ProvenanceSubjectOAuthClient,
			SubjectID:         client.ID,
			SubjectLabel:      client.ClientID,
			Origin:            models.GrantOriginDiscoveryClaim,
			Justification:     regJustification,
			Purpose:           in.Purpose,
			DiscoveredAgentID: &agent.ID,
			GrantedBy:         in.ActingUser,
			GrantedByLabel:    in.ActingUserLabel,
			IsStanding:        true,
		})
		if err != nil {
			return fmt.Errorf("record registration provenance: %w", err)
		}
		result.ProvenanceIDs = append(result.ProvenanceIDs, regProv.ID)

		// --- 7. governance status ------------------------------------------
		if err := tx.Model(&models.MCPOAuthClient{}).Where("id = ?", client.ID).
			Updates(map[string]interface{}{
				"governance_status": models.GovernanceStatusActive,
				"owner_user_id":     *agent.OwnerUserID,
			}).Error; err != nil {
			return fmt.Errorf("set governance status: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ensureAnchor gets or creates the service account an agent's entitlements attach to.
//
// Keyed on oauth_client_id so it is idempotent: provisioning the same agent into a
// second Application reuses one anchor rather than fragmenting its entitlements across
// several principals, which would make "what does this agent have?" unanswerable.
func (m *provisioningManager) ensureAnchor(tx *gorm.DB, workspaceID uuid.UUID,
	agent *models.DiscoveredAgent, client *models.MCPOAuthClient) (*models.ServiceAccount, bool, error) {

	var existing models.ServiceAccount
	err := tx.Where("workspace_id = ? AND oauth_client_id = ?", workspaceID, client.ID).First(&existing).Error
	if err == nil {
		// Backfill the workload identity if discovery has since learned it and the
		// anchor predates that. Never overwrite a non-empty value — an operator may
		// have corrected it.
		if existing.SpiffeID == nil || *existing.SpiffeID == "" {
			if anchor := identityAnchorFrom(agent.Metadata); anchor != "" {
				if uerr := tx.Model(&models.ServiceAccount{}).
					Where("id = ? AND workspace_id = ?", existing.ID, workspaceID).
					Update("spiffe_id", anchor).Error; uerr != nil {
					return nil, false, fmt.Errorf("backfill spiffe_id: %w", uerr)
				}
				existing.SpiffeID = &anchor
			}
		}
		return &existing, false, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, fmt.Errorf("look up entitlement anchor: %w", err)
	}

	sa := models.ServiceAccount{
		ID:          uuid.New(),
		WorkspaceID: workspaceID,
		// Named after the agent so an operator reading role_bindings can tell what it
		// is without joining three tables.
		Name:          anchorName(agent, client),
		Description:   fmt.Sprintf("Entitlement anchor for discovered agent %s", agent.DisplayName),
		Status:        "active",
		OAuthClientID: &client.ID,
	}
	// The workload identity discovery already reported. This is the bridge between
	// "the pod authenticates as system:serviceaccount:ns:sa" and "this principal holds
	// these entitlements".
	if anchor := identityAnchorFrom(agent.Metadata); anchor != "" {
		sa.SpiffeID = &anchor
	}
	if err := tx.Create(&sa).Error; err != nil {
		return nil, false, fmt.Errorf("create entitlement anchor: %w", err)
	}
	return &sa, true, nil
}

// ensureRegistration returns the registration id, creating a pending one if the agent
// has never registered itself with this Application.
func (m *provisioningManager) ensureRegistration(tx *gorm.DB, workspaceID, rsID, clientID uuid.UUID) (uuid.UUID, error) {
	var reg models.ResourceServerClientRegistration
	err := tx.Where("resource_server_id = ? AND oauth_client_id = ?", rsID, clientID).First(&reg).Error
	if err == nil {
		return reg.ID, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return uuid.Nil, fmt.Errorf("look up registration: %w", err)
	}

	reg = models.ResourceServerClientRegistration{
		ID:               uuid.New(),
		ResourceServerID: rsID,
		OAuthClientID:    clientID,
		WorkspaceID:      workspaceID,
		// pending_approval, not approved: the very next step approves it, and going
		// through the real approval path means access_requests and the role binding
		// are handled by the one primitive that already gets that right.
		Status: models.ClientRegStatusPendingApproval,
	}
	if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&reg).Error; err != nil {
		return uuid.Nil, fmt.Errorf("create registration: %w", err)
	}
	// A concurrent provision may have won the insert; re-read to get the surviving id.
	if err := tx.Where("resource_server_id = ? AND oauth_client_id = ?", rsID, clientID).
		First(&reg).Error; err != nil {
		return uuid.Nil, fmt.Errorf("re-read registration: %w", err)
	}
	return reg.ID, nil
}

func (m *provisioningManager) resourceServerName(tx *gorm.DB, rsID uuid.UUID) (string, error) {
	var name string
	err := tx.Raw(`SELECT name FROM resource_servers WHERE id = ?`, rsID).Scan(&name).Error
	if name == "" {
		name = rsID.String()
	}
	return name, err
}

// identityAnchorFrom pulls the Kubernetes workload identity out of a sighting's
// metadata: metadata.provisioning_hints.identity_anchor, e.g.
// "system:serviceaccount:analytics:pipeline-runner".
func identityAnchorFrom(metadata json.RawMessage) string {
	if len(metadata) == 0 {
		return ""
	}
	var m struct {
		ProvisioningHints struct {
			IdentityAnchor string `json:"identity_anchor"`
		} `json:"provisioning_hints"`
	}
	if err := json.Unmarshal(metadata, &m); err != nil {
		return ""
	}
	return m.ProvisioningHints.IdentityAnchor
}

// anchorName builds a stable, readable service-account name for an agent.
func anchorName(agent *models.DiscoveredAgent, client *models.MCPOAuthClient) string {
	// The fingerprint prefix keeps it unique without being unreadable, and it ties
	// the anchor back to the sighting it came from.
	fp := agent.Fingerprint
	if len(fp) > 8 {
		fp = fp[:8]
	}
	base := client.ClientID
	if base == "" {
		base = "agent"
	}
	if len(base) > 40 {
		base = base[:40]
	}
	return fmt.Sprintf("agent-%s-%s", base, fp)
}

/* ------------------------------ deprovision ----------------------------- */

func (m *provisioningManager) Deprovision(workspaceID uuid.UUID, in DeprovisionInput) (*DeprovisionResult, error) {
	if !containsString(models.ValidRevokedVia(), in.Via) {
		return nil, fmt.Errorf("unknown revocation mechanism %q", in.Via)
	}
	if in.DiscoveredAgentID == nil && in.OAuthClientID == nil {
		return nil, errors.New("one of discovered_agent_id or oauth_client_id is required")
	}

	res := &DeprovisionResult{}

	err := m.db.Transaction(func(tx *gorm.DB) error {
		// Resolve the identity from whichever handle the caller had.
		clientID := uuid.Nil
		if in.OAuthClientID != nil {
			clientID = *in.OAuthClientID
		} else {
			var agent models.DiscoveredAgent
			if err := tx.First(&agent, "id = ? AND workspace_id = ?",
				*in.DiscoveredAgentID, workspaceID).Error; err != nil {
				return fmt.Errorf("discovered agent not found in this workspace: %w", err)
			}
			if agent.MatchedClientID == nil {
				// Never provisioned, so there is nothing to take away. Not an error:
				// quarantine and leaver both fan out over agents that may or may not
				// have been provisioned.
				res.AlreadyDeprovisioned = true
				return nil
			}
			clientID = *agent.MatchedClientID
		}
		res.OAuthClientID = clientID

		var client models.MCPOAuthClient
		if err := tx.First(&client, "id = ?", clientID).Error; err != nil {
			return fmt.Errorf("oauth client not found: %w", err)
		}

		// The paired anchors. Plural deliberately: nothing stops an older path having
		// created more than one, and leaving a stray anchor holding bindings would
		// leave the agent partly alive.
		var anchors []models.ServiceAccount
		if err := tx.Where("workspace_id = ? AND oauth_client_id = ?", workspaceID, clientID).
			Find(&anchors).Error; err != nil {
			return fmt.Errorf("find entitlement anchors: %w", err)
		}

		// 1. Role bindings held by each anchor, with provenance closed first.
		for _, sa := range anchors {
			var bindings []models.RoleBinding
			if err := tx.Where("workspace_id = ? AND service_account_id = ?", workspaceID, sa.ID).
				Find(&bindings).Error; err != nil {
				return fmt.Errorf("find bindings for anchor %s: %w", sa.ID, err)
			}
			for _, b := range bindings {
				bindingID := b.ID
				closed, cerr := m.provenance.CloseGrant(tx, workspaceID, CloseGrantInput{
					RoleBindingID: &bindingID,
					Via:           in.Via,
					Reason:        in.Reason,
					By:            in.By,
					At:            time.Now(),
				})
				if cerr != nil {
					return cerr
				}
				if closed {
					res.ProvenanceClosed++
				}
				if derr := m.repo.DeleteRoleBindingTx(tx, bindingID); derr != nil {
					return fmt.Errorf("delete binding %s: %w", bindingID, derr)
				}
				res.BindingsRemoved++
			}

			// 2. Live tokens for the anchor. This is what makes revocation immediate
			// rather than eventual: introspection treats revoked_tokens as
			// authoritative, so without this the agent keeps working until its current
			// token expires (up to an hour for native M2M).
			tokens, terr := m.repo.LiveTokenJTIsForSubject(sa.ID, models.ProvenanceSubjectServiceAccount)
			if terr != nil {
				return fmt.Errorf("list live tokens for anchor %s: %w", sa.ID, terr)
			}
			if len(tokens) > 0 {
				if rerr := m.repo.RevokeTokensTx(tx, tokens, deprovisionReason(in)); rerr != nil {
					return rerr
				}
				res.TokensRevoked += len(tokens)
			}

			// 3. Disable the anchor so nothing can bind to it again without a new
			// provision. Kept rather than deleted: it is referenced by closed
			// provenance and by audit history.
			if uerr := tx.Model(&models.ServiceAccount{}).
				Where("id = ? AND workspace_id = ? AND status <> ?", sa.ID, workspaceID, "disabled").
				Update("status", "disabled").Error; uerr != nil {
				return fmt.Errorf("disable anchor %s: %w", sa.ID, uerr)
			}
			res.ServiceAccountsDisabled++
		}

		// 4. Registrations: revoke rather than delete, so the history of the agent
		// having been connected survives.
		var regs []models.ResourceServerClientRegistration
		if err := tx.Where("oauth_client_id = ? AND status <> ?", clientID, models.ClientRegStatusRevoked).
			Find(&regs).Error; err != nil {
			return fmt.Errorf("find registrations: %w", err)
		}
		for _, reg := range regs {
			regID := reg.ID
			closed, cerr := m.provenance.CloseGrant(tx, workspaceID, CloseGrantInput{
				ClientRegistrationID: &regID,
				Via:                  in.Via,
				Reason:               in.Reason,
				By:                   in.By,
				At:                   time.Now(),
			})
			if cerr != nil {
				return cerr
			}
			if closed {
				res.ProvenanceClosed++
			}
			if uerr := tx.Model(&models.ResourceServerClientRegistration{}).
				Where("id = ?", regID).
				Update("status", models.ClientRegStatusRevoked).Error; uerr != nil {
				return fmt.Errorf("revoke registration %s: %w", regID, uerr)
			}
			res.RegistrationsRevoked++
		}

		// 5. The identity itself.
		if uerr := tx.Model(&models.MCPOAuthClient{}).Where("id = ?", clientID).
			Update("governance_status", models.GovernanceStatusDeprovisioned).Error; uerr != nil {
			return fmt.Errorf("set governance status: %w", uerr)
		}

		// 6. Zero-residual check. Asserting the outcome rather than assuming it is the
		// difference between "we revoked" and "we ran some statements".
		var residual int64
		if err := tx.Model(&models.RoleBinding{}).
			Joins("JOIN service_accounts sa ON sa.id = role_bindings.service_account_id").
			Where("sa.oauth_client_id = ? AND (role_bindings.expires_at IS NULL OR role_bindings.expires_at > NOW())",
				clientID).
			Count(&residual).Error; err != nil {
			return fmt.Errorf("residual check: %w", err)
		}
		res.ResidualBindings = int(residual)
		if residual > 0 {
			// Fail the transaction. A de-provision that leaves live bindings behind
			// must not report success — that is exactly how "revoked" access keeps
			// working.
			return fmt.Errorf("de-provision incomplete: %d role binding(s) still resolvable for client %s",
				residual, clientID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func deprovisionReason(in DeprovisionInput) string {
	if strings.TrimSpace(in.Reason) != "" {
		return in.Reason
	}
	return "agent deprovisioned via " + in.Via
}

/* ---------------------------- console approvals -------------------------- */

// GrantEntitlementInput is an approval made through the console rather than through
// the discovery pipeline: an admin approving a connection, or approving a pending
// access request.
type GrantEntitlementInput struct {
	ResourceServerID uuid.UUID
	// ClientID is the public oauth client_id being approved.
	ClientID string
	// RoleID nil means "approve the connection, grant no role" — the existing
	// connection-only behaviour.
	RoleID       *uuid.UUID
	SubjectType  string
	SubjectID    uuid.UUID
	SubjectLabel string

	AccessRequestID *uuid.UUID
	Origin          string
	Justification   string
	Purpose         string

	ExpiresAt  *time.Time
	IsStanding bool

	ActingUser      *uuid.UUID
	ActingUserLabel string
}

// GrantResult reports what an approval produced.
type GrantResult struct {
	RegistrationID uuid.UUID  `json:"registration_id"`
	RoleBindingID  *uuid.UUID `json:"role_binding_id,omitempty"`
	ProvenanceID   *uuid.UUID `json:"provenance_id,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	IsStanding     bool       `json:"is_standing"`
	// LegacyStandingDefault is true when the caller supplied neither an expiry nor an
	// explicit standing justification, and this grant was therefore made permanent to
	// preserve the endpoint's historical behaviour. Surfaced so a console can warn and
	// so the count can be driven to zero.
	LegacyStandingDefault bool `json:"legacy_standing_default,omitempty"`
}

// legacyStandingJustification marks a permanent grant that nobody actually justified.
//
// These endpoints created permanent bindings unconditionally before governance
// existed, and the console does not yet send a duration. Refusing the request would
// break a live path, so instead the grant is recorded as standing with THIS
// justification — which keeps behaviour identical while making every unjustified
// permanent grant visible, countable, and reviewable in certification. Once the
// console sends a duration, the fallback can be turned into a hard error.
const legacyStandingJustification = "approved via console with no stated duration (legacy default; " +
	"review and set an expiry)"

// GrantEntitlement approves a client registration and, optionally, binds a role —
// with an expiry and with provenance, in ONE transaction.
//
// This exists because both console approval paths previously called the atomic-approve
// primitive with no expiry and wrote no provenance, so every approval produced a
// permanent grant that nothing could explain later. Routing both through here means
// the expiry and the "why" are not optional extras a caller can forget.
func (m *provisioningManager) GrantEntitlement(workspaceID uuid.UUID, in GrantEntitlementInput) (*GrantResult, error) {
	if in.ResourceServerID == uuid.Nil || in.ClientID == "" {
		return nil, errors.New("resource_server_id and client_id are required")
	}
	if !containsString(models.ValidGrantOrigins(), in.Origin) {
		return nil, fmt.Errorf("unknown grant origin %q", in.Origin)
	}

	res := &GrantResult{}
	justification := strings.TrimSpace(in.Justification)
	expiresAt := in.ExpiresAt
	standing := in.IsStanding

	// Only relevant when a role is actually being bound; a connection-only approval
	// grants no authority and so has no duration to reason about.
	if in.RoleID != nil {
		switch {
		case expiresAt != nil && standing:
			return nil, errors.New("a standing grant cannot also have an expiry")
		case expiresAt != nil:
			if !expiresAt.After(time.Now()) {
				return nil, fmt.Errorf("expires_at %s is not in the future", expiresAt.Format(time.RFC3339))
			}
		case standing:
			if justification == "" {
				return nil, errors.New("a standing (non-expiring) grant requires a justification")
			}
		default:
			// Neither given. Preserve the endpoint's historical behaviour rather than
			// breaking it, but record the grant as an unjustified permanent one.
			standing = true
			res.LegacyStandingDefault = true
			if justification == "" {
				justification = legacyStandingJustification
			}
		}
	}

	err := m.db.Transaction(func(tx *gorm.DB) error {
		// ensureRegistration needs the client's internal id, which the approve
		// primitive resolves from the public client_id. Resolve it here so provenance
		// can point at the registration row.
		var client models.MCPOAuthClient
		if cerr := tx.Where("client_id = ?", in.ClientID).First(&client).Error; cerr != nil {
			return fmt.Errorf("oauth client %q not found: %w", in.ClientID, cerr)
		}
		regID, err := m.ensureRegistration(tx, workspaceID, in.ResourceServerID, client.ID)
		if err != nil {
			return err
		}
		res.RegistrationID = regID

		if in.RoleID != nil {
			// Preventive check here too: a console approval is just as capable of
			// creating a conflict as a discovery-driven provision, and a control that
			// only guards one entry point is not a control.
			if err := m.checkSoD(tx, workspaceID, in.SubjectType, in.SubjectID,
				in.SubjectLabel, *in.RoleID); err != nil {
				return err
			}
		}

		var binding *ApprovalRoleBinding
		if in.RoleID != nil {
			binding = &ApprovalRoleBinding{
				RoleID:      *in.RoleID,
				SubjectType: in.SubjectType,
				SubjectID:   in.SubjectID,
				ExpiresAt:   expiresAt,
			}
		}
		if aerr := m.oauth.ApproveClientRegistrationInTx(tx, in.ResourceServerID.String(),
			in.ClientID, binding); aerr != nil {
			return aerr
		}
		if binding == nil {
			return nil
		}

		// Locate the binding the approval created, so provenance points at a real row.
		var rb models.RoleBinding
		q := tx.Where(`workspace_id = ? AND role_id = ? AND scope_type = 'resource_server' AND scope_id = ?`,
			workspaceID, *in.RoleID, in.ResourceServerID)
		if in.SubjectType == "service_account" {
			q = q.Where("service_account_id = ?", in.SubjectID)
		} else {
			q = q.Where("user_id = ?", in.SubjectID)
		}
		if berr := q.First(&rb).Error; berr != nil {
			return fmt.Errorf("could not locate the role binding just created: %w", berr)
		}
		res.RoleBindingID = &rb.ID

		// Is this entitlement already explained? A re-approval is legitimate and
		// idempotent, so check BEFORE inserting.
		//
		// Catching the unique violation afterwards does not work: Postgres marks the
		// whole transaction as failed on a constraint violation, so the surrounding
		// commit then fails with "current transaction is aborted" even if the error is
		// handled. A genuine concurrent race still hits the index and rolls that
		// transaction back, which is correct — the caller retries and finds the row.
		var existing int64
		if cerr := tx.Model(&models.EntitlementProvenance{}).
			Where("role_binding_id = ? AND revoked_at IS NULL", rb.ID).
			Count(&existing).Error; cerr != nil {
			return fmt.Errorf("check existing provenance: %w", cerr)
		}
		if existing > 0 {
			res.ExpiresAt = expiresAt
			res.IsStanding = standing
			return nil
		}

		rsName, _ := m.resourceServerName(tx, in.ResourceServerID)
		prov, perr := m.provenance.OpenGrant(tx, workspaceID, OpenGrantInput{
			EntitlementType: models.EntitlementRoleBinding,
			RoleBindingID:   &rb.ID,
			Snapshot: map[string]interface{}{
				"role_id":            in.RoleID.String(),
				"role_name":          rb.RoleName,
				"scope_type":         "resource_server",
				"resource_server_id": in.ResourceServerID.String(),
				"resource_server":    rsName,
				"oauth_client_id":    in.ClientID,
			},
			Label:           fmt.Sprintf("%s on %s", rb.RoleName, rsName),
			SubjectType:     in.SubjectType,
			SubjectID:       in.SubjectID,
			SubjectLabel:    in.SubjectLabel,
			Origin:          in.Origin,
			Justification:   justification,
			Purpose:         in.Purpose,
			AccessRequestID: in.AccessRequestID,
			GrantedBy:       in.ActingUser,
			GrantedByLabel:  in.ActingUserLabel,
			ExpiresAt:       expiresAt,
			IsStanding:      standing,
		})
		if perr != nil {
			return fmt.Errorf("record provenance: %w", perr)
		}
		res.ProvenanceID = &prov.ID
		res.ExpiresAt = expiresAt
		res.IsStanding = standing
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// ErrSoDViolation is returned when a grant would breach a blocking SoD rule.
var ErrSoDViolation = errors.New("separation-of-duties violation")

// checkSoD refuses a grant that would create a blocking violation.
//
// The refusal is RECORDED as a preventive violation, not just returned: an attempt to
// give an agent role-management authority is worth keeping as evidence even though it
// did not succeed. Recording happens outside the transaction that is about to roll
// back, for the obvious reason that a rolled-back transaction records nothing.
func (m *provisioningManager) checkSoD(tx *gorm.DB, workspaceID uuid.UUID,
	subjectType string, subjectID uuid.UUID, subjectLabel string, roleID uuid.UUID) error {

	in := SoDCheckInput{
		SubjectType:  subjectType,
		SubjectID:    subjectID,
		SubjectLabel: subjectLabel,
		AddingRoleID: roleID,
	}
	decision, err := m.sod.Check(tx, workspaceID, in)
	if err != nil {
		return fmt.Errorf("separation-of-duties check: %w", err)
	}
	if decision.Allowed {
		return nil
	}

	// Build the message before returning, so the caller sees WHICH rule and WHY rather
	// than a bare refusal they cannot act on.
	first := decision.Blocking[0]
	msg := fmt.Sprintf("%s: %s", first.RuleName, first.Explanation)
	if len(decision.Blocking) > 1 {
		msg += fmt.Sprintf(" (and %d further rule(s))", len(decision.Blocking)-1)
	}

	// Record the attempt on a SEPARATE connection: this transaction is about to roll
	// back, and evidence written inside it would roll back with it.
	if recorder, ok := m.sod.(interface {
		RecordPreventiveViolation(uuid.UUID, SoDCheckInput, SoDHit) error
	}); ok {
		for _, hit := range decision.Blocking {
			if rerr := recorder.RecordPreventiveViolation(workspaceID, in, hit); rerr != nil {
				// Losing the evidence must not turn a correct refusal into an accidental
				// approval, so this is logged by the caller's error path, not returned.
				log.Printf("sod: could not record preventive violation for rule %s: %v",
					hit.RuleName, rerr)
			}
		}
	}
	return fmt.Errorf("%w: %s", ErrSoDViolation, msg)
}
