//go:build integration

package flows

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// WorkspaceScenario holds the IDs and credentials for a seeded workspace with
// an admin user. All fields are populated by SeedWorkspaceWithAdmin.
type WorkspaceScenario struct {
	WorkspaceID     uuid.UUID
	AdminUserID     uuid.UUID
	AdminRoleID     uuid.UUID
	ClientID        uuid.UUID
	WorkspaceDomain string
	AdminEmail      string
	AdminPassword   string
}

// EndUserScenario holds the IDs and credentials for a non-admin end user
// added to an existing workspace.
type EndUserScenario struct {
	UserID      uuid.UUID
	Email       string
	Password    string
	WorkspaceID uuid.UUID
}

// RSScenario holds the IDs and credentials for a seeded resource server.
type RSScenario struct {
	RSID                uuid.UUID
	ResourceURI         string
	IntrospectionSecret string
	ScopeIDs            []uuid.UUID
	ScopeStrings        []string
	WorkspaceID         uuid.UUID
}

// SAScenario holds the IDs and credentials for a seeded service account with
// an associated OAuth client.
type SAScenario struct {
	SAID           uuid.UUID
	ClientID       uuid.UUID // mcp_oauth_clients.id (UUID PK, used for FK refs)
	ClientIDString string    // mcp_oauth_clients.client_id (the OAuth client_id string for BasicAuth)
	ClientSecret   string
	WorkspaceID    uuid.UUID
}

// SeedWorkspaceWithAdmin creates a fully wired workspace: a workspaces row, a
// tenants row (lockstep invariant — same id), an admin user, an admin role, and
// a role binding tying the user to that role.
//
// nonce must be unique per test run; callers typically pass a uuid.New().String()
// short suffix.
func SeedWorkspaceWithAdmin(db *gorm.DB, nonce string) (*WorkspaceScenario, error) {
	workspaceID := uuid.New()
	adminUserID := uuid.New()
	adminRoleID := uuid.New()
	clientID := uuid.New()

	domain := nonce + ".test.local"
	email := "admin@" + nonce + ".test.local"
	password := "Password123!"

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("bcrypt admin password: %w", err)
	}

	// workspaces row
	if err := db.Exec(`
		INSERT INTO workspaces (id, name, workspace_domain, email, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'active', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		workspaceID, "workspace-"+nonce, domain, email,
	).Error; err != nil {
		return nil, fmt.Errorf("insert workspace: %w", err)
	}

	// NOTE: the tenants table was dropped in Phase 6 (CLAUDE.md). No tenants row needed.

	// users row — admin user; id == workspaceID is the convention used by the
	// existing seed helpers for the primary admin.
	if err := db.Exec(`
		INSERT INTO users (id, client_id, workspace_id, email, password_hash, workspace_domain, provider, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'local', true, NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		adminUserID, clientID, workspaceID, email, string(hash), domain,
	).Error; err != nil {
		return nil, fmt.Errorf("insert admin user: %w", err)
	}

	// roles row — admin role
	if err := db.Exec(`
		INSERT INTO roles (id, workspace_id, name, description, is_system, created_at, updated_at)
		VALUES ($1, $2, 'admin', 'Admin role', true, NOW(), NOW())
		ON CONFLICT DO NOTHING`,
		adminRoleID, workspaceID,
	).Error; err != nil {
		return nil, fmt.Errorf("insert admin role: %w", err)
	}

	// role_bindings row — bind admin user to admin role (OAuth RBAC)
	if err := db.Exec(`
		INSERT INTO role_bindings (id, workspace_id, user_id, role_id, assignment_source, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'signup', NOW(), NOW())
		ON CONFLICT DO NOTHING`,
		uuid.New(), workspaceID, adminUserID, adminRoleID,
	).Error; err != nil {
		return nil, fmt.Errorf("insert admin role binding: %w", err)
	}

	// workspace_memberships row — required by workspace_role.go middleware for
	// console/operator access (role_bindings is for OAuth RBAC only).
	if err := db.Exec(`
		INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status, source, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'active', 'signup', NOW(), NOW())
		ON CONFLICT (workspace_id, user_id) DO NOTHING`,
		uuid.New(), workspaceID, adminUserID, adminRoleID,
	).Error; err != nil {
		return nil, fmt.Errorf("insert workspace membership: %w", err)
	}

	return &WorkspaceScenario{
		WorkspaceID:     workspaceID,
		AdminUserID:     adminUserID,
		AdminRoleID:     adminRoleID,
		ClientID:        clientID,
		WorkspaceDomain: domain,
		AdminEmail:      email,
		AdminPassword:   password,
	}, nil
}

// AddEndUserWithRole creates a non-admin user inside the given workspace.
// The user is seeded with provider="custom" and the fixed password "EndUserPass123!".
func AddEndUserWithRole(db *gorm.DB, ws *WorkspaceScenario, nonce string) (*EndUserScenario, error) {
	userID := uuid.New()
	email := "enduser-" + nonce + "@" + ws.WorkspaceDomain
	password := "EndUserPass123!"

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("bcrypt end-user password: %w", err)
	}

	if err := db.Exec(`
		INSERT INTO users (id, workspace_id, email, password_hash, workspace_domain, provider, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, 'custom', true, NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		userID, ws.WorkspaceID, email, string(hash), ws.WorkspaceDomain,
	).Error; err != nil {
		return nil, fmt.Errorf("insert end user: %w", err)
	}

	return &EndUserScenario{
		UserID:      userID,
		Email:       email,
		Password:    password,
		WorkspaceID: ws.WorkspaceID,
	}, nil
}

// AddResourceServer creates a resource_servers row and a single oauth_scopes
// row ("read:<nonce>") attached to it. The introspection secret is returned in
// plain text inside RSScenario; only the bcrypt hash is stored.
func AddResourceServer(db *gorm.DB, ws *WorkspaceScenario, publicBaseURL, nonce string) (*RSScenario, error) {
	rsID := uuid.New()
	scopeID := uuid.New()

	resourceURI := publicBaseURL + "/mcp"
	introspectionSecret := "rs-secret-" + nonce
	scopeString := "read:" + nonce

	introspectionHash, err := bcrypt.GenerateFromPassword([]byte(introspectionSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("bcrypt introspection secret: %w", err)
	}

	// scopes_supported must list scopeString: the scope resolver's
	// intersectWithRS (services/scope_resolver.go) only grants a requested scope
	// when it appears in resource_servers.scopes_supported (NOT the oauth_scopes
	// table). Without this, every M2M/native scope is silently dropped.
	if err := db.Exec(`
		INSERT INTO resource_servers (
			id, workspace_id, name, public_base_url, protected_base_path,
			resource_uri, status, state, introspection_secret_hash, scopes_supported,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, '/mcp', $5, 'ready', 'ready', $6, ARRAY[$7]::text[], NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		rsID, ws.WorkspaceID, "rs-"+nonce, publicBaseURL, resourceURI, string(introspectionHash), scopeString,
	).Error; err != nil {
		return nil, fmt.Errorf("insert resource server: %w", err)
	}

	if err := db.Exec(`
		INSERT INTO oauth_scopes (id, workspace_id, resource_server_id, scope_string, display_name, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $4, NOW(), NOW())
		ON CONFLICT DO NOTHING`,
		scopeID, ws.WorkspaceID, rsID, scopeString,
	).Error; err != nil {
		return nil, fmt.Errorf("insert oauth scope: %w", err)
	}

	return &RSScenario{
		RSID:                rsID,
		ResourceURI:         resourceURI,
		IntrospectionSecret: introspectionSecret,
		ScopeIDs:            []uuid.UUID{scopeID},
		ScopeStrings:        []string{scopeString},
		WorkspaceID:         ws.WorkspaceID,
	}, nil
}

// AddServiceAccountWithScopes creates an mcp_oauth_clients row (confidential,
// client_secret_basic), a service_accounts row, an oauth_client_secrets row,
// and a resource_server_client_registrations row with status "approved".
//
// The plain-text client secret is returned in SAScenario; only the bcrypt hash
// is stored in the database.
func AddServiceAccountWithScopes(db *gorm.DB, ws *WorkspaceScenario, rs *RSScenario, nonce string) (*SAScenario, error) {
	mcpClientID := uuid.New()
	saID := uuid.New()
	secretID := uuid.New()
	regID := uuid.New()

	clientPublicID := "sa-" + nonce
	hydraClientID := "sa-hydra-" + nonce
	clientSecret := "sa-secret-" + nonce

	secretHash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("bcrypt client secret: %w", err)
	}

	// mcp_oauth_clients — confidential client using client_secret_basic
	if err := db.Exec(`
		INSERT INTO mcp_oauth_clients (
			id, client_id, hydra_client_id, client_name,
			token_endpoint_auth_method, is_confidential,
			allowed_token_endpoint_auth_methods,
			client_kind, home_workspace_id,
			grant_types, response_types, redirect_uris,
			registration_type, sync_status,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			'client_secret_basic', true,
			ARRAY['client_secret_basic'],
			'm2m', $5,
			ARRAY['client_credentials'], ARRAY['token'], ARRAY[]::text[],
			'prereg', 'active',
			NOW(), NOW()
		) ON CONFLICT (client_id) DO NOTHING`,
		mcpClientID, clientPublicID, hydraClientID, "Service Account "+nonce, ws.WorkspaceID,
	).Error; err != nil {
		return nil, fmt.Errorf("insert mcp_oauth_clients: %w", err)
	}

	// service_accounts — primary key is (workspace_id, id)
	if err := db.Exec(`
		INSERT INTO service_accounts (id, workspace_id, name, oauth_client_id, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'active', NOW(), NOW())
		ON CONFLICT (workspace_id, id) DO NOTHING`,
		saID, ws.WorkspaceID, "sa-"+nonce, mcpClientID,
	).Error; err != nil {
		return nil, fmt.Errorf("insert service_accounts: %w", err)
	}

	// oauth_client_secrets — bcrypt hash of the plain-text secret
	if err := db.Exec(`
		INSERT INTO oauth_client_secrets (id, client_id, secret_hash, created_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (id) DO NOTHING`,
		secretID, mcpClientID, string(secretHash),
	).Error; err != nil {
		return nil, fmt.Errorf("insert oauth_client_secrets: %w", err)
	}

	// resource_server_client_registrations — marks the SA as approved for the RS
	if err := db.Exec(`
		INSERT INTO resource_server_client_registrations (
			id, resource_server_id, oauth_client_id, workspace_id,
			status, registration_type, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'approved', 'prereg', NOW(), NOW())
		ON CONFLICT (resource_server_id, oauth_client_id) DO NOTHING`,
		regID, rs.RSID, mcpClientID, ws.WorkspaceID,
	).Error; err != nil {
		return nil, fmt.Errorf("insert resource_server_client_registrations: %w", err)
	}

	// Grant the SA an effective scope on the RS by seeding the full
	// role → permission → scope → role_binding chain that scope_resolver
	// walks to resolve SA effective scopes (services/scope_resolver.go:514-535).
	// Without this chain the M2M grant returns
	// "no scopes granted to this service account for the requested resource".
	if err := grantServiceAccountScope(db, ws, rs, saID, nonce); err != nil {
		return nil, err
	}

	return &SAScenario{
		SAID:           saID,
		ClientID:       mcpClientID,
		ClientIDString: clientPublicID,
		ClientSecret:   clientSecret,
		WorkspaceID:    ws.WorkspaceID,
	}, nil
}

// grantServiceAccountScope wires the role → permission → oauth_scope →
// role_binding chain so the given service account has a real effective scope on
// the resource server. It reuses the RS's existing oauth_scope (seeded by
// AddResourceServer as "read:<nonce>") when present; otherwise it inserts one.
// All ids/names are unique per nonce so parallel tests don't collide.
func grantServiceAccountScope(db *gorm.DB, ws *WorkspaceScenario, rs *RSScenario, saID uuid.UUID, nonce string) error {
	roleID := uuid.New()
	permID := uuid.New()

	// Reuse the RS's existing oauth_scope when AddResourceServer already made one;
	// otherwise insert a fresh "read:<nonce>" scope (the value the M2M tests request).
	scopeID := uuid.New()
	scopeString := "read:" + nonce
	if len(rs.ScopeIDs) > 0 {
		scopeID = rs.ScopeIDs[0]
	} else {
		if err := db.Exec(`
			INSERT INTO oauth_scopes (id, workspace_id, resource_server_id, scope_string, display_name, source, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $4, 'discovered', NOW(), NOW())
			ON CONFLICT DO NOTHING`,
			scopeID, ws.WorkspaceID, rs.RSID, scopeString,
		).Error; err != nil {
			return fmt.Errorf("grantServiceAccountScope: insert oauth_scope: %w", err)
		}
	}

	// roles — unique per-workspace name ("admin" is already taken by SeedWorkspaceWithAdmin).
	if err := db.Exec(`
		INSERT INTO roles (id, workspace_id, name, description, is_system, created_at, updated_at)
		VALUES ($1, $2, $3, 'SA scope role', false, NOW(), NOW())
		ON CONFLICT DO NOTHING`,
		roleID, ws.WorkspaceID, "sa-role-"+nonce,
	).Error; err != nil {
		return fmt.Errorf("grantServiceAccountScope: insert role: %w", err)
	}

	// permissions — any non-empty resource/action; unique per (workspace, resource, action).
	if err := db.Exec(`
		INSERT INTO permissions (id, resource, action, full_permission_string, workspace_id, created_at, updated_at)
		VALUES ($1, $2, 'read', $3, $4, NOW(), NOW())
		ON CONFLICT DO NOTHING`,
		permID, "sa-"+nonce, "sa-"+nonce+":read", ws.WorkspaceID,
	).Error; err != nil {
		return fmt.Errorf("grantServiceAccountScope: insert permission: %w", err)
	}

	// role_permissions — link role → permission.
	if err := db.Exec(`
		INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		roleID, permID,
	).Error; err != nil {
		return fmt.Errorf("grantServiceAccountScope: insert role_permission: %w", err)
	}

	// oauth_scope_permissions — link scope → permission.
	if err := db.Exec(`
		INSERT INTO oauth_scope_permissions (scope_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		scopeID, permID,
	).Error; err != nil {
		return fmt.Errorf("grantServiceAccountScope: insert oauth_scope_permission: %w", err)
	}

	// role_bindings — bind the SA to the role, scoped to this RS.
	if err := db.Exec(`
		INSERT INTO role_bindings (
			id, workspace_id, service_account_id, role_id, role_name,
			scope_type, scope_id, conditions, assignment_source, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, 'resource_server', $6, '{}'::jsonb, 'manual_admin', NOW(), NOW())
		ON CONFLICT DO NOTHING`,
		uuid.New(), ws.WorkspaceID, saID, roleID, "sa-role-"+nonce, rs.RSID,
	).Error; err != nil {
		return fmt.Errorf("grantServiceAccountScope: insert role_binding: %w", err)
	}

	return nil
}

// CIBAScenario holds the end user created for native CIBA flows.
type CIBAScenario struct {
	UserID      uuid.UUID
	Email       string
	WorkspaceID uuid.UUID
}

// AddCIBAUser creates an end user bound to the given SA's OAuth client and a
// workspace_device_tokens row so that bc-authorize can resolve the user and
// find a registered push device.
//
// The user's users.client_id is set to sa.ClientID (the SA's mcp_oauth_clients.id)
// because GetTenantUserByEmail queries by (email, client_id=sa_uuid).
func AddCIBAUser(db *gorm.DB, ws *WorkspaceScenario, sa *SAScenario, nonce string) (*CIBAScenario, error) {
	userID := uuid.New()
	email := "ciba-" + nonce + "@" + ws.WorkspaceDomain

	if err := db.Exec(`
		INSERT INTO users (id, client_id, workspace_id, email, password_hash, workspace_domain, provider, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, '', $5, 'custom', true, NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		userID, sa.ClientID, ws.WorkspaceID, email, ws.WorkspaceDomain,
	).Error; err != nil {
		return nil, fmt.Errorf("insert ciba user: %w", err)
	}

	// workspace_device_tokens uses bigint for created_at/updated_at (unix seconds).
	now := time.Now().Unix()
	if err := db.Exec(`
		INSERT INTO workspace_device_tokens (id, user_id, workspace_id, device_token, platform, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'test', true, $5, $5)
		ON CONFLICT DO NOTHING`,
		uuid.New(), userID, ws.WorkspaceID, "device-token-"+nonce, now,
	).Error; err != nil {
		return nil, fmt.Errorf("insert workspace_device_token: %w", err)
	}

	return &CIBAScenario{
		UserID:      userID,
		Email:       email,
		WorkspaceID: ws.WorkspaceID,
	}, nil
}

// XAAScenario holds the cross-workspace relationship seeded for XAA ID-JAG tests.
// The single SA from workspace A is approved for workspace B's RS, enabling the
// issue-in-A → redeem-in-B round-trip.
type XAAScenario struct {
	WorkspaceA *WorkspaceScenario
	SAA        *SAScenario // wsA SA — authenticated for both issue and redeem
	RSA        *RSScenario // wsA RS (source of truth / token subject context)
	WorkspaceB *WorkspaceScenario
	RSB        *RSScenario // wsB RS — wsA SA is approved here; user JIT-mapped
}

// AddXAARelationship creates a second workspace (B) with a resource server and
// wires the existing workspace-A SA to redeem ID-JAGs against workspace B.
//
// Setup details:
//   - Creates wsB workspace, admin user, admin role.
//   - Creates wsB RS with one scope.
//   - Bridges wsB admin role → wsB RS scope so the mapped user has effective
//     scope grants in wsB.
//   - Creates an oidc_user_identities row (provider="authsec:id-jag") mapping
//     the wsA admin user UUID → wsB admin user so mapSubject returns a user
//     with valid role bindings instead of JIT-provisioning a zero-binding user.
//   - Approves the wsA SA for the wsB RS.
func AddXAARelationship(db *gorm.DB, wsA *WorkspaceScenario, saA *SAScenario, rsA *RSScenario, nonce string) (*XAAScenario, error) {
	wsB, err := SeedWorkspaceWithAdmin(db, "xb"+nonce)
	if err != nil {
		return nil, fmt.Errorf("AddXAARelationship: seed wsB: %w", err)
	}

	rsB, err := AddResourceServer(db, wsB, "https://xb-rs-"+nonce+".example.com", "xb"+nonce)
	if err != nil {
		return nil, fmt.Errorf("AddXAARelationship: seed wsB RS: %w", err)
	}

	// Bridge wsB admin role → wsB RS scope via permissions.
	permID := uuid.New()
	if err := db.Exec(`
		INSERT INTO permissions (id, resource, action, full_permission_string, workspace_id, created_at, updated_at)
		VALUES ($1, $2, 'read', $3, $4, NOW(), NOW())`,
		permID, "xb-"+nonce, "xb-"+nonce+":read", wsB.WorkspaceID,
	).Error; err != nil {
		return nil, fmt.Errorf("AddXAARelationship: insert permission: %w", err)
	}
	if err := db.Exec(`
		INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		wsB.AdminRoleID, permID,
	).Error; err != nil {
		return nil, fmt.Errorf("AddXAARelationship: insert role_permission: %w", err)
	}
	if len(rsB.ScopeIDs) > 0 {
		if err := db.Exec(`
			INSERT INTO oauth_scope_permissions (scope_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			rsB.ScopeIDs[0], permID,
		).Error; err != nil {
			return nil, fmt.Errorf("AddXAARelationship: insert oauth_scope_permission: %w", err)
		}
	}

	// Pre-map wsA admin user → wsB admin user via oidc_user_identities so that
	// mapSubject returns a user with role bindings (not a zero-binding JIT user).
	// provider_name = "authsec:id-jag" matches what ValidateIDJAG uses for self-issued tokens.
	// provider_user_id = wsA admin UUID (the `sub` claim in the ID-JAG).
	if err := db.Exec(`
		INSERT INTO oidc_user_identities (id, workspace_id, user_id, provider_name, provider_user_id, email, created_at, updated_at)
		VALUES ($1, $2, $3, 'authsec:id-jag', $4, $5, NOW(), NOW())
		ON CONFLICT (workspace_id, provider_name, provider_user_id) DO NOTHING`,
		uuid.New(), wsB.WorkspaceID, wsB.AdminUserID, wsA.AdminUserID.String(), wsA.AdminEmail,
	).Error; err != nil {
		return nil, fmt.Errorf("AddXAARelationship: insert oidc_user_identities: %w", err)
	}

	// Approve wsA SA for wsB RS.
	if err := db.Exec(`
		INSERT INTO resource_server_client_registrations (
			id, resource_server_id, oauth_client_id, workspace_id,
			status, registration_type, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'approved', 'prereg', NOW(), NOW())
		ON CONFLICT (resource_server_id, oauth_client_id) DO NOTHING`,
		uuid.New(), rsB.RSID, saA.ClientID, wsB.WorkspaceID,
	).Error; err != nil {
		return nil, fmt.Errorf("AddXAARelationship: approve wsA SA for wsB RS: %w", err)
	}

	return &XAAScenario{
		WorkspaceA: wsA,
		SAA:        saA,
		RSA:        rsA,
		WorkspaceB: wsB,
		RSB:        rsB,
	}, nil
}
