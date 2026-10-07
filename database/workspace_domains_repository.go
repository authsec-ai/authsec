package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/google/uuid"
)

// WorkspaceDomain represents a verified or pending custom domain for a tenant
type WorkspaceDomain struct {
	ID                   uuid.UUID  `db:"id"`
	WorkspaceID          uuid.UUID  `db:"workspace_id"`
	Domain               string     `db:"domain"`
	Kind                 string     `db:"kind"` // 'platform_subdomain' or 'custom'
	IsPrimary            bool       `db:"is_primary"`
	IsVerified           bool       `db:"is_verified"`
	VerificationMethod   string     `db:"verification_method"` // 'dns_txt'
	VerificationToken    string     `db:"verification_token"`
	VerificationTXTName  *string    `db:"verification_txt_name"`  // e.g., _authsec-challenge.domain
	VerificationTXTValue *string    `db:"verification_txt_value"` // e.g., authsec-domain-verification=<token>
	VerifiedAt           *time.Time `db:"verified_at"`
	LastCheckedAt        *time.Time `db:"last_checked_at"`
	FailureReason        *string    `db:"failure_reason"`
	CreatedAt            time.Time  `db:"created_at"`
	UpdatedAt            time.Time  `db:"updated_at"`
	CreatedBy            *uuid.UUID `db:"created_by"`
	UpdatedBy            *uuid.UUID `db:"updated_by"`
}

// WorkspaceDomainsRepository handles database operations for tenant domains
type WorkspaceDomainsRepository struct {
	db *DBConnection
}

// NewWorkspaceDomainsRepository creates a new repository
func NewWorkspaceDomainsRepository(db *DBConnection) *WorkspaceDomainsRepository {
	return &WorkspaceDomainsRepository{db: db}
}

// generateVerificationToken creates a random 32-byte token (hex encoded)
func (tdr *WorkspaceDomainsRepository) generateVerificationToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return hex.EncodeToString(token), nil
}

// normalizeDomain converts domain to lowercase and removes trailing dot
func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(domain, ".")
}

// workspaceDomainColumns is the column list scanWorkspaceDomain expects.
const workspaceDomainColumns = `id, workspace_id, domain, kind, is_primary, is_verified,
			verification_method, verification_token, verification_txt_name,
			verification_txt_value, verified_at, last_checked_at, failure_reason,
			created_at, updated_at, created_by, updated_by`

func scanWorkspaceDomain(scan func(dest ...interface{}) error) (*WorkspaceDomain, error) {
	td := &WorkspaceDomain{}
	err := scan(
		&td.ID, &td.WorkspaceID, &td.Domain, &td.Kind, &td.IsPrimary, &td.IsVerified,
		&td.VerificationMethod, &td.VerificationToken, &td.VerificationTXTName,
		&td.VerificationTXTValue, &td.VerifiedAt, &td.LastCheckedAt, &td.FailureReason,
		&td.CreatedAt, &td.UpdatedAt, &td.CreatedBy, &td.UpdatedBy,
	)
	return td, err
}

// errDomainNotFound is returned for a domain that does not exist in the
// workspace, including another workspace's.
var errDomainNotFound = fmt.Errorf("domain not found")

// The methods taking a ctx work in the workspace it carries (see
// WithWorkspace), through internal/tenancy under row-level security. The
// methods taking a workspace id are the older entry points and run the same
// statements for that workspace.

// Create registers a new domain for ctx's workspace (pending verification).
// Domains are unique across workspaces.
func (tdr *WorkspaceDomainsRepository) Create(ctx context.Context, domain string, createdBy *uuid.UUID) (*WorkspaceDomain, error) {
	workspaceID, err := ctxWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	// Validate and normalize domain
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}
	if strings.Contains(domain, "/") || strings.Contains(domain, "\\") || strings.Contains(domain, "*") {
		return nil, fmt.Errorf("invalid domain format")
	}

	// Check if domain is already claimed by another tenant
	var existingWorkspaceID uuid.UUID
	err = tdr.db.DB.QueryRowContext(ctx,
		// TENANT-EXEMPT: domains are unique across workspaces; this finds another workspace's claim on the name.
		"SELECT workspace_id FROM workspace_domains WHERE domain = $1",
		domain,
	).Scan(&existingWorkspaceID)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to check domain uniqueness: %w", err)
	}
	if err == nil && existingWorkspaceID != workspaceID {
		return nil, fmt.Errorf("domain already claimed by another tenant")
	}

	// Generate verification token
	token, err := tdr.generateVerificationToken()
	if err != nil {
		return nil, err
	}

	// Build TXT record name and value
	txtName := fmt.Sprintf("_authsec-challenge.%s", domain)
	txtValue := fmt.Sprintf("authsec-domain-verification=%s", token)
	now := time.Now()

	td := &WorkspaceDomain{
		ID:                   uuid.New(),
		WorkspaceID:          workspaceID,
		Domain:               domain,
		Kind:                 "custom",
		IsPrimary:            false,
		IsVerified:           false,
		VerificationMethod:   "dns_txt",
		VerificationToken:    token,
		VerificationTXTName:  &txtName,
		VerificationTXTValue: &txtValue,
		CreatedAt:            now,
		UpdatedAt:            now,
		CreatedBy:            createdBy,
	}

	err = insertScoped(ctx, tdr.db.DB, `
		INSERT INTO workspace_domains (
			workspace_id, id, domain, kind, is_primary, is_verified,
			verification_method, verification_token, verification_txt_name,
			verification_txt_value, created_at, updated_at, created_by
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		td.ID, domain, td.Kind, false, false, "dns_txt", token, txtName, txtValue, now, now, createdBy)
	if err != nil {
		return nil, fmt.Errorf("failed to create domain: %w", err)
	}
	return td, nil
}

// CreateDomain registers a new domain for a tenant (pending verification)
func (tdr *WorkspaceDomainsRepository) CreateDomain(workspaceID uuid.UUID, domain string, createdBy *uuid.UUID) (*WorkspaceDomain, error) {
	return tdr.Create(WithWorkspace(context.Background(), workspaceID), domain, createdBy)
}

// Get retrieves a domain of ctx's workspace by id; another workspace's is
// "domain not found".
func (tdr *WorkspaceDomainsRepository) Get(ctx context.Context, id uuid.UUID) (*WorkspaceDomain, error) {
	td, err := scanWorkspaceDomain(func(dest ...interface{}) error {
		return tenancy.QueryRowContext(ctx, tdr.db.DB,
			`SELECT `+workspaceDomainColumns+` FROM workspace_domains WHERE workspace_id = $1 AND id = $2`,
			[]interface{}{id}, dest...)
	})
	if errors.Is(err, tenancy.ErrNotFound) {
		return nil, errDomainNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get domain: %w", err)
	}
	return td, nil
}

// domainContext returns a context carrying the workspace that owns domain id,
// for the id-only entry points below. Their callers (DomainController, after
// it compares the domain's workspace with the token's, and DomainService)
// predate the scoped layer; the statements they lead to run scoped to the
// owning workspace.
func (tdr *WorkspaceDomainsRepository) domainContext(id uuid.UUID) (context.Context, error) {
	var ws uuid.UUID
	// TENANT-EXEMPT: resolves the owner of a domain id (globally unique) for the legacy id-only entry points; nothing else is read.
	err := tdr.db.QueryRow(`SELECT workspace_id FROM workspace_domains WHERE id = $1`, id).Scan(&ws)
	if err == sql.ErrNoRows {
		return nil, errDomainNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get domain: %w", err)
	}
	return WithWorkspace(context.Background(), ws), nil
}

// GetDomainByID retrieves a domain by ID. Callers must check the domain's
// workspace; new code uses Get.
func (tdr *WorkspaceDomainsRepository) GetDomainByID(id uuid.UUID) (*WorkspaceDomain, error) {
	ctx, err := tdr.domainContext(id)
	if err != nil {
		return nil, err
	}
	return tdr.Get(ctx, id)
}

// GetDomainByHostname retrieves a verified domain by hostname (for Host → tenant resolution)
func (tdr *WorkspaceDomainsRepository) GetDomainByHostname(hostname string) (*WorkspaceDomain, error) {
	hostname = normalizeDomain(hostname)

	// TENANT-EXEMPT: Host → workspace resolution before any workspace is known; verified domains are unique across workspaces.
	query := `SELECT ` + workspaceDomainColumns + `
		FROM workspace_domains
		WHERE domain = $1 AND is_verified = true
		LIMIT 1
	`
	td, err := scanWorkspaceDomain(tdr.db.QueryRow(query, hostname).Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("domain not found or not verified")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get domain: %w", err)
	}

	return td, nil
}

// List retrieves the domains of ctx's workspace, primary first.
func (tdr *WorkspaceDomainsRepository) List(ctx context.Context) ([]WorkspaceDomain, error) {
	var domains []WorkspaceDomain
	err := queryScoped(ctx, tdr.db.DB, `SELECT `+workspaceDomainColumns+`
		FROM workspace_domains
		WHERE workspace_id = $1
		ORDER BY is_primary DESC, created_at DESC`, nil, func(rows *sql.Rows) error {
		td, err := scanWorkspaceDomain(rows.Scan)
		if err != nil {
			return fmt.Errorf("failed to scan domain: %w", err)
		}
		domains = append(domains, *td)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query domains: %w", err)
	}
	return domains, nil
}

// ListWorkspaceDomains retrieves all domains for a tenant
func (tdr *WorkspaceDomainsRepository) ListWorkspaceDomains(workspaceID uuid.UUID) ([]WorkspaceDomain, error) {
	return tdr.List(WithWorkspace(context.Background(), workspaceID))
}

// Primary retrieves the primary domain of ctx's workspace.
func (tdr *WorkspaceDomainsRepository) Primary(ctx context.Context) (*WorkspaceDomain, error) {
	td, err := scanWorkspaceDomain(func(dest ...interface{}) error {
		return tenancy.QueryRowContext(ctx, tdr.db.DB, `SELECT `+workspaceDomainColumns+`
		FROM workspace_domains
		WHERE workspace_id = $1 AND is_primary = true
		LIMIT 1`, nil, dest...)
	})
	if err != nil {
		if errors.Is(err, tenancy.ErrNotFound) {
			return nil, fmt.Errorf("no primary domain found for tenant")
		}
		return nil, fmt.Errorf("failed to query primary domain: %w", err)
	}
	return td, nil
}

// GetPrimaryDomainByWorkspaceID retrieves the primary domain for a tenant
func (tdr *WorkspaceDomainsRepository) GetPrimaryDomainByWorkspaceID(workspaceID uuid.UUID) (*WorkspaceDomain, error) {
	return tdr.Primary(WithWorkspace(context.Background(), workspaceID))
}

// MarkVerified marks a domain of ctx's workspace as verified.
func (tdr *WorkspaceDomainsRepository) MarkVerified(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	now := time.Now()
	result, err := tenancy.ExecContext(ctx, tdr.db.DB, `
		UPDATE workspace_domains
		SET is_verified = true, verified_at = $2, updated_at = $2, updated_by = $3
		WHERE workspace_id = $1 AND id = $4
	`, now, updatedBy, id)
	if err != nil {
		return fmt.Errorf("failed to verify domain: %w", err)
	}
	if affected(result) == 0 {
		return errDomainNotFound
	}
	return nil
}

// VerifyDomain marks a domain as verified. Callers must check the domain's
// workspace; new code uses MarkVerified.
func (tdr *WorkspaceDomainsRepository) VerifyDomain(id uuid.UUID, updatedBy *uuid.UUID) error {
	ctx, err := tdr.domainContext(id)
	if err != nil {
		return err
	}
	return tdr.MarkVerified(ctx, id, updatedBy)
}

// SetPrimary makes a domain of ctx's workspace its primary one (and unsets
// the others), in one transaction.
func (tdr *WorkspaceDomainsRepository) SetPrimary(ctx context.Context, domainID uuid.UUID, updatedBy *uuid.UUID) error {
	ws, err := ctxWorkspace(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	return tenancy.WithTx(ctx, tdr.db.DB, ws, func(tx *sql.Tx) error {
		// First, unset all other primary domains for this tenant
		if _, err := tenancy.ExecContext(ctx, tx, `
			UPDATE workspace_domains
			SET is_primary = false, updated_at = $2, updated_by = $3
			WHERE workspace_id = $1 AND is_primary = true
		`, now, updatedBy); err != nil {
			return fmt.Errorf("failed to unset other primary domains: %w", err)
		}
		// Then set this one as primary
		result, err := tenancy.ExecContext(ctx, tx, `
			UPDATE workspace_domains
			SET is_primary = true, updated_at = $2, updated_by = $3
			WHERE workspace_id = $1 AND id = $4
		`, now, updatedBy, domainID)
		if err != nil {
			return fmt.Errorf("failed to set primary domain: %w", err)
		}
		if affected(result) == 0 {
			return fmt.Errorf("domain not found for tenant")
		}
		return nil
	})
}

// SetPrimaryDomain sets a domain as primary for a tenant (and unsets others)
func (tdr *WorkspaceDomainsRepository) SetPrimaryDomain(workspaceID, domainID uuid.UUID, updatedBy *uuid.UUID) error {
	return tdr.SetPrimary(WithWorkspace(context.Background(), workspaceID), domainID, updatedBy)
}

// Delete deletes a domain of ctx's workspace.
func (tdr *WorkspaceDomainsRepository) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := tenancy.ExecContext(ctx, tdr.db.DB,
		`DELETE FROM workspace_domains WHERE workspace_id = $1 AND id = $2`, id)
	if err != nil {
		return fmt.Errorf("failed to delete domain: %w", err)
	}
	if affected(result) == 0 {
		return errDomainNotFound
	}
	return nil
}

// DeleteDomain deletes a domain. Callers must check the domain's workspace;
// new code uses Delete.
func (tdr *WorkspaceDomainsRepository) DeleteDomain(id uuid.UUID) error {
	ctx, err := tdr.domainContext(id)
	if err != nil {
		return err
	}
	return tdr.Delete(ctx, id)
}

// VerifiedDomains returns the verified domains of ctx's workspace, primary
// first.
func (tdr *WorkspaceDomainsRepository) VerifiedDomains(ctx context.Context) ([]string, error) {
	var domains []string
	err := queryScoped(ctx, tdr.db.DB, `
		SELECT domain
		FROM workspace_domains
		WHERE workspace_id = $1 AND is_verified = true
		ORDER BY is_primary DESC`, nil, func(rows *sql.Rows) error {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return fmt.Errorf("failed to scan domain: %w", err)
		}
		domains = append(domains, domain)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query verified domains: %w", err)
	}
	return domains, nil
}

// GetVerifiedDomainsForTenant returns only verified domains for a tenant
func (tdr *WorkspaceDomainsRepository) GetVerifiedDomainsForTenant(workspaceID uuid.UUID) ([]string, error) {
	return tdr.VerifiedDomains(WithWorkspace(context.Background(), workspaceID))
}

// RecordVerification records a verification attempt on a domain of ctx's
// workspace.
func (tdr *WorkspaceDomainsRepository) RecordVerification(ctx context.Context, id uuid.UUID, isVerified bool, failureReason *string) error {
	result, err := tenancy.ExecContext(ctx, tdr.db.DB, `
		UPDATE workspace_domains
		SET is_verified = $2, last_checked_at = $3, failure_reason = $4, updated_at = $3
		WHERE workspace_id = $1 AND id = $5
	`, isVerified, time.Now(), failureReason, id)
	if err != nil {
		return fmt.Errorf("failed to update verification status: %w", err)
	}
	if affected(result) == 0 {
		return errDomainNotFound
	}
	return nil
}

// UpdateVerificationStatus updates verification attempt details. Callers
// must check the domain's workspace; new code uses RecordVerification.
func (tdr *WorkspaceDomainsRepository) UpdateVerificationStatus(id uuid.UUID, isVerified bool, failureReason *string) error {
	ctx, err := tdr.domainContext(id)
	if err != nil {
		return err
	}
	return tdr.RecordVerification(ctx, id, isVerified, failureReason)
}

// OwnsVerifiedDomain reports whether hostname is a verified domain of ctx's
// workspace.
func (tdr *WorkspaceDomainsRepository) OwnsVerifiedDomain(ctx context.Context, hostname string) (bool, error) {
	var count int
	err := tenancy.QueryRowContext(ctx, tdr.db.DB,
		"SELECT COUNT(*) FROM workspace_domains WHERE workspace_id = $1 AND domain = $2 AND is_verified = true",
		[]interface{}{normalizeDomain(hostname)}, &count)
	if err != nil {
		return false, fmt.Errorf("failed to check domain ownership: %w", err)
	}
	return count > 0, nil
}

// IsDomainOwnedByTenant checks if a hostname is owned by the tenant and is verified
func (tdr *WorkspaceDomainsRepository) IsDomainOwnedByTenant(workspaceID uuid.UUID, hostname string) (bool, error) {
	return tdr.OwnsVerifiedDomain(WithWorkspace(context.Background(), workspaceID), hostname)
}

// ValidateRedirectURIs validates all redirect URIs for a tenant
func (tdr *WorkspaceDomainsRepository) ValidateRedirectURIs(workspaceID uuid.UUID, redirectURIs []string) ([]string, error) {
	// Special case: allow localhost in development (can be made configurable via env)
	isDev := os.Getenv("ENVIRONMENT") == "development" || os.Getenv("ENVIRONMENT") == ""

	var validatedHosts []string
	var errs []error

	for _, uri := range redirectURIs {
		// Skip empty URIs
		uri = strings.TrimSpace(uri)
		if uri == "" {
			continue
		}

		// Allow localhost in development mode
		if isDev && strings.Contains(uri, "localhost") {
			validatedHosts = append(validatedHosts, uri)
			continue
		}

		// Validate and normalize
		host, err := tdr.NormalizeHostnameAndCheckOwnership(workspaceID, uri)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		validatedHosts = append(validatedHosts, host)
	}

	if len(errs) > 0 {
		return validatedHosts, &RedirectURIValidationError{Errors: errs}
	}

	return validatedHosts, nil
}

// NormalizeHostnameAndCheckOwnership validates a redirect URI hostname and checks tenant ownership
func (tdr *WorkspaceDomainsRepository) NormalizeHostnameAndCheckOwnership(workspaceID uuid.UUID, redirectURI string) (string, error) {
	// Parse redirect URI to extract host
	if !strings.HasPrefix(redirectURI, "http://") && !strings.HasPrefix(redirectURI, "https://") {
		return "", &InvalidRedirectURIError{Message: "invalid redirect URI: must start with http:// or https://"}
	}

	// Simple host extraction
	uriWithoutScheme := redirectURI
	if strings.HasPrefix(redirectURI, "https://") {
		uriWithoutScheme = redirectURI[8:]
	} else if strings.HasPrefix(redirectURI, "http://") {
		uriWithoutScheme = redirectURI[7:]
	}

	// Extract host (before first /, ?, or :)
	host := uriWithoutScheme
	if idx := strings.IndexAny(host, "/?"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		// Only strip port if it's not part of IPv6 address
		if !strings.Contains(host[:idx], "[") {
			host = host[:idx]
		}
	}

	// Reject wildcards and dangerous patterns
	if strings.Contains(host, "*") || strings.Contains(host, "%") {
		return "", &InvalidRedirectURIError{Message: "wildcard hosts not allowed"}
	}

	// Validate hostname format
	if err := validateHostnameFormat(host); err != nil {
		return "", err
	}

	// Check if domain is owned by tenant and is verified
	owned, err := tdr.IsDomainOwnedByTenant(workspaceID, host)
	if err != nil {
		return "", err
	}
	if !owned {
		return "", &DomainOwnershipError{Hostname: host, WorkspaceID: workspaceID}
	}

	return host, nil
}

// validateHostnameFormat performs basic validation on hostname format
func validateHostnameFormat(hostname string) error {
	// Reject if empty
	if hostname == "" {
		return &InvalidRedirectURIError{Message: "empty hostname"}
	}

	// Reject if contains invalid characters (path separators, backslashes, wildcards, spaces)
	if strings.ContainsAny(hostname, "/\\* ") {
		return &InvalidRedirectURIError{Message: "invalid hostname characters"}
	}

	// Validate domain format (basic check: at least one dot, no consecutive dots, reasonable length)
	// This is a minimal check - real validation is done by DNS and DB
	if !strings.Contains(hostname, ".") || len(hostname) < 3 || len(hostname) > 253 {
		return &InvalidRedirectURIError{Message: "invalid hostname format"}
	}

	// Reject IP addresses in production (optional - can be configurable via env)
	isDev := os.Getenv("ENVIRONMENT") == "development" || os.Getenv("ENVIRONMENT") == ""
	if !isDev {
		if ip := net.ParseIP(hostname); ip != nil {
			return &InvalidRedirectURIError{Message: "IP addresses not allowed in redirect URIs"}
		}
	}

	return nil
}

// Custom error types

type InvalidRedirectURIError struct {
	Message string
}

func (e *InvalidRedirectURIError) Error() string {
	return e.Message
}

type DomainOwnershipError struct {
	Hostname    string
	WorkspaceID uuid.UUID
}

func (e *DomainOwnershipError) Error() string {
	return fmt.Sprintf("redirect URI host %s is not owned by tenant %s", e.Hostname, e.WorkspaceID)
}

type RedirectURIValidationError struct {
	Errors []error
}

func (e *RedirectURIValidationError) Error() string {
	var msgs []string
	for _, err := range e.Errors {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}
