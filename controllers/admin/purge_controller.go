package admin

// PurgeController provides a temporary admin endpoint to completely remove a
// registered user and all their associated data from the platform.
//
// What gets purged (in order):
//  1. DCR (mcp_oauth_clients) v2-Hydra clients — collected from the tenant DB's
//     resource_server_client_registrations BEFORE the DB is dropped
//  2. Hydra OAuth clients linked to the tenant (via tenant_hydra_clients), on
//     both the legacy and v2 Hydra
//  3. Vault PKI secrets engine mount for the tenant domain
//  4. Vault KV secrets under the tenant path
//  5. Tenant database (DROP DATABASE) — takes all tenant-DB tables with it
//     (auth_request_context, credentials/passkeys, tenant_totp_secrets,
//     oidc_states, resource_servers, oauth_consent_grants, …)
//  6. Master DB rows: tenant_hydra_clients, tenant_mappings, clients, projects,
//     role_bindings, resource_server_tenant_index, saml_requests,
//     saml_callback_states, device_codes, mcp_oauth_clients, users, tenants,
//     pending_registrations. (FK-CASCADE master tables — saml_sp_certificates,
//     risk_policies, agent_guard_settings, agent_action_requests — are removed
//     automatically when the tenants row is deleted.)
//
// This endpoint is intentionally unauthenticated in routes.go and must be
// removed or gated behind a proper permission before going to production.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/gin-gonic/gin"
)

type PurgeController struct{}

func NewPurgeController() *PurgeController { return &PurgeController{} }

// PurgeUserByEmail DELETE /authsec/admin/purge/user
// Body: { "email": "user@example.com" }
func (pc *PurgeController) PurgeUserByEmail(c *gin.Context) {
	var req struct {
		Email       string `json:"email"`
		TenantID    string `json:"tenant_id"`
		ResourceURI string `json:"resource_uri"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	tenantID := strings.TrimSpace(req.TenantID)
	resourceURI := strings.TrimSpace(req.ResourceURI)
	if email == "" && tenantID == "" && resourceURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provide one of: email, tenant_id, resource_uri"})
		return
	}

	cfg := config.GetConfig()
	db := config.DB

	report := gin.H{
		"email":   email,
		"steps":   []string{},
		"errors":  []string{},
		"success": false,
	}
	steps := []string{}
	errs := []string{}

	addStep := func(s string) { steps = append(steps, s); log.Printf("[purge] %s", s) }
	addErr := func(s string) { errs = append(errs, s); log.Printf("[purge] ERROR: %s", s) }

	// ── 1. Resolve the tenant ─────────────────────────────────────────────────
	// Tolerant of a tenant that a previous purge already half-removed: we only
	// need a tenant_id to clean its master rows. Resolution order honours
	// whichever identifier was supplied: tenant_id > resource_uri > email.
	var userID, tenantDB, tenantDomain, vaultMount string

	if tenantID == "" && resourceURI != "" {
		// resource_server_tenant_index is the master source-of-truth for a
		// resource_uri → tenant mapping, and survives a tenant-DB drop.
		_ = db.Raw(`SELECT tenant_id::text FROM resource_server_tenant_index WHERE resource_uri = ? LIMIT 1`,
			resourceURI).Row().Scan(&tenantID)
	}
	if tenantID == "" && email != "" {
		_ = db.Raw(`SELECT COALESCE(u.id::text,''), COALESCE(u.tenant_id::text,'') FROM users u WHERE LOWER(u.email) = ? LIMIT 1`,
			email).Row().Scan(&userID, &tenantID)
	}
	if strings.TrimSpace(tenantID) == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "could not resolve a tenant from the provided identifier(s); it may already be fully purged"})
		return
	}

	// Tenant row may be absent (already purged) — that's fine; tenantDB stays
	// empty and we skip the DROP, still cleaning every master row by tenant_id.
	_ = db.Raw(`SELECT COALESCE(tenant_db,''), COALESCE(tenant_domain,''), COALESCE(vault_mount,'')
		FROM tenants WHERE tenant_id = ? LIMIT 1`, tenantID).Row().Scan(&tenantDB, &tenantDomain, &vaultMount)

	report["tenant_id"] = tenantID
	addStep(fmt.Sprintf("resolved tenant=%s db=%s (user=%s)", tenantID, tenantDB, userID))

	// v2 Hydra admin URL — DCR clients (and v2-flow clients) live on the v2
	// Hydra, not the legacy one the original purge used.
	v2Admin := cfg.HydraV2AdminURL
	if v2Admin == "" {
		v2Admin = cfg.HydraAdminURL
	}

	// ── 1b. Collect DCR clients registered to this tenant's Applications ──────
	// mcp_oauth_clients lives in the MASTER DB and has no tenant_id; it's linked
	// to the tenant only via the tenant DB's resource_server_client_registrations.
	// So we must read the client_ids BEFORE the tenant database is dropped.
	var dcrClientIDs []string
	if tenantDB != "" {
		tdsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
			cfg.DBHost, cfg.DBUser, cfg.DBPassword, tenantDB, cfg.DBPort)
		if tconn, terr := sql.Open("postgres", tdsn); terr == nil {
			if rows, qerr := tconn.Query(`SELECT DISTINCT client_id FROM resource_server_client_registrations`); qerr == nil {
				for rows.Next() {
					var cid string
					if rows.Scan(&cid) == nil && cid != "" {
						dcrClientIDs = append(dcrClientIDs, cid)
					}
				}
				rows.Close()
			}
			tconn.Close()
		}
		addStep(fmt.Sprintf("found %d DCR client(s) for tenant", len(dcrClientIDs)))
	}

	// Delete each DCR client's Hydra client on the v2 Hydra (the master
	// mcp_oauth_clients rows themselves are removed in the master-purge step).
	for _, cid := range dcrClientIDs {
		var hcid string
		_ = db.Raw(`SELECT hydra_client_id FROM mcp_oauth_clients WHERE client_id = ?`, cid).Row().Scan(&hcid)
		if hcid == "" {
			continue
		}
		if err := purgeHTTPDelete(fmt.Sprintf("%s/admin/clients/%s", v2Admin, hcid)); err != nil {
			addErr(fmt.Sprintf("v2 hydra delete dcr %s: %v", hcid, err))
		} else {
			addStep(fmt.Sprintf("deleted v2 hydra client %s (dcr)", hcid))
		}
	}

	// ── 2. Delete Hydra clients ───────────────────────────────────────────────
	type hydraRow struct {
		HydraClientID string
	}
	var hydraClients []hydraRow
	db.Raw(`SELECT hydra_client_id FROM tenant_hydra_clients WHERE tenant_id = ?`, tenantID).Scan(&hydraClients)
	for _, hc := range hydraClients {
		url := fmt.Sprintf("%s/admin/clients/%s", cfg.HydraAdminURL, hc.HydraClientID)
		if err := purgeHTTPDelete(url); err != nil {
			addErr(fmt.Sprintf("hydra delete %s: %v", hc.HydraClientID, err))
		} else {
			addStep(fmt.Sprintf("deleted hydra client %s", hc.HydraClientID))
		}
		// Also remove it from the v2 Hydra (harmless 404 on single-Hydra setups).
		if v2Admin != cfg.HydraAdminURL {
			if err := purgeHTTPDelete(fmt.Sprintf("%s/admin/clients/%s", v2Admin, hc.HydraClientID)); err != nil {
				addErr(fmt.Sprintf("v2 hydra delete %s: %v", hc.HydraClientID, err))
			}
		}
	}

	// ── 3. Disable Vault PKI mount ────────────────────────────────────────────
	if vaultMount != "" {
		if err := purgeVaultDisableMount(cfg.VaultAddr, cfg.VaultToken, vaultMount); err != nil {
			addErr(fmt.Sprintf("vault disable mount %s: %v", vaultMount, err))
		} else {
			addStep(fmt.Sprintf("disabled vault PKI mount %s", vaultMount))
		}
	}

	// ── 4. Delete Vault KV secrets for tenant ────────────────────────────────
	kvPath := fmt.Sprintf("kv/metadata/secret/%s", tenantID)
	if err := purgeVaultDeleteKV(cfg.VaultAddr, cfg.VaultToken, kvPath); err != nil {
		addErr(fmt.Sprintf("vault kv delete %s: %v", kvPath, err))
	} else {
		addStep(fmt.Sprintf("deleted vault KV path %s", kvPath))
	}

	// ── 5. Drop tenant database ───────────────────────────────────────────────
	if tenantDB != "" {
		adminDSN := fmt.Sprintf("host=%s user=%s password=%s dbname=postgres port=%s sslmode=disable",
			cfg.DBHost, cfg.DBUser, cfg.DBPassword, cfg.DBPort)
		adminConn, err := sql.Open("postgres", adminDSN)
		if err != nil {
			addErr(fmt.Sprintf("connect to postgres for DROP: %v", err))
		} else {
			defer adminConn.Close()
			// Terminate active connections first
			_, _ = adminConn.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, tenantDB)
			if _, err := adminConn.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS "%s"`, tenantDB)); err != nil {
				addErr(fmt.Sprintf("drop database %s: %v", tenantDB, err))
			} else {
				addStep(fmt.Sprintf("dropped database %s", tenantDB))
			}
		}
	}

	// ── 6. Purge master DB rows ───────────────────────────────────────────────
	sqlDB, err := db.DB()
	if err != nil {
		addErr(fmt.Sprintf("get raw db: %v", err))
	} else {
		purgeQueries := []struct {
			label string
			query string
		}{
			{"tenant_hydra_clients", `DELETE FROM tenant_hydra_clients WHERE tenant_id = $1`},
			{"tenant_mappings", `DELETE FROM tenant_mappings WHERE tenant_id = $1`},
			{"clients", `DELETE FROM clients WHERE tenant_id = $1`},
			{"projects", `DELETE FROM projects WHERE tenant_id = $1`},
			{"role_bindings", `DELETE FROM role_bindings WHERE tenant_id = $1`},
			// OAuth-v2 / MCP / SAML / device-flow master tables that are NOT
			// cleaned up by the tenants FK CASCADE (no FK, or FK dropped).
			// tenant_id is UUID in these, so cast the param.
			{"resource_server_tenant_index", `DELETE FROM resource_server_tenant_index WHERE tenant_id = $1::uuid`},
			{"saml_requests", `DELETE FROM saml_requests WHERE tenant_id = $1::uuid`},
			{"saml_callback_states", `DELETE FROM saml_callback_states WHERE tenant_id = $1::uuid`},
			{"device_codes", `DELETE FROM device_codes WHERE tenant_id = $1::uuid`},
			{"users", `DELETE FROM users WHERE tenant_id = $1`},
			{"tenants", `DELETE FROM tenants WHERE tenant_id = $1`},
		}
		for _, q := range purgeQueries {
			if _, err := sqlDB.Exec(q.query, tenantID); err != nil {
				addErr(fmt.Sprintf("delete %s: %v", q.label, err))
			} else {
				addStep(fmt.Sprintf("deleted %s rows for tenant %s", q.label, tenantID))
			}
		}

		// DCR clients: master mcp_oauth_clients rows (collected before the tenant
		// DB was dropped; the table has no tenant_id of its own).
		for _, cid := range dcrClientIDs {
			if _, err := sqlDB.Exec(`DELETE FROM mcp_oauth_clients WHERE client_id = $1`, cid); err != nil {
				addErr(fmt.Sprintf("delete mcp_oauth_clients %s: %v", cid, err))
			} else {
				addStep(fmt.Sprintf("deleted mcp_oauth_clients %s", cid))
			}
		}

		// pending_registrations: clean by tenant (it carries tenant_id) and, when
		// we were given an email, by email too.
		if _, err := sqlDB.Exec(`DELETE FROM pending_registrations WHERE tenant_id = $1::uuid`, tenantID); err != nil {
			addErr(fmt.Sprintf("delete pending_registrations by tenant: %v", err))
		} else {
			addStep("deleted pending_registrations (by tenant)")
		}
		if email != "" {
			if _, err := sqlDB.Exec(`DELETE FROM pending_registrations WHERE LOWER(email) = $1`, email); err != nil {
				addErr(fmt.Sprintf("delete pending_registrations by email: %v", err))
			} else {
				addStep("deleted pending_registrations (by email)")
			}
		}
	}

	report["steps"] = steps
	report["errors"] = errs
	report["success"] = len(errs) == 0
	report["purged_at"] = time.Now().UTC()

	status := http.StatusOK
	if len(errs) > 0 && len(steps) <= 1 {
		status = http.StatusInternalServerError
	} else if len(errs) > 0 {
		status = http.StatusPartialContent
	}
	c.JSON(status, report)
}

func purgeHTTPDelete(url string) error {
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
}

func purgeVaultDisableMount(vaultAddr, vaultToken, mount string) error {
	url := fmt.Sprintf("%s/v1/sys/mounts/%s", vaultAddr, mount)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", vaultToken)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("vault status %d: %s", resp.StatusCode, string(body))
}

func purgeVaultDeleteKV(vaultAddr, vaultToken, metadataPath string) error {
	url := fmt.Sprintf("%s/v1/%s", vaultAddr, metadataPath)
	body, _ := json.Marshal(map[string]interface{}{"versions": []int{}})
	req, err := http.NewRequest(http.MethodDelete, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", vaultToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	b, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("vault status %d: %s", resp.StatusCode, string(b))
}
