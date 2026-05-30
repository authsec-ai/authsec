package admin

// PurgeController provides a temporary admin endpoint to completely remove a
// registered user and all their associated data from the platform.
//
// What gets purged (in order):
//  1. Vault PKI secrets engine mount for the tenant domain
//  2. Vault KV secrets under the tenant path
//  3. Tenant database (DROP DATABASE)
//  4. Master DB rows: projects, role_bindings, users, workspaces,
//     pending_registrations
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
		Email string `json:"email" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email is required"})
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))

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

	// ── 1. Look up user + workspace ───────────────────────────────────────────
	// Single-DB mode: there is no per-tenant database, so tenantDB is always "".
	// workspaces has columns id / workspace_domain / vault_mount (no tenant_db).
	var userID, tenantID, tenantDB, tenantDomain, vaultMount string
	row := db.Raw(`
		SELECT u.id, u.workspace_id,
		       '' AS tenant_db,
		       COALESCE(t.workspace_domain, ''),
		       COALESCE(t.vault_mount, '')
		FROM users u
		LEFT JOIN workspaces t ON t.id = u.workspace_id
		WHERE LOWER(u.email) = ?
		LIMIT 1`, email).Row()
	if err := row.Scan(&userID, &tenantID, &tenantDB, &tenantDomain, &vaultMount); err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "no user found with that email"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("lookup failed: %v", err)})
		return
	}
	addStep(fmt.Sprintf("found user=%s tenant=%s db=%s", userID, tenantID, tenantDB))

	// ── 2. Disable Vault PKI mount ────────────────────────────────────────────
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

	// ── 3. Drop tenant database ───────────────────────────────────────────────
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

	// ── 4. Purge master DB rows ───────────────────────────────────────────────
	sqlDB, err := db.DB()
	if err != nil {
		addErr(fmt.Sprintf("get raw db: %v", err))
	} else {
		purgeQueries := []struct {
			label string
			query string
		}{
			// Phase A: tenant_mappings + tenants tables deleted (Phase 6).
			// Phase B: clients table deleted — no purge entry needed.
			// Phase C: tenant_hydra_clients table dropped.
			// Phase E: projects table dropped — no purge entry needed.
			{"role_bindings", `DELETE FROM role_bindings WHERE workspace_id = $1`},
			{"users", `DELETE FROM users WHERE workspace_id = $1`},
			{"workspaces", `DELETE FROM workspaces WHERE id = $1`},
		}
		for _, q := range purgeQueries {
			if _, err := sqlDB.Exec(q.query, tenantID); err != nil {
				addErr(fmt.Sprintf("delete %s: %v", q.label, err))
			} else {
				addStep(fmt.Sprintf("deleted %s rows for tenant %s", q.label, tenantID))
			}
		}

		// pending_registrations keyed by email not tenant_id
		if _, err := sqlDB.Exec(`DELETE FROM pending_registrations WHERE LOWER(email) = $1`, email); err != nil {
			addErr(fmt.Sprintf("delete pending_registrations: %v", err))
		} else {
			addStep("deleted pending_registrations")
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
