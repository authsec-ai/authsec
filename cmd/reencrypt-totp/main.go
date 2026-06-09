// Command reencrypt-totp re-encrypts every stored TOTP secret under the
// currently-configured TOTP_ENCRYPTION_KEY, retiring two legacy states:
//
//   - plaintext base32 secrets in the service path (totp_secrets,
//     tenant_totp_secrets), which were never encrypted; and
//   - secrets encrypted with the published "dev" fallback key (the
//     mfa_methods.method_data->>'secret_encrypted' handler path, plus any
//     service-path rows already migrated), a consequence of the
//     TOTP_ENCRYPTION_key env-var typo.
//
// It relies on utils.DecryptStringCompat (try the active key, then the legacy
// dev key, else treat as plaintext) to normalise each value to plaintext, then
// re-encrypts with utils.EncryptString (the active key). Every rewrite is
// verified by decrypting the new ciphertext before it is written.
//
// SAFETY:
//   - Dry-run by default. Pass --commit to write.
//   - Idempotent: re-running re-encrypts already-correct rows (new nonce, same
//     plaintext) without harm.
//   - Run against staging first. Requires the same env (DB_* and
//     TOTP_ENCRYPTION_KEY) as the service so the active key matches.
//
// Usage:
//
//	reencrypt-totp            # dry run: report what would change
//	reencrypt-totp --commit   # apply changes
package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/utils"
	_ "github.com/lib/pq"
)

var commit = flag.Bool("commit", false, "apply changes (default: dry-run, no writes)")

func dsn(cfg *config.Config, dbName string) string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, dbName, cfg.DBSSLMode)
}

func main() {
	flag.Parse()
	cfg := config.LoadConfig()

	mode := "DRY-RUN (no writes)"
	if *commit {
		mode = "COMMIT (writing changes)"
	}
	log.Printf("reencrypt-totp starting — mode: %s", mode)

	// ── Master database: totp_secrets (service path) ──
	masterDB, err := sql.Open("postgres", dsn(cfg, cfg.DBName))
	if err != nil {
		log.Fatalf("open master DB: %v", err)
	}
	defer masterDB.Close()
	if err := masterDB.Ping(); err != nil {
		log.Fatalf("ping master DB: %v", err)
	}

	total := 0
	total += reencryptSecretColumn(masterDB, cfg.DBName, "totp_secrets")

	// ── Each tenant database: tenant_totp_secrets, totp_secrets, mfa_methods ──
	tenantDBs, err := listTenantDatabases(masterDB)
	if err != nil {
		log.Fatalf("list tenant databases: %v", err)
	}
	log.Printf("found %d tenant database(s)", len(tenantDBs))

	for _, dbName := range tenantDBs {
		tdb, err := sql.Open("postgres", dsn(cfg, dbName))
		if err != nil {
			log.Printf("[%s] open: %v (skipping)", dbName, err)
			continue
		}
		if err := tdb.Ping(); err != nil {
			log.Printf("[%s] ping: %v (skipping)", dbName, err)
			tdb.Close()
			continue
		}
		total += reencryptSecretColumn(tdb, dbName, "tenant_totp_secrets")
		total += reencryptSecretColumn(tdb, dbName, "totp_secrets")
		total += reencryptMFAMethods(tdb, dbName)
		tdb.Close()
	}

	if *commit {
		log.Printf("reencrypt-totp done — %d secret(s) re-encrypted", total)
	} else {
		log.Printf("reencrypt-totp dry-run done — %d secret(s) WOULD be re-encrypted (re-run with --commit)", total)
	}
}

func listTenantDatabases(masterDB *sql.DB) ([]string, error) {
	rows, err := masterDB.Query(`SELECT tenant_db FROM tenants WHERE tenant_db IS NOT NULL AND tenant_db <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seen := map[string]struct{}{}
	var out []string
	for rows.Next() {
		var db string
		if err := rows.Scan(&db); err != nil {
			return nil, err
		}
		if _, ok := seen[db]; ok {
			continue
		}
		seen[db] = struct{}{}
		out = append(out, db)
	}
	return out, rows.Err()
}

func tableExists(db *sql.DB, table string) bool {
	var reg *string
	if err := db.QueryRow(`SELECT to_regclass($1)`, "public."+table).Scan(&reg); err != nil {
		return false
	}
	return reg != nil
}

// reencryptSecretColumn normalises and re-encrypts the `secret` column of a
// table whose rows are keyed by `id`. Returns the number of rows rewritten.
func reencryptSecretColumn(db *sql.DB, dbName, table string) int {
	if !tableExists(db, table) {
		return 0
	}

	type row struct {
		id     string
		secret string
	}

	rows, err := db.Query(fmt.Sprintf(`SELECT id, secret FROM %s`, table)) // table is a fixed constant, not user input
	if err != nil {
		log.Printf("[%s.%s] query: %v (skipping)", dbName, table, err)
		return 0
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.secret); err != nil {
			log.Printf("[%s.%s] scan: %v", dbName, table, err)
			continue
		}
		if r.secret == "" {
			continue
		}
		pending = append(pending, r)
	}
	rows.Close()

	changed := 0
	for _, r := range pending {
		plain := utils.DecryptStringCompat(r.secret)
		newEnc, err := utils.EncryptString(plain)
		if err != nil {
			log.Printf("[%s.%s] id=%s encrypt: %v (skipping)", dbName, table, r.id, err)
			continue
		}
		// Verify the new ciphertext round-trips before writing.
		if rt, err := utils.DecryptString(newEnc); err != nil || rt != plain {
			log.Printf("[%s.%s] id=%s verify failed (skipping)", dbName, table, r.id)
			continue
		}
		changed++
		if *commit {
			if _, err := db.Exec(fmt.Sprintf(`UPDATE %s SET secret = $1 WHERE id = $2`, table), newEnc, r.id); err != nil {
				log.Printf("[%s.%s] id=%s update: %v", dbName, table, r.id, err)
				changed--
			}
		}
	}
	if changed > 0 {
		verb := "would re-encrypt"
		if *commit {
			verb = "re-encrypted"
		}
		log.Printf("[%s.%s] %s %d secret(s)", dbName, table, verb, changed)
	}
	return changed
}

// reencryptMFAMethods re-encrypts the secret_encrypted field inside the
// mfa_methods.method_data JSONB for TOTP methods (the webauthn handler path).
func reencryptMFAMethods(db *sql.DB, dbName string) int {
	if !tableExists(db, "mfa_methods") {
		return 0
	}

	type row struct {
		clientID   string
		methodType string
		data       []byte
	}

	rows, err := db.Query(`SELECT client_id, method_type, method_data FROM mfa_methods WHERE method_type = 'totp' AND method_data IS NOT NULL`)
	if err != nil {
		log.Printf("[%s.mfa_methods] query: %v (skipping)", dbName, err)
		return 0
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.clientID, &r.methodType, &r.data); err != nil {
			log.Printf("[%s.mfa_methods] scan: %v", dbName, err)
			continue
		}
		pending = append(pending, r)
	}
	rows.Close()

	changed := 0
	for _, r := range pending {
		var m map[string]interface{}
		if err := json.Unmarshal(r.data, &m); err != nil {
			log.Printf("[%s.mfa_methods] client=%s json: %v (skipping)", dbName, r.clientID, err)
			continue
		}
		enc, ok := m["secret_encrypted"].(string)
		if !ok || enc == "" {
			continue
		}
		plain := utils.DecryptStringCompat(enc)
		newEnc, err := utils.EncryptString(plain)
		if err != nil {
			log.Printf("[%s.mfa_methods] client=%s encrypt: %v (skipping)", dbName, r.clientID, err)
			continue
		}
		if rt, err := utils.DecryptString(newEnc); err != nil || rt != plain {
			log.Printf("[%s.mfa_methods] client=%s verify failed (skipping)", dbName, r.clientID)
			continue
		}
		m["secret_encrypted"] = newEnc
		nb, err := json.Marshal(m)
		if err != nil {
			log.Printf("[%s.mfa_methods] client=%s marshal: %v (skipping)", dbName, r.clientID, err)
			continue
		}
		changed++
		if *commit {
			if _, err := db.Exec(`UPDATE mfa_methods SET method_data = $1 WHERE client_id = $2 AND method_type = $3`, nb, r.clientID, r.methodType); err != nil {
				log.Printf("[%s.mfa_methods] client=%s update: %v", dbName, r.clientID, err)
				changed--
			}
		}
	}
	if changed > 0 {
		verb := "would re-encrypt"
		if *commit {
			verb = "re-encrypted"
		}
		log.Printf("[%s.mfa_methods] %s %d TOTP secret(s)", dbName, verb, changed)
	}
	return changed
}
