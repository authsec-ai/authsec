package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	"github.com/authsec-ai/authsec/utils"
)

// RotateLegacyMFACiphertexts re-encrypts, under the configured
// TOTP_ENCRYPTION_KEY, every MFA ciphertext that only the legacy hardcoded key
// opens (AS-020): TOTP seeds and SMS codes inside mfa_methods.method_data and
// the encrypted backup codes. It is idempotent: a value the current key
// already opens is left alone, so it is safe to run at every startup.
func RotateLegacyMFACiphertexts(db *sql.DB) (int, error) {
	// TENANT-EXEMPT: platform key rotation at startup re-encrypts every workspace's MFA ciphertexts
	rows, err := db.Query(`SELECT id, method_data, backup_codes FROM mfa_methods`)
	if err != nil {
		return 0, fmt.Errorf("list mfa_methods: %w", err)
	}
	type row struct {
		id          string
		methodData  sql.NullString
		backupCodes sql.NullString
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.methodData, &r.backupCodes); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan mfa_methods: %w", err)
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	rotated := 0
	for _, r := range all {
		changed := false

		methodData := r.methodData
		if methodData.Valid && methodData.String != "" {
			var doc interface{}
			if err := json.Unmarshal([]byte(methodData.String), &doc); err == nil {
				doc, c, err := reencryptJSON(doc)
				if err != nil {
					return rotated, err
				}
				if c {
					b, _ := json.Marshal(doc)
					methodData.String = string(b)
					changed = true
				}
			}
		}

		backupCodes := r.backupCodes
		if backupCodes.Valid && backupCodes.String != "" {
			var codes []string
			if err := json.Unmarshal([]byte(backupCodes.String), &codes); err == nil {
				c := false
				for i, code := range codes {
					fresh, ok, err := utils.ReencryptLegacy(code)
					if err != nil {
						return rotated, err
					}
					if ok {
						codes[i], c = fresh, true
					}
				}
				if c {
					b, _ := json.Marshal(codes)
					backupCodes.String = string(b)
					changed = true
				}
			}
		}

		if !changed {
			continue
		}
		// TENANT-EXEMPT: the row just read by the platform key rotation, by primary key
		if _, err := db.Exec(`UPDATE mfa_methods SET method_data = $1::jsonb, backup_codes = $2, updated_at = now() WHERE id = $3`,
			methodData, backupCodes, r.id); err != nil {
			return rotated, fmt.Errorf("update mfa_methods %s: %w", r.id, err)
		}
		rotated++
	}
	if rotated > 0 {
		log.Printf("[MFA_KEYS] re-encrypted %d mfa_methods rows from the legacy key", rotated)
	}
	return rotated, nil
}

func reencryptJSON(v interface{}) (interface{}, bool, error) {
	switch t := v.(type) {
	case string:
		fresh, ok, err := utils.ReencryptLegacy(t)
		return fresh, ok, err
	case map[string]interface{}:
		changed := false
		for k, child := range t {
			nv, c, err := reencryptJSON(child)
			if err != nil {
				return v, false, err
			}
			if c {
				t[k], changed = nv, true
			}
		}
		return t, changed, nil
	case []interface{}:
		changed := false
		for i, child := range t {
			nv, c, err := reencryptJSON(child)
			if err != nil {
				return v, false, err
			}
			if c {
				t[i], changed = nv, true
			}
		}
		return t, changed, nil
	}
	return v, false, nil
}
