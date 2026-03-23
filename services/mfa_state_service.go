package services

import (
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type MFAMethodSummary struct {
	MethodType string `json:"method_type"`
	IsPrimary  bool   `json:"is_primary"`
	Verified   bool   `json:"verified"`
}

type MFAState struct {
	Methods              []MFAMethodSummary `json:"methods"`
	DefaultMethod        string             `json:"default_method"`
	RequiresRegistration bool               `json:"requires_registration"`
}

func (s MFAState) MethodMaps() []map[string]interface{} {
	methods := make([]map[string]interface{}, 0, len(s.Methods))
	for _, method := range s.Methods {
		methods = append(methods, map[string]interface{}{
			"method_type": method.MethodType,
			"is_primary":  method.IsPrimary,
			"verified":    method.Verified,
		})
	}
	return methods
}

func ResolveMFAState(db *gorm.DB, userID, clientID, tenantID uuid.UUID, requestHost, preferredMethod string) (MFAState, error) {
	state := MFAState{
		Methods: make([]MFAMethodSummary, 0, 2),
	}

	if hasTOTP, isPrimary, err := hasVerifiedTOTPMethod(db, userID, tenantID); err != nil {
		return state, err
	} else if hasTOTP {
		state.Methods = append(state.Methods, MFAMethodSummary{
			MethodType: "totp",
			IsPrimary:  isPrimary,
			Verified:   true,
		})
	}

	hasCurrentWebAuthn, requiresRegistration, err := resolveWebAuthnMethodState(db, userID, clientID, requestHost)
	if err != nil {
		return state, err
	}
	if hasCurrentWebAuthn {
		state.Methods = append(state.Methods, MFAMethodSummary{
			MethodType: "webauthn",
			IsPrimary:  len(state.Methods) == 0,
			Verified:   true,
		})
	} else if requiresRegistration {
		state.RequiresRegistration = true
	}

	state.DefaultMethod = selectDefaultMethod(state.Methods, preferredMethod)
	return state, nil
}

func hasVerifiedTOTPMethod(db *gorm.DB, userID, tenantID uuid.UUID) (bool, bool, error) {
	type totpResult struct {
		Count      int64
		HasPrimary bool
	}

	if db.Migrator().HasTable("tenant_totp_secrets") {
		var result totpResult
		err := db.Raw(`
			SELECT COUNT(*) AS count, COALESCE(bool_or(is_primary), false) AS has_primary
			FROM tenant_totp_secrets
			WHERE user_id = ?
			  AND tenant_id = ?
			  AND is_verified = true
			  AND is_active = true
		`, userID, tenantID).Scan(&result).Error
		return result.Count > 0, result.HasPrimary, err
	}

	var result totpResult
	query := db.Raw(`
		SELECT COUNT(*) AS count, COALESCE(bool_or(is_primary), false) AS has_primary
		FROM totp_secrets
		WHERE user_id = ?
		  AND is_active = true
		  AND (? = '00000000-0000-0000-0000-000000000000'::uuid OR tenant_id = ?)
	`, userID, tenantID, tenantID)
	if !db.Migrator().HasTable("totp_secrets") {
		return false, false, nil
	}
	if err := query.Scan(&result).Error; err != nil {
		return false, false, err
	}
	return result.Count > 0, result.HasPrimary, nil
}

func resolveWebAuthnMethodState(db *gorm.DB, userID, clientID uuid.UUID, requestHost string) (bool, bool, error) {
	if !db.Migrator().HasTable("credentials") {
		return false, false, nil
	}

	host := normalizeRPIDHost(requestHost)
	query := db.Table("credentials").Where(
		"user_id = ? OR client_id = ? OR client_id = ?",
		userID,
		userID,
		coalesceUUID(clientID, userID),
	)

	if host == "" {
		var count int64
		if err := query.Count(&count).Error; err != nil {
			return false, false, err
		}
		return count > 0, false, nil
	}

	var currentCount int64
	if err := query.Where("(rp_id = ? OR rp_id IS NULL)", host).Count(&currentCount).Error; err != nil {
		return false, false, err
	}
	if currentCount > 0 {
		return true, false, nil
	}

	var otherCount int64
	if err := db.Table("credentials").
		Where("user_id = ? OR client_id = ? OR client_id = ?", userID, userID, coalesceUUID(clientID, userID)).
		Where("rp_id IS NOT NULL AND rp_id != ?", host).
		Count(&otherCount).Error; err != nil {
		return false, false, err
	}

	return false, otherCount > 0, nil
}

func selectDefaultMethod(methods []MFAMethodSummary, preferredMethod string) string {
	if preferredMethod != "" {
		for _, method := range methods {
			if method.MethodType == preferredMethod {
				return preferredMethod
			}
		}
	}

	for _, method := range methods {
		if method.IsPrimary {
			return method.MethodType
		}
	}
	if len(methods) == 0 {
		return ""
	}
	return methods[0].MethodType
}

func normalizeRPIDHost(requestHost string) string {
	host := strings.TrimSpace(strings.ToLower(requestHost))
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}

func coalesceUUID(value, fallback uuid.UUID) uuid.UUID {
	if value == uuid.Nil {
		return fallback
	}
	return value
}
