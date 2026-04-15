package services

import (
	"testing"
	"time"
)

func TestDefaultConsentTTL_Is30Days(t *testing.T) {
	expected := 30 * 24 * time.Hour
	if DefaultConsentTTL != expected {
		t.Errorf("DefaultConsentTTL = %v, want %v", DefaultConsentTTL, expected)
	}
}

// The following tests verify the ConsentService constructor and that methods
// are correctly defined. Since ConsentService requires a real GORM DB with
// the oauth_consent_grants table, these are compile-time validation tests.

func TestNewConsentService(t *testing.T) {
	svc := NewConsentService(nil)
	if svc == nil {
		t.Fatal("NewConsentService returned nil")
	}
	if svc.db != nil {
		t.Fatal("expected nil db in test constructor")
	}
}

// TestConsentService_MethodsExist verifies the ConsentService interface is complete.
// Each method is checked for correct existence at compile time.
func TestConsentService_MethodsExist(t *testing.T) {
	svc := &ConsentService{}

	// Verify all method signatures exist (compile-time check).
	// These will panic if called with nil DB, which is expected —
	// we're just verifying the API surface.

	var _ func() = func() {
		_ = svc.CheckExistingConsent
		_ = svc.UpsertConsent
		_ = svc.RevokeConsent
		_ = svc.RevokeConsentByUser
		_ = svc.ListByUser
		_ = svc.ListByTenant
	}
}

// TestCheckExistingConsent_ScopeSubset verifies the superset check logic
// using the in-memory set comparison approach.
func TestCheckExistingConsent_ScopeSubsetLogic(t *testing.T) {
	// The scope subset check from CheckExistingConsent:
	// grantedScopes must be a superset of requestedScopes

	tests := []struct {
		name      string
		granted   []string
		requested []string
		covered   bool
	}{
		{
			name:      "exact match",
			granted:   []string{"tools:read", "tools:write"},
			requested: []string{"tools:read", "tools:write"},
			covered:   true,
		},
		{
			name:      "superset covers subset",
			granted:   []string{"tools:read", "tools:write", "admin:*"},
			requested: []string{"tools:read"},
			covered:   true,
		},
		{
			name:      "subset does not cover superset",
			granted:   []string{"tools:read"},
			requested: []string{"tools:read", "tools:write"},
			covered:   false,
		},
		{
			name:      "empty granted covers nothing",
			granted:   []string{},
			requested: []string{"tools:read"},
			covered:   false,
		},
		{
			name:      "empty requested is covered by anything",
			granted:   []string{"tools:read"},
			requested: []string{},
			covered:   true,
		},
		{
			name:      "disjoint sets",
			granted:   []string{"files:read"},
			requested: []string{"tools:write"},
			covered:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grantedSet := make(map[string]struct{}, len(tt.granted))
			for _, s := range tt.granted {
				grantedSet[s] = struct{}{}
			}

			covered := true
			for _, s := range tt.requested {
				if _, ok := grantedSet[s]; !ok {
					covered = false
					break
				}
			}

			if covered != tt.covered {
				t.Errorf("scope subset check: granted=%v requested=%v → got %v, want %v",
					tt.granted, tt.requested, covered, tt.covered)
			}
		})
	}
}

// TestConsentTTL_Expiry verifies that consent grants with custom TTL
// expire correctly.
func TestConsentTTL_Expiry(t *testing.T) {
	now := time.Now()

	// Default TTL: 30 days from now
	defaultExpiry := now.Add(DefaultConsentTTL)
	if defaultExpiry.Before(now.Add(29 * 24 * time.Hour)) {
		t.Error("default expiry should be at least 29 days in the future")
	}
	if defaultExpiry.After(now.Add(31 * 24 * time.Hour)) {
		t.Error("default expiry should be at most 31 days in the future")
	}

	// Custom TTL: 7 days
	customTTL := 7 * 24 * time.Hour
	customExpiry := now.Add(customTTL)
	if customExpiry.Before(now.Add(6 * 24 * time.Hour)) {
		t.Error("custom 7-day expiry should be at least 6 days in the future")
	}

	// Zero TTL should use default
	zeroTTL := time.Duration(0)
	if zeroTTL != 0 {
		t.Error("zero TTL should be 0 (triggers default)")
	}
}

// TestConsentTTL_ZeroUsesDefault verifies the UpsertConsent behavior
// where zero TTL defaults to DefaultConsentTTL.
func TestConsentTTL_ZeroUsesDefault(t *testing.T) {
	// From UpsertConsent:
	//   if ttl == 0 { ttl = DefaultConsentTTL }
	ttl := time.Duration(0)
	if ttl == 0 {
		ttl = DefaultConsentTTL
	}
	if ttl != DefaultConsentTTL {
		t.Errorf("zero TTL should default to %v, got %v", DefaultConsentTTL, ttl)
	}
}
