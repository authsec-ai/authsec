package services

import "testing"

func TestOAuthASMetadataOIDCShape(t *testing.T) {
	svc := &OAuthASService{}

	meta := svc.ASMetadata("https://authsec.example.com")

	// grant_types_supported includes both authorization_code and refresh_token
	grantTypes, ok := meta["grant_types_supported"].([]string)
	if !ok {
		t.Fatalf("grant_types_supported missing or wrong type: %#v", meta["grant_types_supported"])
	}
	wantGrants := map[string]bool{"authorization_code": true, "refresh_token": true}
	if len(grantTypes) != len(wantGrants) {
		t.Fatalf("expected %d grant types, got %#v", len(wantGrants), grantTypes)
	}
	for _, gt := range grantTypes {
		if !wantGrants[gt] {
			t.Fatalf("unexpected grant type %q in %#v", gt, grantTypes)
		}
	}

	responseModes, ok := meta["response_modes_supported"].([]string)
	if !ok {
		t.Fatalf("response_modes_supported missing or wrong type: %#v", meta["response_modes_supported"])
	}
	if len(responseModes) != 1 || responseModes[0] != "query" {
		t.Fatalf("expected query-only response mode, got %#v", responseModes)
	}

	// OIDC Discovery fields
	for _, field := range []string{
		"userinfo_endpoint",
		"end_session_endpoint",
		"pushed_authorization_request_endpoint",
		"scopes_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
		"claims_supported",
	} {
		if meta[field] == nil {
			t.Errorf("OIDC metadata field %q missing", field)
		}
	}

	scopes, ok := meta["scopes_supported"].([]string)
	if !ok {
		t.Fatalf("scopes_supported wrong type: %#v", meta["scopes_supported"])
	}
	wantScopes := map[string]bool{"openid": false, "profile": false, "email": false, "offline_access": false}
	for _, s := range scopes {
		if _, exists := wantScopes[s]; exists {
			wantScopes[s] = true
		}
	}
	for s, found := range wantScopes {
		if !found {
			t.Errorf("scopes_supported missing %q", s)
		}
	}
}
