package services

import "testing"

func TestOAuthASMetadataV1Shape(t *testing.T) {
	svc := &OAuthASService{}

	meta := svc.ASMetadata("https://authsec.example.com")

	grantTypes, ok := meta["grant_types_supported"].([]string)
	if !ok {
		t.Fatalf("grant_types_supported missing or wrong type: %#v", meta["grant_types_supported"])
	}
	if len(grantTypes) != 1 || grantTypes[0] != "authorization_code" {
		t.Fatalf("expected authorization_code-only v1 metadata, got %#v", grantTypes)
	}

	responseModes, ok := meta["response_modes_supported"].([]string)
	if !ok {
		t.Fatalf("response_modes_supported missing or wrong type: %#v", meta["response_modes_supported"])
	}
	if len(responseModes) != 1 || responseModes[0] != "query" {
		t.Fatalf("expected query-only response mode, got %#v", responseModes)
	}
}
