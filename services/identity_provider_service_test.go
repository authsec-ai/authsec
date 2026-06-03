package services

import "testing"

func TestValidateKnownOIDCProviderConfigRejectsMismatchedMicrosoftEndpoints(t *testing.T) {
	err := validateKnownOIDCProviderConfig("microsoft", CreateOIDCIDPRequest{
		AuthorizationURL: "https://github.com/login/oauth/authorize",
		TokenURL:         "https://github.com/login/oauth/access_token",
		UserinfoURL:      "https://api.github.com/user",
		Scopes:           "user:email",
	})
	if err == nil {
		t.Fatal("expected microsoft provider with GitHub endpoints to be rejected")
	}
}

func TestValidateKnownOIDCProviderConfigAcceptsMicrosoftEndpoints(t *testing.T) {
	err := validateKnownOIDCProviderConfig("microsoft", CreateOIDCIDPRequest{
		AuthorizationURL: "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize",
		TokenURL:         "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
		UserinfoURL:      "https://graph.microsoft.com/oidc/userinfo",
		Scopes:           "openid email profile User.Read",
	})
	if err != nil {
		t.Fatalf("expected microsoft provider config to be valid: %v", err)
	}
}

func TestValidateKnownOIDCProviderConfigRejectsMicrosoftCommonEndpoint(t *testing.T) {
	err := validateKnownOIDCProviderConfig("microsoft", CreateOIDCIDPRequest{
		AuthorizationURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:         "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserinfoURL:      "https://graph.microsoft.com/oidc/userinfo",
		Scopes:           "openid email profile User.Read",
	})
	if err == nil {
		t.Fatal("expected microsoft provider using /common to be rejected")
	}
}
