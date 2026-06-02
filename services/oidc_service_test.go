package services

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/authsec-ai/authsec/models"
	"github.com/stretchr/testify/require"
)

func TestOIDCProviderRedirectURIUsedForAuthorizationAndTokenExchange(t *testing.T) {
	const callbackURL = "https://tenant.example.com/authsec/uflow/oidc/callback"

	var tokenForm url.Values
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		tokenForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-token","token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()

	svc := &OIDCService{httpClient: tokenServer.Client()}
	provider := &models.OIDCProvider{
		ProviderName:     "google",
		ClientID:         "client-id",
		AuthorizationURL: "https://accounts.example.com/authorize",
		TokenURL:         tokenServer.URL,
		Scopes:           "openid email profile",
		RedirectURI:      callbackURL,
	}

	authURL, err := svc.buildAuthorizationURL(provider, "state", "challenge", svc.resolveCallbackURL(provider))
	require.NoError(t, err)
	parsedAuthURL, err := url.Parse(authURL)
	require.NoError(t, err)
	require.Equal(t, callbackURL, parsedAuthURL.Query().Get("redirect_uri"))

	_, err = svc.exchangeCodeForTokens(provider, "code", "verifier", "client-secret")
	require.NoError(t, err)
	require.Equal(t, callbackURL, tokenForm.Get("redirect_uri"))
}
