package services

import "strings"

// OAuthProviderTemplate holds the well-known URLs for a pre-built OAuth provider.
type OAuthProviderTemplate struct {
	AuthorizeURL  string
	TokenURL      string
	DefaultScopes []string
}

var oauthProviderTemplates = map[string]OAuthProviderTemplate{
	"google": {
		AuthorizeURL:  "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:      "https://oauth2.googleapis.com/token",
		DefaultScopes: []string{"openid", "email", "profile"},
	},
	"github": {
		AuthorizeURL:  "https://github.com/login/oauth/authorize",
		TokenURL:      "https://github.com/login/oauth/access_token",
		DefaultScopes: []string{"read:user", "user:email"},
	},
	"slack": {
		AuthorizeURL:  "https://slack.com/oauth/v2/authorize",
		TokenURL:      "https://slack.com/api/oauth.v2.access",
		DefaultScopes: []string{"users:read"},
	},
	"microsoft": {
		AuthorizeURL:  "https://login.microsoftonline.com/{ms_tenant_id}/oauth2/v2.0/authorize",
		TokenURL:      "https://login.microsoftonline.com/{ms_tenant_id}/oauth2/v2.0/token",
		DefaultScopes: []string{"openid", "email", "profile"},
	},
	"linear": {
		AuthorizeURL:  "https://linear.app/oauth/authorize",
		TokenURL:      "https://api.linear.app/oauth/token",
		DefaultScopes: []string{"read"},
	},
	"notion": {
		AuthorizeURL:  "https://api.notion.com/v1/oauth/authorize",
		TokenURL:      "https://api.notion.com/v1/oauth/token",
		DefaultScopes: []string{},
	},
}

// GetOAuthProviderTemplate returns the template for a known provider key.
// Returns (template, true) for known providers; (zero, false) for "custom" or unknown.
func GetOAuthProviderTemplate(provider string) (OAuthProviderTemplate, bool) {
	t, ok := oauthProviderTemplates[provider]
	return t, ok
}

// ApplyMSTenantID substitutes {ms_tenant_id} placeholders in Microsoft OAuth URLs.
func ApplyMSTenantID(authorizeURL, tokenURL, msTenantID string) (string, string) {
	authorizeURL = strings.ReplaceAll(authorizeURL, "{ms_tenant_id}", msTenantID)
	tokenURL = strings.ReplaceAll(tokenURL, "{ms_tenant_id}", msTenantID)
	return authorizeURL, tokenURL
}
