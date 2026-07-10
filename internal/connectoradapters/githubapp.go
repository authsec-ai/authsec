package connectoradapters

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GitHub-App installation tokens are minted (not OAuth-refreshed): sign a short
// JWT with the App's private key → exchange it at the installation endpoint for
// a ~1h installation token. This file does that minting + a small per-
// installation cache so repeated actions don't re-mint every call.

// GitHubAppCreds is what the broker resolves for a github_app connection: the
// App's numeric id, its private-key PEM, and the installation id to mint for.
type GitHubAppCreds struct {
	AppID          string
	PrivateKeyPEM  string
	InstallationID string
}

type ghInstallToken struct {
	token   string
	expires time.Time
}

var (
	ghTokenCache   = map[string]ghInstallToken{} // key: appID + ":" + installationID
	ghTokenCacheMu sync.Mutex
)

// MintGitHubInstallationToken returns a valid installation access token for the
// given App + installation, minting a fresh one (and caching it) when the cached
// one is missing or within 5 minutes of expiry. The returned token is what the
// broker injects as the Bearer credential for a github_app connection.
func MintGitHubInstallationToken(ctx context.Context, creds GitHubAppCreds) (string, error) {
	if creds.AppID == "" || creds.PrivateKeyPEM == "" || creds.InstallationID == "" {
		return "", fmt.Errorf("github app credentials incomplete (need app_id, private key, installation id)")
	}
	cacheKey := creds.AppID + ":" + creds.InstallationID

	ghTokenCacheMu.Lock()
	if t, ok := ghTokenCache[cacheKey]; ok && time.Until(t.expires) > 5*time.Minute {
		ghTokenCacheMu.Unlock()
		return t.token, nil
	}
	ghTokenCacheMu.Unlock()

	appJWT, err := signGitHubAppJWT(creds.AppID, creds.PrivateKeyPEM)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", creds.InstallationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("mint installation token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("github installation-token endpoint %d", resp.StatusCode)
	}
	var out struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Token == "" {
		return "", fmt.Errorf("parse installation token response")
	}

	exp := time.Now().Add(55 * time.Minute) // GitHub installation tokens last ~1h
	if out.ExpiresAt != "" {
		if t, e := time.Parse(time.RFC3339, out.ExpiresAt); e == nil {
			exp = t
		}
	}
	ghTokenCacheMu.Lock()
	ghTokenCache[cacheKey] = ghInstallToken{token: out.Token, expires: exp}
	ghTokenCacheMu.Unlock()

	return out.Token, nil
}

// signGitHubAppJWT builds the short-lived App JWT (RS256, iss=App ID) GitHub
// requires to authenticate as the App before minting an installation token.
func signGitHubAppJWT(appID, privateKeyPEM string) (string, error) {
	key, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("parse app private key: %w", err)
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Add(-30 * time.Second).Unix(), // clock-skew allowance
		"exp": now.Add(9 * time.Minute).Unix(),   // GitHub max is 10m
		"iss": appID,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return tok.SignedString(key)
}

func parseRSAPrivateKey(pem string) (*rsa.PrivateKey, error) {
	pem = strings.TrimSpace(pem)
	// golang-jwt handles both PKCS1 and PKCS8 PEM.
	if key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(pem)); err == nil {
		return key, nil
	} else {
		return nil, err
	}
}
