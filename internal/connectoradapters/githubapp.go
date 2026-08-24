package connectoradapters

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
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
//
// WorkspaceID is required and is part of the cache key. It is not used to talk
// to GitHub — it exists so one tenant's token can never be served to another.
type GitHubAppCreds struct {
	WorkspaceID    string
	AppID          string
	PrivateKeyPEM  string
	InstallationID string
}

type ghInstallToken struct {
	token   string
	expires time.Time
}

var (
	ghTokenCache   = map[string]ghInstallToken{}
	ghTokenCacheMu sync.Mutex
)

// ghCacheKey scopes a cached installation token so that it can only ever be
// returned to the exact caller that earned it.
//
// Both `app_id` and `installation_id` are public values, and both arrive from
// caller-supplied input on some paths (a request body, and an
// X-GitHub-Installation-ID header). Keying on those two alone means a caller
// who names another tenant's app+installation pair receives that tenant's live
// token straight from the cache — before the private key is ever exercised, so
// holding a valid key is not required. Two additions close that:
//
//   - workspace: a token minted for one workspace is unreachable from another.
//   - key fingerprint: a caller presenting a wrong or forged private key lands
//     on a different key entirely, so it cannot hit a legitimate entry and is
//     forced down the minting path, where GitHub rejects the bad signature.
//
// The fingerprint is of the PEM, never logged, and only ever compared.
func ghCacheKey(creds GitHubAppCreds) string {
	sum := sha256.Sum256([]byte(creds.PrivateKeyPEM))
	return strings.Join([]string{
		creds.WorkspaceID,
		creds.AppID,
		creds.InstallationID,
		hex.EncodeToString(sum[:8]),
	}, ":")
}

// evictExpiredLocked drops entries that can no longer be served. Callers hold
// ghTokenCacheMu. Without this the map only ever grows: every workspace ×
// installation pair the process has ever seen stays resident for the life of
// the process.
func evictExpiredLocked(now time.Time) {
	for k, v := range ghTokenCache {
		if !v.expires.After(now) {
			delete(ghTokenCache, k)
		}
	}
}

// MintGitHubInstallationToken returns a valid installation access token for the
// given App + installation, minting a fresh one (and caching it) when the cached
// one is missing or within 5 minutes of expiry. The returned token is what the
// broker injects as the Bearer credential for a github_app connection.
func MintGitHubInstallationToken(ctx context.Context, creds GitHubAppCreds) (string, error) {
	if creds.AppID == "" || creds.PrivateKeyPEM == "" || creds.InstallationID == "" {
		return "", fmt.Errorf("github app credentials incomplete (need app_id, private key, installation id)")
	}
	// Refused rather than defaulted: a blank workspace would collapse every
	// tenant onto one cache key, which is the defect this guards against.
	if creds.WorkspaceID == "" {
		return "", fmt.Errorf("github app credentials incomplete (workspace is required to scope the token cache)")
	}
	cacheKey := ghCacheKey(creds)

	ghTokenCacheMu.Lock()
	if t, ok := ghTokenCache[cacheKey]; ok && time.Until(t.expires) > 5*time.Minute {
		ghTokenCacheMu.Unlock()
		return t.token, nil
	}
	evictExpiredLocked(time.Now())
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
