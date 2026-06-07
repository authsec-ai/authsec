package config

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"strings"
)

func resolveUIConfig(publicUIOrigin, publicUIBasePath, legacyReactAppURL string) (string, string, error) {
	publicUIOrigin = strings.TrimSpace(publicUIOrigin)
	publicUIBasePath = strings.TrimSpace(publicUIBasePath)
	legacyReactAppURL = strings.TrimSpace(legacyReactAppURL)

	if publicUIOrigin != "" {
		origin, err := normalizeUIOrigin(publicUIOrigin)
		if err != nil {
			return "", "", err
		}
		basePath, err := normalizeUIBasePath(publicUIBasePath)
		if err != nil {
			return "", "", err
		}
		return origin, basePath, nil
	}

	if publicUIBasePath != "" {
		return "", "", fmt.Errorf("PUBLIC_UI_BASE_PATH requires PUBLIC_UI_ORIGIN to be set")
	}

	if legacyReactAppURL == "" {
		// Fall back to PUBLIC_UI_ORIGIN or BASE_URL rather than a hardcoded domain.
		if origin := os.Getenv("PUBLIC_UI_ORIGIN"); origin != "" {
			legacyReactAppURL = origin
		} else if base := os.Getenv("BASE_URL"); base != "" {
			legacyReactAppURL = base
		} else {
			legacyReactAppURL = "http://localhost:3000"
		}
	}

	parsed, err := url.Parse(legacyReactAppURL)
	if err != nil {
		return "", "", fmt.Errorf("REACT_APP_URL must be an absolute URL: %w", err)
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return "", "", fmt.Errorf("REACT_APP_URL must include scheme and host")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", fmt.Errorf("REACT_APP_URL must not include query or fragment")
	}

	origin, err := normalizeUIOrigin(parsed.Scheme + "://" + parsed.Host)
	if err != nil {
		return "", "", fmt.Errorf("invalid REACT_APP_URL origin: %w", err)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", "", fmt.Errorf("REACT_APP_URL must not include a path; use PUBLIC_UI_ORIGIN + PUBLIC_UI_BASE_PATH instead")
	}
	log.Printf("WARNING: REACT_APP_URL is deprecated; prefer PUBLIC_UI_ORIGIN + PUBLIC_UI_BASE_PATH")
	return origin, "", nil
}

func normalizeUIOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("UI origin is required")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("failed to parse UI origin: %w", err)
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return "", fmt.Errorf("UI origin must be an absolute URL")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("UI origin must use http or https")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("UI origin must not include query or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("UI origin must not include a path; use PUBLIC_UI_BASE_PATH instead")
	}

	return parsed.Scheme + "://" + parsed.Host, nil
}

func normalizeUIBasePath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "/" {
		return "", nil
	}
	if strings.Contains(raw, "?") || strings.Contains(raw, "#") {
		return "", fmt.Errorf("UI base path must not include query or fragment")
	}
	if !strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("UI base path must start with '/'")
	}

	cleaned := path.Clean(raw)
	if cleaned == "." || cleaned == "/" {
		return "", nil
	}
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	return cleaned, nil
}

func joinURLPath(basePath, route string) string {
	basePath = strings.TrimSpace(basePath)
	route = strings.TrimSpace(route)

	if route == "" {
		if basePath == "" {
			return "/"
		}
		return basePath
	}

	if !strings.HasPrefix(route, "/") {
		route = "/" + route
	}
	if basePath == "" {
		return route
	}
	return strings.TrimRight(basePath, "/") + route
}

func BuildUIRouteURLFromRedirectURI(redirectURI, route string, query url.Values) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(redirectURI))
	if err != nil {
		return "", fmt.Errorf("invalid redirect URI: %w", err)
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return "", fmt.Errorf("redirect URI must be absolute")
	}

	basePath, err := deriveUIBasePathFromCallbackPath(parsed.Path)
	if err != nil {
		return "", err
	}

	base := &url.URL{
		Scheme: parsed.Scheme,
		Host:   parsed.Host,
		Path:   joinURLPath(basePath, route),
	}
	base.RawQuery = query.Encode()
	return base.String(), nil
}

func BuildUILoginURLFromRedirectURI(redirectURI, loginChallenge string) (string, error) {
	query := url.Values{}
	query.Set("login_challenge", loginChallenge)
	return BuildUIRouteURLFromRedirectURI(redirectURI, "/oidc/login", query)
}

func deriveUIBasePathFromCallbackPath(callbackPath string) (string, error) {
	callbackPath = strings.TrimSpace(callbackPath)
	if callbackPath == "" {
		return "", fmt.Errorf("redirect URI path is empty")
	}

	prefixes := []string{
		"/authsec/oidc/auth/callback",
		"/oidc/auth/callback",
	}
	for _, prefix := range prefixes {
		if callbackPath == prefix {
			return strings.TrimSuffix(prefix, "/oidc/auth/callback"), nil
		}
		if strings.HasPrefix(callbackPath, prefix+"/") {
			return strings.TrimSuffix(prefix, "/oidc/auth/callback"), nil
		}
	}

	return "", fmt.Errorf("redirect URI path %q does not match a supported UI callback route", callbackPath)
}
