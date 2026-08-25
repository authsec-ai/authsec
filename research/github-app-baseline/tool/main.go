// Tool captures Task 101 capability-baseline fixtures from a live GitHub
// App. It mirrors — never imports — the token flow used by the product
// (internal/connectoradapters/githubapp.go): sign an RS256 App JWT, exchange
// it at the installation endpoint for a short-lived installation token.
//
// Secrets discipline: the private key, App JWT and installation tokens are
// held in memory only. They are never printed and never written to disk.
// Fixture files contain response bodies (with token-like fields scrubbed) and
// a whitelist of non-secret headers.
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const apiVersion = "2022-11-28"

// env returns a required env var, or exits with a clear message.
func env(name string) string {
	v := os.Getenv(name)
	if v == "" {
		fmt.Fprintf(os.Stderr, "missing required env var %s\n", name)
		os.Exit(2)
	}
	return v
}

// gitHubAppCreds mirrors connectoradapters.GitHubAppCreds.
type gitHubAppCreds struct {
	AppID string
	Key   *rsa.PrivateKey
}

func loadKey(pemPath string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS8 key is not RSA")
		}
		return rsaKey, nil
	}
	return nil, errors.New("unsupported private key format")
}

// signGitHubAppJWT mirrors githubapp.go's signGitHubAppJWT: RS256, iss=App ID,
// iat 30s in the past for clock skew, exp 9m (GitHub max is 10m).
func signGitHubAppJWT(appID string, key *rsa.PrivateKey) (string, error) {
	now := time.Now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadJSON, _ := json.Marshal(struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}{now.Add(-30 * time.Second).Unix(), now.Add(9 * time.Minute).Unix(), appID})
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// api is a minimal GitHub API client that never leaks credentials.
type api struct {
	base  string
	creds gitHubAppCreds
	// installToken is the live installation token for the current command.
	installToken string
}

func newAPI() (*api, error) {
	appID := env("GITHUB_APP_ID")
	keyPath := env("GITHUB_APP_PRIVATE_KEY_PATH")
	key, err := loadKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load app private key: %w", err)
	}
	base := os.Getenv("GITHUB_BASE_URL")
	if base == "" {
		base = "https://api.github.com"
	}
	return &api{base: strings.TrimSuffix(base, "/"), creds: gitHubAppCreds{AppID: appID, Key: key}}, nil
}

// appJWT mints (and does not log) a fresh App JWT.
func (a *api) appJWT() (string, error) {
	return signGitHubAppJWT(a.creds.AppID, a.creds.Key)
}

// mintInstallationToken mirrors githubapp.go's MintGitHubInstallationToken.
func (a *api) mintInstallationToken(ctx context.Context, installationID string) (string, error) {
	jwt, err := a.appJWT()
	if err != nil {
		return "", err
	}
	endpoint := fmt.Sprintf("%s/app/installations/%s/access_tokens", a.base, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("installation-token endpoint %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Token == "" {
		return "", errors.New("parse installation token response")
	}
	return out.Token, nil
}

// call performs one authenticated request. auth is "app" (App JWT) or "install".
// The credential is never logged; only whitelisted headers are returned.
func (a *api) call(ctx context.Context, method, url, auth string) (*http.Response, []byte, error) {
	var token string
	switch auth {
	case "app":
		t, err := a.appJWT()
		if err != nil {
			return nil, nil, err
		}
		token = t
	case "install":
		if a.installToken == "" {
			return nil, nil, errors.New("no installation token available; set GITHUB_APP_INSTALLATION_ID or use an install-scoped command")
		}
		token = a.installToken
	default:
		return nil, nil, fmt.Errorf("unknown auth mode %q", auth)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp, body, err
}

// whitelisted headers only — never Authorization, never Set-Cookie.
var headerAllowlist = []string{
	"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
	"X-RateLimit-Used", "X-RateLimit-Resource",
	"Link", "ETag", "Retry-After", "X-GitHub-Request-Id", "X-GitHub-Api-Version",
}

// secretField matches JSON keys that could carry credential material.
var secretField = regexp.MustCompile(`(?i)^(token|access_token|refresh_token|client_secret|private_key|pem|secret)$`)

// urlTokenParam matches signed ?token= query params (e.g. raw.githubusercontent
// download_url values) that carry short-lived media credentials.
var urlTokenParam = regexp.MustCompile(`([?&])token=[^&"']+`)

// scrub walks decoded JSON and replaces credential-looking values.
func scrub(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			if secretField.MatchString(k) && val != nil {
				t[k] = "<redacted>"
				continue
			}
			if s, ok := val.(string); ok {
				t[k] = urlTokenParam.ReplaceAllString(s, "${1}token=<redacted>")
				continue
			}
			t[k] = scrub(val)
		}
		return t
	case []interface{}:
		for i, val := range t {
			t[i] = scrub(val)
		}
		return t
	default:
		return v
	}
}

// writeFixture persists status+headers (`.http`) and scrubbed body (`.json`)
// under fixtures/<group>/<name>.*. Non-2xx bodies are preserved as evidence.
func writeFixture(group, name string, resp *http.Response, body []byte) (string, string, error) {
	dir := filepath.Join("fixtures", group)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}

	httpPath := filepath.Join(dir, name+".http")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s\n", resp.Proto, resp.Status))
	for _, h := range headerAllowlist {
		if v := resp.Header.Get(h); v != "" {
			sb.WriteString(fmt.Sprintf("%s: %s\n", h, v))
		}
	}
	if err := os.WriteFile(httpPath, []byte(sb.String()), 0o644); err != nil {
		return "", "", err
	}

	var bodyBytes []byte
	if len(body) > 0 {
		var decoded interface{}
		if json.Unmarshal(body, &decoded) == nil {
			scrubbed, _ := json.MarshalIndent(scrub(decoded), "", "  ")
			bodyBytes = scrubbed
		} else {
			bodyBytes = body
		}
	}
	jsonPath := filepath.Join(dir, name+".json")
	if err := os.WriteFile(jsonPath, bodyBytes, 0o644); err != nil {
		return "", "", err
	}
	return httpPath, jsonPath, nil
}

func mustJSON(cmd *flag.FlagSet, group, name, auth string, url string, resp *http.Response, body []byte) {
	h, j, err := writeFixture(group, name, resp, body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write fixture: %v\n", err)
		os.Exit(1)
	}
	rl := resp.Header.Get("X-RateLimit-Remaining")
	fmt.Printf("%s %s -> %s [rate remaining: %s]\n  %s\n  %s\n", cmd.Name(), url, resp.Status, orDash(rl), h, j)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func main() {
	ctx := context.Background()

	sub := flag.NewFlagSet("tool", flag.ExitOnError)
	sub.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: tool <command> [args]

commands:
  app                  GET /app (App JWT auth)
  installations        GET /app/installations (App JWT auth)
  install-meta <id>    GET /app/installations/{id} (App JWT auth)
  repos <id>           GET /installation/repositories?per_page=100 (+ follow Link)
  install <id>         GET /app/installations/{id} + mint token warm-up
  endpoint <auth> <name> <group> <path>   generic GET; auth=app|install
  mint-test <id>       exercise token minting only, print nothing sensitive
  version`)
	}
	sub.Parse(os.Args[1:])
	args := sub.Args()
	if len(args) == 0 {
		sub.Usage()
		os.Exit(2)
	}

	a, err := newAPI()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if id := os.Getenv("GITHUB_APP_INSTALLATION_ID"); id != "" {
		t, err := a.mintInstallationToken(ctx, id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mint installation token: %v\n", err)
			os.Exit(1)
		}
		a.installToken = t // in memory only
	}

	switch args[0] {
	case "app":
		resp, body, err := a.call(ctx, "GET", a.base+"/app", "app")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		mustJSON(sub, "meta", "app", "app", a.base+"/app", resp, body)
	case "installations":
		resp, body, err := a.call(ctx, "GET", a.base+"/app/installations", "app")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		mustJSON(sub, "meta", "installations", "app", a.base+"/app/installations", resp, body)
	case "install-meta":
		if len(args) < 2 {
			sub.Usage()
			os.Exit(2)
		}
		url := a.base + "/app/installations/" + args[1]
		resp, body, err := a.call(ctx, "GET", url, "app")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		mustJSON(sub, "meta", "install-"+args[1], "app", url, resp, body)
	case "repos":
		if len(args) < 2 {
			sub.Usage()
			os.Exit(2)
		}
		page := 1
		url := a.base + "/installation/repositories?per_page=100"
		for {
			resp, body, err := a.call(ctx, "GET", url, "install")
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			mustJSON(sub, "repos", fmt.Sprintf("install-%s-page%d", args[1], page), "install", url, resp, body)
			next := nextLink(resp.Header.Get("Link"))
			if next == "" || page >= 3 {
				break
			}
			url = next
			page++
		}
	case "install":
		if len(args) < 2 {
			sub.Usage()
			os.Exit(2)
		}
		url := a.base + "/app/installations/" + args[1]
		resp, body, err := a.call(ctx, "GET", url, "app")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		mustJSON(sub, "meta", "install-"+args[1], "app", url, resp, body)
		if a.installToken == "" {
			t, err := a.mintInstallationToken(ctx, args[1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "mint: %v\n", err)
				os.Exit(1)
			}
			a.installToken = t
		}
		fmt.Printf("installation token minted in memory (not printed, not stored)\n")
	case "endpoint":
		// tool endpoint <auth> <name> <group> <path>
		if len(args) < 5 {
			sub.Usage()
			os.Exit(2)
		}
		auth, name, group, path := args[1], args[2], args[3], args[4]
		url := a.base + path
		resp, body, err := a.call(ctx, "GET", url, auth)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		mustJSON(sub, group, name, auth, url, resp, body)
	case "mint-test":
		if len(args) < 2 {
			sub.Usage()
			os.Exit(2)
		}
		tok, err := a.mintInstallationToken(ctx, args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		sum := sha256.Sum256([]byte(tok))
		fmt.Printf("mint ok, token length %d, sha256[:12]=%x (never logged)\n", len(tok), sum[:6])
	case "burst":
		// tool burst <auth> <path> <count>
		if len(args) < 4 {
			sub.Usage()
			os.Exit(2)
		}
		auth, path := args[1], args[2]
		count, err := strconv.Atoi(args[3])
		if err != nil || count < 1 || count > 5000 {
			fmt.Fprintln(os.Stderr, "count must be an integer 1..5000")
			os.Exit(2)
		}
		url := a.base + path
		start := time.Now()
		var statuses = map[string]int{}
		for i := 0; i < count; i++ {
			resp, _, err := a.call(ctx, "GET", url, auth)
			if err != nil {
				fmt.Fprintf(os.Stderr, "burst request %d: %v\n", i, err)
				break
			}
			statuses[resp.Status]++
			if i%25 == 0 || resp.StatusCode >= 400 {
				ra := resp.Header.Get("Retry-After")
				fmt.Printf("burst %4d -> %s remaining=%s reset=%s retry-after=%s\n",
					i+1, resp.Status,
					orDash(resp.Header.Get("X-RateLimit-Remaining")),
					orDash(resp.Header.Get("X-RateLimit-Reset")),
					orDash(ra))
			}
		}
		elapsed := time.Since(start)
		fmt.Printf("burst done: %d requests in %s, status histogram: %v\n", count, elapsed.Round(time.Millisecond), statuses)
	case "scan-sim":
		// tool scan-sim <owner> <repo> <branch> — runs the product's per-repo
		// scan sequence (tree -> CODEOWNERS probes -> rule-matched blobs) and
		// records call count + wall clock. No fixtures written; summary only.
		if len(args) < 4 {
			sub.Usage()
			os.Exit(2)
		}
		owner, repo, branch := args[1], args[2], args[3]
		start := time.Now()
		calls := 0
		lat := func(label, path string, status int) {
			calls++
			fmt.Printf("  %-28s %-3d %s\n", label, status, path)
		}
		var entries []struct {
			Path string `json:"path"`
			Type string `json:"type"`
			SHA  string `json:"sha"`
		}
		treeURL := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1", a.base, owner, repo, branch)
		resp, body, err := a.call(ctx, "GET", treeURL, "install")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		lat("tree", treeURL, resp.StatusCode)
		var tree struct {
			Tree []struct {
				Path string `json:"path"`
				Type string `json:"type"`
				SHA  string `json:"sha"`
			} `json:"tree"`
			Truncated bool `json:"truncated"`
		}
		_ = json.Unmarshal(body, &tree)
		entries = tree.Tree

		codeownerPaths := []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}
		for _, p := range codeownerPaths {
			u := fmt.Sprintf("%s/repos/%s/%s/contents/%s?ref=%s", a.base, owner, repo, p, branch)
			r, _, err := a.call(ctx, "GET", u, "install")
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			lat("codeowners", u, r.StatusCode)
			if r.StatusCode < 400 {
				break
			}
		}

		matched := 0
		for _, e := range entries {
			if e.Type != "blob" {
				continue
			}
			if !catalogMatch(e.Path) {
				continue
			}
			u := fmt.Sprintf("%s/repos/%s/%s/git/blobs/%s", a.base, owner, repo, e.SHA)
			r, _, err := a.call(ctx, "GET", u, "install")
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			lat("blob "+e.Path, u, r.StatusCode)
			matched++
		}
		elapsed := time.Since(start)
		fmt.Printf("scan-sim %s/%s: %d calls in %s; %d tree entries, truncated=%v, matched blobs=%d\n",
			owner, repo, calls, elapsed.Round(time.Millisecond), len(entries), tree.Truncated, matched)
	case "exhaust":
		// tool exhaust <path> <count> — drive the installation's core bucket
		// toward zero with unique-URL requests (cache-busting so every call
		// counts), then capture the rate-limit-exceeded response as a fixture.
		if len(args) < 3 {
			sub.Usage()
			os.Exit(2)
		}
		path := args[1]
		count, err := strconv.Atoi(args[2])
		if err != nil || count < 1 || count > 6000 {
			fmt.Fprintln(os.Stderr, "count must be an integer 1..6000")
			os.Exit(2)
		}
		offset := 0
		if len(args) >= 4 {
			offset, err = strconv.Atoi(args[3])
			if err != nil {
				fmt.Fprintln(os.Stderr, "offset must be an integer")
				os.Exit(2)
			}
		}
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		start := time.Now()
		var lastStatus string
		for i := 1; i <= count; i++ {
			u := fmt.Sprintf("%s%s%s_=%d", a.base, path, sep, offset+i)
			resp, body, err := a.call(ctx, "GET", u, "install")
			if err != nil {
				fmt.Fprintf(os.Stderr, "exhaust %d: %v\n", i, err)
				break
			}
			lastStatus = resp.Status
			if i%500 == 0 || resp.StatusCode == 403 || resp.StatusCode == 429 {
				fmt.Printf("exhaust %5d -> %s remaining=%s\n", i, resp.Status,
					orDash(resp.Header.Get("X-RateLimit-Remaining")))
				if resp.StatusCode == 403 || resp.StatusCode == 429 {
					h, j, wErr := writeFixture("failure-modes", "exhausted", resp, body)
					if wErr != nil {
						fmt.Fprintln(os.Stderr, wErr)
					} else {
						fmt.Printf("exhausted fixture: %s %s\n", h, j)
					}
					break
				}
			}
		}
		fmt.Printf("exhaust done: last status %s in %s\n", lastStatus, time.Since(start).Round(time.Second))
	case "revoke-test":
		// tool revoke-test <installation-id> <window-seconds> <path>
		// Mints ONE installation token, holds it in memory, and polls the given
		// path every 5s — so the caller can revoke the installation mid-window
		// and we observe what happens to the in-flight token. Never logs the
		// token itself.
		if len(args) < 4 {
			sub.Usage()
			os.Exit(2)
		}
		instID := args[1]
		window, err := strconv.Atoi(args[2])
		if err != nil || window < 30 || window > 900 {
			fmt.Fprintln(os.Stderr, "window must be an integer 30..900")
			os.Exit(2)
		}
		tok, err := a.mintInstallationToken(ctx, instID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mint: %v\n", err)
			os.Exit(1)
		}
		a.installToken = tok
		url := a.base + args[3]
		fmt.Printf("revoke-test: token minted for installation %s; polling %s every 5s for %ds\n", instID, url, window)
		deadline := time.Now().Add(time.Duration(window) * time.Second)
		for time.Now().Before(deadline) {
			resp, body, err := a.call(ctx, "GET", url, "install")
			ts := time.Now().UTC().Format("15:04:05")
			if err != nil {
				fmt.Printf("%s poll -> error: %v\n", ts, err)
			} else {
				msg := ""
				var e struct {
					Message string `json:"message"`
					Status  string `json:"status"`
				}
				if json.Unmarshal(body, &e) == nil && e.Message != "" {
					msg = " | " + e.Message
				}
				fmt.Printf("%s poll -> %s%s\n", ts, resp.Status, msg)
				if resp.StatusCode >= 400 && strings.Contains(e.Message, "installation") {
					_, j, wErr := writeFixture("failure-modes", "revoked-in-flight", resp, body)
					if wErr == nil {
						fmt.Printf("revoked-in-flight fixture written: %s\n", j)
					}
					return
				}
			}
			time.Sleep(5 * time.Second)
		}
		fmt.Println("revoke-test: window elapsed without observing a change")
	case "version":
		fmt.Println("task101 capture tool (zero-dep mirror of the product adapter)")
	default:
		sub.Usage()
		os.Exit(2)
	}
}

var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func nextLink(link string) string {
	if m := linkNextRe.FindStringSubmatch(link); len(m) == 2 {
		return m[1]
	}
	return ""
}

// catalogMatch mirrors the product's DefaultRuleCatalog allowlist
// (services/iga_provider.go): workflow files, agent json, mcp json,
// and package manifests.
func catalogMatch(path string) bool {
	lower := strings.ToLower(path)
	switch {
	case strings.HasPrefix(lower, ".github/workflows/") && (strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")):
		return true
	case strings.HasSuffix(lower, ".agent.json") || lower == "agent.json" || lower == "agents.json":
		return true
	case lower == ".mcp.json" || lower == "mcp.json" || strings.HasPrefix(lower, ".cursor/mcp.json") || strings.HasPrefix(lower, ".vscode/mcp.json"):
		return true
	case strings.HasSuffix(lower, "package.json"):
		return true
	}
	return false
}
