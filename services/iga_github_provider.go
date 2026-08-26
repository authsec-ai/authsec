package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GitHubProvider is the real REST client.
//
// STATUS: the transport — pagination, rate limits, retries, conditional
// requests — is exercised against a local test server and is trustworthy. The
// ENDPOINT SHAPES are written from the published docs and have NOT been
// confirmed against a live tenant, which is exactly what the Stage-0 spike is
// for: which native-agent endpoints exist on which plan, and what their
// payloads actually look like, are recorded there. Until that runs this is
// opt-in (IGA_GITHUB_LIVE=1) and the fixture provider stays the default, so
// nobody mistakes unverified endpoint mapping for verified behaviour.
type GitHubProvider struct {
	// BaseURL allows pointing at a GHES host or a test server.
	BaseURL string
	HTTP    *http.Client
	// TokenFn mints an installation token. Injected so tests need no signing
	// key and so the token never has to live on this struct.
	TokenFn func(ctx context.Context, in ProviderContext) (string, error)
	// APIVersion is pinned: GitHub changes, and an unpinned client changes with
	// it silently.
	APIVersion string
	// MaxRetries bounds backoff so a rate-limited scan pauses rather than
	// hammering or hanging forever.
	MaxRetries int
	// etags caches per-URL validators so an unchanged page costs no quota.
	etags map[string]string
	// lastLink holds the Link header of the most recent response, used by
	// paginate to find the next page.
	lastLink string
}

// NewGitHubProvider builds a provider with sane defaults.
func NewGitHubProvider() *GitHubProvider {
	return &GitHubProvider{
		BaseURL:    "https://api.github.com",
		HTTP:       &http.Client{Timeout: 30 * time.Second},
		APIVersion: "2022-11-28",
		MaxRetries: 4,
		etags:      map[string]string{},
		// Default TokenFn: deliberately inert. It holds no App id and no private
		// key, so it could never mint anything — returning a clear error beats a
		// call that reads as wired and fails at GitHub. Real tokens come from
		// NewGitHubProviderForWorkspaceApp, which resolves the workspace's App.
		TokenFn: func(_ context.Context, _ ProviderContext) (string, error) {
			return "", fmt.Errorf("no GitHub credentials bound: build this provider with NewGitHubProviderForWorkspaceApp")
		},
	}
}

func (g *GitHubProvider) Name() string { return "github" }

var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// rateLimitPause reports how long to wait before retrying, and whether this
// response was a throttle at all.
//
// GitHub signals throttling on BOTH 403 and 429, so checking only 429 silently
// turns a rate limit into a scan failure. Retry-After wins when present;
// otherwise x-ratelimit-reset is used, but only when the remaining count is
// actually zero — a 403 with quota left is a permission problem, not a pause.
func rateLimitPause(resp *http.Response, attempt int) (time.Duration, bool) {
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
		return 0, false
	}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second, true
		}
	}
	remaining := resp.Header.Get("X-RateLimit-Remaining")
	if remaining == "0" {
		if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
			if ts, err := strconv.ParseInt(reset, 10, 64); err == nil {
				if d := time.Until(time.Unix(ts, 0)); d > 0 {
					return d, true
				}
				return time.Second, true
			}
		}
	}
	// A secondary limit may arrive with no headers at all; back off bounded.
	if resp.StatusCode == http.StatusTooManyRequests {
		return time.Duration(math.Pow(2, float64(attempt))) * time.Second, true
	}
	return 0, false
}

// ghError distinguishes the failure modes the coverage model depends on:
// permission denial, absence and throttling must never collapse together.
type ghError struct {
	Status int
	Msg    string
}

func (e *ghError) Error() string { return fmt.Sprintf("github %d: %s", e.Status, e.Msg) }

// IsPermissionDenied reports a 403 that is not a rate limit.
func (e *ghError) IsPermissionDenied() bool { return e.Status == http.StatusForbidden }

// IsAbsent reports a 404 — which alone never proves deletion.
func (e *ghError) IsAbsent() bool { return e.Status == http.StatusNotFound }

// get performs one authenticated request with retries, conditional-request
// support and rate-limit awareness. Returns (body, notModified, error).
func (g *GitHubProvider) get(ctx context.Context, in ProviderContext, url string) ([]byte, bool, error) {
	token, err := g.TokenFn(ctx, in)
	if err != nil {
		return nil, false, fmt.Errorf("mint installation token: %w", err)
	}

	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, false, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", g.APIVersion)
		// Conditional request: an unchanged page returns 304 and costs no quota.
		if tag, ok := g.etags[url]; ok && tag != "" {
			req.Header.Set("If-None-Match", tag)
		}

		resp, err := g.HTTP.Do(req)
		if err != nil {
			if attempt >= g.MaxRetries {
				return nil, false, err
			}
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case <-time.After(time.Duration(math.Pow(2, float64(attempt))) * time.Second):
			}
			continue
		}

		if pause, throttled := rateLimitPause(resp, attempt); throttled {
			resp.Body.Close()
			if attempt >= g.MaxRetries {
				return nil, false, &ghError{Status: resp.StatusCode, Msg: "rate limited; retries exhausted"}
			}
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case <-time.After(pause):
			}
			continue
		}

		if resp.StatusCode == http.StatusNotModified {
			resp.Body.Close()
			return nil, true, nil
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		linkHdr := resp.Header.Get("Link")
		if tag := resp.Header.Get("ETag"); tag != "" {
			g.etags[url] = tag
		}
		resp.Body.Close()
		if readErr != nil {
			return nil, false, readErr
		}

		if resp.StatusCode >= 400 {
			return nil, false, &ghError{Status: resp.StatusCode, Msg: strings.TrimSpace(string(body))}
		}
		// Stash the next link so paginate can find it without re-reading.
		g.lastLink = linkHdr
		return body, false, nil
	}
}

// paginate walks Link-header pages, calling fn per page body.
func (g *GitHubProvider) paginate(ctx context.Context, in ProviderContext, url string, fn func([]byte) error) error {
	seen := 0
	for url != "" {
		body, notModified, err := g.get(ctx, in, url)
		if err != nil {
			return err
		}
		if !notModified {
			if err := fn(body); err != nil {
				return err
			}
		}
		next := ""
		if m := linkNextRe.FindStringSubmatch(g.lastLink); len(m) == 2 {
			next = m[1]
		}
		url = next
		seen++
		// Defensive bound: a provider loop must not spin forever.
		if seen > 1000 {
			return fmt.Errorf("pagination exceeded 1000 pages; aborting")
		}
	}
	return nil
}

/* ----------------------------- capability probe ------------------------- */

// Capabilities probes what this installation may actually see. A class the
// installation cannot read is reported unsupported/not_configured rather than
// being silently enumerated as empty.
func (g *GitHubProvider) Capabilities(ctx context.Context, in ProviderContext) (map[string]string, error) {
	caps := map[string]string{}
	probe := func(class, url string) {
		_, _, err := g.get(ctx, in, g.BaseURL+url)
		switch e := err.(type) {
		case nil:
			caps[class] = models.CoverageComplete
		case *ghError:
			switch {
			case e.IsPermissionDenied():
				caps[class] = models.CoverageNotConfigured
			case e.IsAbsent():
				caps[class] = models.CoverageUnsupported
			default:
				caps[class] = models.CoverageUnknown
			}
		default:
			caps[class] = models.CoverageUnknown
		}
	}
	probe(models.ClassRepository, "/installation/repositories?per_page=1")
	return caps, nil
}

/* -------------------------------- scopes -------------------------------- */

type ghRepo struct {
	ID            int64  `json:"id"`
	NodeID        string `json:"node_id"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
}

func (g *GitHubProvider) ListScopes(ctx context.Context, in ProviderContext) ([]ProviderScope, error) {
	var out []ProviderScope
	err := g.paginate(ctx, in, g.BaseURL+"/installation/repositories?per_page=100", func(b []byte) error {
		var page struct {
			Repositories []ghRepo `json:"repositories"`
		}
		if err := json.Unmarshal(b, &page); err != nil {
			return err
		}
		for _, r := range page.Repositories {
			branch := r.DefaultBranch
			if branch == "" {
				branch = "main"
			}
			// The immutable node id is the recognition key input; full_name is
			// a locator that changes on rename.
			id := r.NodeID
			if id == "" {
				id = strconv.FormatInt(r.ID, 10)
			}
			out = append(out, ProviderScope{
				Kind: "repository", NativeID: id,
				DisplayName: r.FullName, DefaultBranch: branch,
			})
		}
		return nil
	})
	return out, err
}

/* ------------------------------- lane A/C ------------------------------- */

// ListNativeAgents reads the provider's own agent objects. The endpoint is
// plan-dependent and partly preview, so an absence is reported as unsupported
// rather than as "no agents".
func (g *GitHubProvider) ListNativeAgents(ctx context.Context, in ProviderContext, scope ProviderScope) ([]ProviderObject, error) {
	body, notModified, err := g.get(ctx, in,
		fmt.Sprintf("%s/repos/%s/copilot/agents", g.BaseURL, scope.DisplayName))
	if err != nil {
		if e, ok := err.(*ghError); ok && (e.IsAbsent() || e.IsPermissionDenied()) {
			return nil, nil // capability absent; coverage records why
		}
		return nil, err
	}
	if notModified {
		return nil, nil
	}
	var page struct {
		Agents []struct {
			ID          string   `json:"id"`
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Tools       []string `json:"tools"`
		} `json:"agents"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, err
	}
	out := make([]ProviderObject, 0, len(page.Agents))
	for _, a := range page.Agents {
		out = append(out, ProviderObject{
			ObjectType: models.ClassAgentProfile, NativeID: a.ID,
			DisplayName: a.Name,
			// Provider-declared: GitHub's own schema calls this an agent.
			EvidenceMode: models.EvidencePlatformDeclared,
			Payload: map[string]interface{}{
				"name": a.Name, "description": a.Description, "declared_tools": a.Tools,
			},
		})
	}
	return out, nil
}

func (g *GitHubProvider) ListIdentities(ctx context.Context, in ProviderContext, scope ProviderScope) ([]ProviderObject, error) {
	// The installation itself is the identity acting on this repository.
	return []ProviderObject{{
		ObjectType: models.ClassAppInstallation, NativeID: in.InstallationID,
		DisplayName:  "installation " + in.InstallationID,
		EvidenceMode: models.EvidenceIdentityGrant,
		Payload:      map[string]interface{}{"installation_id": in.InstallationID},
	}}, nil
}

// ListGrants reads deploy keys and the installation's repository permissions.
// Rights are recorded in GitHub's own wording; the normalized reading is
// derived separately so a reviewer can see both.
func (g *GitHubProvider) ListGrants(ctx context.Context, in ProviderContext, scope ProviderScope) ([]ProviderGrant, error) {
	var out []ProviderGrant

	body, _, err := g.get(ctx, in, fmt.Sprintf("%s/repos/%s/keys?per_page=100", g.BaseURL, scope.DisplayName))
	if err != nil {
		if e, ok := err.(*ghError); !ok || !(e.IsAbsent() || e.IsPermissionDenied()) {
			return nil, err
		}
	} else {
		var keys []struct {
			ID       int64  `json:"id"`
			Title    string `json:"title"`
			ReadOnly bool   `json:"read_only"`
		}
		if err := json.Unmarshal(body, &keys); err == nil {
			for _, k := range keys {
				right := "write"
				if k.ReadOnly {
					right = "read"
				}
				out = append(out, ProviderGrant{
					SubjectNativeID: strconv.FormatInt(k.ID, 10),
					SubjectKind:     "deploy_key", SubjectName: k.Title,
					GrantKind:      "deploy_key",
					NativeRights:   map[string]string{"contents": right},
					CredentialType: "deploy_key",
					KeyIdentifier:  strconv.FormatInt(k.ID, 10),
				})
			}
		}
	}
	return out, nil
}

// ListCodeowners reads CODEOWNERS from its three documented locations and
// preserves file order, because GitHub applies last-match-wins.
func (g *GitHubProvider) ListCodeowners(ctx context.Context, in ProviderContext, scope ProviderScope) ([]CodeownerRule, error) {
	for _, p := range []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"} {
		body, _, err := g.get(ctx, in,
			fmt.Sprintf("%s/repos/%s/contents/%s?ref=%s", g.BaseURL, scope.DisplayName, p, scope.DefaultBranch))
		if err != nil {
			continue
		}
		var f struct {
			Content  string `json:"content"`
			Encoding string `json:"encoding"`
		}
		if err := json.Unmarshal(body, &f); err != nil {
			continue
		}
		raw := f.Content
		if f.Encoding == "base64" {
			dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(raw, "\n", ""))
			if err != nil {
				continue
			}
			raw = string(dec)
		}
		return ParseCodeowners(raw), nil
	}
	return nil, nil
}

// ParseCodeowners turns a CODEOWNERS file into ordered rules. Order is
// preserved because the LAST matching pattern wins.
func ParseCodeowners(text string) []CodeownerRule {
	var out []CodeownerRule
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		out = append(out, CodeownerRule{Pattern: fields[0], Owners: fields[1:]})
	}
	return out
}

/* -------------------------------- lane B -------------------------------- */

func (g *GitHubProvider) ListSBOM(ctx context.Context, in ProviderContext, scope ProviderScope) ([]ProviderObject, error) {
	body, notModified, err := g.get(ctx, in,
		fmt.Sprintf("%s/repos/%s/dependency-graph/sbom", g.BaseURL, scope.DisplayName))
	if err != nil {
		if e, ok := err.(*ghError); ok && (e.IsAbsent() || e.IsPermissionDenied()) {
			return nil, nil
		}
		return nil, err
	}
	if notModified {
		return nil, nil
	}
	var doc struct {
		SBOM struct {
			Packages []struct {
				Name    string `json:"name"`
				Version string `json:"versionInfo"`
			} `json:"packages"`
		} `json:"sbom"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make([]ProviderObject, 0, len(doc.SBOM.Packages))
	for _, p := range doc.SBOM.Packages {
		out = append(out, ProviderObject{
			ObjectType: models.ClassSBOMComponent, NativeID: p.Name,
			DisplayName: p.Name,
			// A dependency is a supporting signal only, never an agent.
			EvidenceMode: models.EvidenceFrameworkDep,
			Payload:      map[string]interface{}{"package": p.Name, "version": p.Version},
		})
	}
	return out, nil
}

// ListTree lists the default-branch tree in one call and reports truncation
// honestly. A truncated tree must degrade coverage, never shrink the count.
func (g *GitHubProvider) ListTree(ctx context.Context, in ProviderContext, scope ProviderScope) ([]TreeEntry, bool, error) {
	body, notModified, err := g.get(ctx, in,
		fmt.Sprintf("%s/repos/%s/git/trees/%s?recursive=1", g.BaseURL, scope.DisplayName, scope.DefaultBranch))
	if err != nil {
		if e, ok := err.(*ghError); ok && (e.IsAbsent() || e.IsPermissionDenied()) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if notModified {
		return nil, false, nil
	}
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
			SHA  string `json:"sha"`
			Size int64  `json:"size"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(body, &tree); err != nil {
		return nil, false, err
	}
	out := make([]TreeEntry, 0, len(tree.Tree))
	for _, t := range tree.Tree {
		if t.Type != "blob" {
			continue
		}
		out = append(out, TreeEntry{Path: t.Path, SHA: t.SHA, Size: t.Size})
	}
	return out, tree.Truncated, nil
}

func (g *GitHubProvider) FetchBlob(ctx context.Context, in ProviderContext, scope ProviderScope, e TreeEntry) ([]byte, error) {
	body, _, err := g.get(ctx, in,
		fmt.Sprintf("%s/repos/%s/git/blobs/%s", g.BaseURL, scope.DisplayName, e.SHA))
	if err != nil {
		return nil, err
	}
	var blob struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal(body, &blob); err != nil {
		return nil, err
	}
	if blob.Encoding == "base64" {
		return base64.StdEncoding.DecodeString(strings.ReplaceAll(blob.Content, "\n", ""))
	}
	return []byte(blob.Content), nil
}

// NewGitHubProviderForWorkspaceApp builds a live provider whose tokens are
// minted from the workspace's single registered GitHub App.
//
// One App key per workspace, in one place. A GitHub App private key grants
// access across EVERY installation of that App, so a second copy of it would be
// a second thing to leak for no gain — which is why this reuses the existing
// store and MintGitHubAppToken's JWT signing and exchange rather than standing
// up a parallel one.
//
// What it does NOT reuse is the connector as a record of anything. No connector
// row is read or created here: the ConnectorConnection below is a throwaway
// struct literal, built solely because MintGitHubAppToken takes one, and it
// carries nothing but the installation id. Governance lives in
// iga_integrations, which holds verified_at, requested-versus-granted
// permissions, the capability profile and the cross-workspace rebinding guard.
func NewGitHubProviderForWorkspaceApp(db *gorm.DB, vaultClient vault.VaultClient) *GitHubProvider {
	p := NewGitHubProvider()
	oauth := NewConnectorOAuthService(db, vaultClient)
	p.TokenFn = func(ctx context.Context, in ProviderContext) (string, error) {
		if in.WorkspaceID == uuid.Nil {
			return "", fmt.Errorf("workspace required to resolve GitHub App credentials")
		}
		if in.InstallationID == "" {
			return "", fmt.Errorf("integration has no verified installation id")
		}
		// MintGitHubAppToken reads only the installation id off the connection,
		// so this carries it across without inventing a connector row.
		return oauth.MintGitHubAppToken(ctx, in.WorkspaceID, "github",
			&models.ConnectorConnection{ExternalAccountID: in.InstallationID})
	}
	return p
}
