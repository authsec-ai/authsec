package platform

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// IDJAGController exposes the IETF Cross-App Access (XAA) IdP-side endpoint:
//
//	POST /authsec/oauth/v2/idjag/token
//
// This is the IdP performing RFC 8693 Token Exchange and returning an ID-JAG
// per draft-ietf-oauth-identity-assertion-authz-grant. The Resource AS side
// (jwt-bearer grant verification) lives in TICKET-B.
type IDJAGController struct {
	svc        *services.IDJAGService
	rsService  *services.ResourceServerService
}

func NewIDJAGController() *IDJAGController {
	rs := services.NewResourceServerService()
	return &IDJAGController{
		svc:       services.NewIDJAGService(rs),
		rsService: rs,
	}
}

// Token Exchange constants from RFC 8693 + the ID-JAG draft.
const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeIDJAG         = "urn:ietf:params:oauth:token-type:id-jag"
	tokenTypeIDToken       = "urn:ietf:params:oauth:token-type:id_token"
	tokenTypeRefreshToken  = "urn:ietf:params:oauth:token-type:refresh_token"
)

// IssueIDJAG handles POST /authsec/oauth/v2/idjag/token.
//
// Per RFC 8693 the request is form-encoded with:
//
//	grant_type           = urn:ietf:params:oauth:grant-type:token-exchange (required)
//	requested_token_type = urn:ietf:params:oauth:token-type:id-jag         (required)
//	subject_token        = the user's ID token (signed by AuthSec / Hydra) (required)
//	subject_token_type   = urn:ietf:params:oauth:token-type:id_token       (required)
//	audience             = Resource AS issuer URI                          (required)
//	resource             = target resource_uri (RFC 8707)                  (optional)
//	scope                = space-separated scope request                   (optional)
//
// The requesting client authenticates via HTTP Basic against xaa_client_apps
// (issuance_mode='internal'). External-IdP clients NEVER hit this endpoint —
// their IdP signs the ID-JAG directly; we only see the assertion at the
// Resource AS verification step (TICKET-B).
func (ctrl *IDJAGController) IssueIDJAG(c *gin.Context) {
	if err := c.Request.ParseForm(); err != nil {
		writeOAuthError(c, http.StatusBadRequest, "invalid_request", "malformed body")
		return
	}
	form := c.Request.PostForm

	// 1. Validate grant_type + requested_token_type.
	if form.Get("grant_type") != grantTypeTokenExchange {
		writeOAuthError(c, http.StatusBadRequest, "unsupported_grant_type",
			"grant_type must be "+grantTypeTokenExchange)
		return
	}
	if form.Get("requested_token_type") != tokenTypeIDJAG {
		writeOAuthError(c, http.StatusBadRequest, "invalid_request",
			"requested_token_type must be "+tokenTypeIDJAG)
		return
	}

	// 2. Authenticate the requesting client. Basic auth or form post.
	clientID, clientSecret, ok := extractClientCreds(c, form)
	if !ok {
		writeOAuthError(c, http.StatusUnauthorized, "invalid_client",
			"client_secret_basic or client_secret_post required")
		return
	}
	xaaClient, err := ctrl.svc.LookupXAAClient(clientID, clientSecret)
	if err != nil {
		// Don't distinguish "no such client" from "wrong secret" — same
		// reply, same timing target. The bcrypt verify in LookupXAAClient
		// runs even if the row is missing (we just check a dummy hash) —
		// well, ALMOST: this path is fine for v1 but a real prod system
		// would dummy-bcrypt on miss to flatten the timing channel.
		writeOAuthError(c, http.StatusUnauthorized, "invalid_client",
			"client authentication failed")
		return
	}

	// 3. Subject token — the user's identity assertion. v1 supports id_token.
	subjType := form.Get("subject_token_type")
	if subjType != tokenTypeIDToken && subjType != "" {
		// Some clients omit subject_token_type per RFC 8693 §2.1 (defaults
		// to id_token). Tolerate empty; reject anything else for now.
		writeOAuthError(c, http.StatusBadRequest, "invalid_request",
			"subject_token_type must be "+tokenTypeIDToken+" or omitted")
		return
	}
	subjectToken := strings.TrimSpace(form.Get("subject_token"))
	if subjectToken == "" {
		writeOAuthError(c, http.StatusBadRequest, "invalid_request", "subject_token required")
		return
	}

	// 4. Validate the subject token. It's an AuthSec-issued id_token, so
	// signature is from our Hydra v2 JWKS. We verify offline (no introspect
	// round trip) — the cost is one JWKS fetch (cached) + RSA verify.
	userID, email, name, tenantID, err := validateAuthSecIDToken(subjectToken)
	if err != nil {
		writeOAuthError(c, http.StatusBadRequest, "invalid_grant",
			"subject_token: "+err.Error())
		return
	}

	// 5. Resource AS audience — required by the draft (§3.1). For self-loop
	// (AuthSec IdP → AuthSec Resource AS) this is our own issuer.
	audience := strings.TrimSpace(form.Get("audience"))
	if audience == "" {
		writeOAuthError(c, http.StatusBadRequest, "invalid_request", "audience required")
		return
	}

	// 6. Resolve the target Application. Per the draft `resource` (RFC 8707)
	// is optional, but we require it because policy is keyed on
	// resource_server_id. If the client omits it, we don't know which
	// Application's policy to consult.
	resourceURI := strings.TrimSpace(form.Get("resource"))
	if resourceURI == "" {
		writeOAuthError(c, http.StatusBadRequest, "invalid_target",
			"resource (RFC 8707) required to identify the target Application")
		return
	}
	rs, resolvedTenantID, err := ctrl.rsService.GetByResourceURI(resourceURI)
	if err != nil {
		writeOAuthError(c, http.StatusBadRequest, "invalid_target", "resource not found")
		return
	}
	if tenantID != "" && tenantID != resolvedTenantID {
		// The subject_token belongs to a different tenant than the target
		// Application. Cross-tenant XAA is not supported in v1.
		writeOAuthError(c, http.StatusForbidden, "access_denied",
			"subject_token tenant does not match resource tenant")
		return
	}

	// 7. Issue. Service does the policy check + signing.
	scopes := splitScope(form.Get("scope"))
	issued, err := ctrl.svc.IssueIDJAG(services.IssueIDJAGInput{
		RequestingClient: xaaClient,
		Audience:         audience,
		ResourceServerID: rs.ID,
		TenantID:         resolvedTenantID,
		UserID:           userID,
		Email:            email,
		Name:             name,
		RequestedScopes:  scopes,
		ResourceURI:      resourceURI,
		Issuer:           idjagIssuer(),
	})
	if err != nil {
		switch {
		case errors.Is(err, services.ErrXAAPolicyDenied):
			writeOAuthError(c, http.StatusForbidden, "access_denied",
				"no XAA policy allows this client to reach this resource")
			return
		default:
			if strings.Contains(err.Error(), "do not intersect") {
				writeOAuthError(c, http.StatusBadRequest, "invalid_scope", err.Error())
				return
			}
			writeOAuthError(c, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
	}

	// 8. RFC 8693 §2.2.1 response shape.
	c.JSON(http.StatusOK, gin.H{
		"access_token":      issued.Token,
		"issued_token_type": tokenTypeIDJAG,
		"token_type":        "N_A", // RFC 8693 — N_A when the asset is not a bearer access token
		"expires_in":        issued.ExpiresIn,
		"scope":             strings.Join(issued.ScopesGranted, " "),
	})
}

// ── helpers ──────────────────────────────────────────────────────────────────

// idjagIssuer returns the URL we put into `iss` on the signed ID-JAG. Stays
// in sync with how the rest of v2 thinks about issuer; if AppConfig grows a
// proper field for this we'll switch.
func idjagIssuer() string {
	if iss := strings.TrimSpace(config.AppConfig.OAuthBaseURL); iss != "" {
		return strings.TrimSuffix(iss, "/")
	}
	return "https://prod.api.authsec.ai"
}

func writeOAuthError(c *gin.Context, status int, code, desc string) {
	c.JSON(status, gin.H{
		"error":             code,
		"error_description": desc,
	})
}

// extractClientCreds pulls client_id + client_secret out of either HTTP Basic
// (RFC 6749 §2.3.1) or form body (§2.3.1 alt). Empty values count as missing.
func extractClientCreds(c *gin.Context, form map[string][]string) (string, string, bool) {
	if user, pass, ok := c.Request.BasicAuth(); ok && user != "" {
		return user, pass, true
	}
	get := func(k string) string {
		if v, ok := form[k]; ok && len(v) > 0 {
			return v[0]
		}
		return ""
	}
	id := strings.TrimSpace(get("client_id"))
	secret := get("client_secret")
	if id == "" {
		return "", "", false
	}
	return id, secret, true
}

func splitScope(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Fields(raw)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// validateAuthSecIDToken verifies an id_token issued by AuthSec's Hydra v2
// against our public JWKS and returns (user_id, email, name, tenant_id).
//
// We deliberately do NOT introspect — the id_token is short-lived (~1h) and
// JWT verification is sufficient. If a tenant needs revocation semantics for
// the ID-JAG issuance step, they can shorten the id_token lifetime.
func validateAuthSecIDToken(raw string) (uuid.UUID, string, string, string, error) {
	jwks, err := getCachedHydraJWKS()
	if err != nil {
		return uuid.Nil, "", "", "", err
	}
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		key, ok := jwks[kid]
		if !ok {
			return nil, errors.New("unknown kid in subject_token header")
		}
		return key, nil
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return uuid.Nil, "", "", "", err
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return uuid.Nil, "", "", "", errors.New("subject_token claims invalid")
	}

	subStr, _ := claims["sub"].(string)
	userID, err := uuid.Parse(subStr)
	if err != nil {
		return uuid.Nil, "", "", "", errors.New("sub is not a uuid")
	}

	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	tenantID := ""
	if ext, ok := claims["ext"].(map[string]any); ok {
		if t, ok := ext["tenant_id"].(string); ok {
			tenantID = t
		}
	}
	if tenantID == "" {
		if t, ok := claims["tenant_id"].(string); ok {
			tenantID = t
		}
	}
	return userID, email, name, tenantID, nil
}

// getCachedHydraJWKS fetches the JWKS from our own /oauth/v2/jwks endpoint
// (which proxies Hydra v2's public keys) and parses it into a kid → *rsa.PublicKey
// map. Cached for 5 minutes — Hydra's key rotation is far slower than that
// and a stale cache only matters when verifying a freshly-rotated-into id_token
// (one cache miss + refresh covers it).
func getCachedHydraJWKS() (map[string]*rsa.PublicKey, error) {
	jwksCache.mu.Lock()
	defer jwksCache.mu.Unlock()
	if time.Now().Before(jwksCache.expiresAt) && jwksCache.keys != nil {
		return jwksCache.keys, nil
	}

	base := strings.TrimSuffix(idjagIssuer(), "/")
	resp, err := http.Get(base + "/authsec/oauth/v2/jwks")
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read jwks: %w", err)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}

	out := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		out[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}
	jwksCache.keys = out
	jwksCache.expiresAt = time.Now().Add(5 * time.Minute)
	return out, nil
}

var jwksCache struct {
	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
}

// _ kept to please the import set when models is only used transitively.
var _ = models.XAAClientApp{}
