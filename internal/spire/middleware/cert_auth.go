package middleware

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/utils"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// CABundleSource returns the PEM CA bundle of a workspace's PKI mount
// (the Vault client in production).
type CABundleSource interface {
	GetCABundle(ctx context.Context, mount string) (string, error)
}

// CertAuthConfig configures the certificate authenticator.
type CertAuthConfig struct {
	Workspaces repositories.WorkspaceRepository
	Agents     repositories.AgentRepository
	// CA verifies that a client certificate chains to its workspace's CA.
	// Without it no certificate can be verified, and every request is
	// refused.
	CA CABundleSource
	// TrustForwardedCertHeader accepts the certificate an ingress forwards
	// in ssl-client-cert. Only for deployments whose ingress terminates
	// mTLS and overwrites that header: a certificate is public, so a
	// client-supplied header proves nothing. Off by default
	// (SPIRE_TRUST_CLIENT_CERT_HEADER=true turns it on).
	TrustForwardedCertHeader bool
	// DevBypass lets the mTLS group take its workspace from X-Tenant-ID
	// without a certificate. Development only (SPIRE_DEV_MTLS_BYPASS=true
	// with ENVIRONMENT development/dev and no TLS_SERVER_CERT_PATH).
	DevBypass bool
	Logger    *logrus.Entry
}

// CertAuthenticator authenticates agents and workloads by their X.509 SVID.
// The workspace comes only from the verified certificate: its SPIFFE ID's
// trust domain must name an active workspace and the certificate must chain
// to that workspace's CA. X-Tenant-ID, query and body workspace values are
// never read (except by the development bypass).
type CertAuthenticator struct {
	cfg CertAuthConfig

	mu      sync.Mutex
	bundles map[string]cachedBundle
}

type cachedBundle struct {
	pool    *x509.CertPool
	expires time.Time
}

const caBundleTTL = 5 * time.Minute

// NewCertAuthenticator creates the authenticator.
func NewCertAuthenticator(cfg CertAuthConfig) *CertAuthenticator {
	if cfg.Logger == nil {
		cfg.Logger = logrus.NewEntry(logrus.StandardLogger())
	}
	return &CertAuthenticator{cfg: cfg, bundles: map[string]cachedBundle{}}
}

// DevBypassFromEnv reports whether the development mTLS bypass is enabled:
// SPIRE_DEV_MTLS_BYPASS=true, ENVIRONMENT development or dev, and no
// TLS_SERVER_CERT_PATH. ENVIRONMENT alone never enables it (AS-076/AS-081).
func DevBypassFromEnv() bool {
	env := os.Getenv("ENVIRONMENT")
	return os.Getenv("SPIRE_DEV_MTLS_BYPASS") == "true" &&
		(env == "development" || env == "dev") &&
		os.Getenv("TLS_SERVER_CERT_PATH") == ""
}

// RequireAgent admits only active agents (spiffe://<workspace>/agent/...)
// registered in the certificate's workspace.
func (a *CertAuthenticator) RequireAgent() gin.HandlerFunc {
	return func(c *gin.Context) { a.authenticate(c, true) }
}

// RequireSVID admits any verified SVID of a workspace (the mTLS group).
func (a *CertAuthenticator) RequireSVID() gin.HandlerFunc {
	return func(c *gin.Context) {
		if a.cfg.DevBypass && c.Request.TLS == nil {
			a.devBypass(c)
			return
		}
		a.authenticate(c, false)
	}
}

func abort(c *gin.Context, status int, code, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"code": code, "message": msg}})
}

func (a *CertAuthenticator) authenticate(c *gin.Context, agentOnly bool) {
	leaf, intermediates, ok := a.clientCertificate(c)
	if !ok {
		abort(c, http.StatusUnauthorized, "UNAUTHORIZED", "Client certificate required")
		return
	}
	spiffeID, err := spiffeIDOf(leaf)
	if err != nil {
		abort(c, http.StatusUnauthorized, "UNAUTHORIZED", "No valid SPIFFE ID in client certificate")
		return
	}
	ctx := c.Request.Context()
	ws, err := a.cfg.Workspaces.GetByTrustDomain(ctx, utils.TrustDomainOf(spiffeID))
	if err != nil {
		abort(c, http.StatusUnauthorized, "UNAUTHORIZED", "Client certificate is not from a known workspace")
		return
	}
	if err := a.verifyChain(ctx, ws, leaf, intermediates); err != nil {
		a.cfg.Logger.WithError(err).WithField("spiffe_id", spiffeID).Warn("client certificate refused")
		abort(c, http.StatusUnauthorized, "UNAUTHORIZED", "Client certificate could not be verified")
		return
	}
	wsID, _ := uuid.Parse(ws.ID)
	isAgent := isAgentSpiffeID(spiffeID)
	kind := "spire_workload"
	if isAgent {
		kind = "spire_agent"
	}
	tc := tenancy.Context{WorkspaceID: wsID, PrincipalKind: kind, Realm: "spire"}
	if agentOnly {
		if !isAgent {
			abort(c, http.StatusForbidden, "FORBIDDEN", "Certificate does not belong to an agent")
			return
		}
		agent, err := a.cfg.Agents.GetBySpiffeID(tenancy.WithContext(ctx, tc), spiffeID)
		if err != nil {
			abort(c, http.StatusUnauthorized, "UNAUTHORIZED", "Agent not found")
			return
		}
		if agent.Status != models.AgentStatusActive {
			abort(c, http.StatusForbidden, "FORBIDDEN", "Agent is not active")
			return
		}
		if id, err := uuid.Parse(agent.ID); err == nil {
			tc.PrincipalID = id
		}
		c.Set(SpireAgentIDKey, agent.ID)
	}
	tenancy.Set(c, tc)
	c.Set(SpireSpiffeIDKey, spiffeID)
	c.Set(SpireIsAgentKey, isAgent)
	c.Set(SpireClientCertKey, leaf)
	c.Next()
}

// clientCertificate returns the presented certificate: the TLS peer
// certificate, or, only when configured, the ingress-forwarded one.
func (a *CertAuthenticator) clientCertificate(c *gin.Context) (*x509.Certificate, []*x509.Certificate, bool) {
	if c.Request.TLS != nil && len(c.Request.TLS.PeerCertificates) > 0 {
		pcs := c.Request.TLS.PeerCertificates
		return pcs[0], pcs[1:], true
	}
	if !a.cfg.TrustForwardedCertHeader {
		return nil, nil, false
	}
	header := c.GetHeader("ssl-client-cert")
	if header == "" {
		return nil, nil, false
	}
	decoded, err := url.QueryUnescape(header)
	if err != nil {
		return nil, nil, false
	}
	var certs []*x509.Certificate
	rest := []byte(decoded)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, cert)
		}
	}
	if len(certs) == 0 {
		return nil, nil, false
	}
	return certs[0], certs[1:], true
}

// verifyChain checks that leaf chains to the workspace's CA, is in its
// validity period, and may be used for client authentication.
func (a *CertAuthenticator) verifyChain(ctx context.Context, ws *models.Tenant, leaf *x509.Certificate, intermediates []*x509.Certificate) error {
	roots, err := a.workspaceRoots(ctx, ws)
	if err != nil {
		return err
	}
	inter := x509.NewCertPool()
	for _, ic := range intermediates {
		inter.AddCert(ic)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

func (a *CertAuthenticator) workspaceRoots(ctx context.Context, ws *models.Tenant) (*x509.CertPool, error) {
	if a.cfg.CA == nil {
		return nil, errNoCA
	}
	if ws.VaultMount == "" {
		return nil, errNoPKI
	}
	a.mu.Lock()
	if b, ok := a.bundles[ws.ID]; ok && time.Now().Before(b.expires) {
		a.mu.Unlock()
		return b.pool, nil
	}
	a.mu.Unlock()
	bundle, err := a.cfg.CA.GetCABundle(ctx, ws.VaultMount)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(bundle)) {
		return nil, errNoPKI
	}
	a.mu.Lock()
	a.bundles[ws.ID] = cachedBundle{pool: pool, expires: time.Now().Add(caBundleTTL)}
	a.mu.Unlock()
	return pool, nil
}

// devBypass is the development-only path: the workspace from X-Tenant-ID,
// which must be an active workspace's id. Never enabled in production.
func (a *CertAuthenticator) devBypass(c *gin.Context) {
	a.cfg.Logger.Warn("DEV MODE: bypassing mTLS authentication (SPIRE_DEV_MTLS_BYPASS)")
	ws, err := a.cfg.Workspaces.GetByID(c.Request.Context(), c.GetHeader("X-Tenant-ID"))
	if err != nil {
		abort(c, http.StatusUnauthorized, "UNAUTHORIZED", "X-Tenant-ID must name an active workspace")
		return
	}
	wsID, _ := uuid.Parse(ws.ID)
	tenancy.Set(c, tenancy.Context{WorkspaceID: wsID, PrincipalKind: "spire_dev", Realm: "spire"})
	c.Set(SpireSpiffeIDKey, "spiffe://"+ws.ID+"/dev/admin")
	c.Set(SpireIsAgentKey, false)
	c.Next()
}

// spiffeIDOf returns the certificate's single, well-formed SPIFFE ID.
func spiffeIDOf(cert *x509.Certificate) (string, error) {
	var found string
	for _, u := range cert.URIs {
		if u.Scheme != "spiffe" {
			continue
		}
		if found != "" {
			return "", errMultipleSpiffeIDs
		}
		found = u.String()
	}
	if found == "" {
		return "", errNoSpiffeID
	}
	if err := utils.ValidateSpiffeID(found); err != nil {
		return "", err
	}
	return found, nil
}

// isAgentSpiffeID reports whether the SPIFFE ID's path starts with /agent/.
func isAgentSpiffeID(spiffeID string) bool {
	rest := strings.TrimPrefix(spiffeID, "spiffe://")
	_, path, _ := strings.Cut(rest, "/")
	return strings.HasPrefix(path, "agent/")
}

type certError string

func (e certError) Error() string { return string(e) }

const (
	errNoCA              = certError("no CA source configured: certificates cannot be verified")
	errNoPKI             = certError("workspace PKI is not provisioned")
	errNoSpiffeID        = certError("no SPIFFE ID in certificate")
	errMultipleSpiffeIDs = certError("more than one SPIFFE ID in certificate")
)
