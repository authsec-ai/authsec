package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (ca *testCA) issue(t *testing.T, spiffeID string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(spiffeID)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{u},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

type fakeWorkspaces map[string]*models.Tenant

func (f fakeWorkspaces) GetByID(_ context.Context, id string) (*models.Tenant, error) {
	if w, ok := f[id]; ok {
		return w, nil
	}
	return nil, fmt.Errorf("not found")
}
func (f fakeWorkspaces) GetByDomain(context.Context, string) (*models.Tenant, error) {
	return nil, fmt.Errorf("not found")
}
func (f fakeWorkspaces) GetByTrustDomain(ctx context.Context, td string) (*models.Tenant, error) {
	return f.GetByID(ctx, td)
}
func (f fakeWorkspaces) UpdateVaultMount(context.Context, string, string) error { return nil }

// fakeAgents answers only for the workspace on ctx, like the scoped repository.
type fakeAgents map[string]*models.Agent // key: workspace|spiffe

func (f fakeAgents) GetBySpiffeID(ctx context.Context, spiffeID string) (*models.Agent, error) {
	tc, err := tenancy.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if a, ok := f[tc.WorkspaceID.String()+"|"+spiffeID]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("not found")
}
func (f fakeAgents) Create(context.Context, *models.Agent) error              { return nil }
func (f fakeAgents) GetByID(context.Context, string) (*models.Agent, error)   { return nil, nil }
func (f fakeAgents) GetByNode(context.Context, string) (*models.Agent, error) { return nil, nil }
func (f fakeAgents) Update(context.Context, *models.Agent) error              { return nil }
func (f fakeAgents) List(context.Context) ([]*models.Agent, error)            { return nil, nil }
func (f fakeAgents) UpdateLastSeen(context.Context, string) error             { return nil }

type fakeCA map[string]string // mount -> PEM

func (f fakeCA) GetCABundle(_ context.Context, mount string) (string, error) {
	if p, ok := f[mount]; ok {
		return p, nil
	}
	return "", fmt.Errorf("no CA at %s", mount)
}

type certFixture struct {
	wsA, wsB   string
	caA, caB   *testCA
	auth       *CertAuthenticator
	authHeader *CertAuthenticator
}

func newFixture(t *testing.T) *certFixture {
	gin.SetMode(gin.TestMode)
	f := &certFixture{wsA: uuid.NewString(), wsB: uuid.NewString(), caA: newTestCA(t, "A"), caB: newTestCA(t, "B")}
	ws := fakeWorkspaces{
		f.wsA: {ID: f.wsA, Status: "active", VaultMount: "pki/a"},
		f.wsB: {ID: f.wsB, Status: "active", VaultMount: "pki/b"},
	}
	agents := fakeAgents{
		f.wsA + "|spiffe://" + f.wsA + "/agent/n1": {ID: uuid.NewString(), Status: "active"},
		f.wsB + "|spiffe://" + f.wsB + "/agent/n1": {ID: uuid.NewString(), Status: "active"},
	}
	ca := fakeCA{"pki/a": f.caA.pem, "pki/b": f.caB.pem}
	f.auth = NewCertAuthenticator(CertAuthConfig{Workspaces: ws, Agents: agents, CA: ca})
	f.authHeader = NewCertAuthenticator(CertAuthConfig{Workspaces: ws, Agents: agents, CA: ca, TrustForwardedCertHeader: true})
	return f
}

// serve runs mw and reports the status and the workspace the handler saw.
func serve(mw gin.HandlerFunc, req *http.Request) (int, string) {
	r := gin.New()
	seen := ""
	r.GET("/x", mw, func(c *gin.Context) {
		ws, _ := tenancy.Workspace(c)
		seen = ws.String()
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, seen
}

func withCert(cert *x509.Certificate) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return req
}

func TestCertAuth_WorkspaceComesFromVerifiedCertificateOnly(t *testing.T) {
	f := newFixture(t)
	req := withCert(f.caB.issue(t, "spiffe://"+f.wsB+"/agent/n1"))
	req.Header.Set("X-Tenant-ID", f.wsA)
	code, seen := serve(f.auth.RequireAgent(), req)
	if code != http.StatusOK || seen != f.wsB {
		t.Fatalf("got %d workspace %q, want 200 in B %s (X-Tenant-ID must be ignored)", code, seen, f.wsB)
	}
}

func TestCertAuth_CertificateMustChainToItsWorkspaceCA(t *testing.T) {
	f := newFixture(t)
	// Claims workspace B, signed by A's CA.
	code, _ := serve(f.auth.RequireAgent(), withCert(f.caA.issue(t, "spiffe://"+f.wsB+"/agent/n1")))
	if code != http.StatusUnauthorized {
		t.Fatalf("cross-CA certificate: got %d, want 401", code)
	}
	// Self-signed.
	self := newTestCA(t, "self")
	code, _ = serve(f.auth.RequireSVID(), withCert(self.issue(t, "spiffe://"+f.wsA+"/w")))
	if code != http.StatusUnauthorized {
		t.Fatalf("unknown CA: got %d, want 401", code)
	}
}

func TestCertAuth_NoCertificateIsRefusedWhateverTheHeaders(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-Tenant-ID", f.wsA)
	if code, _ := serve(f.auth.RequireAgent(), req); code != http.StatusUnauthorized {
		t.Fatalf("agent group without certificate: got %d, want 401", code)
	}
	if code, _ := serve(f.auth.RequireSVID(), req); code != http.StatusUnauthorized {
		t.Fatalf("mTLS group without certificate: got %d, want 401", code)
	}
}

func TestCertAuth_ForwardedHeaderOnlyWhenTrusted(t *testing.T) {
	f := newFixture(t)
	cert := f.caA.issue(t, "spiffe://"+f.wsA+"/agent/n1")
	hdr := url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("ssl-client-cert", hdr)
	if code, _ := serve(f.auth.RequireAgent(), req); code != http.StatusUnauthorized {
		t.Fatalf("untrusted forwarded header: got %d, want 401", code)
	}
	if code, seen := serve(f.authHeader.RequireAgent(), req); code != http.StatusOK || seen != f.wsA {
		t.Fatalf("trusted forwarded header: got %d %q", code, seen)
	}
}

func TestCertAuth_AgentMustBeRegisteredInItsWorkspace(t *testing.T) {
	f := newFixture(t)
	code, _ := serve(f.auth.RequireAgent(), withCert(f.caA.issue(t, "spiffe://"+f.wsA+"/agent/unknown")))
	if code != http.StatusUnauthorized {
		t.Fatalf("unregistered agent: got %d, want 401", code)
	}
	code, _ = serve(f.auth.RequireAgent(), withCert(f.caA.issue(t, "spiffe://"+f.wsA+"/ns/default")))
	if code != http.StatusForbidden {
		t.Fatalf("workload certificate on the agent group: got %d, want 403", code)
	}
}

func TestCertAuth_NoCASourceFailsClosed(t *testing.T) {
	f := newFixture(t)
	a := NewCertAuthenticator(CertAuthConfig{Workspaces: f.auth.cfg.Workspaces, Agents: f.auth.cfg.Agents})
	if code, _ := serve(a.RequireSVID(), withCert(f.caA.issue(t, "spiffe://"+f.wsA+"/w"))); code != http.StatusUnauthorized {
		t.Fatalf("without a CA source: got %d, want 401", code)
	}
}
