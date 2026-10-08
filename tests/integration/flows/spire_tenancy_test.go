//go:build integration

package flows

// Embedded SPIRE control plane tenancy (AS-081). The routes are mounted on
// a router of their own (ENABLE_EMBEDDED_SPIRE is off in the shared one).
// Vault is not available: tests assert the auth gates, the join-token
// lifecycle and data isolation; where a Vault call is unavoidable they
// assert the request got past authorization (503 "Vault PKI is not
// configured"). Client certificates are verified against test CAs injected
// as the workspaces' CA bundles.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/config"
	platformCtrl "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/spire"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/routes"
)

// ---------------------------------------------------------------- harness

type spireCAs struct {
	mu  sync.Mutex
	pem map[string]string // vault mount -> CA PEM
}

func (s *spireCAs) GetCABundle(_ context.Context, mount string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.pem[mount]; ok {
		return p, nil
	}
	return "", fmt.Errorf("no CA at %s", mount)
}

var (
	spireOnce   sync.Once
	spireRouter *gin.Engine
	spireCAsSrc = &spireCAs{pem: map[string]string{}}
)

func spireEnv(t *testing.T) *gin.Engine {
	t.Helper()
	testsupport.Get(t)
	spireOnce.Do(func() {
		os.Setenv("SPIRE_RECONCILE", "false")
		sqlDB, err := config.DB.DB()
		if err != nil {
			t.Fatalf("sql db: %v", err)
		}
		deps, err := spire.Bootstrap(&spire.BootstrapConfig{MasterDB: sqlDB, CABundles: spireCAsSrc})
		if err != nil {
			t.Fatalf("spire bootstrap: %v", err)
		}
		r := gin.New()
		routes.RegisterEmbeddedSpireRoutes(r.Group("/authsec"), deps)
		// The shared controller would make the admin agent controller's
		// provisioning path think embedded SPIRE is on in other tests.
		platformCtrl.SetSharedSpireController(nil)
		spireRouter = r
	})
	return spireRouter
}

type spireReq struct {
	token   string
	cert    *x509.Certificate
	headers map[string]string
}

func spireDo(t *testing.T, method, path string, body interface{}, o spireReq) *httptest.ResponseRecorder {
	t.Helper()
	r := spireEnv(t)
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if o.token != "" {
		req.Header.Set("Authorization", "Bearer "+o.token)
	}
	// The SPIRE limiters key on X-Forwarded-For; one key per request keeps
	// the tests independent of the budgets.
	req.Header.Set("X-Forwarded-For", "10.9."+fmt.Sprint(time.Now().UnixNano()%250)+"."+fmt.Sprint(time.Now().UnixNano()%250))
	for k, v := range o.headers {
		req.Header.Set(k, v)
	}
	if o.cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{o.cert}}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func wantStatus(t *testing.T, w *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("%s: got %d, want %d (body: %s)", what, w.Code, want, w.Body.String())
	}
}

// pastAuthorization: Vault is not configured in tests, so a request that
// reaches PKI work answers 503 with this message.
func wantVaultUnavailable(t *testing.T, w *httptest.ResponseRecorder, what string) {
	t.Helper()
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "Vault PKI is not configured") {
		t.Fatalf("%s: want the request past authorization (503 Vault unavailable), got %d %s", what, w.Code, w.Body.String())
	}
}

type spireCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// giveWorkspaceCA provisions a test CA as ws's PKI.
func giveWorkspaceCA(t *testing.T, ws uuid.UUID) *spireCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: ws.String()},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	mount := "pki/test-" + ws.String()
	if err := config.DB.Exec(`UPDATE workspaces SET vault_mount = ? WHERE id = ?`, mount, ws).Error; err != nil {
		t.Fatalf("set vault_mount: %v", err)
	}
	spireCAsSrc.mu.Lock()
	spireCAsSrc.pem[mount] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	spireCAsSrc.mu.Unlock()
	return &spireCA{cert: cert, key: key}
}

func (ca *spireCA) issue(t *testing.T, spiffeID string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(spiffeID)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		URIs: []*url.URL{u}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func newCSR(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "node"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func seedSpireAgent(t *testing.T, ws uuid.UUID, node string) string {
	t.Helper()
	spiffeID := "spiffe://" + ws.String() + "/agent/" + node
	if err := config.DB.Exec(`INSERT INTO spire_agents (workspace_id, node_id, spiffe_id, attestation_type, status)
		VALUES (?, ?, ?, 'join_token', 'active')`, ws, node, spiffeID).Error; err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	return spiffeID
}

func seedSpireEntry(t *testing.T, ws uuid.UUID, path, parent string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := config.DB.Exec(`INSERT INTO spire_workload_entries (id, workspace_id, spiffe_id, parent_id, selectors)
		VALUES (?, ?, ?, ?, '{"unix:uid":"1000"}')`, id, ws, "spiffe://"+ws.String()+path, parent).Error; err != nil {
		t.Fatalf("seed entry: %v", err)
	}
	return id
}

// nonAdminToken is a console token of tn's end user: a workspace member
// without the owner/admin role.
func nonAdminToken(t *testing.T, tn *Tenant) string {
	return consoleTokenFor(t, tn.EndUser.UserID, tn.WS.WorkspaceID, tn.EndUser.Email)
}

func mintJoinToken(t *testing.T, tn *Tenant) (id, secret string) {
	t.Helper()
	w := spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/join-tokens", map[string]interface{}{"description": "node"}, spireReq{token: tn.AdminToken})
	wantStatus(t, w, http.StatusCreated, "mint join token")
	var out struct{ ID, Token string }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.ID == "" || out.Token == "" {
		t.Fatalf("mint response lacks id/token: %s", w.Body.String())
	}
	return out.ID, out.Token
}

func nodeAttest(t *testing.T, token, workspace, node string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]interface{}{
		"node_id": node, "attestation_type": "join_token", "evidence": map[string]interface{}{}, "csr": newCSR(t),
	}
	if token != "" {
		body["join_token"] = token
	}
	if workspace != "" {
		body["workspace_id"] = workspace
	}
	return spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/node/attest", body, spireReq{})
}

// ---------------------------------------------------------------- tests

// Join tokens are per workspace: minted by an owner/admin, listed without
// secret or hash, revoked only by their own workspace.
func Test_Spire_JoinTokens_AreWorkspaceScoped(t *testing.T) {
	a, b := TwoTenants(t)
	id, secret := mintJoinToken(t, a)

	sum := sha256.Sum256([]byte(secret))
	if got := columnValue(t, "spire_join_tokens", "token_hash", "id = ?", id); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("stored token_hash %q is not the SHA-256 of the token", got)
	}

	w := spireDo(t, http.MethodGet, "/authsec/spiresvc/v1/join-tokens", nil, spireReq{token: a.AdminToken})
	wantStatus(t, w, http.StatusOK, "list own tokens")
	if !strings.Contains(w.Body.String(), id) || strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), "hash") {
		t.Fatalf("list must show the token without its secret or hash: %s", w.Body.String())
	}
	w = spireDo(t, http.MethodGet, "/authsec/spiresvc/v1/join-tokens", nil, spireReq{token: b.AdminToken})
	wantStatus(t, w, http.StatusOK, "B lists")
	if strings.Contains(w.Body.String(), id) {
		t.Fatalf("B sees A's join token: %s", w.Body.String())
	}

	wantStatus(t, spireDo(t, http.MethodDelete, "/authsec/spiresvc/v1/join-tokens/"+id, nil, spireReq{token: b.AdminToken}),
		http.StatusNotFound, "B revokes A's token")
	assertCount(t, 0, "spire_join_tokens", "id = ? AND revoked_at IS NOT NULL", id)

	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/join-tokens", nil, spireReq{}),
		http.StatusUnauthorized, "mint without a token")
	if w := spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/join-tokens", nil, spireReq{token: nonAdminToken(t, a)}); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin mints a join token: got %d", w.Code)
	}

	wantStatus(t, spireDo(t, http.MethodDelete, "/authsec/spiresvc/v1/join-tokens/"+id, nil, spireReq{token: a.AdminToken}),
		http.StatusOK, "A revokes its own token")
}

// Node attestation needs a valid join token, which decides the workspace.
// Before AS-081 the body's workspace_id decided it, with no credential.
func Test_Spire_NodeAttest_RequiresAJoinToken(t *testing.T) {
	a, b := TwoTenants(t)

	wantStatus(t, nodeAttest(t, "", a.WS.WorkspaceID.String(), "n-none"), http.StatusUnauthorized, "no join token")
	wantStatus(t, nodeAttest(t, "not-a-token", a.WS.WorkspaceID.String(), "n-bad"), http.StatusUnauthorized, "unknown join token")

	id, secret := mintJoinToken(t, a)
	// Naming another workspace is refused and does not burn the token.
	wantStatus(t, nodeAttest(t, secret, b.WS.WorkspaceID.String(), "n1"), http.StatusUnauthorized, "A's token for workspace B")
	assertCount(t, 0, "spire_join_tokens", "id = ? AND used_at IS NOT NULL", id)

	// The right token gets past authorization (then Vault is unavailable)
	// and is consumed by this node.
	wantVaultUnavailable(t, nodeAttest(t, secret, "", "n1"), "A's token")
	assertCount(t, 1, "spire_join_tokens", "id = ? AND used_at IS NOT NULL AND used_by_node_id = 'n1'", id)

	wantStatus(t, nodeAttest(t, secret, "", "n2"), http.StatusUnauthorized, "token reuse")

	// Expired and revoked tokens are refused.
	expID, expSecret := mintJoinToken(t, a)
	if err := config.DB.Exec(`UPDATE spire_join_tokens SET expires_at = now() - interval '1 minute' WHERE id = ?`, expID).Error; err != nil {
		t.Fatal(err)
	}
	wantStatus(t, nodeAttest(t, expSecret, "", "n3"), http.StatusUnauthorized, "expired token")
	revID, revSecret := mintJoinToken(t, a)
	wantStatus(t, spireDo(t, http.MethodDelete, "/authsec/spiresvc/v1/join-tokens/"+revID, nil, spireReq{token: a.AdminToken}), http.StatusOK, "revoke")
	wantStatus(t, nodeAttest(t, revSecret, "", "n4"), http.StatusUnauthorized, "revoked token")
}

// PKI provisioning was anonymous and took the workspace from the body/path.
func Test_Spire_PKIProvision_IsAdminOnlyAndOwnWorkspace(t *testing.T) {
	a, b := TwoTenants(t)
	base := "/authsec/spiresvc/admin/pki/provision"

	wantStatus(t, spireDo(t, http.MethodPost, base, map[string]string{"workspace_id": a.WS.WorkspaceID.String()}, spireReq{}),
		http.StatusUnauthorized, "anonymous provision")
	if w := spireDo(t, http.MethodPost, base, map[string]string{}, spireReq{token: nonAdminToken(t, a)}); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin provision: got %d, want 403 (%s)", w.Code, w.Body.String())
	}
	wantStatus(t, spireDo(t, http.MethodPost, base+"/"+b.WS.WorkspaceID.String(), map[string]string{}, spireReq{token: a.AdminToken}),
		http.StatusNotFound, "A provisions B by path")
	wantStatus(t, spireDo(t, http.MethodPost, base, map[string]string{"workspace_id": b.WS.WorkspaceID.String()}, spireReq{token: a.AdminToken}),
		http.StatusNotFound, "A provisions B by body")
	if b.WS.WorkspaceDomain != "" {
		wantStatus(t, spireDo(t, http.MethodPost, base, map[string]string{"allowed_domains": b.WS.WorkspaceDomain}, spireReq{token: a.AdminToken}),
			http.StatusBadRequest, "A provisions at B's domain mount")
	}
	wantVaultUnavailable(t, spireDo(t, http.MethodPost, base+"/"+a.WS.WorkspaceID.String(), map[string]string{}, spireReq{token: a.AdminToken}), "A provisions A")
}

// Entries and agents through the platform-token group: workspace from the
// token only; another workspace's entry is 404.
func Test_Spire_Entries_AreIsolated(t *testing.T) {
	a, b := TwoTenants(t)
	wsA, wsB := a.WS.WorkspaceID.String(), b.WS.WorkspaceID.String()

	w := spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/entries", map[string]interface{}{
		"spiffe_id": "spiffe://" + wsA + "/ns/web", "selectors": map[string]string{"unix:uid": "1000"},
	}, spireReq{token: a.AdminToken})
	wantStatus(t, w, http.StatusCreated, "A creates an entry")
	var entry struct {
		ID          string `json:"id"`
		WorkspaceID string `json:"workspace_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &entry)
	if entry.WorkspaceID != wsA {
		t.Fatalf("entry workspace %q, want %s", entry.WorkspaceID, wsA)
	}

	path := "/authsec/spiresvc/v1/entries/" + entry.ID
	wantStatus(t, spireDo(t, http.MethodGet, path, nil, spireReq{token: b.AdminToken}), http.StatusNotFound, "B reads A's entry")
	wantStatus(t, spireDo(t, http.MethodPut, path, map[string]interface{}{
		"spiffe_id": "spiffe://" + wsB + "/ns/x", "parent_id": "p", "selectors": map[string]string{"a": "b"},
	}, spireReq{token: b.AdminToken}), http.StatusNotFound, "B updates A's entry")
	wantStatus(t, spireDo(t, http.MethodDelete, path, nil, spireReq{token: b.AdminToken}), http.StatusNotFound, "B deletes A's entry")
	assertCount(t, 1, "spire_workload_entries", "id = ? AND workspace_id = ?", entry.ID, wsA)

	w = spireDo(t, http.MethodGet, "/authsec/spiresvc/v1/entries", nil, spireReq{token: b.AdminToken})
	wantStatus(t, w, http.StatusOK, "B lists")
	if strings.Contains(w.Body.String(), entry.ID) {
		t.Fatalf("B's list shows A's entry")
	}
	wantStatus(t, spireDo(t, http.MethodGet, "/authsec/spiresvc/v1/entries?workspace_id="+wsA, nil, spireReq{token: b.AdminToken}),
		http.StatusNotFound, "B lists with A's workspace_id")
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/entries", map[string]interface{}{
		"workspace_id": wsA, "spiffe_id": "spiffe://" + wsA + "/ns/evil", "selectors": map[string]string{"a": "b"},
	}, spireReq{token: b.AdminToken}), http.StatusNotFound, "B creates in A by body")
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/entries", map[string]interface{}{
		"spiffe_id": "spiffe://" + wsA + "/ns/evil", "selectors": map[string]string{"a": "b"},
	}, spireReq{token: b.AdminToken}), http.StatusBadRequest, "B names A's trust domain")
	if w := spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/entries", map[string]interface{}{
		"spiffe_id": "spiffe://" + wsA + "/ns/eu", "selectors": map[string]string{"a": "b"},
	}, spireReq{token: nonAdminToken(t, a)}); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin creates an entry: got %d, want 403", w.Code)
	}
	wantStatus(t, spireDo(t, http.MethodGet, path, nil, spireReq{token: a.AdminToken}), http.StatusOK, "A reads its entry")

	// Agents.
	agentA := seedSpireAgent(t, a.WS.WorkspaceID, "agents-a")
	agentB := seedSpireAgent(t, b.WS.WorkspaceID, "agents-b")
	w = spireDo(t, http.MethodGet, "/authsec/spiresvc/v1/agents", nil, spireReq{token: a.AdminToken})
	wantStatus(t, w, http.StatusOK, "A lists agents")
	if !strings.Contains(w.Body.String(), agentA) || strings.Contains(w.Body.String(), agentB) {
		t.Fatalf("A's agent list must hold its agent only: %s", w.Body.String())
	}
	wantStatus(t, spireDo(t, http.MethodGet, "/authsec/spiresvc/v1/agents", nil, spireReq{}), http.StatusUnauthorized, "anonymous agent list")
}

// Agent-certificate and mTLS routes take the workspace only from the
// verified client certificate. X-Tenant-ID was trusted before AS-081.
func Test_Spire_CertificateRoutes_IgnoreXTenantID(t *testing.T) {
	a, b := TwoTenants(t)
	wsA, wsB := a.WS.WorkspaceID.String(), b.WS.WorkspaceID.String()
	caA := giveWorkspaceCA(t, a.WS.WorkspaceID)
	caB := giveWorkspaceCA(t, b.WS.WorkspaceID)
	agentB := seedSpireAgent(t, b.WS.WorkspaceID, "node-b")
	entryA := seedSpireEntry(t, a.WS.WorkspaceID, "/ns/a", "")
	entryB := seedSpireEntry(t, b.WS.WorkspaceID, "/ns/b", "")
	xTenantA := map[string]string{"X-Tenant-ID": wsA}

	// No certificate: refused whatever X-Tenant-ID says.
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/authsec/spiresvc/v1/entries/by-parent?parent_id=x&workspace_id=" + wsA},
		{http.MethodPost, "/authsec/spiresvc/v1/workload/attest"},
		{http.MethodPost, "/authsec/spiresvc/v1/workload/revoke"},
		{http.MethodPost, "/authsec/spiresvc/v1/agent/renew"},
		{http.MethodPost, "/authsec/spiresvc/v1/attest"},
		{http.MethodPost, "/authsec/spiresvc/v1/renew"},
		{http.MethodPost, "/authsec/spiresvc/v1/revoke"},
		{http.MethodPost, "/authsec/spiresvc/v1/jwt/issue"},
	} {
		body := map[string]string{"workspace_id": wsA}
		if rt.method == http.MethodGet {
			body = nil
		}
		var b interface{}
		if body != nil {
			b = body
		}
		wantStatus(t, spireDo(t, rt.method, rt.path, b, spireReq{headers: xTenantA}), http.StatusUnauthorized, rt.path+" without a certificate")
	}

	// B's agent, with X-Tenant-ID: A, sees B's entries only.
	certB := caB.issue(t, agentB)
	w := spireDo(t, http.MethodGet, "/authsec/spiresvc/v1/entries/by-parent", nil, spireReq{cert: certB, headers: xTenantA})
	wantStatus(t, w, http.StatusOK, "B's agent lists its entries")
	if !strings.Contains(w.Body.String(), entryB.String()) || strings.Contains(w.Body.String(), entryA.String()) {
		t.Fatalf("B's agent must see B's entries only: %s", w.Body.String())
	}
	wantStatus(t, spireDo(t, http.MethodGet, "/authsec/spiresvc/v1/entries/by-parent?workspace_id="+wsA, nil, spireReq{cert: certB}),
		http.StatusNotFound, "B's agent names workspace A")

	// A certificate for B's agent signed by A's CA is not B's.
	wantStatus(t, spireDo(t, http.MethodGet, "/authsec/spiresvc/v1/entries/by-parent", nil, spireReq{cert: caA.issue(t, agentB)}),
		http.StatusUnauthorized, "B's identity under A's CA")
	// An unregistered agent of A.
	wantStatus(t, spireDo(t, http.MethodGet, "/authsec/spiresvc/v1/entries/by-parent", nil, spireReq{cert: caA.issue(t, "spiffe://"+wsA+"/agent/ghost")}),
		http.StatusUnauthorized, "unregistered agent")

	// Agent renewal: the certificate's agent only.
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/agent/renew", map[string]string{"agent_id": uuid.NewString(), "csr": newCSR(t)}, spireReq{cert: certB}),
		http.StatusNotFound, "renew another agent")
	wantVaultUnavailable(t, spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/agent/renew", map[string]string{"csr": newCSR(t)}, spireReq{cert: certB, headers: xTenantA}),
		"B's agent renews itself")

	// Workload attest: B's entries only; a body workspace_id of A is 404.
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/workload/attest", map[string]interface{}{
		"workspace_id": wsA, "selectors": map[string]string{"unix:uid": "1000"}, "csr": newCSR(t),
	}, spireReq{cert: certB}), http.StatusNotFound, "attest naming workspace A")
	wantVaultUnavailable(t, spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/workload/attest", map[string]interface{}{
		"selectors": map[string]string{"unix:uid": "1000"}, "csr": newCSR(t),
	}, spireReq{cert: certB, headers: xTenantA}), "B's agent attests a B workload")

	// Workload revoke: an SVID recorded in A is not found for B's agent.
	if err := config.DB.Exec(`INSERT INTO spire_workload_svids (workspace_id, entry_id, agent_spiffe_id, spiffe_id, serial_number)
		VALUES (?, ?, 'spiffe://'||?||'/agent/n', 'spiffe://x/y', 'serial-a')`, wsA, entryA, wsA).Error; err != nil {
		t.Fatal(err)
	}
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/workload/revoke", map[string]string{"serial_number": "serial-a"}, spireReq{cert: certB, headers: xTenantA}),
		http.StatusNotFound, "B's agent revokes A's SVID")

	// mTLS group: a B workload certificate acts in B, whatever X-Tenant-ID.
	workloadB := caB.issue(t, "spiffe://"+wsB+"/ns/b")
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/revoke", map[string]string{"workspace_id": wsA, "serial_number": "s"}, spireReq{cert: workloadB}),
		http.StatusNotFound, "mTLS revoke naming workspace A")
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/revoke", map[string]string{"serial_number": "s"}, spireReq{cert: workloadB, headers: xTenantA}),
		http.StatusNotFound, "mTLS revoke of an unknown serial")
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/jwt/issue", map[string]interface{}{
		"spiffe_id": "spiffe://" + wsA + "/ns/a", "audience": []string{"x"},
	}, spireReq{cert: workloadB, headers: xTenantA}), http.StatusForbidden, "JWT-SVID for another identity")
}

// Public JWT-SVID endpoints validate the workspace they name; validation
// derives it from the token's issuer.
func Test_Spire_JWTBundleAndValidate_ValidateTheWorkspace(t *testing.T) {
	wantStatus(t, spireDo(t, http.MethodGet, "/authsec/spiresvc/v1/jwt/bundle?workspace_id="+uuid.NewString(), nil, spireReq{}),
		http.StatusNotFound, "bundle of an unknown workspace")
	wantStatus(t, spireDo(t, http.MethodGet, "/authsec/spiresvc/v1/jwt/bundle?workspace_id=../../etc", nil, spireReq{}),
		http.StatusBadRequest, "bundle of a malformed id")
	wantStatus(t, spireDo(t, http.MethodGet, "/authsec/spiresvc/bundle/"+uuid.NewString(), nil, spireReq{}),
		http.StatusNotFound, "x509 bundle of an unknown workspace")

	// A token claiming an unknown workspace's issuer is simply invalid.
	forged := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
		b64(`{"iss":"spiffe://`+uuid.NewString()+`","sub":"spiffe://x/y","exp":9999999999}`) + ".c2ln"
	w := spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/jwt/validate", map[string]string{"token": forged}, spireReq{})
	wantStatus(t, w, http.StatusOK, "validate")
	if !strings.Contains(w.Body.String(), `"valid":false`) {
		t.Fatalf("forged token reported valid: %s", w.Body.String())
	}
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spiresvc/v1/jwt/renew", map[string]string{"token": forged}, spireReq{}),
		http.StatusUnauthorized, "renew a forged token")
}

func b64(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// /authsec/spire (headless): everything but discovery/JWKS needs a token,
// and every resource is the caller's workspace's.
func Test_SpireHeadless_RequiresAuthAndIsolatesWorkspaces(t *testing.T) {
	a, b := TwoTenants(t)

	wantStatus(t, spireDo(t, http.MethodGet, "/authsec/spire/.well-known/openid-configuration", nil, spireReq{}), http.StatusOK, "discovery is public")
	for _, p := range []string{"/authsec/spire/policy", "/authsec/spire/roles/bindings", "/authsec/spire/registry/workloads"} {
		wantStatus(t, spireDo(t, http.MethodGet, p, nil, spireReq{}), http.StatusUnauthorized, p+" anonymous")
	}
	// Any caller could get a JWT-SVID for any X-SPIFFE-ID.
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spire/oidc/issue/jwt-svid", nil,
		spireReq{headers: map[string]string{"X-SPIFFE-ID": "spiffe://example.org/admin"}}), http.StatusUnauthorized, "anonymous JWT-SVID")
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spire/oidc/exchange/spiffe", nil, spireReq{token: a.AdminToken}), http.StatusGone, "platform SVID exchange")

	// Policies: same name in both workspaces; each sees its own.
	policy := map[string]interface{}{
		"name": "shared-name", "rules": []map[string]interface{}{{"name": "r", "effect": "allow",
			"subjects": []map[string]string{{"type": "spiffe_id", "value": "*"}}}},
	}
	w := spireDo(t, http.MethodPost, "/authsec/spire/policy", policy, spireReq{token: a.AdminToken})
	wantStatus(t, w, http.StatusCreated, "A creates a policy")
	var pa struct{ ID uint }
	_ = json.Unmarshal(w.Body.Bytes(), &pa)
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spire/policy", policy, spireReq{token: b.AdminToken}), http.StatusCreated, "B reuses the name")
	pid := fmt.Sprint(pa.ID)
	wantStatus(t, spireDo(t, http.MethodGet, "/authsec/spire/policy/"+pid, nil, spireReq{token: b.AdminToken}), http.StatusNotFound, "B reads A's policy")
	wantStatus(t, spireDo(t, http.MethodPut, "/authsec/spire/policy/"+pid, policy, spireReq{token: b.AdminToken}), http.StatusNotFound, "B updates A's policy")
	wantStatus(t, spireDo(t, http.MethodDelete, "/authsec/spire/policy/"+pid, nil, spireReq{token: b.AdminToken}), http.StatusNotFound, "B deletes A's policy")
	if w := spireDo(t, http.MethodPost, "/authsec/spire/policy", policy, spireReq{token: nonAdminToken(t, a)}); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin creates a policy: got %d", w.Code)
	}
	assertCount(t, 1, "spire_policies", "id = ? AND workspace_id = ?", pa.ID, a.WS.WorkspaceID)
	assertCount(t, 1, "spire_policy_rules", "policy_id = ? AND workspace_id = ?", pa.ID, a.WS.WorkspaceID)
	wantStatus(t, spireDo(t, http.MethodPut, "/authsec/spire/policy/"+pid, policy, spireReq{token: a.AdminToken}), http.StatusOK, "A updates its policy")

	// Registry.
	// (Registering also creates a SPIRE server entry over gRPC, which the
	// tests do not run; the row is seeded.)
	var wl struct{ SpiffeID string }
	wl.SpiffeID = "/ns/" + uuid.NewString()
	var wlID uint
	if err := config.DB.Raw(`INSERT INTO spire_workloads (spiffe_id, owner, workspace_id) VALUES (?, 'o', ?) RETURNING id`,
		wl.SpiffeID, a.WS.WorkspaceID).Scan(&wlID).Error; err != nil {
		t.Fatal(err)
	}
	w = spireDo(t, http.MethodGet, "/authsec/spire/registry/workloads", nil, spireReq{token: a.AdminToken})
	if !strings.Contains(w.Body.String(), wl.SpiffeID) {
		t.Fatalf("A does not list its workload: %s", w.Body.String())
	}
	w = spireDo(t, http.MethodGet, "/authsec/spire/registry/workloads", nil, spireReq{token: b.AdminToken})
	if strings.Contains(w.Body.String(), wl.SpiffeID) {
		t.Fatalf("B lists A's workload")
	}
	wantStatus(t, spireDo(t, http.MethodDelete, "/authsec/spire/registry/workloads/"+fmt.Sprint(wlID), nil, spireReq{token: b.AdminToken}),
		http.StatusNotFound, "B deletes A's workload")

	// OIDC: a JWT-SVID of A cannot be exchanged or introspected by B.
	w = spireDo(t, http.MethodPost, "/authsec/spire/oidc/issue/jwt-svid?spiffe_id="+url.QueryEscape(wl.SpiffeID), nil, spireReq{token: a.AdminToken})
	wantStatus(t, w, http.StatusOK, "A issues a JWT-SVID for its workload")
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &tok)
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spire/oidc/issue/jwt-svid?spiffe_id="+url.QueryEscape(wl.SpiffeID), nil, spireReq{token: b.AdminToken}),
		http.StatusNotFound, "B issues for A's workload")
	exch := map[string]string{"role_arn": "arn:aws:iam::1:role/r", "jwt_svid": tok.AccessToken}
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spire/oidc/exchange/aws", exch, spireReq{token: b.AdminToken}), http.StatusUnauthorized, "B exchanges A's JWT-SVID")
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spire/oidc/exchange/aws", exch, spireReq{token: a.AdminToken}), http.StatusNotImplemented, "A exchanges its JWT-SVID")

	// Role bindings.
	wantStatus(t, spireDo(t, http.MethodPost, "/authsec/spire/roles/bind", map[string]string{"subject": "s-" + a.WS.WorkspaceID.String(), "role": "r"}, spireReq{token: a.AdminToken}),
		http.StatusCreated, "A binds a role")
	w = spireDo(t, http.MethodGet, "/authsec/spire/roles/bindings", nil, spireReq{token: b.AdminToken})
	if strings.Contains(w.Body.String(), "s-"+a.WS.WorkspaceID.String()) {
		t.Fatalf("B lists A's role binding")
	}

	// Audit: admin only, own workspace.
	if w := spireDo(t, http.MethodGet, "/authsec/spire/audit/logs", nil, spireReq{token: nonAdminToken(t, a)}); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin reads audit: got %d", w.Code)
	}
	w = spireDo(t, http.MethodGet, "/authsec/spire/audit/logs", nil, spireReq{token: b.AdminToken})
	wantStatus(t, w, http.StatusOK, "B reads its audit")
	if strings.Contains(w.Body.String(), a.WS.WorkspaceID.String()) {
		t.Fatalf("B's audit shows A's rows")
	}
}
