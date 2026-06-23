package fakes

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// JWKSFake is an httptest server that implements:
//
//	GET /v1/jwt/bundle?workspace_id=<id>
//
// returning an RSA public key for each registered workspace.
// Tests call RegisterWorkspace to add a key and get the matching signer back.
type JWKSFake struct {
	mu     sync.RWMutex
	keys   map[string]*rsa.PrivateKey // workspace_id → private key
	server *httptest.Server
}

func newJWKSFake() *JWKSFake {
	return &JWKSFake{keys: make(map[string]*rsa.PrivateKey)}
}

// RegisterWorkspace generates an RSA keypair for workspaceID and stores it.
// Returns the private key so callers can sign SVIDs.
func (f *JWKSFake) RegisterWorkspace(workspaceID string) (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.keys[workspaceID] = priv
	f.mu.Unlock()
	return priv, nil
}

// PrivateKey returns the registered private key for workspaceID, or nil.
func (f *JWKSFake) PrivateKey(workspaceID string) *rsa.PrivateKey {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.keys[workspaceID]
}

// URL returns the base URL of the fake JWKS server.
func (f *JWKSFake) URL() string {
	if f.server != nil {
		return f.server.URL
	}
	return ""
}

func (f *JWKSFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/jwt/bundle") {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	wsID := r.URL.Query().Get("workspace_id")
	f.mu.RLock()
	priv, ok := f.keys[wsID]
	f.mu.RUnlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "workspace not found"})
		return
	}

	pub := &priv.PublicKey
	nBytes := pub.N.Bytes()
	eBytes := big.NewInt(int64(pub.E)).Bytes()

	resp := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": "spiffe-" + wsID,
				"n":   base64.RawURLEncoding.EncodeToString(nBytes),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
