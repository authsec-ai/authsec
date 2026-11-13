package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/agentgateway"
)

// Version is the gateway's software version (set at link time).
var Version = "dev"

// Agent credential headers.
const (
	AgentKeyHeader = "X-AuthSec-Agent-Key"
	AgentKeyPrefix = "agk_"
)

// Gateway is the enforcement point.
type Gateway struct {
	cfg      *Config
	pdp      *PDPClient
	up       *Uploader
	pins     *PinStore
	upstream *http.Client
	keys     map[string]AgentKey // by key sha256
	spiffe   map[string]SPIFFEAgent
	now      func() time.Time
}

// Options replace collaborators (tests).
type Options struct {
	// PDPHTTP is the client used to reach AuthSec.
	PDPHTTP *http.Client
	// UpstreamHTTP is the client used to reach MCP servers and providers.
	UpstreamHTTP *http.Client
}

// New builds a gateway from a finished configuration.
func New(cfg *Config, opt Options) (*Gateway, error) {
	pins, err := NewPinStore(cfg.PinStore)
	if err != nil {
		return nil, err
	}
	for _, s := range cfg.MCPServers {
		for tool, h := range s.Pins {
			if !agentgateway.ValidDigest(h) {
				return nil, fmt.Errorf("mcp_servers %s: pin for %s must be sha256:<64 hex>", s.Name, tool)
			}
			pins.Seed(s.Name, tool, h)
		}
	}
	up := NewUploader(cfg)
	pdpHTTP := opt.PDPHTTP
	if pdpHTTP == nil {
		pdpHTTP = &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, MaxIdleConnsPerHost: 64,
			IdleConnTimeout: 90 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	}
	pdp := NewPDPClient(cfg, Version, pdpHTTP, up)
	up.Attach(pdp)
	upstream := opt.UpstreamHTTP
	if upstream == nil {
		upstream = &http.Client{Timeout: time.Duration(cfg.Upstream.TimeoutS) * time.Second,
			Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, MaxIdleConnsPerHost: 64,
				IdleConnTimeout: 90 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
			// An upstream redirect is not followed: the agent's call must not
			// be replayed, with the customer's credentials, somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	g := &Gateway{cfg: cfg, pdp: pdp, up: up, pins: pins, upstream: upstream,
		keys: map[string]AgentKey{}, spiffe: map[string]SPIFFEAgent{}, now: time.Now}
	for _, k := range cfg.Agents.Keys {
		g.keys[k.KeySHA256] = k
	}
	for _, s := range cfg.Agents.SPIFFE {
		g.spiffe[s.ID] = s
	}
	return g, nil
}

// PDP is the gateway's PDP client (tests).
func (g *Gateway) PDP() *PDPClient { return g.pdp }

// Uploader is the gateway's uploader (tests).
func (g *Gateway) Uploader() *Uploader { return g.up }

// Pins is the gateway's pin store (tests).
func (g *Gateway) Pins() *PinStore { return g.pins }

// Run starts the background loops (hints, upload) until ctx ends.
func (g *Gateway) Run(ctx context.Context) {
	go g.pdp.RunHints(ctx, time.Duration(g.cfg.AuthSec.HintsIntervalS)*time.Second)
	g.up.Run(ctx, time.Duration(g.cfg.Upload.IntervalMS)*time.Millisecond)
}

// Handler is the agent-facing handler.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	for i := range g.cfg.MCPServers {
		s := &g.cfg.MCPServers[i]
		h := g.mcpHandler(s)
		mux.Handle(s.PathPrefix, h)
		mux.Handle(s.PathPrefix+"/", h)
	}
	for i := range g.cfg.LLM {
		l := &g.cfg.LLM[i]
		mux.Handle(l.PathPrefix+"/", g.llmHandler(l))
	}
	return mux
}

// AdminHandler is the local admin API (pins), or nil when no admin token is
// configured.
func (g *Gateway) AdminHandler() http.Handler {
	if g.cfg.AdminTokenEnv == "" {
		return nil
	}
	token := os.Getenv(g.cfg.AdminTokenEnv)
	if len(token) < 16 {
		log.Printf("[agent-gateway] admin API off: %s is unset or shorter than 16 characters", g.cfg.AdminTokenEnv)
		return nil
	}
	return g.adminHandler(token)
}

func (g *Gateway) adminHandler(token string) http.Handler {
	mux := http.NewServeMux()
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("/admin/pins", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"pins": g.pins.List()})
	}))
	mux.HandleFunc("/admin/pins/approve", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Server string `json:"server"`
			Tool   string `json:"tool"`
			Hash   string `json:"hash"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
			http.Error(w, "body must be JSON {server, tool, hash?}", http.StatusBadRequest)
			return
		}
		p, err := g.pins.Approve(body.Server, body.Tool, body.Hash)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		log.Printf("[agent-gateway] pin approved server=%s tool=%s hash=%s", p.Server, p.Tool, p.Hash)
		writeJSON(w, http.StatusOK, p)
	}))
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

/* ------------------------------ agent identity ----------------------------- */

var errNoAgent = errors.New("no agent credential")

// HashAgentKey is the configured form of an agent key (sha256, hex).
func HashAgentKey(k string) string {
	sum := sha256.Sum256([]byte(k))
	return hex.EncodeToString(sum[:])
}

// GenerateAgentKey returns a new agent key ("agk_" + 32 random bytes).
func GenerateAgentKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return AgentKeyPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func spiffeFromCert(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return ""
	}
	for _, u := range r.TLS.PeerCertificates[0].URIs {
		if u.Scheme == "spiffe" {
			return u.String()
		}
	}
	return ""
}

// agentKeyFrom finds an agent key in the request: X-AuthSec-Agent-Key, or
// the "API key" an OpenAI (Authorization: Bearer) or Anthropic (x-api-key)
// client sends, when it is an agk_ key.
func agentKeyFrom(r *http.Request) string {
	if k := strings.TrimSpace(r.Header.Get(AgentKeyHeader)); k != "" {
		return k
	}
	if a := r.Header.Get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		if k := strings.TrimSpace(a[7:]); strings.HasPrefix(k, AgentKeyPrefix) {
			return k
		}
	}
	if k := strings.TrimSpace(r.Header.Get("X-Api-Key")); strings.HasPrefix(k, AgentKeyPrefix) {
		return k
	}
	return ""
}

// identify names the calling agent: a verified client certificate's SPIFFE
// ID, the trusted SPIFFE header, or an agent key.
func (g *Gateway) identify(r *http.Request) (agentgateway.Request, error) {
	var req agentgateway.Request
	id := spiffeFromCert(r)
	if id == "" && g.cfg.Agents.TrustSPIFFEHeader {
		if h := strings.TrimSpace(r.Header.Get(g.cfg.Agents.SPIFFEHeader)); strings.HasPrefix(h, "spiffe://") {
			id = h
		}
	}
	if id != "" {
		req.SubjectID = id
		if a, ok := g.spiffe[id]; ok {
			req.IdentityID, req.WorkloadID, req.Labels = a.IdentityID, a.WorkloadID, a.Labels
		}
		return req, nil
	}
	if k := agentKeyFrom(r); k != "" {
		if a, ok := g.keys[HashAgentKey(k)]; ok {
			req.SubjectID, req.IdentityID, req.WorkloadID, req.Labels = a.ID, a.IdentityID, a.WorkloadID, a.Labels
			return req, nil
		}
	}
	return req, errNoAgent
}

// upstreamRequestHeaders are the agent's headers forwarded upstream; the
// agent's own credentials (Authorization, x-api-key, the agent key) and
// cookies never are.
func copyHeaders(dst, src http.Header, allowed map[string]bool) {
	for k, vs := range src {
		ck := http.CanonicalHeaderKey(k)
		if !allowed[ck] && !(strings.HasPrefix(ck, "Mcp-Param-")) {
			continue
		}
		for _, v := range vs {
			dst.Add(ck, v)
		}
	}
}

func newRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ServerTLSConfig is the agent-facing TLS configuration, or nil for plain
// HTTP. With a client CA, client certificates are verified when presented
// (agents with keys need none) and a SPIFFE URI SAN names the agent.
func (g *Gateway) ServerTLSConfig() (*tls.Config, error) {
	t := g.cfg.TLS
	if t == nil || t.CertFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if t.ClientCAFile != "" {
		pem, err := os.ReadFile(t.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("tls client ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("tls client ca: no certificate in file")
		}
		tc.ClientCAs, tc.ClientAuth = pool, tls.VerifyClientCertIfGiven
	}
	return tc, nil
}
