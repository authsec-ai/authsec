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
	keys     map[string]AgentKey // legacy local keys, by sha256
	spiffe   map[string]SPIFFEAgent
	pkeys    *ProviderKeyStore
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
		keys: map[string]AgentKey{}, spiffe: map[string]SPIFFEAgent{}, pkeys: newProviderKeyStore(pdp), now: time.Now}
	if cfg.LegacyAgentKeys {
		for _, k := range cfg.Agents.Keys {
			g.keys[k.KeySHA256] = k
		}
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

// ProviderKeys is the gateway's in-memory provider key store (tests).
func (g *Gateway) ProviderKeys() *ProviderKeyStore { return g.pkeys }

// Run starts the background loops (hints, upload) until ctx ends.
func (g *Gateway) Run(ctx context.Context) {
	if g.cfg.ProviderKeys == ProviderKeysAuthSec && len(g.cfg.LLM) > 0 {
		go g.pkeys.Warm(ctx)
	}
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

var (
	errNoAgent = errors.New("no agent credential")
	// errWorkloadMismatch: an AuthSec-issued key presented without the
	// workload identity it is bound to (or with another one).
	errWorkloadMismatch = errors.New("agent key not presented with its bound workload identity")
)

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

// workloadIdentity is the caller's verified workload identity: a verified
// client certificate's SPIFFE ID, or the trusted SPIFFE header.
func (g *Gateway) workloadIdentity(r *http.Request) string {
	id := spiffeFromCert(r)
	if id == "" && g.cfg.Agents.TrustSPIFFEHeader {
		if h := strings.TrimSpace(r.Header.Get(g.cfg.Agents.SPIFFEHeader)); strings.HasPrefix(h, "spiffe://") {
			id = h
		}
	}
	return id
}

// identify names the calling agent (W6). An AuthSec-issued agent key is
// accepted ONLY with the workload identity it is bound to: the verified
// SPIFFE ID must be the key's spiffe_id, and the AuthSec workload id the
// SPIFFE ID maps to (agents.spiffe) must be the key's workload_id -- both,
// whichever the key names. A key alone, or a workload identity alone, is
// refused; a SPIFFE ID alone is accepted only with
// agents.allow_spiffe_only, and a locally generated key alone only with
// legacy_agent_keys.
func (g *Gateway) identify(r *http.Request) (agentgateway.Request, error) {
	var req agentgateway.Request
	id := g.workloadIdentity(r)
	mapped, hasMap := g.spiffe[id]
	if k := agentKeyFrom(r); k != "" {
		sha := HashAgentKey(k)
		if h, ok := g.pdp.AgentKey(sha); ok {
			if id == "" {
				return req, errWorkloadMismatch
			}
			if h.SPIFFEID != "" && h.SPIFFEID != id {
				return req, errWorkloadMismatch
			}
			if h.WorkloadID != "" && (!hasMap || !strings.EqualFold(mapped.WorkloadID, h.WorkloadID)) {
				return req, errWorkloadMismatch
			}
			req.SubjectID, req.IdentityID, req.WorkloadID = h.ClientID, h.IdentityID, h.WorkloadID
			if req.IdentityID == "" && hasMap {
				req.IdentityID = mapped.IdentityID
			}
			if req.WorkloadID == "" && hasMap {
				req.WorkloadID = mapped.WorkloadID
			}
			req.Labels = append(append([]string(nil), h.Labels...), mapped.Labels...)
			return req, nil
		}
		if g.cfg.LegacyAgentKeys {
			if a, ok := g.keys[sha]; ok {
				req.SubjectID, req.IdentityID, req.WorkloadID, req.Labels = a.ID, a.IdentityID, a.WorkloadID, a.Labels
				return req, nil
			}
		}
		return req, errNoAgent
	}
	if id != "" && g.cfg.Agents.AllowSPIFFEOnly {
		req.SubjectID = id
		if hasMap {
			req.IdentityID, req.WorkloadID, req.Labels = mapped.IdentityID, mapped.WorkloadID, mapped.Labels
		}
		return req, nil
	}
	return req, errNoAgent
}

// identifyMessage is the refusal text for an identify error.
func identifyMessage(err error) string {
	if errors.Is(err, errWorkloadMismatch) {
		return "This AuthSec agent key is accepted only from the workload identity it is bound to (present both)."
	}
	return "An AuthSec agent key and the workload identity it is bound to are required."
}

// runID is the call's run id: the agent's X-AuthSec-Run-Id when usable,
// else a new one. It is echoed to the agent.
func runID(w http.ResponseWriter, r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get(agentgateway.RunIDHeader))
	if !agentgateway.ValidRunID(id) {
		id = "run_" + newRequestID()
	}
	w.Header().Set(agentgateway.RunIDHeader, id)
	return id
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
