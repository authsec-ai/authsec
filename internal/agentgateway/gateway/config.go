// Package gateway is the AuthSec agent runtime gateway
// (SPEC-agent-runtime-gateway.md §7): a policy enforcement point that runs in
// the customer's environment, in front of MCP servers (Streamable HTTP) and
// model providers (OpenAI-compatible and Anthropic APIs). It asks AuthSec,
// the policy decision point, over the AuthZEN Authorization API, caches the
// answers, enforces them, forwards allowed calls with the customer's own
// credentials (which never leave this process), and uploads decision
// metadata. It never sends prompt, completion, argument or result text
// anywhere but the configured upstream.
package gateway

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Fail modes (spec §7).
const (
	FailAuto   = "auto"
	FailClosed = "closed"
	FailOpen   = "open"
)

// Provider kinds of an LLM upstream.
const (
	ProviderOpenAI           = "openai"
	ProviderAnthropic        = "anthropic"
	ProviderOpenAICompatible = "openai_compatible"
)

// Config is the gateway's configuration (YAML, with environment overrides).
type Config struct {
	// Listen is the agent-facing address (default ":8080").
	Listen string `yaml:"listen"`
	// AdminListen serves the local pin-approval API (default
	// "127.0.0.1:9091"); it is off unless AdminTokenEnv names a set variable.
	AdminListen   string `yaml:"admin_listen"`
	AdminTokenEnv string `yaml:"admin_token_env"`
	TLS           *TLS   `yaml:"tls"`

	AuthSec AuthSec `yaml:"authsec"`
	// FailMode is auto (default), closed or open.
	FailMode string `yaml:"fail_mode"`

	Cache  CacheConfig  `yaml:"cache"`
	Upload UploadConfig `yaml:"upload"`
	Agents AgentsConfig `yaml:"agents"`

	MCPServers []MCPServer    `yaml:"mcp_servers"`
	LLM        []LLMUpstream  `yaml:"llm"`
	PinStore   string         `yaml:"pin_store"`
	Limits     LimitsConfig   `yaml:"limits"`
	Upstream   UpstreamConfig `yaml:"upstream"`
}

// TLS serves the agent-facing listener over TLS; with ClientCAFile, client
// certificates are verified and a SPIFFE URI SAN names the agent.
type TLS struct {
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	ClientCAFile string `yaml:"client_ca_file"`
}

// AuthSec is where the PDP is and how the gateway authenticates.
type AuthSec struct {
	// URL is the AuthSec API base, e.g. https://api.authsec.ai/authsec.
	URL string `yaml:"url"`
	// CredentialEnv names the variable holding the gateway credential
	// (default AUTHSEC_GATEWAY_CREDENTIAL). The credential is never in YAML.
	CredentialEnv string `yaml:"credential_env"`
	// TimeoutMS bounds one PDP call (default 300); then the fail mode applies.
	TimeoutMS int `yaml:"timeout_ms"`
	// HintsIntervalS is how often policy hints are refreshed (default 60).
	HintsIntervalS int `yaml:"hints_interval_s"`

	credential string
}

// CacheConfig bounds the decision cache.
type CacheConfig struct {
	MaxEntries int `yaml:"max_entries"`
}

// UploadConfig tunes the decision upload.
type UploadConfig struct {
	IntervalMS int `yaml:"interval_ms"`
	BatchSize  int `yaml:"batch_size"`
	MaxQueue   int `yaml:"max_queue"`
}

// LimitsConfig bounds request bodies.
type LimitsConfig struct {
	MaxBodyBytes int64 `yaml:"max_body_bytes"`
}

// UpstreamConfig tunes the upstream HTTP client.
type UpstreamConfig struct {
	TimeoutS int `yaml:"timeout_s"`
}

// AgentsConfig is how the gateway knows which agent is calling.
type AgentsConfig struct {
	// Keys are per-agent gateway keys: the agent presents the key; only
	// its sha256 is configured.
	Keys []AgentKey `yaml:"keys"`
	// SPIFFE maps verified SPIFFE IDs (mTLS, or the trusted header) to
	// selector attributes; an unlisted SPIFFE ID is the subject with none.
	SPIFFE []SPIFFEAgent `yaml:"spiffe"`
	// TrustSPIFFEHeader takes the SPIFFE ID from SPIFFEHeader. Set it only
	// behind an mTLS-terminating proxy that overwrites the header.
	TrustSPIFFEHeader bool   `yaml:"trust_spiffe_header"`
	SPIFFEHeader      string `yaml:"spiffe_header"`
}

// AgentKey is one agent's gateway key.
type AgentKey struct {
	// ID is the agent's gateway client id (AuthZEN subject.id).
	ID string `yaml:"id"`
	// KeySHA256 is the lower-case hex sha256 of the key.
	KeySHA256  string   `yaml:"key_sha256"`
	IdentityID string   `yaml:"identity_id"`
	WorkloadID string   `yaml:"workload_id"`
	Labels     []string `yaml:"labels"`
}

// SPIFFEAgent gives a SPIFFE ID selector attributes.
type SPIFFEAgent struct {
	ID         string   `yaml:"id"`
	IdentityID string   `yaml:"identity_id"`
	WorkloadID string   `yaml:"workload_id"`
	Labels     []string `yaml:"labels"`
}

// MCPServer is one upstream MCP server (Streamable HTTP).
type MCPServer struct {
	// Name is the server's name in policies (resource server).
	Name string `yaml:"name"`
	// URL is its MCP endpoint.
	URL string `yaml:"url"`
	// PathPrefix is where agents reach it on the gateway (default /mcp/<name>).
	PathPrefix string `yaml:"path_prefix"`
	// Headers are added upstream; a value "env:NAME" is read from the
	// environment (credentials stay in this process).
	Headers map[string]string `yaml:"headers"`
	// PinTools pins tool definitions from tools/list (default true).
	PinTools *bool `yaml:"pin_tools"`
	// RequirePinned refuses a call to a tool never seen in tools/list.
	RequirePinned bool `yaml:"require_pinned"`
	// Pins pre-approve definition hashes by tool name.
	Pins map[string]string `yaml:"pins"`
}

// LLMUpstream is one model provider.
type LLMUpstream struct {
	// Name labels it (default the provider).
	Name string `yaml:"name"`
	// Provider is openai, anthropic or openai_compatible.
	Provider string `yaml:"provider"`
	// PolicyProvider is the provider name in policies (default Provider;
	// set it for an openai_compatible upstream, e.g. "groq").
	PolicyProvider string `yaml:"policy_provider"`
	// BaseURL, e.g. https://api.openai.com (paths /v1/... are appended).
	BaseURL string `yaml:"base_url"`
	// PathPrefix is where agents reach it (default /llm/<name>).
	PathPrefix string `yaml:"path_prefix"`
	// APIKeyEnv names the variable holding the provider key.
	APIKeyEnv string `yaml:"api_key_env"`
	// Headers are added upstream ("env:NAME" values read from the environment).
	Headers map[string]string `yaml:"headers"`

	apiKey string
}

// LoadConfig reads a YAML file (path may be empty) and applies the
// environment: AUTHSEC_URL, AUTHSEC_GATEWAY_CREDENTIAL (or the configured
// variable), AGENT_GATEWAY_LISTEN, AGENT_GATEWAY_FAIL_MODE.
func LoadConfig(path string) (*Config, error) {
	cfg := &Config{}
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		dec.KnownFields(true)
		if err := dec.Decode(cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	if v := os.Getenv("AUTHSEC_URL"); v != "" {
		cfg.AuthSec.URL = v
	}
	if v := os.Getenv("AGENT_GATEWAY_LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := os.Getenv("AGENT_GATEWAY_FAIL_MODE"); v != "" {
		cfg.FailMode = v
	}
	if err := cfg.finish(os.Getenv); err != nil {
		return nil, err
	}
	return cfg, nil
}

func resolveHeaders(h map[string]string, getenv func(string) string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range h {
		if name, ok := strings.CutPrefix(v, "env:"); ok {
			val := getenv(name)
			if val == "" {
				return nil, fmt.Errorf("header %s: environment variable %s is empty", k, name)
			}
			v = val
		}
		if strings.ContainsAny(k+v, "\r\n") {
			return nil, fmt.Errorf("header %s: control characters", k)
		}
		out[k] = v
	}
	return out, nil
}

// finish applies defaults and validates; getenv reads secrets.
func (c *Config) finish(getenv func(string) string) error {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.AdminListen == "" {
		c.AdminListen = "127.0.0.1:9091"
	}
	if c.FailMode == "" {
		c.FailMode = FailAuto
	}
	switch c.FailMode {
	case FailAuto, FailClosed, FailOpen:
	default:
		return fmt.Errorf("fail_mode must be auto, closed or open")
	}
	u, err := url.Parse(strings.TrimRight(c.AuthSec.URL, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("authsec.url must be an http(s) URL (AUTHSEC_URL)")
	}
	c.AuthSec.URL = strings.TrimRight(c.AuthSec.URL, "/")
	if c.AuthSec.CredentialEnv == "" {
		c.AuthSec.CredentialEnv = "AUTHSEC_GATEWAY_CREDENTIAL"
	}
	c.AuthSec.credential = strings.TrimSpace(getenv(c.AuthSec.CredentialEnv))
	if !strings.HasPrefix(c.AuthSec.credential, "agw_") {
		return fmt.Errorf("%s must hold the gateway credential (agw_...)", c.AuthSec.CredentialEnv)
	}
	if c.AuthSec.TimeoutMS <= 0 {
		c.AuthSec.TimeoutMS = 300
	}
	if c.AuthSec.HintsIntervalS <= 0 {
		c.AuthSec.HintsIntervalS = 60
	}
	if c.Cache.MaxEntries <= 0 {
		c.Cache.MaxEntries = 10000
	}
	if c.Upload.IntervalMS <= 0 {
		c.Upload.IntervalMS = 2000
	}
	if c.Upload.BatchSize <= 0 || c.Upload.BatchSize > 1000 {
		c.Upload.BatchSize = 500
	}
	if c.Upload.MaxQueue <= 0 {
		c.Upload.MaxQueue = 50000
	}
	if c.Limits.MaxBodyBytes <= 0 {
		c.Limits.MaxBodyBytes = 16 << 20
	}
	if c.Upstream.TimeoutS <= 0 {
		c.Upstream.TimeoutS = 600
	}
	if c.Agents.SPIFFEHeader == "" {
		c.Agents.SPIFFEHeader = "X-Client-SPIFFE-ID"
	}
	ids := map[string]bool{}
	for i, k := range c.Agents.Keys {
		k.KeySHA256 = strings.ToLower(strings.TrimSpace(k.KeySHA256))
		if k.ID == "" || len(k.KeySHA256) != 64 {
			return fmt.Errorf("agents.keys[%d]: id and a 64-hex key_sha256 are required", i)
		}
		if ids[k.ID] {
			return fmt.Errorf("agents.keys[%d]: duplicate id %q", i, k.ID)
		}
		ids[k.ID] = true
		c.Agents.Keys[i] = k
	}
	if len(c.MCPServers) == 0 && len(c.LLM) == 0 {
		return errors.New("configure at least one mcp_servers or llm upstream")
	}
	prefixes := map[string]bool{}
	for i := range c.MCPServers {
		s := &c.MCPServers[i]
		if s.Name == "" || strings.Contains(s.Name, "/") {
			return fmt.Errorf("mcp_servers[%d]: a name without '/' is required", i)
		}
		if pu, err := url.Parse(s.URL); err != nil || (pu.Scheme != "https" && pu.Scheme != "http") || pu.Host == "" {
			return fmt.Errorf("mcp_servers[%d]: url must be an http(s) URL", i)
		}
		if s.PathPrefix == "" {
			s.PathPrefix = "/mcp/" + s.Name
		}
		s.PathPrefix = "/" + strings.Trim(s.PathPrefix, "/")
		if s.PinTools == nil {
			t := true
			s.PinTools = &t
		}
		if s.Headers, err = resolveHeaders(s.Headers, getenv); err != nil {
			return fmt.Errorf("mcp_servers[%d]: %w", i, err)
		}
		if prefixes[s.PathPrefix] {
			return fmt.Errorf("duplicate path_prefix %s", s.PathPrefix)
		}
		prefixes[s.PathPrefix] = true
	}
	for i := range c.LLM {
		l := &c.LLM[i]
		switch l.Provider {
		case ProviderOpenAI, ProviderAnthropic, ProviderOpenAICompatible:
		default:
			return fmt.Errorf("llm[%d]: provider must be openai, anthropic or openai_compatible", i)
		}
		if l.BaseURL == "" {
			switch l.Provider {
			case ProviderOpenAI:
				l.BaseURL = "https://api.openai.com"
			case ProviderAnthropic:
				l.BaseURL = "https://api.anthropic.com"
			default:
				return fmt.Errorf("llm[%d]: base_url is required", i)
			}
		}
		if pu, err := url.Parse(l.BaseURL); err != nil || (pu.Scheme != "https" && pu.Scheme != "http") || pu.Host == "" {
			return fmt.Errorf("llm[%d]: base_url must be an http(s) URL", i)
		}
		l.BaseURL = strings.TrimRight(l.BaseURL, "/")
		if l.Name == "" {
			l.Name = l.Provider
		}
		if l.PolicyProvider == "" {
			l.PolicyProvider = l.Provider
		}
		l.PolicyProvider = strings.ToLower(l.PolicyProvider)
		if l.PathPrefix == "" {
			l.PathPrefix = "/llm/" + l.Name
		}
		l.PathPrefix = "/" + strings.Trim(l.PathPrefix, "/")
		if l.APIKeyEnv == "" {
			return fmt.Errorf("llm[%d]: api_key_env is required (the provider key stays in this process)", i)
		}
		l.apiKey = strings.TrimSpace(getenv(l.APIKeyEnv))
		if l.apiKey == "" {
			return fmt.Errorf("llm[%d]: %s is empty", i, l.APIKeyEnv)
		}
		if l.Headers, err = resolveHeaders(l.Headers, getenv); err != nil {
			return fmt.Errorf("llm[%d]: %w", i, err)
		}
		if prefixes[l.PathPrefix] {
			return fmt.Errorf("duplicate path_prefix %s", l.PathPrefix)
		}
		prefixes[l.PathPrefix] = true
	}
	return nil
}

func (c *Config) timeout() time.Duration {
	return time.Duration(c.AuthSec.TimeoutMS) * time.Millisecond
}
