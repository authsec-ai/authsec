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

	"github.com/authsec-ai/authsec/internal/agentgateway"
)

// Fail modes (spec §7). AuthSec sets each gateway's fail mode (policy
// hints, fail_mode); the local value can only make it stricter (AS-174).
const (
	FailAuto   = agentgateway.FailAuto
	FailClosed = agentgateway.FailClosed
	FailOpen   = agentgateway.FailOpen
)

// Where provider keys come from (provider_keys).
const (
	// ProviderKeysAuthSec (the default): the gateway fetches the provider
	// keys AuthSec holds for it (GET /pdp/v1/provider-keys, with its agw_
	// credential) and keeps them in memory only, never on disk.
	ProviderKeysAuthSec = "authsec"
	// ProviderKeysLocal: each llm upstream's key is read from the
	// environment variable api_key_env (the pre-W6 behaviour).
	ProviderKeysLocal = "local"
)

// Hold modes (holds.mode): what the gateway does with a call held for a
// person (argument bounds).
const (
	// HoldWait (default) waits up to holds.wait_timeout_s for the decision,
	// then answers "held" (HTTP 202) if there is none yet.
	HoldWait = "wait"
	// HoldReturn answers "held" at once; the agent retries the same call
	// with X-AuthSec-Hold-Id once it is approved.
	HoldReturn = "return"
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
	// FailMode is auto (default), closed or open. It can only tighten the
	// fail mode AuthSec sets for this gateway (closed > auto > open): with
	// AuthSec saying auto, a local "open" acts as auto.
	FailMode string `yaml:"fail_mode"`

	Cache  CacheConfig  `yaml:"cache"`
	Upload UploadConfig `yaml:"upload"`
	Agents AgentsConfig `yaml:"agents"`

	// ProviderKeys is authsec (default: keys from AuthSec's secrets store)
	// or local (keys from api_key_env).
	ProviderKeys string `yaml:"provider_keys"`
	// LegacyAgentKeys keeps agents.keys (agent keys generated locally, before
	// AuthSec issued them) working, presented alone. Default false: such a
	// configuration is refused until the agents move to AuthSec-issued keys,
	// which are accepted only with their bound workload identity.
	LegacyAgentKeys bool `yaml:"legacy_agent_keys"`
	// Holds tunes how held calls are answered.
	Holds HoldsConfig `yaml:"holds"`

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
	// HintsIntervalS is how often policy hints (fail mode, cache lifetime,
	// stopped agents) are refreshed (default 5, at most 60). It bounds how
	// long a stopped agent can still be served from the decision cache.
	HintsIntervalS int `yaml:"hints_interval_s"`

	credential string
}

// CacheConfig bounds the decision cache.
type CacheConfig struct {
	MaxEntries int `yaml:"max_entries"`
	// MaxTTLSeconds, when > 0, caps how long a decision is cached below
	// what AuthSec allows (it can only shorten it).
	MaxTTLSeconds int `yaml:"max_ttl_seconds"`
}

// UploadConfig tunes the decision upload.
type UploadConfig struct {
	IntervalMS int `yaml:"interval_ms"`
	BatchSize  int `yaml:"batch_size"`
	MaxQueue   int `yaml:"max_queue"`
}

// HoldsConfig is what the gateway does with a held call.
type HoldsConfig struct {
	// Mode is wait (default) or return.
	Mode string `yaml:"mode"`
	// WaitTimeoutS bounds the wait (default 30, at most 300).
	WaitTimeoutS int `yaml:"wait_timeout_s"`
	// PollIntervalMS is how often a waiting call asks (default 1000).
	PollIntervalMS int `yaml:"poll_interval_ms"`
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
	// Keys are LEGACY locally generated agent keys (only their sha256 is
	// configured), honoured only with legacy_agent_keys: true. AuthSec-issued
	// keys arrive in the policy hints and need no configuration.
	Keys []AgentKey `yaml:"keys"`
	// AllowSPIFFEOnly accepts a verified SPIFFE ID with no agent key.
	// Default false: an agent presents its AuthSec-issued key AND the
	// workload identity the key is bound to.
	AllowSPIFFEOnly bool `yaml:"allow_spiffe_only"`
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
	// APIKeyEnv names the variable holding the provider key (provider_keys:
	// local only).
	APIKeyEnv string `yaml:"api_key_env"`
	// ProviderKey picks one of the keys AuthSec holds for this gateway, by
	// name or id (provider_keys: authsec). Empty: the only key of
	// PolicyProvider.
	ProviderKey string `yaml:"provider_key"`
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
		c.AuthSec.HintsIntervalS = 5
	}
	if c.AuthSec.HintsIntervalS > 60 {
		c.AuthSec.HintsIntervalS = 60
	}
	if c.Cache.MaxTTLSeconds < 0 {
		c.Cache.MaxTTLSeconds = 0
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
	switch c.ProviderKeys {
	case "":
		c.ProviderKeys = ProviderKeysAuthSec
	case ProviderKeysAuthSec, ProviderKeysLocal:
	default:
		return errors.New("provider_keys must be authsec or local")
	}
	switch c.Holds.Mode {
	case "":
		c.Holds.Mode = HoldWait
	case HoldWait, HoldReturn:
	default:
		return errors.New("holds.mode must be wait or return")
	}
	if c.Holds.WaitTimeoutS <= 0 {
		c.Holds.WaitTimeoutS = 30
	}
	if c.Holds.WaitTimeoutS > 300 {
		c.Holds.WaitTimeoutS = 300
	}
	if c.Holds.PollIntervalMS <= 0 {
		c.Holds.PollIntervalMS = 1000
	}
	if len(c.Agents.Keys) > 0 && !c.LegacyAgentKeys {
		return errors.New("agents.keys are locally generated (legacy) agent keys: issue AuthSec agent keys bound to each " +
			"agent's workload identity, or set legacy_agent_keys: true to keep these working meanwhile")
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
		if c.ProviderKeys == ProviderKeysLocal {
			if l.APIKeyEnv == "" {
				return fmt.Errorf("llm[%d]: api_key_env is required with provider_keys: local", i)
			}
			if l.ProviderKey != "" {
				return fmt.Errorf("llm[%d]: provider_key names an AuthSec-held key; it is not read with provider_keys: local", i)
			}
			l.apiKey = strings.TrimSpace(getenv(l.APIKeyEnv))
			if l.apiKey == "" {
				return fmt.Errorf("llm[%d]: %s is empty", i, l.APIKeyEnv)
			}
		} else if l.APIKeyEnv != "" {
			return fmt.Errorf("llm[%d]: api_key_env is read only with provider_keys: local; "+
				"with provider_keys: authsec (the default) add the key in AuthSec and name it in provider_key", i)
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
