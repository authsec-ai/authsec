package services

import (
	"strings"
	"unicode"
)

// Confidence and decision values stored on discovery_candidates.
const (
	confidenceNone   = "none"
	confidenceLow    = "low"
	confidenceMedium = "medium"
	confidenceHigh   = "high"

	decisionPromote = "promote"
	decisionHold    = "hold"

	agentLabelKey = "authsec.ai/agent"
)

// Observation is one discovered thing, independent of where it was found.
// EnvKeys are variable names only. Values are never inspected.
type Observation struct {
	Source       string
	DisplayName  string
	Image        string
	Command      string
	Argv         []string
	Exe          string
	Path         string
	Unit         string
	WorkloadName string
	Namespace    string
	ContainerID  string
	EnvKeys      []string
	Labels       map[string]string
}

// FilterDecision is the filter step. Promote is only medium and high.
// LogicalKey is empty when no framework matched, or when the only available
// name is a generic runtime. An empty key never merges two candidates.
type FilterDecision struct {
	Kind       string
	Confidence string
	Decision   string
	Frameworks []string
	Signals    []string
	Reasons    []string
	LogicalKey string
}

type fwToken struct {
	framework string
	token     string
}

// Copied from the iga-agent vocabulary. Bare "mcp" is intentionally absent:
// it matches inside unrelated words. Short tokens use a name-byte boundary.
var frameworkTokens = []fwToken{
	{"claude-code", "claude-code"},
	{"claude-code", "claude_code"},
	{"claude-code", "@anthropic-ai/claude-code"},
	{"claude", "claude"},
	{"codex", "openai-codex"},
	{"codex", "codex-cli"},
	{"codex", "codex"},
	{"cursor", "cursor-agent"},
	{"cursor", "cursor-cli"},
	{"cursor", "cursor"},
	{"aider", "aider"},
	{"langchain", "langchain"},
	{"langchain", "langserve"},
	{"langgraph", "langgraph"},
	{"llamaindex", "llamaindex"},
	{"llamaindex", "llama-index"},
	{"llamaindex", "llama_index"},
	{"crewai", "crewai"},
	{"crewai", "crew-ai"},
	{"autogen", "autogen"},
	{"autogen", "pyautogen"},
	{"autogpt", "autogpt"},
	{"autogpt", "auto-gpt"},
	{"semantic-kernel", "semantic-kernel"},
	{"semantic-kernel", "semantic_kernel"},
	{"haystack", "haystack-ai"},
	{"haystack", "farm-haystack"},
	{"dspy", "dspy-ai"},
	{"dspy", "dspy"},
	{"openai-agents", "openai-agents"},
	{"openai-agents", "openai_agents"},
	{"anthropic-sdk", "anthropic-sdk"},
	{"anthropic-sdk", "anthropic"},
	{"ollama", "ollama"},
	{"vllm", "vllm"},
	{"mcp", "modelcontextprotocol"},
	{"mcp", "mcp-server"},
	{"mcp", "mcp_server"},
	{"mcp", "fastmcp"},
}

// Env marker value is the framework. An empty value is a generic provider
// credential: real, but not enough on its own to call the workload an agent.
var envMarkers = map[string]string{
	"CLAUDE_CODE":              "claude-code",
	"CLAUDE_CODE_SESSION":      "claude-code",
	"CLAUDE_API_KEY":           "claude",
	"ANTHROPIC_API_KEY":        "anthropic-sdk",
	"ANTHROPIC_BASE_URL":       "anthropic-sdk",
	"CODEX_SESSION":            "codex",
	"CURSOR_SESSION":           "cursor",
	"AIDER_MODEL":              "aider",
	"LANGCHAIN_API_KEY":        "langchain",
	"LANGCHAIN_TRACING_V2":     "langchain",
	"LANGCHAIN_PROJECT":        "langchain",
	"LANGSMITH_API_KEY":        "langchain",
	"CREWAI_TELEMETRY_OPT_OUT": "crewai",
	"AUTOGEN_USE_DOCKER":       "autogen",
	"LLAMA_INDEX_CACHE_DIR":    "llamaindex",
	"DSPY_CACHEDIR":            "dspy",
	"OPENAI_API_KEY":           "",
	"OPENAI_BASE_URL":          "",
	"AZURE_OPENAI_ENDPOINT":    "",
	"GOOGLE_API_KEY":           "",
	"GEMINI_API_KEY":           "",
	"COHERE_API_KEY":           "",
	"MISTRAL_API_KEY":          "",
	"OLLAMA_HOST":              "ollama",
	"MCP_SERVER_URL":           "mcp",
	"MCP_SERVERS":              "mcp",
	"MCP_CONFIG_PATH":          "mcp",
	"MCP_TRANSPORT":            "mcp",
}

var genericNames = map[string]struct{}{
	"":                       {},
	"python":                 {},
	"python3":                {},
	"node":                   {},
	"nodejs":                 {},
	"ruby":                   {},
	"java":                   {},
	"bash":                   {},
	"sh":                     {},
	"nginx":                  {},
	"pause":                  {},
	"coredns":                {},
	"envoy":                  {},
	"pilot":                  {},
	"calico":                 {},
	"kube-proxy":             {},
	"local-path-provisioner": {},
}

type tokenHit struct {
	framework string
	token     string
	where     string
	level     int
}

// Classify assigns a confidence and a promote/hold decision. It does not
// read a database and it does not drop the observation.
func Classify(o Observation) FilterDecision {
	var hits []tokenHit
	kind := classifyKind(o)

	if val, ok := o.Labels[agentLabelKey]; ok && val != "false" {
		hits = append(hits, tokenHit{
			token: agentLabelKey, where: "label", level: 3,
		})
	}

	search := []struct {
		where string
		text  string
		level int
	}{
		{"image", o.Image, 3},
		{"exe", o.Exe, 3},
		{"path", o.Path, 3},
		{"unit", o.Unit, 3},
		{"workload", o.WorkloadName, 3},
		{"command", commandText(o), 2},
	}
	for _, field := range search {
		if strings.TrimSpace(field.text) == "" {
			continue
		}
		hay := strings.ToLower(field.text)
		seenFW := map[string]bool{}
		for _, tok := range frameworkTokens {
			if seenFW[tok.framework] {
				continue
			}
			if !containsToken(hay, tok.token) {
				continue
			}
			seenFW[tok.framework] = true
			hits = append(hits, tokenHit{
				framework: tok.framework,
				token:     tok.token,
				where:     field.where,
				level:     field.level,
			})
		}
	}

	for _, key := range o.EnvKeys {
		fw, ok := envMarkers[strings.ToUpper(strings.TrimSpace(key))]
		if !ok {
			continue
		}
		level := 1
		if fw != "" {
			level = 3
		}
		hits = append(hits, tokenHit{
			framework: fw,
			token:     key,
			where:     "env",
			level:     level,
		})
	}

	best := 0
	for _, h := range hits {
		if h.level > best {
			best = h.level
		}
	}
	conf := confidenceNone
	switch best {
	case 3:
		conf = confidenceHigh
	case 2:
		conf = confidenceMedium
	case 1:
		conf = confidenceLow
	}

	frameworks := frameworksAt(hits, 2)
	reasons := reasonsFor(hits, kind, conf)
	signals := make([]string, 0, len(hits))
	for _, h := range hits {
		token := h.token
		if h.framework != "" {
			token = h.framework + ":" + h.token
		}
		signals = append(signals, h.where+":"+token)
	}

	decision := decisionHold
	if conf == confidenceHigh || conf == confidenceMedium {
		decision = decisionPromote
	}

	return FilterDecision{
		Kind:       kind,
		Confidence: conf,
		Decision:   decision,
		Frameworks: frameworks,
		Signals:    signals,
		Reasons:    reasons,
		LogicalKey: logicalKey(bestFramework(hits), chooseName(o)),
	}
}

func commandText(o Observation) string {
	if strings.TrimSpace(o.Command) != "" {
		return o.Command
	}
	return strings.Join(o.Argv, " ")
}

func classifyKind(o Observation) string {
	if strings.TrimSpace(o.ContainerID) != "" {
		return "docker.container"
	}
	base := candidateName(o.Exe)
	if base == "python" || base == "python3" {
		return "python.process"
	}
	if strings.TrimSpace(o.Unit) != "" {
		return "linux.systemd"
	}
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(o.Path)), ".py") {
		return "python.file"
	}
	if strings.TrimSpace(o.WorkloadName) != "" || strings.TrimSpace(o.Namespace) != "" {
		return "k8s.workload"
	}
	if strings.TrimSpace(o.Path) != "" && strings.TrimSpace(o.Exe) == "" {
		return "linux.file"
	}
	return "linux.process"
}

func frameworksAt(hits []tokenHit, minLevel int) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, h := range hits {
		if h.framework == "" || h.level < minLevel {
			continue
		}
		if _, ok := seen[h.framework]; ok {
			continue
		}
		seen[h.framework] = struct{}{}
		out = append(out, h.framework)
	}
	return out
}

func bestFramework(hits []tokenHit) string {
	bestLevel := 0
	bestLen := -1
	fw := ""
	for _, h := range hits {
		if h.framework == "" || h.level < 2 {
			continue
		}
		if h.level > bestLevel || (h.level == bestLevel && len(h.token) > bestLen) {
			bestLevel = h.level
			bestLen = len(h.token)
			fw = h.framework
		}
	}
	return fw
}

func logicalKey(framework, name string) string {
	framework = candidateName(framework)
	name = candidateName(name)
	if framework == "" || name == "" || genericName(name) {
		return ""
	}
	return "agent:" + framework + ":" + name
}

func reasonsFor(hits []tokenHit, kind, conf string) []string {
	if len(hits) == 0 {
		switch kind {
		case "python.process":
			return []string{"Python process with no framework signal."}
		case "docker.container":
			return []string{"Container with no framework signal."}
		default:
			return []string{"No agent framework signal."}
		}
	}
	out := make([]string, 0, len(hits)+1)
	for _, h := range hits {
		out = append(out, hitReason(h))
	}
	switch conf {
	case confidenceHigh, confidenceMedium:
		out = append(out, "Classified as an agent.")
	case confidenceLow:
		out = append(out, "Held: a provider credential alone is not an agent.")
	}
	return out
}

func hitReason(h tokenHit) string {
	switch h.where {
	case "label":
		return "Workload label authsec.ai/agent declares this is an agent."
	case "image":
		return "Image reference contains " + h.token + "."
	case "exe":
		return "Executable path contains " + h.token + "."
	case "path":
		return "File path contains " + h.token + "."
	case "unit":
		return "Systemd unit contains " + h.token + "."
	case "workload":
		return "Workload name contains " + h.token + "."
	case "command":
		return "Command references " + h.token + "."
	case "env":
		if h.framework == "" {
			return "Generic provider credential " + h.token + " is not enough to call this an agent."
		}
		return "Environment " + h.token + " indicates " + h.framework + "."
	default:
		return "Matched " + h.token + "."
	}
}

func chooseName(o Observation) string {
	argv := o.Argv
	if len(argv) == 0 && strings.TrimSpace(o.Command) != "" {
		argv = strings.Fields(o.Command)
	}
	var py string
	for _, arg := range argv {
		if strings.HasSuffix(strings.ToLower(arg), ".py") {
			py = arg
			break
		}
	}
	ordered := []string{o.WorkloadName, py, o.Exe, o.Unit, o.Path}
	for _, raw := range ordered {
		n := candidateName(raw)
		if n == "" || genericName(n) {
			continue
		}
		return n
	}
	if mod := moduleToken(argv); mod != "" {
		return mod
	}
	if img := imageRepoBasename(o.Image); img != "" && !genericName(img) {
		return img
	}
	return ""
}

func moduleToken(argv []string) string {
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] != "-m" {
			continue
		}
		mod := argv[i+1]
		if !isModuleToken(mod) {
			continue
		}
		parts := strings.Split(mod, ".")
		n := candidateName(parts[len(parts)-1])
		if n != "" && !genericName(n) {
			return n
		}
	}
	return ""
}

func isModuleToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r == '.' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}

func imageRepoBasename(image string) string {
	ref := strings.TrimSpace(image)
	if ref == "" {
		return ""
	}
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	slash := strings.LastIndex(ref, "/")
	if colon := strings.LastIndex(ref, ":"); colon > slash {
		ref = ref[:colon]
	}
	return candidateName(ref)
}

func candidateName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\\", "/")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.ToLower(s)
	s = strings.TrimSuffix(s, ".py")
	s = strings.TrimSuffix(s, ".service")
	s = strings.ReplaceAll(s, "_", "-")
	return s
}

func genericName(s string) bool {
	_, ok := genericNames[s]
	return ok
}

// needsBoundary is true for tokens short enough to sit inside another word.
// claude and cursor are six characters and are included because both appear
// inside unrelated names (claudette, precursor).
func needsBoundary(token string) bool {
	if len(token) < 6 {
		return true
	}
	switch token {
	case "claude", "cursor", "codex", "dspy":
		return true
	default:
		return false
	}
}

func containsToken(haystack, token string) bool {
	token = strings.ToLower(token)
	if token == "" || token == "mcp" || haystack == "" {
		return false
	}
	if !needsBoundary(token) {
		return strings.Contains(haystack, token)
	}
	rest := haystack
	for {
		i := strings.Index(rest, token)
		if i < 0 {
			return false
		}
		before := i == 0 || !isNameByte(rest[i-1])
		end := i + len(token)
		after := end == len(rest) || !isNameByte(rest[end])
		if before && after {
			return true
		}
		rest = rest[i+1:]
	}
}

func isNameByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// detectionHolds reports whether the connector looked and found nothing an
// agent inventory should keep. A sighting with no detection block is legacy
// (repository scans, older tests) and is not held.
func detectionHolds(metadata map[string]interface{}) bool {
	present, conf := reportedConfidence(metadata)
	if !present {
		return false
	}
	return conf == "" || conf == confidenceNone || conf == confidenceLow
}

func reportedConfidence(metadata map[string]interface{}) (bool, string) {
	if metadata == nil {
		return false, ""
	}
	raw, ok := metadata["detection"]
	if !ok || raw == nil {
		return false, ""
	}
	det, ok := raw.(map[string]interface{})
	if !ok {
		return true, confidenceNone
	}
	conf := strings.ToLower(strings.TrimSpace(asString(det["confidence"])))
	return true, conf
}

func reportedFrameworks(metadata map[string]interface{}) []string {
	if metadata == nil {
		return nil
	}
	det, ok := metadata["detection"].(map[string]interface{})
	if !ok {
		return nil
	}
	return stringList(det["frameworks"])
}
