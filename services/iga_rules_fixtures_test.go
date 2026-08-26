package services

import (
	"encoding/json"
	"strings"
	"testing"
)

// Rule fixtures — the catalogue's own regression suite.
//
// Every rule carries at least three: a TRUE POSITIVE that must fire, a NEAR
// MISS that must NOT fire, and an ADVERSARIAL case whose behaviour is asserted
// so it is a decision on record rather than an accident.
//
// These are unit tests on purpose. The integration suite only runs when
// IGA_TEST_DSN is set, so a catalogue regression would sail through an ordinary
// `go test ./...`. The catalogue IS the product's coverage claim; it needs a
// gate that always runs.
type ruleFixture struct {
	// name describes the case, and appears in test output.
	name string
	// ruleID is the rule under test. Several rules may claim the same path;
	// the fixture asserts what THIS one does.
	ruleID string
	path   string
	body   string
	// fires is the assertion: did this rule produce facts?
	fires bool
	// why records the reasoning, so a future reader can tell an intentional
	// non-match from an oversight.
	why string
	// wantFact, when set, must be present in the produced facts.
	wantFact string
	// forbidden, when set, must NOT appear anywhere in the persisted facts.
	forbidden string
}

func fixtures() []ruleFixture {
	return []ruleFixture{
		// ---- workflow.agent-invocation -------------------------------------
		{
			name: "TP/named agent action", ruleID: "workflow.agent-invocation",
			path: ".github/workflows/review.yml",
			body: "on:\n  pull_request_target:\npermissions:\n  contents: write\n  issues: read\njobs:\n" +
				"  review:\n    runs-on: ubuntu-latest\n    steps:\n" +
				"      - uses: anthropics/claude-code-action@v1\n",
			fires: true, wantFact: "declared_runtimes",
			why: "an explicit agent action reference is the strongest CI signal there is",
		},
		{
			name: "NEAR-MISS/prose mention only", ruleID: "workflow.agent-invocation",
			path: ".github/workflows/build.yml",
			body: "# TODO: maybe ask claude to review these\non:\n  push:\njobs:\n" +
				"  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
			fires: false,
			why: "the vocabulary is package and action names, never bare words: " +
				"'claude' in a comment is not 'claude-code-action'. This is exactly the " +
				"over-match the catalogue refuses to make",
		},
		{
			name: "ADVERSARIAL/sha-pinned action ref", ruleID: "workflow.agent-invocation",
			path: ".github/workflows/pinned.yml",
			body: "on:\n  push:\njobs:\n  x:\n    steps:\n" +
				"      - uses: anthropics/claude-code-action@a1b2c3d4e5f6a7b8c9d0\n",
			fires: true,
			why: "a pinned sha is good practice, not evasion; the org/repo part still " +
				"names the action, so detection must survive it",
		},

		// ---- workflow.reusable-and-composite -------------------------------
		{
			name: "TP/calls a reusable workflow", ruleID: "workflow.reusable-and-composite",
			path: ".github/workflows/caller.yml",
			body: "on:\n  push:\njobs:\n  call:\n" +
				"    uses: acme/shared/.github/workflows/agent.yml@main\n",
			fires: true, wantFact: "calls",
			why: "the caller side of a centralised invocation; counting leaves would " +
				"report 200 agents for one",
		},
		{
			name: "NEAR-MISS/ordinary marketplace action", ruleID: "workflow.reusable-and-composite",
			path: ".github/workflows/plain.yml",
			body: "on:\n  push:\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n" +
				"      - uses: actions/setup-node@v4\n",
			fires: false,
			why: "a marketplace action step is not a reusable workflow or a local " +
				"composite action; treating it as one would flag every repository on GitHub",
		},
		{
			name: "ADVERSARIAL/composite definition with no calls", ruleID: "workflow.reusable-and-composite",
			path:  "action.yml",
			body:  "name: shared-agent\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n",
			fires: true, wantFact: "composite_action_definition",
			why: "a definition is recorded even with no visible callers, because its " +
				"callers may live in repositories we were never granted",
		},

		// ---- workflow.self-hosted-runner -----------------------------------
		{
			name: "TP/self-hosted runner", ruleID: "workflow.self-hosted-runner",
			path: ".github/workflows/agent.yml",
			body: "on:\n  push:\njobs:\n  x:\n    runs-on: self-hosted\n    steps:\n" +
				"      - uses: anthropics/claude-code-action@v1\n",
			fires: true, wantFact: "severity_modifier",
			why: "the agent runs inside the customer network, which changes the " +
				"severity of every other finding in the same file",
		},
		{
			name: "NEAR-MISS/github-hosted runner", ruleID: "workflow.self-hosted-runner",
			path: ".github/workflows/agent.yml",
			body: "on:\n  push:\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n" +
				"      - uses: anthropics/claude-code-action@v1\n",
			fires: false,
			why: "a GitHub-hosted runner carries no such context; firing here would " +
				"add severity to every workflow in existence",
		},
		{
			name: "ADVERSARIAL/label array form", ruleID: "workflow.self-hosted-runner",
			path:  ".github/workflows/agent.yml",
			body:  "on:\n  push:\njobs:\n  x:\n    runs-on: [self-hosted, linux, x64]\n",
			fires: true,
			why:   "the array form is common in real repositories and must not be a blind spot",
		},

		// ---- manifest.agent-declaration ------------------------------------
		{
			name: "TP/agent manifest", ruleID: "manifest.agent-declaration",
			path:  "agent.json",
			body:  `{"name":"triage","model":"gpt-4o","instructions":"you are a triage agent"}`,
			fires: true, wantFact: "prompt_present",
			why: "a manifest is an explicit declaration; the prompt's existence is evidence",
			// The instruction TEXT must never survive into the facts.
			forbidden: "you are a triage agent",
		},
		{
			name: "NEAR-MISS/malformed json", ruleID: "manifest.agent-declaration",
			path: "agent.json", body: `{"name":"broken",,,}`,
			fires: false,
			why: "a file we cannot parse yields no facts. Guessing at a malformed " +
				"declaration would invent inventory",
		},
		{
			name: "ADVERSARIAL/nested credential in tools", ruleID: "manifest.agent-declaration",
			path:  "agent.json",
			body:  `{"name":"billing","tools":[{"name":"db","apiKey":"sk-live-LEAK"}]}`,
			fires: true, forbidden: "sk-live-LEAK",
			why: "fires, and the credential is stripped at depth. This is the case that " +
				"used to persist a live key because SensitiveKeys was never enforced",
		},

		// ---- manifest.mcp-server-config ------------------------------------
		{
			name: "TP/mcpServers map", ruleID: "manifest.mcp-server-config",
			path:  ".mcp.json",
			body:  `{"mcpServers":{"fs":{"command":"npx","env":{"ROOT_TOKEN":"x"}}}}`,
			fires: true, forbidden: `"x"`,
			why: "an MCP config is the closest thing in a repository to an entitlement " +
				"grant: a literal list of what the agent may touch",
		},
		{
			name: "NEAR-MISS/settings file with no MCP block", ruleID: "manifest.mcp-server-config",
			path: ".claude/settings.json", body: `{"theme":"dark","fontSize":13}`,
			fires: false,
			why: "the glob claims every settings file, so the content test is what " +
				"prevents an editor preference from becoming an agent",
		},
		{
			name: "ADVERSARIAL/alternate servers key", ruleID: "manifest.mcp-server-config",
			path: ".vscode/mcp.json", body: `{"servers":{"db":{"url":"http://localhost:1"}}}`,
			fires: true,
			why: "clients disagree on the key name; supporting only mcpServers would " +
				"miss half the ecosystem",
		},

		// ---- container.dockerfile ------------------------------------------
		{
			name: "TP/installs an agent framework", ruleID: "container.dockerfile",
			path:  "Dockerfile",
			body:  "FROM python:3.12-slim\nRUN pip install langchain langgraph\nENV OPENAI_API_KEY=x\n",
			fires: true, wantFact: "declared_frameworks",
			why: "an install line is a declaration of capability inside a shipped image",
		},
		{
			name: "NEAR-MISS/ordinary web app", ruleID: "container.dockerfile",
			path: "Dockerfile", body: "FROM python:3.12-slim\nRUN pip install flask gunicorn\n",
			fires: false,
			why:   "no agent framework; a web app must not appear in an agent inventory",
		},
		{
			name: "ADVERSARIAL/framework baked into a private base image", ruleID: "container.dockerfile",
			path: "Dockerfile", body: "FROM internal-registry/ml-base:2024\nCMD [\"python\",\"main.py\"]\n",
			fires: false,
			why: "DOCUMENTED BLIND SPOT, asserted so it stays honest: a framework " +
				"installed at build time into a generically-named image is invisible to " +
				"static analysis and closes only with runtime evidence",
		},

		// ---- container.compose --------------------------------------------
		{
			name: "TP/self-hosted model server", ruleID: "container.compose",
			path:  "docker-compose.yml",
			body:  "services:\n  llm:\n    image: ollama/ollama:latest\n",
			fires: true, wantFact: "declared_frameworks",
			why: "compose files are where self-hosted model servers actually appear",
		},
		{
			name: "NEAR-MISS/database and cache only", ruleID: "container.compose",
			path:  "docker-compose.yml",
			body:  "services:\n  db:\n    image: postgres:16\n  cache:\n    image: redis:7\n",
			fires: false, why: "infrastructure is not an agent",
		},
		{
			name: "ADVERSARIAL/framework named only in a comment", ruleID: "container.compose",
			path:  "docker-compose.yml",
			body:  "# was running vllm here before\nservices:\n  web:\n    image: nginx\n",
			fires: true,
			why: "KNOWN OVER-MATCH, recorded deliberately: matching is case-insensitive " +
				"substring, so a commented-out framework still fires. Documented in the " +
				"catalogue so a customer who finds it trusts us more, not less",
		},

		// ---- dependency.python / node / go --------------------------------
		{
			name: "TP/langchain in requirements", ruleID: "dependency.python",
			path: "requirements.txt", body: "flask==3.0.0\nlangchain==0.2.1\n",
			fires: true, wantFact: "requires_corroboration",
			why: "weak alone and labelled as such in its own output: a dependency " +
				"proves capability, not use",
		},
		{
			name: "NEAR-MISS/plain python app", ruleID: "dependency.python",
			path: "requirements.txt", body: "flask==3.0.0\nrequests==2.32.0\n",
			fires: false, why: "no agent framework present",
		},
		{
			name: "ADVERSARIAL/framework as a dev-only dependency", ruleID: "dependency.python",
			path:  "pyproject.toml",
			body:  "[tool.poetry.group.dev.dependencies]\nlangchain = \"^0.2\"\n",
			fires: true,
			why: "fires at LOW. A dev dependency may be imported by nothing, which is " +
				"precisely why one LOW signal is a candidate and never an agent",
		},
		{
			name: "TP/agent sdk in package.json", ruleID: "dependency.node",
			path:  "package.json",
			body:  `{"dependencies":{"@anthropic-ai/claude-code":"^1.0.0","react":"^18"}}`,
			fires: true, why: "the node ecosystem's equivalent weak signal",
		},
		{
			name: "NEAR-MISS/ordinary frontend", ruleID: "dependency.node",
			path: "package.json", body: `{"dependencies":{"react":"^18","vite":"^5"}}`,
			fires: false, why: "no agent framework present",
		},
		{
			name: "ADVERSARIAL/vendored dependency manifest", ruleID: "dependency.node",
			path:  "node_modules/some-pkg/package.json",
			body:  `{"dependencies":{"langchain":"^0.2"}}`,
			fires: false,
			why: "vendored paths are skipped before any rule runs. Without that guard a " +
				"repository committing its dependencies would cost thousands of blob " +
				"fetches and fill the inventory with findings about libraries",
		},
		{
			name: "TP/agent framework in go.mod", ruleID: "dependency.go",
			path: "go.mod", body: "module x\n\nrequire github.com/tmc/langchaingo v0.1.0\n",
			fires: true, why: "the go ecosystem's equivalent weak signal",
		},
		{
			name: "NEAR-MISS/ordinary go service", ruleID: "dependency.go",
			path: "go.mod", body: "module x\n\nrequire github.com/gin-gonic/gin v1.10.0\n",
			fires: false, why: "no agent framework present",
		},
		{
			name: "ADVERSARIAL/framework named in go.sum only", ruleID: "dependency.go",
			path: "go.sum", body: "github.com/tmc/langchaingo v0.1.0 h1:abc=\n",
			fires: true,
			why:   "a lockfile entry is still a declaration of what the build pulls in",
		},

		// ---- iac.terraform ------------------------------------------------
		{
			name: "TP/bedrock agent with an IAM role", ruleID: "iac.terraform",
			path: "infra/agent.tf",
			body: "resource \"aws_bedrock_agent\" \"triage\" {\n  name = \"triage\"\n" +
				"  agent_resource_role_arn = aws_iam_role.agent.arn\n}\n",
			fires: true, wantFact: "identity_references",
			why: "the IAM reference is the highest-value extraction here: it names the " +
				"identity the agent will actually run as, which is the join to IGA",
		},
		{
			name: "NEAR-MISS/ordinary infrastructure", ruleID: "iac.terraform",
			path:  "infra/vpc.tf",
			body:  "resource \"aws_vpc\" \"main\" {\n  cidr_block = \"10.0.0.0/16\"\n}\n",
			fires: false, why: "a VPC is not an agent",
		},
		{
			name: "ADVERSARIAL/module reference only", ruleID: "iac.terraform",
			path:  "infra/main.tf",
			body:  "module \"vertex\" {\n  source = \"./modules/google_vertex_ai\"\n}\n",
			fires: true,
			why: "a module source naming a managed AI service is an explicit deployment " +
				"declaration even though the resource block lives elsewhere",
		},

		// ---- iac.kubernetes-in-repo ---------------------------------------
		{
			name: "TP/deployment with a service account", ruleID: "iac.kubernetes-in-repo",
			path: "k8s/agent.yaml",
			body: "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: triage-agent\n" +
				"spec:\n  template:\n    spec:\n      serviceAccountName: triage-sa\n" +
				"      containers:\n        - image: ollama/ollama:latest\n",
			fires: true, wantFact: "correlation_hook",
			why: "THE CORRELATION HOOK. What this reports as declared is what the " +
				"cluster collector later reports as observed",
		},
		{
			name: "NEAR-MISS/plain service manifest", ruleID: "iac.kubernetes-in-repo",
			path:  "k8s/svc.yaml",
			body:  "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\n",
			fires: false, why: "a Service with no agent framework is ordinary infrastructure",
		},
		{
			name: "ADVERSARIAL/yaml that is not a manifest", ruleID: "iac.kubernetes-in-repo",
			path: "k8s/notes.yaml", body: "notes:\n  - we run ollama in prod\n",
			fires: false,
			why: "the shape check (apiVersion + kind) is what stops this rule claiming " +
				"every YAML file in the directory",
		},

		// ---- iac.helm-values ----------------------------------------------
		{
			name: "TP/values naming a framework image", ruleID: "iac.helm-values",
			path:  "values.yaml",
			body:  "image:\n  repository: ollama/ollama\n  tag: latest\n",
			fires: true, wantFact: "image_repository",
			why: "chart values are where the deployed image is actually chosen",
		},
		{
			name: "NEAR-MISS/ordinary chart values", ruleID: "iac.helm-values",
			path: "values.yaml", body: "image:\n  repository: nginx\n  tag: 1.27\n",
			fires: false, why: "no agent framework present",
		},
		{
			name: "ADVERSARIAL/framework in a disabled block", ruleID: "iac.helm-values",
			path:  "values.yaml",
			body:  "agent:\n  enabled: false\n  image:\n    repository: vllm/vllm-openai\n",
			fires: true,
			why: "fires, and correctly: a declaration exists. Whether it is enabled is " +
				"runtime state, which repository evidence can never establish",
		},

		// ---- secret.reference ---------------------------------------------
		{
			name: "TP/provider credential name", ruleID: "secret.reference",
			path: ".env.example", body: "ANTHROPIC_API_KEY=\nDATABASE_URL=\n",
			fires: true, wantFact: "provider_secret_names",
			why: "a provider-specific name is worth more than a generic one, though " +
				"still LOW until something corroborates it",
		},
		{
			name: "NEAR-MISS/no credential-shaped names", ruleID: "secret.reference",
			path: ".env.example", body: "PORT=8080\nLOG_LEVEL=debug\n",
			fires: false, why: "nothing here looks like a credential reference",
		},
		{
			name: "ADVERSARIAL/generic names only", ruleID: "secret.reference",
			path: ".env.example", body: "API_TOKEN=\nAPP_SECRET=\n",
			fires: true, wantFact: "noise_risk",
			why: "fires but marks itself high-noise: bare generics match ordinary " +
				"applications, so the row says so rather than pretending to be a finding",
		},
	}
}

// Every rule in the catalogue has at least three fixtures, and every fixture
// behaves as recorded.
func TestRuleCatalogueFixtures(t *testing.T) {
	cat := DefaultRuleCatalog()
	byID := map[string]IGARule{}
	for _, r := range cat.Rules {
		byID[r.ID] = r
	}

	for _, fx := range fixtures() {
		t.Run(fx.ruleID+"/"+fx.name, func(t *testing.T) {
			rule, ok := byID[fx.ruleID]
			if !ok {
				t.Fatalf("fixture names rule %q which is not in catalogue %s",
					fx.ruleID, cat.Version)
			}
			// The rule must actually claim this path, or the fixture is testing
			// nothing. A vendored path is the deliberate exception.
			claims := false
			for _, r := range cat.MatchRules(fx.path) {
				if r.ID == fx.ruleID {
					claims = true
				}
			}
			if !claims {
				if fx.fires {
					t.Fatalf("rule %s does not claim path %q, so it can never fire there",
						fx.ruleID, fx.path)
				}
				t.Logf("PASS (not claimed): %s — %s", fx.path, fx.why)
				return
			}

			facts, _, err := rule.ExtractRedacted(fx.path, []byte(fx.body))
			fired := err == nil && facts != nil

			if fired != fx.fires {
				t.Fatalf("expected fires=%v, got %v (err=%v)\nwhy: %s\nfacts: %v",
					fx.fires, fired, err, fx.why, facts)
			}
			if !fired {
				t.Logf("PASS (correctly silent): %s", fx.why)
				return
			}
			if fx.wantFact != "" {
				if _, ok := facts[fx.wantFact]; !ok {
					t.Fatalf("expected fact %q in %v", fx.wantFact, facts)
				}
			}
			if fx.forbidden != "" {
				blob, _ := json.Marshal(facts)
				if strings.Contains(string(blob), fx.forbidden) {
					t.Fatalf("FORBIDDEN CONTENT PERSISTED (%q): %s", fx.forbidden, blob)
				}
			}
			t.Logf("PASS: %s", fx.why)
		})
	}
}

// Coverage of the fixture suite itself: no rule may ship without its three
// cases, because an unfixtured rule is an unmeasured coverage claim.
func TestEveryRuleHasThreeFixtures(t *testing.T) {
	counts := map[string]int{}
	for _, fx := range fixtures() {
		counts[fx.ruleID]++
	}
	cat := DefaultRuleCatalog()
	var thin []string
	for _, r := range cat.Rules {
		if counts[r.ID] < 3 {
			thin = append(thin, r.ID)
		}
	}
	if len(thin) > 0 {
		t.Fatalf("catalogue %s: these rules have fewer than 3 fixtures: %v",
			cat.Version, thin)
	}
	t.Logf("PASS: catalogue %s — %d rules, %d fixtures, all rules >= 3",
		cat.Version, len(cat.Rules), len(fixtures()))
}

// The combination rule, which decides what may be COUNTED.
func TestCombinationRule(t *testing.T) {
	cases := []struct {
		name    string
		signals []RuleSignal
		want    string
		counts  bool
	}{
		{
			name:    "one low is a candidate, never an agent",
			signals: []RuleSignal{{RuleID: "dependency.python", Confidence: ConfidenceLow}},
			want:    ConfidenceLow, counts: false,
		},
		{
			name: "two INDEPENDENT lows corroborate to medium",
			signals: []RuleSignal{
				{RuleID: "dependency.python", Confidence: ConfidenceLow},
				{RuleID: "secret.reference", Confidence: ConfidenceLow},
			},
			want: ConfidenceMedium, counts: false,
		},
		{
			name: "two matches of the SAME rule are one signal",
			signals: []RuleSignal{
				{RuleID: "dependency.python", Confidence: ConfidenceLow, Path: "a/requirements.txt"},
				{RuleID: "dependency.python", Confidence: ConfidenceLow, Path: "b/requirements.txt"},
			},
			want: ConfidenceLow, counts: false,
		},
		{
			name: "high wins outright and may be counted",
			signals: []RuleSignal{
				{RuleID: "dependency.python", Confidence: ConfidenceLow},
				{RuleID: "manifest.agent-declaration", Confidence: ConfidenceHigh},
			},
			want: ConfidenceHigh, counts: true,
		},
		{
			name:    "medium alone is still not countable",
			signals: []RuleSignal{{RuleID: "iac.terraform", Confidence: ConfidenceMedium}},
			want:    ConfidenceMedium, counts: false,
		},
		{name: "no signals", signals: nil, want: "", counts: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CombineConfidence(c.signals)
			if got != c.want {
				t.Fatalf("expected %q, got %q", c.want, got)
			}
			if CountsAsAgent(got) != c.counts {
				t.Fatalf("expected countable=%v for %q", c.counts, got)
			}
			t.Logf("PASS: %q -> countable=%v", got, c.counts)
		})
	}
}
