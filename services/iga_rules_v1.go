package services

import "strings"

// Catalogue v1 extractors — the declaration sites added under AS-107.
//
// Split into their own file because the catalogue is the product's coverage
// claim: it is versioned, reviewed and rescanned as a unit, and keeping its
// rules together makes "what do we actually detect?" answerable by reading one
// file rather than grepping a 900-line provider.

// managedAIResourceTokens are provider-native managed AI resources. Their
// presence in IaC is an explicit deployment declaration, not an inference.
var managedAIResourceTokens = []string{
	"aws_bedrock", "bedrock_agent", "aws_sagemaker",
	"google_vertex_ai", "vertex_ai_endpoint",
	"azurerm_cognitive_account", "azure_openai",
}

// iamReferenceTokens name the identity a declared workload will run as.
//
// This is the highest-value extraction in the IaC rules: it is the join from a
// repository declaration to the identity side of IGA. A declared agent whose
// identity we can name is governable; one we cannot is just a file.
var iamReferenceTokens = []string{
	"aws_iam_role", "iam_instance_profile", "role_arn", "assume_role",
	"google_service_account", "service_account_email",
	"azurerm_user_assigned_identity", "managed_identity",
	"serviceaccountname", "service_account_name",
}

// extractTerraform reports an agent or managed-AI resource declared in HCL.
func extractTerraform(filePath string, body []byte) (map[string]interface{}, []string, error) {
	text := string(body)
	frameworks := containsAny(text, agentFrameworkTokens)
	managedAI := containsAny(text, managedAIResourceTokens)
	if len(frameworks) == 0 && len(managedAI) == 0 {
		return nil, nil, nil
	}
	facts := map[string]interface{}{
		"iac_kind":  "terraform",
		"iac_path":  filePath,
		"resources": iacResourceNames(text),
		"reason":    "agent framework or managed-AI resource declared in terraform",
	}
	if len(frameworks) > 0 {
		facts["frameworks"] = frameworks
	}
	if len(managedAI) > 0 {
		facts["managed_ai_resources"] = managedAI
	}
	if ids := containsAny(text, iamReferenceTokens); len(ids) > 0 {
		facts["identity_references"] = ids
	}
	return facts, collectSecretNames(text), nil
}

// extractKubernetesManifest is THE CORRELATION HOOK.
//
// The same manifest this rule reports as DECLARED is what the cluster collector
// later reports as OBSERVED. Matching the two is the shadow-agent detection the
// whole product is aimed at, and it only works while both channels recognise an
// agent by the same vocabulary — which is why this shares agentFrameworkTokens
// rather than keeping a list of its own. Diverge here and the hook silently
// stops matching, which reads to a customer as a product bug.
func extractKubernetesManifest(filePath string, body []byte) (map[string]interface{}, []string, error) {
	text := string(body)
	lower := strings.ToLower(text)
	// Shape check first: a YAML file is only a k8s manifest if it says so.
	// Without this the rule would claim every *.yaml in the repository.
	if !strings.Contains(lower, "apiversion:") || !strings.Contains(lower, "kind:") {
		return nil, nil, nil
	}
	frameworks := containsAny(text, agentFrameworkTokens)
	if len(frameworks) == 0 {
		return nil, nil, nil
	}
	facts := map[string]interface{}{
		"iac_kind":   "kubernetes",
		"iac_path":   filePath,
		"frameworks": frameworks,
		// Marked so a later correlation pass can find these rows without
		// re-parsing anything: this is the row the cluster collector may match.
		"correlation_hook": "kubernetes",
		"reason":           "in-repo kubernetes manifest declaring an agent framework",
	}
	if k := firstYAMLValue(text, "kind"); k != "" {
		facts["k8s_kind"] = k
	}
	if n := firstYAMLValue(text, "name"); n != "" {
		facts["name"] = n
	}
	if sa := firstYAMLValue(text, "serviceAccountName"); sa != "" {
		facts["service_account"] = sa
	}
	return facts, collectSecretNames(text), nil
}

// extractHelmValues reads image declarations from chart values.
func extractHelmValues(filePath string, body []byte) (map[string]interface{}, []string, error) {
	text := string(body)
	frameworks := containsAny(text, agentFrameworkTokens)
	if len(frameworks) == 0 {
		return nil, nil, nil
	}
	facts := map[string]interface{}{
		"iac_kind":   "helm",
		"iac_path":   filePath,
		"frameworks": frameworks,
		"reason":     "helm values declare an agent framework image",
	}
	if img := firstYAMLValue(text, "repository"); img != "" {
		facts["image_repository"] = img
	}
	return facts, collectSecretNames(text), nil
}

// extractSecretReference records model-provider credential NAMES.
//
// Provider-specific names score higher than generic suffixes on purpose: a bare
// API_KEY or TOKEN matches ordinary applications and produces exactly the noise
// that gets an inventory abandoned. Both are recorded — be permissive about
// what you RECORD — but only the specific ones carry weight, and even those are
// LOW until something corroborates them.
//
// Redaction is absolute here by construction: this rule reads names and never
// reaches for a value. A rule that could capture a value does not ship.
func extractSecretReference(filePath string, body []byte) (map[string]interface{}, []string, error) {
	names := collectSecretNames(string(body))
	if len(names) == 0 {
		return nil, nil, nil
	}
	var provider, generic []string
	for _, n := range names {
		up := strings.ToUpper(n)
		matched := false
		for _, p := range providerCredentialNames {
			if strings.Contains(up, p) {
				provider = append(provider, n)
				matched = true
				break
			}
		}
		if !matched {
			generic = append(generic, n)
		}
	}
	facts := map[string]interface{}{
		"secret_reference_path": filePath,
	}
	if len(generic) > 0 {
		facts["generic_secret_names"] = generic
	}
	if len(provider) == 0 {
		// The documented noise case. Named as such in the row itself so a
		// reviewer sees why it is weak without having to know the catalogue.
		facts["reason"] = "only generic credential names; these match ordinary applications too"
		facts["noise_risk"] = "high"
		return facts, names, nil
	}
	facts["provider_secret_names"] = provider
	facts["reason"] = "model-provider credential name referenced"
	return facts, names, nil
}

// extractReusableWorkflow records the CALLER side of a centralised invocation.
//
// Large orgs centralise agent invocation into one reusable workflow called from
// 200 repositories. Count the leaves and you report 200 agents; count only the
// definition and you report one. Both are wrong. This rule records the EDGE and
// leaves the counting decision to correlation, where both ends are visible.
func extractReusableWorkflow(filePath string, body []byte) (map[string]interface{}, []string, error) {
	text := string(body)
	refs := reusableWorkflowRefs(text)
	isDefinition := strings.HasSuffix(filePath, "action.yml") || strings.HasSuffix(filePath, "action.yaml")
	if len(refs) == 0 && !isDefinition {
		return nil, nil, nil
	}
	facts := map[string]interface{}{
		"workflow_path": filePath,
		"reason":        "workflow calls a reusable workflow or local composite action",
	}
	if len(refs) > 0 {
		facts["calls"] = refs
		// Stated in the row: the callee may live in a repository we were never
		// granted, in which case it resolves to unknown — and unknown must be
		// reported as unknown, never as clean.
		facts["target_resolution"] = "unresolved"
	}
	if isDefinition {
		facts["composite_action_definition"] = true
		facts["reason"] = "composite action definition; callers may live in repositories we cannot read"
	}
	return facts, collectSecretNames(text), nil
}

// extractSelfHostedRunner is CONTEXT, not detection.
//
// A self-hosted runner means the agent executes inside the customer's own
// network with whatever that host can reach, which changes the severity of
// every other finding in the same file. It never proposes an agent by itself,
// which is why it is LOW and why its facts say so explicitly.
func extractSelfHostedRunner(filePath string, body []byte) (map[string]interface{}, []string, error) {
	lower := strings.ToLower(string(body))
	if !strings.Contains(lower, "runs-on:") || !strings.Contains(lower, "self-hosted") {
		return nil, nil, nil
	}
	return map[string]interface{}{
		"workflow_path":     filePath,
		"runner":            "self-hosted",
		"severity_modifier": true,
		"detection":         false,
		"reason": "steps in this file execute inside the customer network, " +
			"reaching whatever that host can reach",
	}, nil, nil
}

/* ------------------------- extractor helpers ---------------------------- */

// iacResourceNames pulls terraform resource/module names without a full HCL
// parse. Best-effort by design: detection has already happened before this is
// called, so a missed name costs a less descriptive row, never a missed finding.
func iacResourceNames(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "resource ") && !strings.HasPrefix(trimmed, "module ") {
			continue
		}
		fields := strings.FieldsFunc(trimmed, func(r rune) bool {
			return r == '"' || r == ' ' || r == '{'
		})
		var parts []string
		for _, f := range fields {
			if f != "" {
				parts = append(parts, f)
			}
			if len(parts) == 3 {
				break
			}
		}
		if len(parts) < 2 {
			continue
		}
		name := strings.Join(parts, ".")
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
		// Bounded: a row is evidence, not a copy of the file.
		if len(out) >= 25 {
			break
		}
	}
	return out
}

// firstYAMLValue reads the first scalar value for a key, without a YAML parse.
// Deliberately shallow: these facts are descriptive only, and a wrong guess
// must never change whether something was detected.
func firstYAMLValue(text, key string) string {
	lowerKey := strings.ToLower(key) + ":"
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(trimmed), lowerKey) {
			continue
		}
		v := strings.TrimSpace(trimmed[len(lowerKey):])
		v = strings.Trim(v, "\"'")
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		if len(v) > 200 {
			v = v[:200]
		}
		return v
	}
	return ""
}

// reusableWorkflowRefs finds `uses:` targets pointing at a reusable workflow or
// a local composite action, as opposed to an ordinary marketplace action step.
func reusableWorkflowRefs(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "uses:") {
			continue
		}
		ref := strings.TrimSpace(strings.TrimPrefix(trimmed, "uses:"))
		ref = strings.Trim(ref, "\"'")
		if ref == "" || seen[ref] {
			continue
		}
		isReusable := strings.Contains(ref, "/.github/workflows/")
		isLocal := strings.HasPrefix(ref, "./")
		if !isReusable && !isLocal {
			continue
		}
		seen[ref] = true
		out = append(out, ref)
		if len(out) >= 25 {
			break
		}
	}
	return out
}
