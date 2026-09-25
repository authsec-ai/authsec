package igagraph

import (
	"encoding/json"
	"testing"

	"github.com/authsec-ai/authsec/models"
)

// workloadProviderAttrs copies the collected workload's display facts (D-85)
// and nothing else; a list is written empty only where empty is a collected
// answer, and a list this scan did not read (variables returned as an error,
// a gateway target list not read in full) is left out -- unknown, never empty
// and never the last list kept. The rescan path is proven end to end in
// tests/integration/p2_wdetail_detail_test.go.
func TestP2WdetailWorkloadProviderAttrs(t *testing.T) {
	attrs := func(kind string, a models.AWSWorkloadAttrs) map[string]any {
		t.Helper()
		cw := models.CloudWorkload{RuntimeKind: kind}
		if err := cw.SetAWSAttrs(a); err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(workloadProviderAttrs(cw), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	lam := attrs(models.WorkloadLambdaFunction, models.AWSWorkloadAttrs{
		Status: "Active", EnvVarNames: []string{"A"}, ExecutionRoleARN: "arn:aws:iam::1:role/r",
		UnresolvedRoleARN: "arn:aws:iam::1:role/x", DetailError: "boom"})
	if len(lam) != 2 || lam["status"] != "Active" || len(lam["env_var_names"].([]any)) != 1 {
		t.Errorf("lambda = %v, want status and env_var_names only: never a role, an error or anything else", lam)
	}
	if names, ok := attrs(models.WorkloadLambdaFunction, models.AWSWorkloadAttrs{})["env_var_names"].([]any); !ok || len(names) != 0 {
		t.Errorf("a Lambda with no variables = %v, want env_var_names [] (listed, none)", names)
	}
	if _, ok := attrs(models.WorkloadECSTaskDefinition, models.AWSWorkloadAttrs{Status: "ACTIVE"})["env_var_names"]; ok {
		t.Error("an ECS task definition got env_var_names: nothing collected them for that kind")
	}
	// AWS returned the environment as an error (e.g. KMS): nothing was read,
	// so the names are unknown -- absent, never [] ("has none").
	if v, ok := attrs(models.WorkloadLambdaFunction, models.AWSWorkloadAttrs{Status: "Active", EnvVarsUnread: true})["env_var_names"]; ok {
		t.Errorf("a Lambda whose variables were NOT read = %v, want env_var_names absent (unknown), never []", v)
	}

	agent := attrs(models.WorkloadBedrockAgent, models.AWSWorkloadAttrs{Status: "PREPARED", FoundationModel: "m"})
	if agent["foundation_model"] != "m" || agent["status"] != "PREPARED" || agent["gateway_targets"] != nil {
		t.Errorf("bedrock agent = %v", agent)
	}

	gw := func(a models.AWSWorkloadAttrs) (any, bool) {
		v, ok := attrs(models.WorkloadBedrockAgentCoreGW, a)["gateway_targets"]
		return v, ok
	}
	target := models.AWSGatewayTarget{TargetID: "t", Name: "n", Status: "READY", Type: "LAMBDA"}
	if v, ok := gw(models.AWSWorkloadAttrs{GatewayTargets: []models.AWSGatewayTarget{target}}); !ok || len(v.([]any)) != 1 {
		t.Errorf("a read target list = %v", v)
	}
	if v, ok := gw(models.AWSWorkloadAttrs{}); !ok || len(v.([]any)) != 0 {
		t.Errorf("a target list read in full with none = %v (present %v), want []", v, ok)
	}
	if v, ok := gw(models.AWSWorkloadAttrs{TargetsIncomplete: true}); ok {
		t.Errorf("an UNREAD target list = %v, want absent (unknown), never []", v)
	}
	// The collector keeps its last complete list when ListGatewayTargets
	// fails; this scan did not confirm it, so it is not shown as current.
	if v, ok := gw(models.AWSWorkloadAttrs{TargetsIncomplete: true, GatewayTargets: []models.AWSGatewayTarget{target}}); ok {
		t.Errorf("an unread list with the kept previous targets = %v, want absent (not read this scan), never the old list", v)
	}
}
