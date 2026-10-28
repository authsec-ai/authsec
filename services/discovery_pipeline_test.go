package services

import "testing"

func TestNginxHolds(t *testing.T) {
	d := Classify(Observation{
		Image:        "nginx:1.27",
		WorkloadName: "invoice-worker",
		Namespace:    "payments",
	})
	if d.Decision != decisionHold || d.Confidence != confidenceNone {
		t.Fatalf("nginx should be held at none, got %+v", d)
	}
	if d.LogicalKey != "" {
		t.Fatalf("nginx must not get a merge key, got %q", d.LogicalKey)
	}
	if d.Kind != "k8s.workload" {
		t.Fatalf("kind = %q, want k8s.workload", d.Kind)
	}
}

func TestLangchainImagePromotes(t *testing.T) {
	d := Classify(Observation{
		Image:        "authsec/langchain-sample-agent:local",
		WorkloadName: "langchain-sample-agent",
		Namespace:    "agents",
	})
	if d.Decision != decisionPromote || d.Confidence != confidenceHigh {
		t.Fatalf("langchain image should promote at high, got %+v", d)
	}
	if d.LogicalKey != "agent:langchain:langchain-sample-agent" {
		t.Fatalf("logical key = %q", d.LogicalKey)
	}
	if !hasString(d.Frameworks, "langchain") {
		t.Fatalf("frameworks = %v", d.Frameworks)
	}
}

func TestBarePythonHolds(t *testing.T) {
	d := Classify(Observation{Exe: "/usr/bin/python3"})
	if d.Decision != decisionHold || d.Kind != "python.process" {
		t.Fatalf("bare python should be a held python process, got %+v", d)
	}
	if d.LogicalKey != "" {
		t.Fatalf("bare python must not merge, got %q", d.LogicalKey)
	}
	if !hasFilterReason(d, "Python process with no framework signal.") {
		t.Fatalf("reasons = %v", d.Reasons)
	}
}

func TestPythonModuleCrewAIPromotes(t *testing.T) {
	d := Classify(Observation{
		Exe:     "/usr/bin/python3",
		Argv:    []string{"python3", "-m", "crewai"},
		Command: "python3 -m crewai",
	})
	if d.Decision != decisionPromote || d.Confidence != confidenceMedium {
		t.Fatalf("python -m crewai should promote at medium, got %+v", d)
	}
	if d.LogicalKey != "agent:crewai:crewai" {
		t.Fatalf("logical key = %q", d.LogicalKey)
	}
	if d.Kind != "python.process" {
		t.Fatalf("kind = %q", d.Kind)
	}
}

func TestShortTokenBoundary(t *testing.T) {
	inside := []Observation{
		{Image: "acme/precursor:1", WorkloadName: "precursor"},
		{Command: "foodspy run", Exe: "/usr/bin/foodspy"},
		{Image: "acme/claudette:1", WorkloadName: "claudette"},
	}
	for _, o := range inside {
		d := Classify(o)
		if d.Confidence != confidenceNone || d.Decision != decisionHold {
			t.Fatalf("%+v matched a short token: %+v", o, d)
		}
	}

	hit := Classify(Observation{Image: "acme/claude-runner:1", WorkloadName: "claude-runner"})
	if hit.Decision != decisionPromote || !hasString(hit.Frameworks, "claude") {
		t.Fatalf("claude-runner should match the claude token on a boundary, got %+v", hit)
	}
	if hit.LogicalKey != "agent:claude:claude-runner" {
		t.Fatalf("logical key = %q", hit.LogicalKey)
	}
}

func TestGenericProviderKeyHolds(t *testing.T) {
	d := Classify(Observation{
		Image:        "payments-api:1",
		WorkloadName: "payments-api",
		EnvKeys:      []string{"OPENAI_API_KEY"},
	})
	if d.Decision != decisionHold || d.Confidence != confidenceLow {
		t.Fatalf("a generic API key alone must be held, got %+v", d)
	}
	if d.LogicalKey != "" {
		t.Fatalf("provider key must not merge, got %q", d.LogicalKey)
	}
}

func TestMissingDetectionDoesNotHold(t *testing.T) {
	if detectionHolds(nil) {
		t.Fatal("nil metadata is a legacy sighting and must still promote")
	}
	if detectionHolds(map[string]interface{}{"image": map[string]interface{}{"full": "nginx:1.27"}}) {
		t.Fatal("a sighting with no detection block must still promote")
	}
	none := map[string]interface{}{"detection": map[string]interface{}{"confidence": "none", "signals": []interface{}{}}}
	if !detectionHolds(none) {
		t.Fatal("confidence none is a hold")
	}
	low := map[string]interface{}{"detection": map[string]interface{}{"confidence": "low"}}
	if !detectionHolds(low) {
		t.Fatal("confidence low is a hold")
	}
	empty := map[string]interface{}{"detection": map[string]interface{}{"confidence": ""}}
	if !detectionHolds(empty) {
		t.Fatal("an empty confidence means the connector looked and found nothing")
	}
	if detectionHolds(map[string]interface{}{"detection": map[string]interface{}{"confidence": "high"}}) {
		t.Fatal("high promotes")
	}
	if detectionHolds(map[string]interface{}{"detection": map[string]interface{}{"confidence": "medium"}}) {
		t.Fatal("medium promotes")
	}
}

func TestContainerWithoutFrameworkHolds(t *testing.T) {
	d := Classify(Observation{Exe: "/usr/sbin/nginx", ContainerID: "abc"})
	if d.Kind != "docker.container" || d.Decision != decisionHold {
		t.Fatalf("container without a framework should be held, got %+v", d)
	}
	if !hasFilterReason(d, "Container with no framework signal.") {
		t.Fatalf("reasons = %v", d.Reasons)
	}
}

func hasString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func hasFilterReason(d FilterDecision, want string) bool {
	for _, r := range d.Reasons {
		if r == want {
			return true
		}
	}
	return false
}
