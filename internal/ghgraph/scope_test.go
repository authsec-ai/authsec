package ghgraph

import (
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// A partition key reads back to the partition that wrote it, whatever the
// repository id looks like -- a misparsed key would end the wrong class.
func TestPartitionKeyRoundTrip(t *testing.T) {
	integ := uuid.New()
	for _, p := range []Partition{
		{IntegrationID: integ, Class: ClassInstallation},
		{IntegrationID: integ, Repo: "R_kgDOabc", Class: ClassDeployKey},
		{IntegrationID: integ, Repo: "odd|repo|id", Class: ClassWorkflow},
	} {
		got, ok := ParsePartition(p.Key())
		if !ok || got != p {
			t.Fatalf("ParsePartition(%q) = %+v %v, want %+v", p.Key(), got, ok, p)
		}
	}
	for _, bad := range []string{"", "not-a-uuid|r|c", "only-one|"} {
		if _, ok := ParsePartition(bad); ok {
			t.Fatalf("ParsePartition(%q) accepted a key this package never writes", bad)
		}
	}
}

// CanEnd: only a succeeded scan ends anything, and then only what it read in
// full -- or a repository its listing no longer returned.
func TestCanEnd(t *testing.T) {
	integ, other := uuid.New(), uuid.New()
	s := Scope{IntegrationID: integ, Succeeded: true, Repos: map[string]map[string]string{
		"R1": {ClassDeployKey: models.CoveragePartial, ClassWorkflow: models.CoverageComplete},
	}}
	for _, c := range []struct {
		p    Partition
		want bool
	}{
		{Partition{IntegrationID: integ, Repo: "R1", Class: ClassDeployKey}, false},   // read failed
		{Partition{IntegrationID: integ, Repo: "R1", Class: ClassWorkflow}, true},     // read in full
		{Partition{IntegrationID: integ, Repo: "R1", Class: ClassCopilotAgent}, true}, // listed nothing
		{Partition{IntegrationID: integ, Repo: "R1", Class: ClassRepository}, true},
		{Partition{IntegrationID: integ, Repo: "R9", Class: ClassDeployKey}, true}, // dropped from the listing
		{Partition{IntegrationID: integ, Class: ClassInstallation}, true},
		{Partition{IntegrationID: other, Repo: "R9", Class: ClassDeployKey}, false}, // not this integration's
	} {
		if got := s.CanEnd(c.p); got != c.want {
			t.Errorf("CanEnd(%+v) = %v, want %v", c.p, got, c.want)
		}
	}
	s.Succeeded = false
	if s.CanEnd(Partition{IntegrationID: integ, Repo: "R9", Class: ClassDeployKey}) {
		t.Fatal("a failed scan ended a partition")
	}
}

// Keys start with the provider, use the shared separator, and never collide
// across kinds.
func TestKeys(t *testing.T) {
	keys := []string{
		RepositoryKey("github.com", "1"), InstallationKey("github.com", "1"),
		DeployKeyKey("github.com", "1"), DeployKeyCredentialKey("github.com", "1"),
		DeployKeyGrantKey("github.com", "1"), CopilotAgentKey("github.com", "1", "1"),
		WorkflowKey("github.com", "1", "1"), DeclaredAgentKey("github.com", "1"),
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if !strings.HasPrefix(k, "github"+Sep+"github.com"+Sep) || seen[k] {
			t.Fatalf("bad or duplicate key %q", k)
		}
		seen[k] = true
	}
}
