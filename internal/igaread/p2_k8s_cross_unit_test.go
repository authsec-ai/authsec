package igaread

// Unit tests for the pure parts of the cross-provider and Kubernetes
// hardening reads (traverse_cross.go, traverse_k8s.go; D-108..D-111).

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/models"
)

func TestGraphK8sImplicitGroup(t *testing.T) {
	group := func(name string) string {
		return k8sgraph.SubjectKey("c1", models.K8sSubject{Kind: models.K8sSubjectGroup, Name: name})
	}
	for key, want := range map[string]bool{
		group("system:serviceaccounts"):      true,
		group("system:serviceaccounts:shop"): true,
		group("system:authenticated"):        true,
		group("system:masters"):              false,
		group("system:unauthenticated"):      false,
		group("system:serviceaccountsX"):     false,
		k8sgraph.SubjectKey("c1", models.K8sSubject{Kind: models.K8sSubjectUser, Name: "system:authenticated"}): false,
		k8sgraph.ServiceAccountKey("c1", "shop", "checkout"):                                                    false,
		"": false,
	} {
		if got := graphK8sImplicitGroup(key); got != want {
			t.Errorf("graphK8sImplicitGroup(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestGraphSideAndKinds(t *testing.T) {
	aws, k8s, ext := &GraphNode{provider: models.ProviderAWS}, &GraphNode{provider: models.ProviderK8s}, &GraphNode{}
	if aws.side() != models.ProviderAWS || k8s.side() != models.ProviderK8s || ext.side() != models.ProviderAWS {
		t.Errorf("sides = %s %s %s", aws.side(), k8s.side(), ext.side())
	}
	for _, k := range graphEdgeKinds {
		if !graphSideHasKind(models.ProviderAWS, k) {
			t.Errorf("AWS lacks %s", k)
		}
	}
	for k, want := range map[string]bool{
		GraphEdgeExecutesAs: true, GraphEdgeGrant: true, GraphEdgeMemberOf: true,
		GraphEdgeCanAssume: false, GraphEdgeTarget: false, GraphEdgeTaskExecutionRole: false,
	} {
		if graphSideHasKind(models.ProviderK8s, k) != want {
			t.Errorf("k8s has %s = %v, want %v", k, !want, want)
		}
	}
	// can_assume leads out of a Kubernetes ServiceAccount only when a
	// principal resolves to it.
	sa, idle := uuid.New(), uuid.New()
	tr := &graphTraversal{cross: &graphCross{byIdentity: map[uuid.UUID][]uuid.UUID{sa: {uuid.New()}}}}
	kinds := func(id uuid.UUID, dir string) []string {
		return tr.kindsFor(&GraphNode{typ: RefIdentity, id: id, provider: models.ProviderK8s}, dir)
	}
	if got := kinds(sa, GraphForward); strings.Join(got, ",") != "can_assume,grant,member_of" {
		t.Errorf("resolved SA forward kinds = %v", got)
	}
	if got := kinds(idle, GraphForward); strings.Join(got, ",") != "grant,member_of" {
		t.Errorf("unresolved SA forward kinds = %v", got)
	}
	if got := kinds(sa, GraphReverse); strings.Join(got, ",") != "executes_as,member_of" {
		t.Errorf("SA reverse kinds = %v", got)
	}
	if got := (&graphTraversal{}).kindsFor(&GraphNode{typ: RefIdentity, id: sa, provider: models.ProviderK8s}, GraphForward); strings.Join(got, ",") != "grant,member_of" {
		t.Errorf("SA forward kinds with no resolutions read = %v", got)
	}
}
