package igaread

// Unit tests for the Kubernetes traversal's pure parts (traverse_k8s.go): the
// coverage-gap rule over every sweep state, rule labels and group keys, and
// the provider rendering of every edge spec. The traversal itself is tested
// against real PostgreSQL in tests/integration/p2_k8s_graph_*_test.go.

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/internal/k8sread"
)

func TestP2K8sGraphCoverageGapRule(t *testing.T) {
	src, other := uuid.New(), uuid.New()
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	sweep := func(complete, clusterScoped bool, ns ...string) *k8sread.Sweep {
		return &k8sread.Sweep{Complete: complete, ClusterScoped: clusterScoped, Namespaces: ns, ObservedAt: at}
	}
	key := func(source uuid.UUID, cluster, ns string) string {
		return k8sgraph.Partition{SourceID: source, Cluster: cluster, Namespace: ns, Class: k8sgraph.ClassIdentity}.Key()
	}
	for _, tc := range []struct {
		name  string
		sweep *k8sread.Sweep
		key   string
		want  string // "" = no gap
	}{
		{"covered namespace", sweep(true, true, "a"), key(src, "c1", "a"), ""},
		{"covered cluster part", sweep(true, true, "a"), key(src, "c1", ""), ""},
		{"namespaced-only, namespaced row", sweep(true, false, "a"), key(src, "c1", "a"), ""},
		{"namespaced-only, cluster row", sweep(true, false, "a"), key(src, "c1", ""), K8sGapNamespacedOnly},
		{"namespace not read", sweep(true, true, "a"), key(src, "c1", "b"), K8sGapNamespaceNotSwept},
		{"incomplete", sweep(false, true, "a"), key(src, "c1", "a"), K8sGapIncomplete},
		{"incomplete beats scope", sweep(false, false), key(src, "c1", ""), K8sGapIncomplete},
		{"no sweep of this source", sweep(true, true, "a"), key(other, "c1", "a"), K8sGapNotSwept},
		{"no sweep of this cluster", sweep(true, true, "a"), key(src, "c2", "a"), K8sGapNotSwept},
		{"unattributed bare namespace", sweep(true, true, "a"), "a", K8sGapUnattributed},
		{"unattributed empty", sweep(true, true, "a"), "", K8sGapUnattributed},
	} {
		c := &graphK8sCoverage{sweeps: map[k8sread.SweepKey]*k8sread.Sweep{{SourceID: src, Cluster: "c1"}: tc.sweep}}
		g := c.gapOf(tc.key)
		switch {
		case tc.want == "" && g != nil:
			t.Errorf("%s: gap %+v, want none", tc.name, g)
		case tc.want != "" && (g == nil || g.state != tc.want):
			t.Errorf("%s: gap %+v, want %s", tc.name, g, tc.want)
		}
		if g == nil {
			continue
		}
		l := g.limitation()
		if l.Code() != LimK8sCoverageGap {
			t.Errorf("%s: code %q", tc.name, l.Code())
		}
		switch g.state {
		case K8sGapUnattributed:
			if l["cluster"] != nil || l["namespace"] != nil || l["observed_at"] != nil {
				t.Errorf("%s: %v, want nothing claimed of an unattributed row", tc.name, l)
			}
		case K8sGapNotSwept:
			if l["cluster"] == nil || l["observed_at"] != nil {
				t.Errorf("%s: %v, want the cluster and no sweep time", tc.name, l)
			}
		default:
			if l["observed_at"] != "2026-10-01T12:00:00Z" {
				t.Errorf("%s: observed_at %v", tc.name, l["observed_at"])
			}
		}
	}
}

func TestP2K8sGraphRuleLabelsAndKeys(t *testing.T) {
	for _, tc := range []struct {
		rule  GraphK8sRule
		label string
	}{
		{GraphK8sRule{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"secrets"}}, "get, list on secrets"},
		{GraphK8sRule{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}, "* on */*"},
		{GraphK8sRule{Verbs: []string{"get"}, APIGroups: []string{"apps"}, Resources: []string{"deployments"},
			ResourceNames: []string{"web"}}, "get on apps/deployments/web"},
		{GraphK8sRule{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz"}}, "get on /healthz"},
		{GraphK8sRule{Resources: []string{"pods"}}, "no verbs on pods"},
		{graphK8sParseRule(`{"verbs":["get"],"api_groups":[""],"resources":["pods"],"resource_names":null}`), "get on pods"},
	} {
		if got := graphK8sRuleLabel(tc.rule); got != tc.label {
			t.Errorf("label(%+v) = %q, want %q", tc.rule, got, tc.label)
		}
	}
	r := graphK8sParseRule(`{"verbs":["list","get"],"resources":["secrets"]}`)
	if r.APIGroups == nil || r.ResourceNames == nil || r.NonResourceURLs == nil {
		t.Errorf("parsed rule %+v: every list is [] when absent", r)
	}
	// One rule, three places: a ClusterRole's, a Role's in a and in b, and
	// another cluster's -- four keys. Verb order never matters.
	c1, c2 := &GraphScope{ID: "c1"}, &GraphScope{ID: "c2"}
	keys := map[string]bool{
		graphK8sGroupKey(r, c1, ""):  true,
		graphK8sGroupKey(r, c1, "a"): true,
		graphK8sGroupKey(r, c1, "b"): true,
		graphK8sGroupKey(r, c2, "a"): true,
	}
	if len(keys) != 4 {
		t.Errorf("group keys %v: a rule's scope must be in its key", keys)
	}
	swapped := graphK8sParseRule(`{"verbs":["get","list"],"resources":["secrets"]}`)
	if graphK8sGroupKey(r, c1, "a") != graphK8sGroupKey(swapped, c1, "a") {
		t.Error("verb order changed the group key")
	}
	for k := range keys {
		if !strings.HasPrefix(k, "k8s:") {
			t.Errorf("group key %q does not keep apart from AWS keys", k)
		}
	}
}

// Every edge spec renders to its provider and nothing else: no slot left, no
// other provider named. For AWS the rendered text is the SQL the spec always
// ran (the slot sits exactly where the literal 'aws' did).
func TestP2K8sGraphSpecsRenderOneProvider(t *testing.T) {
	for dir, specs := range graphSpecs {
		for kind, s := range specs {
			for _, part := range []string{s.from, graphPredicates(s, false), graphPredicates(s, true)} {
				aws, k8s := graphRender(part, "aws"), graphRender(part, "k8s")
				if strings.Contains(aws, graphProviderSlot) || strings.Contains(aws, "'k8s'") {
					t.Errorf("%s %s aws render: %s", dir, kind, aws)
				}
				if strings.Contains(k8s, graphProviderSlot) || strings.Contains(k8s, "'aws'") {
					t.Errorf("%s %s k8s render names another provider: %s", dir, kind, k8s)
				}
			}
			if !strings.Contains(s.where, graphProviderSlot) {
				t.Errorf("%s %s: where names no provider; its far node could be any provider's", dir, kind)
			}
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("rendering for an unknown provider did not panic")
		}
	}()
	graphRender("x = "+graphProviderSlot, "github")
}
