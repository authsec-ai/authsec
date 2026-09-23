package igaread

// Unit tests for the traversal's pure helpers (T6.4): labels (D-87, §2.6),
// group keys (D-37), statement parsing, reserve (D-40), the path
// enumeration's order and bounds (§5.4), and the path verdict over both
// orientations (D-38). The traversal itself is tested against real
// PostgreSQL in tests/integration/p2_graph_*_test.go and p2_graph_level_test.go.

import (
	"strings"
	"testing"
	"time"
)

func TestP2GraphExternalLabels(t *testing.T) {
	for _, tc := range []struct{ mech, issuer, subject, want string }{
		{"aws_account", "aws", "300000000003", "300000000003"},
		{"aws_account", "aws", "*", "any AWS principal"},
		{"aws_principal", "aws", "arn:aws:iam::300000000003:role/partner", "arn:aws:iam::300000000003:role/partner"},
		{"aws_service", "aws", "lambda.amazonaws.com", "lambda.amazonaws.com"},
		{"oidc", "token.actions.githubusercontent.com", "repo:authsec-ai/authsec:*", "token.actions.githubusercontent.com repo:authsec-ai/authsec:*"},
		{"saml", "arn:aws:iam::1:saml-provider/Okta", "*", "arn:aws:iam::1:saml-provider/Okta *"},
		{"k8s_service_account", "oidc.eks.us-east-1.amazonaws.com/id/X", "pod:system:serviceaccount:payments:api", "payments/api"},
		{"k8s_service_account", "oidc.eks.us-east-1.amazonaws.com/id/X", "system:serviceaccount:ns:sa", "ns/sa"},
	} {
		if got := GraphExternalLabel(tc.mech, tc.issuer, tc.subject); got != tc.want {
			t.Errorf("label(%s, %s) = %q, want %q", tc.mech, tc.subject, got, tc.want)
		}
	}
	// D-87: an account is parsed only for aws_account and aws_principal.
	for _, tc := range []struct{ mech, subject, want string }{
		{"aws_account", "300000000003", "300000000003"},
		{"aws_account", "*", ""},
		{"aws_principal", "arn:aws:iam::300000000003:role/x", "300000000003"},
		{"aws_service", "lambda.amazonaws.com", ""},
		{"oidc", "arn:aws:iam::300000000003:role/x", ""},
	} {
		if got := graphExternalAccount(tc.mech, tc.subject); got != tc.want {
			t.Errorf("account(%s, %s) = %q, want %q", tc.mech, tc.subject, got, tc.want)
		}
	}
}

func TestP2GraphResourceAndStatementLabels(t *testing.T) {
	for text, want := range map[string]string{
		"arn:aws:s3:::support-tickets/*":             "support-tickets/*",
		"arn:aws:iam::429418377036:role/x":           "role/x",
		"arn:aws:kms:us-east-1:429418377036:key/abc": "key/abc",
		"*": "*",
	} {
		if got := GraphResourceLabel(text); got != want {
			t.Errorf("resource label(%q) = %q, want %q", text, got, want)
		}
	}
	if got := GraphStatementLabel([]string{"s3:GetObject", "s3:ListBucket", "s3:GetObject"}, nil); got != "s3:GetObject, s3:ListBucket" {
		t.Errorf("label = %q", got)
	}
	if got := GraphStatementLabel(nil, []string{"iam:*"}); got != "all actions except iam:*" {
		t.Errorf("NotAction label = %q, want all actions except iam:* (§2.6)", got)
	}
}

func TestP2GraphParseStatementBothShapes(t *testing.T) {
	st := graphParseStatement(`{"Sid":"A","Effect":"Allow","Action":["s3:GetObject"],"Resource":"*",` +
		`"Condition":{"StringEquals":{"aws:PrincipalTag/team":"x"},"Bool":{"aws:SecureTransport":"true"}}}`)
	if len(st.Actions) != 1 || st.Actions[0] != "s3:GetObject" || len(st.Condition) == 0 {
		t.Fatalf("verbatim = %+v", st)
	}
	if keys := graphConditionKeys(st.Condition); len(keys) != 2 || keys[0] != "aws:PrincipalTag/team" || keys[1] != "aws:SecureTransport" {
		t.Errorf("condition keys = %v, want both keys, sorted", keys)
	}
	// The projector's fallback shape (models.NativeRights, lowercase keys).
	fb := graphParseStatement(`{"effect":"allow","not_actions":["iam:*"],"resources":["*"]}`)
	if len(fb.NotActions) != 1 || fb.NotActions[0] != "iam:*" || len(fb.Actions) != 0 {
		t.Errorf("fallback = %+v, want NotAction iam:*", fb)
	}
	if got := graphParseStatement(""); len(got.Actions)+len(got.NotActions) != 0 {
		t.Errorf("empty native rights = %+v", got)
	}
}

// D-37: the same actions and targets share a key; a Condition, an exclusion
// or a Deny never does. Order does not matter; NotActions are prefixed "!".
func TestP2GraphGroupKey(t *testing.T) {
	acts := graphGroupActions([]string{"s3:PutObject", "s3:GetObject"}, nil)
	base := GraphGroupKey(acts, []string{"resource:b", "resource:a"}, "allow", "", nil)
	if base != "s3:GetObject,s3:PutObject→resource:a,resource:b" {
		t.Fatalf("key = %q", base)
	}
	if again := GraphGroupKey(graphGroupActions([]string{"s3:GetObject", "s3:PutObject"}, nil),
		[]string{"resource:a", "resource:b"}, "allow", "", nil); again != base {
		t.Errorf("reordered statement key %q != %q", again, base)
	}
	for name, k := range map[string]string{
		"condition": GraphGroupKey(acts, []string{"resource:a", "resource:b"}, "allow", `{"Bool":{"k":"v"}}`, nil),
		"exclusion": GraphGroupKey(acts, []string{"resource:a", "resource:b"}, "allow", "", []string{"resource:x"}),
		"deny":      GraphGroupKey(acts, []string{"resource:a", "resource:b"}, "deny", "", nil),
	} {
		if k == base || !strings.HasPrefix(k, base+"#") {
			t.Errorf("%s key %q must differ from %q by a digest", name, k, base)
		}
	}
	c1 := GraphGroupKey(acts, nil, "allow", graphCanonicalJSON([]byte(`{"Bool":{"a":"1","b":"2"}}`)), nil)
	c2 := GraphGroupKey(acts, nil, "allow", graphCanonicalJSON([]byte(`{"Bool":{"b":"2","a":"1"}}`)), nil)
	if c1 != c2 {
		t.Errorf("one condition in two key orders gave %q and %q", c1, c2)
	}
	if got := graphGroupActions(nil, []string{"iam:*"}); len(got) != 1 || got[0] != "!iam:*" {
		t.Errorf("NotAction group actions = %v, want [!iam:*]", got)
	}
}

func TestP2GraphReserve(t *testing.T) {
	if r := graphReserve(3 * time.Second); r != 750*time.Millisecond {
		t.Errorf("reserve(3s) = %s, want a quarter", r)
	}
	if r := graphReserve(400 * time.Millisecond); r != 250*time.Millisecond {
		t.Errorf("reserve(400ms) = %s, want the 250 ms floor", r)
	}
}

func graphUnitEdge(claim, kind, from, to string) *GraphEdge {
	return &GraphEdge{Claim: claim, Kind: kind, From: from, To: to}
}

// Shortest first, simple paths only, the hop limit and the path budget named.
func TestP2GraphEnumeratePaths(t *testing.T) {
	// w -> r1 -> s1 -> x (3 steps); w -> r1 -> r2 (can_assume) -> s2 -> x (4);
	// r2 -> r1 closes a cycle; s3 is a dead end.
	edges := []*GraphEdge{
		graphUnitEdge("e1", GraphEdgeExecutesAs, "w", "r1"),
		graphUnitEdge("e2", GraphEdgeCanAssume, "r1", "r2"),
		graphUnitEdge("e3", GraphEdgeCanAssume, "r2", "r1"),
		graphUnitEdge("e4", GraphEdgeGrant, "r1", "s1"),
		graphUnitEdge("e5", GraphEdgeGrant, "r2", "s2"),
		graphUnitEdge("e6", GraphEdgeTarget, "s1", "x"),
		graphUnitEdge("e7", GraphEdgeTarget, "s2", "x"),
		graphUnitEdge("e8", GraphEdgeGrant, "r1", "s3"),
	}
	claims := func(p []*GraphEdge) string {
		var s []string
		for _, e := range p {
			s = append(s, e.Claim)
		}
		return strings.Join(s, ",")
	}
	paths, overflow, hop, work := graphEnumeratePaths(edges, "w", "x", 200, 4)
	if len(paths) != 2 || claims(paths[0]) != "e1,e4,e6" || claims(paths[1]) != "e1,e2,e5,e7" || overflow || hop || work {
		t.Fatalf("paths = %v %v %v %v, want the 3-step path then the 4-step one, complete", paths, overflow, hop, work)
	}
	if !graphReachable(edges, "w", "x") || graphReachable(edges, "x", "w") {
		t.Error("reachability must follow each edge's own direction")
	}
	// The path budget: one path fits, more exist.
	paths, overflow, _, _ = graphEnumeratePaths(edges, "w", "x", 1, 4)
	if len(paths) != 1 || !overflow || claims(paths[0]) != "e1,e4,e6" {
		t.Errorf("maxPaths=1: %v overflow=%v, want the shortest and overflow", paths, overflow)
	}
	// The hop limit: the can_assume path is cut, and SAYS so.
	paths, _, hop, _ = graphEnumeratePaths(edges, "w", "x", 200, 0)
	if len(paths) != 1 || !hop {
		t.Errorf("maxHops=0: %v hopBound=%v, want the direct path and hopBound", paths, hop)
	}
	// No path at all.
	if paths, _, _, _ := graphEnumeratePaths(edges, "x", "w", 200, 4); len(paths) != 0 {
		t.Errorf("x -> w = %v, want none", paths)
	}
}

// graphUnitSearch is one orientation's search result: exhausted both sides
// (or not), with the given paths and bound.
func graphUnitSearch(paths int, bound string, exhausted bool) *graphSearch {
	s := &graphSearch{fwd: &graphSide{}, rev: &graphSide{}, bound: bound}
	for i := 0; i < paths; i++ {
		s.paths = append(s.paths, []*GraphEdge{graphUnitEdge("e", GraphEdgeGrant, "a", "b")})
	}
	if !exhausted {
		s.fwd.frontier = []*GraphNode{{}}
	}
	return s
}

// /graph/path over both orientations (§5.4, D-38): none_exists only when both
// were searched to exhaustion before any budget bound; a reverse list is
// complete only when the forward orientation finished too.
func TestP2GraphPathDecide(t *testing.T) {
	none := func() *graphSearch { return graphUnitSearch(0, "", true) }
	for _, tc := range []struct {
		name        string
		there, back *graphSearch
		outcome     string
		reverse     bool
		more        bool
		boundBy     string
	}{
		{"forward paths, complete", graphUnitSearch(1, "", true), nil, GraphPathFound, false, false, ""},
		{"forward paths, a budget bound", graphUnitSearch(1, GraphBoundNodes, false), nil, GraphPathFound, false, true, GraphBoundNodes},
		{"reverse paths, both complete", none(), graphUnitSearch(2, "", true), GraphPathFound, true, false, ""},
		{"reverse paths, forward unfinished", graphUnitSearch(0, GraphBoundEdges, false), graphUnitSearch(1, "", true),
			GraphPathFound, true, true, GraphBoundEdges},
		{"reverse paths, reverse bound first", graphUnitSearch(0, GraphBoundEdges, false), graphUnitSearch(1, GraphBoundTime, false),
			GraphPathFound, true, true, GraphBoundTime},
		{"none either way", none(), none(), GraphPathNoneExists, false, false, ""},
		{"forward none, reverse bound", none(), graphUnitSearch(0, GraphBoundEdges, false), GraphPathNotFoundWithinBudget, false, false, GraphBoundEdges},
		{"forward bound, reverse none", graphUnitSearch(0, GraphBoundTime, false), none(), GraphPathNotFoundWithinBudget, false, false, GraphBoundTime},
		{"reverse never searched", none(), nil, GraphPathNotFoundWithinBudget, false, false, GraphBoundTime},
	} {
		d := graphPathDecide(tc.there, tc.back)
		if d.outcome != tc.outcome || d.reverse != tc.reverse || d.morePaths != tc.more || d.boundBy != tc.boundBy {
			t.Errorf("%s: %+v, want outcome %s reverse %v more %v bound_by %q", tc.name, d, tc.outcome, tc.reverse, tc.more, tc.boundBy)
		}
	}
	// An unfollowed resolution, the hop limit and the path budget are never
	// "none": each is a reason, in that order after a budget.
	s := none()
	s.unfollowed = true
	if d := graphPathDecide(s, none()); d.outcome != GraphPathNotFoundWithinBudget || d.boundBy != GraphBoundResolution {
		t.Errorf("unfollowed resolution: %+v, want not_found_within_budget, resolution_not_followed", d)
	}
	s = none()
	s.hopBound, s.unfollowed = true, true
	if d := graphPathDecide(none(), s); d.boundBy != GraphBoundAssumeHops {
		t.Errorf("hop limit and resolution: %+v, want bound_by assume_hops first", d)
	}
}
