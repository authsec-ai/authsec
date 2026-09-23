package igaread

// Pure pieces of the list engine (lists.go, nodes.go). Everything that
// touches the database is proven end to end in tests/integration/p2_lists_*.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

func listsTestAccounts(conns ...ConnectorInfo) *Accounts {
	a := &Accounts{byAccount: map[string]*ConnectorInfo{}, byConnector: map[uuid.UUID]*ConnectorInfo{}}
	for i := range conns {
		c := &conns[i]
		a.byConnector[c.ID] = c
		a.byAccount[c.AccountID] = c
	}
	return a
}

// The account facet ALWAYS offers unknown, and every live connected account,
// even at 0 (D-14, §2.14.10); unknown sorts last.
func TestP2ListsAccountFacetOffersUnknownAndConnected(t *testing.T) {
	accts := listsTestAccounts(
		ConnectorInfo{ID: uuid.New(), AccountID: "111111111111", Label: "prod", Status: "active"},
		ConnectorInfo{ID: uuid.New(), AccountID: "222222222222", Label: "old", Status: models.CloudConnectorRevoked},
	)
	got := listsAccountFacet(map[string]int64{"333333333333": 2}, accts)
	byValue := map[string]FacetValue{}
	for _, v := range got {
		byValue[v.Value] = v
	}
	if u, ok := byValue["unknown"]; !ok || u.Count != 0 || u.Label != "Unknown account" {
		t.Errorf("facet = %+v, want unknown offered at 0", got)
	}
	if p, ok := byValue["111111111111"]; !ok || p.Count != 0 || p.Label != "prod" {
		t.Errorf("facet = %+v, want the connected account at 0 with its label", got)
	}
	if _, ok := byValue["222222222222"]; ok {
		t.Errorf("facet = %+v: a revoked connector's account with no rows is not a choice", got)
	}
	if x := byValue["333333333333"]; x.Count != 2 || x.Label != "333333333333" {
		t.Errorf("an unconnected account with rows = %+v, want its id as label", x)
	}
	if got[len(got)-1].Value != "unknown" {
		t.Errorf("facet order = %+v, want unknown last", got)
	}
	if got[0].Value != "333333333333" {
		t.Errorf("facet order = %+v, want the largest count first", got)
	}
}

// A descending sort reverses the whole tuple, id included, and every sort
// ends with id (§5.2, D-13).
func TestP2ListsPageSQLKeysetAndOrder(t *testing.T) {
	spec := &listsWorkloads
	fs := []listsFilter{{sql: "w.workspace_id = ?", args: []any{uuid.New()}}}
	keys := spec.keys["account"]
	after := &listsAfter{keys: []any{"111111111111", "fn"}, id: uuid.New()}

	asc, args := listsPageSQL(spec, fs, keys, false, after, 10)
	if !strings.Contains(asc, "("+WorkloadAccountSQL+", lower(w.display_name), w.id) > (?::text, ?::text, ?::uuid)") {
		t.Errorf("ascending keyset missing or malformed:\n%s", asc)
	}
	if !strings.Contains(asc, "ORDER BY "+WorkloadAccountSQL+" ASC, lower(w.display_name) ASC, w.id ASC") {
		t.Errorf("ascending order must end with id:\n%s", asc)
	}
	if n := len(args); n != 5 || args[4] != 11 {
		t.Errorf("args = %v, want workspace, two keys, id, then limit+1", args)
	}
	desc, _ := listsPageSQL(spec, fs, keys, true, after, 10)
	if !strings.Contains(desc, ") < (") || !strings.Contains(desc, "w.id DESC") || strings.Contains(desc, " ASC") {
		t.Errorf("descending must reverse the whole tuple:\n%s", desc)
	}
	first, fargs := listsPageSQL(spec, fs, keys, false, nil, 10)
	if strings.Contains(first, ") > (") || len(fargs) != 2 {
		t.Errorf("a first page has no keyset:\n%s %v", first, fargs)
	}
}

// Cursor keys: the right number of values, numeric ones as integers; anything
// else is cursor_invalid.
func TestP2ListsDecodeCursorKey(t *testing.T) {
	keys := listsResources.keys["kind"] // ordinal (numeric), then name
	raw, _ := json.Marshal(listsCursorKey{K: []string{"1", "arn:aws:s3:::a/*"}, A: "d"})
	a, err := listsDecodeCursor(&Cursor{Key: raw, ID: uuid.New()}, keys)
	if err != nil || a.keys[0] != int64(1) || a.keys[1] != "arn:aws:s3:::a/*" || a.accounts != "d" {
		t.Fatalf("decode = %+v %v", a, err)
	}
	for name, k := range map[string]listsCursorKey{
		"too few":     {K: []string{"1"}},
		"too many":    {K: []string{"1", "x", "y"}},
		"not numeric": {K: []string{"one", "x"}},
	} {
		raw, _ := json.Marshal(k)
		if _, err := listsDecodeCursor(&Cursor{Key: raw}, keys); err == nil || err.Code != "cursor_invalid" {
			t.Errorf("%s: %v, want cursor_invalid", name, err)
		}
	}
}

// meta.coverage affects: each list names only the surfaces that project its
// rows, and says what the gap leaves out.
func TestP2ListsCoverageAffects(t *testing.T) {
	for _, tc := range []struct{ list, surface, want string }{
		{ListRouteIdentities, "iam_users", "identities of kind iam_user"},
		{ListRouteIdentities, "iam_roles", "identities of kind iam_role"},
		{ListRouteIdentities, "lambda:eu-west-1", "used_by_count: workloads of kind lambda_function in eu-west-1"},
		{ListRouteIdentities, "policy_documents", ""},
		{ListRouteWorkloads, "lambda:eu-west-1", "workloads of kind lambda_function in eu-west-1"},
		{ListRouteWorkloads, "agentcore-gateways:us-east-1", "workloads of kind bedrock_agentcore_gateway in us-east-1"},
		{ListRouteWorkloads, "compute:eu-west-1", "workloads in eu-west-1"},
		{ListRouteWorkloads, "workload_scan", "all workloads"},
		{ListRouteWorkloads, "iam_roles", "execution roles of workloads"},
		{ListRouteWorkloads, "iam_users", ""},
		{ListRouteWorkloads, "activity", ""},
		{ListRouteResources, "policy_documents", "resources named by unreadable policy documents"},
		{ListRouteResources, "permission_scan", "all resources"},
		{ListRouteResources, "lambda:eu-west-1", ""},
	} {
		if got := listsAffects(tc.list, tc.surface); got != tc.want {
			t.Errorf("%s / %s = %q, want %q", tc.list, tc.surface, got, tc.want)
		}
	}
}

// §5.2 totals: counted up to 10 000; beyond, not known with total_at_least;
// a count that did not finish is not known, never a guess.
func TestP2ListsTotalsBeyondTheCap(t *testing.T) {
	var m ListMeta
	m.SetTotal(TotalCap+1, true)
	if m.TotalKnown || m.Total != nil || m.TotalAtLeast == nil || *m.TotalAtLeast != TotalCap {
		t.Errorf("10001 counted = %+v, want total_known false, total_at_least 10000", m)
	}
	m = ListMeta{}
	m.SetTotal(TotalCap, true)
	if !m.TotalKnown || m.Total == nil || *m.Total != TotalCap {
		t.Errorf("10000 counted = %+v, want known", m)
	}
	m = ListMeta{}
	m.SetTotal(0, false)
	if m.TotalKnown || m.Total != nil || m.TotalAtLeast != nil {
		t.Errorf("a timed-out count = %+v, want unknown with no number", m)
	}
}

// D-16: an S3 object selector is typed as an object, never a bucket, and the
// execution_role object carries the fields its state has.
func TestP2ListsResourceTypeAndExecutionRole(t *testing.T) {
	for text, want := range map[string]string{
		"arn:aws:s3:::support-tickets/*":            "s3_object",
		"arn:aws:s3:::support-tickets":              "s3_bucket",
		"arn:aws:dynamodb:us-east-1:1:table/orders": "dynamodb_table",
		"*": "unknown",
	} {
		if got := ResourceType(text); got != want {
			t.Errorf("ResourceType(%q) = %q, want %q", text, got, want)
		}
	}
	id, name := uuid.New(), "SharedToolRole"
	if got := ExecutionRoleOf(models.ExecRoleResolved, "", &id, &name); got["identity"] != R(RefIdentity, id) || got["name"] != name {
		t.Errorf("resolved = %v", got)
	}
	if got := ExecutionRoleOf(models.ExecRoleResolved, "", nil, nil); got["identity"] != nil || got["name"] != nil {
		t.Errorf("resolved with no live edge = %v, want identity and name null, never a guess", got)
	}
	got := ExecutionRoleOf(models.ExecRoleNotInScan, "arn:aws:iam::1:role/x", nil, nil)
	if got["execution_role_arn"] != "arn:aws:iam::1:role/x" {
		t.Errorf("not_in_scan = %v, want the ARN it runs as", got)
	}
	if _, has := got["identity"]; has {
		t.Errorf("not_in_scan = %v names an identity", got)
	}
	if got := ExecutionRoleOf(models.ExecRoleNone, "", nil, nil); len(got) != 1 {
		t.Errorf("none = %v, want only its state", got)
	}
}
