package igaread

// Pure pieces of the workload detail and tabs (workload_detail.go,
// workload_partitions.go). Everything that touches the database is proven end
// to end in tests/integration/p2_wdetail_*.

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// A statement's actions come from its VERBATIM native_rights, where Action and
// NotAction may be a string or a list -- and from the projector's fallback
// shape when the verbatim bytes were missing. Never nil.
func TestP2WdetailStatementActions(t *testing.T) {
	for name, tc := range map[string]struct {
		native      string
		actions     string
		notActions  string
		wantNonNull bool
	}{
		"Action as a string": {`{"Sid":"A","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`, "s3:GetObject", "", true},
		"Action as a list":   {`{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}`, "s3:GetObject,s3:ListBucket", "", true},
		"NotAction":          {`{"Effect":"Deny","NotAction":"iam:*","Resource":"*"}`, "", "iam:*", true},
		"the fallback shape": {`{"effect":"allow","actions":["kms:Decrypt"],"not_actions":["kms:Delete*"]}`, "kms:Decrypt", "kms:Delete*", true},
		"nothing stored":     {``, "", "", true},
		"not JSON":           {`{`, "", "", true},
	} {
		a, n := StatementActions(json.RawMessage(tc.native))
		if a == nil || n == nil {
			t.Errorf("%s: nil list (%v, %v): the API writes [] for none", name, a, n)
		}
		if strings.Join(a, ",") != tc.actions || strings.Join(n, ",") != tc.notActions {
			t.Errorf("%s: actions %v not_actions %v, want %q %q", name, a, n, tc.actions, tc.notActions)
		}
	}
}

// D-84: the API's index is 1-based, converted in one helper.
func TestP2WdetailStatementIndexIsOneBased(t *testing.T) {
	zero := 0
	if got := APIStatementIndex(&zero); got == nil || *got != 1 {
		t.Errorf("stored 0 -> %v, want 1", got)
	}
	if got := APIStatementIndex(nil); got != nil {
		t.Errorf("no stored index -> %v, want nil", *got)
	}
}

// D-85: provider_attrs is an allowlist -- a stored key outside it never
// reaches the response -- and what was not collected is null, never "".
func TestP2WdetailProviderAttrsAllowlist(t *testing.T) {
	pa := workloadProviderAttrsOf(json.RawMessage(`{"status":"Active","env_var_names":[],
		"secret_value":"never","arn":"arn:aws:lambda:x","gateway_targets":[{"id":"t1","name":"n","status":"","type":"LAMBDA","extra":"x"}]}`))
	raw, _ := json.Marshal(pa)
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	if len(got) != 4 {
		t.Fatalf("provider_attrs = %s, want exactly the four allowlisted keys", raw)
	}
	if strings.Contains(string(raw), "never") || strings.Contains(string(raw), "arn:aws") || strings.Contains(string(raw), "extra") {
		t.Fatalf("provider_attrs leaked a key outside the allowlist: %s", raw)
	}
	if got["foundation_model"] != nil || got["status"] != "Active" {
		t.Errorf("provider_attrs = %s, want the model null (not collected) and the status", raw)
	}
	if names, ok := got["env_var_names"].([]any); !ok || len(names) != 0 {
		t.Errorf("env_var_names = %v, want [] (collected, none)", got["env_var_names"])
	}
	if empty := workloadProviderAttrsOf(json.RawMessage(`{}`)); empty.Status != nil || empty.EnvVarNames != nil || empty.GatewayTargets != nil {
		t.Errorf("an empty provider_attrs = %+v, want every fact null", empty)
	}
}

// D-75 on a per-object route: an unknown parameter is 400 naming it, the
// first in name order; include_ended is a boolean.
func TestP2WdetailRouteParams(t *testing.T) {
	if e := RouteParams(url.Values{"rev": {"1"}}, "rev"); e != nil {
		t.Errorf("a defined parameter = %v", e)
	}
	e := RouteParams(url.Values{"zeta": {"1"}, "alpha": {"1"}, "rev": {"1"}}, "rev")
	if e == nil || e.Extra["parameter"] != "alpha" {
		t.Errorf("two unknown parameters = %v, want alpha named (name order)", e)
	}
	for v, want := range map[string]bool{"": false, "false": false, "true": true} {
		got, err := ParseIncludeEnded(url.Values{"include_ended": {v}})
		if err != nil || got != want {
			t.Errorf("include_ended=%q = %v, %v", v, got, err)
		}
	}
	if _, err := ParseIncludeEnded(url.Values{"include_ended": {"1"}}); err == nil {
		t.Error("include_ended=1 accepted; want 400")
	}
	if got := strings.Join(EdgeStates(false), ","); got != "current,stale" {
		t.Errorf("default edge states = %s, want current,stale", got)
	}
	if got := strings.Join(EdgeStates(true), ","); got != "current,stale,ended" {
		t.Errorf("include_ended edge states = %s", got)
	}
}

// meta.coverage names a partition's required surfaces and scanners the run
// reported and did not reach: unsupported is never a gap, not_selected reads
// stale (D-58), and a surface the run did not report is not guessed.
func TestP2WdetailCoverageGaps(t *testing.T) {
	p := igagraph.Partition{
		RequiredSurfaces: []string{models.SurfaceIAMRoles, "lambda:us-east-1", models.SurfaceIAMUsers},
		RequiredScanners: []string{models.SurfaceWorkloadScan, "compute:us-east-1"},
	}
	cov := models.ScanCoverage{Surfaces: map[string]models.SurfaceCoverage{
		models.SurfaceIAMRoles:     {State: models.CloudCoverageDenied},
		"lambda:us-east-1":         {State: models.CloudCoverageReached},
		models.SurfaceWorkloadScan: {State: models.CloudCoverageUnsupported},
		"compute:us-east-1":        {State: models.CloudCoverageNotSelected},
	}}
	var got []string
	for _, g := range workloadCoverageGaps(p, cov) {
		got = append(got, g.surface+"="+g.state)
	}
	if strings.Join(got, ",") != "iam_roles=denied,compute:us-east-1=stale" {
		t.Errorf("gaps = %v, want iam_roles denied and compute:us-east-1 stale only", got)
	}
	for surface, want := range map[string]string{
		"lambda:us-east-1":            "workloads of kind lambda_function in us-east-1",
		models.SurfaceIAMRoles:        "identities of kind iam_role",
		models.SurfacePolicyDocuments: "resources named by unreadable policy documents",
	} {
		if got := workloadCoverageAffects(surface); got != want {
			t.Errorf("affects(%s) = %q, want %q", surface, got, want)
		}
	}
}

// Every EdgeStaleReasons input is in its result, even with no partition to
// explain it (no connector): [] rather than absent.
func TestP2WdetailEdgeStaleReasonsNamesEveryEdge(t *testing.T) {
	q := &Query{}
	id := uuid.New()
	got, err := q.EdgeStaleReasons(listsTestAccounts(), []EdgePartition{{ID: id}})
	if err != nil {
		t.Fatal(err)
	}
	if rs, ok := got[id]; !ok || rs == nil || len(rs) != 0 {
		t.Errorf("an unexplained stale edge = %v (present %v), want []", rs, ok)
	}
}

// §5.2 Totals / D-15 / §2.14.14 on a multi-section tab's section (D-77): the
// list envelope's rule exactly. total only when total_known; above 10 000,
// total_known false with total_at_least; a count that timed out, total_known
// false and NOTHING else -- so "more than 10 000" and "not counted" never
// render alike, and a section never writes "total": null.
func TestP2WdetailSectionTotalsFollowTheListRule(t *testing.T) {
	for name, tc := range map[string]struct {
		n     int64
		known bool
		want  string
	}{
		"counted":             {3, true, `{"items":[],"next_cursor":null,"total_known":true,"total":3}`},
		"empty":               {0, true, `{"items":[],"next_cursor":null,"total_known":true,"total":0}`},
		"at the cap":          {TotalCap, true, `{"items":[],"next_cursor":null,"total_known":true,"total":10000}`},
		"above the cap":       {TotalCap + 1, true, `{"items":[],"next_cursor":null,"total_known":false,"total_at_least":10000}`},
		"the count timed out": {0, false, `{"items":[],"next_cursor":null,"total_known":false}`},
	} {
		sec := PagedSection[WorkloadIdentityClaim]{Items: []WorkloadIdentityClaim{}}
		sec.SetTotal(tc.n, tc.known)
		raw, err := json.Marshal(sec)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != tc.want {
			t.Errorf("%s: section = %s, want %s", name, raw, tc.want)
		}
		// And the list envelope states the same count the same way.
		var m ListMeta
		m.SetTotal(tc.n, tc.known)
		if m.TotalKnown != sec.TotalKnown || (m.Total == nil) != (sec.Total == nil) || (m.TotalAtLeast == nil) != (sec.TotalAtLeast == nil) {
			t.Errorf("%s: section %+v and list meta %+v disagree", name, sec, m)
		}
	}
}
