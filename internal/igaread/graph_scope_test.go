package igaread

import (
	"net/url"
	"strings"
	"testing"
)

func TestGraphScopeRewriteIsIdentityUntilV2(t *testing.T) {
	const sql = `SELECT id FROM iga_workload w WHERE w.provider = 'aws' AND far.provider = 'aws'`
	if got := (GraphScope{}).rewrite(sql); got != sql {
		t.Fatalf("default rewrite changed SQL:\n got %s", got)
	}
	if got := (&Query{}).SQL(sql); got != sql {
		t.Fatalf("default Query.SQL changed SQL:\n got %s", got)
	}
	one := GraphScope{V2: true, Providers: []string{"linux"}}
	if got := one.rewrite(sql); got != `SELECT id FROM iga_workload w WHERE w.provider = 'linux' AND far.provider = 'linux'` {
		t.Fatalf("single provider = %s", got)
	}
	all := GraphScope{V2: true, Providers: []string{"ad", "aws", "kubernetes", "linux"}}
	got := all.rewrite(sql)
	want := `SELECT id FROM iga_workload w WHERE w.provider IN ('ad','aws','kubernetes','linux') AND far.provider IN ('ad','aws','kubernetes','linux')`
	if got != want {
		t.Fatalf("all providers =\n got  %s\n want %s", got, want)
	}
}

func TestParseGraphOnlyRejectsUnknown(t *testing.T) {
	if _, err := parseGraphOnly(url.Values{}); err != nil {
		t.Fatal(err)
	}
	sc, err := parseGraphOnly(url.Values{"graph": {"v2"}})
	if err != nil || !sc.V2 {
		t.Fatalf("v2 = %+v %v", sc, err)
	}
	if _, err := parseGraphOnly(url.Values{"graph": {"aws"}}); err == nil {
		t.Fatal("graph=aws accepted")
	}
	ctx, err := bindOptIn(t.Context(), url.Values{"provider": {"linux"}})
	if err == nil || !strings.Contains(err.Error(), "provider requires graph=v2") {
		t.Fatalf("provider without v2 = %v", err)
	}
	_ = ctx
	provs, err := parseV2Providers(url.Values{"provider": {"linux", "ad"}})
	if err != nil || strings.Join(provs, ",") != "ad,linux" {
		t.Fatalf("providers = %v %v", provs, err)
	}
	if _, err := parseV2Providers(url.Values{"provider": {"github"}}); err == nil {
		t.Fatal("github accepted")
	}
}

func TestEdgeKindsStayAWSUntilV2(t *testing.T) {
	if strings.Join((&Query{}).edgeKinds(), ",") != strings.Join(graphEdgeKinds, ",") {
		t.Fatal("default edge kinds changed")
	}
	got := strings.Join((&Query{V2: true}).edgeKinds(), ",")
	if !strings.HasPrefix(got, strings.Join(graphEdgeKinds, ",")) || !strings.Contains(got, "observed_access") || !strings.Contains(got, "backed_by_directory") {
		t.Fatalf("v2 kinds = %s", got)
	}
}
