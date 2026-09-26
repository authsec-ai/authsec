package igaread

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	igraph "github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

func a5cIdentityParams(t *testing.T, vals url.Values) *ListParams {
	t.Helper()
	p, err := ParseListParams(vals, listsIdentities.sorts, listsIdentities.defSort, listsIdentities.facetNames())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The default identity page does not select account_state, and graph=v2 does
// not change that SELECT either: the state is a second lookup. The name sort
// SQL is the same string. The package kind rank stays the AWS CASE.
func TestA5CDefaultIdentitySQLUnchanged(t *testing.T) {
	ws := uuid.New()
	p := a5cIdentityParams(t, url.Values{})
	fs, _, _, err := listsIdentityFilters(p, ws, GraphScope{})
	if err != nil {
		t.Fatal(err)
	}
	sql, _ := listsPageSQL(&listsIdentities, fs, listsIdentities.keys["name"], false, nil, 50)
	if strings.Contains(sql, "account_state") {
		t.Fatalf("default identity SQL selects account_state:\n%s", sql)
	}
	if !strings.Contains(sql, "provider = 'aws'") {
		t.Fatalf("default identity SQL dropped the AWS predicate:\n%s", sql)
	}
	v2 := withIdentityV2Spec(&listsIdentities)
	fs2, _, _, err := listsIdentityFilters(p, ws, GraphScope{V2: true, Providers: append([]string(nil), graphV2ProviderOrder...)})
	if err != nil {
		t.Fatal(err)
	}
	sql2, _ := listsPageSQL(v2, fs2, v2.keys["name"], false, nil, 50)
	if sql != sql2 {
		t.Fatalf("v2 name-sort SQL differs from the default\n default:\n%s\n v2:\n%s", sql, sql2)
	}
	if listsIdentities.keys["kind"][0].sql != IdentityKindRankSQL {
		t.Fatalf("default kind rank changed to %s", listsIdentities.keys["kind"][0].sql)
	}
	if strings.Contains(IdentityKindRankSQL, models.AccountKindLocalUser) {
		t.Fatal("IdentityKindRankSQL grew a non-IAM kind")
	}
}

func TestA5CIdentityKindVocabulary(t *testing.T) {
	if got := identityKindsForProviders([]string{models.ProviderLinux}); strings.Join(got, ",") !=
		models.AccountKindLocalUser+","+models.AccountKindLocalGroup {
		t.Fatalf("linux kinds = %v", got)
	}
	if got := identityKindsForProviders([]string{models.ProviderKubernetes}); strings.Join(got, ",") !=
		models.AccountKindK8sSA+","+models.AccountKindK8sGroup {
		t.Fatalf("kubernetes kinds = %v", got)
	}
	if got := identityKindsForProviders([]string{models.ProviderAD}); strings.Join(got, ",") != strings.Join([]string{
		models.AccountKindADUser, models.AccountKindADGroup, models.AccountKindADComputer, models.AccountKindADManagedSA,
	}, ",") {
		t.Fatalf("ad kinds = %v", got)
	}
	if got := identityKindsForProviders([]string{models.ProviderAWS}); strings.Join(got, ",") != strings.Join(listsIdentityKinds, ",") {
		t.Fatalf("aws kinds = %v", got)
	}
	if got := identityKindsForProviders(graphV2ProviderOrder); len(got) != len(v2IdentityKindOrder()) {
		t.Fatalf("all providers = %v", got)
	}
	for _, kind := range identityKindsForProviders([]string{models.ProviderLinux, models.ProviderKubernetes, models.ProviderAD}) {
		if iamIdentityKind(kind) {
			t.Fatalf("non-AWS providers admitted %s", kind)
		}
		admitted := false
		for _, provider := range []string{models.ProviderLinux, models.ProviderKubernetes, models.ProviderAD} {
			if models.CheckProviderKind(provider, kind) == nil && providerAdmitsKind(provider, kind) {
				admitted = true
			}
		}
		if !admitted {
			t.Fatalf("%s is in the vocabulary but CheckProviderKind admits it for no provider", kind)
		}
	}
}

func TestA5CIdentityKindFilter(t *testing.T) {
	ws := uuid.New()
	local := a5cIdentityParams(t, url.Values{"kind": {models.AccountKindLocalUser}})
	_, _, _, err := listsIdentityFilters(local, ws, GraphScope{})
	if err == nil || err.Code != "invalid_parameter" || err.Message != "kind must be one of iam_role, iam_user, iam_group" ||
		err.Extra["parameter"] != "kind" {
		t.Fatalf("default kind=local_user = %+v", err)
	}

	if _, _, _, err := listsIdentityFilters(local, ws, GraphScope{V2: true, Providers: []string{models.ProviderLinux}}); err != nil {
		t.Fatalf("v2 linux local_user: %v", err)
	}
	adUser := a5cIdentityParams(t, url.Values{"kind": {models.AccountKindADUser}})
	_, _, _, err = listsIdentityFilters(adUser, ws, GraphScope{V2: true, Providers: []string{models.ProviderLinux}})
	if err == nil || err.Code != "invalid_parameter" || err.Message != "provider linux does not admit account kind ad_user" {
		t.Fatalf("linux+ad_user = %+v", err)
	}
	_, _, _, err = listsIdentityFilters(a5cIdentityParams(t, url.Values{"kind": {"nope"}}), ws,
		GraphScope{V2: true, Providers: append([]string(nil), graphV2ProviderOrder...)})
	if err == nil || err.Code != "invalid_parameter" || !strings.HasPrefix(err.Message, "kind must be one of ") ||
		!strings.Contains(err.Message, models.AccountKindLocalUser) {
		t.Fatalf("unknown kind = %+v", err)
	}
	_, _, _, err = listsIdentityFilters(local, ws, GraphScope{V2: true, Providers: []string{models.ProviderAWS}})
	if err == nil || err.Code != "invalid_parameter" || !strings.Contains(err.Message, models.AccountKindLocalUser) {
		t.Fatalf("aws+local_user = %+v", err)
	}
}

func TestA5CIdentityKindFacetAndRank(t *testing.T) {
	counts := map[string]int64{
		models.CloudIdentityIAMRole:   2,
		models.AccountKindLocalUser:   1,
		models.AccountKindK8sSA:       1,
		models.AccountKindADManagedSA: 1,
	}
	def := listsIdentities.facets["kind"].finalize(counts, nil)
	v2 := listsLabelled(identityKindLabelsV2)(counts, nil)
	label := func(vals []FacetValue, kind string) string {
		for _, v := range vals {
			if v.Value == kind {
				return v.Label
			}
		}
		return ""
	}
	if label(def, models.CloudIdentityIAMRole) != "IAM role" || label(def, models.AccountKindLocalUser) != models.AccountKindLocalUser {
		t.Fatalf("default facet labels changed: %+v", def)
	}
	if label(v2, models.AccountKindLocalUser) != "Local user" ||
		label(v2, models.AccountKindK8sSA) != "Kubernetes service account" ||
		label(v2, models.AccountKindADManagedSA) != "AD managed service account" ||
		label(v2, models.CloudIdentityIAMRole) != "IAM role" {
		t.Fatalf("v2 facet labels = %+v", v2)
	}

	v2spec := withIdentityV2Spec(&listsIdentities)
	rank := v2spec.keys["kind"][0].sql
	if listsIdentities.keys["kind"][0].sql != IdentityKindRankSQL {
		t.Fatal("building the v2 spec mutated the default rank")
	}
	prev := -1
	for i, kind := range v2IdentityKindOrder() {
		needle := "WHEN '" + kind + "' THEN "
		at := strings.Index(rank, needle)
		if at < 0 {
			t.Fatalf("rank SQL missing %s: %s", kind, rank)
		}
		if at <= prev {
			t.Fatalf("%s is not after the previous kind in %s", kind, rank)
		}
		prev = at
		if !strings.Contains(rank, needle+itoa(i)) {
			t.Fatalf("rank of %s is not %d in %s", kind, i, rank)
		}
	}
	if strings.Contains(IdentityKindRankSQL, models.AccountKindLocalUser) {
		t.Fatal("default rank SQL names a new kind")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestA5CAccountStateOmittedWithoutV2AndRegionStaysGlobal(t *testing.T) {
	accts := listsTestAccounts(ConnectorInfo{ID: uuid.New(), AccountID: "111111111111", Label: "prod", Status: "active"})
	aws := IdentityRecord{
		ID: uuid.New(), DisplayName: "role", AccountKind: models.CloudIdentityIAMRole,
		SourceKey: igraph.Key("aws", "arn:aws:iam::111111111111:role/r"),
		AccountID: "111111111111", Lifecycle: models.LifecycleActive, State: StateCurrent,
	}
	row := aws.Row(accts, Unknown(), nil)
	if row.Region != "global" {
		t.Fatalf("AWS region = %q, want global", row.Region)
	}
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "account_state") {
		t.Fatalf("account_state present without v2: %s", raw)
	}
	enabled := models.AccountStateEnabled
	row.AccountState = &enabled
	if row.Lifecycle != models.LifecycleActive || row.State != StateCurrent || row.Region != "global" {
		t.Fatalf("setting account_state changed the row: %+v", row)
	}
	raw, _ = json.Marshal(row)
	if !strings.Contains(string(raw), `"account_state":"enabled"`) {
		t.Fatalf("v2 account_state = %s", raw)
	}

	// Linux, Kubernetes and AD rows keep region "global" and an empty arn.
	// NativeOfKey only returns a segment for an aws key; the native key is
	// not copied into arn. Account stays null because the key is not an ARN.
	for _, tc := range []IdentityRecord{
		{ID: uuid.New(), DisplayName: "alice", AccountKind: models.AccountKindLocalUser,
			SourceKey: igraph.Key("linux", "uid", "estate", "host", "1000")},
		{ID: uuid.New(), DisplayName: "invoice", AccountKind: models.AccountKindK8sSA,
			SourceKey: igraph.Key("kubernetes", "sa", "estate", "pay", "invoice")},
		{ID: uuid.New(), DisplayName: "ada", AccountKind: models.AccountKindADUser,
			SourceKey: igraph.Key("ad", "DC=authsec,DC=test", "11111111-1111-1111-1111-111111111111")},
	} {
		got := tc.Row(nil, Unknown(), nil)
		if got.Region != "global" || got.ARN != "" || got.Account != nil {
			t.Fatalf("%s row region=%q arn=%q account=%v", tc.AccountKind, got.Region, got.ARN, got.Account)
		}
	}
}
