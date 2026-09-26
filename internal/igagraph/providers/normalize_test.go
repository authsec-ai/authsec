package providers

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLinuxInvoiceProjectsDeclaredAndObserved(t *testing.T) {
	estate := "estate-1"
	plan, err := Normalize(Input{
		Provider: "linux", EstateID: estate,
		Objects: []Object{
			{Ref: "o_workload", Kind: "linux.systemd_workload", Native: map[string]any{"unit": "invoice-worker.service"},
				Attrs: map[string]any{"nftables": map[string]any{"chain": "output"}, "token": "CANARY-SECRET-DO-NOT-LEAK-1"}},
			{Ref: "o_identity", Kind: "linux.local_account", Native: map[string]any{"uid": 995, "user_namespace": "host"},
				Attrs: map[string]any{"name": "svc-invoice"}},
			{Ref: "o_db", Kind: "network.endpoint", Native: map[string]any{
				"address": "10.20.0.15", "port": 5432, "protocol": "tcp", "address_family": "ipv4"}},
		},
		Observations: []Observation{{
			ID: uuid.New(), Kind: "runtime.network_connect", SubjectRef: "o_workload", IdentityRef: "o_identity",
			ResourceRef: "o_db", Runtime: map[string]any{"boot_id": "boot-a", "pid_namespace": "host", "pid": 824, "start_ticks": 93401},
			ObservedAt: time.Now(), Outcome: "success", Attribution: "kernel_process_credentials",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Workloads) != 1 || plan.Workloads[0].RuntimeKind != "systemd" {
		t.Fatalf("workloads %+v", plan.Workloads)
	}
	if len(plan.Identities) != 1 || plan.Identities[0].Kind != "local_user" || plan.Identities[0].Name != "svc-invoice" {
		t.Fatalf("identities %+v", plan.Identities)
	}
	if len(plan.Resources) != 1 || len(plan.Runtimes) != 1 || len(plan.Bindings) != 1 || len(plan.Observed) != 1 {
		t.Fatalf("res %d rt %d bind %d obs %d", len(plan.Resources), len(plan.Runtimes), len(plan.Bindings), len(plan.Observed))
	}
	if plan.Bindings[0].Kind != "uid" || plan.Observed[0].Outcome != "success" {
		t.Fatalf("binding %+v observed %+v", plan.Bindings[0], plan.Observed[0])
	}
	var nft bool
	for _, pol := range plan.Policies {
		if pol.Kind == "linux_nftables" {
			nft = true
		}
		if strings.Contains(string(pol.Document), "CANARY-SECRET-DO-NOT-LEAK") {
			t.Fatal("secret reached a policy document")
		}
	}
	if !nft {
		t.Fatal("nftables policy missing")
	}
	if strings.Contains(string(plan.Workloads[0].Attrs), "CANARY-SECRET-DO-NOT-LEAK") {
		t.Fatal("token stored on the workload")
	}
	again, err := ProcessPair(estate)
	if err != nil {
		t.Fatal(err)
	}
	if again[0] == again[1] {
		t.Fatal("pid reuse collapsed")
	}
}

func ProcessPair(estate string) ([2]string, error) {
	a, err := Normalize(Input{Provider: "linux", EstateID: estate, Objects: []Object{{
		Ref: "g", Kind: "linux.process_group",
		Native: map[string]any{"boot_id": "b", "root_pid": "1", "start_ticks": "9"},
	}}})
	if err != nil {
		return [2]string{}, err
	}
	b, err := Normalize(Input{Provider: "linux", EstateID: estate, Objects: []Object{{
		Ref: "g", Kind: "linux.process_group",
		Native: map[string]any{"boot_id": "b", "root_pid": "1", "start_ticks": "10"},
	}}})
	if err != nil {
		return [2]string{}, err
	}
	return [2]string{a.Workloads[0].SourceKey, b.Workloads[0].SourceKey}, nil
}

func TestKubernetesRBACKeepsScopeAndDoesNotInventRules(t *testing.T) {
	estate := "cluster-1"
	plan, err := Normalize(Input{Provider: "kubernetes", EstateID: estate, Objects: []Object{
		{Ref: "sa", Kind: "k8s.service_account", Native: map[string]any{"namespace": "pay", "name": "invoice", "uid": "sa-uid-1"}},
		{Ref: "def", Kind: "k8s.service_account", Native: map[string]any{"namespace": "pay", "name": "default", "uid": "sa-def"}},
		{Ref: "role", Kind: "k8s.cluster_role", Native: map[string]any{
			"name": "view", "uid": "role-1",
			"rules": []any{map[string]any{
				"apiGroups": []any{""}, "resources": []any{"pods"}, "verbs": []any{"get"},
				"resourceNames": []any{"invoice"}, "nonResourceURLs": []any{"/healthz"},
			}},
		}},
		{Ref: "agg", Kind: "k8s.cluster_role", Native: map[string]any{
			"name": "agg", "uid": "role-2", "aggregationRule": map[string]any{"clusterRoleSelectors": []any{}},
		}},
		{Ref: "bind", Kind: "k8s.role_binding", Native: map[string]any{
			"name": "view-pay", "namespace": "pay", "namespace_uid": "ns-pay", "uid": "bind-1",
			"roleRef": map[string]any{"kind": "ClusterRole", "name": "view"},
			"subjects": []any{
				map[string]any{"kind": "ServiceAccount", "name": "invoice", "namespace": "pay"},
				map[string]any{"kind": "User", "name": "ada@example.com"},
			},
		}},
		{Ref: "dep", Kind: "k8s.workload", Native: map[string]any{
			"apiGroup": "apps", "kind": "Deployment", "namespace": "pay", "name": "invoice", "uid": "dep-1", "slot": "0",
			"serviceAccountName": "invoice",
			"annotations":        map[string]any{"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/invoice"},
		}},
		{Ref: "pending", Kind: "k8s.workload", Native: map[string]any{
			"apiGroup": "apps", "kind": "Deployment", "namespace": "other", "name": "job", "uid": "dep-2", "slot": "0",
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var namespaced bool
	for _, a := range plan.Assignments {
		if a.Kind == "k8s_role_binding" && a.ScopeKind == "namespace" && a.NamespaceUID == "ns-pay" {
			namespaced = true
		}
	}
	if !namespaced {
		t.Fatalf("RoleBinding to ClusterRole was not kept namespaced: %+v", plan.Assignments)
	}
	var keptNames bool
	for _, st := range plan.Statements {
		if strings.Contains(string(st.Rights), "nonResourceURLs") || strings.Contains(string(st.Rights), "/healthz") {
			keptNames = strings.Contains(string(st.Rights), "invoice")
		}
	}
	if !keptNames {
		t.Fatal("resourceNames or nonResourceURLs were dropped")
	}
	var partial bool
	for _, pol := range plan.Policies {
		if pol.Name == "agg" && pol.Partial {
			partial = true
		}
	}
	if !partial {
		t.Fatal("aggregated role without rules must stay partial")
	}
	for _, g := range plan.Grants {
		if g.Calculation != "partial" || g.Conclusion != "unknown" {
			t.Fatalf("grant is an authz verdict: %+v", g)
		}
	}
	var declared, pending bool
	for _, rel := range plan.Relationships {
		if rel.Type == "executes_as" && rel.Basis == "declared" {
			declared = true
		}
	}
	for _, id := range plan.Identities {
		if id.Name == "default" && id.ImmutableKey == "sa-def" {
			// present
		}
		if id.Backing == "pending" {
			pending = true
		}
	}
	if !declared || !pending {
		t.Fatalf("declared %v pending %v", declared, pending)
	}
	var standardGroup, derivedMember bool
	for _, id := range plan.Identities {
		if id.Kind == "k8s_group" && id.Name == "system:serviceaccounts:pay" {
			standardGroup = true
		}
	}
	for _, rel := range plan.Relationships {
		if rel.Type == "member_of" && rel.Basis == "derived" && rel.DerivationRule == "k8s.serviceaccount.group.v1" {
			derivedMember = true
		}
	}
	if !standardGroup || !derivedMember {
		t.Fatal("standard serviceaccount group or its derived membership is missing")
	}
	var userUnresolved, roleUnresolved bool
	for _, u := range plan.Unresolved {
		if strings.HasPrefix(u, "k8s-user:") {
			userUnresolved = true
		}
		if strings.Contains(u, "arn:aws:iam::123456789012:role/invoice") {
			roleUnresolved = true
		}
	}
	if !userUnresolved || !roleUnresolved {
		t.Fatalf("unresolved %+v", plan.Unresolved)
	}
	for _, id := range plan.Identities {
		if id.Provider == "aws" {
			t.Fatal("annotation fabricated an AWS identity")
		}
	}
	recreated, err := Normalize(Input{Provider: "kubernetes", EstateID: estate, Objects: []Object{
		{Kind: "k8s.service_account", Native: map[string]any{"namespace": "pay", "name": "invoice", "uid": "sa-uid-2"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var first string
	for _, id := range plan.Identities {
		if id.Name == "invoice" && id.Kind == "k8s_service_account" {
			first = id.SourceKey
		}
	}
	if recreated.Identities[0].SourceKey != first || recreated.Identities[0].ImmutableKey == "sa-uid-1" {
		t.Fatalf("recreate key %s uid %s", recreated.Identities[0].SourceKey, recreated.Identities[0].ImmutableKey)
	}
}

func TestADProjectsWithoutMailAndKeepsRename(t *testing.T) {
	forest := "DC=authsec,DC=test"
	guid := "aabbccdd-eeff-0011-2233-445566778899"
	raw := func(kind, dn, name string, disabled bool, member []string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{
			"account_kind": kind, "object_guid": guid, "object_sid": "S-1-5-21-1",
			"distinguished_name": dn, "sam_account_name": name, "forest_id": forest,
			"member": member, "account_flags": map[string]any{"account_disabled": disabled},
			"msDS-ManagedPassword": "CANARY-SECRET-DO-NOT-LEAK-2",
		})
		return b
	}
	// Distinct GUIDs for the group graph.
	user := adRaw(forest, "11111111-1111-1111-1111-111111111111", "ad_user", "CN=ada,DC=test", "ada", false, nil)
	disabled := adRaw(forest, "22222222-2222-2222-2222-222222222222", "ad_user", "CN=off,DC=test", "off", true, nil)
	group := adRaw(forest, "33333333-3333-3333-3333-333333333333", "ad_group", "CN=eng,DC=test", "eng", false, []string{"CN=ada,DC=test", "CN=ops,DC=test"})
	nested := adRaw(forest, "44444444-4444-4444-4444-444444444444", "ad_group", "CN=ops,DC=test", "ops", false, nil)
	computer := adRaw(forest, "55555555-5555-5555-5555-555555555555", "ad_computer", "CN=host,DC=test", "host", false, nil)
	gmsa := adRaw(forest, "66666666-6666-6666-6666-666666666666", "ad_managed_service_account", "CN=msa,DC=test", "msa", false, nil)
	plan, err := Normalize(Input{Provider: "ad", Objects: []Object{
		{Kind: "user", Raw: user},
		{Kind: "user", Raw: disabled},
		{Kind: "group", Raw: group},
		{Kind: "group", Raw: nested},
		{Kind: "computer", Raw: computer},
		{Kind: "msDS-GroupManagedServiceAccount", Raw: gmsa},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Identities) != 6 {
		t.Fatalf("identities %d", len(plan.Identities))
	}
	var off, member int
	for _, id := range plan.Identities {
		if strings.Contains(string(id.Attrs), "CANARY-SECRET-DO-NOT-LEAK") {
			t.Fatal("secret attribute stored")
		}
		if id.Name == "off" && id.State != "disabled" {
			t.Fatalf("disabled state %+v", id)
		}
		if id.Name == "off" {
			off++
		}
	}
	for _, rel := range plan.Relationships {
		if rel.Type == "member_of" {
			member++
		}
	}
	if off != 1 || member != 2 {
		t.Fatalf("off %d member %d unresolved %+v", off, member, plan.Unresolved)
	}
	renamed := adRaw(forest, "11111111-1111-1111-1111-111111111111", "ad_user", "CN=ada-renamed,DC=test", "ada2", false, nil)
	again, err := Normalize(Input{Provider: "ad", Objects: []Object{{Kind: "user", Raw: renamed}}})
	if err != nil {
		t.Fatal(err)
	}
	var first string
	for _, id := range plan.Identities {
		if id.Name == "ada" {
			first = id.SourceKey
		}
	}
	if again.Identities[0].SourceKey != first {
		t.Fatalf("rename changed the key %s -> %s", first, again.Identities[0].SourceKey)
	}
	_ = guid
	_ = raw
}

func adRaw(forest, guid, kind, dn, name string, disabled bool, member []string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"account_kind": kind, "object_guid": guid, "object_sid": "S-1-5-21-1",
		"distinguished_name": dn, "sam_account_name": name, "display_name": name,
		"forest_id": forest, "member": member,
		"account_flags":        map[string]any{"account_disabled": disabled},
		"msDS-ManagedPassword": "CANARY-SECRET-DO-NOT-LEAK-2",
	})
	return b
}
