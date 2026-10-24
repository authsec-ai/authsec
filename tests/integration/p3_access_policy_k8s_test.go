package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// Kubernetes access policies (146, block only): a block on a Role takes the
// ServiceAccount out of every binding of it through the in-cluster agent
// (here: the instruction rows are answered as the agent would), records the
// binding's uid, removes it again when a later sweep shows it back, and puts
// it back at the end.

const kapCluster = "kap-cluster"

type kapLab struct {
	*apLab
	src           uuid.UUID
	role, booker  uuid.UUID
	idle, foreign uuid.UUID
}

func newKapLab(t *testing.T) *kapLab {
	t.Helper()
	l := newAPLab(t)
	if err := services.VerifyK8sAccessSchema(l.db); err != nil {
		t.Skip(err.Error())
	}
	k := &kapLab{apLab: l, src: uuid.New()}
	p3exec(t, l.db, `INSERT INTO discovery_sources (id, workspace_id, kind, display_name, cluster_name, actuation_token_hash, enforcement_bindings)
		VALUES (?, ?, ?, ?, ?, 'hash', true)`, k.src, l.ws, models.DiscoverySourceK8sWebhook, "agent-kap", kapCluster)
	t.Cleanup(func() {
		for _, table := range []string{"iga_gov_k8s_access", "provisioning_instructions", "iga_k8s_sweep"} {
			l.db.Exec(`DELETE FROM `+table+` WHERE workspace_id = ?`, l.ws)
		}
	})
	sa := func(name string) models.K8sSubject {
		return models.K8sSubject{Kind: models.K8sSubjectServiceAccount, Name: name, Namespace: "agents"}
	}
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	snap := models.K8sRBACSnapshot{WorkspaceID: l.ws.String(), DiscoverySourceID: k.src.String(), Source: models.DiscoverySourceK8sWebhook,
		Cluster: kapCluster, ScanKind: "rbac", SweepStartedAt: at.Add(-30 * time.Second).Format(time.RFC3339), ObservedAt: at.Format(time.RFC3339),
		Complete: true, ClusterScoped: true, Namespaces: []string{"agents"},
		ServiceAccounts: []models.K8sServiceAccount{{Name: "booker", Namespace: "agents"}, {Name: "idle", Namespace: "agents"}},
		Roles: []models.K8sRole{{Kind: models.K8sKindRole, Name: "secret-reader", Namespace: "agents",
			Rules: []models.K8sPolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}}}},
		Bindings: []models.K8sBinding{
			{Kind: models.K8sKindRoleBinding, Name: "booker-secrets", Namespace: "agents", UID: "uid-1",
				RoleRef: models.K8sRoleRef{Kind: models.K8sKindRole, Name: "secret-reader"}, Subjects: []models.K8sSubject{sa("booker")}},
		}}
	if _, err := services.NewK8sRBACManager(l.db, p3GraphOn(t, l.db)()).Ingest(l.ws, snap); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	id := func(table, key string) uuid.UUID {
		var ids []uuid.UUID
		l.db.Table(table).Where("workspace_id = ? AND source_key = ?", l.ws, key).Pluck("id", &ids)
		if len(ids) != 1 {
			t.Fatalf("%s %q: %v", table, key, ids)
		}
		return ids[0]
	}
	k.role = id("iga_policy", k8sgraph.RoleKey(kapCluster, models.K8sRole{Name: "secret-reader", Namespace: "agents"}))
	k.booker = id("iga_identity_accounts", k8sgraph.ServiceAccountKey(kapCluster, "agents", "booker"))
	k.idle = id("iga_identity_accounts", k8sgraph.ServiceAccountKey(kapCluster, "agents", "idle"))
	return k
}

func (k *kapLab) intent(effect string, sas []uuid.UUID, access ...string) igagov.AccessIntent {
	end := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	in := igagov.AccessIntent{Effect: effect, Resource: igagov.AccessResource{ResourceID: k.role.String()}, Access: access, EndsAt: &end}
	for _, s := range sas {
		in.Roles = append(in.Roles, igagov.AccessRole{IdentityAccountID: s.String()})
	}
	return in
}

// step runs the k8s_access job of one row once.
func (k *kapLab) step(row uuid.UUID) {
	t := k.t
	t.Helper()
	p3exec(t, k.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now(), lease_owner = '', lease_expires_at = NULL
		WHERE workspace_id = ? AND kind = 'k8s_access' AND status IN ('queued','running')`, k.ws)
	if _, err := repositories.NewIGAGovJobRepository(k.db).EnqueueTx(k.db, &models.IGAGovJob{WorkspaceID: k.ws,
		Kind: repositories.GovJobK8sAccess, SubjectID: &row, DedupeKey: "k8s_access:" + row.String(), RunAfter: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	j := p3ClaimOwn(t, k.db, k.ws, "worker-k8s", 2*time.Minute, time.Now(), repositories.GovJobK8sAccess)
	if j == nil {
		t.Fatalf("no k8s_access job for %s", row)
	}
	err := services.NewGovAccess(k.db).K8sAccessHandler(context.Background(), services.NewPolicyJobRun(k.db, *j, "worker-k8s"))
	p3exec(t, k.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now() WHERE id = ?`, j.ID)
	if err != nil && !isRetryLater(err) {
		t.Fatalf("k8s_access %s: %v", row, err)
	}
}

func (k *kapLab) rowOf(policy uuid.UUID) models.IGAGovK8sAccess {
	k.t.Helper()
	var rows []models.IGAGovK8sAccess
	k.db.Where("workspace_id = ? AND policy_id = ?", k.ws, policy).Order("created_at").Find(&rows)
	if len(rows) != 1 {
		k.t.Fatalf("rows of %s: %d", policy, len(rows))
	}
	return rows[0]
}

// agentApplies answers the row's open instruction as the agent does.
func (k *kapLab) agentApplies(row models.IGAGovK8sAccess, kind string, result string) map[string]any {
	k.t.Helper()
	var inst models.ProvisioningInstruction
	if err := k.db.Where("workspace_id = ? AND id = ?", k.ws, *row.InstructionID).Take(&inst).Error; err != nil {
		k.t.Fatal(err)
	}
	if inst.Kind != kind || inst.Status != models.InstructionPending || inst.DiscoverySourceID != k.src {
		k.t.Fatalf("instruction %+v, want pending %s", inst, kind)
	}
	var payload map[string]any
	_ = json.Unmarshal(inst.Payload, &payload)
	p3exec(k.t, k.db, `UPDATE provisioning_instructions SET status = 'applied', applied_at = now(), result = ?::jsonb WHERE id = ?`, result, inst.ID)
	return payload
}

func TestAccessPolicyK8sLifecycle(t *testing.T) {
	k := newKapLab(t)
	ctx := context.Background()
	in := k.intent("block", []uuid.UUID{k.booker}, "all")
	pv, err := k.svc.Preview(ctx, k.ws, in)
	if err != nil || len(pv.Blockers) != 0 || !strings.Contains(pv.Sentence, "Block all access on Kubernetes Role agents/secret-reader (cluster "+kapCluster+")") ||
		!hasWarning(pv, "k8s_whole_binding") || len(pv.Documents) != 1 || !strings.Contains(string(pv.Documents[0].Document), `"booker-secrets"`) {
		t.Fatalf("preview: %+v %v", pv, err)
	}
	v, err := k.svc.Create(ctx, k.ws, k.user, services.AccessPolicyRequest{AccessIntent: in, Name: "Pause booker", Reason: "incident 12"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	row := k.rowOf(v.ID)
	if row.BindingKind != "RoleBinding" || row.BindingNamespace != "agents" || row.BindingName != "booker-secrets" || row.ConnectorID != k.src {
		t.Fatalf("row: %+v", row)
	}

	// Remove: one instruction to the agent; applied, the row is active.
	k.step(row.ID)
	row = k.rowOf(v.ID)
	payload := k.agentApplies(row, models.InstructionRemoveBindingSubject, `{"binding_uid":"uid-1","removed":true}`)
	if payload["name"] != "booker-secrets" || payload["namespace"] != "agents" || payload["role_name"] != "secret-reader" {
		t.Fatalf("payload: %v", payload)
	}
	k.step(row.ID)
	if row = k.rowOf(v.ID); row.State != models.R2StateActive || !strings.Contains(string(row.Removed), "uid-1") {
		t.Fatalf("after removal: %+v", row)
	}
	if got, _ := k.svc.Get(ctx, k.ws, v.ID); got.Status != services.AccessStatusActive || got.Resource.Provider != models.ProviderK8s ||
		got.Resource.Name != "agents/secret-reader" || got.Resource.AccountID != kapCluster || len(got.Deployments) != 1 ||
		got.Deployments[0].TargetRef != "k8s:"+kapCluster+"/rolebinding/agents/booker-secrets" {
		t.Fatalf("view: %+v", got)
	}
	if list, _, err := k.svc.List(ctx, k.ws, services.AccessListQuery{Provider: "k8s"}); err != nil || len(list) != 1 {
		t.Fatalf("list k8s: %v %v", list, err)
	}

	// A sweep well after the removal shows the subject back: removed again.
	p3exec(t, k.db, `UPDATE iga_policy_assignment SET state = 'current', last_confirmed_at = now() + interval '1 hour'
		WHERE workspace_id = ? AND policy_id = ?`, k.ws, k.role)
	k.step(row.ID)
	row = k.rowOf(v.ID)
	if row.Drift != "subject_readded" {
		t.Fatalf("drift: %+v", row)
	}
	// The binding was re-created meanwhile: the re-removal names the new uid,
	// which is what the end restores into.
	k.agentApplies(row, models.InstructionRemoveBindingSubject, `{"binding_uid":"uid-2","removed":true}`)
	p3exec(t, k.db, `UPDATE iga_policy_assignment SET state = 'ended', valid_to = now(), ended_reason = 'deleted' WHERE workspace_id = ? AND policy_id = ?`, k.ws, k.role)
	k.step(row.ID)
	if row = k.rowOf(v.ID); row.Drift != "" || row.State != models.R2StateActive || !strings.Contains(string(row.Removed), "uid-2") {
		t.Fatalf("after re-removal: %+v", row)
	}

	// End: the subject is put back into the same binding.
	if _, err := k.svc.End(ctx, k.ws, k.user, v.ID, services.AccessReasonRequest{Reason: "done"}); err != nil {
		t.Fatal(err)
	}
	k.step(row.ID)
	row = k.rowOf(v.ID)
	payload = k.agentApplies(row, models.InstructionRestoreBindingSubject, `{"outcome":"restored"}`)
	if payload["binding_uid"] != "uid-2" {
		t.Fatalf("restore payload: %v", payload)
	}
	k.step(row.ID)
	if row = k.rowOf(v.ID); row.State != models.R2StateExpired || row.StateReason != "" {
		t.Fatalf("after restore: %+v", row)
	}
	if got, _ := k.svc.Get(ctx, k.ws, v.ID); got.Status != services.AccessStatusEnded {
		t.Fatalf("ended: %s", got.Status)
	}
}

func TestAccessPolicyK8sRefusals(t *testing.T) {
	k := newKapLab(t)
	ctx := context.Background()
	for _, c := range []struct {
		name string
		in   igagov.AccessIntent
		code string
	}{
		{"an allow", k.intent("allow", []uuid.UUID{k.booker}, "read"), services.GovCodeAccessInvalid},
		{"read only", k.intent("block", []uuid.UUID{k.booker}, "read"), services.GovCodeAccessInvalid},
		{"a ServiceAccount without a binding", k.intent("block", []uuid.UUID{k.idle}, "all"), services.GovCodeK8sNoBinding},
		{"an AWS role", k.intent("block", []uuid.UUID{k.apLab.role("NotAServiceAccount")}, "all"), services.GovCodeRoleIneligible},
	} {
		if got := previewCode(k.svc.Preview(ctx, k.ws, c.in)); got != c.code {
			t.Errorf("%s: preview %s, want %s", c.name, got, c.code)
		}
	}

	// An agent that may not change bindings is a blocker.
	p3exec(t, k.db, `UPDATE discovery_sources SET enforcement_bindings = false WHERE id = ?`, k.src)
	if got := previewCode(k.svc.Preview(ctx, k.ws, k.intent("block", []uuid.UUID{k.booker}, "all"))); got != services.GovCodeK8sAgentCannotAct {
		t.Fatalf("agent without bindings: %s", got)
	}
	p3exec(t, k.db, `UPDATE discovery_sources SET enforcement_bindings = true WHERE id = ?`, k.src)

	// A second block on the same subject and binding is refused.
	if _, err := k.svc.Create(ctx, k.ws, k.user, services.AccessPolicyRequest{AccessIntent: k.intent("block", []uuid.UUID{k.booker}, "all"),
		Name: "first", Reason: "t"}); err != nil {
		t.Fatal(err)
	}
	if got := previewCode(k.svc.Preview(ctx, k.ws, k.intent("block", []uuid.UUID{k.booker}, "all"))); got != services.GovCodeK8sPolicyConflict {
		t.Fatalf("second block: %s", got)
	}

	// Another workspace's role is 404.
	other := p3NewGov(t, k.db, "kap-other")
	foreign := uuid.New()
	p3exec(t, k.db, `INSERT INTO iga_policy (id, workspace_id, provider, policy_kind, display_name, source_key, continuity)
		VALUES (?, ?, 'k8s', 'k8s_role', 'theirs', ?, 'recognition_only')`, foreign, other.ws, k8sgraph.RoleKey(kapCluster, models.K8sRole{Name: "theirs", Namespace: "x"}))
	in := k.intent("block", []uuid.UUID{k.booker}, "all")
	in.Resource.ResourceID = foreign.String()
	if got := previewCode(k.svc.Preview(ctx, k.ws, in)); got != services.GovCodeResourceNotFound {
		t.Errorf("another workspace's role: %s", got)
	}
}
