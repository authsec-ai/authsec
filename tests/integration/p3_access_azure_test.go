package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// Access policies on an Azure storage account (144), over a fake
// role-assignment API: a block removes the principal's own assignment and End
// restores it; an allow creates an assignment and End deletes it; access from
// a broader scope is a preview blocker.

type fakeRBAC struct {
	mu   sync.Mutex
	defs []azure.RoleDefinition
	as   map[string]azure.RoleAssignment // by lower-case id
}

func (f *fakeRBAC) ListRoleAssignmentsForPrincipal(_ context.Context, _, _, principal string) ([]azure.RoleAssignment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []azure.RoleAssignment
	for _, a := range f.as {
		if a.Properties.PrincipalID == principal {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeRBAC) ListRoleDefinitions(context.Context, string, string) ([]azure.RoleDefinition, error) {
	return f.defs, nil
}

func (f *fakeRBAC) PutRoleAssignment(_ context.Context, _ string, s azure.RoleAssignmentSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := s.Scope + "/providers/Microsoft.Authorization/roleAssignments/" + s.Name
	var a azure.RoleAssignment
	a.ID, a.Name = id, s.Name
	a.Properties.Scope, a.Properties.RoleDefinitionID, a.Properties.PrincipalID, a.Properties.PrincipalType =
		s.Scope, s.RoleDefinitionID, s.PrincipalID, s.PrincipalType
	f.as[strings.ToLower(id)] = a
	return id, nil
}

func (f *fakeRBAC) GetRoleAssignment(_ context.Context, _, id string) (*azure.RoleAssignment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.as[strings.ToLower(id)]; ok {
		return &a, nil
	}
	return nil, nil
}

func (f *fakeRBAC) DeleteRoleAssignment(_ context.Context, _, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.as, strings.ToLower(id))
	return nil
}

func (f *fakeRBAC) CallerPermissions(context.Context, string, string) ([]azure.Permission, error) {
	return []azure.Permission{{Actions: []string{"Microsoft.Authorization/roleAssignments/*"}}}, nil
}

func (f *fakeRBAC) roles(principal string) []string {
	as, _ := f.ListRoleAssignmentsForPrincipal(context.Background(), "", "", principal)
	var out []string
	for _, a := range as {
		out = append(out, a.Properties.RoleDefinitionID[strings.LastIndex(a.Properties.RoleDefinitionID, "/")+1:])
	}
	return out
}

func azureDef(t *testing.T, sub, guid string, actions, dataActions []string) azure.RoleDefinition {
	t.Helper()
	var d azure.RoleDefinition
	raw, _ := json.Marshal(map[string]any{"id": azure.RoleDefinitionResourceID(sub, guid), "name": guid,
		"properties": map[string]any{"permissions": []map[string]any{{"actions": actions, "dataActions": dataActions}}}})
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// azLab is a workspace with one connected subscription holding the storage
// account stdemo, over a fakeRBAC.
type azLab struct {
	*apLab
	t             *testing.T
	ctx           context.Context
	fake          *fakeRBAC
	tenantID, sub string
	scope         string // stdemo
	res           uuid.UUID
}

func newAzLab(t *testing.T) *azLab {
	l := newAPLab(t)
	if err := services.VerifyAzureAccessSchema(l.db); err != nil {
		t.Skip(err.Error())
	}
	z := &azLab{apLab: l, t: t, ctx: context.Background(), tenantID: uuid.NewString(), sub: uuid.NewString()}
	z.scope = "/subscriptions/" + z.sub + "/resourcegroups/rg/providers/microsoft.storage/storageaccounts/stdemo"
	p3exec(t, l.db, `INSERT INTO cloud_connector (workspace_id, provider, scope_kind, scope_id, parent_scope_id, status, auth_ref, attrs)
		VALUES (?, 'azure', 'subscription', ?, ?, 'active', 'vault://azure/test', jsonb_build_object('display_name', 'Authnull', 'tenant_id', ?::text))`,
		l.ws, z.sub, z.tenantID, z.tenantID)
	z.res = z.resource("storage_account", "stdemo", z.scope)
	z.fake = &fakeRBAC{as: map[string]azure.RoleAssignment{}, defs: []azure.RoleDefinition{
		azureDef(t, z.sub, azure.RoleStorageBlobDataReader, nil, []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"}),
		azureDef(t, z.sub, azure.RoleStorageBlobDataContributor, nil, []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"}),
		azureDef(t, z.sub, azure.RoleReader, []string{"*/read"}, nil),
		azureDef(t, z.sub, roleKeyVaultSecretsUser, nil, []string{"Microsoft.KeyVault/vaults/secrets/getSecret/action"}),
	}}
	t.Cleanup(services.SetAzureAccessDeps(&services.AzureAccessDeps{RBAC: z.fake,
		Token: func(context.Context, uuid.UUID, string) (string, error) { return "tok", nil }}))
	return z
}

// Key Vault Secrets User: data actions only.
const roleKeyVaultSecretsUser = "4633458b-17de-408a-b874-0445c86b69e6"

func (z *azLab) resource(kind, name, scope string) uuid.UUID {
	id := uuid.New()
	p3exec(z.t, z.db, `INSERT INTO iga_resources (id, workspace_id, resource_kind, display_name, provider, source_key)
		VALUES (?, ?, ?, ?, 'azure', ?)`, id, z.ws, kind, name, "azure\x1f"+z.tenantID+"\x1fresource\x1f"+scope)
	return id
}

func (z *azLab) principal(name string) (uuid.UUID, string) {
	id, oid := uuid.New(), uuid.NewString()
	p3exec(z.t, z.db, `INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, provider, source_key, continuity, immutable_key, display_name, provider_attrs)
		VALUES (?, ?, ?, 'azure', ?, 'immutable', ?, ?, '{}'::jsonb)`,
		id, z.ws, models.CloudIdentityEntraServicePrincipal, "azure\x1f"+z.tenantID+"\x1fobject\x1f"+oid, oid, name)
	return id, oid
}

// assign gives the principal a role on scope.
func (z *azLab) assign(scope, name, roleGUID, oid string) {
	z.fake.PutRoleAssignment(z.ctx, "", azure.RoleAssignmentSpec{Scope: scope, Name: name,
		RoleDefinitionID: azure.RoleDefinitionResourceID(z.sub, roleGUID), PrincipalID: oid, PrincipalType: "ServicePrincipal"})
}

// step runs the azure_access job of one row once.
func (z *azLab) step(row uuid.UUID) {
	t := z.t
	t.Helper()
	p3exec(t, z.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now(), lease_owner = '', lease_expires_at = NULL
		WHERE workspace_id = ? AND kind = 'azure_access' AND status IN ('queued','running')`, z.ws)
	if _, err := repositories.NewIGAGovJobRepository(z.db).EnqueueTx(z.db, &models.IGAGovJob{WorkspaceID: z.ws,
		Kind: repositories.GovJobAzureAccess, SubjectID: &row, DedupeKey: "azure_access:" + row.String(), RunAfter: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	j := p3ClaimOwn(t, z.db, z.ws, "worker-az", 2*time.Minute, time.Now(), repositories.GovJobAzureAccess)
	if j == nil {
		t.Fatalf("no azure_access job for %s", row)
	}
	err := services.NewGovAccess(z.db).AzureAccessHandler(z.ctx, services.NewPolicyJobRun(z.db, *j, "worker-az"))
	p3exec(t, z.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now() WHERE id = ?`, j.ID)
	if err != nil && !isRetryLater(err) {
		t.Fatalf("azure_access %s: %v", row, err)
	}
}

// rows are the policy's Azure rows in a state, oldest version first.
func (z *azLab) rows(policy uuid.UUID, states ...string) []models.IGAGovAzureAccess {
	var rows []models.IGAGovAzureAccess
	if err := z.db.Where("workspace_id = ? AND policy_id = ? AND state IN ?", z.ws, policy, states).Order("created_at").Find(&rows).Error; err != nil {
		z.t.Fatal(err)
	}
	return rows
}

// run settles every row of the policy.
func (z *azLab) run(policy uuid.UUID) {
	z.t.Helper()
	for pass := 0; pass < 6; pass++ {
		rows := z.rows(policy, models.R2StateApproved, models.R2StateDeploying, models.R2StateExpiring)
		if len(rows) == 0 {
			return
		}
		for _, r := range rows {
			z.step(r.ID)
		}
	}
	z.t.Fatalf("Azure rows of %s did not settle", policy)
}

func (z *azLab) intent(effect string, res, who uuid.UUID, access ...string) igagov.AccessIntent {
	end := time.Now().Add(time.Hour)
	if len(access) == 0 {
		access = []string{"read"}
	}
	return igagov.AccessIntent{Effect: effect, Resource: igagov.AccessResource{ResourceID: res.String()},
		Roles: []igagov.AccessRole{{IdentityAccountID: who.String()}}, Access: access, EndsAt: &end}
}

func (z *azLab) create(name string, in igagov.AccessIntent) *services.AccessPolicyView {
	z.t.Helper()
	v, err := z.svc.Create(z.ctx, z.ws, z.user, services.AccessPolicyRequest{AccessIntent: in, Name: name, Reason: "t"})
	if err != nil {
		z.t.Fatalf("create %s: %v", name, err)
	}
	return v
}

func (z *azLab) end(id uuid.UUID) {
	z.t.Helper()
	if _, err := z.svc.End(z.ctx, z.ws, z.user, id, services.AccessReasonRequest{Reason: "done"}); err != nil {
		z.t.Fatal(err)
	}
}

func TestAccessPolicyAzure(t *testing.T) {
	z := newAzLab(t)
	l, ctx, fake, sub, scope, res := z.apLab, z.ctx, z.fake, z.sub, z.scope, z.res
	blocked, blockedOID := z.principal("sp-reader")
	allowed, allowedOID := z.principal("sp-new")
	wide, wideOID := z.principal("sp-sub-wide")
	z.assign(scope, "orig-1", azure.RoleStorageBlobDataReader, blockedOID)
	z.assign("/subscriptions/"+sub, "wide-1", azure.RoleStorageBlobDataContributor, wideOID)
	run := z.run
	intent := func(effect string, who uuid.UUID) igagov.AccessIntent { return z.intent(effect, res, who) }

	// Block: the principal's own assignment is removed, then restored on End.
	pv, err := l.svc.Preview(ctx, l.ws, intent("block", blocked))
	if err != nil || len(pv.Blockers) != 0 || !strings.Contains(pv.Sentence, "Block read on Azure") {
		t.Fatalf("block preview: %+v %v", pv, err)
	}
	v, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: intent("block", blocked), Name: "az block", Reason: "t"})
	if err != nil {
		t.Fatalf("create block: %v", err)
	}
	run(v.ID)
	if got := fake.roles(blockedOID); len(got) != 0 {
		t.Fatalf("blocked principal still has %v", got)
	}
	if v, err = l.svc.Get(ctx, l.ws, v.ID); err != nil || v.Status != services.AccessStatusActive {
		t.Fatalf("block after apply: %+v %v", v, err)
	}
	// The views say which cloud: resource provider/name/kind, role kind,
	// the deployment's ARM scope.
	if v.Resource.Provider != "azure" || v.Resource.Name != "stdemo" || v.Resource.Kind != "storage_account" ||
		v.Resource.ARN != scope || v.Resource.AccountID != sub || v.Resource.Bucket != "" {
		t.Fatalf("resource view: %+v", v.Resource)
	}
	if len(v.Roles) != 1 || v.Roles[0].Kind != models.CloudIdentityEntraServicePrincipal || v.Roles[0].ARN != "" || v.Roles[0].Name != "sp-reader" {
		t.Fatalf("role view: %+v", v.Roles)
	}
	if len(v.Deployments) != 1 || v.Deployments[0].TargetRef != scope || v.Deployments[0].AWSPolicyARN != "" {
		t.Fatalf("deployment view: %+v", v.Deployments)
	}
	if got, _, err := l.svc.List(ctx, l.ws, services.AccessListQuery{Provider: "azure"}); err != nil || len(got) != 1 {
		t.Fatalf("?provider=azure: %d %v", len(got), err)
	}
	if got, _, err := l.svc.List(ctx, l.ws, services.AccessListQuery{Provider: "aws"}); err != nil || len(got) != 0 {
		t.Fatalf("?provider=aws: %d %v", len(got), err)
	}
	if _, _, err := l.svc.List(ctx, l.ws, services.AccessListQuery{Provider: "gcp"}); err == nil {
		t.Fatal("?provider=gcp accepted")
	}
	// Readiness: the subscription, by name, ready (the fake can write).
	rd, err := services.AccessPolicyReadiness(ctx, l.db, l.ws)
	if err != nil || len(rd.AzureSubscriptions) != 1 || !rd.AzureSubscriptions[0].Ready || rd.AzureSubscriptions[0].Name != "Authnull" ||
		rd.AzureSubscriptions[0].SubscriptionID != sub {
		t.Fatalf("readiness: %+v %v", rd, err)
	}
	if _, err := l.svc.End(ctx, l.ws, l.user, v.ID, services.AccessReasonRequest{Reason: "done"}); err != nil {
		t.Fatal(err)
	}
	// Until the assignment is back, the policy is ending, not ended.
	if v, err = l.svc.Get(ctx, l.ws, v.ID); err != nil || v.Status != services.AccessStatusEnding ||
		v.StatusReason != "restoring access in Azure" || v.EndedAt != nil {
		t.Fatalf("after End, before the job: %+v %v", v, err)
	}
	run(v.ID)
	if got := fake.roles(blockedOID); len(got) != 1 || got[0] != azure.RoleStorageBlobDataReader {
		t.Fatalf("End did not restore the assignment: %v", got)
	}
	if v, err = l.svc.Get(ctx, l.ws, v.ID); err != nil || v.Status != services.AccessStatusEnded || v.EndedAt == nil {
		t.Fatalf("after the restore: %+v %v", v, err)
	}

	// Allow: AuthSec's assignment exists while active, gone after End.
	v, err = l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: intent("allow", allowed), Name: "az allow", Reason: "t"})
	if err != nil {
		t.Fatalf("create allow: %v", err)
	}
	run(v.ID)
	if got := fake.roles(allowedOID); len(got) != 1 || got[0] != azure.RoleStorageBlobDataReader {
		t.Fatalf("allow did not assign: %v", got)
	}
	if _, err := l.svc.End(ctx, l.ws, l.user, v.ID, services.AccessReasonRequest{Reason: "done"}); err != nil {
		t.Fatal(err)
	}
	if v, err = l.svc.Get(ctx, l.ws, v.ID); err != nil || v.Status != services.AccessStatusEnding || v.StatusReason != "removing from Azure" {
		t.Fatalf("allow after End, before the job: %+v %v", v, err)
	}
	run(v.ID)
	if got := fake.roles(allowedOID); len(got) != 0 {
		t.Fatalf("End left the allow's assignment: %v", got)
	}

	// Inherited access cannot be blocked on one resource.
	pv, err = l.svc.Preview(ctx, l.ws, intent("block", wide))
	if err != nil || len(pv.Blockers) != 1 || pv.Blockers[0].Code != services.GovCodeAzureInherited {
		t.Fatalf("inherited preview: %+v %v", pv, err)
	}
}

// Without migration 144, Azure access policies are unavailable (503 with the
// reason) and AWS ones keep working. Runs only on a database without 144.
func TestAccessPolicyAzureWithout144(t *testing.T) {
	l := newAPLab(t)
	if err := services.VerifyAzureAccessSchema(l.db); err == nil {
		t.Skip("this database has migration 144")
	}
	ctx := context.Background()
	tenantID, sub := uuid.NewString(), uuid.NewString()
	res := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_resources (id, workspace_id, resource_kind, display_name, provider, source_key)
		VALUES (?, ?, 'storage_account', 'stdemo', 'azure', ?)`, res, l.ws,
		"azure\x1f"+tenantID+"\x1fresource\x1f/subscriptions/"+sub+"/resourcegroups/rg/providers/microsoft.storage/storageaccounts/stdemo")
	end := time.Now().Add(time.Hour)
	_, err := l.svc.Preview(ctx, l.ws, igagov.AccessIntent{Effect: "block", Resource: igagov.AccessResource{ResourceID: res.String()},
		Roles: []igagov.AccessRole{{IdentityAccountID: uuid.NewString()}}, Access: []string{"read"}, EndsAt: &end})
	var ge *services.GovError
	if !errors.As(err, &ge) || ge.Status != 503 || !strings.Contains(fmt.Sprint(ge.Detail["reason"]), "144") {
		t.Fatalf("Azure preview without 144: %v", err)
	}
	a := l.role("ApNo144Role")
	v, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{Name: "aws still works", Reason: "t",
		AccessIntent: igagov.AccessIntent{Effect: "block", Resource: igagov.AccessResource{ResourceID: l.bucket.String()},
			Roles: []igagov.AccessRole{{IdentityAccountID: a.String()}}, Access: []string{"read"}, EndsAt: &end}})
	if err != nil {
		t.Fatalf("AWS create without 144: %v", err)
	}
	l.run(v.ID)
	if got, _, err := l.svc.List(ctx, l.ws, services.AccessListQuery{}); err != nil || len(got) != 1 || got[0].Resource.Provider != "aws" {
		t.Fatalf("AWS list without 144: %+v %v", got, err)
	}
}

// Two blocks keeping the same assignment removed: whichever ends first hands
// it to the other instead of restoring it. Before, ending the first one gave
// the access back while the second was active (until its next check), and
// editing a block did the same whenever the old version ended after the new
// one had deployed (it had found nothing left to record).
func TestAccessPolicyAzureOverlappingBlocks(t *testing.T) {
	z := newAzLab(t)
	stillBlocked := func(oid, when string) {
		t.Helper()
		if got := z.fake.roles(oid); len(got) != 0 {
			t.Fatalf("%s: the principal has %v back while a block is active", when, got)
		}
	}

	// Two policies.
	{
		who, oid := z.principal("sp-two")
		z.assign(z.scope, "two-1", azure.RoleStorageBlobDataReader, oid)
		a := z.create("az block a", z.intent("block", z.res, who))
		z.run(a.ID)
		b := z.create("az block b", z.intent("block", z.res, who))
		z.run(b.ID)
		z.end(a.ID)
		z.run(a.ID)
		stillBlocked(oid, "after the first block ended")
		z.end(b.ID)
		z.run(b.ID)
		if got := z.fake.roles(oid); len(got) != 1 || got[0] != azure.RoleStorageBlobDataReader {
			t.Fatalf("after both ended: %v, want the reader back", got)
		}
	}

	// An edit is make-before-break: the new version deploys (the assignment
	// is already gone, so it records nothing), then the old one is
	// superseded and ends.
	// Editing a block.
	{
		who, oid := z.principal("sp-edit")
		z.assign(z.scope, "edit-1", azure.RoleStorageBlobDataReader, oid)
		v := z.create("az edit", z.intent("block", z.res, who))
		z.run(v.ID)
		stillBlocked(oid, "after the first version")
		in := z.intent("block", z.res, who, "read", "write")
		if _, err := z.svc.Edit(z.ctx, z.ws, z.user, v.ID, services.AccessPolicyRequest{AccessIntent: in, Name: v.Name, Reason: "wider",
			BaseVersionNo: 1}); err != nil {
			t.Fatalf("edit: %v", err)
		}
		cur := z.rows(v.ID, models.R2StateApproved)
		if len(cur) != 1 {
			t.Fatalf("after edit: %d approved rows", len(cur))
		}
		z.step(cur[0].ID)
		old := z.rows(v.ID, models.R2StateExpiring)
		if len(old) != 1 {
			t.Fatalf("the new version is active but %d old rows are expiring", len(old))
		}
		z.step(old[0].ID)
		stillBlocked(oid, "after the edit settled")
		z.end(v.ID)
		z.run(v.ID)
		if got := z.fake.roles(oid); len(got) != 1 {
			t.Fatalf("after End: %v, want the reader back", got)
		}
	}

	// A handed assignment on a block that ends undeployed is restored.
	{
		who, oid := z.principal("sp-undeployed")
		z.assign(z.scope, "undeployed-1", azure.RoleStorageBlobDataReader, oid)
		a := z.create("az undeployed a", z.intent("block", z.res, who))
		z.run(a.ID)
		b := z.create("az undeployed b", z.intent("block", z.res, who))
		bRow := z.rows(b.ID, models.R2StateApproved)[0]
		z.end(a.ID)
		z.run(a.ID) // hands over to b's approved row
		stillBlocked(oid, "after the hand-over")
		z.end(b.ID) // b never deployed; it holds the assignment
		if got := z.rows(b.ID, models.R2StateExpiring); len(got) != 1 || got[0].ID != bRow.ID {
			t.Fatalf("b's row should be expiring to restore: %+v", got)
		}
		z.run(b.ID)
		if got := z.fake.roles(oid); len(got) != 1 {
			t.Fatalf("after b ended: %v, want the reader back", got)
		}
	}
}

// A block and an allow on the same principal and resource cannot run at the
// same time: Azure has no deny, so the two would undo each other. And a block
// never takes over AuthSec's own allow assignment: it would restore it at its
// end as standing access.
func TestAccessPolicyAzureBlockAndAllow(t *testing.T) {
	z := newAzLab(t)
	who, oid := z.principal("sp-both")

	allow := z.create("az allow", z.intent("allow", z.res, who))
	z.run(allow.ID)
	pv, err := z.svc.Preview(z.ctx, z.ws, z.intent("block", z.res, who))
	if err != nil || len(pv.Blockers) != 1 || pv.Blockers[0].Code != services.GovCodeAzureConflict {
		t.Fatalf("block over an active allow: %+v %v", pv, err)
	}
	if _, err := z.svc.Create(z.ctx, z.ws, z.user, services.AccessPolicyRequest{AccessIntent: z.intent("block", z.res, who),
		Name: "az conflicting block", Reason: "t"}); err == nil {
		t.Fatal("a block over an active allow was created")
	}
	z.end(allow.ID)
	z.run(allow.ID)

	other, _ := z.principal("sp-blocked-first")
	block := z.create("az block first", z.intent("block", z.res, other))
	z.run(block.ID)
	if pv, err = z.svc.Preview(z.ctx, z.ws, z.intent("allow", z.res, other)); err != nil || len(pv.Blockers) != 1 ||
		pv.Blockers[0].Code != services.GovCodeAzureConflict {
		t.Fatalf("allow over an active block: %+v %v", pv, err)
	}
	z.end(block.ID)
	z.run(block.ID)

	// Editing an allow into a block: the new block deploys while the old
	// allow's assignment is still there. It is not the block's to record.
	v := z.create("az allow then block", z.intent("allow", z.res, who))
	z.run(v.ID)
	if _, err := z.svc.Edit(z.ctx, z.ws, z.user, v.ID, services.AccessPolicyRequest{AccessIntent: z.intent("block", z.res, who),
		Name: v.Name, Reason: "now block", BaseVersionNo: 1}); err != nil {
		t.Fatalf("edit allow into block: %v", err)
	}
	z.step(z.rows(v.ID, models.R2StateApproved)[0].ID)
	z.step(z.rows(v.ID, models.R2StateExpiring)[0].ID)
	if got := z.fake.roles(oid); len(got) != 0 {
		t.Fatalf("while blocked: %v", got)
	}
	z.end(v.ID)
	z.run(v.ID)
	if got := z.fake.roles(oid); len(got) != 0 {
		t.Fatalf("the block's end gave the allow's assignment back as standing access: %v", got)
	}
}

// Resources other than storage: "all" also removes the roles with data access
// in the type's provider (Key Vault Secrets User); read, write and delete do
// not map to data actions there yet, so a block that would leave such a role
// is refused rather than reported active.
func TestAccessPolicyAzureNonStorageData(t *testing.T) {
	z := newAzLab(t)
	kvScope := "/subscriptions/" + z.sub + "/resourcegroups/rg/providers/microsoft.keyvault/vaults/kvdemo"
	kv := z.resource("key_vault", "kvdemo", kvScope)
	who, oid := z.principal("sp-secrets")
	z.assign(kvScope, "kv-1", roleKeyVaultSecretsUser, oid)

	pv, err := z.svc.Preview(z.ctx, z.ws, z.intent("block", kv, who, "read"))
	if err != nil || len(pv.Blockers) != 1 || pv.Blockers[0].Code != services.GovCodeAzureDataUnclassified {
		t.Fatalf("read block with a data role: %+v %v", pv, err)
	}

	pv, err = z.svc.Preview(z.ctx, z.ws, z.intent("block", kv, who, "all"))
	if err != nil || len(pv.Blockers) != 0 {
		t.Fatalf("all block: %+v %v", pv, err)
	}
	v := z.create("az kv all", z.intent("block", kv, who, "all"))
	z.run(v.ID)
	if got := z.fake.roles(oid); len(got) != 0 {
		t.Fatalf("an all block left %v", got)
	}
	z.end(v.ID)
	z.run(v.ID)
	if got := z.fake.roles(oid); len(got) != 1 || got[0] != roleKeyVaultSecretsUser {
		t.Fatalf("after End: %v", got)
	}

	// A subscription-wide data role is inherited, for "all" too.
	wideWho, wideOID := z.principal("sp-secrets-wide")
	z.assign("/subscriptions/"+z.sub, "kv-wide", roleKeyVaultSecretsUser, wideOID)
	pv, err = z.svc.Preview(z.ctx, z.ws, z.intent("block", kv, wideWho, "all"))
	if err != nil || len(pv.Blockers) != 1 || pv.Blockers[0].Code != services.GovCodeAzureInherited {
		t.Fatalf("all block over a subscription-wide data role: %+v %v", pv, err)
	}
}
