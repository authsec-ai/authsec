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

func TestAccessPolicyAzure(t *testing.T) {
	l := newAPLab(t)
	if err := services.VerifyAzureAccessSchema(l.db); err != nil {
		t.Skip(err.Error())
	}
	ctx := context.Background()
	tenantID, sub := uuid.NewString(), uuid.NewString()
	scope := "/subscriptions/" + sub + "/resourcegroups/rg/providers/microsoft.storage/storageaccounts/stdemo"

	p3exec(t, l.db, `INSERT INTO cloud_connector (workspace_id, provider, scope_kind, scope_id, parent_scope_id, status, auth_ref, attrs)
		VALUES (?, 'azure', 'subscription', ?, ?, 'active', 'vault://azure/test', jsonb_build_object('display_name', 'Authnull', 'tenant_id', ?::text))`,
		l.ws, sub, tenantID, tenantID)
	res := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_resources (id, workspace_id, resource_kind, display_name, provider, source_key)
		VALUES (?, ?, 'storage_account', 'stdemo', 'azure', ?)`, res, l.ws, "azure\x1f"+tenantID+"\x1fresource\x1f"+scope)
	principal := func(name string) (uuid.UUID, string) {
		id, oid := uuid.New(), uuid.NewString()
		p3exec(t, l.db, `INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, provider, source_key, continuity, immutable_key, display_name, provider_attrs)
			VALUES (?, ?, ?, 'azure', ?, 'immutable', ?, ?, '{}'::jsonb)`,
			id, l.ws, models.CloudIdentityEntraServicePrincipal, "azure\x1f"+tenantID+"\x1fobject\x1f"+oid, oid, name)
		return id, oid
	}
	blocked, blockedOID := principal("sp-reader")
	allowed, allowedOID := principal("sp-new")
	wide, wideOID := principal("sp-sub-wide")

	readerDef := azure.RoleDefinitionResourceID(sub, azure.RoleStorageBlobDataReader)
	fake := &fakeRBAC{as: map[string]azure.RoleAssignment{}, defs: []azure.RoleDefinition{
		azureDef(t, sub, azure.RoleStorageBlobDataReader, nil, []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"}),
		azureDef(t, sub, azure.RoleStorageBlobDataContributor, nil, []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"}),
		azureDef(t, sub, azure.RoleReader, []string{"*/read"}, nil),
	}}
	fake.PutRoleAssignment(ctx, "", azure.RoleAssignmentSpec{Scope: scope, Name: "orig-1", RoleDefinitionID: readerDef,
		PrincipalID: blockedOID, PrincipalType: "ServicePrincipal"})
	fake.PutRoleAssignment(ctx, "", azure.RoleAssignmentSpec{Scope: "/subscriptions/" + sub, Name: "wide-1",
		RoleDefinitionID: azure.RoleDefinitionResourceID(sub, azure.RoleStorageBlobDataContributor), PrincipalID: wideOID, PrincipalType: "ServicePrincipal"})
	defer services.SetAzureAccessDeps(&services.AzureAccessDeps{RBAC: fake,
		Token: func(context.Context, uuid.UUID, string) (string, error) { return "tok", nil }})()

	run := func(policy uuid.UUID) {
		t.Helper()
		gov := services.NewGovAccess(l.db)
		for pass := 0; pass < 6; pass++ {
			var rows []models.IGAGovAzureAccess
			l.db.Where("workspace_id = ? AND policy_id = ? AND state IN ?", l.ws, policy,
				[]string{models.R2StateApproved, models.R2StateDeploying, models.R2StateExpiring}).Find(&rows)
			if len(rows) == 0 {
				return
			}
			for _, r := range rows {
				p3exec(t, l.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now(), lease_owner = '', lease_expires_at = NULL
					WHERE workspace_id = ? AND kind = 'azure_access' AND status IN ('queued','running')`, l.ws)
				id := r.ID
				if _, err := repositories.NewIGAGovJobRepository(l.db).EnqueueTx(l.db, &models.IGAGovJob{WorkspaceID: l.ws,
					Kind: repositories.GovJobAzureAccess, SubjectID: &id, DedupeKey: "azure_access:" + id.String(), RunAfter: time.Now().Add(-time.Hour)}); err != nil {
					t.Fatal(err)
				}
				j := p3ClaimOwn(t, l.db, l.ws, "worker-az", 2*time.Minute, time.Now(), repositories.GovJobAzureAccess)
				if j == nil {
					t.Fatalf("no azure_access job for %s", id)
				}
				err := gov.AzureAccessHandler(ctx, services.NewPolicyJobRun(l.db, *j, "worker-az"))
				p3exec(t, l.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now() WHERE id = ?`, j.ID)
				if err != nil && !isRetryLater(err) {
					t.Fatalf("azure_access %s: %v", id, err)
				}
			}
		}
		t.Fatalf("Azure rows of %s did not settle", policy)
	}
	end := time.Now().Add(time.Hour)
	intent := func(effect string, who uuid.UUID) igagov.AccessIntent {
		return igagov.AccessIntent{Effect: effect, Resource: igagov.AccessResource{ResourceID: res.String()},
			Roles: []igagov.AccessRole{{IdentityAccountID: who.String()}}, Access: []string{"read"}, EndsAt: &end}
	}

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
