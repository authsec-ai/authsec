package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// A block on an Azure AI Search service reaches its index data. The agent in
// the field queried an index with Search Index Data Reader, a role with data
// actions only, so a block that looked only at management actions left it in
// place: the policy said Active and the agent kept answering. Now the block
// removes it (and Search Service Contributor, which lists the admin keys), End
// restores both, and an allow assigns Search Index Data Reader.
func TestAccessPolicyAzureSearchIndex(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	tenantID, sub := uuid.NewString(), uuid.NewString()
	scope := "/subscriptions/" + sub + "/resourcegroups/rg/providers/microsoft.search/searchservices/sales-search"

	p3exec(t, l.db, `INSERT INTO cloud_connector (workspace_id, provider, scope_kind, scope_id, parent_scope_id, status, auth_ref)
		VALUES (?, 'azure', 'subscription', ?, ?, 'active', 'vault://azure/test')`, l.ws, sub, tenantID)
	res := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_resources (id, workspace_id, resource_kind, display_name, provider, source_key)
		VALUES (?, ?, 'microsoft.search/searchservices', 'sales-search', 'azure', ?)`, res, l.ws, "azure\x1f"+tenantID+"\x1fresource\x1f"+scope)
	principal := func(name string) (uuid.UUID, string) {
		id, oid := uuid.New(), uuid.NewString()
		p3exec(t, l.db, `INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, provider, source_key, continuity, immutable_key, display_name, provider_attrs)
			VALUES (?, ?, ?, 'azure', ?, 'immutable', ?, ?, '{}'::jsonb)`,
			id, l.ws, models.CloudIdentityEntraManagedIdentity, "azure\x1f"+tenantID+"\x1fobject\x1f"+oid, oid, name)
		return id, oid
	}
	agent, agentOID := principal("foundry-project-mi")
	newcomer, newcomerOID := principal("other-agent-mi")

	const searchServiceContributor = "7ca78c08-252a-4471-8644-bb5ff32d4ba0"
	fake := &fakeRBAC{as: map[string]azure.RoleAssignment{}, defs: []azure.RoleDefinition{
		azureDef(t, sub, azure.RoleSearchIndexDataReader, nil, []string{"Microsoft.Search/searchServices/indexes/documents/read"}),
		azureDef(t, sub, azure.RoleSearchIndexDataContributor, nil, []string{"Microsoft.Search/searchServices/indexes/documents/*"}),
		azureDef(t, sub, searchServiceContributor, []string{"Microsoft.Search/searchServices/*"}, nil),
		azureDef(t, sub, azure.RoleStorageBlobDataReader, nil, []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"}),
	}}
	for name, role := range map[string]string{"idx-reader": azure.RoleSearchIndexDataReader, "svc-contrib": searchServiceContributor} {
		fake.PutRoleAssignment(ctx, "", azure.RoleAssignmentSpec{Scope: scope, Name: name,
			RoleDefinitionID: azure.RoleDefinitionResourceID(sub, role), PrincipalID: agentOID, PrincipalType: "ServicePrincipal"})
	}
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

	// Block read: both of the agent's roles on the service go, and come back on End.
	v, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: intent("block", agent), Name: "block search", Reason: "t"})
	if err != nil {
		t.Fatalf("create block: %v", err)
	}
	run(v.ID)
	if got := fake.roles(agentOID); len(got) != 0 {
		t.Fatalf("the agent still holds %v on the search service", got)
	}
	if _, err := l.svc.End(ctx, l.ws, l.user, v.ID, services.AccessReasonRequest{Reason: "done"}); err != nil {
		t.Fatal(err)
	}
	run(v.ID)
	if got := fake.roles(agentOID); len(got) != 2 {
		t.Fatalf("End did not restore both roles: %v", got)
	}

	// Allow read: AuthSec assigns Search Index Data Reader, not Reader.
	v, err = l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: intent("allow", newcomer), Name: "allow search", Reason: "t"})
	if err != nil {
		t.Fatalf("create allow: %v", err)
	}
	run(v.ID)
	if got := fake.roles(newcomerOID); len(got) != 1 || got[0] != azure.RoleSearchIndexDataReader {
		t.Fatalf("allow assigned %v, want Search Index Data Reader", got)
	}
	if _, err := l.svc.End(ctx, l.ws, l.user, v.ID, services.AccessReasonRequest{Reason: "done"}); err != nil {
		t.Fatal(err)
	}
	run(v.ID)
	if got := fake.roles(newcomerOID); len(got) != 0 {
		t.Fatalf("End left the allow's assignment: %v", got)
	}
}
