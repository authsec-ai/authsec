package integration

// The frozen-contract fixture (SPEC-iga-phase2-graph.md §5, T6.7): ONE rich
// estate, built through the P2-0 lab's REAL scan worker and REAL projector over
// faked AWS, that every §5.3 route can be called against. The contract tests
// (p2_contract_*_test.go) pin the response shapes on it field by field.
//
// Everything below is produced by the pipeline. Nothing is inserted into the
// graph directly: the only rows written by hand are the workspace member the
// classification decision is made as (users / roles / workspace_memberships,
// which no scan produces) -- and the decision itself goes through the real
// POST route.
//
//	accounts   A 429418377036 (connected, us-east-1), B 905418271234
//	           (connected; its Group listing is DENIED in every scan, its Role
//	           listing in its second: B's roles and their edges go STALE, with
//	           stale_reason), C 300000000003 (never connected: a KMS key and a
//	           trusting root)
//	workloads  Lambda ticket-tools  -> SharedToolRole
//	           Lambda orphan-fn     -> MissingRole (no such role: not_in_inventory)
//	           ECS ticket-worker:1  -> SharedToolRole (task role), ImagePullRole
//	                                   (task_execution_role)
//	           Bedrock support-bot  -> SupportAgentRole (foundation model)
//	SharedToolRole
//	  TicketRead   ReadTickets  s3:GetObject  support-tickets/*   selector
//	               ListTickets  s3:ListBucket support-tickets     exact, Condition;
//	                            the bucket's policy (with a Deny) is READ
//	  ToolboxRead  (no Sid)     s3:GetObject  support-tickets/*   same action and
//	                                                              selector as ReadTickets
//	  FinanceAll   AllButFinance s3:* NotResource finance/*       an exclusion
//	  GuardRails   NoDeletes    Deny s3:DeleteObject support-tickets/*
//	  ExternalKey  Decrypt      kms:Decrypt  key in C             external
//	  CrossKey     DecryptB     kms:Decrypt  key in B             exact, connected
//	  AuditRead    AWS-managed; GetPolicyVersion DENIED           unreadable document
//	  LegacyRead   s3:GetObject support-tickets/*  (detached in scan 3: the path
//	               remains through TicketRead and ToolboxRead)
//	priya (user)   boundary PowerUserAccess; member of ops; inline PriyaOwn; two
//	               access keys
//	ops (group)    OpsRead ops-bucket/*
//	TempRole       present in scan 1, deleted before scan 3 (retired)
//	trust          B CrossRole trusts A SharedToolRole (cross-account) and B
//	               LoopRole; LoopRole trusts CrossRole (a cycle);
//	               A GithubDeployRole trusts GitHub OIDC (repo:acme/app:ref:refs/heads/main);
//	               A PartnerRole trusts C's root (not connected)
//
// Revisions: rev 1 = A's first scan, rev 2 = B's, rev 3 = A's second (the
// detach, TempRole gone, ListTickets' Condition edited: a statement revision),
// rev 4 = B's second (Role listing denied: stale, never ended).

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

const (
	contractAccountC = "300000000003" // NEVER connected
	contractGitHub   = "arn:aws:iam::" + accountA + ":oidc-provider/token.actions.githubusercontent.com"
	contractSub      = "repo:acme/app:ref:refs/heads/main"
	contractTickets  = "arn:aws:s3:::support-tickets/*"
	contractBucket   = "arn:aws:s3:::support-tickets"
	contractKeyC     = "arn:aws:kms:us-east-1:" + contractAccountC + ":key/partner-key"
	contractKeyB     = "arn:aws:kms:us-east-1:" + accountB + ":key/sandbox-key"
	contractFinance  = "arn:aws:s3:::finance/*"
	contractAuditARN = "arn:aws:iam::aws:policy/AuditRead"
	contractTaskDef  = "arn:aws:ecs:us-east-1:" + accountA + ":task-definition/ticket-worker:1"
	contractAgentARN = "arn:aws:bedrock:us-east-1:" + accountA + ":agent/AGENTCONTRACT1"
)

// contractFixture is the estate plus the refs the contract tests address.
type contractFixture struct {
	l    *p2Lab
	a, b *p2Account
	api  *readAPI
	// runs, in publication order: A's first scan, B's, A's second, B's second.
	runA1, runB, runA2, runB2 models.CloudScanRun
	fakesA                    *s3bFakes

	// Typed refs, "<type>:<uuid>".
	lambda, ecs, agent, orphan              string
	shared, pull, agentRole, cross, loop    string
	priya, ops, temp, github, partner       string
	oidc, rootC                             string
	tickets, bucket, keyC, keyB, finance    string
	ticketRead, toolbox, financeAll, guards string
	readTickets, toolboxStmt, allButFinance string
	grantReadTickets, grantToolbox          string
	executesLambda, crossEdge               string

	// The classification decision's actor (a verified human).
	user, member uuid.UUID
}

// contractSeq keeps owner names unique across this file's scans.
var contractSeq int

// contractCycle scans an account through the REAL worker with the given fakes
// and projects it, requiring the projection to complete.
func contractCycle(l *p2Lab, a *p2Account, f *s3bFakes) models.CloudScanRun {
	l.t.Helper()
	contractSeq++
	run := s3bScan(l, a, f, "contract-scan-"+itoaContract(contractSeq))
	l.project("contract-projector-" + itoaContract(contractSeq))
	return run
}

func itoaContract(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%10]}, b...)
		n /= 10
	}
	return string(b)
}

// contractManaged defines a customer-managed policy with its OWN PolicyId.
// The fake IAM derives an unset PolicyId from the ARN's length and last
// character, so TicketRead and LegacyRead (or ToolboxRead in A and
// SandboxRead in B) would share one -- two policies AWS would never confuse,
// projected as one incarnation.
func contractManaged(a *p2Account, name, doc string) string {
	arn := a.managed(name, doc)
	a.iam.policyIDs[arn] = "ANPACONTRACT" + strings.ToUpper(a.id+name)
	return arn
}

// contractAWSManaged is s3aAWSManaged with its own PolicyId (contractManaged).
func contractAWSManaged(a *p2Account, name, doc string) string {
	arn := s3aAWSManaged(a, name, doc)
	a.iam.policyIDs[arn] = "ANPACONTRACTAWS" + strings.ToUpper(name)
	return arn
}

// contractDoc wraps statements in a policy document.
func contractDoc(statements ...string) string { return evidenceDoc(statements...) }

// contractLab builds the estate. It takes about as long as three lab cycles.
func contractLab(t *testing.T) *contractFixture {
	t.Helper()
	l := newP2Lab(t, "p2-contract", true)
	// Both accounts are onboarded before anything is projected, so B counts as
	// connected when A's policies name B's key (D-3, D-61).
	a := l.account(accountA)
	b := l.account(accountB)
	f := &contractFixture{l: l, a: a, b: b}

	/* ------------------------------ account A ------------------------------ */

	// SharedToolRole: the Lambda's and the ECS task's role. Its trust also
	// admits the ECS tasks service.
	shared := trustRole(a, "SharedToolRole", "AROASHAREDTOOLROLE01", trustDoc(
		trustAllow(`{"Service":"lambda.amazonaws.com"}`, "sts:AssumeRole"),
		trustAllow(`{"Service":"ecs-tasks.amazonaws.com"}`, "sts:AssumeRole")))
	s3aEditRole(t, a, "SharedToolRole", func(r *iamtypes.Role) {
		r.Tags = []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String("support")}}
	})
	pull := trustRole(a, "ImagePullRole", "AROAIMAGEPULLROLEIMG", trustDoc(
		trustAllow(`{"Service":"ecs-tasks.amazonaws.com"}`, "sts:AssumeRole")))
	agentRole := trustRole(a, "SupportAgentRole", "AROASUPPORTAGENTROLE", trustDoc(
		trustAllow(`{"Service":"bedrock.amazonaws.com"}`, "sts:AssumeRole")))
	// orphan-fn runs as a role no scan lists: execution_role not_in_inventory,
	// with the ARN it names.
	listsFunctions(a, "us-east-1", "ticket-tools", shared, "orphan-fn", a.roleARN("MissingRole"))

	a.attach("SharedToolRole", contractManaged(a, "TicketRead", contractDoc(
		`{"Sid":"ReadTickets","Effect":"Allow","Action":"s3:GetObject","Resource":"`+contractTickets+`"}`,
		`{"Sid":"ListTickets","Effect":"Allow","Action":"s3:ListBucket","Resource":"`+contractBucket+`",`+
			`"Condition":{"StringLike":{"s3:prefix":["tickets/*"]}}}`)))
	a.attach("SharedToolRole", contractManaged(a, "ToolboxRead", contractDoc(
		`{"Effect":"Allow","Action":"s3:GetObject","Resource":"`+contractTickets+`"}`)))
	a.attach("SharedToolRole", contractManaged(a, "FinanceAll", contractDoc(
		`{"Sid":"AllButFinance","Effect":"Allow","Action":"s3:*","NotResource":"`+contractFinance+`"}`)))
	a.attach("SharedToolRole", contractManaged(a, "GuardRails", contractDoc(
		`{"Sid":"NoDeletes","Effect":"Deny","Action":"s3:DeleteObject","Resource":"`+contractTickets+`"}`)))
	a.attach("SharedToolRole", contractManaged(a, "ExternalKey", contractDoc(
		`{"Sid":"Decrypt","Effect":"Allow","Action":"kms:Decrypt","Resource":"`+contractKeyC+`"}`)))
	a.attach("SharedToolRole", contractManaged(a, "CrossKey", contractDoc(
		`{"Sid":"DecryptB","Effect":"Allow","Action":"kms:Decrypt","Resource":"`+contractKeyB+`"}`)))
	a.attach("SharedToolRole", contractManaged(a, "LegacyRead", contractDoc(
		`{"Sid":"LegacyGet","Effect":"Allow","Action":"s3:GetObject","Resource":"`+contractTickets+`"}`)))
	// An AWS-managed policy whose document cannot be read (D-51): attached,
	// but no statement of it is known.
	contractAWSManaged(a, "AuditRead", contractDoc(
		`{"Sid":"Audit","Effect":"Allow","Action":"cloudtrail:LookupEvents","Resource":"*"}`))
	a.attach("SharedToolRole", contractAuditARN)
	a.iam.failPolicyVersion[contractAuditARN] = denied("iam:GetPolicyVersion")

	// priya: a user with a boundary, in a group, with keys.
	boundary := contractAWSManaged(a, "PowerUserAccess", contractDoc(
		`{"Effect":"Allow","NotAction":["iam:*","organizations:*"],"Resource":"*"}`))
	s3aGroup(a, "ops", "AGPAOPSOPSOPSOPSOPS1")
	s3aGroupAttach(t, a, "ops", contractManaged(a, "OpsRead", contractDoc(
		`{"Sid":"ReadOps","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::ops-bucket/*"}`)))
	s3aUser(a, "priya", "AIDAPRIYAPRIYAPRIYA1")
	s3aEditUser(t, a, "priya", func(u *iamtypes.User) { u.PermissionsBoundary = s3aBoundary(boundary) })
	s3aJoin(a, "priya", "ops")
	a.iam.inlineUserPolicies["priya"] = map[string]string{
		"PriyaOwn": contractDoc(`{"Sid":"OwnRead","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::priya-scratch/*"}`),
	}
	a.iam.keys["priya"] = []iamtypes.AccessKeyMetadata{
		{AccessKeyId: aws.String("AKIACONTRACTACTIVE01"), UserName: aws.String("priya"),
			Status: iamtypes.StatusTypeActive, CreateDate: ago(400 * 24 * time.Hour)},
		{AccessKeyId: aws.String("AKIACONTRACTINACTIV1"), UserName: aws.String("priya"),
			Status: iamtypes.StatusTypeInactive, CreateDate: ago(30 * 24 * time.Hour)},
	}
	a.iam.keyLastUse["AKIACONTRACTACTIVE01"] = ago(3 * 24 * time.Hour)

	// Trust: OIDC federation, an unconnected account's root, a role to retire.
	trustRole(a, "GithubDeployRole", "AROAGITHUBDEPLOYROL1", trustDoc(
		`{"Sid":"FromMain","Effect":"Allow","Principal":{"Federated":"`+contractGitHub+`"},`+
			`"Action":"sts:AssumeRoleWithWebIdentity",`+
			`"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"`+contractSub+`"}}}`))
	trustRole(a, "PartnerRole", "AROAPARTNERROLEPART1", trustDoc(
		trustAllow(`{"AWS":"arn:aws:iam::`+contractAccountC+`:root"}`, "sts:AssumeRole")))
	a.role("TempRole", "AROATEMPROLETEMPROL1")

	f.fakesA = &s3bFakes{
		ecs: &fakeECS{defs: map[string]ecstypes.TaskDefinition{contractTaskDef: {
			TaskDefinitionArn: aws.String(contractTaskDef), Family: aws.String("ticket-worker"),
			TaskRoleArn: aws.String(shared), ExecutionRoleArn: aws.String(pull),
			Status: ecstypes.TaskDefinitionStatusActive,
		}}},
		bedrock: &fakeBedrock{agents: map[string]bedrockagenttypes.Agent{"AGENTCONTRACT1": {
			AgentId: aws.String("AGENTCONTRACT1"), AgentArn: aws.String(contractAgentARN),
			AgentName: aws.String("support-bot"), AgentResourceRoleArn: aws.String(agentRole),
			FoundationModel: aws.String("amazon.titan-text-express-v1"),
			AgentStatus:     bedrockagenttypes.AgentStatusPrepared,
		}}},
		s3: &fakeS3Policy{policyByBucket: map[string]string{"support-tickets": contractDoc(
			`{"Effect":"Deny","Principal":"*","Action":"s3:DeleteBucket","Resource":"` + contractBucket + `"}`)}},
		kms: &fakeKMSPolicy{},
		activity: &fakeActivity{services: []iamtypes.ServiceLastAccessed{
			{ServiceName: aws.String("Amazon S3"), ServiceNamespace: aws.String("s3"), LastAuthenticated: ago(4 * 24 * time.Hour)},
		}},
	}
	f.runA1 = contractCycle(l, a, f.fakesA)

	/* ------------------------------ account B ------------------------------ */

	// CrossRole trusts A's SharedToolRole (live in a connected account when B
	// is projected, so the source is that identity: D-41) by a Sid-keyed
	// statement, and B's LoopRole by a Sid-less one; LoopRole trusts CrossRole
	// -- a cycle.
	crossARN := "arn:aws:iam::" + accountB + ":role/CrossRole"
	loopARN := "arn:aws:iam::" + accountB + ":role/LoopRole"
	trustRole(b, "CrossRole", "AROACROSSROLECROSSR1", trustDoc(
		`{"Sid":"FromTools","Effect":"Allow","Principal":{"AWS":"`+shared+`"},"Action":"sts:AssumeRole"}`,
		trustAllow(`{"AWS":"`+loopARN+`"}`, "sts:AssumeRole")))
	trustRole(b, "LoopRole", "AROALOOPROLELOOPROL1", trustDoc(
		trustAllow(`{"AWS":"`+crossARN+`"}`, "sts:AssumeRole")))
	b.attach("CrossRole", contractManaged(b, "SandboxRead", contractDoc(
		`{"Sid":"ReadSandbox","Effect":"Allow","Action":"s3:GetObject","Resource":"`+contractTickets+`"}`)))
	// The denied surface: B's Group listing.
	b.iam.fail["GetAccountAuthorizationDetails:Group"] = denied("iam:GetAccountAuthorizationDetails")
	f.runB = contractCycle(l, b, &s3bFakes{})

	/* ------------------------- account A, second scan ------------------------ */

	// LegacyRead is detached (its grant ends; the path remains), TempRole is
	// deleted (retired), ListTickets' Condition is edited (a revision).
	a.detach("SharedToolRole", a.policyARN("LegacyRead"))
	trustRemoveRole(a, "TempRole")
	contractManaged(a, "TicketRead", contractDoc(
		`{"Sid":"ReadTickets","Effect":"Allow","Action":"s3:GetObject","Resource":"`+contractTickets+`"}`,
		`{"Sid":"ListTickets","Effect":"Allow","Action":"s3:ListBucket","Resource":"`+contractBucket+`",`+
			`"Condition":{"StringLike":{"s3:prefix":["tickets/*","archive/*"]}}}`))
	f.fakesA.activity = &fakeActivity{services: f.fakesA.activity.(*fakeActivity).services}
	f.runA2 = contractCycle(l, a, f.fakesA)

	/* ------------------------- account B, second scan ------------------------ */

	// The Role listing is refused too: nothing may END on a read that did not
	// happen (§4.10 canEnd), so B's roles, their trust edges and their grants
	// stay, STALE, each with the surface that explains it (D-74).
	b.iam.fail["GetAccountAuthorizationDetails:Role"] = denied("iam:GetAccountAuthorizationDetails")
	f.runB2 = contractCycle(l, b, &s3bFakes{})

	f.api = l.api()
	f.resolve(t)

	// A classification decision, through the real POST, by a verified human.
	name := "Priya Shah"
	f.user, f.member = classMember(t, l.db, l.ws, &name, "priya@contract.test", "active")
	f.api.withClaims(classClaims(f.user, f.member))
	code, body := f.api.do(http.MethodPost, "/workloads/"+refUUID(t, f.lambda).String()+"/classification", map[string]any{
		"operation_id": uuid.NewString(), "decision": "classified_agent",
		"purpose": "Customer support triage", "reason": "Owns tier-1 ticket routing", "expected_version": 0,
	})
	mustStatus(t, "fixture: classify ticket-tools", code, body, http.StatusOK)
	f.api.withClaims(map[string]string{})
	return f
}

// resolve looks up every ref the tests address, failing on a fixture that did
// not produce it.
func (f *contractFixture) resolve(t *testing.T) {
	t.Helper()
	l := f.l
	wl := func(name string) string { return evidenceNode(t, l, "workload", "iga_workload", name) }
	id := func(name string) string { return evidenceNode(t, l, "identity", "iga_identity_accounts", name) }
	res := func(text string) string { return evidenceNode(t, l, "resource", "iga_resources", text) }
	pol := func(name string) string { return evidenceNode(t, l, "policy", "iga_policy", name) }

	f.lambda, f.agent, f.orphan = wl("ticket-tools"), wl("support-bot"), wl("orphan-fn")
	var ecsIDs []uuid.UUID
	l.db.Raw(`SELECT id FROM iga_workload WHERE workspace_id = ? AND runtime_kind = 'ecs_task_definition'`, l.ws).Scan(&ecsIDs)
	if len(ecsIDs) != 1 {
		t.Fatalf("fixture: %d ECS task definitions projected, want 1", len(ecsIDs))
	}
	f.ecs = refOf("workload", ecsIDs[0])
	f.shared, f.pull, f.agentRole = id("SharedToolRole"), id("ImagePullRole"), id("SupportAgentRole")
	f.cross, f.loop = id("CrossRole"), id("LoopRole")
	f.priya, f.ops, f.temp = id("priya"), id("ops"), id("TempRole")
	f.github, f.partner = id("GithubDeployRole"), id("PartnerRole")
	f.oidc, f.rootC = evidenceExternal(t, l, contractSub), evidenceExternal(t, l, contractAccountC)
	f.tickets, f.bucket, f.keyC, f.keyB, f.finance = res(contractTickets), res(contractBucket), res(contractKeyC), res(contractKeyB), res(contractFinance)
	f.ticketRead, f.toolbox, f.financeAll, f.guards = pol("TicketRead"), pol("ToolboxRead"), pol("FinanceAll"), pol("GuardRails")

	stmt := func(policy, sid string) string {
		var ids []uuid.UUID
		l.db.Raw(`SELECT e.id FROM iga_entitlements e JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
		           WHERE e.workspace_id = ? AND e.provider = 'aws' AND p.display_name = ? AND e.sid = ? AND e.lifecycle = 'active'`,
			l.ws, policy, sid).Scan(&ids)
		if len(ids) != 1 {
			t.Fatalf("fixture: %d active statements %s/%q, want 1", len(ids), policy, sid)
		}
		return refOf("statement", ids[0])
	}
	f.readTickets, f.toolboxStmt, f.allButFinance = stmt("TicketRead", "ReadTickets"), stmt("ToolboxRead", ""), stmt("FinanceAll", "AllButFinance")
	f.grantReadTickets = evidenceGrant(t, l, "SharedToolRole", "TicketRead", "ReadTickets")
	f.grantToolbox = evidenceGrant(t, l, "SharedToolRole", "ToolboxRead", "")
	f.executesLambda = evidenceRelationship(t, l, "executes_as", "ticket-tools", "SharedToolRole")
	f.crossEdge = evidenceRelationship(t, l, "can_assume", "SharedToolRole", "CrossRole")
}
