package integration

// T3.5 (SPEC-iga-phase2-graph.md §1.4 "observation added", §4.8): evidence for
// access keys and EKS Pod Identity associations, keyed so that neither becomes
// "supporting evidence" for every edge of the identity it is filed under.
// Through the REAL scan worker and projector.

import (
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	agentcoretypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"
)

// s3bUserWithKey adds an IAM user holding TicketRead directly and one active
// access key, so the user has a grant AND a credential.
func s3bUserWithKey(a *p2Account, userName, userID, keyID string) (userARN string) {
	userARN = "arn:aws:iam::" + a.id + ":user/" + userName
	a.iam.users = append(a.iam.users, iamtypes.User{
		Arn: aws.String(userARN), UserName: aws.String(userName), UserId: aws.String(userID),
		Path: aws.String("/"), CreateDate: ago(200 * 24 * time.Hour),
	})
	policy := a.managed("TicketRead", docTicketRead)
	a.iam.attachedUserPolicies[userName] = []iamtypes.AttachedPolicy{{
		PolicyArn: aws.String(policy), PolicyName: aws.String("TicketRead"),
	}}
	a.iam.keys[userName] = []iamtypes.AccessKeyMetadata{{
		AccessKeyId: aws.String(keyID), UserName: aws.String(userName),
		Status: iamtypes.StatusTypeActive, CreateDate: ago(90 * 24 * time.Hour),
	}}
	a.iam.keyLastUse[keyID] = ago(3 * time.Hour)
	return userARN
}

// T3.5: the access key's observation is the CREDENTIAL's evidence -- keyed by
// the key id, which iga_credentials.key_identifier also holds -- and is linked
// to none of the user's grants, assignments or relationships. And an
// unchanged, ACTIVE key (whose last-used date moves between scans) confirms
// its one observation instead of writing a new row every scan.
//
// Safeguards (mutation-checked, see the report):
//   - AccessKeyEvidenceKey = the key id: keyed by the user ARN instead, the key
//     observation becomes supporting evidence on the user's grant;
//   - last_used_at kept out of the hashed facts: hashed, the second scan of
//     the same key writes a second row.
func TestP2S3bAccessKeyEvidenceAttachesToTheCredentialAndDedupes(t *testing.T) {
	l := newP2Lab(t, "p2-s3b-accesskey", true)
	a := l.account(accountA)
	const keyID = "AKIAS3BEXAMPLEKEY01"
	userARN := s3bUserWithKey(a, "ci-bot", "AIDAS3BCIBOT000001", keyID)

	run1 := l.scanAndProject(a)

	obs := s3bObservations(t, l, "iam:ListAccessKeys")
	if len(obs) != 1 {
		t.Fatalf("access key observations = %d, want 1 (iam_access_keys: observation added)", len(obs))
	}
	o := obs[0]
	userID := s3bCloudIdentityID(t, l, userARN)
	if o.IdentityID == nil || *o.IdentityID != userID || o.Surface != models.SurfaceIAMAccessKeys ||
		o.SubjectNativeID != igagraph.AccessKeyEvidenceKey(keyID) || o.SubjectNativeID != keyID {
		t.Fatalf("access key observation = %+v, want subject the user, surface iam_access_keys, keyed by the key id", o)
	}
	facts := o.facts(t)
	if facts["key_id"] != keyID || facts["status"] != "Active" || facts["created_at"] == nil {
		t.Errorf("access key facts = %v, want key id, status and creation time", facts)
	}
	if _, hashed := facts["last_used_at"]; hashed {
		t.Errorf("last_used_at is in the hashed facts (%v): an active key would write a new observation every scan", facts)
	}

	// Attaches to the credential: the projected credential carries the same key.
	var credentials int64
	l.db.Raw(`SELECT count(*) FROM iga_credentials WHERE workspace_id = ? AND provider = 'aws'
	          AND key_identifier = ?`, l.ws, o.SubjectNativeID).Scan(&credentials)
	if credentials != 1 {
		t.Fatalf("iga_credentials with key_identifier = the observation's key: %d, want 1", credentials)
	}

	// ... and to NO edge of the user. The user's grant exists and IS evidenced
	// (by the user's own observation and the policy version's), just not by
	// its key.
	var userGrants int64
	l.db.Raw(`SELECT count(*) FROM iga_access_edges g JOIN iga_identity_accounts i
	            ON i.workspace_id = g.workspace_id AND i.id = g.subject_identity_account_id
	          WHERE g.workspace_id = ? AND i.source_key = ?`, l.ws, igagraph.Key("aws", userARN)).Scan(&userGrants)
	if userGrants == 0 {
		t.Fatal("setup: the user's TicketRead grant was not projected")
	}
	linked := s3bEdgeEvidence(t, l)
	if len(linked) == 0 {
		t.Fatal("setup: no edge evidence at all")
	}
	if edge, ok := linked[o.ID]; ok {
		t.Fatalf("the access key observation is linked as evidence on a %s edge: a key's observation "+
			"must attach to the credential, never to every edge of the user", edge)
	}

	// ---- rescan: same key, still active, used again since ---------------------
	a.iam.keyLastUse[keyID] = ago(time.Minute)
	run2 := l.scanAndProject(a)

	obs = s3bObservations(t, l, "iam:ListAccessKeys")
	if len(obs) != 1 {
		t.Fatalf("access key observations after an unchanged rescan = %d, want 1: "+
			"a moving last-used date must not write a row per scan", len(obs))
	}
	if obs[0].ID != o.ID || obs[0].ConfirmationCount != 2 || obs[0].LastConfirmedRunID == nil ||
		*obs[0].LastConfirmedRunID != run2.ID {
		t.Fatalf("after rescan: %+v, want the same row confirmed by run %s (count 2)", obs[0], run2.ID)
	}
	// The date itself lives on the credential row, refreshed in place.
	var lastUsed time.Time
	if err := l.db.Raw(`SELECT last_used_at FROM cloud_secret WHERE workspace_id = ? AND native_id = ?`,
		l.ws, keyID).Row().Scan(&lastUsed); err != nil {
		t.Fatalf("read cloud_secret: %v", err)
	}
	if time.Since(lastUsed) > time.Hour {
		t.Errorf("cloud_secret.last_used_at = %s, want the rescan's newer date", lastUsed)
	}
	_ = run1

	// A status change IS a new fact.
	a.iam.keys["ci-bot"][0].Status = iamtypes.StatusTypeInactive
	l.scanAndProject(a)
	if n := len(s3bObservations(t, l, "iam:ListAccessKeys")); n != 2 {
		t.Errorf("access key observations after Active -> Inactive = %d, want 2 (a new fact is a new row)", n)
	}
}

// T3.5: one observation per Pod Identity association, subject the ROLE, keyed
// by igagraph.PodIdentityEvidenceKey(role ARN, issuer, k8s subject) -- values
// the collected cloud_assume_edge row holds, so the pod-identity can_assume
// projection can rebuild the key -- and linked to none of the role's other
// edges (its grants, its executes_as).
//
// Safeguard (mutation-checked): the key. Filed under the role's ARN, the
// association would become evidence on the role's grant and executes_as.
func TestP2S3bPodIdentityEvidenceIsTheAssociations(t *testing.T) {
	l := newP2Lab(t, "p2-s3b-podidentity", true)
	a := l.account(accountA)
	role := a.role("ledger-pod-role", "AROAS3BLEDGERPOD01")
	a.attach("ledger-pod-role", a.managed("TicketRead", docTicketRead))
	a.lambda("us-east-1", "ledger-fn", role) // an executes_as edge on the same role

	eks := podIdentityEKS(role)
	s3bScanAndProject(l, a, &s3bFakes{eks: eks})

	obs := s3bObservations(t, l, "eks:DescribePodIdentityAssociation")
	if len(obs) != 1 {
		t.Fatalf("pod identity observations = %d, want 1 (eks_pod_identity: observation added)", len(obs))
	}
	o := obs[0]
	roleID := s3bCloudIdentityID(t, l, role)

	var edge struct {
		Subject string
		Issuer  *string
	}
	if err := l.db.Raw(`SELECT subject, issuer FROM cloud_assume_edge WHERE workspace_id = ? AND identity_id = ?
	                     AND mechanism = ?`, l.ws, roleID, models.AssumeMechanismEKSPodIdentity).
		Row().Scan(&edge.Subject, &edge.Issuer); err != nil {
		t.Fatalf("read the pod identity edge: %v", err)
	}
	issuer := ""
	if edge.Issuer != nil {
		issuer = *edge.Issuer
	}
	wantKey := igagraph.PodIdentityEvidenceKey(role, issuer, edge.Subject)
	if o.IdentityID == nil || *o.IdentityID != roleID || o.Surface != models.SurfaceEKSPodIdentity ||
		o.SubjectNativeID != wantKey || !strings.Contains(o.SubjectNativeID, igagraph.Sep) {
		t.Fatalf("pod identity observation = %+v, want subject the role, keyed %q (rebuildable from the edge row)", o, wantKey)
	}
	facts := o.facts(t)
	for k, want := range map[string]any{
		"namespace": "payments", "service_account": "ledger-agent", "role_arn": role,
		"cluster_name": "prod-cluster", "association_id": "a-1111111111", "region": "us-east-1",
		"oidc_issuer": eksIssuerNoSch, "k8s_subject": awsdiscovery.K8sSubject("payments", "ledger-agent"),
	} {
		if facts[k] != want {
			t.Errorf("pod identity fact %s = %v, want %v", k, facts[k], want)
		}
	}

	linked := s3bEdgeEvidence(t, l)
	if len(linked) == 0 {
		t.Fatal("setup: no edge evidence at all")
	}
	if edge, ok := linked[o.ID]; ok {
		t.Fatalf("the pod identity observation is linked as evidence on a %s edge of the role", edge)
	}
	_ = uuid.Nil
}

// The T3.5 gate (E4): "Every surface in §1.4 writes evidence." One full scan
// through the real worker with every surface populated, then at least one
// observation filed under each surface -- and the gateway's never labelled
// aws:unknown. Exempt, per §1.4: policy_documents (no rows of its own),
// oidc_providers ("gate only"), organizations (unsupported), activity
// (persisted as cloud_usage, not an observation).
//
// The same run checks the T3.8 vocabulary from the writer's side: every
// coverage key it emitted is a models.Surface* constant or a regional key
// built from a models.Surface*Prefix -- never an invented string.
func TestP2S3bEverySurfaceWritesEvidence(t *testing.T) {
	l := newP2Lab(t, "p2-s3b-every-surface", true)
	a := l.account(accountA)
	role := a.role("everything-role", "AROAS3BEVERYTHING1")
	a.attach("everything-role", a.managed("TicketRead", docTicketRead))
	a.iam.inlineRolePolicies["everything-role"] = map[string]string{"bucket": `{"Version":"2012-10-17",` +
		`"Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::s3b-evidence-bucket"}]}`}
	a.lambda("us-east-1", "everything-fn", role)
	userARN := s3bUserWithKey(a, "ci-bot", "AIDAS3BCIBOT000002", "AKIAS3BEXAMPLEKEY02")
	a.iam.groups = []iamtypes.GroupDetail{{
		Arn: aws.String("arn:aws:iam::" + a.id + ":group/s3b-ops"), GroupName: aws.String("s3b-ops"),
		GroupId: aws.String("AGPAS3BOPS00000001"), Path: aws.String("/"),
	}}
	a.iam.userGroups["ci-bot"] = []string{"s3b-ops"}

	tdARN := "arn:aws:ecs:us-east-1:" + a.id + ":task-definition/everything:1"
	agentARN := "arn:aws:bedrock:us-east-1:" + a.id + ":agent/AGENTEVERY"
	f := &s3bFakes{
		ecs: &fakeECS{defs: map[string]ecstypes.TaskDefinition{tdARN: {
			TaskDefinitionArn: aws.String(tdARN), Family: aws.String("everything"), TaskRoleArn: aws.String(role),
		}}},
		ec2: &fakeEC2{instances: []ec2types.Instance{{InstanceId: aws.String("i-0s3beverything01"),
			State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}}}},
		bedrock: &fakeBedrock{agents: map[string]bedrockagenttypes.Agent{"AGENTEVERY": {
			AgentId: aws.String("AGENTEVERY"), AgentArn: aws.String(agentARN), AgentName: aws.String("every-bot"),
			AgentResourceRoleArn: aws.String(role),
		}}},
		agentCore: &fakeAgentCore{
			runtimes: []agentcoretypes.AgentRuntime{{AgentRuntimeId: aws.String("rt-every"),
				AgentRuntimeArn:  aws.String("arn:aws:bedrock-agentcore:us-east-1:" + a.id + ":runtime/rt-every"),
				AgentRuntimeName: aws.String("every-runtime")}},
			roleByID:        map[string]string{"rt-every": role},
			gateways:        []agentcoretypes.GatewaySummary{{GatewayId: aws.String("gw-every"), Name: aws.String("every-gw")}},
			gatewayRoleByID: map[string]string{"gw-every": role},
		},
		eks: podIdentityEKS(role),
		s3: &s3bS3Policy{docs: map[string]string{"s3b-evidence-bucket": `{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::s3b-evidence-bucket"}]}`}},
		kms: &fakeKMSPolicy{},
		credentialCSV: "user,arn,password_enabled,password_last_used,mfa_active," +
			"access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date," +
			"access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\n" +
			"ci-bot," + userARN + ",false,N/A,true,true,2026-01-01T00:00:00Z,N/A,false,N/A,N/A\n",
	}
	run := s3bScanAndProject(l, a, f)

	var rows []struct {
		Surface string
		N       int64
	}
	l.db.Raw(`SELECT surface, count(*) AS n FROM cloud_observation WHERE workspace_id = ? GROUP BY surface`, l.ws).Scan(&rows)
	bySurface := map[string]int64{}
	for _, r := range rows {
		bySurface[r.Surface] = r.N
	}
	for _, surface := range []string{
		models.SurfaceIAMRoles, models.SurfaceIAMUsers, models.SurfaceIAMGroups, models.SurfaceIAMPolicies,
		models.SurfaceIAMAccessKeys, models.SurfaceIAMCredentialReport, models.SurfaceEKSPodIdentity,
		models.SurfaceResourcePolicies,
		models.SurfaceRegional(models.SurfaceLambdaPrefix, "us-east-1"),
		models.SurfaceRegional(models.SurfaceECSPrefix, "us-east-1"),
		models.SurfaceRegional(models.SurfaceEC2Prefix, "us-east-1"),
		models.SurfaceRegional(models.SurfaceBedrockAgentsPrefix, "us-east-1"),
		models.SurfaceRegional(models.SurfaceBedrockAgentCorePrefix, "us-east-1"),
		models.SurfaceRegional(models.SurfaceAgentCoreGatewaysPrefix, "us-east-1"),
	} {
		if bySurface[surface] == 0 {
			t.Errorf("surface %s wrote no evidence (T3.5: every surface in §1.4 writes evidence); by surface: %v",
				surface, bySurface)
		}
	}
	if obs := s3bObservations(t, l, "aws:unknown"); len(obs) != 0 {
		t.Errorf("%d observations labelled aws:unknown", len(obs))
	}

	// The vocabulary, from the writer's side.
	global := map[string]bool{}
	for _, s := range []string{models.SurfaceIAMRoles, models.SurfaceIAMUsers, models.SurfaceIAMGroups,
		models.SurfaceIAMAccessKeys, models.SurfaceIAMPolicies, models.SurfacePolicyDocuments,
		models.SurfaceOIDCProviders, models.SurfaceEKSPodIdentity, models.SurfacePermissionScan,
		models.SurfaceWorkloadScan, models.SurfaceActivity, models.SurfaceIAMCredentialReport,
		models.SurfaceResourcePolicies, models.SurfaceOrganizations} {
		global[s] = true
	}
	regional := map[string]bool{"compute": true}
	for _, p := range []string{models.SurfaceLambdaPrefix, models.SurfaceECSPrefix, models.SurfaceEC2Prefix,
		models.SurfaceBedrockAgentsPrefix, models.SurfaceBedrockAgentCorePrefix, models.SurfaceAgentCoreGatewaysPrefix,
		models.SurfaceAgentCoreIdentitiesPrefix, models.SurfaceAgentCoreCredProviderPrefix,
		models.SurfaceCloudTrailEventsPrefix, models.SurfaceCloudTrailStatusPrefix} {
		regional[p] = true
	}
	for key := range s3bRunCoverage(t, l, run.ID).Surfaces {
		prefix, region, isRegional := strings.Cut(key, ":")
		if (isRegional && (!regional[prefix] || region == "")) || (!isRegional && !global[key]) {
			t.Errorf("coverage key %q is not in the models.Surface* vocabulary", key)
		}
	}
}

// T3.5's dedupe half, through the real writer and conflict targets (022, 025,
// 035): an unchanged policy version rescanned writes no second observation --
// its one row is CONFIRMED by the second run (count 2, last_confirmed_run_id =
// run 2) -- and a subject-less observation (an AgentCore workload identity,
// which has no cloud_* row) dedupes the same way under the partial index.
// Nothing exercised the policy_id branch of the five-column COALESCE before.
//
// Safeguard (mutation-checked): the policy_id term of the writer's conflict
// target (cloud_observation_writer.go) -- without it the upsert names no
// index and every write fails.
func TestP2S3bPolicyAndSubjectlessObservationsDedupe(t *testing.T) {
	l := newP2Lab(t, "p2-s3b-dedupe", true)
	a := l.account(accountA)
	a.role("dedupe-role", "AROAS3BDEDUPEROLE1")
	a.attach("dedupe-role", a.managed("TicketRead", docTicketRead))
	f := &s3bFakes{agentCore: &fakeAgentCore{workloadIdentities: []agentcoretypes.WorkloadIdentityType{{
		Name:                aws.String("s3b-wid"),
		WorkloadIdentityArn: aws.String("arn:aws:bedrock-agentcore:us-east-1:" + a.id + ":workload-identity-directory/default/workload-identity/s3b-wid"),
	}}}}

	type row struct {
		PolicyID           *uuid.UUID
		SourceAPI          string
		ConfirmationCount  int
		LastConfirmedRunID *uuid.UUID
	}
	read := func() (policy, subjectless []row) {
		t.Helper()
		if err := l.db.Raw(`SELECT policy_id, source_api, confirmation_count, last_confirmed_run_id
		                      FROM cloud_observation WHERE workspace_id = ? AND policy_id IS NOT NULL
		                     ORDER BY policy_id, source_api`, l.ws).Scan(&policy).Error; err != nil {
			t.Fatalf("read policy observations: %v", err)
		}
		if err := l.db.Raw(`SELECT policy_id, source_api, confirmation_count, last_confirmed_run_id
		                      FROM cloud_observation WHERE workspace_id = ? AND identity_id IS NULL
		                       AND permission_id IS NULL AND resource_id IS NULL AND workload_id IS NULL
		                       AND policy_id IS NULL`, l.ws).Scan(&subjectless).Error; err != nil {
			t.Fatalf("read subject-less observations: %v", err)
		}
		return policy, subjectless
	}

	s3bScanAndProject(l, a, f)
	p1, n1 := read()
	if len(p1) == 0 || len(n1) == 0 {
		t.Fatalf("setup: %d policy-subject and %d subject-less observations, want both", len(p1), len(n1))
	}
	run2 := s3bScanAndProject(l, a, f)
	p2, n2 := read()
	if len(p2) != len(p1) || len(n2) != len(n1) {
		t.Fatalf("after an unchanged rescan: %d policy / %d subject-less rows, want %d / %d (no new rows)",
			len(p2), len(n2), len(p1), len(n1))
	}
	for _, r := range append(p2, n2...) {
		if r.ConfirmationCount != 2 || r.LastConfirmedRunID == nil || *r.LastConfirmedRunID != run2.ID {
			t.Errorf("%s observation (policy %v): count %d, confirmed by %v; want 2, run %s",
				r.SourceAPI, r.PolicyID, r.ConfirmationCount, r.LastConfirmedRunID, run2.ID)
		}
	}
}

// T3.8, the reader's side of the vocabulary: every regional surface a graph
// partition may require (igagraph.KnownSurfaces) is a models.Surface*Prefix
// key the workload scanner emits -- so the collector's constants and the
// projector's own list (snapshot.go, frozen by D-60) cannot drift apart
// without this failing. The global surfaces are checked the same way.
func TestP2S3bGraphSurfaceVocabularyIsTheModelsVocabulary(t *testing.T) {
	const region = "eu-west-1"
	emitted := map[string]bool{models.SurfaceCompute(region): true}
	for _, p := range []string{models.SurfaceLambdaPrefix, models.SurfaceECSPrefix, models.SurfaceEC2Prefix,
		models.SurfaceBedrockAgentsPrefix, models.SurfaceBedrockAgentCorePrefix, models.SurfaceAgentCoreGatewaysPrefix} {
		emitted[models.SurfaceRegional(p, region)] = true
	}
	for _, s := range []string{models.SurfaceIAMRoles, models.SurfaceIAMUsers, models.SurfaceIAMGroups,
		models.SurfaceIAMAccessKeys, models.SurfaceIAMPolicies, models.SurfacePolicyDocuments,
		models.SurfaceOIDCProviders, models.SurfaceEKSPodIdentity, models.SurfacePermissionScan,
		models.SurfaceWorkloadScan} {
		emitted[s] = true
	}
	known := igagraph.KnownSurfaces([]string{region})
	for s := range known {
		if !emitted[s] {
			t.Errorf("the graph may require %q, which no scanner emits under a models.Surface* name", s)
		}
	}
	for s := range emitted {
		if !known[s] {
			t.Errorf("%q is emitted but the graph's vocabulary does not know it", s)
		}
	}
	// organizations is reported, never required: no partition may wait on a
	// surface that is always unsupported.
	if known[models.SurfaceOrganizations] {
		t.Error("organizations must not be a surface any partition can require")
	}
}
