package igagraph

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// T4.2's gate: keys per §4.4, incl. statement keys -- Sid, hash, duplicates,
// reorder -- and the incarnation property B21 depends on.

func identity(t *testing.T, kind, arn, uniqueID string) models.CloudIdentity {
	t.Helper()
	ci := models.CloudIdentity{ID: uuid.New(), Kind: kind, NativeID: arn}
	if err := ci.SetAWSAttrs(models.AWSIdentityAttrs{UniqueID: uniqueID}); err != nil {
		t.Fatal(err)
	}
	return ci
}

func statements(t *testing.T, doc string) []awsdiscovery.PolicyStatement {
	t.Helper()
	st, _, err := awsdiscovery.ParsePolicyDocument(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return st
}

func keysOf(incarnation string, stmts []awsdiscovery.PolicyStatement) []string {
	sids, seen := CountSids(stmts), map[string]int{}
	out := make([]string, 0, len(stmts))
	for _, st := range stmts {
		k, _ := StatementKey(incarnation, st, sids, seen)
		out = append(out, k)
	}
	return out
}

func TestKeyIsNamespaced(t *testing.T) {
	k := IdentityKey(models.CloudIdentity{NativeID: "arn:aws:iam::1:role/x"})
	if !strings.HasPrefix(k, "aws"+Sep) {
		t.Fatalf("key %q is not namespaced by provider", k)
	}
}

// A Sid survives a reorder AND an edit: same key, the content hash moves.
func TestStatementKeySidSurvivesReorderAndEdit(t *testing.T) {
	a := statements(t, `{"Statement":[
	  {"Sid":"Read","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"},
	  {"Sid":"List","Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b"}]}`)
	b := statements(t, `{"Statement":[
	  {"Sid":"List","Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b"},
	  {"Sid":"Read","Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::b/*"}]}`)
	inc := Key("aws", "policy", "ANPA1")
	ka, kb := keysOf(inc, a), keysOf(inc, b)
	if ka[0] != kb[1] || ka[1] != kb[0] {
		t.Fatalf("Sid-keyed statements changed key on reorder/edit: %v vs %v", ka, kb)
	}
	if !SidKeyed(ka[0]) {
		t.Fatalf("%q is not recognised as Sid-keyed", ka[0])
	}
	if a[0].ContentHash() == b[1].ContentHash() {
		t.Fatal("an edit to a Sid statement did not change its content hash; no revision would be recorded")
	}
}

// Without a Sid, the key IS the content: a reorder keeps it, an edit replaces it.
func TestStatementKeyHashReorderKeepsEditReplaces(t *testing.T) {
	a := statements(t, `{"Statement":[
	  {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"},
	  {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b"}]}`)
	reordered := statements(t, `{"Statement":[
	  {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b"},
	  {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`)
	edited := statements(t, `{"Statement":[
	  {"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*"},
	  {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b"}]}`)
	inc := Key("aws", "policy", "ANPA1")
	ka, kr, ke := keysOf(inc, a), keysOf(inc, reordered), keysOf(inc, edited)
	if ka[0] != kr[1] || ka[1] != kr[0] {
		t.Fatalf("reorder changed a hash-keyed statement's key: %v vs %v", ka, kr)
	}
	if ke[0] == ka[0] {
		t.Fatal("an edit to a Sid-less statement kept its key; it must end and a new one begin")
	}
	if ke[1] != ka[1] {
		t.Fatal("editing one statement changed an untouched statement's key")
	}
	if SidKeyed(ka[0]) {
		t.Fatal("a Sid-less statement was treated as Sid-keyed")
	}
}

// Identical Sid-less statements are told apart by their order among equals,
// and a duplicated Sid falls back to the hash (a Sid is only identity when it
// is unique in the document).
func TestStatementKeyDuplicates(t *testing.T) {
	st := statements(t, `{"Statement":[
	  {"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},
	  {"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},
	  {"Sid":"Dup","Effect":"Allow","Action":"s3:ListBucket","Resource":"*"},
	  {"Sid":"Dup","Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`)
	k := keysOf(Key("aws", "policy", "ANPA1"), st)
	seen := map[string]bool{}
	for _, key := range k {
		if seen[key] {
			t.Fatalf("two statements share key %q: %v", key, k)
		}
		seen[key] = true
	}
	if !strings.HasSuffix(k[0], "#1") || !strings.HasSuffix(k[1], "#2") {
		t.Fatalf("identical statements not disambiguated by order: %v", k)
	}
	if SidKeyed(k[2]) || SidKeyed(k[3]) {
		t.Fatal("a Sid that is not unique in its document was used as identity")
	}
}

// Canonicalisation: formatting and the order of actions inside a statement are
// not edits.
func TestContentHashIsCanonical(t *testing.T) {
	a := statements(t, `{"Statement":{"Effect":"Allow","Action":["s3:B","s3:A"],"Resource":"*","Condition":{"StringEquals":{"k":"v","a":"b"}}}}`)
	b := statements(t, `{"Statement":[{ "Effect" : "allow", "Action":["s3:A","s3:B","s3:A"],"Resource":["*"],
	   "Condition":{"StringEquals":{"a":"b","k":"v"}}}]}`)
	if a[0].ContentHash() != b[0].ContentHash() {
		t.Fatal("equivalent statements hashed differently; every rescan would record a revision")
	}
}

// B21's property, at the key level: a customer-managed policy recreated under
// the same ARN (new PolicyId) shares NO statement, assignment or grant key with
// its predecessor.
func TestRecreatedPolicySharesNoKey(t *testing.T) {
	role := identity(t, models.CloudIdentityIAMRole, "arn:aws:iam::1:role/r", "AROA1")
	old := models.CloudPolicy{PolicyKind: models.CloudPolicyManaged, NativeID: "arn:aws:iam::1:policy/P", PolicyID: "ANPA-OLD"}
	neu := old
	neu.PolicyID = "ANPA-NEW"
	if PolicyKey(old, nil) != PolicyKey(neu, nil) {
		t.Fatal("recognition key must match across a recreation, or recreation is undetectable")
	}
	oi := PolicyIncarnationKey(old, nil, PolicyImmutableKey(old, nil))
	ni := PolicyIncarnationKey(neu, nil, PolicyImmutableKey(neu, nil))
	if oi == ni {
		t.Fatal("a recreated policy kept its incarnation key")
	}
	st := statements(t, `{"Statement":[{"Sid":"S","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	so, sn := keysOf(oi, st)[0], keysOf(ni, st)[0]
	if so == sn {
		t.Fatal("same Sid under a recreated policy reused the old statement key")
	}
	ao := AssignmentKey(oi, EndpointKey(role), models.CloudAttachmentAttached)
	an := AssignmentKey(ni, EndpointKey(role), models.CloudAttachmentAttached)
	if ao == an || GrantKey(ao, so) == GrantKey(an, sn) {
		t.Fatal("a recreated policy's assignment or grant reused a predecessor key")
	}
}

// An inline policy belongs to its holder: two roles each with an inline
// ReadData are two policies, and a RECREATED holder makes a new incarnation.
func TestInlinePolicyIsHolderScoped(t *testing.T) {
	a := identity(t, models.CloudIdentityIAMRole, "arn:aws:iam::1:role/a", "AROAA")
	b := identity(t, models.CloudIdentityIAMRole, "arn:aws:iam::1:role/b", "AROAB")
	p := models.CloudPolicy{PolicyKind: models.CloudPolicyInline, Name: "ReadData"}
	if PolicyKey(p, &a) == PolicyKey(p, &b) {
		t.Fatal("two holders' inline policies of one name collapsed into one")
	}
	recreated := identity(t, models.CloudIdentityIAMRole, "arn:aws:iam::1:role/a", "AROA-NEW")
	if PolicyKey(p, &a) != PolicyKey(p, &recreated) {
		t.Fatal("inline recognition key must survive the holder's recreation, so it is detected")
	}
	if PolicyIncarnationKey(p, &a, PolicyImmutableKey(p, &a)) ==
		PolicyIncarnationKey(p, &recreated, PolicyImmutableKey(p, &recreated)) {
		t.Fatal("an inline policy of a recreated holder kept the old incarnation")
	}
}

// Endpoint keys use the immutable key: a role recreated under the same ARN
// yields different edge keys.
func TestEndpointKeyUsesImmutableKey(t *testing.T) {
	a := identity(t, models.CloudIdentityIAMRole, "arn:aws:iam::1:role/r", "AROA1")
	b := identity(t, models.CloudIdentityIAMRole, "arn:aws:iam::1:role/r", "AROA2")
	if EndpointKey(a) == EndpointKey(b) {
		t.Fatal("a recreated role would inherit the old role's relationships")
	}
}

// Workload keys never change with a transient detail failure: a bare id gets
// the ARN the successful read would have returned.
func TestWorkloadKeyConstructsARN(t *testing.T) {
	ec2 := models.CloudWorkload{RuntimeKind: models.WorkloadEC2Instance, NativeID: "i-123", Region: "eu-central-1"}
	if got := WorkloadARN(ec2, "", "111122223333"); got != "arn:aws:ec2:eu-central-1:111122223333:instance/i-123" {
		t.Fatalf("EC2 ARN = %q (an empty partition is the commercial one)", got)
	}
	agentBare := models.CloudWorkload{RuntimeKind: models.WorkloadBedrockAgent, NativeID: "AGENT1", Region: "us-east-1"}
	agentARN := models.CloudWorkload{RuntimeKind: models.WorkloadBedrockAgent,
		NativeID: "arn:aws:bedrock:us-east-1:111122223333:agent/AGENT1", Region: "us-east-1"}
	if WorkloadKey(agentBare, "aws", "111122223333") != WorkloadKey(agentARN, "aws", "111122223333") {
		t.Fatal("a failed GetAgent changed the agent's key")
	}
}

// The partition is the connector's, never assumed: a GovCloud instance keyed
// arn:aws:... would disagree with every ARN AWS itself returns there.
func TestWorkloadKeyUsesTheConnectorPartition(t *testing.T) {
	ec2 := models.CloudWorkload{RuntimeKind: models.WorkloadEC2Instance, NativeID: "i-9", Region: "us-gov-west-1"}
	if got := WorkloadARN(ec2, "aws-us-gov", "111122223333"); got != "arn:aws-us-gov:ec2:us-gov-west-1:111122223333:instance/i-9" {
		t.Fatalf("GovCloud EC2 ARN = %q", got)
	}
	gw := models.CloudWorkload{RuntimeKind: models.WorkloadBedrockAgentCoreGW, NativeID: "gw-1", Region: "cn-north-1"}
	if got := WorkloadARN(gw, "aws-cn", "111122223333"); got != "arn:aws-cn:bedrock-agentcore:cn-north-1:111122223333:gateway/gw-1" {
		t.Fatalf("China gateway ARN = %q", got)
	}
	// ONE constructor: what the graph derives from a bare id is exactly what
	// the collector keys a detail-failed row by (awsdiscovery.WorkloadARN).
	for _, w := range []models.CloudWorkload{ec2, gw,
		{RuntimeKind: models.WorkloadBedrockAgent, NativeID: "A1", Region: "us-gov-east-1"},
		{RuntimeKind: models.WorkloadBedrockAgentCoreRT, NativeID: "R1", Region: "us-gov-east-1"}} {
		for _, part := range []string{"aws", "aws-us-gov", "aws-cn"} {
			if got, want := WorkloadARN(w, part, "111122223333"),
				awsdiscovery.WorkloadARN(part, w.RuntimeKind, w.Region, "111122223333", w.NativeID); got != want {
				t.Fatalf("%s in %s: graph %q, collector %q", w.RuntimeKind, part, got, want)
			}
		}
	}
	// Never an ARN on a guessed account.
	if got := WorkloadARN(ec2, "aws", ""); got != "i-9" {
		t.Fatalf("no account must leave the bare id, got %q", got)
	}
}

func TestContinuityTable(t *testing.T) {
	for kind, want := range map[string]string{
		models.CloudIdentityIAMRole:       ContinuityImmutable,
		models.CloudIdentityIAMUser:       ContinuityImmutable,
		models.CloudIdentityIAMGroup:      ContinuityImmutable,
		"managed_policy":                  ContinuityImmutable,
		"inline_policy":                   ContinuityImmutable,
		models.WorkloadLambdaFunction:     ContinuityRecognitionOnly,
		models.WorkloadEC2Instance:        ContinuityRecognitionOnly,
		models.WorkloadBedrockAgent:       ContinuityRecognitionOnly,
		models.WorkloadBedrockAgentCoreGW: ContinuityRecognitionOnly,
	} {
		if got := Continuity(kind); got != want {
			t.Errorf("Continuity(%s) = %s, want %s", kind, got, want)
		}
	}
}

func TestPolicyKindMapping(t *testing.T) {
	for _, tc := range []struct {
		p    models.CloudPolicy
		want string
	}{
		{models.CloudPolicy{PolicyKind: models.CloudPolicyManaged, AWSManaged: true}, models.PolicyKindAWSManaged},
		{models.CloudPolicy{PolicyKind: models.CloudPolicyManaged}, models.PolicyKindCustomerManaged},
		{models.CloudPolicy{PolicyKind: models.CloudPolicyInline}, models.PolicyKindInline},
	} {
		if got := PolicyKind(tc.p); got != tc.want {
			t.Errorf("PolicyKind = %s, want %s", got, tc.want)
		}
	}
}
