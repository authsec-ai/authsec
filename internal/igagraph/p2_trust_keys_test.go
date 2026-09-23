package igagraph

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// The awsdiscovery vocabularies are written through unchanged, and neither
// package can import the other's constants, so equality is asserted here.
func TestTrustVocabulariesAgree(t *testing.T) {
	for got, want := range map[string]string{
		awsdiscovery.ExternalAWSAccount:      models.ExternalPrincipalAWSAccount,
		awsdiscovery.ExternalAWSPrincipal:    models.ExternalPrincipalAWSPrincipal,
		awsdiscovery.ExternalAWSService:      models.ExternalPrincipalAWSService,
		awsdiscovery.ExternalOIDC:            models.ExternalPrincipalOIDC,
		awsdiscovery.ExternalSAML:            models.ExternalPrincipalSAML,
		awsdiscovery.ExternalK8sSA:           models.ExternalPrincipalK8sServiceAccount,
		awsdiscovery.MechanismSTSAssumeRole:  models.MechanismSTSAssumeRole,
		awsdiscovery.MechanismOIDCFederation: models.MechanismOIDCFederation,
		awsdiscovery.MechanismSAMLFederation: models.MechanismSAMLFederation,
		awsdiscovery.MechanismEKSPodIdentity: models.MechanismEKSPodIdentity,
	} {
		if got != want {
			t.Errorf("awsdiscovery %q != models %q", got, want)
		}
	}
}

func trustStatements(t *testing.T, doc string) []awsdiscovery.TrustStatement {
	t.Helper()
	d, err := awsdiscovery.ParseTrustDocument(json.RawMessage(doc))
	if err != nil || len(d.Skipped) > 0 {
		t.Fatalf("parse: %v %v", err, d)
	}
	return d.Statements
}

func trustKeys(roleEP string, stmts []awsdiscovery.TrustStatement) []string {
	sids, seen := CountTrustSids(stmts), map[string]int{}
	var out []string
	for _, st := range stmts {
		k, _ := TrustStatementKey(roleEP, st, sids, seen)
		out = append(out, k)
	}
	return out
}

// §2.6 applied to trust: a unique Sid keys the statement; a duplicate Sid or
// none falls back to the content hash, #n among equals; a reorder keeps every
// key; a Sid-less edit re-keys, a Sid-keyed one does not.
func TestTrustStatementKeys(t *testing.T) {
	ep := Key("aws", "uid", "AROAROLE")
	a := `{"Sid":"Partner","Effect":"Allow","Principal":{"AWS":"905418271234"},"Action":"sts:AssumeRole"}`
	b := `{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}`
	keys := trustKeys(ep, trustStatements(t, `{"Statement":[`+a+`,`+b+`,`+b+`]}`))
	if !strings.HasSuffix(keys[0], Sep+"trust"+Sep+"sid:Partner") || !strings.HasPrefix(keys[0], Key("aws", ep)) {
		t.Errorf("Sid key = %q", keys[0])
	}
	if !strings.HasSuffix(keys[1], "#1") || !strings.HasSuffix(keys[2], "#2") || keys[1][:len(keys[1])-2] != keys[2][:len(keys[2])-2] {
		t.Errorf("identical Sid-less statements = %q, %q; want h:<hash>#1 and #2", keys[1], keys[2])
	}
	reordered := trustKeys(ep, trustStatements(t, `{"Statement":[`+b+`,`+a+`,`+b+`]}`))
	if reordered[1] != keys[0] || reordered[0] != keys[1] || reordered[2] != keys[2] {
		t.Errorf("reorder changed keys: %v -> %v", keys, reordered)
	}
	edited := trustKeys(ep, trustStatements(t, `{"Statement":[`+
		`{"Sid":"Partner","Effect":"Allow","Principal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"},`+
		`{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}`))
	if edited[0] != keys[0] {
		t.Errorf("a Sid-keyed edit re-keyed the statement: %q -> %q", keys[0], edited[0])
	}
	if edited[1] == keys[1] {
		t.Error("a Sid-less edit kept its key; it must end and begin")
	}
	dup := trustKeys(ep, trustStatements(t, `{"Statement":[`+a+`,`+a+`]}`))
	if SidKeyed(dup[0]) || dup[0] == dup[1] {
		t.Errorf("duplicate Sids = %v; a Sid that is not unique is not an identity", dup)
	}
	if other := trustKeys(Key("aws", "uid", "AROANEW"), trustStatements(t, `{"Statement":[`+a+`]}`)); other[0] == keys[0] {
		t.Error("a recreated role (new RoleId) shares a trust statement key with its predecessor")
	}
}

// D-41: the edge key is the principal's recognition key, never its endpoint.
func TestTrustEdgeKeyIsThePrincipalsRecognitionKey(t *testing.T) {
	arn := "arn:aws:iam::905418271234:role/data-reader"
	st := trustStatements(t, `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"`+arn+`"},"Action":"sts:AssumeRole"}]}`)[0]
	sub := st.Subjects()[0]
	if ExternalPrincipalKey(sub.Issuer, sub.Subject) != ExternalPrincipalKey(awsdiscovery.IssuerAWS, arn) {
		t.Fatalf("principal key = %q", ExternalPrincipalKey(sub.Issuer, sub.Subject))
	}
	got, ok := ARNOfIdentityKey(IdentityARNKey(arn))
	if !ok || got != arn {
		t.Errorf("ARNOfIdentityKey(IdentityARNKey(arn)) = %q, %v", got, ok)
	}
	for _, bad := range []string{"", Key("aws", "uid", "AROA1"), Key("github", arn), "aws" + Sep} {
		if _, ok := ARNOfIdentityKey(bad); ok {
			t.Errorf("ARNOfIdentityKey(%q) accepted a non-identity key", bad)
		}
	}
	if PodIdentityIssuer("oidc.eks.us-east-1.amazonaws.com/id/X", "arn:aws:eks:us-east-1:1:cluster/c") != "oidc.eks.us-east-1.amazonaws.com/id/X" ||
		PodIdentityIssuer("", "arn:aws:eks:us-east-1:1:cluster/c") != "arn:aws:eks:us-east-1:1:cluster/c" ||
		PodIdentityIssuer("", "") != "" {
		t.Error("PodIdentityIssuer: the cluster OIDC issuer, else the cluster ARN, else nothing (D-42)")
	}
	if PodIdentitySubjectKey("arn:aws:iam::1:role/r", "i", "s") == "arn:aws:iam::1:role/r" {
		t.Error("the association observation's key collides with the role's own observation")
	}
}

// protected() answers for both can_assume partitions, and only with their own
// exclusion list.
func TestTrustProtectedPartitions(t *testing.T) {
	snap := snapWith(nil)
	trust := snap.EdgePartitionFor(models.RelTypeCanAssume, TrustPartitionKind, "")
	pod := snap.EdgePartitionFor(models.RelTypeCanAssume, models.MechanismEKSPodIdentity, "")
	role := uuid.New()

	if _, _, ok := protected(pod, Exclusions{UnattributedPodIdentity: []uuid.UUID{role}}); !ok {
		t.Error("pod-identity partition does not protect a role with an unattributed association")
	}
	if _, _, ok := protected(pod, Exclusions{UnreadableTrust: []uuid.UUID{role}}); ok {
		t.Error("an unreadable trust DOCUMENT protected pod-identity edges, which it does not declare")
	}
	if _, _, ok := protected(trust, Exclusions{UnattributedPodIdentity: []uuid.UUID{role}}); ok {
		t.Error("an unattributed association protected trust-document edges")
	}
	if _, _, ok := protected(trust, Exclusions{UnreadableTrust: []uuid.UUID{role}}); !ok {
		t.Error("trust partition does not protect a role whose document was unreadable")
	}
}

// D-45: a role with no document and no error is unreadable, not "trusts
// nobody".
func TestTrustUnreadableIncludesAMissingDocument(t *testing.T) {
	ok, bad, none, null, user := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	got := unreadableTrust([]models.CloudIdentity{
		{ID: ok, Kind: models.CloudIdentityIAMRole, TrustDocument: json.RawMessage(`{"Statement":[]}`)},
		{ID: bad, Kind: models.CloudIdentityIAMRole, TrustDocument: json.RawMessage(`{}`), TrustParseError: "parse: x"},
		{ID: none, Kind: models.CloudIdentityIAMRole},
		{ID: null, Kind: models.CloudIdentityIAMRole, TrustDocument: json.RawMessage(`null`)},
		{ID: user, Kind: models.CloudIdentityIAMUser},
	})
	if got[ok] || !got[bad] || !got[none] || !got[null] || got[user] {
		t.Errorf("unreadable = %v", got)
	}
}
