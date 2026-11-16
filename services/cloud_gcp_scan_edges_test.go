package services

import (
	"testing"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
)

func gcp4Snapshot() *GCPScanSnapshot {
	return &GCPScanSnapshot{
		Projects: []gcpProject{{ProjectID: "proj-a", Number: "829"}},
		Providers: []gcpProvider{
			{ProjectID: "proj-a", Pool: "iga-github", Provider: "github", Type: "oidc",
				IssuerURI: "https://token.actions.githubusercontent.com", AttributeCondition: "assertion.repository=='o/r'",
				AttributeMapping: map[string]string{"google.subject": "assertion.sub"}},
			{ProjectID: "proj-a", Pool: "broad", Provider: "gitlab-broad", Type: "oidc", IssuerURI: "https://gitlab.com"},
			{ProjectID: "proj-a", Pool: "aws-pool", Provider: "aws", Type: "aws", AWSAccount: "123456789012"},
		},
	}
}

func mustMember(t *testing.T, raw string) gcp.Member {
	t.Helper()
	m, err := gcp.ParseMember(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return m
}

func TestFederationOfGitHubPool(t *testing.T) {
	f := gcpFederationOf(mustMember(t, "principalSet://iam.googleapis.com/projects/829/locations/global/workloadIdentityPools/iga-github/*"), gcp4Snapshot())
	if f == nil || f.subjectKind != models.AssumeSubjectCIPipeline || f.mechanism != models.AssumeMechanismOIDCFederation {
		t.Fatalf("got %+v", f)
	}
	if f.issuer == nil || *f.issuer != "token.actions.githubusercontent.com" || f.attrs.Unconditioned || f.attrs.AttributeCondition == "" {
		t.Fatalf("issuer/condition: %+v", f.attrs)
	}
}

func TestFederationOfUnconditionedProvider(t *testing.T) {
	f := gcpFederationOf(mustMember(t, "principalSet://iam.googleapis.com/projects/829/locations/global/workloadIdentityPools/broad/*"), gcp4Snapshot())
	if f == nil || !f.attrs.Unconditioned || f.subjectKind != models.AssumeSubjectCIPipeline {
		t.Fatalf("a provider with no condition must be unconditioned: %+v", f)
	}
}

func TestFederationOfAWSAndUnknownPools(t *testing.T) {
	aws := gcpFederationOf(mustMember(t, "principalSet://iam.googleapis.com/projects/829/locations/global/workloadIdentityPools/aws-pool/*"), gcp4Snapshot())
	if aws == nil || aws.subjectKind != models.AssumeSubjectExternal || *aws.issuer != "sts.amazonaws.com" {
		t.Fatalf("aws: %+v", aws)
	}
	unk := gcpFederationOf(mustMember(t, "principal://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/elsewhere/subject/x"), gcp4Snapshot())
	if unk == nil || !unk.attrs.ProviderUnknown || unk.issuer != nil || unk.subjectKind != models.AssumeSubjectExternal {
		t.Fatalf("unknown pool: %+v", unk)
	}
}

func TestFederationOfGKEBothForms(t *testing.T) {
	ksa := gcpFederationOf(mustMember(t, "serviceAccount:proj-a.svc.id.goog[iga/app-ksa]"), gcp4Snapshot())
	if ksa == nil || ksa.subjectKind != models.AssumeSubjectK8sSA || ksa.k8sRef == nil || *ksa.k8sRef != "system:serviceaccount:iga:app-ksa" ||
		ksa.mechanism != models.AssumeMechanismGKEWorkloadIdentity {
		t.Fatalf("KSA form: %+v", ksa)
	}
	direct := gcpFederationOf(mustMember(t,
		"principal://iam.googleapis.com/projects/829/locations/global/workloadIdentityPools/proj-a.svc.id.goog/subject/ns/iga/sa/direct-ksa"), gcp4Snapshot())
	if direct == nil || direct.k8sRef == nil || *direct.k8sRef != "system:serviceaccount:iga:direct-ksa" || direct.subject != *direct.k8sRef {
		t.Fatalf("direct form: %+v", direct)
	}
}

func TestFederationOfOrdinaryMemberIsNil(t *testing.T) {
	for _, raw := range []string{"user:a@x.com", "serviceAccount:sa@p.iam.gserviceaccount.com", "allUsers"} {
		if f := gcpFederationOf(mustMember(t, raw), gcp4Snapshot()); f != nil {
			t.Fatalf("%s: %+v", raw, f)
		}
	}
}

func TestSAKeyOf(t *testing.T) {
	if gcpSAKeyOf("//iam.googleapis.com/projects/p/serviceAccounts/1001") != "1001" ||
		gcpSAKeyOf("//iam.googleapis.com/projects/p/serviceAccounts/App@P.iam.gserviceaccount.com") != "app@p.iam.gserviceaccount.com" {
		t.Fatal("gcpSAKeyOf")
	}
}

// A project-scoped connector never learns its project number; the pool is still
// found through the number in the provider's own name.
func TestFederationJoinsByProviderNameNumber(t *testing.T) {
	snap := &GCPScanSnapshot{
		Projects: []gcpProject{{ProjectID: "proj-a"}}, // no number
		Providers: []gcpProvider{{ProjectID: "proj-a", ProjectRef: "829", Pool: "iga-github", Provider: "github",
			Type: "oidc", IssuerURI: "https://token.actions.githubusercontent.com", AttributeCondition: "x"}},
	}
	f := gcpFederationOf(mustMember(t, "principalSet://iam.googleapis.com/projects/829/locations/global/workloadIdentityPools/iga-github/*"), snap)
	if f == nil || f.attrs.ProviderUnknown || f.subjectKind != models.AssumeSubjectCIPipeline {
		t.Fatalf("got %+v", f)
	}
}
