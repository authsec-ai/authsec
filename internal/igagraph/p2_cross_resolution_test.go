package igagraph

// The read-time cross-provider match rules (trust.go, D-108): issuer
// normalisation and the ServiceAccount a subject names.

import (
	"testing"

	"github.com/authsec-ai/authsec/models"
)

func TestNormalizeOIDCIssuer(t *testing.T) {
	const want = "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE0539D4633E53DE1B716D3041E"
	for _, in := range []string{
		"oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE0539D4633E53DE1B716D3041E",
		"https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE0539D4633E53DE1B716D3041E",
		"https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE0539D4633E53DE1B716D3041E/",
		"HTTPS://OIDC.EKS.us-east-1.amazonaws.com/id/EXAMPLE0539D4633E53DE1B716D3041E//",
		"  http://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE0539D4633E53DE1B716D3041E ",
	} {
		if got := NormalizeOIDCIssuer(in); got != want {
			t.Errorf("NormalizeOIDCIssuer(%q) = %q, want %q", in, got, want)
		}
	}
	// The cluster id is case-sensitive: another case is another issuer.
	if NormalizeOIDCIssuer("https://oidc.eks.us-east-1.amazonaws.com/id/example0539d4633e53de1b716d3041e") == want {
		t.Error("the issuer path must keep its case")
	}
	if NormalizeOIDCIssuer("") != "" || NormalizeOIDCIssuer("https://") != "" {
		t.Error("an empty issuer must stay empty")
	}
}

func TestK8sServiceAccountSubject(t *testing.T) {
	for _, tc := range []struct {
		mech, subject, ns, sa string
		ok                    bool
	}{
		{models.ExternalPrincipalOIDC, "system:serviceaccount:shop:checkout", "shop", "checkout", true},
		{models.ExternalPrincipalK8sServiceAccount, PodIdentitySubject("system:serviceaccount:shop:checkout"), "shop", "checkout", true},
		// The pod-identity prefix belongs to the pod-identity mechanism only.
		{models.ExternalPrincipalK8sServiceAccount, "system:serviceaccount:shop:checkout", "", "", false},
		{models.ExternalPrincipalOIDC, PodIdentitySubject("system:serviceaccount:shop:checkout"), "", "", false},
		// Wildcards name no one ServiceAccount.
		{models.ExternalPrincipalOIDC, "system:serviceaccount:shop:*", "", "", false},
		{models.ExternalPrincipalOIDC, "system:serviceaccount:*:checkout", "", "", false},
		{models.ExternalPrincipalOIDC, "system:serviceaccount:shop:check?ut", "", "", false},
		// Malformed or another kind of subject.
		{models.ExternalPrincipalOIDC, "system:serviceaccount:shop", "", "", false},
		{models.ExternalPrincipalOIDC, "system:serviceaccount::checkout", "", "", false},
		{models.ExternalPrincipalOIDC, "system:serviceaccount:shop:a:b", "", "", false},
		{models.ExternalPrincipalOIDC, "repo:org/repo:ref:refs/heads/main", "", "", false},
		{models.ExternalPrincipalAWSPrincipal, "system:serviceaccount:shop:checkout", "", "", false},
	} {
		ns, sa, ok := K8sServiceAccountSubject(tc.mech, tc.subject)
		if ns != tc.ns || sa != tc.sa || ok != tc.ok {
			t.Errorf("K8sServiceAccountSubject(%s, %q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.mech, tc.subject, ns, sa, ok, tc.ns, tc.sa, tc.ok)
		}
	}
}
