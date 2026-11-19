package services

import (
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
	apikeys "google.golang.org/api/apikeys/v2"
	iam "google.golang.org/api/iam/v1"
)

func TestProbeSaysUnreadable(t *testing.T) {
	attrs := models.GCPConnectorAttrs{CapabilityProfile: map[string]models.GCPSurfaceCapability{
		gcp.SurfaceHMACKeys:         {Can: false, Missing: []string{"storage.hmacKeys.list"}},
		gcp.SurfaceAPIKeys:          {Can: true},
		gcp.SurfaceFederationConfig: {Unknown: true, Reason: "api refused the check"},
	}}
	if reason, skip := gcpProbeSaysUnreadable(attrs, gcp.SurfaceHMACKeys); !skip || reason != "not_readable: missing storage.hmacKeys.list" {
		t.Fatalf("hmac: skip=%v reason=%q", skip, reason)
	}
	// The live case: the reader held every .list and lacked only the .get the
	// probe also asks about. The collectors call list only, so the surface must
	// be ATTEMPTED, not skipped.
	live := models.GCPConnectorAttrs{CapabilityProfile: map[string]models.GCPSurfaceCapability{
		gcp.SurfaceHMACKeys:         {Missing: []string{"storage.hmacKeys.get"}},
		gcp.SurfaceAPIKeys:          {Missing: []string{"apikeys.keys.get"}},
		gcp.SurfaceFederationConfig: {Missing: []string{"iam.workloadIdentityPools.get", "iam.workloadIdentityPoolProviders.get"}},
	}}
	for _, surface := range []string{gcp.SurfaceHMACKeys, gcp.SurfaceAPIKeys, gcp.SurfaceFederationConfig} {
		if reason, skip := gcpProbeSaysUnreadable(live, surface); skip {
			t.Errorf("%s skipped for a missing .get it never calls: %s", surface, reason)
		}
	}
	// A missing .list of the federation pair still skips, naming only that one.
	partial := models.GCPConnectorAttrs{CapabilityProfile: map[string]models.GCPSurfaceCapability{
		gcp.SurfaceFederationConfig: {Missing: []string{"iam.workloadIdentityPools.get", "iam.workloadIdentityPoolProviders.list"}},
	}}
	if reason, skip := gcpProbeSaysUnreadable(partial, gcp.SurfaceFederationConfig); !skip ||
		reason != "not_readable: missing iam.workloadIdentityPoolProviders.list" {
		t.Errorf("partial federation: skip=%v reason=%q", skip, reason)
	}

	// Readable, unknown and never-probed are all ATTEMPTED: only a proved
	// absence of the permission skips a surface.
	for _, surface := range []string{gcp.SurfaceAPIKeys, gcp.SurfaceFederationConfig, gcp.SurfaceKeys} {
		if _, skip := gcpProbeSaysUnreadable(attrs, surface); skip {
			t.Errorf("%s must be attempted", surface)
		}
	}
	if _, skip := gcpProbeSaysUnreadable(models.GCPConnectorAttrs{}, gcp.SurfaceHMACKeys); skip {
		t.Error("a never-probed connector must attempt the surface")
	}
}

// A probe-skipped surface must not stop a scan being Complete(): that is the
// whole point of the probe-gated decision. Every OTHER non-reached state must.
func TestSkippedSurfaceDoesNotBlockComplete(t *testing.T) {
	g := gcp.NewGovernor()
	build := func(skipped, other *gcpSurfaceAcc) models.ScanCoverage {
		return (&GCPScanner{}).buildCoverage(1, time.Now(), "manual", []gcpNamedAcc{
			{surface: gcp.SurfaceIdentities, counter: "identities_upserted", acc: reachedAcc(2)},
			{surface: gcp.SurfaceHMACKeys, counter: "hmac_keys_upserted", acc: skipped},
			{surface: gcp.SurfaceAPIKeys, counter: "api_keys_upserted", acc: other},
		}, g, 1)
	}

	skipped := newGCPSurfaceAcc()
	skipped.skipNotReadable("not_readable: missing storage.hmacKeys.list")

	cov := build(skipped, reachedAcc(1))
	if !cov.Complete() {
		t.Fatalf("skipped surface blocked Complete(): %+v", cov.Surfaces)
	}
	if got := cov.Surfaces[gcp.SurfaceHMACKeys]; got.State != models.CloudCoverageNotSelected || got.Error == "" {
		t.Fatalf("skipped surface must read not_selected with its reason, got %+v", got)
	}

	denied := newGCPSurfaceAcc()
	denied.observe(&gcpTestErr{"permission denied"}, 0)
	if build(skipped, denied).Complete() {
		t.Fatal("a denied surface must still block Complete() even when another is skipped")
	}
}

type gcpTestErr struct{ msg string }

func (e *gcpTestErr) Error() string { return e.msg }

func TestCredentialReconcileSkip(t *testing.T) {
	covWith := func(hmac, api string) models.ScanCoverage {
		return models.ScanCoverage{Surfaces: map[string]models.SurfaceCoverage{
			gcp.SurfaceHMACKeys:      {State: hmac},
			gcp.SurfaceAPIKeys:       {State: api},
			gcp.SurfaceAllowBindings: {State: models.CloudCoverageReached},
			gcp.SurfaceResourceIAM:   {State: models.CloudCoverageReached},
		}}
	}

	// Both reached: nothing is protected, a vanished key is really gone.
	if s := gcpCredentialReconcileSkip(covWith(models.CloudCoverageReached, models.CloudCoverageReached)); len(s.SecretKinds)+len(s.IdentityKinds)+len(s.IdentityNativePrefixes) != 0 {
		t.Fatalf("nothing should be protected: %+v", s)
	}

	// HMAC skipped: its secrets and every member-prefixed owner are protected;
	// API keys (reached) are not.
	s := gcpCredentialReconcileSkip(covWith(models.CloudCoverageNotSelected, models.CloudCoverageReached))
	if len(s.SecretKinds) != 1 || s.SecretKinds[0] != models.CloudSecretGCPHMACKey {
		t.Fatalf("secret kinds: %+v", s.SecretKinds)
	}
	if len(s.IdentityKinds) != 0 || len(s.IdentityNativePrefixes) != 1 || s.IdentityNativePrefixes[0] != "//gcp/principal/" {
		t.Fatalf("identity protection: %+v", s)
	}

	// API keys skipped: the synthetic project owner is protected, or the FK
	// cascade would delete the keys with it.
	s = gcpCredentialReconcileSkip(covWith(models.CloudCoverageReached, models.CloudCoverageNotSelected))
	if len(s.IdentityKinds) != 1 || s.IdentityKinds[0] != models.CloudIdentityGCPProject {
		t.Fatalf("project owner must be protected: %+v", s)
	}

	// A surface missing from the report was never attempted: protect it.
	s = gcpCredentialReconcileSkip(models.ScanCoverage{Surfaces: map[string]models.SurfaceCoverage{}})
	if len(s.SecretKinds) != 2 {
		t.Fatalf("absent surfaces must be protected: %+v", s)
	}
}

func TestAPIKeyRestrictions(t *testing.T) {
	if r := gcpAPIKeyRestrictions(nil); !r.Unrestricted {
		t.Error("a key with no restrictions block is unrestricted")
	}
	if r := gcpAPIKeyRestrictions(&apikeys.V2Restrictions{}); !r.Unrestricted {
		t.Error("an empty restrictions block is unrestricted")
	}
	r := gcpAPIKeyRestrictions(&apikeys.V2Restrictions{
		ApiTargets:            []*apikeys.V2ApiTarget{{Service: "storage.googleapis.com"}},
		ServerKeyRestrictions: &apikeys.V2ServerKeyRestrictions{AllowedIps: []string{"203.0.113.10"}},
	})
	if r.Unrestricted || len(r.APITargets) != 1 || r.APITargets[0] != "storage.googleapis.com" || r.IPs[0] != "203.0.113.10" {
		t.Fatalf("got %+v", r)
	}
}

func TestProjectNumberFromKeyName(t *testing.T) {
	if got := gcpProjectNumberFromKeyName("projects/123456/locations/global/keys/abc"); got != "123456" {
		t.Errorf("got %q", got)
	}
	if got := gcpProjectNumberFromKeyName("keys/abc"); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestSecretNativeIDsAreNamespaced(t *testing.T) {
	// uq_cloud_secret_native is workspace-wide and shared with AWS access keys
	// (bare AKIA...) and SA keys (bare hex): GCP's new kinds must not be bare.
	for _, id := range []string{gcpHMACKeyNativeID("GOOG1E123"), gcpAPIKeyNativeID("projects/1/locations/global/keys/u")} {
		if len(id) < 3 || id[:2] != "//" {
			t.Errorf("%q is not namespaced", id)
		}
	}
}

func TestProviderFrom(t *testing.T) {
	proj := gcpProject{ProjectID: "p"}
	oidc := gcpProviderFrom(proj, "gh", &iam.WorkloadIdentityPoolProvider{
		Name: "projects/1/locations/global/workloadIdentityPools/gh/providers/github",
		Oidc: &iam.Oidc{IssuerUri: "https://token.actions.githubusercontent.com", AllowedAudiences: []string{"a"}, JwksJson: "SECRET-JWKS"},
		AttributeCondition: "assertion.repository == 'o/r'",
	})
	if oidc.Type != "oidc" || oidc.Provider != "github" || oidc.IssuerURI == "" || oidc.AttributeCondition == "" {
		t.Fatalf("oidc: %+v", oidc)
	}
	aws := gcpProviderFrom(proj, "aws", &iam.WorkloadIdentityPoolProvider{Name: "x/providers/a", Aws: &iam.Aws{AccountId: "111"}})
	if aws.Type != "aws" || aws.AWSAccount != "111" || aws.AttributeCondition != "" {
		t.Fatalf("aws: %+v", aws)
	}
}

func TestMemberKinds(t *testing.T) {
	cases := map[string]string{
		"user:a@b.com":                                  models.CloudIdentityGCPUser,
		"group:g@b.com":                                 models.CloudIdentityGCPGroup,
		"domain:b.com":                                  models.CloudIdentityGCPDomain,
		"allUsers":                                      models.CloudIdentityGCPPublic,
		"allAuthenticatedUsers":                         models.CloudIdentityGCPPublic,
		"deleted:user:a@b.com?uid=1":                    models.CloudIdentityGCPDeleted,
		"serviceAccount:service-1@gcp-sa-x.iam.gserviceaccount.com": models.CloudIdentityGCPServiceAgent,
		"serviceAccount:me@p.iam.gserviceaccount.com":   models.CloudIdentityGCPServiceAccount,
		"serviceAccount:p.svc.id.goog[ns/ksa]":          models.CloudIdentityGCPFederated,
		"principal://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/subject/s": models.CloudIdentityGCPFederated,
	}
	for raw, want := range cases {
		m, err := gcp.ParseMember(raw)
		if err != nil {
			t.Fatal(raw, err)
		}
		if got := gcpMemberKind(m); got != want {
			t.Errorf("%s: got %s want %s", raw, got, want)
		}
	}
}

func TestMemberOutsideScope(t *testing.T) {
	projects := []gcpProject{{ProjectID: "iga-dev", Number: "111"}, {ProjectID: "iga-prod", Number: "222"}}
	check := func(raw string, want bool) {
		t.Helper()
		m, err := gcp.ParseMember(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := gcpMemberOutsideScope(m, projects); got != want {
			t.Errorf("%s: got %v want %v", raw, got, want)
		}
	}
	check("serviceAccount:a@iga-dev.iam.gserviceaccount.com", false)
	check("serviceAccount:a@other-proj.iam.gserviceaccount.com", true)
	check("serviceAccount:111-compute@developer.gserviceaccount.com", false)
	check("serviceAccount:999-compute@developer.gserviceaccount.com", true)
	check("serviceAccount:service-222@gcp-sa-pubsub.iam.gserviceaccount.com", false)
	// Users, groups and domains cannot be placed from the address alone.
	check("user:a@elsewhere.com", false)
	check("allUsers", false)

	// A project connector knows no project NUMBER, so a number it cannot match
	// proves nothing and must not be called external.
	m, _ := gcp.ParseMember("serviceAccount:999-compute@developer.gserviceaccount.com")
	if gcpMemberOutsideScope(m, []gcpProject{{ProjectID: "iga-dev"}}) {
		t.Error("unknown project number must not read as external")
	}
}

// A surface skipped for want of token scope must stay skipped even when a later
// project observes a clean result: scopes are token-wide, so one refusal speaks
// for every project.
func TestSkippedSurfaceIsSticky(t *testing.T) {
	a := newGCPSurfaceAcc()
	a.skipNotReadable("not_readable: token scopes cannot list HMAC keys")
	a.observe(nil, 3)
	a.observeVacuous()
	a.fail(&gcpTestErr{"boom"})
	got := a.coverage()
	if got.State != models.CloudCoverageNotSelected || got.Error == "" || got.Count != 0 {
		t.Fatalf("skip was overwritten: %+v", got)
	}
}
