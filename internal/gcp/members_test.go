package gcp

import (
	"errors"
	"strings"
	"testing"
)

func TestParseMember_EveryPrefix(t *testing.T) {
	cases := []struct {
		raw      string
		typ      MemberType
		inner    MemberType
		id       string
		deleted  bool
		uid      string
		nativeID string
	}{
		{"user:Alice@Example.com", MemberUser, MemberUser, "alice@example.com", false, "", "//gcp/principal/user/alice@example.com"},
		{"group:Eng@example.com", MemberGroup, MemberGroup, "eng@example.com", false, "", "//gcp/principal/group/eng@example.com"},
		{"domain:Example.com", MemberDomain, MemberDomain, "example.com", false, "", "//gcp/principal/domain/example.com"},
		{"serviceAccount:sa@p.iam.gserviceaccount.com", MemberServiceAccount, MemberServiceAccount, "sa@p.iam.gserviceaccount.com", false, "", "//gcp/principal/serviceAccount/sa@p.iam.gserviceaccount.com"},
		{"allUsers", MemberAllUsers, MemberAllUsers, "allUsers", false, "", "//gcp/principal/public/allUsers"},
		{"allAuthenticatedUsers", MemberAllAuthUsers, MemberAllAuthUsers, "allAuthenticatedUsers", false, "", "//gcp/principal/public/allAuthenticatedUsers"},
		{"principal://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/gh/subject/Repo-X", MemberPrincipal, MemberPrincipal,
			"projects/123/locations/global/workloadIdentityPools/gh/subject/Repo-X", false, "",
			"//gcp/principal/federated/projects/123/locations/global/workloadIdentityPools/gh/subject/Repo-X"},
		{"principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/gh/attribute.repository/org/r", MemberPrincipalSet, MemberPrincipalSet,
			"projects/123/locations/global/workloadIdentityPools/gh/attribute.repository/org/r", false, "",
			"//gcp/principal/federated/projects/123/locations/global/workloadIdentityPools/gh/attribute.repository/org/r"},
		{"deleted:user:bob@example.com?uid=1111", MemberDeleted, MemberUser, "bob@example.com", true, "1111", "//gcp/principal/deleted/user/1111"},
		{"deleted:serviceAccount:old@p.iam.gserviceaccount.com?uid=2222", MemberDeleted, MemberServiceAccount, "old@p.iam.gserviceaccount.com", true, "2222", "//gcp/principal/deleted/serviceAccount/2222"},
		{"projectOwner:my-proj", MemberProjectRole, MemberProjectRole, "projectOwner:my-proj", false, "", "//gcp/principal/projectRole/projectOwner:my-proj"},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			m, err := ParseMember(c.raw)
			if err != nil {
				t.Fatal(err)
			}
			if m.Type != c.typ || m.Inner != c.inner || m.ID != c.id || m.Deleted != c.deleted || m.UID != c.uid {
				t.Fatalf("got %+v", m)
			}
			if got := m.NativeID(); got != c.nativeID {
				t.Fatalf("native id = %q, want %q", got, c.nativeID)
			}
		})
	}
}

func TestParseMember_PrincipalPoolAndSubject(t *testing.T) {
	m, _ := ParseMember("principal://iam.googleapis.com/projects/9/locations/global/workloadIdentityPools/p1/subject/a/b")
	if m.PoolRef != "projects/9/locations/global/workloadIdentityPools/p1" || m.Subject != "subject/a/b" {
		t.Fatalf("got pool=%q subject=%q", m.PoolRef, m.Subject)
	}
	w, _ := ParseMember("principal://iam.googleapis.com/locations/global/workforcePools/wf/subject/u")
	if w.PoolRef != "locations/global/workforcePools/wf" {
		t.Fatalf("workforce pool = %q", w.PoolRef)
	}
}

func TestParseMember_GKEWorkloadIdentity(t *testing.T) {
	m, err := ParseMember("serviceAccount:my-proj.svc.id.goog[ns1/ksa1]")
	if err != nil || !m.IsGKEWorkloadIdentity() {
		t.Fatalf("got %+v, %v", m, err)
	}
	if m.GKEProject != "my-proj" || m.GKENamespace != "ns1" || m.GKEServiceAccount != "ksa1" || m.Email != "" {
		t.Fatalf("got %+v", m)
	}
}

func TestParseMember_Malformed(t *testing.T) {
	for _, raw := range []string{"", "  ", "bob", "unknown:x", "user:", "deleted:user", "deleted:weird:x?uid=1", "principal://iam.googleapis.com/projects/1", "principal://"} {
		if _, err := ParseMember(raw); !errors.Is(err, ErrBadMember) {
			t.Errorf("%q: want ErrBadMember, got %v", raw, err)
		}
	}
}

func TestParseMember_NativeIDNeverCollidesWithOtherProviders(t *testing.T) {
	for _, raw := range []string{"user:a@b.com", "allUsers", "domain:b.com", "deleted:user:a@b.com?uid=1"} {
		m, _ := ParseMember(raw)
		id := m.NativeID()
		if !strings.HasPrefix(id, "//gcp/principal/") || strings.HasPrefix(id, "arn:") {
			t.Errorf("%s -> %s", raw, id)
		}
	}
}

func TestClassifySA(t *testing.T) {
	cases := map[string]string{
		"my-sa@proj.iam.gserviceaccount.com":                       SAClassUserManaged,
		"123456789-compute@developer.gserviceaccount.com":          SAClassDefaultCompute,
		"my-proj@appspot.gserviceaccount.com":                      SAClassDefaultAppEngine,
		"service-123456@gcp-sa-pubsub.iam.gserviceaccount.com":     SAClassServiceAgent,
		"123456@cloudservices.gserviceaccount.com":                 SAClassServiceAgent,
		"service-123@container-engine-robot.iam.gserviceaccount.com": SAClassServiceAgent,
		"service-123@compute-system.iam.gserviceaccount.com":       SAClassServiceAgent,
		// A user-managed SA that merely looks like an agent stays user_managed.
		"service-123@my-proj.iam.gserviceaccount.com": SAClassUserManaged,
		"MY-SA@Proj.iam.gserviceaccount.com":          SAClassUserManaged,
		"123456789-compute@Developer.gserviceaccount.com": SAClassDefaultCompute,
	}
	for email, want := range cases {
		if got := ClassifySA(email); got != want {
			t.Errorf("%s: got %s want %s", email, got, want)
		}
	}
}
