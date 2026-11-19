package gcp

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// MemberType is the kind of principal an IAM member string names.
type MemberType string

const (
	MemberUser           MemberType = "user"
	MemberGroup          MemberType = "group"
	MemberDomain         MemberType = "domain"
	MemberServiceAccount MemberType = "serviceAccount"
	MemberAllUsers       MemberType = "allUsers"
	MemberAllAuthUsers   MemberType = "allAuthenticatedUsers"
	// MemberPrincipal is principal://, a single federated / workload identity.
	MemberPrincipal MemberType = "principal"
	// MemberPrincipalSet is principalSet://, a set of federated identities.
	MemberPrincipalSet MemberType = "principalSet"
	// MemberProjectRole is projectOwner:/projectEditor:/projectViewer:, a legacy
	// convenience member that stands for the project's owners/editors/viewers.
	MemberProjectRole MemberType = "projectRole"
	// MemberDeleted is any "deleted:" member. Inner holds the original type.
	MemberDeleted MemberType = "deleted"
)

// ErrBadMember is returned for a member string that is empty or unrecognised.
var ErrBadMember = errors.New("gcp: unrecognised IAM member")

// Member is a parsed IAM member.
type Member struct {
	Raw  string
	Type MemberType
	// Inner is the underlying type of a deleted member (user, group,
	// serviceAccount); equal to Type otherwise.
	Inner MemberType
	// ID is the normalised identifier: lower-cased email, domain, or the whole
	// principal:// / principalSet:// resource path (case preserved there, since
	// subjects and attribute values are case-sensitive).
	ID string
	// Email / Domain are set for the types that carry them.
	Email  string
	Domain string
	// UID is the immutable id of a deleted member (deleted:...?uid=).
	UID string
	// Deleted is true for a "deleted:" member.
	Deleted bool
	// PoolRef / Subject are set for principal:// and principalSet://. PoolRef is
	// the pool resource ("projects/N/locations/global/workloadIdentityPools/P" or
	// "locations/global/workforcePools/P"); Subject is what follows it.
	PoolRef string
	Subject string
	// GKEProject / GKENamespace / GKEServiceAccount are set for the GKE
	// Workload Identity member serviceAccount:PROJ.svc.id.goog[ns/ksa].
	GKEProject        string
	GKENamespace      string
	GKEServiceAccount string
}

var gkeWIPattern = regexp.MustCompile(`^([a-z][a-z0-9.:-]*)\.svc\.id\.goog\[([^/\]]+)/([^\]]+)\]$`)

// ParseMember parses an IAM member string as found in a policy binding. It never
// calls an API. An unknown prefix is an error rather than a guess, so a new
// Google member kind surfaces as a counted parse failure, not a wrong identity.
func ParseMember(raw string) (Member, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Member{}, fmt.Errorf("%w: empty", ErrBadMember)
	}
	m := Member{Raw: raw}

	switch s {
	case "allUsers":
		m.Type, m.Inner, m.ID = MemberAllUsers, MemberAllUsers, "allUsers"
		return m, nil
	case "allAuthenticatedUsers":
		m.Type, m.Inner, m.ID = MemberAllAuthUsers, MemberAllAuthUsers, "allAuthenticatedUsers"
		return m, nil
	}

	if strings.HasPrefix(s, "principal://") || strings.HasPrefix(s, "principalSet://") {
		return parsePrincipalURI(m, s)
	}

	if strings.HasPrefix(s, "deleted:") {
		return parseDeleted(m, s)
	}

	prefix, rest, ok := strings.Cut(s, ":")
	if !ok || rest == "" {
		return Member{}, fmt.Errorf("%w: %q", ErrBadMember, s)
	}
	switch prefix {
	case "user", "group", "serviceAccount":
		t := MemberType(prefix)
		m.Type, m.Inner = t, t
		if t == MemberServiceAccount {
			if g := gkeWIPattern.FindStringSubmatch(rest); g != nil {
				m.ID = strings.ToLower(rest)
				m.GKEProject, m.GKENamespace, m.GKEServiceAccount = g[1], g[2], g[3]
				return m, nil
			}
		}
		m.Email = strings.ToLower(rest)
		m.ID = m.Email
		return m, nil
	case "domain":
		m.Type, m.Inner = MemberDomain, MemberDomain
		m.Domain = strings.ToLower(rest)
		m.ID = m.Domain
		return m, nil
	case "projectOwner", "projectEditor", "projectViewer":
		m.Type, m.Inner = MemberProjectRole, MemberProjectRole
		m.ID = prefix + ":" + strings.ToLower(rest)
		return m, nil
	}
	return Member{}, fmt.Errorf("%w: prefix %q", ErrBadMember, prefix)
}

// deleted:user:alice@x.com?uid=123  /  deleted:serviceAccount:sa@p.iam...?uid=1
func parseDeleted(m Member, s string) (Member, error) {
	body := strings.TrimPrefix(s, "deleted:")
	idPart, query, _ := strings.Cut(body, "?")
	typ, id, ok := strings.Cut(idPart, ":")
	if !ok || id == "" {
		return Member{}, fmt.Errorf("%w: %q", ErrBadMember, s)
	}
	switch MemberType(typ) {
	case MemberUser, MemberGroup, MemberServiceAccount:
	default:
		return Member{}, fmt.Errorf("%w: deleted type %q", ErrBadMember, typ)
	}
	m.Type, m.Inner, m.Deleted = MemberDeleted, MemberType(typ), true
	m.Email = strings.ToLower(id)
	m.ID = m.Email
	if q, err := url.ParseQuery(query); err == nil {
		m.UID = q.Get("uid")
	}
	return m, nil
}

// principal://iam.googleapis.com/projects/N/locations/global/workloadIdentityPools/P/subject/S
// principalSet://iam.googleapis.com/projects/N/locations/global/workloadIdentityPools/P/attribute.repo/org/r
// principal://iam.googleapis.com/locations/global/workforcePools/P/subject/S
func parsePrincipalURI(m Member, s string) (Member, error) {
	isSet := strings.HasPrefix(s, "principalSet://")
	m.Type = MemberPrincipal
	if isSet {
		m.Type = MemberPrincipalSet
	}
	m.Inner = m.Type
	rest := s[strings.Index(s, "://")+3:]
	host, path, ok := strings.Cut(rest, "/")
	if !ok || host == "" || path == "" {
		return Member{}, fmt.Errorf("%w: %q", ErrBadMember, s)
	}
	segs := strings.Split(path, "/")
	poolAt := -1
	for i, seg := range segs {
		if (seg == "workloadIdentityPools" || seg == "workforcePools") && i+1 < len(segs) {
			poolAt = i + 1
			break
		}
	}
	if poolAt < 0 {
		return Member{}, fmt.Errorf("%w: no pool in %q", ErrBadMember, s)
	}
	m.PoolRef = strings.Join(segs[:poolAt+1], "/")
	m.Subject = strings.Join(segs[poolAt+1:], "/")
	m.ID = path // case preserved: subjects / attribute values are case-sensitive
	return m, nil
}

// IsGKEWorkloadIdentity reports the serviceAccount:PROJ.svc.id.goog[ns/ksa] form.
func (m Member) IsGKEWorkloadIdentity() bool { return m.GKEServiceAccount != "" }

// NativeID is the cloud_identity.native_id for a principal that exists only in
// bindings. Prefixed "//gcp/principal/" so it can never collide with an AWS ARN,
// an Azure GUID or a real service account's //iam.googleapis.com/... id, because
// uq_cloud_identity_native is (workspace_id, native_id) across ALL providers.
//
// A real live service account is NOT given this id: it is keyed by its unique id
// (see gcpServiceAccountNativeID), and a binding refers to it only by email, so
// the caller must resolve it first and use this only when no real row exists.
func (m Member) NativeID() string {
	if m.IsGKEWorkloadIdentity() {
		// A Kubernetes service account, not a Google one: federated, so it can
		// never be mistaken for the GSA it impersonates.
		return "//gcp/principal/federated/gke/" + m.ID
	}
	switch m.Type {
	case MemberAllUsers, MemberAllAuthUsers:
		return "//gcp/principal/public/" + m.ID
	case MemberDeleted:
		key := m.UID
		if key == "" {
			key = m.ID
		}
		return "//gcp/principal/deleted/" + string(m.Inner) + "/" + key
	case MemberPrincipal, MemberPrincipalSet:
		return "//gcp/principal/federated/" + m.ID
	case MemberDomain:
		return "//gcp/principal/domain/" + m.ID
	default:
		return "//gcp/principal/" + string(m.Type) + "/" + m.ID
	}
}

// ClassifySA classifies a service-account email into the sa_class vocabulary.
func ClassifySA(email string) string {
	e := strings.ToLower(strings.TrimSpace(email))
	switch {
	case defaultComputeRE.MatchString(e):
		return SAClassDefaultCompute
	case defaultAppEngineRE.MatchString(e):
		return SAClassDefaultAppEngine
	case serviceAgentRE.MatchString(e), cloudServicesRE.MatchString(e):
		return SAClassServiceAgent
	}
	return SAClassUserManaged
}

// sa_class values.
const (
	SAClassUserManaged      = "user_managed"
	SAClassDefaultCompute   = "default_compute"
	SAClassDefaultAppEngine = "default_appengine"
	SAClassServiceAgent     = "service_agent"
)

var (
	defaultComputeRE   = regexp.MustCompile(`^\d+-compute@developer\.gserviceaccount\.com$`)
	defaultAppEngineRE = regexp.MustCompile(`^[a-z][a-z0-9-]*@appspot\.gserviceaccount\.com$`)
	// service-<num>@gcp-sa-<x>.iam.gserviceaccount.com, and the older
	// service-<num>@<x>-robot.iam.gserviceaccount.com / @<x>.gserviceaccount.com
	// forms. The host part is what proves it is Google's: a user-managed SA lives
	// at <name>@<project>.iam.gserviceaccount.com, so a bare "service-123@proj.iam"
	// is NOT matched.
	serviceAgentRE  = regexp.MustCompile(`^service-\d+@(gcp-sa-[a-z0-9-]+\.iam|[a-z0-9-]+-(?:robot|system)\.iam|[a-z0-9-]+)\.gserviceaccount\.com$`)
	cloudServicesRE = regexp.MustCompile(`^\d+@cloudservices\.gserviceaccount\.com$`)
)
