package gcp

import (
	"net/url"
	"sort"
	"strings"
)

/* trust.go is the vocabulary of GCP-4: which grants let a principal BECOME a
   service account, how an outside issuer is classified, and how a GKE workload
   is named. Pure functions; no API calls. The impersonation lists are shared:
   GCP-8's findings must reuse them rather than keep their own copy. */

// ImpersonationRoles are the predefined roles whose purpose is to let a member
// act as, or obtain credentials for, a service account.
var ImpersonationRoles = map[string]bool{
	"roles/iam.serviceAccountUser":         true,
	"roles/iam.serviceAccountTokenCreator": true,
	"roles/iam.workloadIdentityUser":       true,
	"roles/iam.serviceAccountKeyAdmin":     true,
}

// ImpersonationPermissions are the permissions that, in ANY role (custom roles
// included), let a member become a service account, and what each one gives.
var ImpersonationPermissions = map[string]string{
	"iam.serviceAccounts.actAs":          CapabilityActAs,
	"iam.serviceAccounts.getAccessToken": CapabilityMintToken,
	"iam.serviceAccounts.signJwt":        CapabilityMintToken,
	"iam.serviceAccounts.signBlob":       CapabilityMintToken,
	"iam.serviceAccounts.getOpenIdToken": CapabilityMintToken,
	// Creating a key is becoming the account for as long as the key lives.
	"iam.serviceAccountKeys.create": CapabilityCreateKey,
}

// What a grant lets its holder do with the service account.
const (
	// CapabilityActAs: attach it to a workload (VM, Cloud Run, Function) and run as it.
	CapabilityActAs = "act_as"
	// CapabilityMintToken: mint its access/ID tokens or sign as it.
	CapabilityMintToken = "mint_token"
	// CapabilityCreateKey: create a long-lived key for it.
	CapabilityCreateKey = "create_key"
	// CapabilityFederate: an outside identity exchanges its token for this one
	// (roles/iam.workloadIdentityUser).
	CapabilityFederate = "federate"
)

// basicImpersonation is what the unexpanded basic roles carry. Owner and
// Editor both include actAs and service-account key creation; Viewer carries
// neither.
var basicImpersonation = map[string][]string{
	"roles/owner":  {CapabilityActAs, CapabilityCreateKey},
	"roles/editor": {CapabilityActAs, CapabilityCreateKey},
}

// ImpersonationCapabilities reports what a binding of role (with its expanded
// permissions) lets the holder do to a service account in its reach. Empty
// means the binding creates no trust edge.
func ImpersonationCapabilities(role string, permissions []string) []string {
	set := map[string]bool{}
	for _, c := range basicImpersonation[role] {
		set[c] = true
	}
	switch role {
	case "roles/iam.workloadIdentityUser":
		set[CapabilityFederate] = true
	case "roles/iam.serviceAccountUser":
		set[CapabilityActAs] = true
	case "roles/iam.serviceAccountTokenCreator":
		set[CapabilityMintToken] = true
	case "roles/iam.serviceAccountKeyAdmin":
		set[CapabilityCreateKey] = true
	}
	for _, p := range permissions {
		if c, ok := ImpersonationPermissions[p]; ok {
			set[c] = true
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Subject kinds of an outside issuer, as cloud_assume_edge.subject_kind.
const (
	IssuerCIPipeline = "ci_pipeline"
	IssuerExternal   = "external_account"
	IssuerK8s        = "k8s_service_account"
)

// ClassifyIssuer says what kind of thing an identity from this provider is, and
// returns the issuer host (no scheme) the edge records. providerType is
// aws | oidc | saml | x509 | unknown, as the federation reader keeps it.
func ClassifyIssuer(providerType, issuerURI string) (subjectKind, issuerHost string) {
	if providerType == "aws" {
		return IssuerExternal, "sts.amazonaws.com"
	}
	host := issuerURI
	if u, err := url.Parse(issuerURI); err == nil && u.Host != "" {
		host = u.Host
		if p := strings.TrimSuffix(u.Path, "/"); p != "" {
			host += p
		}
	}
	h := strings.ToLower(host)
	switch {
	case strings.HasPrefix(h, "token.actions.githubusercontent.com"),
		strings.HasPrefix(h, "gitlab.com"), strings.Contains(h, ".gitlab."),
		strings.HasPrefix(h, "oidc.circleci.com"),
		strings.HasPrefix(h, "app.terraform.io"),
		strings.Contains(h, "bitbucket"),
		strings.HasPrefix(h, "vstoken.dev.azure.com"):
		return IssuerCIPipeline, host
	case strings.HasPrefix(h, "container.googleapis.com"),
		strings.HasPrefix(h, "oidc.eks."),
		strings.Contains(h, "kubernetes"),
		strings.Contains(h, ".svc.id.goog"):
		return IssuerK8s, host
	}
	return IssuerExternal, host
}

// Unconditioned reports a provider whose attribute condition admits every token
// the issuer mints (none, or the literal true): for a public issuer such as
// GitHub that is anyone's workflow.
func Unconditioned(attributeCondition string) bool {
	c := strings.TrimSpace(attributeCondition)
	return c == "" || c == "true"
}

// K8sRef is the Kubernetes service account string the Kubernetes connector
// records for the same workload: system:serviceaccount:<ns>:<sa>.
func K8sRef(namespace, serviceAccount string) string {
	return "system:serviceaccount:" + namespace + ":" + serviceAccount
}

// GKEPool reports whether a workload identity pool reference is a GKE cluster
// pool (<project>.svc.id.goog), returning the pool's project id.
func GKEPool(poolRef string) (string, bool) {
	pool := poolRef[strings.LastIndex(poolRef, "/")+1:]
	if p, ok := strings.CutSuffix(pool, ".svc.id.goog"); ok && p != "" {
		return p, true
	}
	return "", false
}

// GKEPrincipalK8sRef reads the Kubernetes service account out of a direct GKE
// principal subject ("ns/<ns>/sa/<sa>", optionally prefixed "subject/"). The
// second value is false for any other shape (a principalSet over a namespace,
// for one), which is not one service account.
func GKEPrincipalK8sRef(subject string) (string, bool) {
	s := strings.TrimPrefix(subject, "subject/")
	parts := strings.Split(s, "/")
	if len(parts) == 4 && parts[0] == "ns" && parts[2] == "sa" && parts[1] != "" && parts[3] != "" {
		return K8sRef(parts[1], parts[3]), true
	}
	return "", false
}

// PoolID is the last segment of a pool reference.
func PoolID(poolRef string) string {
	return poolRef[strings.LastIndex(poolRef, "/")+1:]
}

// PoolProject is the project number (or id) a workload identity pool reference
// names: projects/<p>/locations/global/workloadIdentityPools/<pool>. Empty for a
// workforce pool, which belongs to an organization.
func PoolProject(poolRef string) string {
	parts := strings.Split(poolRef, "/")
	if len(parts) >= 2 && parts[0] == "projects" {
		return parts[1]
	}
	return ""
}

// IsWorkforcePool reports a workforce (human, IdP) pool rather than a workload one.
func IsWorkforcePool(poolRef string) bool {
	return strings.Contains(poolRef, "/workforcePools/")
}
