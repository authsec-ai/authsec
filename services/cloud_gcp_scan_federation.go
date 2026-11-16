package services

import (
	"sort"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
)

/* cloud_gcp_scan_federation.go joins a binding member that is an outside
   identity with the federation config the scan read (GCP-2's pools and
   providers, kept in the snapshot), so an edge can say WHICH issuer can become
   it and whether the provider admits every token that issuer mints. */

// gcpFederation is what an edge records about an outside member.
type gcpFederation struct {
	subjectKind string
	// subject is what the issuer side is: the pool subject for a principal, the
	// k8s_ref for a GKE service account.
	subject   string
	mechanism string
	issuer    *string
	k8sRef    *string
	attrs     models.GCPAssumeEdgeAttrs
}

// gcpFederationOf classifies a member, or returns nil for an ordinary one.
func gcpFederationOf(m gcp.Member, snapshot *GCPScanSnapshot) *gcpFederation {
	// GKE, member form serviceAccount:<project>.svc.id.goog[<ns>/<ksa>].
	if m.IsGKEWorkloadIdentity() {
		ref := gcp.K8sRef(m.GKENamespace, m.GKEServiceAccount)
		return &gcpFederation{
			subjectKind: models.AssumeSubjectK8sSA, subject: ref,
			mechanism: models.AssumeMechanismGKEWorkloadIdentity, k8sRef: &ref,
			attrs: models.GCPAssumeEdgeAttrs{Pool: m.GKEProject + ".svc.id.goog"},
		}
	}
	if m.Type != gcp.MemberPrincipal && m.Type != gcp.MemberPrincipalSet {
		return nil
	}
	poolID := gcp.PoolID(m.PoolRef)

	// GKE, direct form principal://.../workloadIdentityPools/<project>.svc.id.goog/subject/ns/<ns>/sa/<ksa>.
	if _, ok := gcp.GKEPool(m.PoolRef); ok {
		f := &gcpFederation{
			subjectKind: models.AssumeSubjectK8sSA, subject: m.Subject,
			mechanism: models.AssumeMechanismGKEWorkloadIdentity,
			attrs:     models.GCPAssumeEdgeAttrs{Pool: poolID},
		}
		if ref, ok := gcp.GKEPrincipalK8sRef(m.Subject); ok {
			f.subject, f.k8sRef = ref, &ref
		}
		return f
	}

	f := &gcpFederation{
		subjectKind: models.AssumeSubjectExternal, subject: m.Subject,
		mechanism: models.AssumeMechanismOIDCFederation,
		attrs:     models.GCPAssumeEdgeAttrs{Pool: poolID},
	}
	if gcp.IsWorkforcePool(m.PoolRef) {
		// People signing in through the organization's IdP, not workloads.
		f.attrs.Workforce = true
		return f
	}

	providers := gcpPoolProviders(snapshot, m.PoolRef)
	if len(providers) == 0 {
		f.attrs.ProviderUnknown = true
		return f
	}
	kinds := map[string]bool{}
	var firstIssuer string
	for _, p := range providers {
		if p.Disabled {
			continue
		}
		kind, host := gcp.ClassifyIssuer(p.Type, p.IssuerURI)
		kinds[kind] = true
		if firstIssuer == "" {
			firstIssuer = host
		}
		f.attrs.Providers = append(f.attrs.Providers, p.Provider)
		f.attrs.Issuers = append(f.attrs.Issuers, host)
		if gcp.Unconditioned(p.AttributeCondition) {
			f.attrs.Unconditioned = true
		}
		if f.attrs.AttributeCondition == "" {
			f.attrs.AttributeCondition = p.AttributeCondition
			f.attrs.AttributeMapping = p.AttributeMapping
		}
	}
	if len(f.attrs.Providers) == 0 {
		f.attrs.ProviderUnknown = true // every provider in the pool is disabled
		return f
	}
	// One kind when the pool's providers agree; otherwise the broadest claim
	// (external) rather than a narrower one some provider does not fit.
	if len(kinds) == 1 {
		for k := range kinds {
			f.subjectKind = k
		}
	}
	f.issuer = &firstIssuer
	return f
}

// gcpPoolProviders returns the providers of the pool a member names, matched by
// pool id and its project (number or id), sorted by provider id.
func gcpPoolProviders(snapshot *GCPScanSnapshot, poolRef string) []gcpProvider {
	poolID := gcp.PoolID(poolRef)
	project := gcp.PoolProject(poolRef)
	ids := map[string]bool{project: true}
	for _, p := range snapshot.Projects {
		if p.Number == project || p.ProjectID == project {
			ids[p.ProjectID] = true
		}
	}
	var out []gcpProvider
	for _, p := range snapshot.Providers {
		if p.Pool == poolID && (ids[p.ProjectID] || (p.ProjectRef != "" && p.ProjectRef == project)) {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}
