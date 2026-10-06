package igaread

// Across the providers (D-108): an AWS role's trust that names a Kubernetes
// ServiceAccount -- EKS IRSA (an `oidc` external principal) or EKS Pod
// Identity (a `k8s_service_account` one) -- is the one place the AWS and the
// Kubernetes graphs meet. Everything else stays one provider per edge: every
// edge spec is rendered for the provider of the node it is read FROM, so the
// far node of every edge is of the near node's provider (a projector defect
// that wrote an executes_as across the providers is never walked), and the
// only edge whose two ends are of different providers is the crossing below.
//
// RESOLUTION AT READ TIME. Whether a principal IS a ServiceAccount of the
// workspace is computed inside the request's snapshot (loadCross), never
// stored: the Kubernetes rows arrive from a sweep, outside any AWS
// publication, so a stored resolution would be wrong between the two (or
// have to be written by the Kubernetes ingest into rows a publication owns).
// The rules are igagraph's (NormalizeOIDCIssuer, K8sServiceAccountSubject):
//
//	irsa_issuer_match           an `oidc` principal whose issuer equals,
//	                            scheme- and trailing-slash-insensitively, the
//	                            oidc_issuer of the newest PROJECTED sweep of
//	                            exactly one cluster (by name) of the
//	                            workspace, and whose subject
//	                            system:serviceaccount:<ns>:<sa> names a live
//	                            ServiceAccount of that cluster
//	pod_identity_cluster_match  a pod-identity principal whose association
//	                            (cloud_assume_edge) names exactly one cluster,
//	                            whose name exactly one Kubernetes source
//	                            sweeps (and whose sweep's issuer, when it
//	                            reported one, is the principal's), and whose
//	                            subject names a live ServiceAccount of it
//
// Anything ambiguous, wildcarded or absent is unresolved, as before. A STORED
// resolution (asserted, or any basis) wins: such a principal is not
// re-resolved here. AWS rows exist only in a publication (D-4), so without
// one nothing crosses.
//
// THE CROSSING EDGE is the principal's can_assume claim, drawn from the
// ServiceAccount the principal resolves to -- the principal and the
// ServiceAccount are one principal (§2.12) -- to the AWS role:
//
//	{claim: relationship:<can_assume>, kind: can_assume, from: <the SA>,
//	 to: <the AWS role>, crosses_provider: true,
//	 via_principal: external_principal:<the claim's declared source>,
//	 resolution: {basis: derived, rule: irsa_issuer_match | ...}}
//
// It is read from both ends: forward from a ServiceAccount (its resolved
// principals' can_assume edges, a crossing unit of the level) and in reverse
// from the role (the AWS can_assume row whose source is a resolved principal
// is re-pointed at the ServiceAccount, whose walk then continues on the
// Kubernetes side: the workloads that run as it). The principal node itself
// is then not part of the response. It stays a node, with the read-time
// resolution displayed and not walked, only where the request names it (a
// root or a /graph/path end): there its own edges keep their own source.
// can_assume counts as an assume hop, and every budget applies across it.
//
// An AWS-rooted walk that touches no resolved principal reads and renders
// exactly what it did before; the one extra statement it may issue (the sweep
// read, when a level meets an external principal) changes nothing it returns.

import (
	"sort"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/models"
)

// GraphMixed is meta.graph_state of a response holding nodes of both
// providers: the AWS publication it read is meta.rev, the Kubernetes rows are
// the snapshot's.
const GraphMixed = "mixed"

// graphCrossMatch is one resolved principal.
type graphCrossMatch struct {
	identity uuid.UUID // the Kubernetes ServiceAccount
	rule     string
}

// graphCross is the request's read-time resolutions: principal -> its
// ServiceAccount, and each ServiceAccount's principals (sorted).
type graphCross struct {
	byPrincipal map[uuid.UUID]graphCrossMatch
	byIdentity  map[uuid.UUID][]uuid.UUID
}

func (c *graphCross) match(principal uuid.UUID) (graphCrossMatch, bool) {
	if c == nil {
		return graphCrossMatch{}, false
	}
	m, ok := c.byPrincipal[principal]
	return m, ok
}

// side is the provider whose reads and decorations a node takes: Kubernetes
// for a Kubernetes node, AWS for everything else (an external principal is
// AWS's: principals are the AWS trust graph's).
func (n *GraphNode) side() string {
	if n.provider == models.ProviderK8s {
		return models.ProviderK8s
	}
	return models.ProviderAWS
}

// graphSideHasKind reports whether a provider's projection writes edges of a
// kind in a direction (the crossing aside, which is its own unit): AWS every
// kind; Kubernetes executes_as, grant and member_of (graphK8sEdgeKinds).
func graphSideHasKind(side, kind string) bool {
	return side != models.ProviderK8s || contains(graphK8sEdgeKinds, kind)
}

// graphSplitNodes splits nodes into AWS's (external principals included) and
// Kubernetes'.
func graphSplitNodes(nodes []*GraphNode) (aws, k8s []*GraphNode) {
	for _, n := range nodes {
		if n.side() == models.ProviderK8s {
			k8s = append(k8s, n)
		} else {
			aws = append(aws, n)
		}
	}
	return aws, k8s
}

// graphSplitEdges splits edges by the provider whose claim they are: a
// crossing edge is AWS's (the trust is the AWS projector's claim).
func graphSplitEdges(edges []*GraphEdge) (aws, k8s []*GraphEdge) {
	for _, e := range edges {
		if e.side == models.ProviderK8s {
			k8s = append(k8s, e)
		} else {
			aws = append(aws, e)
		}
	}
	return aws, k8s
}

// sides reports which providers the response's nodes are of.
func (t *graphTraversal) sides() (aws, k8s bool) {
	for _, n := range t.order {
		if n.side() == models.ProviderK8s {
			k8s = true
		} else {
			aws = true
		}
	}
	return aws, k8s
}

// held reports whether the traversal holds (or this level staged) a node.
func (t *graphTraversal) held(ref string, staged map[string]*GraphNode) bool {
	return t.nodes[ref] != nil || staged[ref] != nil
}

// crossPrincipals is the resolved principals of the given ServiceAccounts
// that the traversal does not hold (a held principal keeps its own edges),
// and which ServiceAccount each one is.
func (t *graphTraversal) crossPrincipals(sas []*GraphNode) []uuid.UUID {
	var out []uuid.UUID
	for _, n := range sas {
		for _, p := range t.cross.byIdentity[n.id] {
			if !t.held(R(RefExternalPrincipal, p), nil) {
				out = append(out, p)
			}
		}
	}
	return out
}

// crossAvailable reports whether a Kubernetes identity has a resolved
// principal (so can_assume is one of its forward kinds). Unknown -- the
// resolutions not read -- is false: they are read with every Kubernetes root.
func (t *graphTraversal) crossAvailable(id uuid.UUID) bool {
	return t.cross != nil && len(t.cross.byIdentity[id]) > 0
}

// graphCrossSweep is the newest projected sweep of one (source, cluster).
type graphCrossSweep struct {
	SourceID   uuid.UUID
	Cluster    string
	OIDCIssuer string `gorm:"column:oidc_issuer"`
}

// loadCross reads the request's read-time resolutions once, in its snapshot
// (see the file comment), each statement under the level's allowance.
func (t *graphTraversal) loadCross(lv *graphLevel) error {
	if t.cross != nil {
		return nil
	}
	c, err := readCross(lv.db, t.q.WS, t.q.Published())
	if err != nil {
		return err
	}
	t.cross = c
	return nil
}

// readCross reads a workspace's read-time cross-provider resolutions (see the
// file comment), each statement on the handle db returns. Nothing is read
// without an AWS publication (no AWS row exists, D-4), and nothing past the
// sweeps when no cluster was swept. The external principal detail route
// renders the same resolutions (GetExternalPrincipal), so the canvas and the
// detail panel agree.
func readCross(db func() (*gorm.DB, error), ws uuid.UUID, published bool) (*graphCross, error) {
	out := &graphCross{byPrincipal: map[uuid.UUID]graphCrossMatch{}, byIdentity: map[uuid.UUID][]uuid.UUID{}}
	if !published {
		return out, nil
	}
	tx, err := db()
	if err != nil {
		return nil, err
	}
	var sweeps []graphCrossSweep
	if err := tx.Raw(`SELECT DISTINCT ON (discovery_source_id, cluster)
	                         discovery_source_id AS source_id, cluster, oidc_issuer
	                    FROM iga_k8s_sweep
	                   WHERE workspace_id = ? AND status = ?
	                   ORDER BY discovery_source_id, cluster, generation DESC`,
		ws, models.K8sSweepProjected).Scan(&sweeps).Error; err != nil {
		return nil, err
	}
	if len(sweeps) == 0 {
		return out, nil
	}
	clustersOfIssuer := map[string]map[string]bool{}
	sweepsNamed := map[string][]graphCrossSweep{}
	for _, s := range sweeps {
		sweepsNamed[s.Cluster] = append(sweepsNamed[s.Cluster], s)
		if iss := igagraph.NormalizeOIDCIssuer(s.OIDCIssuer); iss != "" {
			if clustersOfIssuer[iss] == nil {
				clustersOfIssuer[iss] = map[string]bool{}
			}
			clustersOfIssuer[iss][s.Cluster] = true
		}
	}

	if tx, err = db(); err != nil {
		return nil, err
	}
	var principals []struct {
		ID           uuid.UUID
		Issuer       string
		SubjectClaim string
		Mechanism    string
	}
	if err := tx.Raw(`SELECT ep.id, ep.issuer, ep.subject_claim, ep.mechanism
	                    FROM iga_external_principal ep
	                   WHERE ep.workspace_id = ? AND ep.resolution_basis = '' AND ep.mechanism IN ?
	                   ORDER BY ep.id`,
		ws, []string{models.ExternalPrincipalOIDC, models.ExternalPrincipalK8sServiceAccount}).Scan(&principals).Error; err != nil {
		return nil, err
	}
	type candidate struct {
		principal uuid.UUID
		key, rule string
	}
	var cands []candidate
	type podKey struct{ issuer, ref string }
	type pod struct {
		principal uuid.UUID
		ns, sa    string
		at        podKey
	}
	var pods []pod
	var podRefs []string
	for _, p := range principals {
		ns, sa, ok := igagraph.K8sServiceAccountSubject(p.Mechanism, p.SubjectClaim)
		if !ok {
			continue
		}
		iss := igagraph.NormalizeOIDCIssuer(p.Issuer)
		if iss == "" {
			continue
		}
		switch p.Mechanism {
		case models.ExternalPrincipalOIDC:
			names := clustersOfIssuer[iss]
			if len(names) != 1 {
				continue // no cluster reported this issuer, or more than one did
			}
			for cluster := range names {
				cands = append(cands, candidate{p.ID, k8sgraph.ServiceAccountKey(cluster, ns, sa), igagraph.ResolutionRuleIRSAIssuerMatch})
			}
		case models.ExternalPrincipalK8sServiceAccount:
			ref := "system:serviceaccount:" + ns + ":" + sa
			pods = append(pods, pod{principal: p.ID, ns: ns, sa: sa, at: podKey{iss, ref}})
			podRefs = append(podRefs, ref)
		}
	}
	if len(pods) > 0 {
		if tx, err = db(); err != nil {
			return nil, err
		}
		var assoc []struct {
			Issuer      string
			K8sRef      string
			ClusterName string
		}
		if err := tx.Raw(`SELECT DISTINCT COALESCE(issuer, '') AS issuer, k8s_ref,
		                         COALESCE(attrs->>'cluster_name', '') AS cluster_name
		                    FROM cloud_assume_edge
		                   WHERE workspace_id = ? AND mechanism = ? AND k8s_ref IN ?`,
			ws, models.AssumeMechanismEKSPodIdentity, podRefs).Scan(&assoc).Error; err != nil {
			return nil, err
		}
		named := map[podKey]map[string]bool{}
		for _, a := range assoc {
			k := podKey{igagraph.NormalizeOIDCIssuer(a.Issuer), a.K8sRef}
			if named[k] == nil {
				named[k] = map[string]bool{}
			}
			named[k][a.ClusterName] = true
		}
		for _, p := range pods {
			names := named[p.at]
			if len(names) != 1 {
				continue // no association read, or it names several clusters
			}
			var cluster string
			for c := range names {
				cluster = c
			}
			sws := sweepsNamed[cluster]
			if cluster == "" || len(sws) != 1 {
				continue // not swept, or two sources sweep a cluster of that name
			}
			if iss := igagraph.NormalizeOIDCIssuer(sws[0].OIDCIssuer); iss != "" && iss != p.at.issuer {
				continue // the agent says that cluster has another issuer
			}
			cands = append(cands, candidate{p.principal, k8sgraph.ServiceAccountKey(cluster, p.ns, p.sa), igagraph.ResolutionRulePodIdentityCluster})
		}
	}
	if len(cands) == 0 {
		return out, nil
	}
	keys := make([]string, 0, len(cands))
	seen := map[string]bool{}
	for _, c := range cands {
		if !seen[c.key] {
			seen[c.key] = true
			keys = append(keys, c.key)
		}
	}
	if tx, err = db(); err != nil {
		return nil, err
	}
	var sas []struct {
		ID        uuid.UUID
		SourceKey string
	}
	if err := tx.Raw(`SELECT ia.id, ia.source_key FROM iga_identity_accounts ia
	                   WHERE ia.workspace_id = ? AND ia.provider = 'k8s' AND ia.account_kind = ?
	                     AND ia.lifecycle = ? AND ia.source_key IN ? AND `+SupportedSQL("ia", "identity_account_id"),
		ws, models.K8sAccountKindServiceAccount, models.IGALifecycleActive, keys).Scan(&sas).Error; err != nil {
		return nil, err
	}
	byKey := map[string][]uuid.UUID{}
	for _, s := range sas {
		byKey[s.SourceKey] = append(byKey[s.SourceKey], s.ID)
	}
	for _, c := range cands {
		ids := byKey[c.key]
		if len(ids) != 1 {
			continue // not a live ServiceAccount of that cluster
		}
		out.byPrincipal[c.principal] = graphCrossMatch{identity: ids[0], rule: c.rule}
		out.byIdentity[ids[0]] = append(out.byIdentity[ids[0]], c.principal)
	}
	for id := range out.byIdentity {
		ps := out.byIdentity[id]
		sort.Slice(ps, func(i, j int) bool { return ps[i].String() < ps[j].String() })
	}
	return out, nil
}

// crossResolution is the read-time resolution an external principal node
// displays (D-87's shape): in force, derived, by its rule.
func crossResolution(m graphCrossMatch) map[string]any {
	return map[string]any{
		"state": graphResolutionActive, "basis": models.BasisDerived, "rule": m.rule,
		"resolved_to": R(RefIdentity, m.identity), "resolved_by": nil,
	}
}

// crossDetailResolution is crossResolution for the external principal detail
// route's shape (ExternalResolution).
func crossDetailResolution(m graphCrossMatch) *ExternalResolution {
	rule := m.rule
	return &ExternalResolution{State: graphResolutionActive, Basis: models.BasisDerived, Rule: &rule,
		ResolvedTo: R(RefIdentity, m.identity)}
}

// markCrossing makes an edge the crossing (see the file comment).
func markCrossing(e *GraphEdge, principal uuid.UUID, m graphCrossMatch) {
	e.CrossesProvider = true
	e.ViaPrincipal = R(RefExternalPrincipal, principal)
	e.Resolution = map[string]any{"basis": models.BasisDerived, "rule": m.rule}
}
