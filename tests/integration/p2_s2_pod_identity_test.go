package integration

// T2.1 x EKS Pod Identity (SPEC-iga-phase2-graph.md §2.14.13 l.1856-1859; E9
// "anything unreadable ends" is the failure): a region deselected through
// PATCH .../connectors/:id is no longer read, and the Pod Identity bindings
// found there must be KEPT and marked stale -- never deleted as gone, never
// confirmed -- while a binding that vanished from a region the scan DID read
// is still removed. eks_pod_identity is ONE connector-wide surface, so before
// this the scan read the remaining regions, called the surface reached, and
// reconciliation deleted every binding of the deselected region.

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

func TestP2S2DeselectedRegionKeepsPodIdentityBindings(t *testing.T) {
	l := newP2Lab(t, "p2-s2-pod-deselect", true)
	a := l.account(accountA, "us-east-1", "ap-south-2")
	role := a.role("pod-role", "AROAS2PODIDENTITYXXXX")
	// The role is also trusted by another account: a TRUST-POLICY edge, not a
	// Pod Identity one, that is removed while a region is deselected -- and
	// must still be deleted: a deselected region vouches only for what lives
	// in it.
	s2SetTrust(a, "pod-role", s2TrustTwoPrincipals)
	a.svc.WithRegionsAPI(s2Regions("us-east-1", "ap-south-2"))
	api := s2DiscoveryAPI(t, l, a.svc)
	read := l.api()

	// Pod Identity-only clusters: no OIDC issuer, so the region an edge
	// RECORDS is the only evidence of where it lives.
	east := s2PodCluster("east-cluster", role, "east-agent", "east-gone")
	hyd := s2PodCluster("hyd-cluster", role, "hyd-agent")
	regional := map[string]*fakeEKS{"us-east-1": east, "ap-south-2": hyd}
	scan := func(owner string) models.CloudScanRun {
		t.Helper()
		run := s2ScanWith(l, a, owner, func(_ *services.AWSIAMScanner, p *services.AWSPermissionScanner, _ *services.AWSWorkloadScanner) {
			p.WithRegionalEKSAPI(func(region string) awsdiscovery.EKSAPI {
				if f := regional[region]; f != nil {
					return f
				}
				return newFakeEKS()
			})
		})
		if run.Status != models.CloudScanRunPublished {
			t.Fatalf("%s: run %s (%s), want published", owner, run.Status, run.LastError)
		}
		l.project("projector-" + owner)
		return run
	}

	run1 := scan("s2-pod-1")
	edges := s2PodEdges(t, l, a.conn)
	for sa, region := range map[string]string{"east-agent": "us-east-1", "east-gone": "us-east-1", "hyd-agent": "ap-south-2"} {
		if e, ok := edges[sa]; !ok || e.Region != region || e.Generation != run1.Generation {
			t.Fatalf("setup: %s = %+v (present %v), want recorded in %s at generation %d", sa, e, ok, region, run1.Generation)
		}
	}
	if cov := s2Coverage(run1).Surfaces[models.SurfaceEKSPodIdentity]; cov.State != models.CloudCoverageReached || cov.Count != 3 {
		t.Fatalf("setup: eks_pod_identity = %+v, want reached, 3", cov)
	}

	// A binding with NO region evidence -- written before regions were
	// recorded, from a cluster whose issuer names none -- that the next scan
	// does not see. No region was ever deselected, so every region it could
	// live in was read: it is gone.
	s2InsertPodEdge(t, l, a, role, "ghost", nil, run1.Generation)
	run2 := scan("s2-pod-2")
	if _, ok := s2PodEdges(t, l, a.conn)["ghost"]; ok {
		t.Fatalf("an unseen binding of unknown region survived a scan that read every region ever selected")
	}
	if cov := s2Coverage(run2).Surfaces[models.SurfaceEKSPodIdentity]; cov.State != models.CloudCoverageReached {
		t.Fatalf("eks_pod_identity with every region read = %+v, want reached", cov)
	}

	// The same unknown-region binding again, and one whose region only its
	// issuer names (a row from before regions were recorded, in a region
	// that stays selected).
	s2InsertPodEdge(t, l, a, role, "ghost", nil, run2.Generation)
	s2InsertPodEdge(t, l, a, role, "east-legacy", aws.String("oidc.eks.us-east-1.amazonaws.com/id/S2EASTLEGACY"), run2.Generation)

	// DESELECT ap-south-2; in the same interval east-gone is removed from the
	// region that stays selected.
	code, body := api.patchRegions(a.conn, "us-east-1")
	mustStatus(t, "deselect ap-south-2", code, body, http.StatusOK)
	if c := s2Connector(t, l, a.conn); !reflect.DeepEqual(c.RegionsEverSelected, []string{"ap-south-2", "us-east-1"}) ||
		!reflect.DeepEqual(c.DeselectedRegions(), []string{"ap-south-2"}) {
		t.Fatalf("selection history after the PATCH = %v (deselected %v), want [ap-south-2 us-east-1] / [ap-south-2]",
			c.RegionsEverSelected, c.DeselectedRegions())
	}
	east.associations["east-cluster"] = east.associations["east-cluster"][:1]
	if n := s2TrustEdges(t, l, a.conn, s2OtherAccount); n != 1 {
		t.Fatalf("setup: %d trust edges for %s, want 1", n, s2OtherAccount)
	}
	s2SetTrust(a, "pod-role", lambdaTrust)

	run3 := scan("s2-pod-3")
	edges = s2PodEdges(t, l, a.conn)
	// KEPT, not confirmed: the binding of the region nobody read stays at the
	// generation it was last seen at, and so does the one of unknown region
	// (it may live in ap-south-2).
	if e, ok := edges["hyd-agent"]; !ok || e.Generation != run2.Generation {
		t.Fatalf("hyd-agent after ap-south-2 was deselected = %+v (present %v): a binding nobody read was deleted or re-confirmed", e, ok)
	}
	if e, ok := edges["ghost"]; !ok || e.Generation != run2.Generation {
		t.Fatalf("a binding of unknown region after a deselection = %+v (present %v), want kept at generation %d", e, ok, run2.Generation)
	}
	// GONE: bindings of a region this scan read, whether the region was
	// recorded on the row or only named by its cluster's issuer.
	for _, sa := range []string{"east-gone", "east-legacy"} {
		if e, ok := edges[sa]; ok {
			t.Fatalf("%s vanished from us-east-1, which was read, and survived: %+v", sa, e)
		}
	}
	if e := edges["east-agent"]; e.Generation != run3.Generation {
		t.Fatalf("east-agent = %+v, want confirmed at generation %d", e, run3.Generation)
	}
	if n := s2TrustEdges(t, l, a.conn, s2OtherAccount); n != 0 {
		t.Fatalf("a trust principal removed from the policy survived the scan (%d edges): only Pod Identity bindings live in regions", n)
	}
	cov := s2Coverage(run3).Surfaces[models.SurfaceEKSPodIdentity]
	if cov.State != models.CloudCoverageNotSelected || cov.Count != 1 ||
		!strings.Contains(cov.Error, "ap-south-2") || !strings.Contains(cov.Error, "a region not recorded") ||
		!strings.Contains(cov.Error, "2 EKS Pod Identity binding(s)") {
		t.Fatalf("eks_pod_identity after the deselection = %+v, want not_selected naming ap-south-2 and the unrecorded one, 2 kept", cov)
	}

	// THE GRAPH CANNOT END THEM EITHER: the pod-identity partition of this
	// run's snapshot is vetoed (canEnd requires eks_pod_identity reached),
	// while the trust partition beside it may still close.
	s2AssertCanEnd(t, l, run3, models.MechanismEKSPodIdentity, false)
	s2AssertCanEnd(t, l, run3, "trust", true)

	// /coverage states it, with the one fix the evidence supports.
	pod := s2Surface(t, s2CoverageAccount(t, read, "", a), models.SurfaceEKSPodIdentity)
	if digs(pod, "state") != models.CloudCoverageNotSelected || digs(pod, "fix") != "change_regions" ||
		digs(pod, "prevents") != "surface_stale" || dig(pod, "count") != nil {
		t.Fatalf("/coverage eks_pod_identity = %v, want not_selected, change_regions, surface_stale", pod)
	}

	// Still deselected on the next scan: still kept, still not reached.
	run4 := scan("s2-pod-4")
	edges = s2PodEdges(t, l, a.conn)
	if edges["hyd-agent"].Generation != run2.Generation || edges["ghost"].Generation != run2.Generation {
		t.Fatalf("a second scan with ap-south-2 deselected: hyd-agent %+v, ghost %+v, want both kept", edges["hyd-agent"], edges["ghost"])
	}
	if st := s2Coverage(run4).Surfaces[models.SurfaceEKSPodIdentity].State; st != models.CloudCoverageNotSelected {
		t.Fatalf("eks_pod_identity on the second deselected scan = %q, want not_selected", st)
	}

	// And when the read of a SELECTED region fails meanwhile, the failure is
	// what the surface says -- never masked as not_selected, which would
	// offer "change regions" for a refusal -- and nothing is reconciled.
	east.fail["ListClusters"] = denied("eks:ListClusters")
	run4b := scan("s2-pod-4b")
	if st := s2Coverage(run4b).Surfaces[models.SurfaceEKSPodIdentity].State; st != models.CloudCoverageDenied {
		t.Fatalf("eks_pod_identity with us-east-1 refused and ap-south-2 deselected = %q, want denied", st)
	}
	if e, ok := s2PodEdges(t, l, a.conn)["east-agent"]; !ok || e.Generation != run4.Generation {
		t.Fatalf("east-agent after a refused read = %+v (present %v), want kept at %d", e, ok, run4.Generation)
	}
	delete(east.fail, "ListClusters")

	// RESELECTED: the region is read again. Its binding is confirmed, and the
	// unknown-region one -- no region is deselected any more, so every region
	// it could live in was read -- is gone.
	code, body = api.patchRegions(a.conn, "us-east-1", "ap-south-2")
	mustStatus(t, "reselect ap-south-2", code, body, http.StatusOK)
	run5 := scan("s2-pod-5")
	edges = s2PodEdges(t, l, a.conn)
	if e := edges["hyd-agent"]; e.Generation != run5.Generation || e.Region != "ap-south-2" {
		t.Fatalf("hyd-agent after reselection = %+v, want confirmed at %d in ap-south-2", e, run5.Generation)
	}
	if _, ok := edges["ghost"]; ok {
		t.Fatalf("the unknown-region binding survived a scan of every region ever selected")
	}
	if st := s2Coverage(run5).Surfaces[models.SurfaceEKSPodIdentity].State; st != models.CloudCoverageReached {
		t.Fatalf("eks_pod_identity after reselection = %q, want reached", st)
	}
	s2AssertCanEnd(t, l, run5, models.MechanismEKSPodIdentity, true)

	// Kept is not immortal: removed from a region that is read, it goes.
	hyd.associations["hyd-cluster"] = nil
	scan("s2-pod-6")
	if e, ok := s2PodEdges(t, l, a.conn)["hyd-agent"]; ok {
		t.Fatalf("hyd-agent, removed from a selected region, survived: %+v", e)
	}
}

/* --------------------------------- helpers -------------------------------- */

// s2OtherAccount is an account the pod role's trust policy names besides
// Lambda.
const s2OtherAccount = "111122223333"

var s2TrustTwoPrincipals = `{"Version":"2012-10-17","Statement":[` +
	`{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"},` +
	`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + s2OtherAccount + `:root"},"Action":"sts:AssumeRole"}]}`

// s2SetTrust replaces a role's trust policy in the account's IAM fake.
func s2SetTrust(a *p2Account, roleName, doc string) {
	for i := range a.iam.roles {
		if aws.ToString(a.iam.roles[i].RoleName) == roleName {
			a.iam.roles[i].AssumeRolePolicyDocument = aws.String(url.QueryEscape(doc))
			return
		}
	}
	panic("no role " + roleName)
}

// s2TrustEdges counts the connector's trust-policy edges naming the account.
func s2TrustEdges(t *testing.T, l *p2Lab, conn uuid.UUID, account string) int64 {
	t.Helper()
	return l.count(`SELECT count(*) FROM cloud_assume_edge
	                 WHERE workspace_id = ? AND connector_id = ? AND mechanism <> ? AND subject LIKE ?`,
		l.ws, conn, models.AssumeMechanismEKSPodIdentity, "%"+account+"%")
}

// s2PodCluster is an EKS fake with one Pod Identity-only cluster (no OIDC
// issuer) whose associations bind payments/<sa> to roleARN.
func s2PodCluster(cluster, roleARN string, serviceAccounts ...string) *fakeEKS {
	f := newFakeEKS()
	f.clusters[cluster] = ""
	for i, sa := range serviceAccounts {
		id := cluster + "-a-" + string(rune('0'+i))
		f.associations[cluster] = append(f.associations[cluster], ekstypes.PodIdentityAssociation{
			AssociationId:  aws.String(id),
			AssociationArn: aws.String("arn:aws:eks:us-east-1:" + accountA + ":podidentityassociation/" + cluster + "/" + id),
			ClusterName:    aws.String(cluster),
			Namespace:      aws.String("payments"),
			ServiceAccount: aws.String(sa),
			RoleArn:        aws.String(roleARN),
		})
	}
	return f
}

// s2PodEdge is one Pod Identity cloud_assume_edge row.
type s2PodEdge struct {
	Generation int
	Region     string
}

// s2PodEdges lists the connector's Pod Identity edges by service account name.
func s2PodEdges(t *testing.T, l *p2Lab, conn uuid.UUID) map[string]s2PodEdge {
	t.Helper()
	var rows []struct {
		Subject            string
		LastSeenGeneration int
		Region             *string
	}
	if err := l.db.Raw(`SELECT subject, last_seen_generation, attrs->>'region' AS region
	                      FROM cloud_assume_edge
	                     WHERE workspace_id = ? AND connector_id = ? AND mechanism = ?`,
		l.ws, conn, models.AssumeMechanismEKSPodIdentity).Scan(&rows).Error; err != nil {
		t.Fatalf("read pod identity edges: %v", err)
	}
	out := map[string]s2PodEdge{}
	for _, r := range rows {
		sa := r.Subject[strings.LastIndex(r.Subject, ":")+1:]
		e := s2PodEdge{Generation: r.LastSeenGeneration}
		if r.Region != nil {
			e.Region = *r.Region
		}
		out[sa] = e
	}
	return out
}

// s2InsertPodEdge writes a Pod Identity edge the way a scan from before
// regions were recorded left it: attrs {}, the cluster's issuer or none.
func s2InsertPodEdge(t *testing.T, l *p2Lab, a *p2Account, roleARN, sa string, issuer *string, generation int) {
	t.Helper()
	var ci models.CloudIdentity
	if err := l.db.Select("id").First(&ci, "workspace_id = ? AND native_id = ?", l.ws, roleARN).Error; err != nil {
		t.Fatalf("role %s: %v", roleARN, err)
	}
	identity := ci.ID
	subject := awsdiscovery.K8sSubject("legacy", sa)
	if err := l.db.Exec(`INSERT INTO cloud_assume_edge
	        (workspace_id, connector_id, identity_id, subject_kind, subject, issuer, mechanism, k8s_ref, attrs, last_seen_generation)
	        VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}', ?)`,
		l.ws, a.conn, identity, models.AssumeSubjectK8sSA, subject, issuer,
		models.AssumeMechanismEKSPodIdentity, subject, generation).Error; err != nil {
		t.Fatalf("insert legacy pod identity edge %s: %v", sa, err)
	}
}

// s2Connector reads a connector's AWS attrs.
func s2Connector(t *testing.T, l *p2Lab, conn uuid.UUID) models.AWSConnectorAttrs {
	t.Helper()
	var c models.CloudConnector
	if err := l.db.First(&c, "id = ?", conn).Error; err != nil {
		t.Fatalf("read connector: %v", err)
	}
	return c.AWSAttrs()
}

// s2AssertCanEnd loads the run's snapshot the way the projector does and
// asserts whether its can_assume partition of the given kind may end what the
// run did not see.
func s2AssertCanEnd(t *testing.T, l *p2Lab, run models.CloudScanRun, kind string, want bool) {
	t.Helper()
	snap, err := igagraph.Load(context.Background(), l.db, run.ID)
	if err != nil {
		t.Fatalf("load run %s: %v", run.ID, err)
	}
	for _, p := range igagraph.Partitions(snap) {
		if p.RelationshipType == models.RelTypeCanAssume && p.Kind == kind {
			if got := igagraph.NewReconciler(nil).CanEnd(snap, p); got != want {
				t.Fatalf("canEnd(can_assume %s) on run %s = %v, want %v (coverage %v)", kind, run.ID, got, want, snap.Coverage[models.SurfaceEKSPodIdentity])
			}
			return
		}
	}
	t.Fatalf("no can_assume %s partition in run %s", kind, run.ID)
}
