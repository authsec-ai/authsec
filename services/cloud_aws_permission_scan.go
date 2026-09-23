package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Ticket [2]: trust-policy parsing and permission/resource extraction.
//
// This scanner does not read IAM roles, users or policy documents on its own
// -- AWSIAMScanner (ticket [1]) already did, and handed the result over as an
// IAMSnapshot rather than this file re-fetching it. The only AWS call made
// directly here is ListOpenIDConnectProviders, which ticket [1] has no reason
// to know about.
//
// Writes cloud_assume_edge, cloud_permission and cloud_resource, stamped with
// the SAME generation as the IAMSnapshot it was given. One scan run, one
// generation, across every table the run touches -- running this under its own
// generation would let reconciliation age out identities and their
// permissions on different schedules, which is the inconsistency the shared
// generation exists to prevent.
type AWSPermissionScanner struct {
	db         *gorm.DB
	identities repositories.CloudIdentityRepository
	grants     repositories.CloudPermissionRepository
	onboarding *AWSOnboardingService

	// policies writes policies as objects, with their attachments (035). The
	// projector reads THESE; cloud_permission keeps being written from the
	// same parse, for Cloud Inventory, and the projector does not read it.
	policies repositories.CloudPolicyRepository

	// api, when set, replaces the real IAM client -- the same test seam
	// AWSIAMScanner uses.
	api awsdiscovery.IAMAPI

	// eksAPI, when set, replaces the real EKS client for every region. EKS is
	// regional and the live path builds one client per selected region; a test
	// double stands in for all of them.
	eksAPI awsdiscovery.EKSAPI
	// regionalEKS, when set, returns the EKS client for ONE region and wins
	// over eksAPI: one double for every region cannot express "EKS is not
	// offered in this region, and is read in that one" (T3.8), nor "this
	// binding lives in ap-south-2 only", which a region deselection must be
	// tested with (T2.1).
	regionalEKS func(region string) awsdiscovery.EKSAPI

	// s3API/kmsAPI, when set, replace the real resource-policy clients.
	s3API  awsdiscovery.S3PolicyAPI
	kmsAPI awsdiscovery.KMSPolicyAPI

	// evidence records why each permission and resource row exists. Nil writes
	// nothing.
	evidence *ObservationWriter
}

// WithEvidence attaches an observation writer for this run.
func (s *AWSPermissionScanner) WithEvidence(w *ObservationWriter) *AWSPermissionScanner {
	s.evidence = w
	return s
}

// WithFence fences the grant writes (assume edges, resources, permissions)
// so a superseded worker cannot land them (§2.10A, part 3).
func (s *AWSPermissionScanner) WithFence(f repositories.ScanFence) *AWSPermissionScanner {
	s.grants = s.grants.Fenced(f)
	s.policies = s.policies.Fenced(f)
	return s
}

// NewAWSPermissionScanner constructs the scanner.
func NewAWSPermissionScanner(db *gorm.DB, onboarding *AWSOnboardingService) *AWSPermissionScanner {
	return &AWSPermissionScanner{
		db:         db,
		identities: repositories.NewCloudIdentityRepository(db),
		grants:     repositories.NewCloudPermissionRepository(db),
		policies:   repositories.NewCloudPolicyRepository(db),
		onboarding: onboarding,
	}
}

// WithIAMAPI installs a specific IAM client, bypassing assume-role.
func (s *AWSPermissionScanner) WithIAMAPI(api awsdiscovery.IAMAPI) *AWSPermissionScanner {
	s.api = api
	return s
}

// WithEKSAPI installs a specific EKS client for every region, bypassing
// assume-role.
func (s *AWSPermissionScanner) WithEKSAPI(api awsdiscovery.EKSAPI) *AWSPermissionScanner {
	s.eksAPI = api
	return s
}

// WithRegionalEKSAPI installs a per-region EKS client, bypassing assume-role;
// it wins over WithEKSAPI. A test seam.
func (s *AWSPermissionScanner) WithRegionalEKSAPI(f func(region string) awsdiscovery.EKSAPI) *AWSPermissionScanner {
	s.regionalEKS = f
	return s
}

// WithResourcePolicyAPIs installs the S3 and KMS clients used to read
// resource-based policies, bypassing assume-role. Either may be nil.
func (s *AWSPermissionScanner) WithResourcePolicyAPIs(
	s3api awsdiscovery.S3PolicyAPI, kmsapi awsdiscovery.KMSPolicyAPI,
) *AWSPermissionScanner {
	s.s3API, s.kmsAPI = s3api, kmsapi
	return s
}

// PermissionSnapshot is what one permission scan wrote.
type PermissionSnapshot struct {
	ConnectorID        uuid.UUID
	Generation         int
	EdgesWritten       int
	PermissionsWritten int
	ResourcesWritten   int
	// ParseFailures counts policy documents that could not be read at all.
	// Non-zero means this identity's permissions are INCOMPLETE, and coverage
	// must say so rather than reporting the statements that happened to parse.
	ParseFailures int
	// StatementsSkipped counts statements dropped for having no Effect, or
	// neither Action nor NotAction. Surfaced so a silent skip is countable.
	StatementsSkipped int
	// PoliciesWritten counts cloud_policy rows this run recorded (035): each
	// managed policy once, however many principals attach it, plus each
	// inline policy.
	PoliciesWritten int
	// UnreadableDocuments names each document -- policy or role trust policy
	// -- that could not be fetched or parsed this run, with the reason,
	// reported under policy_documents so coverage says WHICH document, not only
	// that one failed (§1.4, T3.3): as items (D-71) and in the prose.
	// Deduplicated, in the order the scan met them.
	UnreadableDocuments []models.CoverageItem
	unreadableSeen      map[models.CoverageItem]bool
	// policyHoldersMissing counts principals whose policies could not be
	// written because their identity row was not found. Their attachments
	// were not re-stamped this run, so cloud_policy reconciliation must not
	// run over them.
	policyHoldersMissing int
	// OIDCProviders is the account's registered providers. Returned rather than
	// only persisted so a caller resolving a cluster by issuer is not forced to
	// make this same call again for data this scan already read.
	OIDCProviders []awsdiscovery.OIDCProvider

	// PodIdentityEdges counts the cloud_assume_edge rows written from EKS Pod
	// Identity associations, as opposed to from trust policies. Reported
	// separately because zero here on an account that has clusters is a
	// meaningful signal, while zero trust-policy edges is not.
	PodIdentityEdges int
	// Complete mirrors the identity scan's own coverage: this ticket cannot be
	// more complete than the data ticket [1] handed it, and OIDC providers
	// being unreadable also marks it incomplete.
	Complete bool
	// Surfaces reports this scan's own two independently-callable surfaces
	// (OIDC providers, EKS Pod Identity), for the caller to fold into the
	// connector's overall coverage report. Trust-policy and policy-document
	// parsing are not surfaces here — see the comment on the Surface constants.
	Surfaces map[string]models.SurfaceCoverage
	// Skipped counts trust policies or policy documents whose identity could
	// not be found by native id. Should be zero in practice -- ticket [1] wrote
	// every identity these ARNs came from moments earlier -- and is surfaced
	// rather than silently dropped in case it is ever not.
	Skipped int

	// resourcePolicyCandidates is every S3 bucket / KMS key this scan named,
	// collected while writing permissions and checked afterward in
	// scanResourcePolicies. Deferred rather than checked inline in
	// getOrCreateResource: that call has no context to make an AWS request
	// with, and threading one through four call sites just for this is a
	// larger change than a second pass over a short, already-deduplicated list.
	resourcePolicyCandidates []resourcePolicyCandidate
}

// resourcePolicyCandidate is one resource discovered while writing
// permissions, worth checking for a resource-based policy afterward.
type resourcePolicyCandidate struct {
	ResourceID uuid.UUID
	Kind       string
	NativeID   string
	// Name is the bucket name for an s3_bucket candidate -- GetBucketPolicy
	// takes a bucket name, not the ARN NativeID carries. Unused for kms_key,
	// where GetKeyPolicy accepts the ARN directly.
	Name string
}

// ScanFromSnapshot parses the trust policies and policy documents an
// AWSIAMScanner run already fetched, and separately lists the account's OIDC
// providers.
//
// Takes an IAMSnapshot rather than a connector id because this is deliberately
// the second half of one logical scan: its identity foreign keys only exist
// because the snapshot's own scan just wrote them, and it must never advance
// or invent its own generation.
func (s *AWSPermissionScanner) ScanFromSnapshot(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot,
) (*PermissionSnapshot, error) {
	if snapshot == nil {
		return nil, errors.New("permission scan needs an IAM snapshot to parse")
	}

	reader, err := s.readerFor(ctx, workspaceID, snapshot.ConnectorID)
	if err != nil {
		return nil, err
	}

	out := &PermissionSnapshot{ConnectorID: snapshot.ConnectorID, Generation: snapshot.Generation}

	providers, oidcErr := reader.OIDCProviders(ctx)
	out.OIDCProviders = providers

	// Roles whose trust documents are unreadable (the IAM scan judged them and
	// stored the reason on each row) are named under policy_documents too:
	// "names the documents" (T3.3) covers both kinds.
	for _, item := range snapshot.UnreadableTrust {
		out.noteUnreadableItem(item)
	}
	if err := s.writeAssumeEdges(workspaceID, snapshot, out); err != nil {
		return out, err
	}
	if err := s.writePermissions(workspaceID, snapshot, out); err != nil {
		return out, err
	}

	// EKS Pod Identity edges. Errors are collected rather than raised: a
	// customer whose role does not cover EKS, or who runs no clusters, must
	// still get a successful permission scan.
	eksErr := s.writePodIdentityEdges(ctx, workspaceID, snapshot, out)

	// This ticket's own completeness is bounded by three independent signals:
	// ticket [1]'s scan must have reached everything (an incomplete IAM read
	// means an incomplete set of trust policies and statements to parse), the
	// OIDC provider read must have succeeded, and the EKS read must have
	// succeeded.
	//
	// EKS gates it for the same reason as the others, and it matters more here:
	// reconciliation below deletes edges from older generations, so an EKS read
	// that was denied would let this scan conclude that every Pod Identity
	// binding it could not see had been removed.
	// A document this run could not parse is a document this run did not read.
	// Reconciliation below deletes rows from older generations, so letting a
	// parse failure pass as complete would delete the trust edges and grants we
	// merely failed to understand today -- turning a transient malformed
	// document into permanent data loss. This is the same rule the coverage
	// states encode: could-not-look is never the same as gone.
	// A statement we could not use is a statement we did not read, exactly like
	// a document we could not parse. Both leave a row from the previous
	// generation unrefreshed, and reconciliation below deletes exactly those.
	//
	// So a statement that loses its Effect in AWS -- or any other shape this
	// parser cannot represent -- must not be able to delete the permission it
	// previously produced. Skipped and failed are counted separately because
	// they say different things to an operator, but either one makes this run
	// non-authoritative.
	// A document that could not be FETCHED is a document this run did not
	// read, exactly like one that did not parse: per-document isolation lets
	// the scan continue past it, but must not let reconciliation delete what
	// the unread document declared last time.
	out.Complete = snapshot.Coverage.Complete() &&
		oidcErr == nil && eksErr == nil &&
		out.ParseFailures == 0 && out.StatementsSkipped == 0 &&
		len(out.UnreadableDocuments) == 0
	out.Surfaces = map[string]models.SurfaceCoverage{
		models.SurfaceOIDCProviders:  surfaceResult(len(providers), oidcErr),
		models.SurfaceEKSPodIdentity: podIdentityCoverage(out.PodIdentityEdges, eksErr),
	}

	// Pod Identity bindings in regions this run did NOT read -- deselected
	// since an earlier scan found them (PATCH .../connectors/:id). A region
	// change applies from the next scan, and the scan after it must neither
	// delete nor confirm what it never looked at: the rows are exempted from
	// reconciliation below and the surface is not_selected, not reached, so
	// the pod-identity partition cannot end them either (canEnd requires
	// eks_pod_identity reached) -- they are kept and marked stale (§2.14.13
	// l.1856-1859). Only when the EKS read itself succeeded: a failed read
	// already reports its own state and reconciles nothing.
	var keepEdges []uuid.UUID
	if eksErr == nil {
		kept, regions, err := s.unreadPodIdentityEdges(workspaceID, snapshot)
		if err != nil {
			return out, err
		}
		if len(kept) > 0 {
			keepEdges = kept
			out.Surfaces[models.SurfaceEKSPodIdentity] = models.SurfaceCoverage{
				State: models.CloudCoverageNotSelected,
				Count: out.PodIdentityEdges,
				Error: fmt.Sprintf("not read in %s (no longer in the connector's selected scope): "+
					"%d EKS Pod Identity binding(s) found there earlier are kept, not confirmed",
					strings.Join(regions, ", "), len(kept)),
			}
		}
	}
	if len(out.UnreadableDocuments) > 0 || out.ParseFailures > 0 || out.StatementsSkipped > 0 {
		out.Surfaces[models.SurfacePolicyDocuments] = policyDocumentsSurface(out, len(snapshot.TrustPolicies))
	}

	// Resource-based policies for the S3 buckets and KMS keys writePermissions
	// named above. Placed after out.Complete is already decided, and reported
	// through out.Surfaces rather than any of the named booleans that formula
	// checks -- see resourcePolicyCandidates' doc comment: this is bonus
	// evidence about resources this scan already wrote, with no reconciled
	// table of its own, and a customer whose deployed role predates
	// s3:GetBucketPolicy/kms:GetKeyPolicy must not have an otherwise-complete
	// permission scan refuse to reconcile edges and grants over it.
	resourcePolicyCount, resourcePolicyErr := s.scanResourcePolicies(ctx, workspaceID, snapshot.ConnectorID, out)
	out.Surfaces[models.SurfaceResourcePolicies] = resourcePolicyCoverage(resourcePolicyCount, resourcePolicyErr) // D-93

	if out.Complete {
		edgesRemoved, permsRemoved, resRemoved, err := s.grants.ReconcileGenerationKeeping(
			workspaceID, snapshot.ConnectorID, snapshot.Generation, keepEdges)
		if err != nil {
			return out, err
		}
		_ = edgesRemoved
		_ = permsRemoved
		_ = resRemoved
	}
	// cloud_policy and its attachments reconcile on the LISTINGS alone, not on
	// out.Complete. An unreadable document's row is re-stamped at this
	// generation like any other (with document_error), so it is never among
	// the rows deleted here; vetoing the account's policy cleanup over one
	// unreadable document is the account-wide veto per-document isolation
	// exists to avoid (§1.4: "the rest of the scan continues"). OIDC and EKS
	// say nothing about policies.
	if snapshot.Coverage.Complete() && out.policyHoldersMissing == 0 {
		if _, _, err := s.policies.ReconcilePolicies(
			workspaceID, snapshot.ConnectorID, snapshot.Generation); err != nil {
			return out, err
		}
	}

	return out, nil
}

func (s *AWSPermissionScanner) writeAssumeEdges(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, out *PermissionSnapshot,
) error {
	for roleARN, doc := range snapshot.TrustPolicies {
		identity, err := s.identities.GetIdentityByNativeID(workspaceID, roleARN)
		if err != nil {
			if errors.Is(err, repositories.ErrCloudIdentityNotFound) {
				out.Skipped++
				continue
			}
			return err
		}

		principals, perr := awsdiscovery.ParseTrustPolicy(doc)
		if perr != nil {
			// The role exists and trusts something we could not read. Count it
			// and move on: one unreadable trust policy must not end the scan,
			// and it must not read as a role nobody can assume.
			out.ParseFailures++
			continue
		}
		for _, p := range principals {
			edge := &models.CloudAssumeEdge{
				WorkspaceID:        workspaceID,
				ConnectorID:        snapshot.ConnectorID,
				IdentityID:         identity.ID,
				SubjectKind:        p.SubjectKind,
				Subject:            p.Subject,
				Issuer:             strPtrOrNil(p.Issuer),
				Mechanism:          p.Mechanism,
				K8sRef:             strPtrOrNil(p.K8sRef),
				LastSeenGeneration: snapshot.Generation,
			}
			if _, _, err := s.grants.UpsertAssumeEdge(edge); err != nil {
				return fmt.Errorf("record assume edge for %s: %w", roleARN, err)
			}
			out.EdgesWritten++
		}
	}
	return nil
}

// writePodIdentityEdges records one cloud_assume_edge per EKS Pod Identity
// association, across every region the connector selected.
//
// This is the only way these edges can be found. A Pod Identity role's trust
// policy names pods.eks.amazonaws.com and nothing else, so writeAssumeEdges
// above sees a cloud_service edge and no service account at all -- the binding
// itself lives in EKS, not in IAM.
//
// The edge is attached to the IAM role by looking the role up in inventory
// rather than by trusting the association's own ARN string: a role that
// ticket [1] never recorded (it lives in another account, or the IAM read was
// denied) has no row to hang an edge off, and inventing one would create an
// identity that no scan discovered.
//
// Returns every failure, across every region and cluster, as one
// *podIdentityFailures (nil when nothing failed). Regions are independent, so
// one region failing does not stop the others -- but any failure means this
// surface was not fully read, which the caller turns into "not complete" so
// nothing gets reconciled away, and the coverage names ALL of it: how many
// clusters and associations could not be described, and every listing that
// failed outright (§1.4 "the report names how many"). It used to report only
// the first error, so a second region's denial read as the first one's partial.
func (s *AWSPermissionScanner) writePodIdentityEdges(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot, out *PermissionSnapshot,
) error {

	connector, err := s.onboardingConnector(workspaceID, snapshot.ConnectorID)
	if err != nil {
		return err
	}
	regions := connector.AWSAttrs().Regions
	if len(regions) == 0 {
		// Nothing to scan is not a failure. A connector with no regions cannot
		// reach a regional service, and onboarding already refuses to create
		// one, so this is defensive rather than expected.
		return nil
	}

	failures := newPodIdentityFailures()
	for _, region := range regions {
		reader, err := s.eksReaderFor(ctx, workspaceID, snapshot.ConnectorID, region)
		if err != nil {
			failures.addListing(err, "")
			continue
		}
		clusters, err := reader.Clusters(ctx)
		if errors.Is(err, awsdiscovery.ErrServiceNotInRegion) && len(clusters) == 0 {
			// T3.8: EKS is not offered in this region -- nothing there to
			// read, and nothing there claimed, so the region is skipped and
			// costs the rest of the surface nothing (a region that listed
			// clusters before failing is no such region, and falls through
			// as the listing failure it is). Unless an earlier scan recorded
			// a binding that may come from here: then a resolver failure is
			// the likelier story, and it is reported as the failure it may be
			// (the same guard regionalCoverage applies to compute). A
			// connector whose every region is skipped this way holds no
			// binding at all, so reached -- no binding in any selected
			// region -- deletes nothing.
			if why, blocks := s.podIdentityRegionUnread(workspaceID, snapshot.ConnectorID, region); blocks {
				failures.addListing(err, why)
			}
			continue
		}
		failures.addClusters(err)
		for _, cluster := range clusters {
			assocs, err := reader.PodIdentityAssociations(ctx, cluster.Name)
			failures.addAssociations(err)
			// T3.6 (S3b): what WAS read is real even when some of the
			// cluster's describes failed (*awsdiscovery.ItemFailures) --
			// written, and confirmed, while the failures keep the surface
			// partial and reconciliation off for the rest.
			for _, assoc := range assocs {
				if err := s.writePodIdentityEdge(workspaceID, snapshot, region, cluster, assoc, out); err != nil {
					return err
				}
			}
		}
	}
	return failures.err()
}

// podIdentityRegionUnread decides whether a region whose EKS endpoint does not
// resolve still blocks eks_pod_identity: yes when an earlier scan recorded a
// binding that may come from it (or that cannot be checked), with the reason
// to append to the failure; no when none ever did -- EKS is simply not
// offered there. Never claim more than the data proves.
func (s *AWSPermissionScanner) podIdentityRegionUnread(
	workspaceID, connectorID uuid.UUID, region string,
) (string, bool) {
	prior, err := s.grants.CountPodIdentityEdges(workspaceID, connectorID, region)
	switch {
	case err != nil:
		return fmt.Sprintf(" (and whether an earlier scan recorded pod identity bindings in %s could not be checked: %v)",
			region, err), true
	case prior > 0:
		return fmt.Sprintf(", but %d pod identity binding(s) an earlier scan recorded may come from %s; not treated as not offered",
			prior, region), true
	}
	return "", false
}

// unreadPodIdentityEdges lists this connector's Pod Identity edges that this
// run did not see AND did not look for, with the regions they are in, sorted.
// Called after writePodIdentityEdges, so every binding this run read is
// already at its generation.
//
// An edge not seen this run is GONE only when its region was read: it is in
// the run's selection (the pinned connector, ForRun), and the EKS pass read
// every selected region (the caller only asks when it did). Otherwise it is
// UNREAD:
//   - its region is recorded and not selected -- deselected since it was
//     found (or never in a selection this connector remembers);
//   - its region is not known -- a row written before regions were recorded,
//     from a cluster whose issuer names none -- and SOME region was deselected
//     since (RegionsEverSelected): it may live there. When no region was ever
//     deselected, every region it could have come from was just read.
func (s *AWSPermissionScanner) unreadPodIdentityEdges(
	workspaceID uuid.UUID, snapshot *IAMSnapshot,
) ([]uuid.UUID, []string, error) {
	connector, err := s.onboardingConnector(workspaceID, snapshot.ConnectorID)
	if err != nil {
		return nil, nil, err
	}
	attrs := connector.AWSAttrs()
	selected := make(map[string]bool, len(attrs.Regions))
	for _, r := range attrs.Regions {
		selected[r] = true
	}
	deselected := len(attrs.DeselectedRegions()) > 0

	held, err := s.grants.HeldOverAssumeEdges(workspaceID, snapshot.ConnectorID,
		snapshot.Generation, models.AssumeMechanismEKSPodIdentity)
	if err != nil {
		return nil, nil, err
	}
	var keep []uuid.UUID
	regions := map[string]bool{}
	for _, e := range held {
		region := podIdentityEdgeRegion(e)
		switch {
		case region != "" && selected[region]:
			continue // read this run, and not there: gone
		case region == "" && !deselected:
			continue // every region it could be in was read: gone
		}
		keep = append(keep, e.ID)
		if region == "" {
			region = "a region not recorded"
		}
		regions[region] = true
	}
	names := make([]string, 0, len(regions))
	for r := range regions {
		names = append(names, r)
	}
	sort.Strings(names)
	return keep, names, nil
}

// podIdentityEdgeRegion is the region a Pod Identity edge was found in: the
// one it recorded, else the region its cluster's OIDC issuer names
// (oidc.eks.<region>.amazonaws.com[.cn]/id/...) -- a row written before the
// region was recorded -- else "" (not known).
func podIdentityEdgeRegion(e models.CloudAssumeEdge) string {
	var a podIdentityEdgeWhere
	if len(e.Attrs) > 0 && json.Unmarshal(e.Attrs, &a) == nil && a.Region != "" {
		return a.Region
	}
	if e.Issuer == nil {
		return ""
	}
	host, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(*e.Issuer, "https://"), "http://"), "/")
	rest, ok := strings.CutPrefix(host, "oidc.eks.")
	if !ok {
		return ""
	}
	region, _, ok := strings.Cut(rest, ".amazonaws.com")
	if !ok || awsdiscovery.ValidateRegion(region) != nil {
		return ""
	}
	return region
}

// podIdentityEdgeWhere decodes the one field of a Pod Identity edge's attrs
// (written by podIdentityEdgeAttrs, cloud_aws_collection_evidence.go) that
// deselection needs: the region it was found in. That region is what lets a
// later scan tell a binding it did not look for -- in a region deselected
// since -- from one that is gone (unreadPodIdentityEdges).
type podIdentityEdgeWhere struct {
	Region string `json:"region,omitempty"`
}

// writePodIdentityEdge records one association, found in region.
func (s *AWSPermissionScanner) writePodIdentityEdge(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, region string,
	cluster awsdiscovery.EKSCluster, assoc awsdiscovery.PodIdentityAssociation,
	out *PermissionSnapshot,
) error {

	identity, err := s.identities.GetIdentityByNativeID(workspaceID, assoc.RoleARN)
	if err != nil {
		if errors.Is(err, repositories.ErrCloudIdentityNotFound) {
			out.Skipped++
			return nil
		}
		return err
	}

	subject := awsdiscovery.K8sSubject(assoc.Namespace, assoc.ServiceAccount)
	edge := &models.CloudAssumeEdge{
		WorkspaceID: workspaceID,
		ConnectorID: snapshot.ConnectorID,
		IdentityID:  identity.ID,
		SubjectKind: models.AssumeSubjectK8sSA,
		Subject:     subject,
		// The cluster's OIDC issuer, which is what tells two clusters apart
		// when both run the same namespace and service account name. Nil rather
		// than empty when the cluster has no OIDC provider configured, which is
		// legitimate for a Pod Identity-only cluster.
		Issuer:    strPtrOrNil(cluster.OIDCIssuer),
		Mechanism: models.AssumeMechanismEKSPodIdentity,
		// Byte-for-byte what the Kubernetes connector records for the same pod.
		K8sRef:             strPtrOrNil(subject),
		LastSeenGeneration: snapshot.Generation,
		// Where the binding was read (podIdentityEdgeAttrs): the region is
		// what lets a later scan tell "EKS is not offered there" from "a
		// binding we recorded there cannot be read" (T3.8).
		Attrs: podIdentityEdgeAttrs(region, cluster, assoc),
	}
	// KNOWN LIMITATION. uq_cloud_assume_edge_subject is
	// (identity_id, subject_kind, subject) and does not include the issuer, so
	// two clusters running the same namespace and service account name, both
	// bound to the SAME role, collapse into one row whose issuer is whichever
	// region was scanned last. Recording it here rather than widening the index,
	// because that is a migration and a schema decision, not a code fix.
	if _, _, err := s.grants.UpsertAssumeEdge(edge); err != nil {
		return fmt.Errorf("record pod identity edge for %s: %w", assoc.RoleARN, err)
	}
	// T3.5: the association's observation (cloud_aws_collection_evidence.go).
	s.recordPodIdentityEvidence(identity.ID, cluster, assoc, edge)
	out.EdgesWritten++
	out.PodIdentityEdges++
	return nil
}

func (s *AWSPermissionScanner) writePermissions(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, out *PermissionSnapshot,
) error {
	// ---- managed policies, each ONCE (T3.1, 035) ---------------------------
	//
	// Every managed policy the read resolved -- every customer-managed policy
	// in the account, attached or not, and every AWS-managed one a principal
	// uses -- is one row per connector with one state and one observation,
	// written before any attachment names it. In ARN order, so a run is
	// reproducible.
	rows := make(map[string]*models.CloudPolicy, len(snapshot.ManagedPolicies))
	arns := make([]string, 0, len(snapshot.ManagedPolicies))
	for arn := range snapshot.ManagedPolicies {
		arns = append(arns, arn)
	}
	sort.Strings(arns)
	for _, arn := range arns {
		if _, err := s.managedPolicyRow(workspaceID, snapshot, snapshot.ManagedPolicies[arn], rows, out); err != nil {
			return err
		}
	}

	// ---- per holder: attachments, inline policies, Cloud Inventory rows -----
	holders := make([]string, 0, len(snapshot.Policies))
	for arn := range snapshot.Policies {
		holders = append(holders, arn)
	}
	sort.Strings(holders)

	for _, identityARN := range holders {
		policies := snapshot.Policies[identityARN]
		identity, err := s.identities.GetIdentityByNativeID(workspaceID, identityARN)
		if err != nil {
			if errors.Is(err, repositories.ErrCloudIdentityNotFound) {
				out.Skipped++
				out.policyHoldersMissing++
				continue
			}
			return err
		}

		// Every statement this identity owns is read in the light of its
		// boundary: the statement text looks unconstrained, the identity is not.
		attrs := identity.AWSAttrs()
		state := boundaryNone
		switch {
		case attrs.DetailIncomplete:
			state = boundaryUnknown
		case attrs.PermissionsBoundaryARN != "":
			state = boundaryPresent
		}
		grants := grantOptions(state)

		for _, p := range policies.Attached {
			row, err := s.managedPolicyRow(workspaceID, snapshot, p, rows, out)
			if err != nil {
				return err
			}
			if err := s.attach(workspaceID, snapshot, row, identity, models.CloudAttachmentAttached); err != nil {
				return err
			}
			// Cloud Inventory's rows, from any document that parses at all --
			// an unreadable one (document_error) contributes nothing to the
			// graph either way, and one with a skipped statement keeps writing
			// its usable statements here, as it always has.
			if parses(p.FetchError, p.Document) {
				if err := s.writePolicyDocument(workspaceID, snapshot, identity.ID, identity.NativeID,
					p.ARN, managedPolicyAPI(p), p.Document, out, grants); err != nil {
					return err
				}
			}
		}
		for _, p := range policies.Inline {
			if err := s.recordInlinePolicy(workspaceID, snapshot, identity, p, out); err != nil {
				return err
			}
			if parses(p.FetchError, p.Document) {
				if err := s.writePolicyDocument(workspaceID, snapshot, identity.ID, identity.NativeID,
					"inline:"+p.Name, authDetailsAPI, p.Document, out, grants); err != nil {
					return err
				}
			}
		}
		// The boundary's own statements, recorded as a ceiling. Written with a
		// distinct derivation so nothing counts them as access granted, and
		// attached as kind 'boundary', which the graph never makes a grant.
		// Users have one too now (§1.3).
		if b := policies.Boundary; b != nil {
			row, err := s.managedPolicyRow(workspaceID, snapshot, *b, rows, out)
			if err != nil {
				return err
			}
			if err := s.attach(workspaceID, snapshot, row, identity, models.CloudAttachmentBoundary); err != nil {
				return err
			}
			if parses(b.FetchError, b.Document) {
				if err := s.writePolicyDocument(workspaceID, snapshot, identity.ID, identity.NativeID,
					"boundary:"+b.ARN, managedPolicyAPI(*b)+" (permissions boundary)", b.Document, out, boundaryOptions()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// policyWriteOptions carries the facts about the OWNING identity that change
// how its statements must be read, rather than facts about the statement.
type policyWriteOptions struct {
	// boundary is what we know about the owning identity's permissions
	// boundary: that it has one, that it has none, or that we could not find
	// out. The third case must not collapse into the second.
	boundary boundaryState
	// derivation separates a grant from a ceiling. A boundary document's
	// statements are written with PermissionDerivationBoundary so no query can
	// count them as access.
	derivation string
}

// boundaryState is what a scan knows about an identity's permissions boundary.
type boundaryState int

const (
	// boundaryNone: the identity was read completely and carries no boundary.
	boundaryNone boundaryState = iota
	// boundaryPresent: the identity carries one.
	boundaryPresent
	// boundaryUnknown: the detail read failed, so we do not know.
	//
	// Treating this as boundaryNone is the over-claim that matters: a role
	// whose boundary we could not read would have its grants recorded as
	// unconstrained, which is precisely the ceiling the boundary imposes being
	// erased by a failed API call.
	boundaryUnknown
)

func grantOptions(b boundaryState) policyWriteOptions {
	return policyWriteOptions{boundary: b, derivation: models.PermissionDerivationGranted}
}

func boundaryOptions() policyWriteOptions {
	// A boundary's own statements are not capped by the boundary -- they ARE
	// the boundary, so the state is none here.
	return policyWriteOptions{boundary: boundaryNone, derivation: models.PermissionDerivationBoundary}
}

// nullableJSON turns the parser's "" for an absent Condition into a NULL the
// jsonb column accepts. An empty string is not valid JSON.
func nullableJSON(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// authDetailsAPI is the call inline and customer-managed documents come from:
// both arrive in the authorization-details listing itself (T3.1).
const authDetailsAPI = "iam:GetAccountAuthorizationDetails"

// managedPolicyAPI names the AWS call a managed policy's document came from,
// so evidence points at something a reader can re-issue: GetPolicyVersion for
// an AWS-managed policy, the LocalManagedPolicy listing for a customer one.
func managedPolicyAPI(p awsdiscovery.AttachedPolicy) string {
	if p.AWSManaged {
		return "iam:GetPolicyVersion"
	}
	return authDetailsAPI
}

// constraintState decides how far a recorded permission may be trusted as a
// statement of access.
//
// Ordered most- to least-specific: a conditional grant is the narrowest claim,
// then a negated one, then merely bounded. Only a statement with none of these
// may be rendered as plain access.
func constraintState(stmt awsdiscovery.PolicyStatement, b boundaryState) string {
	switch {
	case stmt.Condition != "":
		return models.ConstraintConditional
	case len(stmt.NotActions) > 0 || len(stmt.NotResources) > 0:
		return models.ConstraintNegated
	case b == boundaryPresent:
		return models.ConstraintBounded
	case b == boundaryUnknown:
		// We could not read the identity's detail. Unconstrained would assert
		// a ceiling we never checked for.
		return models.ConstraintUnknown
	default:
		return models.ConstraintUnconstrained
	}
}

// writePolicyDocument parses one policy document and writes one cloud_permission
// row per (statement, named resource) pair -- or one unresourced row for a
// statement naming no concrete resource.
//
// A statement listing more than one resource fans out to more than one row
// sharing the same nativeID; the migration's unique index is
// (identity_id, native_id, resource_id) for exactly this reason. Two DIFFERENT
// partial-wildcard resources in one statement collapse into the single
// resource_id=NULL row for that nativeID -- an accepted limitation, since
// cloud_resource never stores a wildcarded string for either one to keep
// distinct in the first place.
//
// A document that does NOT PARSE never fails the scan: it is counted and
// skipped. Returning an error for it aborted ScanFromSnapshot, which recorded
// permission_scan denied and vetoed every partition in the account over one
// document -- the §1.3 defect per-document isolation exists to remove. (The
// callers only hand over documents that parse; this is the backstop.) A
// failed WRITE still returns its error: that includes a lost fence, and a
// superseded worker must stop.
func (s *AWSPermissionScanner) writePolicyDocument(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, identityID uuid.UUID,
	holderNativeID, source, sourceAPI, document string, out *PermissionSnapshot, opts policyWriteOptions,
) error {
	statements, skipped, err := awsdiscovery.ParsePolicyDocument(document)
	if err != nil {
		// A document we cannot read is a coverage failure, not an identity with
		// no permissions: counted, so the legacy reconcile never runs.
		out.ParseFailures++
		log.Printf("aws permission scan: parse policy %s: %v", source, err)
		return nil
	}
	out.StatementsSkipped += skipped

	for _, stmt := range statements {
		// The statement's position in the ORIGINAL document, not in the parsed
		// slice. Numbering the compacted slice meant one unusable statement
		// renumbered every statement after it, silently changing what existing
		// permission rows referred to.
		nativeID := fmt.Sprintf("%s#s%d", source, stmt.Index)
		resources := stmt.Resources
		if len(resources) == 0 {
			// Either a genuinely unresourced statement or one written with
			// NotResource. Both produce a single resource-less row, but they
			// are NOT the same fact: the NotResource text is carried on the row
			// and constraint_state marks it negated, so a bounded exclusion is
			// never read as an account-wide grant.
			resources = []string{"*"}
		}

		// De-duplicate resources that classify to the same scope+ARN within one
		// statement (e.g. Resource listed twice), so the loop below does not
		// attempt two conflicting upserts for the identical conflict target in
		// one transaction-less pass.
		seen := map[string]bool{}

		for _, resource := range resources {
			scopeKind, typed := awsdiscovery.ClassifyResourceScope(resource)
			dedupeKey := scopeKind
			if typed != nil {
				dedupeKey = typed.NativeID
			}
			if seen[dedupeKey] {
				continue
			}
			seen[dedupeKey] = true

			var resourceID *uuid.UUID
			sensitivity := actionsSensitivity(stmt.Actions)
			if typed != nil {
				id, err := s.getOrCreateResource(workspaceID, snapshot, typed, out)
				if err != nil {
					return err
				}
				resourceID = &id
				if s := resourceSensitivity(typed.Service); s == models.SensitivityHigh {
					sensitivity = models.SensitivityHigh
				}
			}

			perm := &models.CloudPermission{
				WorkspaceID:        workspaceID,
				ConnectorID:        snapshot.ConnectorID,
				IdentityID:         identityID,
				ResourceID:         resourceID,
				Plane:              models.PermissionPlaneCloud,
				Effect:             stmt.Effect,
				Actions:            stmt.Actions,
				NotActions:         stmt.NotActions,
				NotResources:       stmt.NotResources,
				Condition:          nullableJSON(stmt.Condition),
				ConstraintState:    constraintState(stmt, opts.boundary),
				ScopeKind:          scopeKind,
				Derivation:         opts.derivation,
				Sensitivity:        sensitivity,
				NativeID:           nativeID,
				LastSeenGeneration: snapshot.Generation,
			}
			stored, _, err := s.grants.UpsertPermission(perm)
			if err != nil {
				return fmt.Errorf("record permission %s: %w", nativeID, err)
			}
			out.PermissionsWritten++

			// Evidence for the grant. The statement is recorded as parsed --
			// including the halves that NARROW it -- because a reviewer shown
			// "allow s3:GetObject" needs to see the condition that was attached
			// to it, and evidence that omits the narrowing repeats the very
			// over-claim the constraint columns exist to prevent.
			if s.evidence != nil && stored != nil {
				// P2-2 / SPEC §4.8: the observation's subject_native_id is the
				// FULLY-QUALIFYING key, not the bare nativeID. One statement
				// produces one cloud_permission row per resource, and two
				// holders of one managed policy share a statement id, so the
				// bare id is ambiguous -- and once 024 SETs NULL the subject FK
				// on reconciliation, subject_native_id is all that survives to
				// tie the evidence to its grant.
				//
				// Built with the SAME helper the projector's evidence pass
				// looks up by (igagraph.PermissionSubjectKey), so the key
				// written and the key read cannot drift. A resourceless or
				// wildcard statement passes "" and the helper substitutes "*".
				resourceNativeID := ""
				if typed != nil {
					resourceNativeID = typed.NativeID
				}
				subjectKey := igagraph.PermissionSubjectKey(*stored, holderNativeID, resourceNativeID)
				if err := s.evidence.Record(
					PermissionSubject(stored.ID),
					sourceAPI, models.SurfaceIAMPolicies, "",
					time.Now(), subjectKey,
					map[string]any{
						"source":           source,
						"statement_index":  stmt.Index,
						"sid":              stmt.Sid,
						"effect":           stmt.Effect,
						"actions":          stmt.Actions,
						"not_actions":      stmt.NotActions,
						"resources":        stmt.Resources,
						"not_resources":    stmt.NotResources,
						"condition":        stmt.Condition,
						"constraint_state": perm.ConstraintState,
						"derivation":       perm.Derivation,
					},
				); err != nil {
					log.Printf("aws permission scan: evidence for %s: %v", nativeID, err)
				}
			}
		}
	}
	return nil
}

// documentError decides whether a document is readable, and why not (T3.3):
// "fetch: ..." from the reader -- naming the call and AWS's error code --
// "fetch: empty document", or awsdiscovery.PolicyDocumentError's "parse: ..."
// (which includes D-49's unusable statements). One definition of readable,
// over the parser the projector runs, so a document recorded readable here
// cannot fail to parse there (§4.7). skipped is the per-document count of
// unusable statements (§1.4: "skipped statements are counted per document").
func documentError(fetchErr, document string) (docErr string, skipped int) {
	if fetchErr != "" {
		return fetchErr, 0
	}
	if strings.TrimSpace(document) == "" {
		return "fetch: empty document", 0
	}
	if _, n, err := awsdiscovery.ParsePolicyDocument(document); err == nil {
		skipped = n
	}
	return awsdiscovery.PolicyDocumentError(document), skipped
}

// parses reports whether a document was fetched and parses at all -- the bar
// for Cloud Inventory's cloud_permission rows, which a skipped statement does
// not lower.
func parses(fetchErr, document string) bool {
	if fetchErr != "" || strings.TrimSpace(document) == "" {
		return false
	}
	_, _, err := awsdiscovery.ParsePolicyDocument(document)
	return err == nil
}

// documentJSON is the document for cloud_policy.document (jsonb), or nil when
// it is not valid JSON -- a jsonb column refuses it, and the row then carries
// document_error instead (cloud_policy_readable_chk).
func documentJSON(document string) json.RawMessage {
	if document == "" || !json.Valid([]byte(document)) {
		return nil
	}
	return json.RawMessage(document)
}

// managedPolicyRow returns the cloud_policy row for a managed policy, writing
// it the first time this run meets the ARN -- ONE row per connector per run,
// one state, one observation, however many principals attach it.
func (s *AWSPermissionScanner) managedPolicyRow(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, p awsdiscovery.AttachedPolicy,
	rows map[string]*models.CloudPolicy, out *PermissionSnapshot,
) (*models.CloudPolicy, error) {
	if row, ok := rows[p.ARN]; ok {
		return row, nil
	}
	row, err := s.recordManagedPolicy(workspaceID, snapshot, p, out)
	if err != nil {
		return nil, err
	}
	rows[p.ARN] = row
	return row, nil
}

// recordManagedPolicy writes a managed policy (as this connector read it), and
// its observation.
//
// Written whether or not the document could be read: its ATTACHMENTS are facts
// read independently of the document (§1.4), and the projector needs the
// unreadable policy at THIS generation to protect what it declared last time.
// The document itself is stored whenever it was fetched and is JSON -- also
// when it did not parse, because document_error, not the column's NULL, is
// what says the graph may not use it.
func (s *AWSPermissionScanner) recordManagedPolicy(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, p awsdiscovery.AttachedPolicy, out *PermissionSnapshot,
) (*models.CloudPolicy, error) {
	docErr, skipped := documentError(p.FetchError, p.Document)
	row := &models.CloudPolicy{
		WorkspaceID:        workspaceID,
		ConnectorID:        snapshot.ConnectorID,
		PolicyKind:         models.CloudPolicyManaged,
		NativeID:           p.ARN,
		Name:               p.Name,
		PolicyID:           p.PolicyID,
		AWSManaged:         p.AWSManaged,
		VersionID:          p.VersionID,
		DocumentError:      docErr,
		LastSeenGeneration: snapshot.Generation,
	}
	if p.FetchError == "" {
		row.Document = documentJSON(p.Document)
		row.DocumentHash = documentHash(p.Document)
	}
	if docErr != "" {
		out.noteUnreadable(p.Name, p.VersionID, docErr)
	}
	stored, err := s.policies.UpsertPolicy(row)
	if err != nil {
		return nil, fmt.Errorf("record policy %s: %w", p.ARN, err)
	}
	out.PoliciesWritten++
	s.recordPolicyEvidence(stored, managedPolicyAPI(p), map[string]any{
		"arn": p.ARN, "policy_id": p.PolicyID, "name": p.Name,
		"version_id": p.VersionID, "aws_managed": p.AWSManaged,
		"document_hash": row.DocumentHash, "document_error": docErr,
		"statements_skipped": skipped,
	})
	return stored, nil
}

// attach records policy -> principal at this generation.
func (s *AWSPermissionScanner) attach(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, policy *models.CloudPolicy,
	holder *models.CloudIdentity, kind string,
) error {
	if err := s.policies.UpsertAttachment(&models.CloudPolicyAttachment{
		WorkspaceID: workspaceID, ConnectorID: snapshot.ConnectorID,
		PolicyRowID: policy.ID, PrincipalIdentityID: holder.ID,
		AttachmentKind: kind, LastSeenGeneration: snapshot.Generation,
	}); err != nil {
		return fmt.Errorf("record %s attachment %s -> %s: %w", kind, policy.NativeID, holder.NativeID, err)
	}
	return nil
}

// recordInlinePolicy writes one holder's inline policy, its 'inline'
// attachment and its observation. Keyed by its holder: two roles each with an
// inline ReadData are two policies (§2.6).
func (s *AWSPermissionScanner) recordInlinePolicy(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, holder *models.CloudIdentity,
	p awsdiscovery.InlinePolicy, out *PermissionSnapshot,
) error {
	docErr, skipped := documentError(p.FetchError, p.Document)
	holderID := holder.ID
	row := &models.CloudPolicy{
		WorkspaceID:        workspaceID,
		ConnectorID:        snapshot.ConnectorID,
		PolicyKind:         models.CloudPolicyInline,
		NativeID:           "inline:" + holder.NativeID + ":" + p.Name,
		HolderIdentityID:   &holderID,
		Name:               p.Name,
		DocumentError:      docErr,
		LastSeenGeneration: snapshot.Generation,
	}
	if p.FetchError == "" {
		row.Document = documentJSON(p.Document)
		row.DocumentHash = documentHash(p.Document)
	}
	if docErr != "" {
		out.noteUnreadable(p.Name+" (inline on "+holder.Name+")", "", docErr)
	}
	stored, err := s.policies.UpsertPolicy(row)
	if err != nil {
		return fmt.Errorf("record inline policy %s: %w", row.NativeID, err)
	}
	out.PoliciesWritten++
	if err := s.attach(workspaceID, snapshot, stored, holder, models.CloudAttachmentInline); err != nil {
		return err
	}
	// Inline documents of roles, users and groups alike arrive in the
	// authorization-details listing (T3.1).
	s.recordPolicyEvidence(stored, authDetailsAPI, map[string]any{
		"name": p.Name, "holder": holder.NativeID,
		"document_hash": row.DocumentHash, "document_error": docErr,
		"statements_skipped": skipped,
	})
	return nil
}

// recordPolicyEvidence records the policy version as an evidence subject
// (035, T3.5): subject policy_id, subject_native_id the policy's native id,
// which is what the projector joins on. The grant, the assignment and the
// target all cite it (§4.8). The facts carry the document hash, so a new
// default version is a new observation and an unchanged one is confirmed on
// the dedupe path: one observation per policy version.
func (s *AWSPermissionScanner) recordPolicyEvidence(p *models.CloudPolicy, api string, facts map[string]any) {
	if s.evidence == nil || p == nil {
		return
	}
	if err := s.evidence.Record(PolicySubject(p.ID), api, models.SurfaceIAMPolicies, "",
		time.Now(), p.NativeID, facts); err != nil {
		log.Printf("aws permission scan: evidence for policy %s: %v", p.NativeID, err)
	}
}

// documentHash is the sha256 of the document text as read, for change
// detection on the policy row.
func documentHash(document string) string {
	sum := sha256.Sum256([]byte(document))
	return hex.EncodeToString(sum[:])
}

// noteUnreadable records one unreadable document, once per name and version.
func (o *PermissionSnapshot) noteUnreadable(name, version, reason string) {
	o.noteUnreadableItem(models.CoverageItem{Policy: name, Version: version, Error: reason})
}

// noteUnreadableItem records one unreadable document -- a policy, or a role's
// trust policy the IAM scan judged -- once.
func (o *PermissionSnapshot) noteUnreadableItem(item models.CoverageItem) {
	if o.unreadableSeen == nil {
		o.unreadableSeen = map[models.CoverageItem]bool{}
	}
	if o.unreadableSeen[item] {
		return
	}
	o.unreadableSeen[item] = true
	o.UnreadableDocuments = append(o.UnreadableDocuments, item)
}

// unreadableLabel is one unreadable document as the coverage prose names it:
// "TicketRead v3 (fetch: AWS returned AccessDenied for iam:GetPolicyVersion: ...)".
func unreadableLabel(item models.CoverageItem) string {
	label := item.Policy
	if item.Version != "" {
		label += " " + item.Version
	}
	return label + " (" + item.Error + ")"
}

// policyDocumentsSurface is policy_documents when something could not be read
// (§1.4): partial, Count the documents examined (policies and role trust
// documents), and the error naming each unreadable one with its reason --
// "1 policy could not be read: TicketRead v3 (parse: ...)". Written ONLY when
// something was dropped; canEnd reads its absence as "nothing was".
//
// The same documents as Items (D-71), and both BOUNDED at
// models.CoverageItemLimit: the count in the prose is always the full one,
// Truncated says the list is not, and an account with thousands of broken
// documents does not write a report that size into every run.
func policyDocumentsSurface(out *PermissionSnapshot, trustDocuments int) models.SurfaceCoverage {
	cov := models.SurfaceCoverage{
		State: models.CloudCoveragePartial,
		Count: out.PoliciesWritten + trustDocuments,
		Error: "policy or trust documents could not be fully read",
	}
	n := len(out.UnreadableDocuments)
	if n == 0 {
		return cov
	}
	listed := out.UnreadableDocuments
	if n > models.CoverageItemLimit {
		listed, cov.Truncated = listed[:models.CoverageItemLimit], true
	}
	cov.Items = append([]models.CoverageItem(nil), listed...)
	labels := make([]string, 0, len(listed))
	for _, item := range listed {
		labels = append(labels, unreadableLabel(item))
	}
	noun := "policies"
	if n == 1 {
		noun = "policy"
	}
	cov.Error = fmt.Sprintf("%d %s could not be read: %s", n, noun, strings.Join(labels, "; "))
	if cov.Truncated {
		cov.Error += fmt.Sprintf("; and %d more", n-len(listed))
	}
	return cov
}

func (s *AWSPermissionScanner) getOrCreateResource(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, typed *awsdiscovery.TypedResource, out *PermissionSnapshot,
) (uuid.UUID, error) {
	sensitivity, reason := resourceSensitivityWithReason(typed.Service)

	// External means "in some account other than the one we scanned", and it is
	// only knowable when the ARN carries an account at all -- S3 bucket ARNs do
	// not. Reporting the scanned account for every resource is what made a
	// cross-account grant render as a local resource.
	external := typed.Account != "" && snapshot.AccountID != "" &&
		typed.Account != snapshot.AccountID

	resource := &models.CloudResource{
		WorkspaceID:        workspaceID,
		ConnectorID:        snapshot.ConnectorID,
		Kind:               typed.Kind,
		NativeID:           typed.NativeID,
		Name:               typed.Name,
		ResourceAccount:    typed.Account,
		IsExternal:         external,
		ObjectKey:          typed.ObjectKey,
		Sensitivity:        sensitivity,
		SensitivitySource:  models.SensitivityFromHeuristic,
		SensitivityReason:  reason,
		LastSeenGeneration: snapshot.Generation,
	}
	stored, created, err := s.grants.UpsertResource(resource)
	if err != nil {
		return uuid.Nil, fmt.Errorf("record resource %s: %w", typed.NativeID, err)
	}
	if created {
		out.ResourcesWritten++
	}
	if typed.Kind == "s3_bucket" || typed.Kind == "kms_key" {
		out.resourcePolicyCandidates = append(out.resourcePolicyCandidates, resourcePolicyCandidate{
			ResourceID: stored.ID, Kind: typed.Kind, NativeID: typed.NativeID, Name: typed.Name,
		})
	}
	return stored.ID, nil
}

// highSensitivityServices per the AWS plan's section 5: actions or resources
// on Secrets Manager, KMS or IAM itself are treated as high. A starting rule,
// not a risk engine -- see the migration's header on cloud_resource.sensitivity.
var highSensitivityServices = map[string]bool{
	"secretsmanager": true,
	"kms":            true,
	"iam":            true,
}

func resourceSensitivity(service string) string {
	v, _ := resourceSensitivityWithReason(service)
	return v
}

// resourceSensitivityWithReason returns the rating AND the rule behind it.
//
// The console showed "High" with nothing to inspect, so a reader could not tell
// an AuthSec guess from a customer classification or a provider fact. The rating
// is worth little; the reason is what lets someone decide whether to believe it.
func resourceSensitivityWithReason(service string) (string, string) {
	svc := strings.ToLower(service)
	if highSensitivityServices[svc] {
		return models.SensitivityHigh,
			fmt.Sprintf("AuthSec rule: %q is on the high-sensitivity service list", svc)
	}
	return models.SensitivityLow, ""
}

// actionsSensitivity classifies by the ACTIONS a statement grants, independent
// of what resource it names -- a statement reading iam:* on a specific role is
// high regardless of whether that role's ARN individually looks sensitive.
func actionsSensitivity(actions []string) string {
	for _, a := range actions {
		service := a
		if i := strings.Index(a, ":"); i > 0 {
			service = a[:i]
		}
		if highSensitivityServices[strings.ToLower(service)] {
			return models.SensitivityHigh
		}
	}
	return models.SensitivityLow
}

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// onboardingConnector reads the connector row, for the region list a regional
// surface needs. Goes through the onboarding service rather than a repository
// of its own so the workspace scoping is identical to every other read here.
func (s *AWSPermissionScanner) onboardingConnector(
	workspaceID, connectorID uuid.UUID,
) (*models.CloudConnector, error) {
	if s.onboarding == nil {
		return nil, errors.New("no onboarding service to read the connector's regions from")
	}
	return s.onboarding.Connector(workspaceID, connectorID)
}

// eksReaderFor builds an EKS reader bound to one region.
//
// Unlike IAM, EKS is regional: the same account shows different clusters in
// different regions, so the region is part of the request rather than an
// irrelevant signing detail.
func (s *AWSPermissionScanner) eksReaderFor(
	ctx context.Context, workspaceID, connectorID uuid.UUID, region string,
) (*awsdiscovery.EKSReader, error) {

	if s.regionalEKS != nil {
		return awsdiscovery.NewEKSReader(s.regionalEKS(region)), nil
	}
	if s.eksAPI != nil {
		return awsdiscovery.NewEKSReader(s.eksAPI), nil
	}
	if s.onboarding == nil {
		return nil, errors.New("no EKS client and no onboarding service to assume a role with")
	}
	cfg, _, err := s.onboarding.ConfigForConnector(ctx, workspaceID, connectorID, region)
	if err != nil {
		return nil, err
	}
	return awsdiscovery.NewEKSReader(awsdiscovery.NewEKSClient(cfg)), nil
}

// resourcePolicyReaderFor mirrors eksReaderFor: an injected client wins, for
// tests; otherwise real S3/KMS clients are built from the connector's own
// assumed-role config. Not region-bound the way EKS is -- GetBucketPolicy and
// GetKeyPolicy both resolve against the resource's own ARN regardless of
// which region the client itself is signing for.
func (s *AWSPermissionScanner) resourcePolicyReaderFor(
	ctx context.Context, workspaceID, connectorID uuid.UUID,
) (*awsdiscovery.ResourcePolicyReader, error) {
	if s.s3API != nil || s.kmsAPI != nil {
		return awsdiscovery.NewResourcePolicyReader(s.s3API, s.kmsAPI), nil
	}
	if s.onboarding == nil {
		return nil, errors.New("no resource-policy client and no onboarding service to assume a role with")
	}
	cfg, _, err := s.onboarding.ConfigForConnector(ctx, workspaceID, connectorID, "")
	if err != nil {
		return nil, err
	}
	return awsdiscovery.NewResourcePolicyReader(
		awsdiscovery.NewS3PolicyClient(cfg), awsdiscovery.NewKMSPolicyClient(cfg)), nil
}

// scanResourcePolicies checks every S3 bucket / KMS key writePermissions
// named, deduplicated by native id so a bucket referenced by ten statements
// is read once. Records each resource's policy as evidence; does not alter
// any cloud_permission row's ConstraintState -- cross-referencing a resource
// policy's explicit deny back into the identity-based grant it narrows is a
// real next step this does not take, see the file header on ResourcePolicy.
func (s *AWSPermissionScanner) scanResourcePolicies(
	ctx context.Context, workspaceID, connectorID uuid.UUID, out *PermissionSnapshot,
) (int, error) {
	if len(out.resourcePolicyCandidates) == 0 {
		return 0, nil
	}
	reader, err := s.resourcePolicyReaderFor(ctx, workspaceID, connectorID)
	if err != nil {
		return 0, err
	}

	seen := make(map[string]bool, len(out.resourcePolicyCandidates))
	checked := 0
	// T3.7: every per-resource read is counted, so resource_policies is
	// reached only when every read succeeded ("no policy" is a success),
	// partial or denied otherwise -- never reached "even when every read was
	// denied" (§1.3). See resourcePolicyCoverage (D-93).
	reads := awsdiscovery.NewItemFailures("resource policies could not be read", false)
	for _, c := range out.resourcePolicyCandidates {
		if seen[c.NativeID] {
			continue
		}
		seen[c.NativeID] = true

		var (
			policy awsdiscovery.ResourcePolicy
			rerr   error
		)
		switch c.Kind {
		case "s3_bucket":
			policy, rerr = reader.BucketPolicy(ctx, c.Name)
		case "kms_key":
			policy, rerr = reader.KeyPolicy(ctx, c.NativeID)
		default:
			continue
		}
		reads.Attempt()
		if rerr != nil {
			log.Printf("aws permission scan: resource policy for %s: %v", c.NativeID, rerr)
			reads.Fail(c.NativeID, resourcePolicySourceAPI(c.Kind), rerr)
			continue
		}
		checked++
		if s.evidence == nil || policy.Document == "" {
			continue
		}
		if werr := s.evidence.Record(
			ResourceSubject(c.ResourceID), resourcePolicySourceAPI(c.Kind),
			models.SurfaceResourcePolicies, "", time.Now(), c.NativeID,
			map[string]any{
				"kind":         c.Kind,
				"has_deny":     policy.HasDeny,
				"parse_failed": policy.ParseFailed,
				"statements":   len(policy.Statements),
			},
		); werr != nil {
			log.Printf("aws permission scan: resource policy evidence for %s: %v", c.NativeID, werr)
		}
	}
	return checked, reads.Err(nil)
}

// resourcePolicySourceAPI names the call each resource kind's policy came
// from, so evidence points at something a reader can re-issue themselves.
func resourcePolicySourceAPI(kind string) string {
	switch kind {
	case "s3_bucket":
		return "s3:GetBucketPolicy"
	case "kms_key":
		return "kms:GetKeyPolicy"
	default:
		return "resource:GetPolicy"
	}
}

// readerFor builds an IAM reader for a connector, assuming its role unless a
// client was injected. Identical to AWSIAMScanner.readerFor -- duplicated
// rather than shared because the two scanners' constructors take different
// enough shapes that extracting this now would be premature; worth revisiting
// if a third AWS scanner needs the same seam.
func (s *AWSPermissionScanner) readerFor(
	ctx context.Context, workspaceID, connectorID uuid.UUID,
) (*awsdiscovery.IAMReader, error) {
	if s.api != nil {
		return awsdiscovery.NewIAMReader(s.api), nil
	}
	if s.onboarding == nil {
		return nil, errors.New("no IAM client and no onboarding service to assume a role with")
	}
	cfg, _, err := s.onboarding.ConfigForConnector(ctx, workspaceID, connectorID, "")
	if err != nil {
		return nil, err
	}
	return awsdiscovery.NewIAMReader(awsdiscovery.NewIAMClient(cfg)), nil
}
