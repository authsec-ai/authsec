package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
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
	db          *gorm.DB
	identities  repositories.CloudIdentityRepository
	grants      repositories.CloudPermissionRepository
	checkpoints repositories.CloudScanCheckpointRepository
	onboarding  *AWSOnboardingService

	// api, when set, replaces the real IAM client -- the same test seam
	// AWSIAMScanner uses.
	api awsdiscovery.IAMAPI

	// eksAPI, when set, replaces the real EKS client for every region. EKS is
	// regional and the live path builds one client per selected region; a test
	// double stands in for all of them.
	eksAPI awsdiscovery.EKSAPI

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

// NewAWSPermissionScanner constructs the scanner.
func NewAWSPermissionScanner(db *gorm.DB, onboarding *AWSOnboardingService) *AWSPermissionScanner {
	return &AWSPermissionScanner{
		db:          db,
		identities:  repositories.NewCloudIdentityRepository(db),
		grants:      repositories.NewCloudPermissionRepository(db),
		checkpoints: repositories.NewCloudScanCheckpointRepository(db),
		onboarding:  onboarding,
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
	out.Complete = snapshot.Coverage.Complete() &&
		oidcErr == nil && eksErr == nil &&
		out.ParseFailures == 0 && out.StatementsSkipped == 0
	out.Surfaces = map[string]models.SurfaceCoverage{
		models.SurfaceOIDCProviders:  surfaceResult(len(providers), oidcErr),
		models.SurfaceEKSPodIdentity: surfaceResult(out.PodIdentityEdges, eksErr),
	}
	if out.ParseFailures > 0 || out.StatementsSkipped > 0 {
		out.Surfaces[models.SurfacePolicyDocuments] = surfacePartial(
			out.PermissionsWritten+out.EdgesWritten,
			out.ParseFailures+out.StatementsSkipped,
			"policy or trust documents could not be fully read")
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
	out.Surfaces["resource_policies"] = surfaceResult(resourcePolicyCount, resourcePolicyErr)

	if out.Complete {
		edgesRemoved, permsRemoved, resRemoved, err := s.grants.ReconcileGeneration(
			workspaceID, snapshot.ConnectorID, snapshot.Generation)
		if err != nil {
			return out, err
		}
		_ = edgesRemoved
		_ = permsRemoved
		_ = resRemoved
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
// Returns the first error encountered. Regions are independent, so one region
// failing does not stop the others -- but any failure means this surface was
// not fully read, which the caller turns into "not complete" so nothing gets
// reconciled away.
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

	var firstErr error
	for _, region := range regions {
		reader, err := s.eksReaderFor(ctx, workspaceID, snapshot.ConnectorID, region)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		clusters, err := reader.Clusters(ctx)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		for _, cluster := range clusters {
			assocs, err := reader.PodIdentityAssociations(ctx, cluster.Name)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			for _, assoc := range assocs {
				if err := s.writePodIdentityEdge(workspaceID, snapshot, cluster, assoc, out); err != nil {
					return err
				}
			}
		}
	}
	return firstErr
}

// writePodIdentityEdge records one association.
func (s *AWSPermissionScanner) writePodIdentityEdge(
	workspaceID uuid.UUID, snapshot *IAMSnapshot,
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
	out.EdgesWritten++
	out.PodIdentityEdges++
	return nil
}

func (s *AWSPermissionScanner) writePermissions(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, out *PermissionSnapshot,
) error {
	// Sorted, not map order, because the checkpoint advanced below is a cursor
	// through this same order. Advancing it out of order would let a resumed
	// scan skip an identity that was never written -- see migration 017.
	arns := make([]string, 0, len(snapshot.Policies))
	for arn := range snapshot.Policies {
		arns = append(arns, arn)
	}
	sort.Strings(arns)

	done := 0
	for _, identityARN := range arns {
		policies := snapshot.Policies[identityARN]
		identity, err := s.identities.GetIdentityByNativeID(workspaceID, identityARN)
		if err != nil {
			if errors.Is(err, repositories.ErrCloudIdentityNotFound) {
				out.Skipped++
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
			if err := s.writePolicyDocument(workspaceID, snapshot, identity.ID, p.ARN, p.Document, out, grants); err != nil {
				return err
			}
		}
		for _, p := range policies.Inline {
			source := "inline:" + p.Name
			if err := s.writePolicyDocument(workspaceID, snapshot, identity.ID, source, p.Document, out, grants); err != nil {
				return err
			}
		}
		// The boundary's own statements, recorded as a ceiling. Written with a
		// distinct derivation so nothing counts them as access granted.
		if b := policies.Boundary; b != nil {
			source := "boundary:" + b.ARN
			if err := s.writePolicyDocument(workspaceID, snapshot, identity.ID, source, b.Document, out, boundaryOptions()); err != nil {
				return err
			}
		}

		// This identity's permissions are now durably written and stamped with
		// this generation, so the cursor may move past it. Advanced AFTER the
		// write, never before: a cursor ahead of the data would make a resumed
		// scan skip an identity nothing had recorded.
		done++
		if err := s.checkpoints.Advance(
			workspaceID, snapshot.ConnectorID, snapshot.Generation,
			models.ScanPhaseIdentityPolicies, identityARN, done,
		); err != nil {
			// A checkpoint that cannot be written costs efficiency on the next
			// attempt, not correctness of this one. Losing the scan over it
			// would be the worse trade.
			log.Printf("aws permission scan: checkpoint advance failed at %s: %v", identityARN, err)
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

// policySourceAPI names the AWS call a statement came from, so evidence points
// at something a reader can re-issue. An inline policy came from GetRolePolicy;
// anything else is a managed policy read through GetPolicyVersion.
func policySourceAPI(source string) string {
	switch {
	case strings.HasPrefix(source, "inline:"):
		return "iam:GetRolePolicy"
	case strings.HasPrefix(source, "boundary:"):
		return "iam:GetPolicyVersion (permissions boundary)"
	default:
		return "iam:GetPolicyVersion"
	}
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
func (s *AWSPermissionScanner) writePolicyDocument(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, identityID uuid.UUID,
	source, document string, out *PermissionSnapshot, opts policyWriteOptions,
) error {
	statements, skipped, err := awsdiscovery.ParsePolicyDocument(document)
	if err != nil {
		// A document we cannot read is a coverage failure, not an identity with
		// no permissions. Returning nil here is what used to make a malformed
		// managed policy look like an empty one.
		out.ParseFailures++
		return fmt.Errorf("parse policy %s: %w", source, err)
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
				if err := s.evidence.Record(
					PermissionSubject(stored.ID),
					policySourceAPI(source), models.SurfaceIAMPolicies, "",
					time.Now(), nativeID,
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
		if rerr != nil {
			log.Printf("aws permission scan: resource policy for %s: %v", c.NativeID, rerr)
			continue
		}
		checked++
		if s.evidence == nil || policy.Document == "" {
			continue
		}
		if werr := s.evidence.Record(
			ResourceSubject(c.ResourceID), resourcePolicySourceAPI(c.Kind),
			"resource_policies", "", time.Now(), c.NativeID,
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
	return checked, nil
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
