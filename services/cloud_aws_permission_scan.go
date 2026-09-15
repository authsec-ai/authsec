package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

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

// PermissionSnapshot is what one permission scan wrote.
type PermissionSnapshot struct {
	ConnectorID        uuid.UUID
	Generation         int
	EdgesWritten       int
	PermissionsWritten int
	ResourcesWritten   int
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
	out.Complete = snapshot.Coverage.Complete() && oidcErr == nil && eksErr == nil
	out.Surfaces = map[string]models.SurfaceCoverage{
		models.SurfaceOIDCProviders:  surfaceResult(len(providers), oidcErr),
		models.SurfaceEKSPodIdentity: surfaceResult(out.PodIdentityEdges, eksErr),
	}

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

		for _, p := range awsdiscovery.ParseTrustPolicy(doc) {
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

		for _, p := range policies.Attached {
			if err := s.writePolicyDocument(workspaceID, snapshot, identity.ID, p.ARN, p.Document, out); err != nil {
				return err
			}
		}
		for _, p := range policies.Inline {
			source := "inline:" + p.Name
			if err := s.writePolicyDocument(workspaceID, snapshot, identity.ID, source, p.Document, out); err != nil {
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
	source, document string, out *PermissionSnapshot,
) error {
	for i, stmt := range awsdiscovery.ParsePolicyDocument(document) {
		nativeID := fmt.Sprintf("%s#s%d", source, i)
		resources := stmt.Resources
		if len(resources) == 0 {
			// No concrete Resource field (NotResource, or an empty list) --
			// one unresourced row, broad by construction.
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
				ScopeKind:          scopeKind,
				Derivation:         models.PermissionDerivationGranted,
				Sensitivity:        sensitivity,
				NativeID:           nativeID,
				LastSeenGeneration: snapshot.Generation,
			}
			if _, _, err := s.grants.UpsertPermission(perm); err != nil {
				return fmt.Errorf("record permission %s: %w", nativeID, err)
			}
			out.PermissionsWritten++
		}
	}
	return nil
}

func (s *AWSPermissionScanner) getOrCreateResource(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, typed *awsdiscovery.TypedResource, out *PermissionSnapshot,
) (uuid.UUID, error) {
	resource := &models.CloudResource{
		WorkspaceID:        workspaceID,
		ConnectorID:        snapshot.ConnectorID,
		Kind:               typed.Kind,
		NativeID:           typed.NativeID,
		Name:               typed.Name,
		Sensitivity:        resourceSensitivity(typed.Service),
		LastSeenGeneration: snapshot.Generation,
	}
	stored, created, err := s.grants.UpsertResource(resource)
	if err != nil {
		return uuid.Nil, fmt.Errorf("record resource %s: %w", typed.NativeID, err)
	}
	if created {
		out.ResourcesWritten++
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
	if highSensitivityServices[strings.ToLower(service)] {
		return models.SensitivityHigh
	}
	return models.SensitivityLow
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
