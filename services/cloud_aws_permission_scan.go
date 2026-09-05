package services

import (
	"context"
	"errors"
	"fmt"
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
	db         *gorm.DB
	identities repositories.CloudIdentityRepository
	grants     repositories.CloudPermissionRepository
	onboarding *AWSOnboardingService

	// api, when set, replaces the real IAM client -- the same test seam
	// AWSIAMScanner uses.
	api awsdiscovery.IAMAPI
}

// NewAWSPermissionScanner constructs the scanner.
func NewAWSPermissionScanner(db *gorm.DB, onboarding *AWSOnboardingService) *AWSPermissionScanner {
	return &AWSPermissionScanner{
		db:         db,
		identities: repositories.NewCloudIdentityRepository(db),
		grants:     repositories.NewCloudPermissionRepository(db),
		onboarding: onboarding,
	}
}

// WithIAMAPI installs a specific IAM client, bypassing assume-role.
func (s *AWSPermissionScanner) WithIAMAPI(api awsdiscovery.IAMAPI) *AWSPermissionScanner {
	s.api = api
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
	// only persisted so the EKS ticket, which resolves a Pod Identity
	// association's cluster by issuer, is not forced to make this same call
	// again for data this scan already read.
	OIDCProviders []awsdiscovery.OIDCProvider
	// Complete mirrors the identity scan's own coverage: this ticket cannot be
	// more complete than the data ticket [1] handed it, and OIDC providers
	// being unreadable also marks it incomplete.
	Complete bool
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

	// This ticket's own completeness is bounded by two independent signals:
	// ticket [1]'s scan must have reached everything (an incomplete IAM read
	// means an incomplete set of trust policies and statements to parse), and
	// the OIDC provider read must itself have succeeded.
	out.Complete = snapshot.Coverage.Complete() && oidcErr == nil

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

func (s *AWSPermissionScanner) writePermissions(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, out *PermissionSnapshot,
) error {
	for identityARN, policies := range snapshot.Policies {
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
