package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/compile"
	"github.com/authsec-ai/authsec/internal/runtimepolicy/profiles"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/pkg/policybundle"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	ErrArtifactNotFound = errors.New("policy artifact not found")
)

// PolicyArtifactService compiles V2 documents into signed binary policy packages
// and stores them in content-addressed storage keyed by SHA-256.
type PolicyArtifactService struct {
	db         *gorm.DB
	compiler   *PolicyCompiler
	signingKey *ecdsa.PrivateKey
	keyID      string
}

// NewPolicyArtifactService creates a new artifact service.
func NewPolicyArtifactService(db *gorm.DB, reg *profiles.Registry, signingKey *ecdsa.PrivateKey, keyID string) *PolicyArtifactService {
	return &PolicyArtifactService{
		db:         db,
		compiler:   NewPolicyCompiler(reg),
		signingKey: signingKey,
		keyID:      keyID,
	}
}

// PolicyArtifact is the stored immutable bundle + signed manifest.
type PolicyArtifact struct {
	ID              uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID     uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	PolicyID        uuid.UUID `json:"policy_id" gorm:"type:uuid;not null"`
	Revision        int       `json:"revision" gorm:"not null"`
	ArtifactSHA256  string    `json:"artifact_sha256" gorm:"type:text;not null;uniqueIndex"`
	ArtifactLength  int       `json:"artifact_length" gorm:"not null"`
	ArtifactData    []byte    `json:"-" gorm:"type:bytea;not null"`
	SignedManifest  string    `json:"signed_manifest" gorm:"type:text;not null"`
	Backend         string    `json:"backend" gorm:"type:text;not null"`
	Profile         string    `json:"profile" gorm:"type:text;not null"`
	CompilerVersion string    `json:"compiler_version" gorm:"type:text;not null"`
	CreatedAt       time.Time `json:"created_at"`
}

func (PolicyArtifact) TableName() string { return "policy_artifacts" }

// BuildAndStore compiles a V2 document into a signed bundle, stores the artifact,
// and returns the manifest reference.
func (s *PolicyArtifactService) BuildAndStore(ctx context.Context, actor Actor, policyID uuid.UUID, revision int, doc models.RuntimePolicyV2Document) (*PolicyArtifact, error) {
	// Compile the V2 document.
	cat := dbCatalog{tx: s.db.WithContext(ctx)}
	compileResult, err := s.compiler.Compile(ctx, cat, actor.WorkspaceID, revision, doc)
	if err != nil {
		return nil, err
	}

	// Build the bundle.
	canonical, _, err := compile.CanonicalV2(doc)
	if err != nil {
		return nil, err
	}

	// Check if OPA Rego was generated (only for gateway broker rules).
	var generatedRego string
	if compileResult.NativePlan != nil {
		var planCheck struct{ Rego string `json:"rego"` }
		_ = json.Unmarshal(compileResult.NativePlan, &planCheck)
		generatedRego = planCheck.Rego
	}

	bundle := &policybundle.Bundle{
		Header: policybundle.Header{
			FormatVersion:    "aspol.v1",
			CompilerBuild:    compileResult.CompilerVersion,
			SchemaVersions:   []string{models.RuntimePolicyFormatV2},
			WorkloadTarget:   workloadTarget(doc),
			Backend:          doc.Enforcement.Backend,
			Profile:          compileResult.BackendProfile,
			CapabilityDigest: compileResult.CapabilityDigest,
		},
		Source: policybundle.Source{
			JSON:          canonical,
			GeneratedRego: generatedRego,
			SourceHashes:  policybundle.ComputeSourceHashes(canonical, generatedRego, nil),
		},
		RuleMap:    toRuleMapEntries(compileResult.RuleMap),
		NativePlan: compileResult.NativePlan,
		Dependencies: policybundle.Dependencies{
			RuntimeABI:       "authsec.v2",
			RequiredControls: doc.RequiredControls,
		},
		ProbePlan: policybundle.ProbePlan{Probes: []policybundle.Probe{}},
	}

	// Serialize and hash.
	bundleData, err := bundle.Serialize()
	if err != nil {
		return nil, fmt.Errorf("policy artifact: serialize: %w", err)
	}
	sum := sha256.Sum256(bundleData)
	artifactHash := hex.EncodeToString(sum[:])

	// Check for existing artifact with same hash (content-addressed dedup).
	var existing PolicyArtifact
	if err := s.db.WithContext(ctx).Where("artifact_sha256 = ?", artifactHash).First(&existing).Error; err == nil {
		return &existing, nil
	}

	// Build and sign the manifest.
	manifest := policybundle.BundleManifest{
		ArtifactSHA256:      artifactHash,
		ArtifactLength:      len(bundleData),
		Format:              "aspol.v1",
		Tenant:              actor.WorkspaceID.String(),
		Workspace:           actor.WorkspaceID.String(),
		TargetWorkload:      workloadTarget(doc),
		Backend:             doc.Enforcement.Backend,
		Profile:             compileResult.BackendProfile,
		CapabilityDigest:    compileResult.CapabilityDigest,
		CanonicalPolicyHash: compileResult.CanonicalHash,
		CompilerBuild:       compileResult.CompilerVersion,
		DeliveryEpoch:       time.Now().Unix(),
		DeliveryRevision:    revision,
		IssueTime:           time.Now().UTC(),
		NotBefore:           time.Now().UTC(),
		Expiry:              time.Now().UTC().Add(30 * 24 * time.Hour), // 30-day default
	}

	var signedManifest string
	if s.signingKey != nil {
		signed, err := policybundle.Sign(manifest, s.signingKey, s.keyID)
		if err != nil {
			return nil, fmt.Errorf("policy artifact: sign: %w", err)
		}
		signedManifest = signed
	} else {
		// No signing key configured — store unsigned manifest JSON.
		raw, _ := json.Marshal(manifest)
		signedManifest = string(raw)
	}

	// Store the artifact.
	artifact := PolicyArtifact{
		ID:              uuid.New(),
		WorkspaceID:     actor.WorkspaceID,
		PolicyID:        policyID,
		Revision:        revision,
		ArtifactSHA256:  artifactHash,
		ArtifactLength:  len(bundleData),
		ArtifactData:    bundleData,
		SignedManifest:  signedManifest,
		Backend:         doc.Enforcement.Backend,
		Profile:         compileResult.BackendProfile,
		CompilerVersion: compileResult.CompilerVersion,
	}

	if err := s.db.WithContext(ctx).Create(&artifact).Error; err != nil {
		return nil, fmt.Errorf("policy artifact: store: %w", err)
	}
	return &artifact, nil
}

// Get retrieves an artifact by SHA-256 hash. Access requires authenticated
// recipient and correct workspace.
func (s *PolicyArtifactService) Get(ctx context.Context, workspaceID uuid.UUID, sha256Hash string) (*PolicyArtifact, error) {
	var artifact PolicyArtifact
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND artifact_sha256 = ?", workspaceID, sha256Hash).
		First(&artifact).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &StatusError{Status: http.StatusNotFound, Code: "not_found", Message: "artifact not found"}
		}
		return nil, err
	}
	return &artifact, nil
}

func workloadTarget(doc models.RuntimePolicyV2Document) string {
	if len(doc.Targets.WorkloadIDs) > 0 {
		return doc.Targets.WorkloadIDs[0]
	}
	return ""
}

func toRuleMapEntries(entries []compile.V2RuleMapEntry) []policybundle.RuleMapEntry {
	out := make([]policybundle.RuleMapEntry, len(entries))
	for i, e := range entries {
		out[i] = policybundle.RuleMapEntry{
			RuleID:            e.RuleID,
			Primitive:         e.Primitive,
			NativeControls:    e.NativeControls,
			ResourceDecisions: e.Decisions,
		}
	}
	return out
}
