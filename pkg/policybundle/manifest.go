package policybundle

import (
	"time"
)

// BundleManifest is the signed metadata about a policy bundle. It contains
// all the fields needed to verify that a bundle is authentic, targeted at the
// correct recipient, and within its validity window.
type BundleManifest struct {
	ArtifactSHA256      string    `json:"artifact_sha256"`
	ArtifactLength      int       `json:"artifact_length"`
	Format              string    `json:"format"`                // "aspol.v1"
	Tenant              string    `json:"tenant"`
	Workspace           string    `json:"workspace"`
	TargetWorkload      string    `json:"target_workload"`
	TargetExecution     string    `json:"target_execution,omitempty"`
	AllowedRecipient    string    `json:"allowed_recipient"`     // SPIFFE URI or enrollment ID
	Backend             string    `json:"backend"`
	Profile             string    `json:"profile"`
	CapabilityDigest    string    `json:"capability_digest"`
	CanonicalPolicyHash string    `json:"canonical_policy_hash"`
	CompilerBuild       string    `json:"compiler_build"`
	DeliveryEpoch       int64     `json:"delivery_epoch"`
	DeliveryRevision    int       `json:"delivery_revision"`
	IssueTime           time.Time `json:"issue_time"`
	NotBefore           time.Time `json:"not_before"`
	Expiry              time.Time `json:"expiry"`
	ApprovalRef         string    `json:"approval_ref,omitempty"`
}

// ValidAt reports whether the manifest is valid at the given time.
func (m *BundleManifest) ValidAt(t time.Time) bool {
	if t.Before(m.NotBefore) {
		return false
	}
	if !m.Expiry.IsZero() && !t.Before(m.Expiry) {
		return false
	}
	return true
}

// MatchesRecipient reports whether the manifest allows the given recipient.
func (m *BundleManifest) MatchesRecipient(recipient string) bool {
	return m.AllowedRecipient == "" || m.AllowedRecipient == recipient
}

// MatchesArtifact reports whether the manifest matches the given artifact hash
// and length.
func (m *BundleManifest) MatchesArtifact(sha256 string, length int) bool {
	return m.ArtifactSHA256 == sha256 && m.ArtifactLength == length
}
