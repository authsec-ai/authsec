package collectorcontract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// NegotiatedCapability describes what optional fields a collector supports.
// It is carried inside SyncRequest.Capabilities (json.RawMessage) and the
// digest of its canonical form is in SyncRequest.CapabilityDigest.
type NegotiatedCapability struct {
	// ActionDetailVersion is the version of ActionDetail the collector emits.
	// Empty means the collector does not emit ActionDetail.
	ActionDetailVersion string `json:"action_detail_version,omitempty"`
	// ObservationFields lists the optional observation fields the collector
	// populates (e.g. "action_detail", "source").
	ObservationFields []string `json:"observation_fields,omitempty"`
	// ObjectFields lists optional object fields (e.g. "credential_provenance").
	ObjectFields []string `json:"object_fields,omitempty"`
}

// CapabilityDigest computes the SHA-256 hex digest of a NegotiatedCapability
// in canonical form (sorted keys, deterministic JSON).
func CapabilityDigest(cap NegotiatedCapability) (string, error) {
	// Normalize: sort field lists for determinism.
	sorted := NegotiatedCapability{
		ActionDetailVersion: cap.ActionDetailVersion,
		ObservationFields:   sortedCopy(cap.ObservationFields),
		ObjectFields:        sortedCopy(cap.ObjectFields),
	}
	b, err := json.Marshal(sorted)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func sortedCopy(ss []string) []string {
	if len(ss) == 0 {
		return ss
	}
	out := make([]string, len(ss))
	copy(out, ss)
	sort.Strings(out)
	return out
}
