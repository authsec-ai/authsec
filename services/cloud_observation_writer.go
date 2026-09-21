package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Evidence for the cloud collectors.
//
// The rule this file exists to enforce, in order and without exception:
//
//	AWS response -> delete sensitive fields -> canonical form -> hash
//
// Hashing first would be easier and is wrong. The hash is durable and
// deterministic, so a hash of a raw response retains a derivative of material
// we told the customer we would not store -- a Lambda environment variable
// value, a secret string that came back on a detail call. Redacting after
// hashing gives away the property while keeping the liability.

// redactedKeys are dropped from any fact payload, at any depth, before hashing.
//
// Matched case-insensitively on the key, because AWS is not consistent
// ("SecretString", "secretAccessKey", "Value" inside an env block) and a reader
// adding a collector should not have to know which spelling this release used.
var redactedKeys = map[string]bool{
	"secretstring":       true,
	"secretbinary":       true,
	"secretaccesskey":    true,
	"sessiontoken":       true,
	"password":           true,
	"privatekey":         true,
	"plaintext":          true,
	"ciphertextblob":     true,
	"clientsecret":       true,
	"authorizationtoken": true,
	// Lambda environment VALUES. The names are metadata worth keeping -- they
	// are what a framework-dependency rule reads -- but a value is a secret
	// often enough that the only safe rule is to drop every one.
	"variables": true,
}

// redactionMarker replaces a dropped value, so the shape of the response
// survives and a reader can see that something was removed rather than that
// AWS returned nothing.
const redactionMarker = "[redacted by authsec]"

// Redact removes sensitive values from a decoded AWS payload, in place-ish.
//
// Returns a new structure rather than mutating: the caller may still need the
// original to build its own rows, and a redactor that quietly emptied the
// caller's data would be a surprising kind of correct.
func Redact(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if redactedKeys[strings.ToLower(k)] {
				out[k] = redactionMarker
				continue
			}
			out[k] = Redact(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = Redact(val)
		}
		return out
	default:
		return v
	}
}

// canonicalJSON renders a value with map keys sorted, so two reads of the same
// unchanged data hash identically.
//
// Go's encoding/json already sorts map keys; this exists to make that a
// documented guarantee of the hash rather than an implementation detail
// somebody could optimise away.
func canonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	// Round-trip through a decoder to normalise number formatting, which
	// differs between a float parsed from JSON and one produced by the SDK.
	var normalised any
	if err := json.Unmarshal(b, &normalised); err != nil {
		return nil, err
	}
	return json.Marshal(normalised)
}

// HashObservation redacts, canonicalises and hashes in that order, returning
// both the payload to store and its hash.
//
// Callers must not hash anything themselves. The single entry point is what
// keeps the order from drifting.
func HashObservation(facts any) (json.RawMessage, string, error) {
	payload, err := canonicalJSON(Redact(facts))
	if err != nil {
		return nil, "", fmt.Errorf("canonicalise observation: %w", err)
	}
	sum := sha256.Sum256(payload)
	return payload, hex.EncodeToString(sum[:]), nil
}

// ObservationSubject names which cloud_* row an observation is about.
type ObservationSubject struct {
	IdentityID   *uuid.UUID
	PermissionID *uuid.UUID
	ResourceID   *uuid.UUID
	WorkloadID   *uuid.UUID
}

// IdentitySubject and friends keep call sites from constructing the struct by
// hand and accidentally setting two fields, which the database would reject at
// the end of a long scan rather than at the line that caused it.
func IdentitySubject(id uuid.UUID) ObservationSubject   { return ObservationSubject{IdentityID: &id} }
func PermissionSubject(id uuid.UUID) ObservationSubject { return ObservationSubject{PermissionID: &id} }
func ResourceSubject(id uuid.UUID) ObservationSubject   { return ObservationSubject{ResourceID: &id} }
func WorkloadSubject(id uuid.UUID) ObservationSubject   { return ObservationSubject{WorkloadID: &id} }

// ObservationWriter records evidence for one scan run.
//
// Constructed per run so the run id, generation and connector are supplied once
// rather than threaded through every collector call site.
type ObservationWriter struct {
	db          *gorm.DB
	workspaceID uuid.UUID
	connectorID uuid.UUID
	runID       uuid.UUID
	generation  int

	written int
	skipped int
}

// NewObservationWriter returns a writer, or nil when there is no run to anchor
// evidence to.
//
// Nil is usable: every method tolerates a nil receiver and does nothing. That
// keeps the collectors free of "if writer != nil" at every call, and means a
// path that has no run -- a test, a legacy caller -- degrades to writing no
// evidence rather than panicking.
func NewObservationWriter(
	db *gorm.DB, workspaceID, connectorID, runID uuid.UUID, generation int,
) *ObservationWriter {
	if runID == uuid.Nil || generation <= 0 {
		return nil
	}
	return &ObservationWriter{
		db: db, workspaceID: workspaceID, connectorID: connectorID,
		runID: runID, generation: generation,
	}
}

// Record writes one observation, deduplicating on unchanged content.
//
// An unchanged re-read writes no NEW row -- the unique index on (workspace,
// subject, source_api, content_hash) absorbs it -- but it does update
// last_confirmed_run_id/at and bump confirmation_count on the existing row.
// Storage stays flat for an account nobody is changing, while reconciliation
// still gets an answer to "did this run see this fact", which a plain
// DO NOTHING would have thrown away silently.
//
// subjectNativeID is the AWS-native id (ARN, role name, ...) of the subject,
// stored on the row itself so it stays legible as "evidence for X" even after
// reconciliation deletes the subject and SETs NULL the FK that used to say so.
func (w *ObservationWriter) Record(
	subject ObservationSubject, sourceAPI, surface, surfaceState string,
	observedAt time.Time, subjectNativeID string, facts any,
) error {
	if w == nil {
		return nil
	}
	payload, hash, err := HashObservation(facts)
	if err != nil {
		return err
	}
	if observedAt.IsZero() {
		// An observation with no provider time is still evidence, but it must
		// not claim a time it does not have. Ingestion time is the honest
		// fallback and is distinguishable because ingested_at equals it.
		observedAt = time.Now()
	}
	now := time.Now()

	obs := &models.CloudObservation{
		WorkspaceID:        w.workspaceID,
		ConnectorID:        w.connectorID,
		ScanRunID:          w.runID,
		Generation:         w.generation,
		IdentityID:         subject.IdentityID,
		PermissionID:       subject.PermissionID,
		ResourceID:         subject.ResourceID,
		WorkloadID:         subject.WorkloadID,
		SourceAPI:          sourceAPI,
		Surface:            surface,
		SurfaceState:       surfaceState,
		ObservedAt:         observedAt,
		SanitizedFacts:     payload,
		ContentHash:        hash,
		SubjectNativeID:    subjectNativeID,
		LastConfirmedRunID: &w.runID,
		LastConfirmedAt:    &now,
		ConfirmationCount:  1,
	}

	// Two different unique indexes back this dedupe, and the row being written
	// decides which one applies. uq_cloud_observation_dedupe (022) is keyed on
	// COALESCE(identity_id, permission_id, resource_id, workload_id) -- correct
	// for the four ordinary subjects, but COALESCE over four NULLs is NULL, and
	// Postgres never treats two NULLs as equal for uniqueness. A subject-less
	// row (AgentCore Workload Identities today -- see the ObservationSubject
	// caller in scanWorkloadIdentities) would insert a fresh row every scan
	// under that index regardless of content. uq_cloud_observation_dedupe_no_subject
	// (025) is the fix: a partial index scoped to exactly the rows the first
	// one cannot dedupe.
	//
	// Neither is named ON CONSTRAINT: the first is on an EXPRESSION
	// (COALESCE(...)), which Postgres cannot convert into a named UNIQUE
	// constraint, so both targets are repeated by column list instead, same as
	// each other for consistency. The COALESCE entry sets Raw: true so GORM
	// emits it verbatim; without that it quotes every Column.Name as a plain
	// identifier, turning the expression into a single invalid, literally-quoted
	// column name instead of the function call Postgres needs to match the index.
	hasSubject := subject.IdentityID != nil || subject.PermissionID != nil ||
		subject.ResourceID != nil || subject.WorkloadID != nil

	conflict := clause.OnConflict{
		DoUpdates: clause.Assignments(map[string]interface{}{
			"last_confirmed_run_id": w.runID,
			"last_confirmed_at":     now,
			"confirmation_count":    gorm.Expr("cloud_observation.confirmation_count + 1"),
		}),
	}
	if hasSubject {
		conflict.Columns = []clause.Column{
			{Name: "workspace_id"},
			{Name: "COALESCE(identity_id, permission_id, resource_id, workload_id)", Raw: true},
			{Name: "source_api"},
			{Name: "content_hash"},
		}
	} else {
		conflict.Columns = []clause.Column{
			{Name: "workspace_id"}, {Name: "source_api"}, {Name: "content_hash"},
		}
		// Matching a PARTIAL index requires the inference clause to repeat its
		// predicate -- Postgres will not infer a partial index from the column
		// list alone.
		conflict.TargetWhere = clause.Where{Exprs: []clause.Expression{clause.Expr{
			SQL: "identity_id IS NULL AND permission_id IS NULL AND resource_id IS NULL AND workload_id IS NULL",
		}}}
	}

	// Insert vs. confirm-only is told apart the same way UpsertWorkload and
	// friends already do it elsewhere in this package: propose an id, ask for
	// it back with Returning, and compare. On conflict, Postgres returns the
	// EXISTING row -- whose id is not the one we proposed -- so a mismatch
	// means this call confirmed a fact it did not create.
	proposed := uuid.New()
	obs.ID = proposed

	res := w.db.Clauses(conflict, clause.Returning{}).Create(obs)
	if res.Error != nil {
		return fmt.Errorf("record observation (%s): %w", sourceAPI, res.Error)
	}
	if obs.ID == proposed {
		w.written++
	} else {
		w.skipped++
	}
	return nil
}

// Counts reports what this run's evidence writing did. Written plus skipped is
// how many facts were offered; skipped alone is how much was unchanged.
func (w *ObservationWriter) Counts() (written, skipped int) {
	if w == nil {
		return 0, 0
	}
	return w.written, w.skipped
}

// SurfaceStateOf reads a surface's state out of a coverage report, for stamping
// on to the evidence collected under it. Empty when the surface is unknown,
// which is itself worth recording rather than guessing "reached".
func SurfaceStateOf(coverage models.ScanCoverage, surface string) string {
	if s, ok := coverage.Surfaces[surface]; ok {
		return s.State
	}
	return ""
}
