package services

import (
	"testing"

	"github.com/google/uuid"
)

// S3a (T3.5, §4.8): the subject stamp that keeps two orphaned observations
// apart, as pure logic. The end-to-end behaviour -- reconciliation deleting
// subjects with identical facts, in two accounts and across a detach,
// reattach and detach -- is proven in
// tests/integration/p2_s3a_orphaned_evidence_test.go.

// Two subjects with IDENTICAL facts hash apart; the same subject re-read hashes
// the same (the dedupe still absorbs an unchanged re-read); evidence with no
// subject is not stamped, so it still dedupes on content alone (025).
func TestS3aSubjectStampSeparatesEqualFacts(t *testing.T) {
	facts := map[string]any{"arn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "version_id": "v3"}
	hashOf := func(subject ObservationSubject) (map[string]any, string) {
		t.Helper()
		stamped, err := stampSubject(facts, subject.ref())
		if err != nil {
			t.Fatalf("stamp: %v", err)
		}
		_, hash, err := HashObservation(stamped)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		m, _ := stamped.(map[string]any)
		return m, hash
	}
	p1, p2 := uuid.New(), uuid.New()
	m1, h1 := hashOf(PolicySubject(p1))
	_, h1again := hashOf(PolicySubject(p1))
	_, h2 := hashOf(PolicySubject(p2))
	_, hPerm := hashOf(PermissionSubject(p1))
	if h1 == h2 {
		t.Error("two policy rows with identical facts hash alike: their orphans would collide")
	}
	if h1 != h1again {
		t.Error("the same subject re-read hashes differently: an unchanged read would grow the table")
	}
	if h1 == hPerm {
		t.Error("the stamp does not name the subject KIND")
	}
	if m1[ObservedSubjectFact] != "policy:"+p1.String() {
		t.Errorf("stamped facts = %v, want %s = policy:%s", m1, ObservedSubjectFact, p1)
	}
	if _, touched := facts[ObservedSubjectFact]; touched || len(facts) != 2 {
		t.Errorf("the caller's facts were modified: %v", facts)
	}

	// No subject: returned as given.
	same, err := stampSubject(facts, ObservationSubject{}.ref())
	if err != nil {
		t.Fatalf("stamp without subject: %v", err)
	}
	if m, ok := same.(map[string]any); !ok || len(m) != 2 {
		t.Errorf("subject-less facts = %v, want them unchanged", same)
	}
}

// Every subject kind stamps; nil facts become the stamp alone; facts that are
// not a JSON object cannot carry it and are refused rather than stored
// unstamped.
func TestS3aSubjectStampShapes(t *testing.T) {
	id := uuid.New()
	for want, subject := range map[string]ObservationSubject{
		"identity:" + id.String():   IdentitySubject(id),
		"permission:" + id.String(): PermissionSubject(id),
		"resource:" + id.String():   ResourceSubject(id),
		"workload:" + id.String():   WorkloadSubject(id),
		"policy:" + id.String():     PolicySubject(id),
	} {
		if got := subject.ref(); got != want {
			t.Errorf("ref = %q, want %q", got, want)
		}
	}
	stamped, err := stampSubject(nil, "policy:"+id.String())
	if m, ok := stamped.(map[string]any); err != nil || !ok || len(m) != 1 {
		t.Errorf("nil facts stamped = %v (%v), want only the stamp", stamped, err)
	}
	type s3aStructFacts struct {
		Name string `json:"name"`
	}
	stamped, err = stampSubject(s3aStructFacts{Name: "x"}, "policy:"+id.String())
	if m, ok := stamped.(map[string]any); err != nil || !ok || m["name"] != "x" || len(m) != 2 {
		t.Errorf("struct facts stamped = %v (%v), want its fields plus the stamp", stamped, err)
	}
	if _, err := stampSubject([]string{"not", "an", "object"}, "policy:"+id.String()); err == nil {
		t.Error("facts that are not an object were accepted: stored unstamped they collide once orphaned")
	}
	// A typed nil encodes as JSON null: refused, not stamped into a nil map.
	if _, err := stampSubject((*s3aStructFacts)(nil), "policy:"+id.String()); err == nil {
		t.Error("facts encoding as null were accepted")
	}
}
