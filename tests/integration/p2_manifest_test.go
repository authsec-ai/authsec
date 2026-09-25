package integration

// D-57 (033, §4.8): iga_publication.manifest is every partition's watermark AS
// OF the revision, keyed by a partition key that covers scope and connector.
// Two accounts projected one after the other: the second publication's
// manifest still names the first account's run for the first account's
// partitions, and no key of one account is also a key of the other.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestP2ManifestIsCumulativeAcrossAccounts(t *testing.T) {
	l := newP2Lab(t, "p2-manifest-cumulative", true)
	a := oneLambda(l)
	b := l.account(accountB)
	b.role("OpsRole", "AROAOPSROLEOPSROLE01")
	b.attach("OpsRole", b.managed("OpsRead", docToolboxRead))

	runA := l.scanAndProject(a)
	runB := l.scanAndProject(b)

	manifest := func(rev int64) map[string]string {
		t.Helper()
		var raw json.RawMessage
		if err := l.db.Raw(`SELECT manifest FROM iga_publication WHERE workspace_id = ? AND rev = ?`, l.ws, rev).
			Row().Scan(&raw); err != nil {
			t.Fatalf("manifest of rev %d: %v", rev, err)
		}
		m := map[string]string{}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("manifest of rev %d: %v", rev, err)
		}
		return m
	}
	first, second := manifest(1), manifest(2)
	if len(first) == 0 {
		t.Fatal("setup: rev 1's manifest is empty")
	}

	// Every entry of rev 1 is still in rev 2 with the SAME run: account A's
	// partitions still stand on A's run after B published.
	for key, run := range first {
		if run != runA.ID.String() {
			t.Fatalf("rev 1 entry %q names run %s, want A's %s", key, run, runA.ID)
		}
		if got, ok := second[key]; !ok || got != runA.ID.String() {
			t.Errorf("rev 2 lost or rewrote A's partition %q: %q (want A's run %s)", key, got, runA.ID)
		}
	}
	// B's own partitions name B's run, and they are NEW keys: the connector is
	// in the key, so B never overwrote one of A's.
	var bKeys int
	for key, run := range second {
		if _, inFirst := first[key]; inFirst {
			continue
		}
		bKeys++
		if run != runB.ID.String() {
			t.Errorf("rev 2 entry %q names run %s, want B's %s", key, run, runB.ID)
		}
		if !strings.Contains(key, b.conn.String()) {
			t.Errorf("B's partition key %q does not carry B's connector %s", key, b.conn)
		}
	}
	if bKeys == 0 {
		t.Fatal("rev 2 added no partitions for B")
	}
	for key := range first {
		if !strings.Contains(key, a.conn.String()) || strings.Contains(key, b.conn.String()) {
			t.Errorf("A's partition key %q does not carry A's connector alone", key)
		}
	}

	// And the key is what the rows are stamped with: a support row's
	// partition_key names its own connector.
	var foreign int64
	l.db.Raw(`SELECT count(*) FROM iga_object_support WHERE workspace_id = ?
	            AND position(connector_id::text IN partition_key) = 0`, l.ws).Scan(&foreign)
	if foreign != 0 {
		t.Errorf("%d support rows carry a partition_key without their own connector", foreign)
	}
	_ = uuid.Nil
}

// The scope in every key is the REAL estate scope, the same one in the
// manifest, on the rows and on the watermarks: a key computed before the
// scope was resolved would never match a watermark, and the superseded check
// would silently pass everything.
func TestP2PartitionKeysCarryTheRealScope(t *testing.T) {
	l := newP2Lab(t, "p2-manifest-scope", true)
	a := oneLambda(l)
	l.scanAndProject(a)
	l.scanAndProject(a)

	nilScope := uuid.Nil.String()
	var raw json.RawMessage
	l.db.Raw(`SELECT manifest FROM iga_publication WHERE workspace_id = ? ORDER BY rev DESC LIMIT 1`, l.ws).Row().Scan(&raw)
	m := map[string]string{}
	_ = json.Unmarshal(raw, &m)
	for key := range m {
		if strings.HasPrefix(key, nilScope) {
			t.Fatalf("manifest key %q carries the nil scope", key)
		}
	}
	var bad int64
	l.db.Raw(`SELECT
	    (SELECT count(*) FROM iga_object_support WHERE workspace_id = ? AND partition_key LIKE ? || '%')
	  + (SELECT count(*) FROM iga_relationship WHERE workspace_id = ? AND partition_key LIKE ? || '%')
	  + (SELECT count(*) FROM iga_projection_state WHERE workspace_id = ?
	       AND partition_key NOT LIKE estate_scope_id::text || '%')`,
		l.ws, nilScope, l.ws, nilScope, l.ws).Row().Scan(&bad)
	if bad != 0 {
		t.Fatalf("%d rows carry a partition key whose scope is nil or not their own", bad)
	}
	var marks, inManifest int64
	l.db.Raw(`SELECT count(*) FROM iga_projection_state WHERE workspace_id = ?`, l.ws).Scan(&marks)
	for key := range m {
		var n int64
		l.db.Raw(`SELECT count(*) FROM iga_projection_state WHERE workspace_id = ? AND partition_key = ?`, l.ws, key).Scan(&n)
		inManifest += n
	}
	if marks == 0 || inManifest != marks {
		t.Fatalf("watermarks = %d, of which %d match a manifest key: the two must be the same keys", marks, inManifest)
	}
}
