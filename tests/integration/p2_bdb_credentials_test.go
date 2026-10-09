package integration

// D-64 (P2-DECISIONS; SPEC-iga-phase2-graph.md §2.5): an access key keeps ONE
// iga_credentials row for life. Through the REAL scan worker and projector.

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"
)

// bdbCredRow is one iga_credentials row.
type bdbCredRow struct {
	ID          uuid.UUID
	Key         string
	Lifecycle   string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

func bdbCredentials(t *testing.T, l *p2Lab) map[string][]bdbCredRow {
	t.Helper()
	var rows []bdbCredRow
	if err := l.db.Raw(`SELECT id, key_identifier AS key, lifecycle, first_seen_at, last_seen_at
	                      FROM iga_credentials WHERE workspace_id = ? AND provider = 'aws'
	                     ORDER BY created_at, id`, l.ws).Scan(&rows).Error; err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	out := map[string][]bdbCredRow{}
	for _, r := range rows {
		out[r.Key] = append(out[r.Key], r)
	}
	return out
}

// D-64: ci-deployer holds two ACTIVE keys (a correct, common state: a new key
// never implies the old one was replaced). Key 1 turns Inactive and stays so
// for THREE more scans, then turns Active again. Throughout, each key is ONE
// row -- the row the first scan wrote, same id and first_seen_at -- whose
// lifecycle follows the provider's status (Inactive -> 'revoked', the M0
// mapping) and whose last_seen_at is each pass's timestamp. Key 2 is untouched.
//
// Before the fix every Inactive pass INSERTED another 'revoked' row beside the
// original, which stayed 'active' at its first reading: 028's partial unique
// index excludes revoked rows, so the upsert never conflicted.
//
// Safeguard (mutation-checked): UpsertCredential updates the key's existing
// row, found by source key regardless of lifecycle.
func TestP2BdbInactiveKeyKeepsOneRow(t *testing.T) {
	l := newP2Lab(t, "p2-bdb-d64", true)
	a := l.account(accountA)
	s3aUser(a, "ci-deployer", "AIDACIDEPLOYER000001")
	key1 := iamtypes.AccessKeyMetadata{AccessKeyId: aws.String("AKIABDBROTATE0000001"), UserName: aws.String("ci-deployer"),
		Status: iamtypes.StatusTypeActive, CreateDate: ago(100 * 24 * time.Hour)}
	key2 := iamtypes.AccessKeyMetadata{AccessKeyId: aws.String("AKIABDBROTATE0000002"), UserName: aws.String("ci-deployer"),
		Status: iamtypes.StatusTypeActive, CreateDate: ago(10 * 24 * time.Hour)}
	a.iam.keys["ci-deployer"] = []iamtypes.AccessKeyMetadata{key1, key2}
	l.scanAndProject(a)

	first := bdbCredentials(t, l)
	if len(first["AKIABDBROTATE0000001"]) != 1 || len(first["AKIABDBROTATE0000002"]) != 1 ||
		first["AKIABDBROTATE0000001"][0].Lifecycle != "active" || first["AKIABDBROTATE0000002"][0].Lifecycle != "active" {
		t.Fatalf("setup: credentials = %+v, want both keys, one active row each", first)
	}
	orig1, orig2 := first["AKIABDBROTATE0000001"][0], first["AKIABDBROTATE0000002"][0]

	expect := func(stage, lifecycle string, run uuid.UUID) {
		t.Helper()
		got := bdbCredentials(t, l)
		at := bdbPublishedAt(t, l, run)
		rows := got["AKIABDBROTATE0000001"]
		if len(rows) != 1 {
			t.Fatalf("%s: key 1 has %d rows %+v, want ONE", stage, len(rows), rows)
		}
		if r := rows[0]; r.ID != orig1.ID || !r.FirstSeenAt.Equal(orig1.FirstSeenAt) || r.Lifecycle != lifecycle ||
			!r.LastSeenAt.Equal(at) {
			t.Errorf("%s: key 1 = %+v, want the original row %s, first seen %s, %s, last seen %s",
				stage, r, orig1.ID, orig1.FirstSeenAt, lifecycle, at)
		}
		if r := got["AKIABDBROTATE0000002"]; len(r) != 1 || r[0].ID != orig2.ID || r[0].Lifecycle != "active" {
			t.Errorf("%s: key 2 = %+v, want its one active row %s", stage, r, orig2.ID)
		}
		if len(got) != 2 {
			t.Errorf("%s: credentials for %d keys, want 2: %+v", stage, len(got), got)
		}
	}

	key1.Status = iamtypes.StatusTypeInactive
	a.iam.keys["ci-deployer"] = []iamtypes.AccessKeyMetadata{key1, key2}
	for i := 1; i <= 3; i++ {
		time.Sleep(10 * time.Millisecond)
		run := l.scanAndProject(a)
		expect(fmt.Sprintf("inactive pass %d", i), "revoked", run.ID)
	}

	key1.Status = iamtypes.StatusTypeActive
	a.iam.keys["ci-deployer"] = []iamtypes.AccessKeyMetadata{key1, key2}
	time.Sleep(10 * time.Millisecond)
	run := l.scanAndProject(a)
	expect("reactivated", "active", run.ID)
}
