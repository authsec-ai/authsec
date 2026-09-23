package igaread

// Pure pieces of the resource detail routes (resource_access.go,
// resource_detail.go): the statement rendering, the member-row state, the page
// cut by holder, and resource_policy's decision over deduplicated reads. The
// routes themselves are proven against PostgreSQL in
// tests/integration/p2_rdetail_*_test.go.

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Actions come back exactly as the statement wrote them -- a string or a list,
// Action or NotAction -- through the collector's own parser; the
// models.NativeRights fallback shape reads the same; nothing readable is [],
// never null.
func TestP2RDetailStatementActions(t *testing.T) {
	for _, tc := range []struct {
		name, native, actions, notActions string
	}{
		{"one action", `{"Sid":"A","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`, "[s3:GetObject]", "[]"},
		{"a list", `{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}`, "[s3:GetObject s3:ListBucket]", "[]"},
		{"NotAction", `{"Effect":"Deny","NotAction":"iam:*","Resource":"*"}`, "[]", "[iam:*]"},
		{"the NativeRights fallback", `{"effect":"allow","actions":["kms:Decrypt"],"not_actions":["kms:Delete*"]}`, "[kms:Decrypt]", "[kms:Delete*]"},
		{"nothing stored", ``, "[]", "[]"},
		{"not a statement", `"garbage"`, "[]", "[]"},
	} {
		a, n := rdetailStatementActions(json.RawMessage(tc.native))
		if a == nil || n == nil {
			t.Errorf("%s: actions %v not_actions %v, want [] rather than null", tc.name, a, n)
		}
		if fmt.Sprint(a) != tc.actions || fmt.Sprint(n) != tc.notActions {
			t.Errorf("%s: actions %v not_actions %v, want %s %s", tc.name, a, n, tc.actions, tc.notActions)
		}
	}
	idx := 1
	st := rdetailStatement(uuid.Nil, "S", &idx, nil, true)
	if st.Index == nil || *st.Index != 2 || !st.Conditional || st.Ref != "statement:"+uuid.Nil.String() {
		t.Errorf("statement = %+v, want the 1-based index 2 (D-84) and conditional", st)
	}
	if st := rdetailStatement(uuid.Nil, "", nil, nil, false); st.Index != nil {
		t.Errorf("a statement with no stored index renders index %v, want null", *st.Index)
	}
}

// D-18: a member row holds only while BOTH its grant and its membership do.
func TestP2RDetailWorseState(t *testing.T) {
	for _, tc := range [][3]string{
		{StateCurrent, StateCurrent, StateCurrent},
		{StateCurrent, StateStale, StateStale},
		{StateStale, StateCurrent, StateStale},
		{StateCurrent, StateEnded, StateEnded},
		{StateEnded, StateStale, StateEnded},
		{StateStale, StateEnded, StateEnded},
	} {
		if got := rdetailWorseState(tc[0], tc[1]); got != tc[2] {
			t.Errorf("rdetailWorseState(%s, %s) = %s, want %s", tc[0], tc[1], got, tc[2])
		}
	}
}

// The page is cut on HOLDERS: every row of a kept holder is on the page, the
// cursor is the last kept holder's key, and a further holder means more.
func TestP2RDetailAccessRowsCutOnHolders(t *testing.T) {
	h1, h2, h3 := uuid.New(), uuid.New(), uuid.New()
	scan := func(h uuid.UUID, name string) rdetailAccessScan {
		return rdetailAccessScan{K0: name, K2: "111122223333", HolderID: h, HolderName: name, GrantID: uuid.New(),
			GrantState: StateCurrent, StatementID: uuid.New(), PolicyID: uuid.New()}
	}
	scans := []rdetailAccessScan{scan(h1, "a"), scan(h1, "a"), scan(h2, "b"), scan(h2, "b"), scan(h2, "b"), scan(h3, "c")}
	accts := &Accounts{byAccount: map[string]*ConnectorInfo{}, byConnector: map[uuid.UUID]*ConnectorInfo{}}

	rows, last, more := rdetailAccessRows(scans, accts, 2)
	if len(rows) != 5 || !more || last.id != h2 || last.key.Name != "b" {
		t.Errorf("limit 2 = %d rows, more %v, last %v; want all 5 rows of a and b, more, cursor at b", len(rows), more, last)
	}
	rows, _, more = rdetailAccessRows(scans, accts, 3)
	if len(rows) != 6 || more {
		t.Errorf("limit 3 = %d rows, more %v; want every row and no more", len(rows), more)
	}
	if rows, _, more := rdetailAccessRows(nil, accts, 3); rows == nil || len(rows) != 0 || more {
		t.Errorf("no rows = %v more %v, want [] and no more", rows, more)
	}
}

// D-19 over deduplicated reads (resourcePolicyState). A row names only its
// first and latest readers and how many there were: read needs a PROVEN read
// by the revision, the latest proven read decides has_deny, and a disagreeing
// row that MAY have been read later makes has_deny null.
func TestP2RDetailResourcePolicyState(t *testing.T) {
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	at := func(h int) time.Time { return base.Add(time.Duration(h) * time.Hour) }
	yes, no := true, false
	obs := func(deny *bool, first, last int, count int, firstIn, lastIn bool) ResourcePolicyObservation {
		lc := at(last)
		return ResourcePolicyObservation{ID: uuid.New(), IngestedAt: at(first), LastConfirmedAt: &lc,
			ConfirmationCount: count, HasDeny: deny, ParseFailed: &no, FirstIn: firstIn, LastIn: lastIn}
	}
	published := at(10)
	render := func(st ResourcePolicyState) string {
		if st.HasDeny == nil {
			return fmt.Sprintf("read=%v has_deny=null", st.Read)
		}
		return fmt.Sprintf("read=%v has_deny=%v", st.Read, *st.HasDeny)
	}
	garbled := obs(&no, 1, 1, 1, true, true)
	garbled.ParseFailed = &yes
	for _, tc := range []struct {
		name string
		obs  []ResourcePolicyObservation
		want string
	}{
		{"nothing observed", nil, "read=false has_deny=null"},
		{"first and latest reader published", []ResourcePolicyObservation{obs(&yes, 1, 5, 4, true, true)}, "read=true has_deny=true"},
		// The reviewer's case: the first reader never published; a published run confirmed it.
		{"first reader unpublished, latest published", []ResourcePolicyObservation{obs(&yes, 1, 5, 2, false, true)}, "read=true has_deny=true"},
		{"latest reader in flight, first published", []ResourcePolicyObservation{obs(&yes, 1, 12, 5, true, false)}, "read=true has_deny=true"},
		// Neither named reader belongs: an unnamed read may, but nothing proves it (D-19's Raise).
		{"neither named reader published", []ResourcePolicyObservation{obs(&yes, 1, 12, 5, false, false)}, "read=false has_deny=null"},
		{"two reads, neither published", []ResourcePolicyObservation{obs(&yes, 1, 5, 2, false, false)}, "read=false has_deny=null"},
		{"unparsed", []ResourcePolicyObservation{garbled}, "read=true has_deny=null"},
		{"the Deny removed: the newer content wins", []ResourcePolicyObservation{
			obs(&yes, 1, 3, 3, true, true), obs(&no, 4, 6, 3, true, true)}, "read=true has_deny=false"},
		// Restored: the Deny's OLD row was re-read latest. First-recorded order would say false.
		{"the Deny restored onto its old row", []ResourcePolicyObservation{
			obs(&yes, 1, 8, 4, true, true), obs(&no, 4, 6, 3, true, true)}, "read=true has_deny=true"},
		// Restored, then a collection moves the old row's latest reader past the revision: it
		// may have been read after the other row's latest proven read. Undecidable.
		{"restored row's latest reader in flight", []ResourcePolicyObservation{
			obs(&yes, 1, 12, 5, false, false), obs(&no, 4, 6, 3, true, true)}, "read=true has_deny=null"},
		{"restored row's latest reader in flight, first published", []ResourcePolicyObservation{
			obs(&yes, 1, 12, 5, true, false), obs(&no, 4, 6, 3, true, true)}, "read=true has_deny=null"},
		// ... but a disagreeing row whose reads all precede the winner's proven read changes nothing,
		{"an older disagreeing row", []ResourcePolicyObservation{
			obs(&yes, 1, 3, 5, false, false), obs(&no, 4, 6, 3, true, true)}, "read=true has_deny=false"},
		// nor does an agreeing one,
		{"a later agreeing row", []ResourcePolicyObservation{
			obs(&no, 1, 12, 5, false, false), obs(&no, 4, 6, 3, true, true)}, "read=true has_deny=false"},
		// nor one with no unnamed reads (count 2: its only reads are the two it names).
		{"a later disagreeing row with no unnamed reads", []ResourcePolicyObservation{
			obs(&yes, 1, 12, 2, false, false), obs(&no, 4, 6, 3, true, true)}, "read=true has_deny=false"},
	} {
		if got := render(resourcePolicyState(tc.obs, published)); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}
