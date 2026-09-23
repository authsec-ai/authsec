package igaread

// Pure pieces of the resource detail routes (resource_access.go): the
// statement rendering, the member-row state, and the page cut by holder. The
// routes themselves are proven against PostgreSQL in
// tests/integration/p2_rdetail_*_test.go.

import (
	"encoding/json"
	"fmt"
	"testing"

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
