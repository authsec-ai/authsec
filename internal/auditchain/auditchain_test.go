package auditchain

import (
	"testing"
	"time"
)

func sp(s string) *string { return &s }

// chain builds n linked rows of one workspace.
func chain(n int) []Row {
	ts := time.Date(2026, 11, 1, 10, 0, 0, 123456000, time.UTC)
	var out []Row
	prev := Genesis
	for i := 1; i <= n; i++ {
		t := ts.Add(time.Duration(i) * time.Minute)
		code := int64(200)
		r := Row{ID: int64(100 + i), WorkspaceID: "ws-a", Seq: int64(i), PrevHash: prev,
			RecordClass: sp("admin_change"), UserID: sp("u1"), Action: sp("update"), Method: sp("PUT"),
			StatusCode: &code, NewValues: sp(`{"a": 1}`), Timestamp: &t}
		r.Hash = Hash(r)
		prev = r.Hash
		out = append(out, r)
	}
	return out
}

func walk(rows []Row, gaps []Gap, anchors []Anchor, startSeq int64, startHash string) *Verifier {
	v := NewVerifier(gaps)
	v.Start(startSeq, startHash, true)
	for _, r := range rows {
		v.Next(r)
	}
	last := int64(0)
	if len(rows) > 0 {
		last = rows[len(rows)-1].Seq
	}
	v.Finish(last, anchors)
	return v
}

func TestCanonicalEncodesNullAndLength(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 6000, time.UTC)
	r := Row{ID: 1, WorkspaceID: "w1", Seq: 1, PrevHash: Genesis, Action: sp("a"), OldValues: sp(`{"a": [1, 2], "b": 1}`), Timestamp: &ts}
	got := Canonical(r)
	want := "authsec.audit.v1|1:1|2:w1|1:1|64:" + Genesis + "|~|~|~|~|1:a|~|~|~|~|~|~|~|~|21:{\"a\": [1, 2], \"b\": 1}|~|~|27:2026-01-02T03:04:05.000006Z"
	if got != want {
		t.Fatalf("canonical:\n got %s\nwant %s", got, want)
	}
	// A value cannot imitate a separator: "a|1:b" and two fields differ.
	x := Row{ID: 1, Action: sp("a|1:b")}
	y := Row{ID: 1, Action: sp("a"), Resource: sp("b")}
	if Canonical(x) == Canonical(y) {
		t.Fatal("canonical form is ambiguous")
	}
}

func TestVerifyIntactChain(t *testing.T) {
	rows := chain(5)
	v := walk(rows, nil, []Anchor{{LastSeq: 3, HeadHash: rows[2].Hash, Day: "d"}}, 1, Genesis)
	if !v.OK() || v.Rows != 5 {
		t.Fatalf("intact chain: %+v", v.Breaks)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	rows := chain(5)
	rows[2].Action = sp("delete") // content changed, hash kept
	v := walk(rows, nil, nil, 1, Genesis)
	if v.OK() || v.Breaks[0].Kind != BreakHash || v.Breaks[0].Seq != 3 {
		t.Fatalf("tamper not detected: %+v", v.Breaks)
	}
}

func TestVerifyDetectsRewrittenLink(t *testing.T) {
	rows := chain(5)
	// An attacker rewrites row 3 and recomputes its hash: row 4's prev_hash
	// no longer matches.
	rows[2].Action = sp("delete")
	rows[2].Hash = Hash(rows[2])
	v := walk(rows, nil, nil, 1, Genesis)
	if v.OK() || v.Breaks[0].Kind != BreakLink || v.Breaks[0].Seq != 4 {
		t.Fatalf("rewritten link not detected: %+v", v.Breaks)
	}
}

func TestVerifyMissingRowsWithoutGap(t *testing.T) {
	rows := chain(6)
	cut := append(append([]Row{}, rows[:2]...), rows[4:]...) // seq 3,4 removed
	v := walk(cut, nil, nil, 1, Genesis)
	if v.OK() || v.Breaks[0].Kind != BreakMissing || v.Breaks[0].Seq != 3 || v.Breaks[0].ToSeq != 4 {
		t.Fatalf("missing rows not reported: %+v", v.Breaks)
	}
	if len(v.Breaks) != 1 {
		t.Fatalf("one hole must be reported once: %+v", v.Breaks)
	}
}

func TestVerifyAcrossRetentionGaps(t *testing.T) {
	rows := chain(10)
	// Purged: 1-3 and 5-6 (4 held), then 7 in a later purge (adjacent gap).
	gaps := []Gap{
		{FromSeq: 1, ToSeq: 3, PrevHash: Genesis, LastHash: rows[2].Hash},
		{FromSeq: 5, ToSeq: 6, PrevHash: rows[3].Hash, LastHash: rows[5].Hash},
		{FromSeq: 7, ToSeq: 7, PrevHash: rows[5].Hash, LastHash: rows[6].Hash},
	}
	left := []Row{rows[3], rows[7], rows[8], rows[9]}
	anchors := []Anchor{{LastSeq: 6, HeadHash: rows[5].Hash, Day: "d1"}, {LastSeq: 9, HeadHash: rows[8].Hash, Day: "d2"}}
	v := walk(left, gaps, anchors, 1, Genesis)
	if !v.OK() {
		t.Fatalf("purged chain must verify: %+v", v.Breaks)
	}
	if v.GapsCrossed != 3 {
		t.Fatalf("gaps crossed = %d", v.GapsCrossed)
	}
	// A forged gap (wrong hashes) does not join the chain.
	bad := append([]Gap{}, gaps...)
	bad[1].PrevHash = Genesis
	v = walk(left, bad, nil, 1, Genesis)
	if v.OK() || v.Breaks[0].Kind != BreakGap {
		t.Fatalf("forged gap not detected: %+v", v.Breaks)
	}
}

func TestVerifyAnchorMismatch(t *testing.T) {
	rows := chain(4)
	v := walk(rows, nil, []Anchor{{LastSeq: 2, HeadHash: Genesis, Day: "d"}}, 1, Genesis)
	if v.OK() || v.Breaks[0].Kind != BreakAnchor {
		t.Fatalf("anchor mismatch not detected: %+v", v.Breaks)
	}
}

func TestVerifyWindowStartsMidChain(t *testing.T) {
	rows := chain(8)
	// Window over 5..8: the walk starts from row 4's hash.
	v := walk(rows[4:], nil, nil, 5, rows[3].Hash)
	if !v.OK() || v.FirstSeq != 5 {
		t.Fatalf("mid-chain window: %+v", v.Breaks)
	}
	// Starting from a wrong predecessor hash is a link break.
	v = walk(rows[4:], nil, nil, 5, Genesis)
	if v.OK() || v.Breaks[0].Kind != BreakLink {
		t.Fatalf("wrong start not detected: %+v", v.Breaks)
	}
}
