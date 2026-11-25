// Package auditchain recomputes and verifies the audit_events hash chains
// (migration 167, SPEC-secops-backend-upgrade.md F7).
//
// The database assigns every new audit_events row its link -- seq, prev_hash
// and hash = sha256(canonical form) -- in the trigger audit_events_chain,
// under a per-chain advisory lock. This package builds the SAME canonical
// form in Go (Canonical), so verification recomputes each hash without
// trusting the database function that wrote it, and walks a chain (Verify)
// across the runs a retention purge removed (gaps) and against the daily
// anchors. It has no database access: the caller loads rows, gaps and
// anchors (services/audit_governance_chain.go).
package auditchain

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// Genesis is the prev_hash of the first link of every chain.
var Genesis = strings.Repeat("0", 64)

// Row is one chained audit_events row as read back from the database. The
// JSON columns are their jsonb text (old_values::text), which is canonical.
type Row struct {
	ID          int64
	WorkspaceID string
	Seq         int64
	PrevHash    string
	Hash        string
	RecordClass *string
	RequestID   *string
	ActorRealm  *string
	UserID      *string
	Action      *string
	Resource    *string
	ResourceID  *string
	Method      *string
	Path        *string
	UserAgent   *string
	ClientIP    *string
	StatusCode  *int64
	Duration    *int64
	OldValues   *string
	NewValues   *string
	Error       *string
	Timestamp   *time.Time
}

func field(b *strings.Builder, v *string) {
	b.WriteByte('|')
	if v == nil {
		b.WriteByte('~')
		return
	}
	b.WriteString(strconv.Itoa(len(*v)))
	b.WriteByte(':')
	b.WriteString(*v)
}

func str(s string) *string { return &s }

func num(n *int64) *string {
	if n == nil {
		return nil
	}
	return str(strconv.FormatInt(*n, 10))
}

// FormatTimestamp is the canonical timestamp: UTC, microseconds, the form
// to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') gives.
func FormatTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}

// Canonical is public.audit_event_canonical(e) for r.
func Canonical(r Row) string {
	var b strings.Builder
	b.WriteString("authsec.audit.v1")
	field(&b, str(strconv.FormatInt(r.ID, 10)))
	field(&b, str(r.WorkspaceID))
	field(&b, str(strconv.FormatInt(r.Seq, 10)))
	field(&b, str(r.PrevHash))
	field(&b, r.RecordClass)
	field(&b, r.RequestID)
	field(&b, r.ActorRealm)
	field(&b, r.UserID)
	field(&b, r.Action)
	field(&b, r.Resource)
	field(&b, r.ResourceID)
	field(&b, r.Method)
	field(&b, r.Path)
	field(&b, r.UserAgent)
	field(&b, r.ClientIP)
	field(&b, num(r.StatusCode))
	field(&b, num(r.Duration))
	field(&b, r.OldValues)
	field(&b, r.NewValues)
	field(&b, r.Error)
	if r.Timestamp == nil {
		field(&b, nil)
	} else {
		field(&b, str(FormatTimestamp(*r.Timestamp)))
	}
	return b.String()
}

// Hash is the link hash of r (hex sha256 of Canonical).
func Hash(r Row) string {
	sum := sha256.Sum256([]byte(Canonical(r)))
	return hex.EncodeToString(sum[:])
}

// Gap is a run of links [FromSeq, ToSeq] a retention purge removed: PrevHash
// is the prev_hash of FromSeq, LastHash the hash of ToSeq.
type Gap struct {
	FromSeq, ToSeq     int64
	PrevHash, LastHash string
}

// Anchor is a recorded chain head.
type Anchor struct {
	LastSeq  int64
	HeadHash string
	Day      string
}

// Break kinds.
const (
	BreakHash         = "hash_mismatch"   // a row's content no longer matches its hash (tampered)
	BreakLink         = "link_mismatch"   // a row's prev_hash is not the previous link's hash
	BreakMissing      = "missing_rows"    // links absent with no retention gap recording them
	BreakGap          = "gap_mismatch"    // a retention gap whose hashes do not join the chain
	BreakAnchor       = "anchor_mismatch" // an anchored head hash differs from the chain
	BreakStartUnknown = "start_unverifiable"
)

// Break is one place the chain does not verify.
type Break struct {
	Kind     string `json:"kind"`
	Seq      int64  `json:"seq"`
	ToSeq    int64  `json:"to_seq,omitempty"`
	RowID    int64  `json:"row_id,omitempty"`
	Expected string `json:"expected,omitempty"`
	Found    string `json:"found,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// Verifier walks one chain in seq order. Start it with the link expected
// before the first row (Start), feed rows (Next), then Finish with anchors.
type Verifier struct {
	gaps     map[int64]Gap // by FromSeq
	nextSeq  int64
	prevHash string
	known    bool // prevHash is known (the walk is anchored)

	hashes map[int64]string // seq -> hash of every link the walk accepted or crossed (gap ends)

	Rows        int64
	GapsCrossed int64
	FirstSeq    int64
	LastSeq     int64
	Breaks      []Break
	// MaxBreaks bounds the breaks kept (0 = 100).
	MaxBreaks int
}

// NewVerifier builds a verifier over the chain's retention gaps.
func NewVerifier(gaps []Gap) *Verifier {
	v := &Verifier{gaps: map[int64]Gap{}, hashes: map[int64]string{}}
	for _, g := range gaps {
		v.gaps[g.FromSeq] = g
	}
	return v
}

func (v *Verifier) addBreak(b Break) {
	max := v.MaxBreaks
	if max <= 0 {
		max = 100
	}
	if len(v.Breaks) < max {
		v.Breaks = append(v.Breaks, b)
	}
}

// Start sets where the walk begins: the first row expected is seq, and its
// prev_hash must be prevHash. known=false when nothing before seq can be
// checked (the predecessor is neither a row nor a gap end): the first row's
// prev_hash is then taken as given and a start_unverifiable break is kept
// unless seq is 1.
func (v *Verifier) Start(seq int64, prevHash string, known bool) {
	v.nextSeq, v.prevHash, v.known = seq, prevHash, known
	if seq <= 1 {
		v.nextSeq, v.prevHash, v.known = 1, Genesis, true
	}
}

// cross walks gaps from v.nextSeq up to (not including) seq. It returns false
// when no recorded gap covers the hole.
func (v *Verifier) cross(seq int64) bool {
	for v.nextSeq < seq {
		g, ok := v.gaps[v.nextSeq]
		if !ok || g.ToSeq >= seq {
			return false
		}
		if v.known && g.PrevHash != v.prevHash {
			v.addBreak(Break{Kind: BreakGap, Seq: g.FromSeq, ToSeq: g.ToSeq, Expected: v.prevHash, Found: g.PrevHash,
				Detail: "the retention gap does not start from the previous link"})
		}
		v.hashes[g.ToSeq] = g.LastHash
		v.prevHash, v.known = g.LastHash, true
		v.nextSeq = g.ToSeq + 1
		v.GapsCrossed++
	}
	return true
}

// Next checks one row; rows must come in ascending seq order.
func (v *Verifier) Next(r Row) {
	if v.Rows == 0 {
		v.FirstSeq = r.Seq
		if !v.known {
			v.addBreak(Break{Kind: BreakStartUnknown, Seq: r.Seq, RowID: r.ID,
				Detail: "the link before this row is neither a surviving row nor a recorded retention gap"})
			v.prevHash, v.known, v.nextSeq = r.PrevHash, true, r.Seq
		}
	}
	v.Rows++
	v.LastSeq = r.Seq
	if r.Seq > v.nextSeq {
		from := v.nextSeq
		if !v.cross(r.Seq) {
			v.addBreak(Break{Kind: BreakMissing, Seq: from, ToSeq: r.Seq - 1,
				Detail: "links are missing and no retention purge recorded removing them"})
			// Resynchronise on this row so one hole is reported once.
			v.prevHash = r.PrevHash
		}
	}
	if r.PrevHash != v.prevHash {
		v.addBreak(Break{Kind: BreakLink, Seq: r.Seq, RowID: r.ID, Expected: v.prevHash, Found: r.PrevHash})
	}
	if h := Hash(r); h != r.Hash {
		v.addBreak(Break{Kind: BreakHash, Seq: r.Seq, RowID: r.ID, Expected: h, Found: r.Hash,
			Detail: "the row's content does not match its hash"})
	}
	v.hashes[r.Seq] = r.Hash
	v.prevHash = r.Hash
	v.nextSeq = r.Seq + 1
}

// Finish crosses any trailing gaps up to and including upTo (the last seq
// the walk covers) and checks every anchor whose head lies inside the walk.
// It returns how many anchors were checked.
func (v *Verifier) Finish(upTo int64, anchors []Anchor) int {
	if upTo >= v.nextSeq {
		v.cross(upTo + 1)
	}
	checked := 0
	for _, a := range anchors {
		h, ok := v.hashes[a.LastSeq]
		if !ok {
			continue
		}
		checked++
		if h != a.HeadHash {
			v.addBreak(Break{Kind: BreakAnchor, Seq: a.LastSeq, Expected: a.HeadHash, Found: h,
				Detail: "the anchor of " + a.Day + " recorded a different head"})
		}
	}
	return checked
}

// OK reports whether the walk found no break.
func (v *Verifier) OK() bool { return len(v.Breaks) == 0 }
