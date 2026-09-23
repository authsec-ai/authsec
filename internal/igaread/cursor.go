package igaread

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// Cursor is the position a list page ended at, bound to what produced it
// (§5.1): the workspace, the revision, the route, the filter set, the sort,
// the last row's sort key and id -- and, for lists that filter or sort on
// classification, the classification clock's seq at the first page.
//
// It is opaque to the client: HMAC-signed with IGA_CURSOR_SECRET, so a client
// cannot move it to another context or edit the position.
type Cursor struct {
	V        int             `json:"v"`
	WS       uuid.UUID       `json:"w"`
	Rev      int64           `json:"r"`
	Route    string          `json:"p"`
	Filter   string          `json:"f"`
	Sort     string          `json:"s"`
	Key      json.RawMessage `json:"k,omitempty"` // the last row's sort key values, route-defined
	ID       uuid.UUID       `json:"i"`
	ClassSeq *int64          `json:"c,omitempty"`
}

const cursorVersion = 1

// CursorContext is what a presented cursor must match, from the request.
type CursorContext struct {
	WS     uuid.UUID
	Route  string
	Filter string
	Sort   string
}

// SignCursor issues the opaque token for c.
func (r *Reader) SignCursor(c Cursor) string {
	c.V = cursorVersion
	payload, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, r.cursorKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// OpenCursor verifies a presented token and checks it belongs to this
// request's context. Any mismatch -- signature, workspace, route, filter set,
// sort -- is 400 cursor_invalid. The revision is NOT checked here: pass
// Cursor.Rev as Pin.CursorRev, so a cursor from an older revision is 409
// revision_stale from Read, the one stale status (§5.1).
func (r *Reader) OpenCursor(token string, want CursorContext) (*Cursor, *Error) {
	body, sig, ok := strings.Cut(token, ".")
	if !ok {
		return nil, CursorInvalid("Malformed cursor.")
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, CursorInvalid("Malformed cursor.")
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, CursorInvalid("Malformed cursor.")
	}
	mac := hmac.New(sha256.New, r.cursorKey)
	mac.Write(payload)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return nil, CursorInvalid("Cursor signature does not verify.")
	}
	var c Cursor
	if err := json.Unmarshal(payload, &c); err != nil || c.V != cursorVersion {
		return nil, CursorInvalid("Malformed cursor.")
	}
	switch {
	case c.WS != want.WS:
		return nil, CursorInvalid("Cursor belongs to another workspace.")
	case c.Route != want.Route:
		return nil, CursorInvalid("Cursor belongs to another route.")
	case c.Filter != want.Filter:
		return nil, CursorInvalid("Cursor was issued for a different filter set.")
	case c.Sort != want.Sort:
		return nil, CursorInvalid("Cursor was issued for a different sort.")
	}
	return &c, nil
}

// nonFilterParams never enter the filter hash: they position, size or shape a
// page, they do not choose its rows. sort is bound separately.
var nonFilterParams = map[string]bool{
	"cursor": true, "rev": true, "limit": true, "sort": true, "facets": true, "include": true,
}

// FilterHash is the canonical hash of a request's filter set: every parameter
// except the positioning ones, keys sorted, repeated values sorted, so the
// same filters in any order hash the same.
func FilterHash(vals url.Values) string {
	keys := make([]string, 0, len(vals))
	for k := range vals {
		if !nonFilterParams[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		vs := append([]string(nil), vals[k]...)
		sort.Strings(vs)
		h.Write([]byte(k))
		h.Write([]byte{0})
		for _, v := range vs {
			h.Write([]byte(v))
			h.Write([]byte{0x1f})
		}
		h.Write([]byte{0x1e})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}
