// Package igagov is the pure core of the Phase 3 policy product
// (SPEC-iga-phase3-policy.md, §4.2): canonical JSON and every hash (§2.8,
// §2.11), the qualified interval and grant age (§2.6), the catalogs (§3.7),
// typed intent (§2.7), finding evaluation over an in-memory revision snapshot
// (§2.5, §8.2), resource-policy route analysis (§3.4) and evidence bundles
// (§2.11).
//
// Nothing in this package touches a database, the network or the clock:
// every time is an input. Outputs are shaped to fit the 047–056 storage
// contract (column names, enums and CHECK constraints); where the vocabularies
// below repeat a CHECK, the migration is the authority.
package igagov

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

/* ------------------------------------------------------------------------- */
/*                       RFC 8785 (JCS) canonical JSON                        */
/* ------------------------------------------------------------------------- */

// maxJSONDepth bounds nesting so hostile input cannot exhaust the stack.
const maxJSONDepth = 512

// ErrNotIJSON is wrapped by every canonicalisation failure: the input is not
// I-JSON (RFC 7493) and therefore has no RFC 8785 canonical form.
var ErrNotIJSON = errors.New("igagov: input is not I-JSON")

type jsonKind uint8

const (
	jsonNull jsonKind = iota
	jsonBool
	jsonNumber
	jsonString
	jsonArray
	jsonObject
)

type jsonMember struct {
	key   string
	value *jsonValue
}

type jsonValue struct {
	kind jsonKind
	b    bool
	num  float64
	str  string
	arr  []*jsonValue
	obj  []jsonMember
}

type jsonParser struct {
	data []byte
	pos  int
}

func (p *jsonParser) fail(format string, args ...any) error {
	return fmt.Errorf("%w: offset %d: %s", ErrNotIJSON, p.pos, fmt.Sprintf(format, args...))
}

func (p *jsonParser) skipWS() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

// parseJSON parses one JSON text strictly: RFC 8259 grammar, valid UTF-8, no
// lone surrogates, no duplicate member names, numbers representable as IEEE
// 754 doubles (RFC 7493 §2), nothing after the value but whitespace.
func parseJSON(data []byte) (*jsonValue, error) {
	p := &jsonParser{data: data}
	p.skipWS()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.data) {
		return nil, p.fail("trailing data")
	}
	return v, nil
}

func (p *jsonParser) value(depth int) (*jsonValue, error) {
	if depth > maxJSONDepth {
		return nil, p.fail("nesting deeper than %d", maxJSONDepth)
	}
	if p.pos >= len(p.data) {
		return nil, p.fail("unexpected end of input")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		s, err := p.string()
		if err != nil {
			return nil, err
		}
		return &jsonValue{kind: jsonString, str: s}, nil
	case c == 't':
		return p.literal("true", &jsonValue{kind: jsonBool, b: true})
	case c == 'f':
		return p.literal("false", &jsonValue{kind: jsonBool})
	case c == 'n':
		return p.literal("null", &jsonValue{kind: jsonNull})
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, p.fail("unexpected character %q", c)
	}
}

func (p *jsonParser) literal(word string, v *jsonValue) (*jsonValue, error) {
	if !bytes.HasPrefix(p.data[p.pos:], []byte(word)) {
		return nil, p.fail("invalid literal")
	}
	p.pos += len(word)
	return v, nil
}

func (p *jsonParser) number() (*jsonValue, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	digits := func() int {
		n := 0
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
			n++
		}
		return n
	}
	if p.pos < len(p.data) && p.data[p.pos] == '0' {
		p.pos++
	} else if digits() == 0 {
		return nil, p.fail("invalid number")
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if digits() == 0 {
			return nil, p.fail("invalid fraction")
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if digits() == 0 {
			return nil, p.fail("invalid exponent")
		}
	}
	f, err := strconv.ParseFloat(string(p.data[start:p.pos]), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, p.fail("number %s is not an IEEE 754 double", p.data[start:p.pos])
	}
	return &jsonValue{kind: jsonNumber, num: f}, nil
}

func hexVal(c byte) (rune, bool) {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0'), true
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return rune(c-'A') + 10, true
	}
	return 0, false
}

func (p *jsonParser) hex4() (rune, error) {
	if p.pos+4 > len(p.data) {
		return 0, p.fail("short \\u escape")
	}
	var r rune
	for i := 0; i < 4; i++ {
		v, ok := hexVal(p.data[p.pos+i])
		if !ok {
			return 0, p.fail("invalid \\u escape")
		}
		r = r<<4 | v
	}
	p.pos += 4
	return r, nil
}

func (p *jsonParser) string() (string, error) {
	p.pos++ // opening quote
	var sb strings.Builder
	for {
		if p.pos >= len(p.data) {
			return "", p.fail("unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return sb.String(), nil
		case c == '\\':
			p.pos++
			if p.pos >= len(p.data) {
				return "", p.fail("unterminated escape")
			}
			e := p.data[p.pos]
			p.pos++
			switch e {
			case '"', '\\', '/':
				sb.WriteByte(e)
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				r, err := p.hex4()
				if err != nil {
					return "", err
				}
				if utf16.IsSurrogate(r) {
					if r >= 0xDC00 || !bytes.HasPrefix(p.data[p.pos:], []byte(`\u`)) {
						return "", p.fail("lone surrogate")
					}
					p.pos += 2
					r2, err := p.hex4()
					if err != nil {
						return "", err
					}
					dec := utf16.DecodeRune(r, r2)
					if dec == utf8.RuneError {
						return "", p.fail("lone surrogate")
					}
					r = dec
				}
				sb.WriteRune(r)
			default:
				return "", p.fail("invalid escape \\%c", e)
			}
		case c < 0x20:
			return "", p.fail("unescaped control character")
		case c < utf8.RuneSelf:
			sb.WriteByte(c)
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size <= 1 {
				return "", p.fail("invalid UTF-8")
			}
			sb.Write(p.data[p.pos : p.pos+size])
			p.pos += size
		}
	}
}

func (p *jsonParser) array(depth int) (*jsonValue, error) {
	p.pos++
	v := &jsonValue{kind: jsonArray, arr: []*jsonValue{}}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return v, nil
	}
	for {
		p.skipWS()
		el, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		v.arr = append(v.arr, el)
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, p.fail("unterminated array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return v, nil
		default:
			return nil, p.fail("expected , or ]")
		}
	}
}

func (p *jsonParser) object(depth int) (*jsonValue, error) {
	p.pos++
	v := &jsonValue{kind: jsonObject, obj: []jsonMember{}}
	seen := map[string]bool{}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return v, nil
	}
	for {
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, p.fail("expected member name")
		}
		k, err := p.string()
		if err != nil {
			return nil, err
		}
		if seen[k] {
			return nil, p.fail("duplicate member name %q", k)
		}
		seen[k] = true
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, p.fail("expected :")
		}
		p.pos++
		p.skipWS()
		el, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		v.obj = append(v.obj, jsonMember{key: k, value: el})
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, p.fail("unterminated object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return v, nil
		default:
			return nil, p.fail("expected , or }")
		}
	}
}

// lessUTF16 orders member names by their UTF-16 code units, as RFC 8785
// §3.2.3 requires (not by UTF-8 bytes or code points: they disagree for
// characters above U+FFFF against U+E000–U+FFFF).
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func (v *jsonValue) writeCanonical(buf *bytes.Buffer) {
	switch v.kind {
	case jsonNull:
		buf.WriteString("null")
	case jsonBool:
		if v.b {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case jsonNumber:
		buf.WriteString(FormatNumberES6(v.num))
	case jsonString:
		writeCanonicalString(buf, v.str)
	case jsonArray:
		buf.WriteByte('[')
		for i, el := range v.arr {
			if i > 0 {
				buf.WriteByte(',')
			}
			el.writeCanonical(buf)
		}
		buf.WriteByte(']')
	case jsonObject:
		members := make([]jsonMember, len(v.obj))
		copy(members, v.obj)
		sort.SliceStable(members, func(i, j int) bool { return lessUTF16(members[i].key, members[j].key) })
		buf.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, m.key)
			buf.WriteByte(':')
			m.value.writeCanonical(buf)
		}
		buf.WriteByte('}')
	}
}

// writeCanonicalString serialises a string as RFC 8785 §3.2.2.2 does
// (ECMAScript JSON.stringify): the two-character escapes for \b \t \n \f \r
// " and \, \u00xx (lower-case hex) for the other C0 controls, everything else
// as literal UTF-8.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	const hexdigits = "0123456789abcdef"
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if c < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexdigits[c>>4])
				buf.WriteByte(hexdigits[c&0xF])
			} else {
				buf.WriteByte(c)
			}
		}
	}
	buf.WriteByte('"')
}

// FormatNumberES6 renders a finite double as ECMAScript's
// Number.prototype.toString does, which RFC 8785 §3.2.2.3 adopts: the
// shortest round-tripping digits, plain notation for decimal exponents in
// [-6, 21), exponential ("1e+21", "5e-324") otherwise, and "0" for ±0.
// NaN and ±Inf have no JSON form; callers never pass them (parseJSON refuses
// them).
func FormatNumberES6(f float64) string {
	if f == 0 {
		return "0"
	}
	var sb strings.Builder
	if f < 0 {
		sb.WriteByte('-')
		f = -f
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d[.ddd]e±XX, shortest digits
	ei := strings.IndexByte(e, 'e')
	digits := strings.Replace(e[:ei], ".", "", 1)
	exp, _ := strconv.Atoi(e[ei+1:])
	k := len(digits)
	n := exp + 1 // value = 0.digits × 10^n
	switch {
	case k <= n && n <= 21:
		sb.WriteString(digits)
		sb.WriteString(strings.Repeat("0", n-k))
	case 0 < n && n <= 21:
		sb.WriteString(digits[:n])
		sb.WriteByte('.')
		sb.WriteString(digits[n:])
	case -6 < n && n <= 0:
		sb.WriteString("0.")
		sb.WriteString(strings.Repeat("0", -n))
		sb.WriteString(digits)
	default:
		sb.WriteByte(digits[0])
		if k > 1 {
			sb.WriteByte('.')
			sb.WriteString(digits[1:])
		}
		sb.WriteByte('e')
		if n-1 >= 0 {
			sb.WriteByte('+')
		}
		sb.WriteString(strconv.Itoa(n - 1))
	}
	return sb.String()
}

// Canonicalize returns the RFC 8785 (JCS) canonical form of a JSON text
// (§2.8: "Canonical JSON is RFC 8785"). Input that is not I-JSON — invalid
// UTF-8, a lone surrogate, a duplicate member name, a number outside the
// double range — is refused rather than guessed at.
func Canonicalize(data []byte) ([]byte, error) {
	v, err := parseJSON(data)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	v.writeCanonical(&buf)
	return buf.Bytes(), nil
}

// CanonicalizeValue marshals a Go value with encoding/json and returns its
// RFC 8785 form (§2.8). Struct field order, map order and json.Marshal's HTML
// escaping do not survive canonicalisation, so equal values give equal bytes.
func CanonicalizeValue(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("igagov: marshal for canonicalisation: %w", err)
	}
	return Canonicalize(raw)
}

// ErrNotStorable is returned for canonical text PostgreSQL cannot store as
// jsonb: the `authsec_document_insert_check` and `iga_gov_bundle_insert_check`
// triggers (049, 050) cast the canonical text to jsonb, and jsonb rejects
// U+0000 ("\u0000").
// DECISION D22.
var ErrNotStorable = errors.New("igagov: canonical text contains U+0000, which jsonb cannot store")

func checkStorable(canonical []byte) error {
	if bytes.Contains(canonical, []byte(`\u0000`)) {
		return ErrNotStorable
	}
	return nil
}

/* ------------------------------------------------------------------------- */
/*                                  Hashes                                    */
/* ------------------------------------------------------------------------- */

// HashPrefix is the algorithm label every hash in this package carries
// (DECISION D1), the
// same form the 049/050/056 insert triggers compute
// ('sha256:' || encode(sha256(canonical), 'hex')).
const HashPrefix = "sha256:"

// unitSep is the ␟ of §2.5 and §2.8: ASCII 0x1F (UNIT SEPARATOR) (DECISION D2).
const unitSep = "\x1f"

// Domain tags for hashes whose spec definition is "JCS(...)" or a ␟-joined
// field list with no domain of its own (§2.8 says nothing about domain
// separation; DECISION D3). Each tag is the first ␟-separated field of the
// hashed text, so no two kinds of hash can collide on the same bytes.
// Content-addressed hashes (documents, bundles) carry NO tag: the database
// triggers recompute them as the plain sha256 of the canonical text.
const (
	DomainIntent       = "authsec.igagov.intent.v1"
	DomainImpact       = "authsec.igagov.impact.v1"
	DomainPrecondition = "authsec.igagov.precondition.v1"
	DomainStateOnly    = "authsec.igagov.precondition.state.v1"
	DomainPlan         = "authsec.igagov.plan.v1"
	DomainMaterial     = "authsec.igagov.material.v1"
	DomainGap          = "authsec.igagov.gap.v1"
	DomainUnanalysed   = "authsec.igagov.unanalysed.v1"
)

func sha256Label(b []byte) string {
	sum := sha256.Sum256(b)
	return HashPrefix + hex.EncodeToString(sum[:])
}

// ContentHash is the content address of canonical text: "sha256:" + hex of
// the sha256 of the bytes exactly as stored. It is the document hash of
// iga_gov_document / cloud_policy_document and the bundle_hash of
// iga_gov_evidence_bundle (§2.11, §3.9), and must equal what the insert
// triggers recompute.
func ContentHash(canonical []byte) string { return sha256Label(canonical) }

// taggedHash hashes domain ␟ part1 ␟ part2 … . Callers pass only canonical
// JSON texts as parts; RFC 8785 escapes U+001F as \u001f, so a raw 0x1F
// never occurs inside a part and the join is injective.
func taggedHash(domain string, parts ...[]byte) string {
	var buf bytes.Buffer
	buf.WriteString(domain)
	for _, p := range parts {
		buf.WriteString(unitSep)
		buf.Write(p)
	}
	return sha256Label(buf.Bytes())
}

// HashCanonicalTagged canonicalises v and hashes it under a domain tag. It is
// the building block for the JCS-defined hashes of §2.8.
func HashCanonicalTagged(domain string, v any) (string, error) {
	c, err := CanonicalizeValue(v)
	if err != nil {
		return "", err
	}
	return taggedHash(domain, c), nil
}

// Fingerprint is a finding's stable identity, §2.5 exactly:
// sha256(kind ␟ RoleId ␟ detail_key), rendered "sha256:<hex>". detail_key is
// the service namespace (unused_service), the statement key (broad_grant) or
// empty. The fields are raw strings as the spec writes them, with no domain
// tag (DECISION D6); a field that
// itself contains ␟ would make the join ambiguous and is refused.
func Fingerprint(kind, roleID, detailKey string) (string, error) {
	for _, f := range []string{kind, roleID, detailKey} {
		if strings.Contains(f, unitSep) {
			return "", fmt.Errorf("igagov: fingerprint field %q contains U+001F", f)
		}
	}
	if kind == "" || roleID == "" {
		return "", errors.New("igagov: fingerprint needs a kind and a RoleId")
	}
	return sha256Label([]byte(kind + unitSep + roleID + unitSep + detailKey)), nil
}

// CanonicalDocument decodes an IAM policy document as AWS returns it
// (URL-encoded, arbitrary whitespace; §2.8) and returns its RFC 8785 text and
// content hash — the pair iga_gov_document / cloud_policy_document store
// (§3.9). The text is checked to be storable as jsonb.
func CanonicalDocument(text string) (canonical []byte, hash string, err error) {
	raw, err := DecodePolicyText(text)
	if err != nil {
		return nil, "", err
	}
	c, err := Canonicalize(raw)
	if err != nil {
		return nil, "", err
	}
	if err := checkStorable(c); err != nil {
		return nil, "", err
	}
	return c, ContentHash(c), nil
}

// DocumentHash is §2.8's desired_document_hash / boundary_document_hash: the
// content hash of the document's canonical text (CanonicalDocument).
func DocumentHash(text string) (string, error) {
	_, h, err := CanonicalDocument(text)
	return h, err
}

// IntentHash is §2.8's intent_hash over JCS(intent), domain-tagged
// (DomainIntent). The stored jsonb intent and the API's intent hash to the
// same value because JCS removes key order and whitespace.
func IntentHash(intentJSON []byte) (string, error) {
	c, err := Canonicalize(intentJSON)
	if err != nil {
		return "", err
	}
	return taggedHash(DomainIntent, c), nil
}

// AttachedEntity is one entity using a policy, as ListEntitiesForPolicy
// reports it across every usage type (§2.8 attachment_set). Kind is role,
// user or group; Usage is boundary or permissions.
type AttachedEntity struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Name  string `json:"name"`
	Usage string `json:"usage"`
}

// Attachment usages (ListEntitiesForPolicy PolicyUsageFilter).
const (
	UsageBoundary    = "boundary"
	UsagePermissions = "permissions"
)

// ArtifactStateFacts is §2.8's artifact_state: the control's incarnation,
// the role's current boundary and its canonical document hash (both null
// when there is none), and the sorted set of entities using that policy. It
// deliberately excludes the role's own permission policies. The compiler's
// ArtifactState(live) builds it from a discovery-role read (DECISION D25:
// the spec's function name is left free for the compiler, which owns the
// live-read type).
type ArtifactStateFacts struct {
	RoleID               string           `json:"role_id"`
	BoundaryARN          *string          `json:"boundary_arn"`
	BoundaryDocumentHash *string          `json:"boundary_document_hash"`
	AttachmentSet        []AttachedEntity `json:"attachment_set"`
}

// Normalized returns a copy with the attachment set sorted (kind, id, usage,
// name) and never nil, so equal states canonicalise identically.
func (s ArtifactStateFacts) Normalized() ArtifactStateFacts {
	out := s
	out.AttachmentSet = append([]AttachedEntity{}, s.AttachmentSet...)
	sort.Slice(out.AttachmentSet, func(i, j int) bool {
		a, b := out.AttachmentSet[i], out.AttachmentSet[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Usage != b.Usage {
			return a.Usage < b.Usage
		}
		return a.Name < b.Name
	})
	return out
}

// Canonical returns JCS(artifact_state) (§2.8).
func (s ArtifactStateFacts) Canonical() ([]byte, error) {
	if s.RoleID == "" {
		return nil, errors.New("igagov: artifact_state needs the role_id")
	}
	if (s.BoundaryARN == nil) != (s.BoundaryDocumentHash == nil) {
		return nil, errors.New("igagov: artifact_state boundary ARN and document hash must be both set or both null")
	}
	return CanonicalizeValue(s.Normalized())
}

// PolicyRef is a policy with its canonical document hash: an attached
// managed policy (ARN) or an inline policy (name) in an apply precondition.
type PolicyRef struct {
	Ref          string `json:"ref"`
	DocumentHash string `json:"document_hash"`
}

// ApplyPrecondition is the input of an apply plan's precondition_hash
// (§2.8): artifact_state, the role ARN and path, its protection tags, and its
// attached managed policies and inline policies with document hashes.
type ApplyPrecondition struct {
	ArtifactState   ArtifactStateFacts `json:"artifact_state"`
	RoleARN         string             `json:"role_arn"`
	RolePath        string             `json:"role_path"`
	ProtectionTags  map[string]string  `json:"protection_tags"`
	ManagedPolicies []PolicyRef        `json:"managed_policies"`
	InlinePolicies  []PolicyRef        `json:"inline_policies"`
}

func sortedRefs(in []PolicyRef) []PolicyRef {
	out := append([]PolicyRef{}, in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// Canonical returns the JCS text the apply precondition hash covers.
func (p ApplyPrecondition) Canonical() ([]byte, error) {
	if _, err := p.ArtifactState.Canonical(); err != nil {
		return nil, err
	}
	n := p
	n.ArtifactState = p.ArtifactState.Normalized()
	if n.ProtectionTags == nil {
		n.ProtectionTags = map[string]string{}
	}
	n.ManagedPolicies = sortedRefs(p.ManagedPolicies)
	n.InlinePolicies = sortedRefs(p.InlinePolicies)
	return CanonicalizeValue(n)
}

// ApplyPreconditionHash is §2.8's precondition_hash for an apply plan,
// domain-tagged (DomainPrecondition).
func ApplyPreconditionHash(p ApplyPrecondition) (string, error) {
	c, err := p.Canonical()
	if err != nil {
		return "", err
	}
	return taggedHash(DomainPrecondition, c), nil
}

// StatePreconditionHash is §2.8's precondition_hash for undo, remove-control
// and role-only recovery plans: JCS({artifact_state}) of the state they start
// from, domain-tagged (DomainStateOnly). Two plans starting from the same
// artifact state get the same hash whatever the role's own policies are.
func StatePreconditionHash(s ArtifactStateFacts) (string, error) {
	if _, err := s.Canonical(); err != nil {
		return "", err
	}
	c, err := CanonicalizeValue(struct {
		ArtifactState ArtifactStateFacts `json:"artifact_state"`
	}{s.Normalized()})
	if err != nil {
		return "", err
	}
	return taggedHash(DomainStateOnly, c), nil
}

// ImpactConsumer, ImpactService and ImpactRoute are the members of §2.8's
// impact.
type ImpactConsumer struct {
	WorkloadID   string `json:"workload_id"`
	Relationship string `json:"relationship"`
}

// ImpactService is a removed or retained service with its basis.
type ImpactService struct {
	Service string `json:"service"`
	Basis   string `json:"basis"`
}

// Impact is the input of impact_hash (§2.8): consumers, owner user ids,
// removed and retained services with basis, the statement-revision hashes of
// every identity statement granting a removed service, and the
// resource-policy routes of §3.4 (route usage and route effect).
type Impact struct {
	Consumers          []ImpactConsumer `json:"consumers"`
	OwnerUserIDs       []string         `json:"owners"`
	Removed            []ImpactService  `json:"removed"`
	Retained           []ImpactService  `json:"retained"`
	StatementRevisions []string         `json:"statement_revisions"`
	Routes             []Route          `json:"routes"`
}

// Normalized sorts and de-duplicates every member so impact_hash does not
// depend on read order.
func (im Impact) Normalized() Impact {
	out := Impact{
		Consumers:          append([]ImpactConsumer{}, im.Consumers...),
		OwnerUserIDs:       sortedUnique(im.OwnerUserIDs),
		Removed:            append([]ImpactService{}, im.Removed...),
		Retained:           append([]ImpactService{}, im.Retained...),
		StatementRevisions: sortedUnique(im.StatementRevisions),
		Routes:             append([]Route{}, im.Routes...),
	}
	sort.Slice(out.Consumers, func(i, j int) bool {
		a, b := out.Consumers[i], out.Consumers[j]
		if a.WorkloadID != b.WorkloadID {
			return a.WorkloadID < b.WorkloadID
		}
		return a.Relationship < b.Relationship
	})
	out.Consumers = uniqueConsumers(out.Consumers)
	svcLess := func(s []ImpactService) func(i, j int) bool {
		return func(i, j int) bool {
			if s[i].Service != s[j].Service {
				return s[i].Service < s[j].Service
			}
			return s[i].Basis < s[j].Basis
		}
	}
	sort.Slice(out.Removed, svcLess(out.Removed))
	sort.Slice(out.Retained, svcLess(out.Retained))
	SortRoutes(out.Routes)
	return out
}

func uniqueConsumers(in []ImpactConsumer) []ImpactConsumer {
	out := in[:0]
	for i, c := range in {
		if i > 0 && c == in[i-1] {
			continue
		}
		out = append(out, c)
	}
	return out
}

// ImpactHash is §2.8's impact_hash over JCS(normalised impact),
// domain-tagged (DomainImpact).
func ImpactHash(im Impact) (string, error) {
	return HashCanonicalTagged(DomainImpact, im.Normalized())
}

// UnanalysedItem is one member of a plan's unanalysed set (§3.4): a
// policy-bearing form, "resources in other accounts", or another item the
// approver must accept (kind unanalysed_form, one iga_gov_acceptance row
// each, keyed by Key).
type UnanalysedItem struct {
	Key    string `json:"key"`
	Form   string `json:"form,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// UnanalysedItemHash is the item_hash an iga_gov_acceptance row of kind
// unanalysed_form binds (DomainUnanalysed over JCS(item)).
func UnanalysedItemHash(it UnanalysedItem) (string, error) {
	return HashCanonicalTagged(DomainUnanalysed, it)
}

// GapRef is a bundle gap's key and hash: what material_hash binds and what an
// iga_gov_acceptance row of kind evidence_gap stores as item_key / item_hash.
type GapRef struct {
	Key  string `json:"key"`
	Hash string `json:"hash"`
}

// PlanHashInput holds the plan_hash inputs of §2.8, in its order, plus
// FirstAttachment (DECISION D5: the 050 comment and §2.8's material list
// include it; plan_hash takes it too so material inputs stay a subset of plan
// inputs plus impact and gaps). Nil pointers are SQL NULL.
type PlanHashInput struct {
	ControlID               string
	Kind                    string
	Delivery                string
	DesiredAttachment       string
	DesiredBoundaryARN      *string
	DesiredDocumentHash     *string
	ReplacedBoundaryARN     *string
	ArtifactDisposition     string
	BundleHash              string
	EvidenceRev             int64
	ResourcePolicyScanRunID *string
	FirstAttachment         bool
	Unanalysed              []UnanalysedItem
	PreconditionHash        string
	// Ops are the compiler's operations in execution order (never sorted);
	// any JSON-marshalable value.
	Ops any
}

// MaterialHashInput adds what material_hash binds beyond the plan's own
// fields: the impact hash and the bundle's gaps (§2.8).
type MaterialHashInput struct {
	Plan       PlanHashInput
	ImpactHash string
	Gaps       []GapRef
}

func canonField(v any) ([]byte, error) {
	return CanonicalizeValue(v)
}

func sortedUnanalysed(in []UnanalysedItem) []UnanalysedItem {
	out := append([]UnanalysedItem{}, in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (p PlanHashInput) validate() error {
	if p.ControlID == "" || p.Kind == "" || p.Delivery == "" || p.DesiredAttachment == "" ||
		p.ArtifactDisposition == "" || p.PreconditionHash == "" {
		return errors.New("igagov: plan hash input is missing a required field")
	}
	return nil
}

// fields returns the canonical texts of the shared plan/material fields; the
// evidence identifiers are added by PlanHash only.
func (p PlanHashInput) fields(withEvidence bool) ([][]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	vals := []any{p.ControlID, p.Kind, p.Delivery, p.DesiredAttachment, p.DesiredBoundaryARN,
		p.DesiredDocumentHash, p.ReplacedBoundaryARN, p.ArtifactDisposition}
	if withEvidence {
		if p.BundleHash == "" || p.EvidenceRev <= 0 {
			return nil, errors.New("igagov: plan hash needs the bundle hash and evidence revision")
		}
		vals = append(vals, p.BundleHash, p.EvidenceRev, p.ResourcePolicyScanRunID)
	}
	ops := p.Ops
	if ops == nil {
		ops = []any{}
	}
	vals = append(vals, p.FirstAttachment, sortedUnanalysed(p.Unanalysed), p.PreconditionHash, ops)
	out := make([][]byte, 0, len(vals))
	for _, v := range vals {
		c, err := canonField(v)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// PlanHash is §2.8's plan_hash: sha256 over DomainPlan ␟ control_id ␟ kind ␟
// delivery ␟ desired_attachment ␟ desired_boundary_arn ␟
// desired_document_hash ␟ replaced_boundary_arn ␟ artifact_disposition ␟
// bundle_hash ␟ evidence_rev ␟ resource_policy_scan_run_id ␟
// first_attachment ␟ JCS(unanalysed) ␟ precondition_hash ␟ JCS(ops). Every
// field is written as its RFC 8785 JSON text (strings quoted, NULL as null),
// which keeps NULL distinct from "" and the ␟ join injective (DECISION D4).
func PlanHash(p PlanHashInput) (string, error) {
	f, err := p.fields(true)
	if err != nil {
		return "", err
	}
	return taggedHash(DomainPlan, f...), nil
}

// MaterialHash is §2.8's material_hash: the plan_hash fields without
// bundle_hash, evidence_rev and resource_policy_scan_run_id, followed by
// impact_hash and JCS of the bundle's gaps as {key, hash} sorted by key,
// under DomainMaterial. An unchanged rescan reproduces it.
func MaterialHash(m MaterialHashInput) (string, error) {
	f, err := m.Plan.fields(false)
	if err != nil {
		return "", err
	}
	if m.ImpactHash == "" {
		return "", errors.New("igagov: material hash needs the impact hash")
	}
	gaps := append([]GapRef{}, m.Gaps...)
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].Key < gaps[j].Key })
	ih, err := canonField(m.ImpactHash)
	if err != nil {
		return "", err
	}
	gc, err := canonField(gaps)
	if err != nil {
		return "", err
	}
	f = append(f, ih, gc)
	return taggedHash(DomainMaterial, f...), nil
}

func sortedUnique(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	w := 0
	for i, s := range out {
		if i > 0 && s == out[w-1] {
			continue
		}
		out[w] = s
		w++
	}
	return out[:w]
}

/* ------------------------------------------------------------------------- */
/*                         IAM policy-document decoding                       */
/* ------------------------------------------------------------------------- */

// ErrPolicyDocument wraps every policy-document decoding failure. A resource
// policy that fails to decode is `unparseable` (056 parse_state), never empty.
var ErrPolicyDocument = errors.New("igagov: invalid IAM policy document")

// Statement effects.
const (
	EffectAllow = "Allow"
	EffectDeny  = "Deny"
)

// Principal is a normalised Principal / NotPrincipal element: "*" sets
// Wildcard; otherwise Values maps the principal type (AWS, Service,
// Federated, CanonicalUser) to its values, each string-or-array decoded to a
// list. {"AWS": "*"} is recorded as a value "*" under AWS and also sets
// Wildcard, because AWS treats it as everyone.
type Principal struct {
	Wildcard bool
	Values   map[string][]string
}

// ConditionEntry is one operator/key pair of a Condition block; Values are
// the strings as written (numbers and booleans in their canonical JSON text).
type ConditionEntry struct {
	Operator string
	Key      string
	Values   []string
}

// Statement is a normalised IAM statement. Exactly one of Action/NotAction is
// set (IsNotAction says which); Resource/NotResource may both be absent
// (trust policies). Raw is the statement's own RFC 8785 text, so a compiler
// can keep Sid, Condition and Resource byte-identical (§3.4 narrowing).
type Statement struct {
	Sid          string
	Effect       string
	Action       []string
	NotAction    []string
	IsNotAction  bool
	Resource     []string
	NotResource  []string
	Principal    *Principal
	NotPrincipal *Principal
	Conditions   []ConditionEntry
	Raw          json.RawMessage
	// Unknown lists member names this decoder does not interpret; they stay
	// in Raw.
	Unknown []string
}

// PolicyDocument is a normalised IAM policy document: Statement decoded from
// object-or-array, every string-or-array element decoded to a list.
type PolicyDocument struct {
	Version    string
	ID         string
	Statements []Statement
}

// DecodePolicyText undoes AWS's URL encoding (GetPolicyVersion,
// GetRolePolicy, GetRole's AssumeRolePolicyDocument return RFC 3986
// percent-encoded JSON) and returns the JSON bytes. Text that already starts
// with "{" is returned as is. "+" is left alone (PathUnescape), because AWS
// encodes a literal plus as %2B.
func DecodePolicyText(text string) ([]byte, error) {
	t := strings.TrimSpace(text)
	if strings.HasPrefix(t, "{") {
		return []byte(t), nil
	}
	u, err := url.PathUnescape(t)
	if err != nil {
		return nil, fmt.Errorf("%w: url-decode: %v", ErrPolicyDocument, err)
	}
	return []byte(strings.TrimSpace(u)), nil
}

// DecodePolicyDocument decodes and normalises an IAM policy document
// (identity, boundary, trust or resource policy; §2.8, §3.4). It refuses
// non-I-JSON, a missing Statement, an Effect other than Allow/Deny, both or
// neither of Action/NotAction, and string-or-array elements of the wrong
// type. Member names it does not interpret are listed, not refused; a
// duplicate member name is refused (I-JSON), so such a resource policy is
// `unparseable` (DECISION D21).
func DecodePolicyDocument(text string) (PolicyDocument, error) {
	raw, err := DecodePolicyText(text)
	if err != nil {
		return PolicyDocument{}, err
	}
	v, err := parseJSON(raw)
	if err != nil {
		return PolicyDocument{}, fmt.Errorf("%w: %v", ErrPolicyDocument, err)
	}
	if v.kind != jsonObject {
		return PolicyDocument{}, fmt.Errorf("%w: document is not an object", ErrPolicyDocument)
	}
	var doc PolicyDocument
	var stmts *jsonValue
	for _, m := range v.obj {
		switch m.key {
		case "Version":
			if m.value.kind != jsonString {
				return doc, fmt.Errorf("%w: Version is not a string", ErrPolicyDocument)
			}
			doc.Version = m.value.str
		case "Id":
			if m.value.kind != jsonString {
				return doc, fmt.Errorf("%w: Id is not a string", ErrPolicyDocument)
			}
			doc.ID = m.value.str
		case "Statement":
			stmts = m.value
		}
	}
	if stmts == nil {
		return doc, fmt.Errorf("%w: no Statement", ErrPolicyDocument)
	}
	var list []*jsonValue
	switch stmts.kind {
	case jsonObject:
		list = []*jsonValue{stmts}
	case jsonArray:
		list = stmts.arr
	default:
		return doc, fmt.Errorf("%w: Statement is neither an object nor an array", ErrPolicyDocument)
	}
	doc.Statements = []Statement{}
	for i, sv := range list {
		st, err := decodeStatement(sv)
		if err != nil {
			return doc, fmt.Errorf("%w: statement %d: %v", ErrPolicyDocument, i, err)
		}
		doc.Statements = append(doc.Statements, st)
	}
	return doc, nil
}

func stringOrArray(v *jsonValue, name string) ([]string, error) {
	switch v.kind {
	case jsonString:
		return []string{v.str}, nil
	case jsonArray:
		out := make([]string, 0, len(v.arr))
		for _, el := range v.arr {
			if el.kind != jsonString {
				return nil, fmt.Errorf("%s has a non-string entry", name)
			}
			out = append(out, el.str)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%s is neither a string nor an array", name)
}

func decodePrincipal(v *jsonValue, name string) (*Principal, error) {
	p := &Principal{Values: map[string][]string{}}
	switch v.kind {
	case jsonString:
		if v.str != "*" {
			return nil, fmt.Errorf("%s string must be \"*\"", name)
		}
		p.Wildcard = true
		return p, nil
	case jsonObject:
		for _, m := range v.obj {
			vals, err := stringOrArray(m.value, name+"."+m.key)
			if err != nil {
				return nil, err
			}
			p.Values[m.key] = vals
			if m.key == "AWS" {
				for _, s := range vals {
					if s == "*" {
						p.Wildcard = true
					}
				}
			}
		}
		return p, nil
	}
	return nil, fmt.Errorf("%s is neither \"*\" nor an object", name)
}

func conditionValueText(v *jsonValue) (string, error) {
	switch v.kind {
	case jsonString:
		return v.str, nil
	case jsonBool, jsonNumber, jsonNull:
		var b bytes.Buffer
		v.writeCanonical(&b)
		return b.String(), nil
	}
	return "", errors.New("condition value must be a scalar")
}

func decodeCondition(v *jsonValue) ([]ConditionEntry, error) {
	if v.kind != jsonObject {
		return nil, errors.New("Condition is not an object")
	}
	var out []ConditionEntry
	for _, op := range v.obj {
		if op.value.kind != jsonObject {
			return nil, fmt.Errorf("Condition operator %s is not an object", op.key)
		}
		for _, k := range op.value.obj {
			var vals []string
			switch k.value.kind {
			case jsonArray:
				for _, el := range k.value.arr {
					s, err := conditionValueText(el)
					if err != nil {
						return nil, err
					}
					vals = append(vals, s)
				}
			default:
				s, err := conditionValueText(k.value)
				if err != nil {
					return nil, err
				}
				vals = []string{s}
			}
			out = append(out, ConditionEntry{Operator: op.key, Key: k.key, Values: vals})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Operator != out[j].Operator {
			return out[i].Operator < out[j].Operator
		}
		return out[i].Key < out[j].Key
	})
	return out, nil
}

func decodeStatement(v *jsonValue) (Statement, error) {
	var st Statement
	if v.kind != jsonObject {
		return st, errors.New("statement is not an object")
	}
	var buf bytes.Buffer
	v.writeCanonical(&buf)
	st.Raw = json.RawMessage(buf.Bytes())
	var err error
	hasAction, hasNotAction := false, false
	for _, m := range v.obj {
		switch m.key {
		case "Sid":
			if m.value.kind != jsonString {
				return st, errors.New("Sid is not a string")
			}
			st.Sid = m.value.str
		case "Effect":
			if m.value.kind != jsonString || (m.value.str != EffectAllow && m.value.str != EffectDeny) {
				return st, errors.New("Effect must be Allow or Deny")
			}
			st.Effect = m.value.str
		case "Action":
			hasAction = true
			if st.Action, err = stringOrArray(m.value, "Action"); err != nil {
				return st, err
			}
		case "NotAction":
			hasNotAction = true
			if st.NotAction, err = stringOrArray(m.value, "NotAction"); err != nil {
				return st, err
			}
		case "Resource":
			if st.Resource, err = stringOrArray(m.value, "Resource"); err != nil {
				return st, err
			}
		case "NotResource":
			if st.NotResource, err = stringOrArray(m.value, "NotResource"); err != nil {
				return st, err
			}
		case "Principal":
			if st.Principal, err = decodePrincipal(m.value, "Principal"); err != nil {
				return st, err
			}
		case "NotPrincipal":
			if st.NotPrincipal, err = decodePrincipal(m.value, "NotPrincipal"); err != nil {
				return st, err
			}
		case "Condition":
			if st.Conditions, err = decodeCondition(m.value); err != nil {
				return st, err
			}
		default:
			st.Unknown = append(st.Unknown, m.key)
		}
	}
	if st.Effect == "" {
		return st, errors.New("no Effect")
	}
	if hasAction == hasNotAction {
		return st, errors.New("exactly one of Action and NotAction is required")
	}
	if st.Principal != nil && st.NotPrincipal != nil {
		return st, errors.New("Principal and NotPrincipal are mutually exclusive")
	}
	if st.Resource != nil && st.NotResource != nil {
		return st, errors.New("Resource and NotResource are mutually exclusive")
	}
	st.IsNotAction = hasNotAction
	sort.Strings(st.Unknown)
	return st, nil
}

/* ------------------------------------------------------------------------- */
/*                       Action patterns and namespaces                       */
/* ------------------------------------------------------------------------- */

// globMatch reports whether s matches an IAM pattern with '*' (any run) and
// '?' (one character), case-insensitively (IAM action names are).
func globMatch(pattern, s string) bool {
	p, t := strings.ToLower(pattern), strings.ToLower(s)
	pi, ti, star, mark := 0, 0, -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == t[ti]):
			pi++
			ti++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ti = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// globsIntersect reports whether some string matches both IAM patterns
// (case-insensitive '*' and '?'), so a statement action such as "iam:C*" is
// recognised as granting the escalation pattern "iam:Create*".
func globsIntersect(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	memo := map[[2]int]bool{}
	seen := map[[2]int]bool{}
	var rec func(i, j int) bool
	rec = func(i, j int) bool {
		k := [2]int{i, j}
		if seen[k] {
			return memo[k]
		}
		seen[k] = true
		var r bool
		switch {
		case i == len(a) && j == len(b):
			r = true
		case i < len(a) && a[i] == '*':
			r = rec(i+1, j) || (j < len(b) && rec(i, j+1))
		case j < len(b) && b[j] == '*':
			r = rec(i, j+1) || (i < len(a) && rec(i+1, j))
		case i < len(a) && j < len(b):
			r = (a[i] == '?' || b[j] == '?' || a[i] == b[j]) && rec(i+1, j+1)
		}
		memo[k] = r
		return r
	}
	return rec(0, 0)
}

// SplitAction splits "ns:Action" into namespace and action. "*" has no
// namespace and reports ok=false.
func SplitAction(action string) (ns, act string, ok bool) {
	i := strings.IndexByte(action, ':')
	if i <= 0 {
		return "", "", false
	}
	return action[:i], action[i+1:], true
}

func allStars(s string) bool {
	return s != "" && strings.Trim(s, "*") == ""
}

// PatternCoversNamespace reports whether an action pattern can match some
// action of namespace ns ("*", "sqs:*", "sq*:Send*", "sqs:SendMessage").
func PatternCoversNamespace(pattern, ns string) bool {
	if allStars(pattern) {
		return true
	}
	pns, _, ok := SplitAction(pattern)
	return ok && globMatch(pns, ns)
}

// patternCoversWholeNamespace reports whether a pattern matches EVERY action
// of ns ("*", "sqs:*", "s*:*").
func patternCoversWholeNamespace(pattern, ns string) bool {
	if allStars(pattern) {
		return true
	}
	pns, act, ok := SplitAction(pattern)
	return ok && allStars(act) && globMatch(pns, ns)
}

// GrantsNamespace reports whether an Allow statement grants some action of
// namespace ns: an Action pattern covering ns, or a NotAction list that does
// not exclude the whole namespace. Deny statements grant nothing.
func (st Statement) GrantsNamespace(ns string) bool {
	if st.Effect != EffectAllow {
		return false
	}
	if st.IsNotAction {
		for _, p := range st.NotAction {
			if patternCoversWholeNamespace(p, ns) {
				return false
			}
		}
		return true
	}
	for _, p := range st.Action {
		if PatternCoversNamespace(p, ns) {
			return true
		}
	}
	return false
}

// ExplicitNamespaces returns the literal namespaces named by an Allow
// statement's Action patterns (lower-cased, sorted). Wildcard namespaces and
// NotAction statements name no literal namespace.
func (st Statement) ExplicitNamespaces() []string {
	if st.Effect != EffectAllow || st.IsNotAction {
		return nil
	}
	var out []string
	for _, p := range st.Action {
		ns, _, ok := SplitAction(p)
		if ok && !strings.ContainsAny(ns, "*?") {
			out = append(out, strings.ToLower(ns))
		}
	}
	return sortedUnique(out)
}

// ResourceIsWildcard reports Resource "*" or any NotResource (which grants
// everything but the listed resources).
func (st Statement) ResourceIsWildcard() bool {
	if st.NotResource != nil {
		return true
	}
	for _, r := range st.Resource {
		if r == "*" {
			return true
		}
	}
	return false
}
