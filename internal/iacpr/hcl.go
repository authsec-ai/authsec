package iacpr

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// A deliberately small Terraform (HCL2 native syntax) scanner. It does not
// evaluate anything: it finds top-level blocks, their labels and their
// attributes as byte ranges of the source text, so a change can be made by
// replacing exactly those bytes and leaving the rest of the file as the
// customer wrote it (§8.11: "AuthSec edits only forms it can locate and
// change mechanically"). Anything it cannot read is not guessed at: the
// caller falls back to export with the reason.
//
// DECISION (T3.17): no HCL2 library is vendored in this module (only HCL1,
// which cannot read Terraform 0.12+ expressions), so the scanner is written
// here; it understands strings with ${...} templates, heredocs, comments and
// nested brackets, which is what locating blocks and attribute values needs.

type tfAttr struct {
	Name      string
	LineStart int // start of the line holding the attribute name
	ValStart  int // first byte of the value expression
	ValEnd    int // one past the last byte of the value expression
	LineEnd   int // one past the newline ending the attribute (or ValEnd)
	Raw       string
}

type tfBlock struct {
	File   string
	Type   string
	Labels []string
	Start  int // first byte of the block type keyword
	Open   int // index of '{'
	Close  int // index of '}'
	End    int // one past the newline after '}' (or Close+1)
	Attrs  []*tfAttr
	Nested []*tfBlock
}

func (b *tfBlock) attr(name string) *tfAttr {
	for _, a := range b.Attrs {
		if a.Name == name {
			return a
		}
	}
	return nil
}

func (b *tfBlock) nested(typ string) []*tfBlock {
	var out []*tfBlock
	for _, n := range b.Nested {
		if n.Type == typ {
			out = append(out, n)
		}
	}
	return out
}

// address is the Terraform resource address of a top-level block.
func (b *tfBlock) address() string {
	switch {
	case b.Type == "resource" && len(b.Labels) == 2:
		return b.Labels[0] + "." + b.Labels[1]
	case b.Type == "data" && len(b.Labels) == 2:
		return "data." + b.Labels[0] + "." + b.Labels[1]
	case b.Type == "module" && len(b.Labels) == 1:
		return "module." + b.Labels[0]
	}
	return b.Type + "." + strings.Join(b.Labels, ".")
}

type tfScanner struct {
	src string
	i   int
}

func parseTerraform(path, src string) ([]*tfBlock, error) {
	s := &tfScanner{src: src}
	var out []*tfBlock
	for {
		s.skipSpace(true)
		if s.i >= len(s.src) {
			return out, nil
		}
		b, err := s.block(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if b == nil {
			return nil, fmt.Errorf("%s: unexpected content at byte %d", path, s.i)
		}
		out = append(out, b)
	}
}

// skipSpace skips blanks and comments; newlines too when nl.
func (s *tfScanner) skipSpace(nl bool) {
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			s.i++
		case c == '\n':
			if !nl {
				return
			}
			s.i++
		case c == '#' || (c == '/' && s.peek(1) == '/'):
			for s.i < len(s.src) && s.src[s.i] != '\n' {
				s.i++
			}
		case c == '/' && s.peek(1) == '*':
			end := strings.Index(s.src[s.i+2:], "*/")
			if end < 0 {
				s.i = len(s.src)
				return
			}
			s.i += end + 4
		default:
			return
		}
	}
}

func (s *tfScanner) peek(n int) byte {
	if s.i+n < len(s.src) {
		return s.src[s.i+n]
	}
	return 0
}

func isIdentStart(c byte) bool { return c == '_' || unicode.IsLetter(rune(c)) }
func isIdentChar(c byte) bool  { return isIdentStart(c) || c == '-' || (c >= '0' && c <= '9') }

func (s *tfScanner) ident() string {
	st := s.i
	if s.i < len(s.src) && isIdentStart(s.src[s.i]) {
		for s.i < len(s.src) && isIdentChar(s.src[s.i]) {
			s.i++
		}
	}
	return s.src[st:s.i]
}

// block reads `type "label"... { body }` at s.i.
func (s *tfScanner) block(path string) (*tfBlock, error) {
	start := s.i
	typ := s.ident()
	if typ == "" {
		return nil, nil
	}
	b := &tfBlock{File: path, Type: typ, Start: start}
	for {
		s.skipSpace(false)
		if s.i >= len(s.src) {
			return nil, fmt.Errorf("block %s: unexpected end", typ)
		}
		c := s.src[s.i]
		switch {
		case c == '"':
			st := s.i
			if err := s.str(); err != nil {
				return nil, err
			}
			l, err := strconv.Unquote(s.src[st:s.i])
			if err != nil {
				return nil, fmt.Errorf("block %s label: %w", typ, err)
			}
			b.Labels = append(b.Labels, l)
		case isIdentStart(c):
			b.Labels = append(b.Labels, s.ident())
		case c == '{':
			b.Open = s.i
			s.i++
			if err := s.body(b); err != nil {
				return nil, err
			}
			return b, nil
		default:
			return nil, fmt.Errorf("block %s: unexpected %q", typ, c)
		}
	}
}

// body reads attributes and nested blocks up to and including the closing
// brace.
func (s *tfScanner) body(b *tfBlock) error {
	for {
		s.skipSpace(true)
		if s.i >= len(s.src) {
			return fmt.Errorf("block %s: missing }", b.Type)
		}
		if s.src[s.i] == '}' {
			b.Close = s.i
			s.i++
			b.End = s.i
			// The rest of the line belongs to the block.
			j := s.i
			for j < len(s.src) && (s.src[j] == ' ' || s.src[j] == '\t' || s.src[j] == '\r') {
				j++
			}
			if j < len(s.src) && s.src[j] == '\n' {
				b.End = j + 1
			}
			return nil
		}
		lineStart := strings.LastIndexByte(s.src[:s.i], '\n') + 1
		nameStart := s.i
		name := s.ident()
		if name == "" {
			// A quoted attribute key is not Terraform block syntax.
			return fmt.Errorf("block %s: unexpected %q", b.Type, s.src[s.i])
		}
		s.skipSpace(false)
		if s.i < len(s.src) && s.src[s.i] == '=' && s.peek(1) != '=' {
			s.i++
			s.skipSpace(false)
			vs := s.i
			if err := s.expr(); err != nil {
				return fmt.Errorf("attribute %s: %w", name, err)
			}
			ve := s.i
			for ve > vs && (s.src[ve-1] == ' ' || s.src[ve-1] == '\t' || s.src[ve-1] == '\r') {
				ve--
			}
			le := s.i
			s.skipSpace(false)
			if s.i < len(s.src) && s.src[s.i] == '\n' {
				s.i++
				le = s.i
			}
			b.Attrs = append(b.Attrs, &tfAttr{Name: name, LineStart: lineStart, ValStart: vs, ValEnd: ve, LineEnd: le, Raw: s.src[vs:ve]})
			continue
		}
		s.i = nameStart
		nb, err := s.block(b.File)
		if err != nil {
			return err
		}
		if nb == nil {
			return fmt.Errorf("block %s: unexpected content", b.Type)
		}
		nb.Start = lineStart
		b.Nested = append(b.Nested, nb)
	}
}

// expr advances over one expression: to a newline (or the enclosing '}')
// at bracket depth zero.
func (s *tfScanner) expr() error {
	depth := 0
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == '"':
			if err := s.str(); err != nil {
				return err
			}
			continue
		case c == '<' && s.peek(1) == '<' && (isIdentStart(s.peek(2)) || (s.peek(2) == '-' && isIdentStart(s.peek(3)))):
			if err := s.heredoc(); err != nil {
				return err
			}
			continue
		case c == '#' || (c == '/' && s.peek(1) == '/'):
			if depth == 0 {
				return nil
			}
			for s.i < len(s.src) && s.src[s.i] != '\n' {
				s.i++
			}
			continue
		case c == '/' && s.peek(1) == '*':
			end := strings.Index(s.src[s.i+2:], "*/")
			if end < 0 {
				return fmt.Errorf("unterminated comment")
			}
			s.i += end + 4
			continue
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			if depth == 0 {
				return nil
			}
			depth--
		case c == '\n':
			if depth == 0 {
				return nil
			}
		}
		s.i++
	}
	if depth != 0 {
		return fmt.Errorf("unbalanced brackets")
	}
	return nil
}

// str advances over a quoted template string, including ${...} and %{...}
// sequences (which may contain strings themselves).
func (s *tfScanner) str() error {
	s.i++ // opening quote
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == '\\':
			s.i += 2
		case c == '"':
			s.i++
			return nil
		case c == '\n':
			return fmt.Errorf("newline in string")
		case (c == '$' || c == '%') && s.peek(1) == c && s.peek(2) == '{':
			// "$${" / "%%{" is an escaped literal "${" / "%{".
			s.i += 3
		case (c == '$' || c == '%') && s.peek(1) == '{':
			s.i += 2
			if err := s.templateExpr(); err != nil {
				return err
			}
		default:
			s.i++
		}
	}
	return fmt.Errorf("unterminated string")
}

// templateExpr advances over the inside of ${...} up to its closing brace.
func (s *tfScanner) templateExpr() error {
	depth := 0
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch c {
		case '"':
			if err := s.str(); err != nil {
				return err
			}
			continue
		case '{', '(', '[':
			depth++
		case ')', ']':
			depth--
		case '}':
			if depth == 0 {
				s.i++
				return nil
			}
			depth--
		}
		s.i++
	}
	return fmt.Errorf("unterminated template")
}

// heredoc advances over <<MARK ... MARK (or <<-MARK).
func (s *tfScanner) heredoc() error {
	s.i += 2
	if s.i < len(s.src) && s.src[s.i] == '-' {
		s.i++
	}
	mark := s.ident()
	nl := strings.IndexByte(s.src[s.i:], '\n')
	if mark == "" || nl < 0 {
		return fmt.Errorf("bad heredoc")
	}
	s.i += nl + 1
	for s.i < len(s.src) {
		e := strings.IndexByte(s.src[s.i:], '\n')
		line := s.src[s.i:]
		if e >= 0 {
			line = s.src[s.i : s.i+e]
		}
		if strings.TrimSpace(line) == mark {
			s.i += len(strings.TrimRight(line, "\r"))
			return nil
		}
		if e < 0 {
			break
		}
		s.i += e + 1
	}
	return fmt.Errorf("unterminated heredoc %s", mark)
}

/* ------------------------------ literal values ----------------------------- */

// errNotLiteral: the expression references something (a variable, a data
// source, a function other than jsonencode) and cannot be read mechanically.
var errNotLiteral = fmt.Errorf("not a literal expression")

// literalString returns the value of a plain quoted string without template
// sequences.
func literalString(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return "", false
	}
	if strings.Contains(strings.ReplaceAll(strings.ReplaceAll(raw, "$${", ""), "%%{", ""), "${") ||
		strings.Contains(strings.ReplaceAll(raw, "%%{", ""), "%{") {
		return "", false
	}
	v, err := strconv.Unquote(raw)
	if err != nil {
		return "", false
	}
	return strings.ReplaceAll(strings.ReplaceAll(v, "$${", "${"), "%%{", "%{"), true
}

// Policy document forms in Terraform.
const (
	docJSONEncode = "jsonencode"
	docHeredoc    = "heredoc"
	docString     = "string"
)

// policyDocument reads a literal policy document from an attribute value:
// jsonencode({...}) with literal contents, a heredoc of JSON, or a quoted
// JSON string. Anything else (data.aws_iam_policy_document, file(),
// templatefile(), variables) is not literal.
func policyDocument(raw string) (doc string, form string, err error) {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "jsonencode(") && strings.HasSuffix(raw, ")"):
		v, err := parseLiteral(raw[len("jsonencode(") : len(raw)-1])
		if err != nil {
			return "", "", err
		}
		b, err := json.Marshal(v)
		if err != nil {
			return "", "", err
		}
		return string(b), docJSONEncode, nil
	case strings.HasPrefix(raw, "<<"):
		body, ok := heredocBody(raw)
		if !ok || strings.Contains(strings.ReplaceAll(body, "$${", ""), "${") {
			return "", "", errNotLiteral
		}
		return strings.ReplaceAll(body, "$${", "${"), docHeredoc, nil
	case strings.HasPrefix(raw, "\""):
		s, ok := literalString(raw)
		if !ok {
			return "", "", errNotLiteral
		}
		return s, docString, nil
	}
	return "", "", errNotLiteral
}

// heredocBody returns the text between a heredoc's marker lines.
func heredocBody(raw string) (string, bool) {
	nl := strings.IndexByte(raw, '\n')
	if nl < 0 {
		return "", false
	}
	head := strings.TrimPrefix(strings.TrimPrefix(raw[:nl], "<<"), "-")
	mark := strings.TrimSpace(head)
	rest := raw[nl+1:]
	end := strings.LastIndex(rest, "\n")
	if end < 0 || strings.TrimSpace(rest[end+1:]) != mark {
		if strings.TrimSpace(rest) == mark {
			return "", true
		}
		return "", false
	}
	return rest[:end], true
}

// parseLiteral parses an HCL literal value (object, tuple, string, number,
// bool, null) into Go values. Any reference or function call is
// errNotLiteral.
func parseLiteral(src string) (any, error) {
	p := &litParser{s: src}
	p.ws()
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, errNotLiteral
	}
	return v, nil
}

type litParser struct {
	s string
	i int
}

func (p *litParser) ws() {
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			p.i++
		case c == '#' || (c == '/' && p.i+1 < len(p.s) && p.s[p.i+1] == '/'):
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
		case c == '/' && p.i+1 < len(p.s) && p.s[p.i+1] == '*':
			e := strings.Index(p.s[p.i+2:], "*/")
			if e < 0 {
				p.i = len(p.s)
				return
			}
			p.i += e + 4
		default:
			return
		}
	}
}

func (p *litParser) value() (any, error) {
	if p.i >= len(p.s) {
		return nil, errNotLiteral
	}
	c := p.s[p.i]
	switch {
	case c == '{':
		return p.object()
	case c == '[':
		return p.tuple()
	case c == '"':
		st := p.i
		sc := &tfScanner{src: p.s, i: p.i}
		if err := sc.str(); err != nil {
			return nil, err
		}
		p.i = sc.i
		v, ok := literalString(p.s[st:p.i])
		if !ok {
			return nil, errNotLiteral
		}
		return v, nil
	case c == '-' || (c >= '0' && c <= '9'):
		st := p.i
		p.i++
		for p.i < len(p.s) && strings.IndexByte("0123456789.eE+-", p.s[p.i]) >= 0 {
			p.i++
		}
		n := json.Number(p.s[st:p.i])
		if _, err := n.Float64(); err != nil {
			return nil, errNotLiteral
		}
		return n, nil
	case isIdentStart(c):
		st := p.i
		for p.i < len(p.s) && isIdentChar(p.s[p.i]) {
			p.i++
		}
		switch p.s[st:p.i] {
		case "true":
			return true, nil
		case "false":
			return false, nil
		case "null":
			return nil, nil
		}
	}
	return nil, errNotLiteral
}

func (p *litParser) object() (any, error) {
	p.i++ // {
	out := map[string]any{}
	for {
		p.ws()
		if p.i >= len(p.s) {
			return nil, errNotLiteral
		}
		if p.s[p.i] == '}' {
			p.i++
			return out, nil
		}
		var key string
		if p.s[p.i] == '"' {
			k, err := p.value()
			if err != nil {
				return nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, errNotLiteral
			}
			key = ks
		} else if isIdentStart(p.s[p.i]) {
			st := p.i
			for p.i < len(p.s) && isIdentChar(p.s[p.i]) {
				p.i++
			}
			key = p.s[st:p.i]
		} else {
			return nil, errNotLiteral
		}
		p.ws()
		if p.i >= len(p.s) || (p.s[p.i] != '=' && p.s[p.i] != ':') {
			return nil, errNotLiteral
		}
		p.i++
		p.ws()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out[key] = v
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
		}
	}
}

func (p *litParser) tuple() (any, error) {
	p.i++ // [
	out := []any{}
	for {
		p.ws()
		if p.i >= len(p.s) {
			return nil, errNotLiteral
		}
		if p.s[p.i] == ']' {
			p.i++
			return out, nil
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
		}
	}
}

/* -------------------------------- rendering -------------------------------- */

// hclEscape escapes template sequences so a JSON string is read by HCL as
// the same literal text (IAM policy variables such as ${aws:username}).
func hclEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "${", "$${"), "%{", "%%{")
}

// jsonencodeExpr renders a canonical policy document as an indented
// jsonencode(...) expression (HCL2 object constructors accept JSON's
// "key": value syntax), indented to sit under an attribute at indent.
func jsonencodeExpr(canonical, indent string) (string, error) {
	var v any
	if err := json.Unmarshal([]byte(canonical), &v); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(v, indent, "  ")
	if err != nil {
		return "", err
	}
	return "jsonencode(" + hclEscape(string(b)) + ")", nil
}

// heredocExpr renders a document as a heredoc in the style found.
func heredocExpr(canonical, oldRaw string) (string, error) {
	var v any
	if err := json.Unmarshal([]byte(canonical), &v); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	nl := strings.IndexByte(oldRaw, '\n')
	head := strings.TrimSpace(oldRaw[:nl])
	mark := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(head, "<<"), "-"))
	return head + "\n" + hclEscape(string(b)) + "\n" + mark, nil
}

// tfName makes a Terraform resource name from free text.
func tfName(s string) string {
	var b strings.Builder
	for i, r := range s {
		switch {
		case r == '_' || unicode.IsLetter(r) || (i > 0 && (unicode.IsDigit(r) || r == '-')):
			b.WriteRune(unicode.ToLower(r))
		default:
			b.WriteByte('_')
		}
	}
	out := strings.ReplaceAll(b.String(), "-", "_")
	if out == "" || !isIdentStart(out[0]) {
		out = "r_" + out
	}
	return out
}

// tfTags renders a tags map literal.
func tfTags(tags map[string]string, indent string) string {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("{\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s  %s = %s\n", indent, strconv.Quote(k), strconv.Quote(hclEscape(tags[k])))
	}
	b.WriteString(indent + "}")
	return b.String()
}

// edit is one byte-range replacement in a file.
type edit struct {
	start, end int
	text       string
}

func applyEdits(src string, edits []edit) (string, error) {
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	prev := len(src) + 1
	for _, e := range edits {
		if e.start < 0 || e.end > len(src) || e.start > e.end || e.end > prev {
			return "", fmt.Errorf("overlapping or invalid edits")
		}
		src = src[:e.start] + e.text + src[e.end:]
		prev = e.start
	}
	return src, nil
}

// lineIndent is the indentation of the line holding position i.
func lineIndent(src string, i int) string {
	ls := strings.LastIndexByte(src[:i], '\n') + 1
	j := ls
	for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
		j++
	}
	return src[ls:j]
}
