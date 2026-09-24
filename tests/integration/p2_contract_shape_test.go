package integration

// A small JSON shape language for the frozen-contract tests
// (p2_contract_*_test.go, SPEC-iga-phase2-graph.md §5): each §5.2 envelope and
// §5.3 body is written down once, field by field, and every response is
// checked against it.
//
// An object shape is CLOSED: every field it names must be present (unless
// marked optional) with the named type, and a field it does not name is an
// error. So a renamed field fails twice (missing and unexpected), a dropped
// field fails, a field that turns from null into absent fails, and a field
// added without updating the contract fails -- the console builds its types
// from these shapes (§2.14.14 "Development fixtures"), so none of those may
// happen silently.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// contractShape checks one decoded JSON value, appending a message per
// violation, each prefixed with its JSON path.
type contractShape interface {
	check(path string, v any, errs *[]string)
}

// contractField is one field of a closed object.
type contractField struct {
	name string
	s    contractShape
	opt  bool // may be absent (it is never null unless its shape allows it)
}

// contractReq is a required field; contractOpt one that may be absent.
func contractReq(name string, s contractShape) contractField { return contractField{name: name, s: s} }
func contractOpt(name string, s contractShape) contractField {
	return contractField{name: name, s: s, opt: true}
}

type contractObjShape struct{ fields []contractField }

// contractObj is a closed object: exactly these fields.
func contractObj(fields ...contractField) contractShape { return contractObjShape{fields} }

// contractExtend is base plus more fields (base must be a contractObj).
func contractExtend(base contractShape, more ...contractField) contractShape {
	b := base.(contractObjShape)
	out := append([]contractField{}, b.fields...)
	for _, m := range more {
		replaced := false
		for i := range out {
			if out[i].name == m.name {
				out[i], replaced = m, true
			}
		}
		if !replaced {
			out = append(out, m)
		}
	}
	return contractObjShape{out}
}

// contractWithout is base minus the named fields.
func contractWithout(base contractShape, names ...string) contractShape {
	b := base.(contractObjShape)
	var out []contractField
	for _, f := range b.fields {
		drop := false
		for _, n := range names {
			drop = drop || f.name == n
		}
		if !drop {
			out = append(out, f)
		}
	}
	return contractObjShape{out}
}

func (s contractObjShape) check(path string, v any, errs *[]string) {
	m, ok := v.(map[string]any)
	if !ok {
		contractFail(errs, path, "want an object, got %s", contractJSON(v))
		return
	}
	known := map[string]bool{}
	for _, f := range s.fields {
		known[f.name] = true
		x, present := m[f.name]
		if !present {
			if !f.opt {
				contractFail(errs, path, "missing field %q", f.name)
			}
			continue
		}
		f.s.check(path+"."+f.name, x, errs)
	}
	var extra []string
	for k := range m {
		if !known[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		contractFail(errs, path, "unexpected field %q = %s", k, contractJSON(m[k]))
	}
}

// contractMapShape is an OPEN object whose values all have one shape (labels
// keyed by ref, tags, facets by name).
type contractMapShape struct{ val contractShape }

func contractMap(val contractShape) contractShape { return contractMapShape{val} }

func (s contractMapShape) check(path string, v any, errs *[]string) {
	m, ok := v.(map[string]any)
	if !ok {
		contractFail(errs, path, "want an object, got %s", contractJSON(v))
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s.val.check(path+"["+k+"]", m[k], errs)
	}
}

type contractArrShape struct {
	elem contractShape
	min  int
}

// contractArr is an array (never null) of elem; contractArrMin also demands
// at least min elements, so a fixture that stopped producing a row fails
// loudly instead of passing vacuously.
func contractArr(elem contractShape) contractShape { return contractArrShape{elem: elem} }
func contractArrMin(min int, elem contractShape) contractShape {
	return contractArrShape{elem: elem, min: min}
}

func (s contractArrShape) check(path string, v any, errs *[]string) {
	a, ok := v.([]any)
	if !ok {
		contractFail(errs, path, "want an array, got %s", contractJSON(v))
		return
	}
	if len(a) < s.min {
		contractFail(errs, path, "want at least %d elements, got %d", s.min, len(a))
	}
	for i, x := range a {
		s.elem.check(fmt.Sprintf("%s[%d]", path, i), x, errs)
	}
}

type contractNullableShape struct{ s contractShape }

// contractNullable is null or s.
func contractNullable(s contractShape) contractShape { return contractNullableShape{s} }

func (s contractNullableShape) check(path string, v any, errs *[]string) {
	if v == nil {
		return
	}
	s.s.check(path, v, errs)
}

// contractFunc is a shape written as code: unions keyed by a discriminator
// (execution_role by state, limitations by code, graph nodes by kind).
type contractFunc func(path string, v any, errs *[]string)

func (f contractFunc) check(path string, v any, errs *[]string) { f(path, v, errs) }

// Leaves.
var (
	contractAnyValue contractShape = contractFunc(func(string, any, *[]string) {})
	contractStr      contractShape = contractFunc(func(path string, v any, errs *[]string) {
		if _, ok := v.(string); !ok {
			contractFail(errs, path, "want a string, got %s", contractJSON(v))
		}
	})
	contractNonEmpty contractShape = contractFunc(func(path string, v any, errs *[]string) {
		if s, ok := v.(string); !ok || s == "" {
			contractFail(errs, path, "want a non-empty string, got %s", contractJSON(v))
		}
	})
	contractBool contractShape = contractFunc(func(path string, v any, errs *[]string) {
		if _, ok := v.(bool); !ok {
			contractFail(errs, path, "want a boolean, got %s", contractJSON(v))
		}
	})
	contractInt contractShape = contractFunc(func(path string, v any, errs *[]string) {
		n, ok := v.(float64)
		if !ok || n != float64(int64(n)) {
			contractFail(errs, path, "want an integer, got %s", contractJSON(v))
		}
	})
	contractNull contractShape = contractFunc(func(path string, v any, errs *[]string) {
		if v != nil {
			contractFail(errs, path, "want null, got %s", contractJSON(v))
		}
	})
	// contractTime is an RFC 3339 time in UTC ("Z"), to the second or with a
	// fraction (§5.2 examples; D-27a renders Changes times to the microsecond).
	contractTime contractShape = contractFunc(func(path string, v any, errs *[]string) {
		s, ok := v.(string)
		if !ok {
			contractFail(errs, path, "want an RFC 3339 time, got %s", contractJSON(v))
			return
		}
		if !contractTimeRE.MatchString(s) {
			contractFail(errs, path, "want an RFC 3339 UTC time ending in Z, got %q", s)
			return
		}
		if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
			contractFail(errs, path, "not an RFC 3339 time: %q (%v)", s, err)
		}
	})
	// contractAccountID is a 12-digit AWS account id.
	contractAccountID contractShape = contractFunc(func(path string, v any, errs *[]string) {
		if s, ok := v.(string); !ok || !contractAccountRE.MatchString(s) {
			contractFail(errs, path, "want a 12-digit account id, got %s", contractJSON(v))
		}
	})
)

var (
	contractTimeRE    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$`)
	contractAccountRE = regexp.MustCompile(`^\d{12}$`)
)

// contractEnum is one of the given strings.
func contractEnum(vals ...string) contractShape {
	return contractFunc(func(path string, v any, errs *[]string) {
		s, ok := v.(string)
		for _, x := range vals {
			if ok && s == x {
				return
			}
		}
		contractFail(errs, path, "want one of %v, got %s", vals, contractJSON(v))
	})
}

// contractConst is exactly one JSON value.
func contractConst(want any) contractShape {
	return contractFunc(func(path string, v any, errs *[]string) {
		if contractJSON(v) != contractJSON(want) {
			contractFail(errs, path, "want %s, got %s", contractJSON(want), contractJSON(v))
		}
	})
}

// contractRef is a typed reference "<type>:<uuid>" (§5.2) of one of types.
func contractRef(types ...string) contractShape {
	return contractFunc(func(path string, v any, errs *[]string) {
		s, ok := v.(string)
		if !ok {
			contractFail(errs, path, "want a typed reference, got %s", contractJSON(v))
			return
		}
		typ, raw, cut := strings.Cut(s, ":")
		if _, err := uuid.Parse(raw); !cut || err != nil || strings.Count(s, ":") != 1 {
			contractFail(errs, path, "want \"<type>:<uuid>\", got %q", s)
			return
		}
		for _, t := range types {
			if typ == t {
				return
			}
		}
		contractFail(errs, path, "want a reference of type %v, got %q", types, s)
	})
}

// contractCoverageRef is "coverage:<run id>:<surface>" (§5.2 claim types).
var contractCoverageRef contractShape = contractFunc(func(path string, v any, errs *[]string) {
	s, _ := v.(string)
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 || parts[0] != "coverage" || parts[2] == "" {
		contractFail(errs, path, "want coverage:<run>:<surface>, got %s", contractJSON(v))
		return
	}
	if _, err := uuid.Parse(parts[1]); err != nil {
		contractFail(errs, path, "want coverage:<run uuid>:<surface>, got %q", s)
	}
})

func contractFail(errs *[]string, path, format string, args ...any) {
	*errs = append(*errs, path+": "+fmt.Sprintf(format, args...))
}

func contractJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	if len(raw) > 300 {
		return string(raw[:300]) + "..."
	}
	return string(raw)
}

// contractCheck validates body against s and fails the test with every
// violation found, each naming its JSON path.
func contractCheck(t *testing.T, what string, body any, s contractShape) {
	t.Helper()
	var errs []string
	s.check("$", body, &errs)
	if len(errs) > 0 {
		t.Errorf("%s: %d contract violation(s):\n  %s", what, len(errs), strings.Join(errs, "\n  "))
	}
}
