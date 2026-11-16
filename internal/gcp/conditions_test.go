package gcp

import (
	"strings"
	"testing"
	"time"
)

func ts(t *testing.T, s string) *time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return &v
}

func TestParseCondition_Bounds(t *testing.T) {
	cases := []struct {
		name    string
		expr    string
		expires string
		starts  string
	}{
		{"expiry", `request.time < timestamp("2027-06-30T00:00:00Z")`, "2027-06-30T00:00:00Z", ""},
		{"expired", `request.time < timestamp('2026-01-01T00:00:00Z')`, "2026-01-01T00:00:00Z", ""},
		{"not before", `request.time >= timestamp("2026-03-01T00:00:00Z")`, "", "2026-03-01T00:00:00Z"},
		{"window", `request.time > timestamp("2026-03-01T00:00:00Z") && request.time < timestamp("2026-09-01T00:00:00Z")`, "2026-09-01T00:00:00Z", "2026-03-01T00:00:00Z"},
		{"parenthesised", `(request.time < timestamp("2026-09-01T00:00:00Z")) && (resource.name.startsWith("projects/_/buckets/a"))`, "2026-09-01T00:00:00Z", ""},
		{"earliest upper bound wins", `request.time < timestamp("2028-01-01T00:00:00Z") && request.time < timestamp("2027-01-01T00:00:00Z")`, "2027-01-01T00:00:00Z", ""},
		{"offset normalised to UTC", `request.time < timestamp("2027-01-01T02:00:00+02:00")`, "2027-01-01T00:00:00Z", ""},
		{"no time", `resource.name.startsWith("projects/_/buckets/a")`, "", ""},
		{"or means no bounds", `request.time < timestamp("2027-01-01T00:00:00Z") || resource.type == "x"`, "", ""},
		{"negation ignored", `!(request.time < timestamp("2027-01-01T00:00:00Z"))`, "", ""},
		{"bad timestamp ignored", `request.time < timestamp("soon")`, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := ParseCondition("t", "d", tc.expr)
			if c == nil {
				t.Fatal("nil condition")
			}
			if c.Expression != tc.expr {
				t.Fatalf("expression altered: %q", c.Expression)
			}
			check := func(label string, got *time.Time, want string) {
				switch {
				case want == "" && got != nil:
					t.Fatalf("%s = %v, want none", label, got)
				case want != "" && (got == nil || !got.Equal(*ts(t, want))):
					t.Fatalf("%s = %v, want %s", label, got, want)
				}
			}
			check("expires", c.ExpiresAt, tc.expires)
			check("starts", c.StartsAt, tc.starts)
		})
	}
}

func TestParseCondition_EmptyIsNil(t *testing.T) {
	if ParseCondition("t", "d", "  ") != nil {
		t.Fatal("no expression is no condition")
	}
}

func TestCondition_JSONKeepsRawCEL(t *testing.T) {
	expr := `request.time < timestamp("2027-06-30T00:00:00Z") && resource.name.startsWith("x\"y")`
	js, err := ParseCondition("Until mid 2027", "contractor", expr).JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(js, `"title":"Until mid 2027"`) || !strings.Contains(js, `"expression"`) {
		t.Fatalf("json = %s", js)
	}
}

func TestCondition_HashDistinguishesConditionsAndNil(t *testing.T) {
	a := ParseCondition("a", "", `request.time < timestamp("2026-01-01T00:00:00Z")`)
	b := ParseCondition("a", "", `request.time < timestamp("2027-01-01T00:00:00Z")`)
	if a.Hash() == b.Hash() || a.Hash() == "" || len(a.Hash()) != 12 {
		t.Fatalf("hashes %q %q", a.Hash(), b.Hash())
	}
	if a.Hash() != ParseCondition("a", "", a.Expression).Hash() {
		t.Fatal("hash must be stable")
	}
	var none *Condition
	if none.Hash() != "" {
		t.Fatal("no condition hashes to empty")
	}
}
