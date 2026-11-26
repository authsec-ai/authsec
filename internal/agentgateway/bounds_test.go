package agentgateway

import (
	"strings"
	"testing"
	"time"
)

func fp(f float64) *float64 { return &f }
func ip(i int) *int         { return &i }

func TestArgBoundsCheck(t *testing.T) {
	b := &ArgBounds{Fields: []ArgBound{
		{Path: "amount", Type: BoundNumber, Min: fp(0), Max: fp(100), Required: true},
		{Path: "payee.country", Type: BoundString, Enum: []string{"US", "DE"}},
		{Path: "memo", Type: BoundString, MaxLen: ip(5), Regex: `^[a-z]*$`},
		{Path: "items", Type: BoundArray, MaxItems: ip(2)},
	}}
	if errs := b.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	cases := map[string][]string{
		`{"amount":10,"payee":{"country":"US"},"memo":"ok","items":[1]}`: nil,
		`{"amount":10.5}`:                       nil,
		`{}`:                                    {"amount:required"},
		`{"amount":101}`:                        {"amount:max"},
		`{"amount":-1}`:                         {"amount:min"},
		`{"amount":"10"}`:                       {"amount:type"},
		`{"amount":1,"payee":{"country":"FR"}}`: {"payee.country:enum"},
		`{"amount":1,"memo":"toolong"}`:         {"memo:max_len"},
		`{"amount":1,"memo":"AB"}`:              {"memo:regex"},
		`{"amount":1,"items":[1,2,3]}`:          {"items:max_items"},
		`not json`:                              {":unreadable"},
	}
	for args, want := range cases {
		v, held := b.Check([]byte(args))
		var got []string
		for _, x := range v {
			got = append(got, x.Path+":"+x.Rule)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: got %v want %v", args, got, want)
		}
		if args == `{"amount":101}` && string(held["amount"]) != "101" {
			t.Errorf("held value: %s", held["amount"])
		}
	}
}

func TestArgBoundsValidateAndPolicy(t *testing.T) {
	bad := []*ArgBounds{
		{Fields: []ArgBound{{Path: "a", Type: BoundNumber}}},
		{Fields: []ArgBound{{Path: "a", Type: BoundNumber, Min: fp(5), Max: fp(1)}}},
		{Fields: []ArgBound{{Path: "a b", Type: BoundString, MaxLen: ip(3)}}},
		{Fields: []ArgBound{{Path: "a", Type: BoundString, Regex: "("}}},
		{Fields: []ArgBound{{Path: "a", Type: BoundArray}}},
		{Fields: []ArgBound{{Path: "a", Type: BoundNumber, Max: fp(1)}}, OnViolation: "maybe"},
		{},
	}
	for i, b := range bad {
		if len(b.Validate()) == 0 {
			t.Errorf("bad %d accepted", i)
		}
	}
	// Bounds on a deny or a model policy are refused.
	p := Policy{Name: "x", Effect: EffectDeny, Kind: KindMCPTool, Enabled: true,
		Conditions: Conditions{ArgBounds: &ArgBounds{Fields: []ArgBound{{Path: "a", Type: BoundNumber, Max: fp(1)}}}}}
	if len(p.Validate()) == 0 {
		t.Fatal("bounds on a deny policy accepted")
	}
	// The deciding allow policy's bounds travel with the result.
	p.Effect = EffectAllow
	if errs := p.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	res := Evaluate([]Policy{p}, Request{Kind: KindMCPTool, SubjectID: "a", Server: "s", Tool: "t"}, ModeEnforce, time.Now(), nil)
	if !res.Allowed || res.ArgBounds == nil {
		t.Fatalf("%+v", res)
	}
	if b, ok := BoundsFromContext(map[string]any{"arg_bounds": map[string]any{"fields": []any{map[string]any{"path": "a", "type": "number"}}}}); ok || b != nil {
		t.Fatal("invalid bounds from context accepted")
	}
}

func TestRunIDValidation(t *testing.T) {
	for _, ok := range []string{"run-1", "a.b:c_d", strings.Repeat("x", 128)} {
		if !ValidRunID(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "has space", strings.Repeat("x", 129), "x\n"} {
		if ValidRunID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	r, err := FromAuthZEN(Request{Kind: KindMCPTool, SubjectID: "a", Server: "s", Tool: "t", RunID: "run-7"}.ToAuthZEN())
	if err != nil || r.RunID != "run-7" {
		t.Fatal(r, err)
	}
}
