package igagov

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var ssmDB = SSMParameterTarget{Partition: "aws", Region: "us-east-1", Account: "111122223333", Param: "prod/db/password"}

// TestSSMAccessDocuments states the intended documents by hand (the action
// table in access_ssm.go, checked against the AWS Service Authorization
// Reference) and compares them as JSON.
func TestSSMAccessDocuments(t *testing.T) {
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const P = "arn:aws:ssm:us-east-1:111122223333:parameter/"
	window := `"Condition":{"DateLessThan":{"aws:CurrentTime":"2026-11-01T00:00:00Z"}}`
	path := `{"Sid":"AuthSecAccessPath","Effect":"Deny","Action":"ssm:GetParametersByPath","Resource":["` + P + `","` + P + `prod","` + P + `prod/db"],` + window + `}`
	main := func(actions ...string) string {
		q := make([]string, len(actions))
		for i, a := range actions {
			q[i] = `"ssm:` + a + `"`
		}
		return `{"Sid":"AuthSecAccessParameter","Effect":"Deny","Resource":"` + P + `prod/db/password",` + window + `,"Action":[` + strings.Join(q, ",") + `]}`
	}
	cases := []struct {
		name   string
		access []string
		end    *time.Time
		want   string
	}{
		{"read", []string{AccessRead}, &end, `{"Version":"2012-10-17","Statement":[` +
			main("AddTagsToResource", "DeleteResourcePolicy", "GetParameter", "GetParameterHistory", "GetParameters", "PutResourcePolicy", "RemoveTagsFromResource") + `,` + path + `]}`},
		{"write", []string{AccessWrite}, &end, `{"Version":"2012-10-17","Statement":[` +
			main("AddTagsToResource", "LabelParameterVersion", "PutParameter", "RemoveTagsFromResource", "UnlabelParameterVersion") + `]}`},
		{"delete", []string{AccessDelete}, &end, `{"Version":"2012-10-17","Statement":[` + main("DeleteParameter", "DeleteParameters") + `]}`},
		{"all, no end", []string{AccessAll}, nil, `{"Version":"2012-10-17","Statement":[
			{"Sid":"AuthSecAccessParameter","Effect":"Deny","Action":"ssm:*","Resource":"` + P + `prod/db/password"},
			{"Sid":"AuthSecAccessPath","Effect":"Deny","Action":"ssm:GetParametersByPath","Resource":["` + P + `","` + P + `prod","` + P + `prod/db"]}]}`},
	}
	for _, c := range cases {
		e := c.end
		if e == nil {
			e = &AccessNoEnd
		}
		doc, _, _, _, err := AccessDocument(AccessEffectBlock, c.access, ssmDB, nil, e)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var got, want map[string]any
		if err := json.Unmarshal(doc, &got); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(c.want), &want); err != nil {
			t.Fatalf("%s: bad want: %v", c.name, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %s\nwant %s", c.name, doc, mustCompact(t, c.want))
		}
	}
	// A parameter at the top level: only the root lists it.
	top := SSMParameterTarget{Partition: "aws", Region: "us-east-1", Account: "111122223333", Param: "db"}
	if got := top.PathARNs(); len(got) != 1 || got[0] != P {
		t.Fatalf("top-level paths %v", got)
	}
}

func TestParseSSMParameterARN(t *testing.T) {
	ok := map[string]SSMParameterTarget{
		"arn:aws:ssm:us-east-1:111122223333:parameter/prod/db/password": ssmDB,
		"arn:aws:ssm:us-east-1:111122223333:parameter/db":               {Partition: "aws", Region: "us-east-1", Account: "111122223333", Param: "db"},
		"arn:aws-cn:ssm:cn-north-1:111122223333:parameter/a.b_c-d":      {Partition: "aws-cn", Region: "cn-north-1", Account: "111122223333", Param: "a.b_c-d"},
		"arn:aws:ssm:us-east-1:111122223333:parameter/" + strings.Repeat("a/", 14) + "z": {Partition: "aws", Region: "us-east-1", Account: "111122223333",
			Param: strings.Repeat("a/", 14) + "z"},
	}
	for arn, want := range ok {
		got, parsed := ParseSSMParameterARN(arn)
		if !parsed || got != want {
			t.Errorf("%s: %v %+v", arn, parsed, got)
		}
	}
	for _, arn := range []string{
		"arn:aws:ssm:us-east-1:111122223333:parameter/prod/*",
		"arn:aws:ssm:us-east-1:111122223333:parameter/prod/db?",
		"arn:aws:ssm:us-east-1:111122223333:parameter/*",
		"arn:aws:ssm:us-east-1:111122223333:parameter/",
		"arn:aws:ssm:us-east-1:111122223333:parameter//prod",
		"arn:aws:ssm:us-east-1:111122223333:parameter/prod/",
		"arn:aws:ssm:us-east-1:111122223333:parameter/" + strings.Repeat("a/", 15) + "z",
		"arn:aws:ssm:*:111122223333:parameter/prod",
		"arn:aws:ssm:us-east-1:111122223333:document/prod",
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:prod-AbCdEf",
	} {
		if _, parsed := ParseSSMParameterARN(arn); parsed {
			t.Errorf("%s parsed", arn)
		}
	}
	if _, err := ParseAWSAccessTarget(ssmDB.ARN(), "x/"); err == nil || !strings.Contains(err.Error(), "resource.prefix") {
		t.Fatalf("a prefix on a parameter: %v", err)
	}
	got, err := ParseAWSAccessTarget(ssmDB.ARN(), "")
	if err != nil || got.Type() != AccessTypeSSMParameter || got.Name() != "/prod/db/password" || got.ARNAccount() != "111122223333" {
		t.Fatalf("parsed %#v %v", got, err)
	}
}

// Every combination fits the limits, names only the parameter and the paths
// above it, denies a listing whenever it denies the value, and refuses an
// allow.
func TestSSMAccessProperties(t *testing.T) {
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	start := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	deep := SSMParameterTarget{Partition: "aws-us-gov", Region: "us-gov-west-1", Account: "111122223333", Param: strings.Repeat("level/", 14) + strings.Repeat("p", 900)}
	levels := []string{AccessRead, AccessWrite, AccessDelete}
	var combos [][]string
	for mask := 1; mask < 8; mask++ {
		var c []string
		for i, l := range levels {
			if mask&(1<<i) != 0 {
				c = append(c, l)
			}
		}
		combos = append(combos, c)
	}
	for _, tg := range []SSMParameterTarget{ssmDB, deep} {
		allowed := map[string]bool{tg.ARN(): true}
		for _, p := range tg.PathARNs() {
			allowed[p] = true
		}
		for _, access := range append(combos, []string{AccessAll}) {
			if _, _, _, _, err := AccessDocument(AccessEffectAllow, access, tg, &start, &end); !errors.Is(err, ErrAccessBlockOnly) {
				t.Fatalf("allow %v: %v", access, err)
			}
			doc, _, actions, resources, err := AccessDocument(AccessEffectBlock, access, tg, &start, &end)
			if err != nil {
				t.Fatalf("%v: %v", access, err)
			}
			if PolicyChars(doc) > MaxPolicyChars || len(actions) < 1 || len(actions) > 50 || len(resources) < 1 || len(resources) > 20 {
				t.Fatalf("%v: %d chars, %d actions, %d resources", access, PolicyChars(doc), len(actions), len(resources))
			}
			if strings.Count(string(doc), `"DateGreaterThan"`) != strings.Count(string(doc), `"Sid"`) {
				t.Fatalf("%v: a statement without the window: %s", access, doc)
			}
			for _, r := range resources {
				if !allowed[r] {
					t.Fatalf("%v names %s", access, r)
				}
			}
			reads := accessHas(access, AccessRead, AccessAll)
			has := func(a string) bool {
				for _, x := range actions {
					if x == a {
						return true
					}
				}
				return false
			}
			if has(ssmByPath) != reads || (accessHas(access, AccessRead) && !has("ssm:GetParameterHistory")) {
				t.Fatalf("%v: %v", access, actions)
			}
		}
	}
}

func TestSSMAccessNotes(t *testing.T) {
	codes := func(access ...string) string {
		var out []string
		for _, n := range ssmDB.Notes(AccessEffectBlock, access) {
			out = append(out, n.Code)
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		want   string
		access []string
	}{
		{"path_listing_blocked,history_blocked,copies_not_covered", []string{AccessRead}},
		{"", []string{AccessWrite}},
		{"overwrite_not_covered", []string{AccessDelete}},
		{"path_listing_blocked,copies_not_covered", []string{AccessAll}},
	} {
		if got := codes(c.access...); got != c.want {
			t.Errorf("%v: %s, want %s", c.access, got, c.want)
		}
	}
	if n := ssmDB.Notes(AccessEffectBlock, []string{AccessRead})[0].Message; !strings.Contains(n, "/, /prod, /prod/db is refused") {
		t.Fatalf("path note %q", n)
	}
	in := AccessIntent{Effect: AccessEffectBlock, Access: []string{AccessRead}}
	if s := AccessSentence(in, ssmDB, []string{"X"}); s != "Block read on SSM parameter /prod/db/password (us-east-1, account 111122223333) for X, with no end date." {
		t.Fatalf("sentence %q", s)
	}
}
