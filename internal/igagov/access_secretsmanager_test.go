package igagov

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var smProd = SecretTarget{Partition: "aws", Region: "us-east-1", Account: "111122223333", Secret: "prod/db", Suffix: "AbCdEf"}

func smDoc(t *testing.T, tg SecretTarget, access []string, end *time.Time) map[string]any {
	t.Helper()
	if end == nil {
		end = &AccessNoEnd
	}
	doc, _, _, _, err := AccessDocument(AccessEffectBlock, access, tg, nil, end)
	if err != nil {
		t.Fatalf("%v: %v", access, err)
	}
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestSecretsManagerAccessDocuments states the intended documents by hand (the
// action table in access_secretsmanager.go, checked against the AWS Service
// Authorization Reference) and compares them as JSON.
func TestSecretsManagerAccessDocuments(t *testing.T) {
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const N = "arn:aws:secretsmanager:*:111122223333:secret:prod/db-??????"
	window := `"Condition":{"DateLessThan":{"aws:CurrentTime":"2026-11-01T00:00:00Z"}}`
	overwrite := `{"Sid":"AuthSecAccessOverwrite","Effect":"Deny","Action":"secretsmanager:CreateSecret","Resource":"*",
		"Condition":{"DateLessThan":{"aws:CurrentTime":"2026-11-01T00:00:00Z"},"Bool":{"secretsmanager:ForceOverwriteReplicaSecret":"true"},
		"StringEquals":{"secretsmanager:Name":"prod/db"}}}`
	main := func(actions ...string) string {
		q := make([]string, len(actions))
		for i, a := range actions {
			q[i] = `"secretsmanager:` + a + `"`
		}
		return `{"Sid":"AuthSecAccessSecret","Effect":"Deny","Resource":"` + N + `",` + window + `,"Action":[` + strings.Join(q, ",") + `]}`
	}
	cases := []struct {
		name   string
		access []string
		end    *time.Time
		want   string
	}{
		{"read", []string{AccessRead}, &end, `{"Version":"2012-10-17","Statement":[` +
			main("DeleteResourcePolicy", "GetSecretValue", "PutResourcePolicy", "ReplicateSecretToRegions", "RotateSecret", "TagResource", "UntagResource") + `]}`},
		{"write", []string{AccessWrite}, &end, `{"Version":"2012-10-17","Statement":[` +
			main("CancelRotateSecret", "PutSecretValue", "ReplicateSecretToRegions", "RestoreSecret", "RotateSecret", "StopReplicationToReplica",
				"TagResource", "UntagResource", "UpdateSecret", "UpdateSecretVersionStage") + `,` + overwrite + `]}`},
		{"delete", []string{AccessDelete}, &end, `{"Version":"2012-10-17","Statement":[` +
			main("DeleteSecret", "RemoveRegionsFromReplication", "ReplicateSecretToRegions", "UpdateSecretVersionStage") + `,` + overwrite + `]}`},
		{"read+write+delete", []string{AccessRead, AccessWrite, AccessDelete}, &end, `{"Version":"2012-10-17","Statement":[` +
			main("CancelRotateSecret", "DeleteResourcePolicy", "DeleteSecret", "GetSecretValue", "PutResourcePolicy", "PutSecretValue",
				"RemoveRegionsFromReplication", "ReplicateSecretToRegions", "RestoreSecret", "RotateSecret", "StopReplicationToReplica",
				"TagResource", "UntagResource", "UpdateSecret", "UpdateSecretVersionStage") + `,` + overwrite + `]}`},
		{"all, no end", []string{AccessAll}, nil, `{"Version":"2012-10-17","Statement":[
			{"Sid":"AuthSecAccessSecret","Effect":"Deny","Action":"secretsmanager:*","Resource":"` + N + `"},
			{"Sid":"AuthSecAccessOverwrite","Effect":"Deny","Action":"secretsmanager:CreateSecret","Resource":"*",
				"Condition":{"Bool":{"secretsmanager:ForceOverwriteReplicaSecret":"true"},"StringEquals":{"secretsmanager:Name":"prod/db"}}}]}`},
	}
	for _, c := range cases {
		got := smDoc(t, smProd, c.access, c.end)
		var want map[string]any
		if err := json.Unmarshal([]byte(c.want), &want); err != nil {
			t.Fatalf("%s: bad want: %v", c.name, err)
		}
		if !reflect.DeepEqual(got, want) {
			g, _ := json.Marshal(got)
			t.Errorf("%s:\n got %s\nwant %s", c.name, g, mustCompact(t, c.want))
		}
	}
	// A pick through the name selector writes the same document.
	sel := smProd
	sel.Suffix = ""
	for _, access := range [][]string{{AccessRead}, {AccessAll}} {
		a, ha, _, _, _ := AccessDocument(AccessEffectBlock, access, smProd, nil, &end)
		b, hb, _, _, _ := AccessDocument(AccessEffectBlock, access, sel, nil, &end)
		if string(a) != string(b) || ha != hb {
			t.Fatalf("%v: the selector pick differs:\n%s\n%s", access, a, b)
		}
	}
}

func TestParseSecretsManagerSecretARN(t *testing.T) {
	long := strings.Repeat("n", 512)
	ok := map[string]SecretTarget{
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-AbCdEf":        smProd,
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-??????":        {Partition: "aws", Region: "us-east-1", Account: "111122223333", Secret: "prod/db"},
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-abcdef-AbCdEf": {Partition: "aws", Region: "us-east-1", Account: "111122223333", Secret: "prod/db-abcdef", Suffix: "AbCdEf"},
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:a/_+=.@-b-AbCdEf":      {Partition: "aws", Region: "us-east-1", Account: "111122223333", Secret: "a/_+=.@-b", Suffix: "AbCdEf"},
		"arn:aws-cn:secretsmanager:cn-north-1:111122223333:secret:prod/db-AbCdEf":    {Partition: "aws-cn", Region: "cn-north-1", Account: "111122223333", Secret: "prod/db", Suffix: "AbCdEf"},
		"arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:p-AbCdEf":   {Partition: "aws-us-gov", Region: "us-gov-west-1", Account: "111122223333", Secret: "p", Suffix: "AbCdEf"},
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:" + long + "-AbCdEf":   {Partition: "aws", Region: "us-east-1", Account: "111122223333", Secret: long, Suffix: "AbCdEf"},
		// Pinned on purpose: a partial ARN whose name ends in six letters
		// reads as a shorter name, so the service checks the name against
		// the last scan.
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-backup": {Partition: "aws", Region: "us-east-1", Account: "111122223333", Secret: "prod/db", Suffix: "backup"},
	}
	for arn, want := range ok {
		got, parsed := ParseSecretsManagerSecretARN(arn)
		if !parsed || got != want {
			t.Errorf("%s: %v %+v", arn, parsed, got)
		}
	}
	for _, arn := range []string{
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-*",
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:*",
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:pr?d/db-??????",
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-?????",
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-???????x",
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db",
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-AbCdE",
		"arn:aws:secretsmanager:*:111122223333:secret:prod/db-AbCdEf",
		"arn:aws:secretsmanager:us-east-1:*:secret:prod/db-AbCdEf",
		"arn:aws:secretsmanager:us-east-1:11112222333:secret:prod/db-AbCdEf",
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:-AbCdEf",
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:" + long + "n-AbCdEf",
		"arn:aws:s3:::prod-db",
	} {
		if _, parsed := ParseSecretsManagerSecretARN(arn); parsed {
			t.Errorf("%s parsed", arn)
		}
	}
	if _, err := ParseAWSAccessTarget("arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-AbCdEf", "x/"); err == nil ||
		!strings.Contains(err.Error(), "resource.prefix") {
		t.Fatalf("a prefix on a secret: %v", err)
	}
	got, err := ParseAWSAccessTarget("arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-??????", "")
	if err != nil || got.Type() != AccessTypeSecretsManagerSecret || got.Name() != "prod/db" || got.ARNAccount() != "111122223333" ||
		got.ARNRegion() != "us-east-1" || got.ARN() != "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-??????" {
		t.Fatalf("the selector row: %#v %v", got, err)
	}
}

// Every combination of access levels: every document fits AWS's size limit
// and the deployment row's CHECKs, names the secret by name or "*" under both
// conditions, never touches an action without a resource type, and an allow
// is refused.
func TestSecretsManagerAccessProperties(t *testing.T) {
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	start := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	long := SecretTarget{Partition: "aws-us-gov", Region: "us-gov-west-1", Account: "111122223333", Secret: strings.Repeat("s", 512)}
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
	actionsOf := map[string]map[string]bool{}
	key := func(a []string) string { return strings.Join(a, "+") }
	for _, tg := range []SecretTarget{smProd, long} {
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
			var d struct {
				Statement []struct {
					Sid       string
					Action    any
					Resource  any
					Condition map[string]map[string]any
				}
			}
			if err := json.Unmarshal(doc, &d); err != nil {
				t.Fatal(err)
			}
			for _, st := range d.Statement {
				switch st.Resource {
				case tg.NameARN():
				case "*":
					if st.Sid != AccessSidOverwrite || st.Condition[CondBool][KeySMForceOverwrite] != "true" ||
						st.Condition[CondStringEquals][KeySMName] != tg.Secret {
						t.Fatalf("%v: %s on * without both conditions: %+v", access, st.Sid, st)
					}
				default:
					t.Fatalf("%v: %s names %v", access, st.Sid, st.Resource)
				}
			}
			set := map[string]bool{}
			for _, a := range actions {
				set[a] = true
				switch a {
				case "secretsmanager:BatchGetSecretValue", "secretsmanager:ListSecrets", "secretsmanager:GetRandomPassword", "secretsmanager:ValidateResourcePolicy":
					t.Fatalf("%v denies %s", access, a)
				}
			}
			read := accessHas(access, AccessRead, AccessAll)
			if set["secretsmanager:GetSecretValue"] != (read && !accessHas(access, AccessAll)) || set[smAll] != accessHas(access, AccessAll) {
				t.Fatalf("%v: %v", access, actions)
			}
			if tg == smProd {
				actionsOf[key(access)] = set
			}
		}
	}
	// Monotonic: more levels never deny less.
	for _, a := range combos {
		for _, b := range combos {
			sub := true
			for _, l := range a {
				sub = sub && accessHas(b, l)
			}
			if !sub {
				continue
			}
			for act := range actionsOf[key(a)] {
				if !actionsOf[key(b)][act] {
					t.Fatalf("%v denies %s, %v does not", a, act, b)
				}
			}
		}
	}
}

func TestSecretsManagerAccessNotes(t *testing.T) {
	codes := func(access ...string) string {
		var out []string
		for _, n := range smProd.Notes(AccessEffectBlock, access) {
			out = append(out, n.Code)
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		want   string
		access []string
	}{
		{"read_copies_blocked,value_check_not_covered,copies_not_covered,same_name_covered", []string{AccessRead}},
		{"overwrite_by_name_blocked,same_name_covered", []string{AccessWrite}},
		{"overwrite_by_name_blocked,version_stage_blocked,overwrite_not_covered,same_name_covered", []string{AccessDelete}},
		{"read_copies_blocked,overwrite_by_name_blocked,version_stage_blocked,copies_not_covered,same_name_covered", []string{AccessDelete, AccessRead, AccessWrite}},
		{"copies_not_covered,same_name_covered", []string{AccessAll}},
	} {
		if got := codes(c.access...); got != c.want {
			t.Errorf("%v: %s, want %s", c.access, got, c.want)
		}
	}
	in := AccessIntent{Effect: AccessEffectBlock, Access: []string{AccessRead}}
	if s := AccessSentence(in, smProd, []string{"X"}); s != "Block read on Secrets Manager secret prod/db (us-east-1, account 111122223333) for X, with no end date." {
		t.Fatalf("sentence %q", s)
	}
}
