package igagov

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

var ddbOrders = DynamoTableTarget{Partition: "aws", Region: "us-east-1", Account: "111122223333", Table: "orders"}

// ddbDoc builds the table's document as the service does and decodes it.
func ddbDoc(t *testing.T, tg DynamoTableTarget, effect string, access []string, start, end *time.Time) map[string]any {
	t.Helper()
	if end == nil {
		end = &AccessNoEnd
	}
	doc, _, _, _, err := AccessDocument(effect, access, tg, start, end)
	if err != nil {
		t.Fatalf("%s %v: %v", effect, access, err)
	}
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestDynamoDBAccessDocuments states the intended documents by hand (the
// action table in access_dynamodb.go, checked against the AWS Service
// Authorization Reference) and compares them as JSON.
func TestDynamoDBAccessDocuments(t *testing.T) {
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const T = "arn:aws:dynamodb:us-east-1:111122223333:table/orders"
	window := `"Condition":{"DateLessThan":{"aws:CurrentTime":"2026-11-01T00:00:00Z"}}`
	replica := `{"Sid":"AuthSecAccessReplica","Effect":"Deny","Action":"dynamodb:CreateTableReplica","Resource":"arn:aws:dynamodb:*:111122223333:table/orders",` + window + `}`
	cases := []struct {
		name   string
		effect string
		access []string
		end    *time.Time
		want   string
	}{
		{"block read", AccessEffectBlock, []string{AccessRead}, &end, `{"Version":"2012-10-17","Statement":[
			{"Sid":"AuthSecAccessTable","Effect":"Deny","Resource":["` + T + `","` + T + `/*"],` + window + `,"Action":[
				"dynamodb:AssociateTableReplica","dynamodb:BatchGetItem","dynamodb:ConditionCheckItem","dynamodb:DescribeStream",
				"dynamodb:EnableKinesisStreamingDestination","dynamodb:ExportTableToPointInTime","dynamodb:GetItem","dynamodb:GetRecords",
				"dynamodb:GetShardIterator","dynamodb:PartiQLDelete","dynamodb:PartiQLInsert","dynamodb:PartiQLSelect","dynamodb:PartiQLUpdate",
				"dynamodb:Query","dynamodb:RestoreTableFromBackup","dynamodb:RestoreTableToPointInTime","dynamodb:Scan","dynamodb:SearchVectors",
				"dynamodb:StartAwsBackupJob","dynamodb:UpdateKinesisStreamingDestination"]},
			{"Sid":"AuthSecAccessReturnValues","Effect":"Deny","Resource":"` + T + `","Action":["dynamodb:DeleteItem","dynamodb:PutItem","dynamodb:UpdateItem"],
				"Condition":{"DateLessThan":{"aws:CurrentTime":"2026-11-01T00:00:00Z"},"StringEquals":{"dynamodb:ReturnValues":["ALL_NEW","ALL_OLD","UPDATED_NEW","UPDATED_OLD"]}}},
			` + replica + `]}`},
		{"block write", AccessEffectBlock, []string{AccessWrite}, &end, `{"Version":"2012-10-17","Statement":[
			{"Sid":"AuthSecAccessTable","Effect":"Deny","Resource":["` + T + `","` + T + `/*"],` + window + `,"Action":[
				"dynamodb:AssociateTableReplica","dynamodb:BatchWriteItem","dynamodb:PartiQLInsert","dynamodb:PartiQLUpdate","dynamodb:PutItem","dynamodb:UpdateItem"]},
			` + replica + `]}`},
		{"block delete", AccessEffectBlock, []string{AccessDelete}, &end, `{"Version":"2012-10-17","Statement":[
			{"Sid":"AuthSecAccessTable","Effect":"Deny","Resource":["` + T + `","` + T + `/*"],` + window + `,"Action":[
				"dynamodb:BatchWriteItem","dynamodb:DeleteItem","dynamodb:DeleteTable","dynamodb:PartiQLDelete","dynamodb:UpdateTimeToLive"]}]}`},
		{"block read+write: ReturnValues on DeleteItem only", AccessEffectBlock, []string{AccessRead, AccessWrite}, &end, ""},
		{"block all, no end", AccessEffectBlock, []string{AccessAll}, nil, `{"Version":"2012-10-17","Statement":[
			{"Sid":"AuthSecAccessTable","Effect":"Deny","Action":"dynamodb:*","Resource":["` + T + `","` + T + `/*"]},
			{"Sid":"AuthSecAccessReplica","Effect":"Deny","Action":"dynamodb:CreateTableReplica","Resource":"arn:aws:dynamodb:*:111122223333:table/orders"}]}`},
		{"allow read", AccessEffectAllow, []string{AccessRead}, &end, `{"Version":"2012-10-17","Statement":[
			{"Sid":"AuthSecAccessRead","Effect":"Allow","Resource":["` + T + `","` + T + `/index/*"],` + window + `,"Action":[
				"dynamodb:BatchGetItem","dynamodb:ConditionCheckItem","dynamodb:DescribeTable","dynamodb:GetItem","dynamodb:PartiQLSelect",
				"dynamodb:Query","dynamodb:Scan","dynamodb:SearchVectors"]}]}`},
		{"allow write", AccessEffectAllow, []string{AccessWrite}, &end, `{"Version":"2012-10-17","Statement":[
			{"Sid":"AuthSecAccessItems","Effect":"Allow","Resource":"` + T + `","Action":["dynamodb:PutItem","dynamodb:UpdateItem"],
				"Condition":{"DateLessThan":{"aws:CurrentTime":"2026-11-01T00:00:00Z"},"StringEqualsIfExists":{"dynamodb:ReturnValues":"NONE"}}}]}`},
		{"allow write+delete", AccessEffectAllow, []string{AccessDelete, AccessWrite}, &end, `{"Version":"2012-10-17","Statement":[
			{"Sid":"AuthSecAccessItems","Effect":"Allow","Resource":"` + T + `","Action":["dynamodb:BatchWriteItem","dynamodb:DeleteItem","dynamodb:PutItem","dynamodb:UpdateItem"],
				"Condition":{"DateLessThan":{"aws:CurrentTime":"2026-11-01T00:00:00Z"},"StringEqualsIfExists":{"dynamodb:ReturnValues":"NONE"}}}]}`},
		{"allow read+write", AccessEffectAllow, []string{AccessRead, AccessWrite}, &end, `{"Version":"2012-10-17","Statement":[
			{"Sid":"AuthSecAccessRead","Effect":"Allow","Resource":["` + T + `","` + T + `/index/*"],` + window + `,"Action":[
				"dynamodb:BatchGetItem","dynamodb:ConditionCheckItem","dynamodb:DescribeTable","dynamodb:GetItem","dynamodb:PartiQLSelect",
				"dynamodb:Query","dynamodb:Scan","dynamodb:SearchVectors"]},
			{"Sid":"AuthSecAccessItems","Effect":"Allow","Resource":"` + T + `",` + window + `,"Action":[
				"dynamodb:PartiQLInsert","dynamodb:PartiQLUpdate","dynamodb:PutItem","dynamodb:UpdateItem"]}]}`},
	}
	for _, c := range cases {
		got := ddbDoc(t, ddbOrders, c.effect, c.access, nil, c.end)
		if c.want == "" {
			// read+write: the main statement denies PutItem/UpdateItem
			// outright, so the ReturnValues statement names DeleteItem only.
			st := got["Statement"].([]any)
			if len(st) != 3 || st[1].(map[string]any)["Sid"] != AccessSidReturnValues || st[1].(map[string]any)["Action"] != "dynamodb:DeleteItem" {
				t.Fatalf("%s: %v", c.name, got)
			}
			continue
		}
		var want map[string]any
		if err := json.Unmarshal([]byte(c.want), &want); err != nil {
			t.Fatalf("%s: bad want: %v", c.name, err)
		}
		if !reflect.DeepEqual(got, want) {
			g, _ := json.Marshal(got)
			t.Errorf("%s:\n got %s\nwant %s", c.name, g, mustCompact(t, c.want))
		}
	}
}

func mustCompact(t *testing.T, s string) string {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func TestParseDynamoDBTableARN(t *testing.T) {
	ok := map[string]DynamoTableTarget{
		"arn:aws:dynamodb:us-east-1:111122223333:table/orders":                         ddbOrders,
		"arn:aws:dynamodb:us-east-1:111122223333:table/orders/index/by-date":           ddbOrders,
		"arn:aws:dynamodb:us-east-1:111122223333:table/orders/index/*":                 ddbOrders,
		"arn:aws:dynamodb:us-east-1:111122223333:table/orders/stream/2026-10-01T00:00": ddbOrders,
		"arn:aws:dynamodb:us-east-1:111122223333:table/orders/*":                       ddbOrders,
		"arn:aws:dynamodb:us-east-1:111122223333:table/orders/backup/01234":            ddbOrders,
		"arn:aws-cn:dynamodb:cn-north-1:111122223333:table/orders":                     {Partition: "aws-cn", Region: "cn-north-1", Account: "111122223333", Table: "orders"},
		"arn:aws-us-gov:dynamodb:us-gov-west-1:111122223333:table/orders":              {Partition: "aws-us-gov", Region: "us-gov-west-1", Account: "111122223333", Table: "orders"},
	}
	for arn, want := range ok {
		got, parsed := ParseDynamoDBTableARN(arn)
		if !parsed || got != want {
			t.Errorf("%s: %v %+v", arn, parsed, got)
		}
	}
	for _, arn := range []string{
		"arn:aws:dynamodb:us-east-1:111122223333:table/*",
		"arn:aws:dynamodb:us-east-1:111122223333:table/ord*",
		"arn:aws:dynamodb:*:111122223333:table/orders",
		"arn:aws:dynamodb:us-east-1:11112222333:table/orders",
		"arn:aws:dynamodb::111122223333:global-table/orders",
		"arn:aws:s3:::orders",
		"arn:aws:dynamodb:us-east-1:111122223333:table/ab",
	} {
		if _, parsed := ParseDynamoDBTableARN(arn); parsed {
			t.Errorf("%s parsed", arn)
		}
	}
	if _, err := ParseAWSAccessTarget("arn:aws:dynamodb:us-east-1:111122223333:table/orders", "x/"); err == nil ||
		!strings.Contains(err.Error(), "resource.prefix") {
		t.Fatalf("a prefix on a table: %v", err)
	}
	got, err := ParseAWSAccessTarget("arn:aws:dynamodb:us-east-1:111122223333:table/orders/index/*", "")
	if err != nil || got.Type() != AccessTypeDynamoDBTable || got.ARN() != ddbOrders.TableARN() || got.ARNAccount() != "111122223333" ||
		got.ARNRegion() != "us-east-1" {
		t.Fatalf("the index row: %#v %v", got, err)
	}
}

// Every combination of access levels: an allow never widens, every document
// fits AWS's size limit and the deployment row's CHECKs, and no allow names a
// resource beyond the table and its indexes.
func TestDynamoDBAccessProperties(t *testing.T) {
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	start := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	long := DynamoTableTarget{Partition: "aws-us-gov", Region: "us-gov-west-1", Account: "111122223333", Table: strings.Repeat("t", 255)}
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
	neverInAllow := []string{"dynamodb:*", "dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator",
		"dynamodb:ExportTableToPointInTime", "dynamodb:RestoreTableToPointInTime", "dynamodb:RestoreTableFromBackup",
		"dynamodb:StartAwsBackupJob", "dynamodb:CreateTableReplica", "dynamodb:AssociateTableReplica",
		"dynamodb:EnableKinesisStreamingDestination", "dynamodb:UpdateKinesisStreamingDestination", "dynamodb:UpdateTable",
		"dynamodb:UpdateTimeToLive", "dynamodb:DeleteTable"}
	for _, tg := range []DynamoTableTarget{ddbOrders, long} {
		for _, effect := range []string{AccessEffectBlock, AccessEffectAllow} {
			cs := combos
			if effect == AccessEffectBlock {
				cs = append(cs, []string{AccessAll})
			}
			for _, access := range cs {
				doc, _, actions, resources, err := AccessDocument(effect, access, tg, &start, &end)
				if err != nil {
					t.Fatalf("%s %v: %v", effect, access, err)
				}
				if PolicyChars(doc) > MaxPolicyChars || len(actions) < 1 || len(actions) > 50 || len(resources) < 1 || len(resources) > 20 {
					t.Fatalf("%s %v: %d chars, %d actions, %d resources", effect, access, PolicyChars(doc), len(actions), len(resources))
				}
				if strings.Count(string(doc), `"DateGreaterThan"`) != strings.Count(string(doc), `"Sid"`) {
					t.Fatalf("%s %v: a statement without the window: %s", effect, access, doc)
				}
				if effect != AccessEffectAllow {
					continue
				}
				read := accessHas(access, AccessRead)
				for _, a := range actions {
					for _, n := range neverInAllow {
						if a == n {
							t.Fatalf("allow %v grants %s", access, a)
						}
					}
					if !read && (a == dynamoDescribeTable || strings.HasPrefix(a, "dynamodb:PartiQL")) {
						t.Fatalf("allow %v without read grants %s", access, a)
					}
				}
				for _, r := range resources {
					if r != tg.TableARN() && r != tg.IndexARN() {
						t.Fatalf("allow %v names %s", access, r)
					}
				}
				if esc := GrantEscalations(actions, resources); len(esc) > 0 {
					t.Fatalf("allow %v escalates: %v", access, esc)
				}
			}
		}
	}
}

func TestDynamoDBAccessNotes(t *testing.T) {
	codes := func(effect string, access ...string) string {
		var out []string
		for _, n := range ddbOrders.Notes(effect, access) {
			out = append(out, n.Code)
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		effect, want string
		access       []string
	}{
		{AccessEffectBlock, "return_values_blocked,partiql_writes_blocked,condition_failure_values_not_covered,copies_not_covered", []string{AccessRead}},
		{AccessEffectBlock, "batch_write_shared,replicas_not_covered", []string{AccessWrite}},
		{AccessEffectBlock, "batch_write_shared,delete_table_blocked,overwrite_not_covered,replicas_not_covered", []string{AccessDelete}},
		{AccessEffectBlock, "delete_table_blocked,copies_not_covered", []string{AccessDelete, AccessRead, AccessWrite}},
		{AccessEffectBlock, "copies_not_covered", []string{AccessAll}},
		{AccessEffectAllow, "allow_items_only", []string{AccessRead}},
		{AccessEffectAllow, "allow_items_only,batch_write_needs_both,return_values_limited", []string{AccessWrite}},
		{AccessEffectAllow, "allow_items_only", []string{AccessDelete, AccessRead, AccessWrite}},
	} {
		if got := codes(c.effect, c.access...); got != c.want {
			t.Errorf("%s %v: %s, want %s", c.effect, c.access, got, c.want)
		}
	}
	in := AccessIntent{Effect: AccessEffectBlock, Access: []string{AccessRead}}
	if s := AccessSentence(in, ddbOrders, []string{"OrdersReader"}); s != "Block read on DynamoDB table orders (us-east-1, account 111122223333) for OrdersReader, with no end date." {
		t.Fatalf("sentence %q", s)
	}
}
