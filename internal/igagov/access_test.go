package igagov

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var accessNow = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func accessIntent(effect string, access []string, ends *time.Time) AccessIntent {
	return AccessIntent{Effect: effect, Resource: AccessResource{ResourceID: "11111111-1111-1111-1111-111111111111"},
		Roles: []AccessRole{{IdentityAccountID: "22222222-2222-2222-2222-222222222222"}}, Access: access, EndsAt: ends}
}

func accessAt(d time.Duration) *time.Time { t := accessNow.Add(d); return &t }

func TestNormalizeAccessIntent(t *testing.T) {
	cases := []struct {
		name  string
		in    AccessIntent
		field string // "" = valid
	}{
		{"block read 1h", accessIntent("block", []string{"read"}, accessAt(time.Hour)), ""},
		{"block no end", accessIntent("block", []string{"all"}, nil), ""},
		{"allow needs end", accessIntent("allow", []string{"read"}, nil), "ends_at"},
		{"allow 31 days", accessIntent("allow", []string{"read"}, accessAt(31*24*time.Hour)), "ends_at"},
		{"allow 30 days", accessIntent("allow", []string{"read"}, accessAt(30*24*time.Hour)), ""},
		{"allow all refused", accessIntent("allow", []string{"all"}, accessAt(time.Hour)), "access"},
		{"end too soon", accessIntent("block", []string{"read"}, accessAt(10*time.Minute)), "ends_at"},
		{"bad effect", accessIntent("deny", []string{"read"}, accessAt(time.Hour)), "effect"},
		{"bad access", accessIntent("block", []string{"list"}, accessAt(time.Hour)), "access"},
		{"no access", accessIntent("block", nil, accessAt(time.Hour)), "access"},
	}
	for _, c := range cases {
		_, err := NormalizeAccessIntent(c.in, accessNow)
		var fe *AccessFieldError
		switch {
		case c.field == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.field != "" && (!errors.As(err, &fe) || fe.Field != c.field):
			t.Errorf("%s: want invalid %s, got %v", c.name, c.field, err)
		}
	}
	// starts_at must be before ends_at, at most 30 days ahead.
	in := accessIntent("block", []string{"read"}, accessAt(2*time.Hour))
	in.StartsAt = accessAt(3 * time.Hour)
	if _, err := NormalizeAccessIntent(in, accessNow); err == nil {
		t.Error("starts_at after ends_at accepted")
	}
	in.StartsAt = accessAt(31 * 24 * time.Hour)
	in.EndsAt = accessAt(32 * 24 * time.Hour)
	if _, err := NormalizeAccessIntent(in, accessNow); err == nil {
		t.Error("starts_at 31 days ahead accepted")
	}
	// "all" collapses, duplicates go, prefix loses its leading slash.
	in = accessIntent("block", []string{"read", "ALL", "write"}, nil)
	in.Resource.Prefix = "/invoices/"
	in.Roles = append(in.Roles, in.Roles[0])
	out, err := NormalizeAccessIntent(in, accessNow)
	if err != nil || len(out.Access) != 1 || out.Access[0] != "all" || out.Resource.Prefix != "invoices/" || len(out.Roles) != 1 {
		t.Fatalf("normalized: %+v %v", out, err)
	}
	in.Resource.Prefix = "invoices/*"
	if _, err := NormalizeAccessIntent(in, accessNow); err == nil {
		t.Error("wildcard prefix accepted")
	}
}

func TestAccessDocument(t *testing.T) {
	bucket, ok := ParseAccessResourceARN("arn:aws:s3:::acme-invoices/2026/*")
	if !ok || bucket.Service != AccessServiceS3 || bucket.Name != "acme-invoices" {
		t.Fatalf("parse: %+v %v", bucket, ok)
	}
	if _, ok := ParseAccessResourceARN("arn:aws:sqs:us-east-1:111111111111:q"); ok {
		t.Fatal("an unsupported ARN parsed as a target")
	}

	// Block read under a prefix, with an end: object actions on bucket/prefix*,
	// ListBucket on the bucket limited by s3:prefix, both inside the window.
	bucket.Prefix = "invoices/"
	end := accessNow.Add(time.Hour)
	doc, hash, acts, res, err := AccessDocument("block", []string{"read"}, bucket, nil, &end)
	if err != nil || !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("doc: %v %s", err, hash)
	}
	var d struct {
		Statement []struct {
			Sid    string
			Action any
		}
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Statement) != 2 {
		t.Fatalf("statements: %s", doc)
	}
	text := string(doc)
	for _, want := range []string{`"Effect":"Deny"`, `"arn:aws:s3:::acme-invoices/invoices/*"`, `"Resource":"arn:aws:s3:::acme-invoices"`,
		`"s3:prefix":"invoices/*"`, `"DateLessThan":{"aws:CurrentTime":"2026-10-14T13:00:00Z"}`, `"s3:GetObject"`, `"s3:ListBucket"`} {
		if !strings.Contains(text, want) {
			t.Errorf("document lacks %s: %s", want, text)
		}
	}
	// The object actions never target the bucket ARN itself (it would match
	// nothing): the bucket statement carries only bucket-level actions.
	for _, st := range d.Statement {
		if b, _ := json.Marshal(st.Action); st.Sid == AccessSidBucket && strings.Contains(string(b), "GetObject") {
			t.Errorf("GetObject on the bucket ARN: %s", text)
		}
	}
	if len(acts) != 3 || len(res) != 2 {
		t.Errorf("actions %v resources %v", acts, res)
	}

	// Block all, no prefix, no end: s3:* on objects and bucket, no condition.
	bucket.Prefix = ""
	doc, _, _, _, err = AccessDocument("block", []string{"all"}, bucket, nil, &AccessNoEnd)
	if err != nil || strings.Contains(string(doc), "Condition") || !strings.Contains(string(doc), `"Action":"s3:*"`) {
		t.Fatalf("block all: %v %s", err, doc)
	}

	// Allow write with a start: Allow, DateGreaterThan, no bucket statement.
	start := accessNow.Add(time.Hour)
	doc, _, _, _, err = AccessDocument("allow", []string{"write"}, bucket, &start, &end)
	if err != nil || !strings.Contains(string(doc), `"Effect":"Allow"`) || !strings.Contains(string(doc), "DateGreaterThan") ||
		strings.Contains(string(doc), AccessSidBucket) {
		t.Fatalf("allow write: %v %s", err, doc)
	}

	if n := AccessPolicyName("AROAEXAMPLE1234567890", "abcdef12-3456-7890-abcd-ef1234567890", 2); n != "AuthSecAccess-AROAEXAMPLE1234567890-abcdef12-v2" {
		t.Errorf("name: %s", n)
	}
}

func TestAccessTargetsDynamoDBAndSSM(t *testing.T) {
	// Parsing: a table (an index ARN names its table), one parameter, a path;
	// wildcards in the region, account or mid-name are refused.
	for arn, want := range map[string]AccessTarget{
		"arn:aws:dynamodb:us-east-1:111111111111:table/Orders":           {Service: AccessServiceDynamoDB, Partition: "aws", Region: "us-east-1", Account: "111111111111", Name: "Orders"},
		"arn:aws:dynamodb:us-east-1:111111111111:table/Orders/index/byID": {Service: AccessServiceDynamoDB, Partition: "aws", Region: "us-east-1", Account: "111111111111", Name: "Orders"},
		"arn:aws:ssm:eu-west-1:111111111111:parameter/prod/db/password":   {Service: AccessServiceSSM, Partition: "aws", Region: "eu-west-1", Account: "111111111111", Name: "prod/db/password"},
		"arn:aws:ssm:eu-west-1:111111111111:parameter/prod/db/*":          {Service: AccessServiceSSM, Partition: "aws", Region: "eu-west-1", Account: "111111111111", Name: "prod/db/*"},
	} {
		got, ok := ParseAccessResourceARN(arn)
		if !ok || got != want {
			t.Errorf("%s: %+v %v", arn, got, ok)
		}
	}
	for _, bad := range []string{"arn:aws:dynamodb:*:111111111111:table/Orders", "arn:aws:dynamodb:us-east-1:*:table/Orders",
		"arn:aws:ssm:us-east-1:111111111111:parameter/prod/*/password", "arn:aws:ssm:*:111111111111:parameter/x"} {
		if _, ok := ParseAccessResourceARN(bad); ok {
			t.Errorf("%s parsed", bad)
		}
	}

	// DynamoDB: block read covers the table and its indexes; delete includes
	// BatchWriteItem (a batch write can delete).
	ddb, _ := ParseAccessResourceARN("arn:aws:dynamodb:us-east-1:111111111111:table/Orders")
	end := accessNow.Add(time.Hour)
	doc, _, acts, res, err := AccessDocument("block", []string{"read", "delete"}, ddb, nil, &end)
	if err != nil {
		t.Fatal(err)
	}
	text := string(doc)
	for _, want := range []string{`"Effect":"Deny"`, `"dynamodb:GetItem"`, `"dynamodb:Query"`, `"dynamodb:DeleteItem"`, `"dynamodb:BatchWriteItem"`,
		`"arn:aws:dynamodb:us-east-1:111111111111:table/Orders"`, `"arn:aws:dynamodb:us-east-1:111111111111:table/Orders/index/*"`, `"Sid":"AuthSecAccessTable"`} {
		if !strings.Contains(text, want) {
			t.Errorf("dynamodb document lacks %s: %s", want, text)
		}
	}
	if len(acts) != 7 || len(res) != 2 {
		t.Errorf("dynamodb actions %v resources %v", acts, res)
	}
	if ddb.Display() != "DynamoDB table Orders (us-east-1)" {
		t.Errorf("display: %s", ddb.Display())
	}

	// SSM path: read also covers the path itself (GetParametersByPath).
	ssm, _ := ParseAccessResourceARN("arn:aws:ssm:eu-west-1:111111111111:parameter/prod/db/*")
	doc, _, _, res, err = AccessDocument("block", []string{"read"}, ssm, nil, nil)
	if err != nil || !strings.Contains(string(doc), `"ssm:GetParametersByPath"`) || len(res) != 2 ||
		!strings.Contains(string(doc), `"arn:aws:ssm:eu-west-1:111111111111:parameter/prod/db"`) {
		t.Fatalf("ssm path: %v %s %v", err, doc, res)
	}
	if ssm.Display() != "SSM parameters /prod/db/* (eu-west-1)" {
		t.Errorf("display: %s", ssm.Display())
	}

	// Service rules: no prefix outside S3; SSM is block-only.
	in := accessIntent("block", []string{"read"}, &end)
	in.Resource.Prefix = "x/"
	if err := ValidateAccessTarget(in, ddb); err == nil {
		t.Error("prefix on a DynamoDB table accepted")
	}
	in = accessIntent("allow", []string{"read"}, &end)
	if err := ValidateAccessTarget(in, ssm); err == nil {
		t.Error("allow on SSM accepted")
	}
	if err := ValidateAccessTarget(in, ddb); err != nil {
		t.Errorf("allow on DynamoDB refused: %v", err)
	}
}
