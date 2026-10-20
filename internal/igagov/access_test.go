package igagov

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
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
	bucket, ok := ParseS3BucketARN("arn:aws:s3:::acme-invoices/2026/*")
	if !ok || bucket.Bucket != "acme-invoices" {
		t.Fatalf("parse: %+v %v", bucket, ok)
	}
	if _, ok := ParseS3BucketARN("arn:aws:dynamodb:us-east-1:111111111111:table/x"); ok {
		t.Fatal("a non-S3 ARN parsed as a bucket")
	}

	// Block read under a prefix, with an end: object actions on bucket/prefix*,
	// the listing actions on the bucket limited by s3:prefix (the folder, the
	// empty prefix and its leading fragments), a second Deny for a request that
	// names no prefix, all inside the window.
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
	if len(d.Statement) != 3 {
		t.Fatalf("statements: %s", doc)
	}
	text := string(doc)
	for _, want := range []string{`"Effect":"Deny"`, `"arn:aws:s3:::acme-invoices/invoices/*"`, `"Resource":"arn:aws:s3:::acme-invoices"`,
		`"invoices/*"`, `"inv"`, `"invoice"`, `"Null":{"s3:prefix":"true"}`,
		`"DateLessThan":{"aws:CurrentTime":"2026-10-14T13:00:00Z"}`, `"s3:GetObject"`, `"s3:ListBucket"`,
		`"s3:ListBucketVersions"`, `"s3:ListBucketMultipartUploads"`, `"s3:GetObjectAttributes"`} {
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
	if len(acts) != 7 || len(res) != 2 {
		t.Errorf("actions %v resources %v", acts, res)
	}

	// A fragment equal to the whole folder is not listed (the folder* value covers it).
	if strings.Contains(text, `"invoices/"`) {
		t.Errorf("the whole folder is listed as a fragment: %s", text)
	}
	// Every listing Deny carries the window.
	if strings.Count(text, `"DateLessThan"`) != 3 {
		t.Errorf("window missing on a statement: %s", text)
	}

	// An Allow never gains the Block's extra read actions.
	if o, b := accessActionsFor(AccessEffectAllow, []string{"read"}, "invoices/"); len(o) != 2 || len(b) != 1 {
		t.Errorf("allow read widened: %v %v", o, b)
	}
	// A folder too long to list its fragments keeps folder*, "" and the no-prefix Deny only.
	long := strings.Repeat("a", MaxListGuardPrefix+1) + "/"
	if v := accessListGuard(long); len(v) != 2 {
		t.Errorf("long folder guard: %v", v)
	}
	if !AccessListGuardPartial(AccessEffectBlock, long) || AccessListGuardPartial(AccessEffectBlock, "invoices/") || AccessListGuardPartial(AccessEffectAllow, long) {
		t.Error("partial-guard flag wrong")
	}
	// A multi-byte folder is split on characters, never inside one.
	for _, v := range accessListGuard("é/日本/") {
		if v != "" && !strings.HasSuffix(v, "*") && !utf8.ValidString(v) {
			t.Errorf("split inside a character: %q", v)
		}
	}
	// Block write: no listing statement at all.
	bucket.Prefix = "invoices/"
	doc, _, _, _, err = AccessDocument("block", []string{"write"}, bucket, nil, &end)
	if err != nil || strings.Contains(string(doc), AccessSidBucket) || strings.Contains(string(doc), AccessSidBucketNone) {
		t.Fatalf("block write: %v %s", err, doc)
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
