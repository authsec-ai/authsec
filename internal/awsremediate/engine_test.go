package awsremediate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/awsremediate"
	"github.com/authsec-ai/authsec/internal/awsremediate/remediatetest"
)

const acct = "123456789012"

func fake(t *testing.T) *remediatetest.Account {
	t.Helper()
	a, err := remediatetest.New(acct)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// run checks, applies and reads back one step, as the service does.
func run(t *testing.T, a *remediatetest.Account, st *awsremediate.Step) (ok bool, err error) {
	t.Helper()
	ctx := context.Background()
	e := &awsremediate.Engine{A: a.Session("authsec-remediate-0123456789abcdef")}
	if err := e.Check(ctx, st); err != nil {
		return false, err
	}
	out, err := e.Apply(ctx, st)
	for k, v := range out {
		st.After[k] = v
	}
	if err != nil {
		return false, err
	}
	ok, _, err = awsremediate.Readback(ctx, a, st)
	return ok, err
}

const s3Doc = `{"Version":"2012-10-17","Statement":[{"Sid":"Read","Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Sid":"Wipe","Effect":"Allow","Action":["s3:DeleteObject","s3:DeleteBucket"],"Resource":"*"}]}`

func TestDetachManagedPolicy(t *testing.T) {
	a := fake(t)
	pol := a.PolicyARN("/", "S3Wide")
	a.AddPolicy(pol, s3Doc, nil)
	r := a.AddRole("agent-role", nil)
	r.Attached = []string{pol}
	p, _ := awsremediate.PrincipalOf(a.RoleARN("agent-role"))
	st := awsremediate.DetachStep(p, pol)
	ok, err := run(t, a, &st)
	if err != nil || !ok {
		t.Fatalf("detach: ok=%v err=%v", ok, err)
	}
	if len(r.Attached) != 0 {
		t.Fatalf("still attached: %v", r.Attached)
	}
	if st.EventName != "DetachRolePolicy" || st.EventSource != "iam.amazonaws.com" {
		t.Fatalf("event %s %s", st.EventSource, st.EventName)
	}
	// A second run is refused: the before-state no longer holds.
	st2 := awsremediate.DetachStep(p, pol)
	if _, err := run(t, a, &st2); awsremediate.CodeOf(err) != awsremediate.CodeTargetChanged {
		t.Fatalf("rerun: %v", err)
	}
}

func TestDetachAuthSecPolicyRefusedByTemplate(t *testing.T) {
	a := fake(t)
	pol := a.PolicyARN("/authsec/", "AuthSecContain-AROA1-abcd1234")
	a.AddPolicy(pol, s3Doc, nil)
	r := a.AddRole("agent-role", nil)
	r.Attached = []string{pol}
	p, _ := awsremediate.PrincipalOf(a.RoleARN("agent-role"))
	st := awsremediate.DetachStep(p, pol)
	if _, err := run(t, a, &st); awsremediate.CodeOf(err) != awsremediate.CodeDenied {
		t.Fatalf("detaching an AuthSec containment policy: %v", err)
	}
	if len(r.Attached) != 1 {
		t.Fatal("the containment policy was detached")
	}
}

func TestProtectedRoleRefused(t *testing.T) {
	a := fake(t)
	pol := a.PolicyARN("/", "S3Wide")
	a.AddPolicy(pol, s3Doc, nil)
	r := a.AddRole("payments", map[string]string{"authsec:protected": "true"})
	r.Attached = []string{pol}
	p, _ := awsremediate.PrincipalOf(a.RoleARN("payments"))
	st := awsremediate.DetachStep(p, pol)
	if _, err := run(t, a, &st); awsremediate.CodeOf(err) != awsremediate.CodeDenied {
		t.Fatalf("protected role: %v", err)
	}
}

func TestRemoveInlineStatement(t *testing.T) {
	a := fake(t)
	r := a.AddRole("agent-role", nil)
	r.Inline["inline-s3"] = s3Doc
	p, _ := awsremediate.PrincipalOf(a.RoleARN("agent-role"))
	newDoc, removed, err := awsremediate.RemoveStatement(s3Doc, "Wipe", -1)
	if err != nil {
		t.Fatal(err)
	}
	if removed.Sid != "Wipe" || strings.Join(removed.Actions, ",") != "s3:DeleteBucket,s3:DeleteObject" {
		t.Fatalf("removed %+v", removed)
	}
	st, err := awsremediate.PutInlineStep(p, "inline-s3", s3Doc, newDoc)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := run(t, a, &st)
	if err != nil || !ok {
		t.Fatalf("put: ok=%v err=%v", ok, err)
	}
	if strings.Contains(r.Inline["inline-s3"], "DeleteBucket") {
		t.Fatal("statement still there")
	}
	// The before-state keeps the old document for a revert.
	if !awsremediate.SameDocument(st.Before["document"].(string), s3Doc) {
		t.Fatal("before lost the old document")
	}
	// Removing the only statement deletes the policy.
	r.Inline["only"] = `{"Version":"2012-10-17","Statement":{"Sid":"X","Effect":"Allow","Action":"s3:*","Resource":"*"}}`
	rest, _, err := awsremediate.RemoveStatement(r.Inline["only"], "X", -1)
	if err != nil || rest != "" {
		t.Fatalf("only statement: %q %v", rest, err)
	}
	del, _ := awsremediate.DeleteInlineStep(p, "only", r.Inline["only"])
	if ok, err := run(t, a, &del); err != nil || !ok {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if _, there := r.Inline["only"]; there {
		t.Fatal("inline policy not deleted")
	}
	if _, _, err := awsremediate.RemoveStatement(s3Doc, "Nope", -1); err != awsremediate.ErrStatementNotFound {
		t.Fatalf("missing sid: %v", err)
	}
}

func TestRewriteManagedPolicyAndReadbackMismatch(t *testing.T) {
	a := fake(t)
	pol := a.PolicyARN("/", "S3Wide")
	p := a.AddPolicy(pol, s3Doc, nil)
	v, doc := p.Default()
	newDoc, _, _ := awsremediate.RemoveStatement(s3Doc, "Wipe", -1)
	st, err := awsremediate.PolicyVersionStep(pol, v, doc, newDoc)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := run(t, a, &st); err != nil || !ok {
		t.Fatalf("version: %v %v", ok, err)
	}
	if st.After["version_id"] != "v2" {
		t.Fatalf("after %v", st.After)
	}
	// A read that still shows the old default is a readback mismatch.
	b := fake(t)
	bp := b.AddPolicy(pol, s3Doc, nil)
	bv, bdoc := bp.Default()
	b.LieOnRead[pol] = true
	st2, _ := awsremediate.PolicyVersionStep(pol, bv, bdoc, newDoc)
	ok, err := run(t, b, &st2)
	if err != nil || ok {
		t.Fatalf("lying read: ok=%v err=%v (want ok=false)", ok, err)
	}
}

func TestRotateAccessKeyHandsOverThroughSecretOnly(t *testing.T) {
	a := fake(t)
	u := a.AddUser("bot", nil, awsremediate.AccessKey{ID: "AKIAOLD0000000000001", Active: true})
	sec := a.AddSecret("bot-key", map[string]string{"authsec:key-handover": "true"}, false)
	p, _ := awsremediate.PrincipalOf(a.UserARN("bot"))
	keys, _ := a.ListAccessKeys(context.Background(), "bot")
	st := awsremediate.RotateKeyStep(p, "AKIAOLD0000000000001", sec.ARN, keys)
	ok, err := run(t, a, &st)
	if err != nil || !ok {
		t.Fatalf("rotate: %v %v", ok, err)
	}
	newID, _ := st.After["new_key_id"].(string)
	if newID == "" || len(u.Keys) != 2 {
		t.Fatalf("new key %q keys %v", newID, u.Keys)
	}
	// The secret went into the handover secret, and nowhere in the step.
	raw, _ := json.Marshal(st)
	for _, s := range remediatetest.GeneratedSecrets() {
		if strings.Contains(string(raw), s) {
			t.Fatal("the key secret is in the step record")
		}
		if strings.Contains(fmt.Sprint(st), s) || strings.Contains(fmt.Sprintf("%+v", st), s) {
			t.Fatal("the key secret prints")
		}
	}
	if !strings.Contains(sec.Values[sec.Current], newID) || !strings.Contains(sec.Values[sec.Current], "SecretAccessKey") {
		t.Fatal("the handover secret does not hold the new key")
	}
	// The old key is deactivated after its grace.
	due := time.Now().Add(time.Hour)
	d := awsremediate.DeactivateKeyStep(p, "AKIAOLD0000000000001", &due)
	if ok, err := run(t, a, &d); err != nil || !ok {
		t.Fatalf("deactivate: %v %v", ok, err)
	}
	for _, k := range u.Keys {
		if k.ID == "AKIAOLD0000000000001" && k.Active {
			t.Fatal("old key still active")
		}
	}
}

func TestRotateAccessKeyUntaggedSecretDeletesNewKey(t *testing.T) {
	a := fake(t)
	u := a.AddUser("bot", nil, awsremediate.AccessKey{ID: "AKIAOLD0000000000001", Active: true})
	sec := a.AddSecret("not-for-handover", nil, false) // not tagged: the template refuses
	p, _ := awsremediate.PrincipalOf(a.UserARN("bot"))
	keys, _ := a.ListAccessKeys(context.Background(), "bot")
	st := awsremediate.RotateKeyStep(p, "AKIAOLD0000000000001", sec.ARN, keys)
	_, err := run(t, a, &st)
	if awsremediate.CodeOf(err) != awsremediate.CodeHandover {
		t.Fatalf("untagged handover: %v", err)
	}
	if len(u.Keys) != 1 || u.Keys[0].ID != "AKIAOLD0000000000001" {
		t.Fatalf("the unusable new key was not deleted: %v", u.Keys)
	}
	if st.After["new_key_deleted"] != true {
		t.Fatalf("after %v", st.After)
	}
	// Two keys already: refused before any write.
	u.Keys = append(u.Keys, awsremediate.AccessKey{ID: "AKIASECOND0000000002", Active: false})
	st2 := awsremediate.RotateKeyStep(p, "AKIAOLD0000000000001", sec.ARN, u.Keys)
	if _, err := run(t, a, &st2); awsremediate.CodeOf(err) != awsremediate.CodeKeyLimit {
		t.Fatalf("key limit: %v", err)
	}
}

func TestRotateSecret(t *testing.T) {
	a := fake(t)
	sec := a.AddSecret("db-password", nil, true)
	info, _ := a.DescribeSecret(context.Background(), sec.ARN)
	st := awsremediate.RotateSecretStep(*info)
	ok, err := run(t, a, &st)
	if err != nil || !ok {
		t.Fatalf("rotate: %v %v", ok, err)
	}
	// Rotation not configured: refused before the write, prepared instead.
	off := a.AddSecret("api-token", nil, false)
	info2, _ := a.DescribeSecret(context.Background(), off.ARN)
	st2 := awsremediate.RotateSecretStep(*info2)
	if _, err := run(t, a, &st2); awsremediate.CodeOf(err) != awsremediate.CodeRotationOff {
		t.Fatalf("rotation off: %v", err)
	}
	if prep := awsremediate.Prepare(st2); !strings.Contains(prep.Description, "not configured") || len(prep.CLI) == 0 {
		t.Fatalf("prepared %+v", prep)
	}
	// The remediation role can never read the value.
	if a.Count("secretsmanager:GetSecretValue") != 0 {
		t.Fatal("a secret value was read")
	}
}

func TestRetireBlockAndAWSRefusal(t *testing.T) {
	a := fake(t)
	a.AddRole("agent-role", nil)
	p, _ := awsremediate.PrincipalOf(a.RoleARN("agent-role"))
	arn := awsremediate.PolicyARN("aws", acct, "/authsec/remediation/", awsremediate.RetirePolicyName("AROA1", "abcd1234"))
	cp, err := awsremediate.CreatePolicyStep(arn, "/authsec/remediation/", awsremediate.RetirePolicyName("AROA1", "abcd1234"),
		`{"Version":"2012-10-17","Statement":[{"Sid":"AuthSecDenyAll","Effect":"Deny","Action":"*","Resource":"*"}]}`, map[string]string{"ManagedBy": "AuthSec"})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := run(t, a, &cp); err != nil || !ok {
		t.Fatalf("create: %v %v", ok, err)
	}
	at := awsremediate.AttachStep(p, arn)
	if ok, err := run(t, a, &at); err != nil || !ok {
		t.Fatalf("attach: %v %v", ok, err)
	}
	// A stack without the attach statement refuses (AWS refusal).
	b := fake(t)
	b.AddRole("agent-role", nil)
	b.AddPolicy(arn, `{"Version":"2012-10-17","Statement":[]}`, nil)
	b.RemoveStatement("AttachRemediationPolicies")
	at2 := awsremediate.AttachStep(p, arn)
	if _, err := run(t, b, &at2); awsremediate.CodeOf(err) != awsremediate.CodeDenied {
		t.Fatalf("no attach statement: %v", err)
	}
}

func TestPreparedNeverCarriesSecrets(t *testing.T) {
	a := fake(t)
	p, _ := awsremediate.PrincipalOf(a.UserARN("bot"))
	st := awsremediate.RotateKeyStep(p, "AKIAOLD", "", nil)
	prep := awsremediate.Prepare(st)
	if !strings.Contains(strings.Join(prep.CLI, " "), "create-access-key") || !strings.Contains(prep.Description, "secret store") {
		t.Fatalf("prepared %+v", prep)
	}
	k := awsremediate.NewAccessKey("AKIAX", "TOPSECRET")
	if strings.Contains(fmt.Sprint(k), "TOPSECRET") || strings.Contains(fmt.Sprintf("%#v", k), "TOPSECRET") {
		t.Fatal("NewKey prints its secret")
	}
	if b, _ := json.Marshal(k); strings.Contains(string(b), "TOPSECRET") {
		t.Fatal("NewKey marshals its secret")
	}
	if awsremediate.SessionName("0123456789ab-cdef-0123-4567-89abcdef0123") != "authsec-remediate-0123456789abcdef" {
		t.Fatal("session name")
	}
}
