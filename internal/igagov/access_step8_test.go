package igagov

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	lambdaFn = LambdaTarget{Partition: "aws", Region: "us-east-1", Account: "111122223333", Function: "book-flight"}
	kmsKey   = KMSKeyTarget{Partition: "aws", Region: "us-east-1", Account: "111122223333", Key: "1234abcd-12ab-34cd-56ef-1234567890ab"}
	kmsMRK   = KMSKeyTarget{Partition: "aws", Region: "us-east-1", Account: "111122223333", Key: "mrk-1234abcd12ab34cd56ef1234567890ab"}
	sqsQ     = MessagingTarget{Kind: AccessTypeSQSQueue, Partition: "aws", Region: "us-east-1", Account: "111122223333", Resource: "orders.fifo"}
	snsT     = MessagingTarget{Kind: AccessTypeSNSTopic, Partition: "aws", Region: "us-east-1", Account: "111122223333", Resource: "alerts"}
)

// TestStep8AccessDocuments states the intended documents by hand (the action
// tables in access_lambda.go, access_kms.go and access_sqs_sns.go, checked
// against the AWS service reference) and compares them as JSON.
func TestStep8AccessDocuments(t *testing.T) {
	window := `"Condition":{"DateLessThan":{"aws:CurrentTime":"2026-11-01T00:00:00Z"}}`
	const FN = "arn:aws:lambda:us-east-1:111122223333:function:book-flight"
	sameDoc(t, "lambda read", blockDoc(t, lambdaFn, AccessRead), `{"Version":"2012-10-17","Statement":[
		{"Sid":"AuthSecAccessFunction","Effect":"Deny","Resource":["`+FN+`","`+FN+`:*"],`+window+`,"Action":["lambda:AddPermission",
			"lambda:CreateFunctionUrlConfig","lambda:GetFunction","lambda:GetFunctionConfiguration","lambda:InvokeAsync","lambda:InvokeFunction",
			"lambda:InvokeFunctionUrl","lambda:PutResourcePolicy","lambda:UpdateFunctionUrlConfig"]}]}`)
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	doc, _, _, _, err := AccessDocument(AccessEffectAllow, []string{AccessRead}, lambdaFn, nil, &end)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"Version":"2012-10-17","Statement":[{"Action":["lambda:InvokeFunction","lambda:InvokeFunctionUrl"],` + window + `,"Effect":"Allow","Resource":["` + FN + `","` + FN + `:*"],"Sid":"AuthSecAccessFunction"}]}`; mustCompact(t, string(doc)) != mustCompact(t, want) {
		t.Fatalf("lambda allow:\n got %s\nwant %s", doc, want)
	}

	const K = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	sameDoc(t, "kms read", blockDoc(t, kmsKey, AccessRead), `{"Version":"2012-10-17","Statement":[
		{"Sid":"AuthSecAccessKey","Effect":"Deny","Resource":"`+K+`",`+window+`,"Action":["kms:CreateGrant","kms:Decapsulate","kms:Decrypt",
			"kms:ReEncryptFrom","kms:TagResource","kms:UntagResource"]}]}`)
	sameDoc(t, "kms delete", blockDoc(t, kmsKey, AccessDelete), `{"Version":"2012-10-17","Statement":[
		{"Sid":"AuthSecAccessKey","Effect":"Deny","Resource":"`+K+`",`+window+`,"Action":["kms:DeleteImportedKeyMaterial","kms:DisableKey","kms:ScheduleKeyDeletion"]}]}`)
	sameDoc(t, "kms mrk all", blockDoc(t, kmsMRK, AccessAll), `{"Version":"2012-10-17","Statement":[
		{"Sid":"AuthSecAccessKey","Effect":"Deny","Action":"kms:*","Resource":"arn:aws:kms:*:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab",`+window+`}]}`)

	const Q = "arn:aws:sqs:us-east-1:111122223333:orders.fifo"
	sameDoc(t, "sqs delete", blockDoc(t, sqsQ, AccessDelete), `{"Version":"2012-10-17","Statement":[
		{"Sid":"AuthSecAccessQueue","Effect":"Deny","Resource":"`+Q+`",`+window+`,"Action":["sqs:DeleteMessage","sqs:DeleteQueue","sqs:PurgeQueue"]}]}`)
	doc, _, _, _, err = AccessDocument(AccessEffectAllow, []string{AccessRead, AccessWrite}, sqsQ, nil, &end)
	if err != nil || !strings.Contains(string(doc), `"sqs:ReceiveMessage"`) || !strings.Contains(string(doc), `"sqs:SendMessage"`) ||
		strings.Contains(string(doc), "Purge") || strings.Contains(string(doc), "SetQueueAttributes") {
		t.Fatalf("sqs allow: %s %v", doc, err)
	}
	const T = "arn:aws:sns:us-east-1:111122223333:alerts"
	sameDoc(t, "sns read", blockDoc(t, snsT, AccessRead), `{"Version":"2012-10-17","Statement":[
		{"Sid":"AuthSecAccessTopic","Effect":"Deny","Resource":"`+T+`",`+window+`,"Action":["sns:AddPermission","sns:ConfirmSubscription",
			"sns:SetSubscriptionAttributes","sns:SetTopicAttributes","sns:Subscribe","sns:TagResource","sns:UntagResource"]}]}`)

	// Allows the types refuse.
	var fe *AccessFieldError
	for _, c := range []struct {
		tg     AWSAccessTarget
		access []string
	}{
		{lambdaFn, []string{AccessWrite}}, {lambdaFn, []string{AccessRead, AccessDelete}},
		{snsT, []string{AccessRead}}, {sqsQ, []string{AccessAll}},
	} {
		if _, _, _, _, err := AccessDocument(AccessEffectAllow, c.access, c.tg, nil, &end); !errors.As(err, &fe) || fe.Field != "access" {
			t.Errorf("%s allow %v: %v", c.tg.Type(), c.access, err)
		}
	}
	if _, _, _, _, err := AccessDocument(AccessEffectAllow, []string{AccessRead}, kmsKey, nil, &end); !errors.Is(err, ErrAccessBlockOnly) {
		t.Fatalf("kms allow: %v", err)
	}
}

func TestParseStep8ARNs(t *testing.T) {
	for arn, ok := range map[string]bool{
		"arn:aws:lambda:us-east-1:111122223333:function:book-flight":         true,
		"arn:aws:lambda:us-east-1:111122223333:function:book-flight:prod":    true,
		"arn:aws:lambda:us-east-1:111122223333:function:book-flight:$LATEST": true,
		"arn:aws:lambda:us-east-1:111122223333:function:book-flight:*":       true,
		"arn:aws:lambda:us-east-1:111122223333:function:book-*":              false,
		"arn:aws:lambda:us-east-1:111122223333:layer:x:1":                    false,
	} {
		got, parsed := ParseLambdaFunctionARN(arn)
		if parsed != ok || (ok && got != lambdaFn) {
			t.Errorf("%s: %v %+v", arn, parsed, got)
		}
	}
	for arn, ok := range map[string]bool{
		"arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab": true,
		"arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab": true,
		"arn:aws:kms:us-east-1:111122223333:alias/app":                                false,
		"arn:aws:kms:us-east-1:111122223333:key/*":                                    false,
	} {
		if _, parsed := ParseKMSKeyARN(arn); parsed != ok {
			t.Errorf("%s: %v", arn, parsed)
		}
	}
	if q, ok := ParseSQSQueueARN("arn:aws:sqs:us-east-1:111122223333:orders.fifo"); !ok || q != sqsQ {
		t.Errorf("queue: %v %+v", ok, q)
	}
	if _, ok := ParseSQSQueueARN("arn:aws:sqs:us-east-1:111122223333:orders-*"); ok {
		t.Error("a queue pattern parsed")
	}
	if tp, ok := ParseSNSTopicARN("arn:aws:sns:us-east-1:111122223333:alerts"); !ok || tp != snsT {
		t.Errorf("topic: %v %+v", ok, tp)
	}
	if _, ok := ParseSNSTopicARN("arn:aws:sns:us-east-1:111122223333:alerts:0b1c2d3e-aaaa-bbbb-cccc-123456789012"); ok {
		t.Error("a subscription ARN parsed as a topic")
	}
}

// Every combination fits the limits and names only the target's own ARNs;
// an allow never names an action that hands access on or destroys.
func TestStep8AccessProperties(t *testing.T) {
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	start := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	combos := [][]string{{AccessRead}, {AccessWrite}, {AccessDelete}, {AccessRead, AccessWrite}, {AccessRead, AccessDelete},
		{AccessWrite, AccessDelete}, {AccessRead, AccessWrite, AccessDelete}, {AccessAll}}
	never := []string{"lambda:UpdateFunctionCode", "lambda:AddPermission", "lambda:CreateFunctionUrlConfig", "sqs:SetQueueAttributes", "sqs:AddPermission",
		"sqs:PurgeQueue", "sqs:DeleteQueue", "sns:Subscribe", "sns:SetTopicAttributes", "sns:AddPermission"}
	for _, tg := range []AWSAccessTarget{lambdaFn, kmsKey, kmsMRK, sqsQ, snsT} {
		for _, effect := range []string{AccessEffectBlock, AccessEffectAllow} {
			for _, access := range combos {
				doc, _, actions, resources, err := AccessDocument(effect, access, tg, &start, &end)
				if err != nil {
					if effect == AccessEffectAllow {
						continue
					}
					t.Fatalf("%s %v: %v", tg.Type(), access, err)
				}
				if PolicyChars(doc) > MaxPolicyChars || len(actions) < 1 || len(actions) > 50 || len(resources) < 1 || len(resources) > 20 {
					t.Fatalf("%s %s %v: %d chars, %d actions, %d resources", tg.Type(), effect, access, PolicyChars(doc), len(actions), len(resources))
				}
				for _, r := range resources {
					if !strings.HasPrefix(r, "arn:aws:"+tg.Service()+":") || !strings.Contains(r, tg.Name()) {
						t.Fatalf("%s %v names %s", tg.Type(), access, r)
					}
				}
				if effect != AccessEffectAllow {
					continue
				}
				for _, a := range actions {
					for _, n := range never {
						if a == n {
							t.Fatalf("%s allow %v grants %s", tg.Type(), access, a)
						}
					}
				}
				if esc := GrantEscalations(actions, resources); len(esc) > 0 {
					t.Fatalf("%s allow %v escalates: %v", tg.Type(), access, esc)
				}
			}
		}
	}
}

func TestStep8AccessNotes(t *testing.T) {
	codes := func(tg AWSAccessTarget, effect string, access ...string) string {
		var out []string
		for _, n := range tg.Notes(effect, access) {
			out = append(out, n.Code)
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		tg     AWSAccessTarget
		effect string
		want   string
		access []string
	}{
		{lambdaFn, AccessEffectBlock, "versions_covered,handoff_blocked,triggers_not_covered", []string{AccessRead}},
		{lambdaFn, AccessEffectAllow, "allow_invoke_only", []string{AccessRead}},
		{kmsKey, AccessEffectBlock, "services_covered,data_keys_not_covered", []string{AccessRead}},
		{kmsMRK, AccessEffectBlock, "delete_is_destroy,replicas_covered", []string{AccessDelete}},
		{snsT, AccessEffectBlock, "handoff_blocked,subscriptions_not_covered", []string{AccessRead}},
		{sqsQ, AccessEffectAllow, "kms_not_granted", []string{AccessWrite}},
	} {
		if got := codes(c.tg, c.effect, c.access...); got != c.want {
			t.Errorf("%s %s %v: %s, want %s", c.tg.Type(), c.effect, c.access, got, c.want)
		}
	}
	in := AccessIntent{Effect: AccessEffectBlock, Access: []string{AccessRead}}
	if s := AccessSentence(in, sqsQ, []string{"X"}); !strings.HasPrefix(s, "Block read on SQS queue orders.fifo (us-east-1, account 111122223333)") {
		t.Fatalf("sentence %q", s)
	}
}

func TestPublicFunctionURL(t *testing.T) {
	public := `{"Version":"2012-10-17","Statement":[{"Sid":"FunctionURLAllowPublicAccess","Effect":"Allow","Principal":"*",
		"Action":"lambda:InvokeFunctionUrl","Resource":"arn:aws:lambda:us-east-1:111122223333:function:f",
		"Condition":{"StringEquals":{"lambda:FunctionUrlAuthType":"NONE"}}}]}`
	iam := strings.Replace(public, `"NONE"`, `"AWS_IAM"`, 1)
	account := strings.Replace(public, `"Principal":"*"`, `"Principal":{"AWS":"arn:aws:iam::111122223333:root"}`, 1)
	if !PublicFunctionURL([]byte(public)) || PublicFunctionURL([]byte(iam)) || PublicFunctionURL([]byte(account)) || PublicFunctionURL([]byte(`{}`)) {
		t.Fatal("public function URL misread")
	}
}
