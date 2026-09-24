package awsdiscovery

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Quick Create link, the template shape it depends on, and the CloudFormation
// callback protocol. These are the parts of automatic onboarding that fail
// silently in production when they are wrong: a NoEcho parameter is dropped by
// the console without a word, and a response host that is guessed rather than
// observed either rejects every real callback or lets a forged one aim AuthSec
// at an arbitrary host.

func TestTemplateParametersScan(t *testing.T) {
	declared, noEcho := templateParameters()
	for _, name := range []string{"AuthSecPrincipalArn", "ExternalId", "CallbackTopicArn", "RoleName", "MaxSessionDurationSeconds"} {
		if _, ok := declared[name]; !ok {
			t.Fatalf("template parameter %s not found by the scan; the Parameters section shape changed", name)
		}
	}
	// Quick Create ignores NoEcho values. Every parameter the Launch link fills
	// in must therefore be a plain parameter, or the customer gets a blank field.
	for _, name := range []string{"AuthSecPrincipalArn", "ExternalId", "CallbackTopicArn", "RoleName"} {
		if _, ok := noEcho[name]; ok {
			t.Fatalf("%s is NoEcho; Quick Create would silently drop the value AuthSec pre-fills", name)
		}
	}

	// The scanner itself must see NoEcho when it is there.
	_, fake := scanTemplateParameters("Parameters:\n  Secret:\n    Type: String\n    NoEcho: true\n  Plain:\n    Type: String\nResources:\n  X:\n    NoEcho: true\n")
	if _, ok := fake["Secret"]; !ok || len(fake) != 1 {
		t.Fatalf("scanner should report exactly Secret as NoEcho, got %v", fake)
	}
}

func TestTemplateCallbackResource(t *testing.T) {
	for _, must := range []string{
		"HasCallback: !Not [!Equals [!Ref CallbackTopicArn, '']]",
		"Type: Custom::AuthSecRegistration",
		"Condition: HasCallback",
		"DependsOn: AuthSecDiscoveryRole",
		"ServiceToken: !Ref CallbackTopicArn",
		"ServiceTimeout: 600",
		"RoleArn: !GetAtt AuthSecDiscoveryRole.Arn",
		"ExternalId: !Ref ExternalId",
		"TemplateVersion: '" + TemplateVersion + "'",
	} {
		if !strings.Contains(CloudFormationTemplate, must) {
			t.Fatalf("template is missing %q", must)
		}
	}
	// The logical id and type the worker checks must be the ones the template uses.
	// Line endings normalised: a Windows checkout embeds the template with CRLF.
	lf := strings.ReplaceAll(CloudFormationTemplate, "\r\n", "\n")
	if !strings.Contains(lf, "\n  "+RegistrationLogicalID+":\n") ||
		!strings.Contains(CloudFormationTemplate, "Type: "+RegistrationResourceType) {
		t.Fatal("RegistrationLogicalID / RegistrationResourceType do not match the template")
	}
	// Metadata, output and the resource property all carry the version.
	if n := strings.Count(CloudFormationTemplate, "'"+TemplateVersion+"'"); n != 3 {
		t.Fatalf("expected TemplateVersion %s in metadata, output and resource (3), found %d", TemplateVersion, n)
	}
}

func TestQuickCreateURL(t *testing.T) {
	tmpl := "https://bucket.s3.us-east-1.amazonaws.com/aws/" + TemplateVersion + "/authsec-aws-discovery-role.yaml"
	link, err := QuickCreateURL("ap-south-1", tmpl, "AuthSec-Discovery-abcd2345", map[string]string{
		"AuthSecPrincipalArn": "arn:aws:iam::111111111111:role/AuthSec",
		"ExternalId":          "0123456789abcdef01234567.sigsigsigsigsigsigsigsigsigsigsi",
		"CallbackTopicArn":    "arn:aws:sns:ap-south-1:111111111111:authsec-cfn-callback",
		"RoleName":            "AuthSecCloudDiscovery-abcd2345",
	})
	if err != nil {
		t.Fatal(err)
	}
	prefix := "https://ap-south-1.console.aws.amazon.com/cloudformation/home?region=ap-south-1#/stacks/create/review?"
	if !strings.HasPrefix(link, prefix) {
		t.Fatalf("link does not use the documented format:\n%s", link)
	}
	q, err := url.ParseQuery(strings.TrimPrefix(link, prefix))
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("templateURL") != tmpl || q.Get("stackName") != "AuthSec-Discovery-abcd2345" ||
		q.Get("param_CallbackTopicArn") != "arn:aws:sns:ap-south-1:111111111111:authsec-cfn-callback" ||
		q.Get("param_RoleName") != "AuthSecCloudDiscovery-abcd2345" {
		t.Fatalf("values did not round-trip through encoding: %v", q)
	}

	cases := map[string]struct {
		region, tmpl, stack string
		params              map[string]string
	}{
		"govcloud":         {"us-gov-west-1", tmpl, "AuthSec-Discovery-x", nil},
		"china":            {"cn-north-1", tmpl, "AuthSec-Discovery-x", nil},
		"http template":    {"us-east-1", "http://bucket.s3.amazonaws.com/t.yaml", "AuthSec-Discovery-x", nil},
		"bad stack name":   {"us-east-1", tmpl, "1-starts-with-digit", nil},
		"undeclared param": {"us-east-1", tmpl, "AuthSec-Discovery-x", map[string]string{"ExternalID": "typo"}},
	}
	for name, c := range cases {
		if _, err := QuickCreateURL(c.region, c.tmpl, c.stack, c.params); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
}

func TestPartitionAndOptIn(t *testing.T) {
	if PartitionForRegion("us-gov-east-1") != PartitionGovUS || PartitionForRegion("cn-northwest-1") != PartitionChina ||
		PartitionForRegion("ap-south-1") != PartitionAWS {
		t.Fatal("partition mapping is wrong")
	}
	if !IsOptInRegion("af-south-1") || IsOptInRegion("ap-south-1") || IsOptInRegion("ap-northeast-3") {
		t.Fatal("opt-in list is wrong (ap-northeast-3 Osaka is enabled by default)")
	}
}

/* ------------------------------ response URL ------------------------------ */

type responseURLFixture struct {
	Region string `json:"region"`
	URL    string `json:"url"`
}

// Every captured fixture must pass, and every host form the allow-list has must
// be exercised by at least one fixture: a form with no fixture is a guess.
func TestResponseURLFixtures(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "cfn_response_urls", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no ResponseURL fixtures found: %v", err)
	}
	formsSeen := map[int]bool{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var fx responseURLFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		u, err := ValidateResponseURL(fx.URL, fx.Region)
		if err != nil {
			t.Fatalf("%s: a real ResponseURL was rejected: %v", f, err)
		}
		compact := strings.ReplaceAll(fx.Region, "-", "")
		for i, form := range responseHostForms {
			if u.Hostname() == form(fx.Region, compact) {
				formsSeen[i] = true
			}
		}
	}
	for i := range responseHostForms {
		if !formsSeen[i] {
			t.Fatalf("responseHostForms[%d] has no fixture; add a captured ResponseURL or remove the form", i)
		}
	}
}

func TestResponseURLRejections(t *testing.T) {
	const good = "https://cloudformation-custom-resource-response-uswest2.s3-us-west-2.amazonaws.com/obj?X-Amz-Signature=abc"
	if _, err := ValidateResponseURL(good, "us-west-2"); err != nil {
		t.Fatalf("baseline should pass: %v", err)
	}
	bad := map[string]string{
		"http":              "http://cloudformation-custom-resource-response-uswest2.s3-us-west-2.amazonaws.com/obj?X-Amz-Signature=abc",
		"dashed bucket":     "https://cloudformation-custom-resource-response-us-west-2.s3-us-west-2.amazonaws.com/obj?X-Amz-Signature=abc",
		"other region":      "https://cloudformation-custom-resource-response-useast1.s3-us-east-1.amazonaws.com/obj?X-Amz-Signature=abc",
		"lookalike suffix":  "https://cloudformation-custom-resource-response-uswest2.s3-us-west-2.amazonaws.com.evil.example/obj?X-Amz-Signature=abc",
		"userinfo":          "https://u:p@cloudformation-custom-resource-response-uswest2.s3-us-west-2.amazonaws.com/obj?X-Amz-Signature=abc",
		"port":              "https://cloudformation-custom-resource-response-uswest2.s3-us-west-2.amazonaws.com:8443/obj?X-Amz-Signature=abc",
		"no signature":      "https://cloudformation-custom-resource-response-uswest2.s3-us-west-2.amazonaws.com/obj",
		"no path":           "https://cloudformation-custom-resource-response-uswest2.s3-us-west-2.amazonaws.com/?X-Amz-Signature=abc",
		"unobserved form":   "https://cloudformation-custom-resource-response-uswest2.s3.amazonaws.com/obj?X-Amz-Signature=abc",
		"arbitrary host":    "https://example.com/obj?X-Amz-Signature=abc",
		"internal metadata": "https://169.254.169.254/latest?X-Amz-Signature=abc",
	}
	for name, raw := range bad {
		if _, err := ValidateResponseURL(raw, "us-west-2"); !errors.Is(err, ErrResponseURLRejected) {
			t.Fatalf("%s: expected ErrResponseURLRejected, got %v", name, err)
		}
	}
	// The global-endpoint form is us-east-1's alone.
	if _, err := ValidateResponseURL("https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com/obj?X-Amz-Signature=abc", "us-east-1"); err != nil {
		t.Fatalf("us-east-1 global form must pass: %v", err)
	}
	if _, err := ValidateResponseURL("https://cloudformation-custom-resource-response-apsouth1.s3.amazonaws.com/obj?X-Amz-Signature=abc", "ap-south-1"); !errors.Is(err, ErrResponseURLRejected) {
		t.Fatal("the global-endpoint form must not be accepted for a region other than us-east-1")
	}

	u, _ := url.Parse(good)
	if strings.Contains(RedactedURL(u), "Signature") {
		t.Fatal("RedactedURL must drop the presigned query")
	}
}

/* --------------------------------- protocol -------------------------------- */

func TestParseCallbackProtocol(t *testing.T) {
	msg := `{"RequestType":"Create","RequestId":"r1","StackId":"arn:aws:cloudformation:ap-south-1:222222222222:stack/AuthSec-Discovery-abcd2345/2d213470-3bbd-11ea-a35f-06b8fd1f0384",` +
		`"ResponseURL":"https://x","ResourceType":"Custom::AuthSecRegistration","LogicalResourceId":"AuthSecRegistration",` +
		`"ResourceProperties":{"ServiceToken":"arn:aws:sns:ap-south-1:111111111111:t","RoleArn":"arn:aws:iam::222222222222:role/R","ExternalId":"e","AccountId":"222222222222"}}`
	envBody, _ := json.Marshal(map[string]string{
		"Type": "Notification", "MessageId": "m", "TopicArn": "arn:aws:sns:ap-south-1:111111111111:t",
		"Message": msg, "Timestamp": "2026-09-24T10:00:00.000Z",
	})
	env, err := ParseSNSEnvelope(string(envBody))
	if err != nil {
		t.Fatal(err)
	}
	req, err := ParseCFNRequest(env.Message)
	if err != nil {
		t.Fatal(err)
	}
	if req.ResourceProperties.RoleArn != "arn:aws:iam::222222222222:role/R" {
		t.Fatalf("properties not decoded: %+v", req.ResourceProperties)
	}
	ref, err := ParseStackID(req.StackID)
	if err != nil || ref.Region != "ap-south-1" || ref.AccountID != "222222222222" || ref.Partition != "aws" {
		t.Fatalf("stack id parse: %+v %v", ref, err)
	}

	for name, m := range map[string]string{
		"other resource": strings.Replace(msg, `"LogicalResourceId":"AuthSecRegistration"`, `"LogicalResourceId":"Other"`, 1),
		"bad type":       strings.Replace(msg, `"RequestType":"Create"`, `"RequestType":"Poke"`, 1),
		"not json":       "{",
	} {
		if _, err := ParseCFNRequest(m); !errors.Is(err, ErrMalformedCallback) {
			t.Fatalf("%s: expected ErrMalformedCallback, got %v", name, err)
		}
	}
	if _, err := ParseSNSEnvelope(`{"Type":"SubscriptionConfirmation"}`); !errors.Is(err, ErrMalformedCallback) {
		t.Fatal("a non-notification envelope must be refused")
	}
}

func TestCFNResponseEncodeFitsLimit(t *testing.T) {
	req := &CFNRequest{StackID: "s", RequestID: "r", LogicalResourceID: RegistrationLogicalID}
	resp := NewCFNResponse(req, CFNStatusFailed, strings.Repeat("x", 10000), "authsec-id")
	body, err := resp.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > cfnResponseMaxBytes {
		t.Fatalf("encoded response is %d bytes, over CloudFormation's limit", len(body))
	}
	var back CFNResponse
	if err := json.Unmarshal(body, &back); err != nil || back.StackID != "s" || back.RequestID != "r" {
		t.Fatalf("ids must survive truncation verbatim: %v %+v", err, back)
	}
}

/* ---------------------------------- config --------------------------------- */

func TestParseCallbackConfig(t *testing.T) {
	topics := `{"us-east-1":"arn:aws:sns:us-east-1:111111111111:authsec-cfn-callback","ap-south-1":"arn:aws:sns:ap-south-1:111111111111:authsec-cfn-callback"}`
	cfg, err := ParseCallbackConfig(topics, "https://sqs.us-east-1.amazonaws.com/111111111111/authsec-cfn-callback",
		"https://bucket.s3.us-east-1.amazonaws.com", "", "af-south-1")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled() || len(cfg.SupportedDeploymentRegions()) != 2 || !cfg.IsOurTopic("arn:aws:sns:ap-south-1:111111111111:authsec-cfn-callback") {
		t.Fatalf("config not usable: %+v", cfg)
	}
	if cfg.IsOurTopic("arn:aws:sns:ap-south-1:999999999999:authsec-cfn-callback") {
		t.Fatal("a topic in another account must not match")
	}
	if !cfg.ScanRegionSupported("af-south-1") || cfg.ScanRegionSupported("me-south-1") || !cfg.ScanRegionSupported("eu-west-1") {
		t.Fatal("opt-in scan allow-list not applied")
	}
	if got := cfg.TemplateURLFor("ap-south-1"); got != "https://bucket.s3.us-east-1.amazonaws.com/aws/"+TemplateVersion+"/authsec-aws-discovery-role.yaml" {
		t.Fatalf("template URL: %s", got)
	}

	disabled, err := ParseCallbackConfig("", "", "", "", "")
	if err != nil || disabled.Enabled() {
		t.Fatalf("empty config must be valid and disabled: %v", err)
	}

	for name, in := range map[string][5]string{
		"topic in wrong region": {`{"us-east-1":"arn:aws:sns:us-west-2:111111111111:t"}`, "", "", "", ""},
		"opt-in topic region":   {`{"af-south-1":"arn:aws:sns:af-south-1:111111111111:t"}`, "", "", "", ""},
		"govcloud topic":        {`{"us-gov-west-1":"arn:aws-us-gov:sns:us-gov-west-1:111111111111:t"}`, "", "", "", ""},
		"bad queue":             {"", "https://example.com/q", "", "", ""},
		"non-S3 template":       {"", "", "https://example.com", "", ""},
		"default region opt-in": {"", "", "", "", "us-east-1"},
		"topics not json":       {"[", "", "", "", ""},
	} {
		if _, err := ParseCallbackConfig(in[0], in[1], in[2], in[3], in[4]); !errors.Is(err, ErrCallbackConfig) {
			t.Fatalf("%s: expected ErrCallbackConfig, got %v", name, err)
		}
	}
}
