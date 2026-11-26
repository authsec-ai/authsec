package igagov

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Lambda functions in access policies (step 8). A block covers the function,
// its versions and aliases; a read block also refuses every way to hand
// invoking to someone else (a resource-policy statement, a function URL). An
// allow covers invoking only: changing the code runs it as the function's
// role. The action table was checked against the AWS service reference for
// lambda (servicereference.us-east-1.amazonaws.com, 2026-10-24).
//
// A function URL whose auth type is NONE takes no IAM at all: the service
// warns when the last scan saw such a URL's resource-policy statement.

// Lambda access-policy names.
const (
	AccessTypeLambdaFunction = "lambda_function"
	AccessSidFunction        = "AuthSecAccessFunction"
)

var (
	lambdaInvoke = []string{"lambda:InvokeFunction", "lambda:InvokeFunctionUrl"}
	// read: invoking, the code and the configuration (environment variables
	// often hold secrets), and handing invoking to others.
	lambdaRead = append([]string{"lambda:InvokeAsync", "lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:AddPermission",
		"lambda:PutResourcePolicy", "lambda:CreateFunctionUrlConfig", "lambda:UpdateFunctionUrlConfig"}, lambdaInvoke...)
	lambdaWrite = []string{"lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:PublishVersion", "lambda:CreateAlias",
		"lambda:UpdateAlias", "lambda:PutFunctionConcurrency", "lambda:PutFunctionEventInvokeConfig", "lambda:UpdateFunctionEventInvokeConfig",
		"lambda:PutFunctionRecursionConfig", "lambda:PutFunctionScalingConfig", "lambda:PutRuntimeManagementConfig",
		"lambda:PutFunctionCodeSigningConfig", "lambda:UpdateFunctionCodeSigningConfig", "lambda:AddPermission", "lambda:RemovePermission",
		"lambda:PutResourcePolicy", "lambda:DeleteResourcePolicy", "lambda:CreateFunctionUrlConfig", "lambda:UpdateFunctionUrlConfig",
		"lambda:TagResource", "lambda:UntagResource"}
	lambdaDelete = []string{"lambda:DeleteFunction", "lambda:DeleteAlias", "lambda:DeleteFunctionUrlConfig", "lambda:DeleteFunctionConcurrency",
		"lambda:DeleteFunctionEventInvokeConfig", "lambda:DeleteFunctionCodeSigningConfig"}
)

var reLambdaARN = regexp.MustCompile(`^arn:(aws[a-z-]*):lambda:([a-z]{2}(?:-[a-z]+)+-\d+):(\d{12}):function:([A-Za-z0-9_-]{1,64})(?::(?:\$LATEST|[A-Za-z0-9_-]{1,128}|\*))?$`)

// LambdaTarget is one function, every version and alias.
type LambdaTarget struct {
	Partition, Region, Account, Function string
}

// ParseLambdaFunctionARN reads the function a function, version or alias ARN
// names.
func ParseLambdaFunctionARN(arn string) (LambdaTarget, bool) {
	m := reLambdaARN.FindStringSubmatch(strings.TrimSpace(arn))
	if m == nil {
		return LambdaTarget{}, false
	}
	return LambdaTarget{Partition: m[1], Region: m[2], Account: m[3], Function: m[4]}, true
}

// LambdaTarget is an AWSAccessTarget.
func (t LambdaTarget) Type() string    { return AccessTypeLambdaFunction }
func (t LambdaTarget) Service() string { return "lambda" }
func (t LambdaTarget) Noun() string    { return "function" }
func (t LambdaTarget) ARN() string {
	return "arn:" + t.Partition + ":lambda:" + t.Region + ":" + t.Account + ":function:" + t.Function
}

// QualifiedARN is every version and alias of the function.
func (t LambdaTarget) QualifiedARN() string { return t.ARN() + ":*" }
func (t LambdaTarget) Name() string         { return t.Function }
func (t LambdaTarget) ARNAccount() string   { return t.Account }
func (t LambdaTarget) ARNRegion() string    { return t.Region }
func (t LambdaTarget) ARNPartition() string { return t.Partition }
func (t LambdaTarget) Where() string {
	return "Lambda function " + t.Function + " (" + t.Region + ", account " + t.Account + ")"
}

// Statements is the function's document. An allow covers invoking only.
func (t LambdaTarget) Statements(effect string, access []string) ([]AccessStatement, error) {
	res := []string{t.ARN(), t.QualifiedARN()}
	if effect == AccessEffectAllow {
		if accessHas(access, AccessWrite, AccessDelete, AccessAll) {
			return nil, &AccessFieldError{Field: "access", Message: "An allow on a function covers invoking it (read) only: changing its code runs that code as the function's role."}
		}
		return []AccessStatement{{Sid: AccessSidFunction, Actions: sortedUnique(lambdaInvoke), Resources: res}}, nil
	}
	acts := levelActions(access, "lambda:*", lambdaRead, lambdaWrite, lambdaDelete)
	if len(acts) == 0 {
		return nil, nil
	}
	return []AccessStatement{{Sid: AccessSidFunction, Actions: acts, Resources: res}}, nil
}

// Notes is the preview's warnings for a function.
func (t LambdaTarget) Notes(effect string, access []string) []AccessNote {
	var out []AccessNote
	add := func(code, msg string) { out = append(out, AccessNote{Code: code, Message: msg}) }
	read := accessHas(access, AccessRead, AccessAll)
	if effect == AccessEffectBlock && read {
		add("versions_covered", "The block covers every version and alias of the function, its code and its configuration (environment variables included).")
		add("handoff_blocked", "Adding to the function's resource policy and creating or changing its function URL are refused too: each can let someone else invoke it.")
		add("triggers_not_covered", "Services that call the function through its resource policy (API Gateway, S3, EventBridge, queue triggers) are not covered.")
	}
	if effect == AccessEffectAllow {
		add("allow_invoke_only", "The allow covers invoking the function, every version and alias.")
	}
	return out
}

// OtherPaths is the other_paths warning.
func (t LambdaTarget) OtherPaths() string {
	return "This changes only the chosen roles. Other roles, users, groups and the function's resource policy are unchanged."
}

// PublicFunctionURL reports whether a function's resource policy lets anyone
// invoke its function URL without IAM: an Allow of lambda:InvokeFunctionUrl
// (or lambda:*) to "*" held to lambda:FunctionUrlAuthType NONE.
func PublicFunctionURL(doc json.RawMessage) bool {
	var d struct {
		Statement json.RawMessage
	}
	if json.Unmarshal(doc, &d) != nil {
		return false
	}
	var stmts []map[string]any
	if json.Unmarshal(d.Statement, &stmts) != nil {
		var one map[string]any
		if json.Unmarshal(d.Statement, &one) != nil {
			return false
		}
		stmts = []map[string]any{one}
	}
	strs := func(v any) []string {
		switch x := v.(type) {
		case string:
			return []string{x}
		case []any:
			var out []string
			for _, e := range x {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
			return out
		}
		return nil
	}
	for _, st := range stmts {
		if st["Effect"] != "Allow" {
			continue
		}
		invokes := false
		for _, a := range strs(st["Action"]) {
			invokes = invokes || strings.EqualFold(a, "lambda:InvokeFunctionUrl") || a == "lambda:*" || a == "*"
		}
		anyone := false
		switch p := st["Principal"].(type) {
		case string:
			anyone = p == "*"
		case map[string]any:
			for _, v := range p {
				for _, s := range strs(v) {
					anyone = anyone || s == "*"
				}
			}
		}
		none := false
		if cond, ok := st["Condition"].(map[string]any); ok {
			for _, kv := range cond {
				if m, ok := kv.(map[string]any); ok {
					for k, v := range m {
						for _, s := range strs(v) {
							none = none || (strings.EqualFold(k, "lambda:FunctionUrlAuthType") && strings.EqualFold(s, "NONE"))
						}
					}
				}
			}
		}
		if invokes && anyone && none {
			return true
		}
	}
	return false
}
