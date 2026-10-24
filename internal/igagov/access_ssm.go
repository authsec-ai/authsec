package igagov

import (
	"regexp"
	"strings"
)

// SSM Parameter Store parameters in access policies (step 5, block only). A
// block is a Deny on the parameter's ARN; a read block also denies
// GetParametersByPath on every path above it, the root included: AWS
// evaluates a path listing on the path only, so a role denied /a/b can still
// read it by listing /a recursively (GetParametersByPath API reference). The
// action table was checked against the AWS service reference for Systems
// Manager (servicereference.us-east-1.amazonaws.com, 2026-10-24).
//
// Unverified against a live account, so chosen to fail safe:
//   - the ARN a listing of the root path "/" is authorized on: the block
//     names "parameter/" and every ancestor without the ssm:Recursive
//     condition, so listing those paths is refused for the block's duration.

// SSM access-policy names.
const (
	AccessTypeSSMParameter = "ssm_parameter"
	AccessSidParameter     = "AuthSecAccessParameter"
	AccessSidPath          = "AuthSecAccessPath"
	ssmAll                 = "ssm:*"
	ssmByPath              = "ssm:GetParametersByPath"
)

// The actions per level a block denies on the parameter.
var (
	// read: the value (GetParameterHistory returns the current value too),
	// the resource policy (sharing it with another account) and tags, which
	// can satisfy another principal's tag-based Allow.
	ssmRead = []string{"ssm:GetParameter", "ssm:GetParameters", "ssm:GetParameterHistory", "ssm:PutResourcePolicy", "ssm:DeleteResourcePolicy",
		"ssm:AddTagsToResource", "ssm:RemoveTagsFromResource"}
	ssmWrite = []string{"ssm:PutParameter", "ssm:LabelParameterVersion", "ssm:UnlabelParameterVersion", "ssm:AddTagsToResource", "ssm:RemoveTagsFromResource"}
	ssmDel   = []string{"ssm:DeleteParameter", "ssm:DeleteParameters"}
)

// SSMParameterTarget is one parameter; Param is the ARN's resource after
// "parameter/" (a hierarchical name without its leading "/").
type SSMParameterTarget struct {
	Partition, Region, Account, Param string
}

// A parameter ARN: names use a-zA-Z0-9_.- and "/" between levels (at most
// 15), so "*" or "?" makes it a pattern.
var reSSMParameterARN = regexp.MustCompile(`^arn:(aws[a-z-]*):ssm:([a-z]{2}(?:-[a-z]+)+-\d+):(\d{12}):parameter/([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+){0,14})$`)

// ParseSSMParameterARN reads the parameter an ARN names.
func ParseSSMParameterARN(arn string) (SSMParameterTarget, bool) {
	m := reSSMParameterARN.FindStringSubmatch(strings.TrimSpace(arn))
	if m == nil || len(m[4]) > 2048 {
		return SSMParameterTarget{}, false
	}
	return SSMParameterTarget{Partition: m[1], Region: m[2], Account: m[3], Param: m[4]}, true
}

func (t SSMParameterTarget) arnOf(path string) string {
	return "arn:" + t.Partition + ":ssm:" + t.Region + ":" + t.Account + ":parameter/" + path
}

// PathARNs are the ARNs a listing that returns the parameter is authorized
// on: the root and every level above it.
func (t SSMParameterTarget) PathARNs() []string {
	out := []string{t.arnOf("")}
	levels := strings.Split(t.Param, "/")
	for i := 1; i < len(levels); i++ {
		out = append(out, t.arnOf(strings.Join(levels[:i], "/")))
	}
	return out
}

// SSMParameterTarget is an AWSAccessTarget.
func (t SSMParameterTarget) Type() string    { return AccessTypeSSMParameter }
func (t SSMParameterTarget) Service() string { return "ssm" }
func (t SSMParameterTarget) Noun() string    { return "parameter" }
func (t SSMParameterTarget) ARN() string     { return t.arnOf(t.Param) }

// Name is the parameter's name: a hierarchical one with its leading "/".
func (t SSMParameterTarget) Name() string {
	if strings.Contains(t.Param, "/") {
		return "/" + t.Param
	}
	return t.Param
}
func (t SSMParameterTarget) ARNAccount() string   { return t.Account }
func (t SSMParameterTarget) ARNRegion() string    { return t.Region }
func (t SSMParameterTarget) ARNPartition() string { return t.Partition }
func (t SSMParameterTarget) Where() string {
	return "SSM parameter " + t.Name() + " (" + t.Region + ", account " + t.Account + ")"
}

// Statements is the parameter's block document; an allow is refused.
func (t SSMParameterTarget) Statements(effect string, access []string) ([]AccessStatement, error) {
	if effect != AccessEffectBlock {
		return nil, ErrAccessBlockOnly
	}
	all := accessHas(access, AccessAll)
	read := accessHas(access, AccessRead)
	var acts []string
	switch {
	case all:
		acts = []string{ssmAll}
	default:
		if read {
			acts = append(acts, ssmRead...)
		}
		if accessHas(access, AccessWrite) {
			acts = append(acts, ssmWrite...)
		}
		if accessHas(access, AccessDelete) {
			acts = append(acts, ssmDel...)
		}
	}
	if len(acts) == 0 {
		return nil, nil
	}
	stmts := []AccessStatement{{Sid: AccessSidParameter, Actions: sortedUnique(acts), Resources: []string{t.ARN()}}}
	if read || all {
		stmts = append(stmts, AccessStatement{Sid: AccessSidPath, Actions: []string{ssmByPath}, Resources: t.PathARNs()})
	}
	return stmts, nil
}

// Notes is the preview's warnings for a parameter, in a fixed order.
func (t SSMParameterTarget) Notes(effect string, access []string) []AccessNote {
	all := accessHas(access, AccessAll)
	read, write, del := accessHas(access, AccessRead), accessHas(access, AccessWrite), accessHas(access, AccessDelete)
	var out []AccessNote
	add := func(code, msg string) { out = append(out, AccessNote{Code: code, Message: msg}) }
	if read || all {
		paths := []string{"/"}
		levels := strings.Split(t.Param, "/")
		for i := 1; i < len(levels); i++ {
			paths = append(paths, "/"+strings.Join(levels[:i], "/"))
		}
		add("path_listing_blocked", "Listing parameters by path under "+strings.Join(paths, ", ")+" is refused too, for every parameter there: a listing of a path above this parameter returns it, and AWS cannot leave one parameter out.")
	}
	if read && !all {
		add("history_blocked", "Reading the parameter's history, sharing it with another account and tagging it are refused too: each can hand its value on.")
	}
	if del && !write && !all {
		add("overwrite_not_covered", "Putting a new value with overwrite can still replace the parameter's value.")
	}
	if read || all {
		add("copies_not_covered", "Copies outside Parameter Store are not covered: values already read by services that use their own role (Lambda, ECS, CloudFormation), caches and other systems.")
	}
	return out
}

// OtherPaths is the other_paths warning.
func (t SSMParameterTarget) OtherPaths() string {
	return "This changes only the chosen roles. Other roles, users, groups and accounts the parameter is shared with are unchanged."
}
