// Package awsremediate is the AWS half of remediation (SPEC-secops-backend-
// upgrade.md W8, P5, C11): the operations a remediation is made of, the
// account they run against (the remediation role's session for writes, the
// discovery role for reads), the engine that checks, applies and reads back
// one step, and the prepared form of each step -- the exact API call, JSON
// document and CLI command a person or a pipeline runs when AuthSec has no
// remediation role, or the target is managed as code.
//
// What is decided where: services/agent_remediation*.go decides WHICH steps
// a remediation has, its mode (write, prepared, IaC pull request), its
// collateral, who may apply it and its proof; this package only does one
// step at a time against an Account, and renders steps. It never stores or
// logs a secret value: a new access key's secret exists only in memory,
// between CreateAccessKey and the PutSecretValue that hands it over.
package awsremediate

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/igagov"
)

// Ops: one write each (plus its readback).
const (
	OpDetachPolicy        = "detach_policy"
	OpAttachPolicy        = "attach_policy"
	OpCreatePolicy        = "create_policy"
	OpPutInlinePolicy     = "put_inline_policy"
	OpDeleteInlinePolicy  = "delete_inline_policy"
	OpCreatePolicyVersion = "create_policy_version"
	OpDeletePolicyVersion = "delete_policy_version"
	// OpRotateAccessKey creates a new access key and hands it over through
	// the customer's handover secret in one step: the secret is never kept.
	OpRotateAccessKey     = "rotate_access_key"
	OpDeactivateAccessKey = "deactivate_access_key"
	OpRotateSecret        = "rotate_secret"
)

// IsAWSOp reports whether op is a step this package applies.
func IsAWSOp(op string) bool {
	switch op {
	case OpDetachPolicy, OpAttachPolicy, OpCreatePolicy, OpPutInlinePolicy, OpDeleteInlinePolicy,
		OpCreatePolicyVersion, OpDeletePolicyVersion, OpRotateAccessKey, OpDeactivateAccessKey, OpRotateSecret:
		return true
	}
	return false
}

// Principal kinds.
const (
	PrincipalRole = "role"
	PrincipalUser = "user"
)

// Principal is an IAM role or user by name.
type Principal struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	ARN  string `json:"arn"`
}

// PrincipalOf parses an IAM role or user ARN.
func PrincipalOf(arn string) (Principal, error) {
	p := strings.SplitN(arn, ":", 6)
	if len(p) != 6 || p[0] != "arn" || p[2] != "iam" {
		return Principal{}, fmt.Errorf("%q is not an IAM role or user ARN", arn)
	}
	res := p[5]
	kind := ""
	switch {
	case strings.HasPrefix(res, "role/"):
		kind = PrincipalRole
	case strings.HasPrefix(res, "user/"):
		kind = PrincipalUser
	default:
		return Principal{}, fmt.Errorf("%q is not an IAM role or user ARN", arn)
	}
	name := res[strings.LastIndex(res, "/")+1:]
	if name == "" {
		return Principal{}, fmt.Errorf("%q names no principal", arn)
	}
	return Principal{Kind: kind, Name: name, ARN: arn}, nil
}

// Partition and account of an ARN.
func ARNAccount(arn string) (partition, account string) {
	p := strings.SplitN(arn, ":", 6)
	if len(p) != 6 {
		return "", ""
	}
	return p[1], p[4]
}

// ARNRegion is an ARN's region ("" for IAM).
func ARNRegion(arn string) string {
	p := strings.SplitN(arn, ":", 6)
	if len(p) != 6 {
		return ""
	}
	return p[3]
}

// Step is one change. Before is the state it was planned against (checked
// again right before the write, and kept so a revert can restore it); After
// is the intended end state (and, once applied, what the write returned:
// new version id, new key id); Readback is what a read showed afterwards.
type Step struct {
	Seq         int            `json:"seq"`
	Op          string         `json:"op"`
	Target      string         `json:"target"`
	EventSource string         `json:"event_source"`
	EventName   string         `json:"event_name"`
	Before      map[string]any `json:"before"`
	After       map[string]any `json:"after"`
	DueAt       *time.Time     `json:"due_at,omitempty"`
}

// Event names (CloudTrail) of each op.
const (
	SourceIAM     = "iam.amazonaws.com"
	SourceSecrets = "secretsmanager.amazonaws.com"
)

// EventOf is the CloudTrail event that records op on a principal kind.
func EventOf(op, principalKind string) (source, name string) {
	user := principalKind == PrincipalUser
	pick := func(role, usr string) string {
		if user {
			return usr
		}
		return role
	}
	switch op {
	case OpDetachPolicy:
		return SourceIAM, pick("DetachRolePolicy", "DetachUserPolicy")
	case OpAttachPolicy:
		return SourceIAM, pick("AttachRolePolicy", "AttachUserPolicy")
	case OpCreatePolicy:
		return SourceIAM, "CreatePolicy"
	case OpPutInlinePolicy:
		return SourceIAM, pick("PutRolePolicy", "PutUserPolicy")
	case OpDeleteInlinePolicy:
		return SourceIAM, pick("DeleteRolePolicy", "DeleteUserPolicy")
	case OpCreatePolicyVersion:
		return SourceIAM, "CreatePolicyVersion"
	case OpDeletePolicyVersion:
		return SourceIAM, "DeletePolicyVersion"
	case OpRotateAccessKey:
		return SourceIAM, "CreateAccessKey"
	case OpDeactivateAccessKey:
		return SourceIAM, "UpdateAccessKey"
	case OpRotateSecret:
		return SourceSecrets, "RotateSecret"
	}
	return "", ""
}

/* ------------------------------ step builders ------------------------------ */

func newStep(op, target, principalKind string, before, after map[string]any) Step {
	src, name := EventOf(op, principalKind)
	if before == nil {
		before = map[string]any{}
	}
	if after == nil {
		after = map[string]any{}
	}
	return Step{Op: op, Target: target, EventSource: src, EventName: name, Before: before, After: after}
}

func principalFields(p Principal, m map[string]any) map[string]any {
	m["principal_kind"], m["principal_name"], m["principal_arn"] = p.Kind, p.Name, p.ARN
	return m
}

// DetachStep detaches policyARN from p.
func DetachStep(p Principal, policyARN string) Step {
	return newStep(OpDetachPolicy, p.ARN, p.Kind,
		principalFields(p, map[string]any{"policy_arn": policyARN, "attached": true}),
		principalFields(p, map[string]any{"policy_arn": policyARN, "attached": false}))
}

// AttachStep attaches policyARN to p.
func AttachStep(p Principal, policyARN string) Step {
	return newStep(OpAttachPolicy, p.ARN, p.Kind,
		principalFields(p, map[string]any{"policy_arn": policyARN, "attached": false}),
		principalFields(p, map[string]any{"policy_arn": policyARN, "attached": true}))
}

// CreatePolicyStep creates an AuthSec remediation policy (path
// /authsec/remediation/).
func CreatePolicyStep(policyARN, path, name, document string, tags map[string]string) (Step, error) {
	canon, hash, err := Canonical(document)
	if err != nil {
		return Step{}, err
	}
	t := map[string]any{}
	for k, v := range tags {
		t[k] = v
	}
	return newStep(OpCreatePolicy, policyARN, "", map[string]any{"exists": false},
		map[string]any{"path": path, "name": name, "document": canon, "document_hash": hash, "tags": t}), nil
}

// PutInlineStep writes document as p's inline policy name; before is the
// document it replaces ("" when there was none).
func PutInlineStep(p Principal, name, before, document string) (Step, error) {
	canon, hash, err := Canonical(document)
	if err != nil {
		return Step{}, err
	}
	b := principalFields(p, map[string]any{"policy_name": name, "exists": before != ""})
	if before != "" {
		bc, bh, err := Canonical(before)
		if err != nil {
			return Step{}, err
		}
		b["document"], b["document_hash"] = bc, bh
	}
	return newStep(OpPutInlinePolicy, p.ARN, p.Kind, b,
		principalFields(p, map[string]any{"policy_name": name, "exists": true, "document": canon, "document_hash": hash})), nil
}

// DeleteInlineStep deletes p's inline policy name, whose document is before.
func DeleteInlineStep(p Principal, name, before string) (Step, error) {
	bc, bh, err := Canonical(before)
	if err != nil {
		return Step{}, err
	}
	return newStep(OpDeleteInlinePolicy, p.ARN, p.Kind,
		principalFields(p, map[string]any{"policy_name": name, "exists": true, "document": bc, "document_hash": bh}),
		principalFields(p, map[string]any{"policy_name": name, "exists": false})), nil
}

// PolicyVersionStep makes document the default version of a customer
// managed policy whose default version is beforeVersion with beforeDoc.
func PolicyVersionStep(policyARN, beforeVersion, beforeDoc, document string) (Step, error) {
	canon, hash, err := Canonical(document)
	if err != nil {
		return Step{}, err
	}
	bc, bh, err := Canonical(beforeDoc)
	if err != nil {
		return Step{}, err
	}
	return newStep(OpCreatePolicyVersion, policyARN, "",
		map[string]any{"default_version": beforeVersion, "document": bc, "document_hash": bh},
		map[string]any{"document": canon, "document_hash": hash, "set_default": true}), nil
}

// DeletePolicyVersionStep deletes a non-default version (the oldest, when a
// policy already has five) whose document is kept in before.
func DeletePolicyVersionStep(policyARN, versionID, doc string) (Step, error) {
	bc, bh, err := Canonical(doc)
	if err != nil {
		return Step{}, err
	}
	return newStep(OpDeletePolicyVersion, policyARN, "",
		map[string]any{"version_id": versionID, "document": bc, "document_hash": bh, "exists": true},
		map[string]any{"version_id": versionID, "exists": false}), nil
}

// RotateKeyStep creates a new key for user and hands it over through the
// customer's handover secret; oldKeyID is the key it replaces.
func RotateKeyStep(user Principal, oldKeyID, handoverSecretARN string, keys []AccessKey) Step {
	ks := make([]any, 0, len(keys))
	for _, k := range keys {
		ks = append(ks, map[string]any{"id": k.ID, "active": k.Active})
	}
	return newStep(OpRotateAccessKey, user.ARN, PrincipalUser,
		principalFields(user, map[string]any{"old_key_id": oldKeyID, "keys": ks, "handover_secret_arn": handoverSecretARN}),
		principalFields(user, map[string]any{"handover_secret_arn": handoverSecretARN, "new_key_active": true}))
}

// DeactivateKeyStep deactivates user's key keyID once due.
func DeactivateKeyStep(user Principal, keyID string, due *time.Time) Step {
	st := newStep(OpDeactivateAccessKey, user.ARN, PrincipalUser,
		principalFields(user, map[string]any{"key_id": keyID, "active": true}),
		principalFields(user, map[string]any{"key_id": keyID, "active": false}))
	st.DueAt = due
	return st
}

// RotateSecretStep starts the configured rotation of a secret.
func RotateSecretStep(info SecretInfo) Step {
	before := map[string]any{"rotation_enabled": info.RotationEnabled, "current_version": info.CurrentVersion}
	if info.LastRotated != nil {
		before["last_rotated"] = info.LastRotated.UTC().Format(time.RFC3339)
	}
	if info.RotationLambdaARN != "" {
		before["rotation_lambda_arn"] = info.RotationLambdaARN
	}
	return newStep(OpRotateSecret, info.ARN, "", before, map[string]any{"rotation_started": true})
}

/* ------------------------------- documents -------------------------------- */

// Canonical returns a policy document's canonical text and content hash.
// IAM's URL-encoded form is decoded first.
func Canonical(doc string) (string, string, error) {
	raw, err := igagov.DecodePolicyText(doc)
	if err != nil {
		return "", "", err
	}
	c, err := igagov.Canonicalize(raw)
	if err != nil {
		return "", "", fmt.Errorf("policy document: %w", err)
	}
	return string(c), igagov.ContentHash(c), nil
}

// SameDocument reports whether two documents are the same policy.
func SameDocument(a, b string) bool {
	_, ha, err1 := Canonical(a)
	_, hb, err2 := Canonical(b)
	return err1 == nil && err2 == nil && ha == hb
}

// ErrStatementNotFound: the statement to remove is not in the document.
var ErrStatementNotFound = errors.New("the statement is not in the policy document")

// RemovedStatement is a statement taken out of a document.
type RemovedStatement struct {
	Index     int            `json:"index"`
	Sid       string         `json:"sid,omitempty"`
	Statement map[string]any `json:"statement"`
	Actions   []string       `json:"actions"`
}

// RemoveStatement takes one statement out of a policy document: the one
// whose Sid is sid, else the one at index (0-based). It returns the new
// document (canonical; "" when no statement is left) and what was removed.
func RemoveStatement(doc, sid string, index int) (string, RemovedStatement, error) {
	raw, err := igagov.DecodePolicyText(doc)
	if err != nil {
		return "", RemovedStatement{}, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", RemovedStatement{}, fmt.Errorf("policy document: %w", err)
	}
	var stmts []any
	switch s := m["Statement"].(type) {
	case []any:
		stmts = s
	case map[string]any:
		stmts = []any{s}
	default:
		return "", RemovedStatement{}, errors.New("policy document has no Statement")
	}
	at := -1
	if sid != "" {
		for i, s := range stmts {
			if sm, ok := s.(map[string]any); ok && sm["Sid"] == sid {
				at = i
				break
			}
		}
	} else if index >= 0 && index < len(stmts) {
		at = index
	}
	if at < 0 {
		return "", RemovedStatement{}, ErrStatementNotFound
	}
	removed, _ := stmts[at].(map[string]any)
	rest := append(append([]any{}, stmts[:at]...), stmts[at+1:]...)
	out := RemovedStatement{Index: at, Statement: removed, Actions: StatementActions(removed)}
	if s, ok := removed["Sid"].(string); ok {
		out.Sid = s
	}
	if len(rest) == 0 {
		return "", out, nil
	}
	m["Statement"] = rest
	c, err := igagov.CanonicalizeValue(m)
	if err != nil {
		return "", RemovedStatement{}, err
	}
	return string(c), out, nil
}

// StatementActions lists a statement's Action (or "NOT " + NotAction).
func StatementActions(st map[string]any) []string {
	var out []string
	add := func(v any, prefix string) {
		switch t := v.(type) {
		case string:
			out = append(out, prefix+t)
		case []any:
			for _, x := range t {
				if s, ok := x.(string); ok {
					out = append(out, prefix+s)
				}
			}
		}
	}
	add(st["Action"], "")
	add(st["NotAction"], "NOT ")
	sort.Strings(out)
	return out
}

// DocumentActions lists every allowed action of a document's Allow
// statements (the grants a principal loses when the document goes).
func DocumentActions(doc string) []string {
	raw, err := igagov.DecodePolicyText(doc)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	var stmts []any
	switch s := m["Statement"].(type) {
	case []any:
		stmts = s
	case map[string]any:
		stmts = []any{s}
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range stmts {
		sm, ok := s.(map[string]any)
		if !ok || sm["Effect"] != "Allow" {
			continue
		}
		for _, a := range StatementActions(sm) {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	sort.Strings(out)
	return out
}

// RetirePolicyName is /authsec/remediation/AuthSecRetire-<unique id>-<8hex>.
func RetirePolicyName(uniqueID, remediationShort string) string {
	if uniqueID == "" {
		uniqueID = "principal"
	}
	return "AuthSecRetire-" + uniqueID + "-" + remediationShort
}

// PolicyARN is a policy ARN under path in the account.
func PolicyARN(partition, account, path, name string) string {
	if partition == "" {
		partition = "aws"
	}
	return "arn:" + partition + ":iam::" + account + ":policy" + path + name
}
