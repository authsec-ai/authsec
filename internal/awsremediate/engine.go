package awsremediate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/awsenforce"
)

// AccessKey is one access key of an IAM user (never its secret).
type AccessKey struct {
	ID     string `json:"id"`
	Active bool   `json:"active"`
}

// PolicyVersion is one version of a managed policy.
type PolicyVersion struct {
	ID        string
	IsDefault bool
	Created   time.Time
}

// SecretInfo is a secret's metadata (DescribeSecret): never its value.
type SecretInfo struct {
	ARN               string
	Name              string
	RotationEnabled   bool
	RotationLambdaARN string
	LastRotated       *time.Time
	// CurrentVersion is the version id staged AWSCURRENT; Pending the one
	// staged AWSPENDING (a rotation in progress), "" when none.
	CurrentVersion string
	PendingVersion string
	Tags           map[string]string
}

// NewKey is a freshly created access key. Its secret is unexported and
// never marshalled or printed: it is only passed to the handover write.
type NewKey struct {
	ID     string
	secret string
}

// NewAccessKey builds a NewKey (the live client and fakes).
func NewAccessKey(id, secret string) NewKey { return NewKey{ID: id, secret: secret} }

// String never shows the secret.
func (k NewKey) String() string { return "AccessKey(" + k.ID + ", secret redacted)" }

// GoString never shows the secret.
func (k NewKey) GoString() string { return k.String() }

// MarshalJSON never writes the secret.
func (k NewKey) MarshalJSON() ([]byte, error) { return json.Marshal(map[string]string{"id": k.ID}) }

// HandoverValue is the JSON written into the handover secret.
func (k NewKey) HandoverValue() string {
	b, _ := json.Marshal(map[string]string{"AccessKeyId": k.ID, "SecretAccessKey": k.secret})
	return string(b)
}

// Reader is what a remediation reads, through the DISCOVERY role (never the
// remediation role, which is write-only): IAM reads and a secret's metadata.
// A missing object is an error IsNotFound recognises, except where noted.
type Reader interface {
	ListAttachedPolicies(ctx context.Context, p Principal) ([]string, error)
	// GetInlinePolicy returns ("", false, nil) when p has no such policy.
	GetInlinePolicy(ctx context.Context, p Principal, name string) (string, bool, error)
	// GetDefaultPolicyVersion returns the default version id and document.
	GetDefaultPolicyVersion(ctx context.Context, policyARN string) (string, string, error)
	ListPolicyVersions(ctx context.Context, policyARN string) ([]PolicyVersion, error)
	GetPolicyVersion(ctx context.Context, policyARN, versionID string) (string, error)
	ListAccessKeys(ctx context.Context, userName string) ([]AccessKey, error)
	DescribeSecret(ctx context.Context, secretARN string) (*SecretInfo, error)
	// PolicyExists reports whether a managed policy exists.
	PolicyExists(ctx context.Context, policyARN string) (bool, error)
}

// Writer is the remediation role's session: the writes the remediation
// template allows, and nothing else.
type Writer interface {
	DetachPolicy(ctx context.Context, p Principal, policyARN string) error
	AttachPolicy(ctx context.Context, p Principal, policyARN string) error
	CreatePolicy(ctx context.Context, path, name, document string, tags map[string]string) (string, error)
	PutInlinePolicy(ctx context.Context, p Principal, name, document string) error
	DeleteInlinePolicy(ctx context.Context, p Principal, name string) error
	CreatePolicyVersion(ctx context.Context, policyARN, document string, setDefault bool) (string, error)
	DeletePolicyVersion(ctx context.Context, policyARN, versionID string) error
	CreateAccessKey(ctx context.Context, userName string) (NewKey, error)
	UpdateAccessKey(ctx context.Context, userName, keyID string, active bool) error
	DeleteAccessKey(ctx context.Context, userName, keyID string) error
	RotateSecret(ctx context.Context, secretARN string) (string, error)
	// PutSecretValue writes value as a new version of secretARN (the
	// handover secret) and returns the version id. value is never logged.
	PutSecretValue(ctx context.Context, secretARN, value string) (string, error)
}

// Account is a remediation's view of one AWS account: reads through the
// discovery role, writes through the remediation role.
type Account interface {
	Reader
	Writer
}

// Error codes of a step.
const (
	CodeDenied        = "aws_refused"
	CodeTargetChanged = "target_changed"
	CodeNotFound      = "target_not_found"
	CodeReadback      = "readback_mismatch"
	CodeRotationOff   = "rotation_not_configured"
	CodeKeyLimit      = "access_key_limit"
	CodeHandover      = "handover_failed"
	CodeFailed        = "aws_error"
)

// StepError is a refused or failed step.
type StepError struct {
	Code    string
	Message string
}

func (e *StepError) Error() string { return e.Code + ": " + e.Message }

func stepErr(code, format string, a ...any) error {
	return &StepError{Code: code, Message: fmt.Sprintf(format, a...)}
}

// CodeOf is a step error's code ("aws_error" for any other error).
func CodeOf(err error) string {
	var se *StepError
	if errors.As(err, &se) {
		return se.Code
	}
	return CodeFailed
}

// IsNotFound recognises a not-found answer.
func IsNotFound(err error) bool { return err != nil && awsenforce.IsNotFound(err) }

func writeErr(op string, err error) error {
	switch {
	case err == nil:
		return nil
	case awsenforce.IsAccessDenied(err):
		return stepErr(CodeDenied, "AWS refused %s (%s): the remediation role does not allow it here, or the target is protected", op, awsenforce.ErrorCode(err))
	case IsNotFound(err):
		return stepErr(CodeNotFound, "%s: the target no longer exists (%s)", op, awsenforce.ErrorCode(err))
	}
	code := awsenforce.ErrorCode(err)
	if code == "" {
		code = "error"
	}
	return stepErr(CodeFailed, "%s failed (%s)", op, code)
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func principalOf(m map[string]any) Principal {
	return Principal{Kind: str(m, "principal_kind"), Name: str(m, "principal_name"), ARN: str(m, "principal_arn")}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Engine applies steps against one account.
type Engine struct{ A Account }

// Check re-reads the target right before the write and refuses the step
// when it is no longer in its recorded before-state (someone changed it
// since the remediation was planned): the before-state is what a revert
// restores, so it must be true.
func (e *Engine) Check(ctx context.Context, st *Step) error {
	b := st.Before
	p := principalOf(b)
	switch st.Op {
	case OpDetachPolicy, OpAttachPolicy:
		got, err := e.A.ListAttachedPolicies(ctx, p)
		if err != nil {
			return writeErr("read attachments", err)
		}
		if contains(got, str(b, "policy_arn")) != (b["attached"] == true) {
			return stepErr(CodeTargetChanged, "the policy's attachment to %s changed since the remediation was planned", p.Name)
		}
	case OpCreatePolicy:
		ok, err := e.A.PolicyExists(ctx, st.Target)
		if err != nil {
			return writeErr("read policy", err)
		}
		if ok {
			return stepErr(CodeTargetChanged, "the policy %s already exists", st.Target)
		}
	case OpPutInlinePolicy, OpDeleteInlinePolicy:
		doc, found, err := e.A.GetInlinePolicy(ctx, p, str(b, "policy_name"))
		if err != nil {
			return writeErr("read inline policy", err)
		}
		if found != (b["exists"] == true) || (found && !SameDocument(doc, str(b, "document"))) {
			return stepErr(CodeTargetChanged, "the inline policy %s of %s changed since the remediation was planned", str(b, "policy_name"), p.Name)
		}
	case OpCreatePolicyVersion:
		v, doc, err := e.A.GetDefaultPolicyVersion(ctx, st.Target)
		if err != nil {
			return writeErr("read policy", err)
		}
		if v != str(b, "default_version") || !SameDocument(doc, str(b, "document")) {
			return stepErr(CodeTargetChanged, "the policy %s has a new default version since the remediation was planned", st.Target)
		}
	case OpDeletePolicyVersion:
		vs, err := e.A.ListPolicyVersions(ctx, st.Target)
		if err != nil {
			return writeErr("read policy versions", err)
		}
		for _, v := range vs {
			if v.ID == str(b, "version_id") {
				if v.IsDefault {
					return stepErr(CodeTargetChanged, "version %s became the default", v.ID)
				}
				return nil
			}
		}
		return stepErr(CodeTargetChanged, "version %s no longer exists", str(b, "version_id"))
	case OpRotateAccessKey:
		keys, err := e.A.ListAccessKeys(ctx, p.Name)
		if err != nil {
			return writeErr("list access keys", err)
		}
		old := str(b, "old_key_id")
		found := false
		for _, k := range keys {
			found = found || k.ID == old
		}
		if !found {
			return stepErr(CodeTargetChanged, "the key %s no longer exists", old)
		}
		if len(keys) >= 2 {
			return stepErr(CodeKeyLimit, "%s already has two access keys; delete the unused one first", p.Name)
		}
	case OpDeactivateAccessKey:
		keys, err := e.A.ListAccessKeys(ctx, p.Name)
		if err != nil {
			return writeErr("list access keys", err)
		}
		for _, k := range keys {
			if k.ID == str(b, "key_id") {
				return nil
			}
		}
		return stepErr(CodeTargetChanged, "the key %s no longer exists", str(b, "key_id"))
	case OpRotateSecret:
		info, err := e.A.DescribeSecret(ctx, st.Target)
		if err != nil {
			return writeErr("describe secret", err)
		}
		if !info.RotationEnabled {
			return stepErr(CodeRotationOff, "rotation is not configured on %s", st.Target)
		}
	default:
		return fmt.Errorf("awsremediate: unknown op %q", st.Op)
	}
	return nil
}

// Apply makes the step's write and returns what it produced (merged into
// After by the caller): a new version id, a new key id. It never returns a
// secret.
func (e *Engine) Apply(ctx context.Context, st *Step) (map[string]any, error) {
	a := st.After
	p := principalOf(st.Before)
	switch st.Op {
	case OpDetachPolicy:
		return nil, writeErr(st.EventName, e.A.DetachPolicy(ctx, p, str(a, "policy_arn")))
	case OpAttachPolicy:
		return nil, writeErr(st.EventName, e.A.AttachPolicy(ctx, p, str(a, "policy_arn")))
	case OpCreatePolicy:
		tags := map[string]string{}
		if t, ok := a["tags"].(map[string]any); ok {
			for k, v := range t {
				tags[k], _ = v.(string)
			}
		}
		arn, err := e.A.CreatePolicy(ctx, str(a, "path"), str(a, "name"), str(a, "document"), tags)
		if err != nil {
			return nil, writeErr("CreatePolicy", err)
		}
		return map[string]any{"policy_arn": arn}, nil
	case OpPutInlinePolicy:
		return nil, writeErr(st.EventName, e.A.PutInlinePolicy(ctx, p, str(a, "policy_name"), str(a, "document")))
	case OpDeleteInlinePolicy:
		return nil, writeErr(st.EventName, e.A.DeleteInlinePolicy(ctx, p, str(a, "policy_name")))
	case OpCreatePolicyVersion:
		v, err := e.A.CreatePolicyVersion(ctx, st.Target, str(a, "document"), true)
		if err != nil {
			return nil, writeErr("CreatePolicyVersion", err)
		}
		return map[string]any{"version_id": v}, nil
	case OpDeletePolicyVersion:
		return nil, writeErr("DeletePolicyVersion", e.A.DeletePolicyVersion(ctx, st.Target, str(a, "version_id")))
	case OpRotateAccessKey:
		key, err := e.A.CreateAccessKey(ctx, p.Name)
		if err != nil {
			return nil, writeErr("CreateAccessKey", err)
		}
		ver, err := e.A.PutSecretValue(ctx, str(a, "handover_secret_arn"), key.HandoverValue())
		if err != nil {
			// The new key could not be handed over and its secret is
			// about to be forgotten: delete it, so no key exists that
			// nobody can use.
			derr := e.A.DeleteAccessKey(ctx, p.Name, key.ID)
			msg := "the new key could not be written to the handover secret (" + awsenforce.ErrorCode(err) + "); it was deleted again"
			if derr != nil {
				msg = "the new key could not be written to the handover secret (" + awsenforce.ErrorCode(err) +
					") and deleting it failed (" + awsenforce.ErrorCode(derr) + "): delete key " + key.ID + " by hand"
			}
			return map[string]any{"new_key_id": key.ID, "new_key_deleted": derr == nil}, stepErr(CodeHandover, "%s", msg)
		}
		return map[string]any{"new_key_id": key.ID, "handover_version_id": ver}, nil
	case OpDeactivateAccessKey:
		return nil, writeErr("UpdateAccessKey", e.A.UpdateAccessKey(ctx, p.Name, str(a, "key_id"), false))
	case OpRotateSecret:
		v, err := e.A.RotateSecret(ctx, st.Target)
		if err != nil {
			return nil, writeErr("RotateSecret", err)
		}
		return map[string]any{"version_id": v}, nil
	}
	return nil, fmt.Errorf("awsremediate: unknown op %q", st.Op)
}

// Readback reads the end state of an applied step (through r: the
// discovery role) and reports whether it is the intended one, with what
// was observed.
func Readback(ctx context.Context, r Reader, st *Step) (bool, map[string]any, error) {
	a := st.After
	p := principalOf(st.Before)
	obs := map[string]any{"read_at": time.Now().UTC().Format(time.RFC3339)}
	switch st.Op {
	case OpDetachPolicy, OpAttachPolicy:
		got, err := r.ListAttachedPolicies(ctx, p)
		if err != nil {
			return false, obs, err
		}
		attached := contains(got, str(a, "policy_arn"))
		obs["attached"] = attached
		return attached == (a["attached"] == true), obs, nil
	case OpCreatePolicy:
		ok, err := r.PolicyExists(ctx, st.Target)
		if err != nil {
			return false, obs, err
		}
		obs["exists"] = ok
		return ok, obs, nil
	case OpPutInlinePolicy, OpDeleteInlinePolicy:
		doc, found, err := r.GetInlinePolicy(ctx, p, str(a, "policy_name"))
		if err != nil {
			return false, obs, err
		}
		obs["exists"] = found
		if found {
			_, h, _ := Canonical(doc)
			obs["document_hash"] = h
		}
		if a["exists"] != true {
			return !found, obs, nil
		}
		return found && SameDocument(doc, str(a, "document")), obs, nil
	case OpCreatePolicyVersion:
		v, doc, err := r.GetDefaultPolicyVersion(ctx, st.Target)
		if err != nil {
			return false, obs, err
		}
		_, h, _ := Canonical(doc)
		obs["default_version"], obs["document_hash"] = v, h
		return SameDocument(doc, str(a, "document")), obs, nil
	case OpDeletePolicyVersion:
		vs, err := r.ListPolicyVersions(ctx, st.Target)
		if err != nil {
			return false, obs, err
		}
		for _, v := range vs {
			if v.ID == str(a, "version_id") {
				obs["exists"] = true
				return false, obs, nil
			}
		}
		obs["exists"] = false
		return true, obs, nil
	case OpRotateAccessKey, OpDeactivateAccessKey:
		keys, err := r.ListAccessKeys(ctx, p.Name)
		if err != nil {
			return false, obs, err
		}
		ks := make([]any, 0, len(keys))
		for _, k := range keys {
			ks = append(ks, map[string]any{"id": k.ID, "active": k.Active})
		}
		obs["keys"] = ks
		want, wantActive := str(a, "new_key_id"), true
		if st.Op == OpDeactivateAccessKey {
			want, wantActive = str(a, "key_id"), false
		}
		if want == "" {
			return false, obs, nil
		}
		for _, k := range keys {
			if k.ID == want {
				return k.Active == wantActive, obs, nil
			}
		}
		// A deactivated key that was deleted meanwhile is also not usable.
		return st.Op == OpDeactivateAccessKey, obs, nil
	case OpRotateSecret:
		info, err := r.DescribeSecret(ctx, st.Target)
		if err != nil {
			return false, obs, err
		}
		obs["current_version"], obs["pending_version"] = info.CurrentVersion, info.PendingVersion
		if info.LastRotated != nil {
			obs["last_rotated"] = info.LastRotated.UTC().Format(time.RFC3339)
		}
		// Rotated: the version AWSCURRENT moved, or the version the call
		// returned is now current.
		v := str(a, "version_id")
		before := str(st.Before, "current_version")
		return info.CurrentVersion != "" && (info.CurrentVersion == v || (before != "" && info.CurrentVersion != before)), obs, nil
	}
	return false, obs, fmt.Errorf("awsremediate: unknown op %q", st.Op)
}

// Prepared is one step as a person or a pipeline runs it: the API call, its
// parameters, the document, and the AWS CLI command. Never a secret.
type Prepared struct {
	Seq         int            `json:"seq"`
	Op          string         `json:"op"`
	Description string         `json:"description"`
	API         string         `json:"api"`
	Params      map[string]any `json:"params"`
	Document    string         `json:"document,omitempty"`
	CLI         []string       `json:"cli"`
	NotBefore   string         `json:"not_before,omitempty"`
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'" }

// Prepare renders a step for a person or a pipeline.
func Prepare(st Step) Prepared {
	a, b := st.After, st.Before
	p := principalOf(b)
	flag, noun := "--role-name", "role"
	if p.Kind == PrincipalUser {
		flag, noun = "--user-name", "user"
	}
	out := Prepared{Seq: st.Seq, Op: st.Op, API: st.EventSource + ":" + st.EventName, Params: map[string]any{}}
	if st.EventSource == SourceIAM {
		out.API = "iam:" + st.EventName
	} else if st.EventSource == SourceSecrets {
		out.API = "secretsmanager:" + st.EventName
	}
	switch st.Op {
	case OpDetachPolicy, OpAttachPolicy:
		verb := "detach"
		if st.Op == OpAttachPolicy {
			verb = "attach"
		}
		prep := "from"
		if verb == "attach" {
			prep = "to"
		}
		out.Description = fmt.Sprintf("%s%s policy %s %s %s %s", strings.ToUpper(verb[:1]), verb[1:], str(a, "policy_arn"), prep, noun, p.Name)
		out.Params = map[string]any{noun + "_name": p.Name, "policy_arn": str(a, "policy_arn")}
		out.CLI = []string{fmt.Sprintf("aws iam %s-%s-policy %s %s --policy-arn %s", verb, noun, flag, shq(p.Name), shq(str(a, "policy_arn")))}
	case OpCreatePolicy:
		out.Description = "Create the AuthSec deny policy " + st.Target
		out.Document = str(a, "document")
		out.Params = map[string]any{"policy_name": str(a, "name"), "path": str(a, "path")}
		out.CLI = []string{fmt.Sprintf("aws iam create-policy --policy-name %s --path %s --policy-document %s",
			shq(str(a, "name")), shq(str(a, "path")), shq(out.Document))}
	case OpPutInlinePolicy:
		out.Description = fmt.Sprintf("Replace inline policy %s of %s %s with the document below", str(a, "policy_name"), noun, p.Name)
		out.Document = str(a, "document")
		out.Params = map[string]any{noun + "_name": p.Name, "policy_name": str(a, "policy_name")}
		out.CLI = []string{fmt.Sprintf("aws iam put-%s-policy %s %s --policy-name %s --policy-document %s",
			noun, flag, shq(p.Name), shq(str(a, "policy_name")), shq(out.Document))}
	case OpDeleteInlinePolicy:
		out.Description = fmt.Sprintf("Delete inline policy %s of %s %s (its only statement is the grant)", str(a, "policy_name"), noun, p.Name)
		out.Params = map[string]any{noun + "_name": p.Name, "policy_name": str(a, "policy_name")}
		out.CLI = []string{fmt.Sprintf("aws iam delete-%s-policy %s %s --policy-name %s", noun, flag, shq(p.Name), shq(str(a, "policy_name")))}
	case OpCreatePolicyVersion:
		out.Description = "Make the document below the default version of " + st.Target
		out.Document = str(a, "document")
		out.Params = map[string]any{"policy_arn": st.Target, "set_as_default": true}
		out.CLI = []string{fmt.Sprintf("aws iam create-policy-version --policy-arn %s --policy-document %s --set-as-default",
			shq(st.Target), shq(out.Document))}
	case OpDeletePolicyVersion:
		out.Description = fmt.Sprintf("Delete version %s of %s (a policy keeps at most five)", str(a, "version_id"), st.Target)
		out.Params = map[string]any{"policy_arn": st.Target, "version_id": str(a, "version_id")}
		out.CLI = []string{fmt.Sprintf("aws iam delete-policy-version --policy-arn %s --version-id %s", shq(st.Target), shq(str(a, "version_id")))}
	case OpRotateAccessKey:
		out.Description = fmt.Sprintf("Create a new access key for user %s and store it ONLY in your secret store (%s); never paste it into a ticket or chat",
			p.Name, nonEmpty(str(a, "handover_secret_arn"), "a secret you choose"))
		out.Params = map[string]any{"user_name": p.Name}
		out.CLI = []string{fmt.Sprintf("aws iam create-access-key --user-name %s --query AccessKey --output json | "+
			"aws secretsmanager put-secret-value --secret-id %s --secret-string file:///dev/stdin",
			shq(p.Name), shq(nonEmpty(str(a, "handover_secret_arn"), "<your-handover-secret>")))}
	case OpDeactivateAccessKey:
		out.Description = fmt.Sprintf("After every consumer reads the new key, deactivate the old key %s of user %s", str(a, "key_id"), p.Name)
		out.Params = map[string]any{"user_name": p.Name, "access_key_id": str(a, "key_id"), "status": "Inactive"}
		out.CLI = []string{fmt.Sprintf("aws iam update-access-key --user-name %s --access-key-id %s --status Inactive", shq(p.Name), shq(str(a, "key_id")))}
		if st.DueAt != nil {
			out.NotBefore = st.DueAt.UTC().Format(time.RFC3339)
		}
	case OpRotateSecret:
		out.Params = map[string]any{"secret_id": st.Target}
		region := ARNRegion(st.Target)
		if b["rotation_enabled"] == true {
			out.Description = "Start the rotation configured on " + st.Target
			out.CLI = []string{fmt.Sprintf("aws secretsmanager rotate-secret --region %s --secret-id %s", shq(region), shq(st.Target))}
		} else {
			out.Description = "Rotation is not configured on " + st.Target + ": configure a rotation function (or managed rotation) for it, then start it. AuthSec never reads or sets the value."
			out.CLI = []string{
				fmt.Sprintf("aws secretsmanager rotate-secret --region %s --secret-id %s --rotation-lambda-arn <your-rotation-function-arn> --rotation-rules AutomaticallyAfterDays=30", shq(region), shq(st.Target)),
			}
		}
	}
	return out
}

func nonEmpty(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
