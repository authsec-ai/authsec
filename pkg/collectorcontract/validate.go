package collectorcontract

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const maxFieldErrors = 20

var (
	refPattern = regexp.MustCompile(`^o_[A-Za-z0-9_]+$`)
	hexDigest  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	outcomes   = map[string]bool{"attempted": true, "success": true, "denied": true, "unknown": true}
	secretKeys = map[string]bool{
		"password": true, "passwd": true, "secret": true, "secret_value": true,
		"token": true, "api_key": true, "apikey": true, "private_key": true,
		"access_key": true, "client_secret": true, "connection_string": true,
		"shadow": true, "credential": true, "credentials": true, "kubeconfig": true,
		"authorization": true, "bearer": true,
	}
	canonicalKeys = map[string]bool{
		"canonical_id": true, "iga_id": true, "graph_id": true,
	}
	topLevelKeys = map[string]bool{
		"schema_version": true, "batch_id": true, "collector_epoch": true, "sequence": true,
		"sent_at": true, "capabilities": true, "capability_digest": true, "snapshot": true,
		"objects": true, "observations": true, "applied": true, "health": true,
		"workspace_id": true, "host_id": true, "estate_id": true,
	}
)

// SupportedSchemaVersions is the 426 body.
func SupportedSchemaVersions() []string { return []string{SchemaVersion} }

// Validate checks one decompressed agent-sync body.
// Secret-like field names and client-supplied canonical ids reject the whole
// batch. Nothing in here writes, and the error values do not echo field values.
func Validate(raw []byte) (*SyncRequest, *ContractError) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, invalid([]FieldError{{Path: "$", Message: "body is required"}})
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, invalid([]FieldError{{Path: "$", Message: "body is not valid JSON"}})
	}
	if fields := walkBanned(generic, "$"); len(fields) > 0 {
		return nil, invalid(fields)
	}
	obj, ok := generic.(map[string]any)
	if !ok {
		return nil, invalid([]FieldError{{Path: "$", Message: "body must be an object"}})
	}
	ver, _ := obj["schema_version"].(string)
	if ver != SchemaVersion {
		return nil, &ContractError{Kind: "upgrade", Supported: SupportedSchemaVersions()}
	}
	var fields []FieldError
	for k := range obj {
		if !topLevelKeys[k] {
			fields = append(fields, FieldError{Path: k, Message: "unknown field"})
		}
	}
	for _, req := range []string{"batch_id", "collector_epoch", "sequence", "sent_at", "objects", "observations", "applied", "health"} {
		if _, ok := obj[req]; !ok {
			fields = append(fields, FieldError{Path: req, Message: "required"})
		}
	}
	var out SyncRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	// Identity fields are known to the struct, so DisallowUnknownFields accepts them.
	if err := dec.Decode(&out); err != nil && len(fields) == 0 {
		fields = append(fields, FieldError{Path: "$", Message: "body does not match the sync schema"})
	}
	if out.Sequence <= 0 {
		fields = append(fields, FieldError{Path: "sequence", Message: "must be a positive integer"})
	}
	if _, err := uuid.Parse(out.BatchID); err != nil {
		fields = append(fields, FieldError{Path: "batch_id", Message: "must be a UUID"})
	}
	if _, err := uuid.Parse(out.CollectorEpoch); err != nil {
		fields = append(fields, FieldError{Path: "collector_epoch", Message: "must be a UUID"})
	}
	if _, err := time.Parse(time.RFC3339, out.SentAt); err != nil {
		fields = append(fields, FieldError{Path: "sent_at", Message: "must be RFC3339"})
	}
	if out.CapabilityDigest != "" && !hexDigest.MatchString(out.CapabilityDigest) {
		fields = append(fields, FieldError{Path: "capability_digest", Message: "must be 64 lowercase hex characters"})
	}
	seenRef := map[string]bool{}
	if out.Objects == nil {
		fields = append(fields, FieldError{Path: "objects", Message: "required"})
	}
	for i, o := range out.Objects {
		p := pathIndex("objects", i)
		if !refPattern.MatchString(o.Ref) {
			fields = append(fields, FieldError{Path: p + ".ref", Message: "must match o_<token>"})
		}
		if seenRef[o.Ref] {
			fields = append(fields, FieldError{Path: p + ".ref", Message: "duplicate ref"})
		}
		seenRef[o.Ref] = true
		if IsPrivilegedKind(o.Kind) {
			fields = append(fields, FieldError{Path: p + ".kind", Message: "privileged kind"})
		} else if !KnownObjectKind(o.Kind) {
			fields = append(fields, FieldError{Path: p + ".kind", Message: "unknown object kind"})
		}
		if o.Native == nil {
			fields = append(fields, FieldError{Path: p + ".native", Message: "required"})
		}
	}
	if out.Observations == nil {
		fields = append(fields, FieldError{Path: "observations", Message: "required"})
	}
	seenEvent := map[string]bool{}
	for i, ob := range out.Observations {
		p := pathIndex("observations", i)
		if strings.TrimSpace(ob.EventID) == "" {
			fields = append(fields, FieldError{Path: p + ".event_id", Message: "required"})
		}
		if seenEvent[ob.EventID] {
			fields = append(fields, FieldError{Path: p + ".event_id", Message: "duplicate event_id"})
		}
		seenEvent[ob.EventID] = true
		if IsPrivilegedKind(ob.Kind) {
			fields = append(fields, FieldError{Path: p + ".kind", Message: "privileged kind"})
		} else if !KnownObservationKind(ob.Kind) {
			fields = append(fields, FieldError{Path: p + ".kind", Message: "unknown observation kind"})
		}
		if !outcomes[ob.Outcome] {
			fields = append(fields, FieldError{Path: p + ".outcome", Message: "must be attempted, success, denied, or unknown"})
		}
		if _, err := time.Parse(time.RFC3339, ob.ObservedAt); err != nil {
			fields = append(fields, FieldError{Path: p + ".observed_at", Message: "must be RFC3339"})
		}
		for _, ref := range []struct{ name, val string }{
			{"subject_ref", ob.SubjectRef}, {"identity_ref", ob.IdentityRef}, {"resource_ref", ob.ResourceRef},
		} {
			if ref.val == "" {
				continue
			}
			if !seenRef[ref.val] {
				fields = append(fields, FieldError{Path: p + "." + ref.name, Message: "unknown ref"})
			}
		}
	}
	if out.Applied == nil {
		fields = append(fields, FieldError{Path: "applied", Message: "required"})
	}
	for i, ap := range out.Applied {
		p := pathIndex("applied", i)
		if _, err := uuid.Parse(ap.WorkloadID); err != nil {
			fields = append(fields, FieldError{Path: p + ".workload_id", Message: "must be a UUID"})
		}
		if strings.TrimSpace(ap.RuntimeGeneration) == "" {
			fields = append(fields, FieldError{Path: p + ".runtime_generation", Message: "required"})
		}
		if strings.TrimSpace(ap.State) == "" {
			fields = append(fields, FieldError{Path: p + ".state", Message: "required"})
		}
		if _, err := time.Parse(time.RFC3339, ap.ObservedAt); err != nil {
			fields = append(fields, FieldError{Path: p + ".observed_at", Message: "must be RFC3339"})
		}
		if ap.Controls == nil {
			fields = append(fields, FieldError{Path: p + ".controls", Message: "required"})
		}
		for j, ctl := range ap.Controls {
			cp := pathIndex(p+".controls", j)
			if ctl.Kind == "" || ctl.State == "" || ctl.Test == "" {
				fields = append(fields, FieldError{Path: cp, Message: "kind, state, and test are required"})
			}
			// The published §22.3 fixture uses a placeholder sha256. That file is
			// checked by the JSON Schema, not by Validate. A sync body must be hex.
			if !hexDigest.MatchString(ctl.ArtifactSHA256) {
				fields = append(fields, FieldError{Path: cp + ".artifact_sha256", Message: "must be 64 lowercase hex characters"})
			}
		}
	}
	if out.Snapshot != nil {
		s := out.Snapshot
		if _, err := uuid.Parse(s.SnapshotID); err != nil {
			fields = append(fields, FieldError{Path: "snapshot.snapshot_id", Message: "must be a UUID"})
		}
		if _, err := uuid.Parse(s.CollectorEpoch); err != nil {
			fields = append(fields, FieldError{Path: "snapshot.collector_epoch", Message: "must be a UUID"})
		}
		if s.CollectorEpoch != "" && s.CollectorEpoch != out.CollectorEpoch {
			fields = append(fields, FieldError{Path: "snapshot.collector_epoch", Message: "must match collector_epoch"})
		}
		if strings.TrimSpace(s.ScopeKey) == "" || strings.TrimSpace(s.ObjectClass) == "" {
			fields = append(fields, FieldError{Path: "snapshot", Message: "scope_key and object_class are required"})
		}
		if s.ChunkNo < 1 || s.TerminalChunkCount < 1 || s.ChunkNo > s.TerminalChunkCount {
			fields = append(fields, FieldError{Path: "snapshot.chunk_no", Message: "chunk must be inside 1..terminal_chunk_count"})
		}
		if !hexDigest.MatchString(s.Digest) {
			fields = append(fields, FieldError{Path: "snapshot.digest", Message: "must be 64 lowercase hex characters"})
		}
	}
	for _, f := range fields {
		if f.Message == "privileged kind" {
			return nil, &ContractError{Kind: "forbidden", Fields: []FieldError{f}}
		}
	}
	if len(fields) > 0 {
		return nil, invalid(fields)
	}
	return &out, nil
}

func invalid(fields []FieldError) *ContractError {
	if len(fields) > maxFieldErrors {
		fields = fields[:maxFieldErrors]
	}
	return &ContractError{Kind: "invalid", Fields: fields}
}

func walkBanned(v any, path string) []FieldError {
	var out []FieldError
	switch n := v.(type) {
	case map[string]any:
		for k, child := range n {
			lk := strings.ToLower(k)
			p := path + "." + k
			if secretKeys[lk] || canonicalKeys[lk] {
				msg := "canonical identifiers are assigned by the server"
				if secretKeys[lk] {
					msg = "secret-like field names are not accepted"
				}
				out = append(out, FieldError{Path: p, Message: msg})
				if len(out) >= maxFieldErrors {
					return out
				}
			}
			out = append(out, walkBanned(child, p)...)
			if len(out) >= maxFieldErrors {
				return out[:maxFieldErrors]
			}
		}
	case []any:
		for i, child := range n {
			out = append(out, walkBanned(child, pathIndex(path, i))...)
			if len(out) >= maxFieldErrors {
				return out[:maxFieldErrors]
			}
		}
	}
	return out
}

func pathIndex(prefix string, i int) string {
	return prefix + "[" + itoa(i) + "]"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
