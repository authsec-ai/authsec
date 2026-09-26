// Package adresolve turns an NSS/SSSD/winbind mapping into a directory
// identity. It never matches a display name or a username.
//
// A mapping is authoritative only when native.mapping_source is sssd or
// winbind. The directory object is then selected by SID, or by objectGUID
// plus a directory instance. Both identifiers are canonicalized with the
// adguid helpers: SID text and binary SIDs become S-1-…, and objectGUID
// wire bytes use AD's mixed-endian layout.
package adresolve

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/authsec-ai/authsec/internal/directory/adguid"
	"github.com/google/uuid"
)

// RuleID is the derivation rule for a backed_by_directory edge. The mapping
// source is appended, so the stored rule names sssd or winbind.
const RuleID = "nss.backed_by_directory.v1"

const (
	SourceSSSD    = "sssd"
	SourceWinbind = "winbind"
)

// Hint is one authoritative mapping carried on a Linux account or group.
// Unreadable means the collector claimed a mapping that could not be parsed.
// That is not the same as an absent mapping.
type Hint struct {
	SID            string
	GUID           string
	Domain         string
	MappingSource  string
	ObservationIDs []uuid.UUID
	Unreadable     bool
	Reason         string
}

// Rule is the derivation_rule stored on the relationship.
func Rule(source string) string {
	return RuleID + "/" + source
}

// Parse reads native.directory_sid, native.directory_guid, native.directory_domain
// and native.mapping_source. The native map is the collector's native object,
// so the keys are the attribute names without the native. prefix.
//
// ok is false when there is no authoritative mapping. A present sssd or
// winbind source with an identifier that does not parse returns a hint with
// Unreadable set. Name fields are not read.
func Parse(native map[string]any, observations []uuid.UUID) (Hint, bool) {
	sidText := field(native, "directory_sid")
	guidText := field(native, "directory_guid")
	domain := field(native, "directory_domain")
	source := strings.ToLower(field(native, "mapping_source"))
	if sidText == "" && guidText == "" && domain == "" && source == "" {
		return Hint{}, false
	}
	if source != SourceSSSD && source != SourceWinbind {
		return Hint{}, false
	}
	h := Hint{Domain: domain, MappingSource: source, ObservationIDs: append([]uuid.UUID(nil), observations...)}
	if sidText != "" {
		sid, err := canonicalSID(sidText)
		if err != nil || sid == "" {
			h.Unreadable = true
			h.Reason = "bad_sid"
			return h, true
		}
		h.SID = sid
	}
	if guidText != "" {
		guid, err := canonicalGUID(guidText)
		if err != nil || guid == "" {
			h.Unreadable = true
			h.Reason = "bad_guid"
			return h, true
		}
		h.GUID = guid
	}
	if h.SID == "" && h.GUID == "" {
		h.Unreadable = true
		h.Reason = "no_identifier"
	}
	return h, true
}

func field(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	switch t := m[k].(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return ""
	}
}

func canonicalSID(v string) (string, error) {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(strings.ToLower(v), "s-") {
		v = "S-" + v[2:]
		raw, err := adguid.SIDBytes(v)
		if err != nil {
			return "", err
		}
		return adguid.ParseSID(raw)
	}
	raw, err := decodeFixed(v, 0)
	if err != nil {
		return "", err
	}
	return adguid.ParseSID(raw)
}

// canonicalGUID accepts hyphenated canonical text, or AD wire bytes as hex
// or base64. Wire bytes go through adguid.Format, which swaps the first
// three fields. A 32-digit hex string is wire order, not an unhyphenated UUID.
func canonicalGUID(v string) (string, error) {
	v = strings.TrimSpace(v)
	if strings.Contains(v, "-") {
		u, err := uuid.Parse(v)
		if err != nil {
			return "", err
		}
		return strings.ToLower(u.String()), nil
	}
	raw, err := decodeFixed(v, 16)
	if err != nil {
		return "", err
	}
	if len(raw) != 16 {
		return "", errGUID
	}
	return adguid.Format(raw)
}

var errGUID = guidError{}

type guidError struct{}

func (guidError) Error() string { return "objectGUID" }

func decodeFixed(v string, want int) ([]byte, error) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "0x"), "0X")
	if b, err := hex.DecodeString(v); err == nil && (want == 0 || len(b) == want) && len(b) > 0 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil && (want == 0 || len(b) == want) && len(b) > 0 {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(v); err == nil && (want == 0 || len(b) == want) && len(b) > 0 {
		return b, nil
	}
	return nil, errGUID
}
