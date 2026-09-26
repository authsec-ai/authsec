package adresolve

import (
	"errors"
	"strings"

	"github.com/google/uuid"
)

// Instance is one ad_directory_instances row in the caller's workspace.
type Instance struct {
	ID        uuid.UUID
	ForestID  string
	DomainSID string
	DomainDN  string
	DNSHost   string
}

var (
	ErrUnknownInstance = errors.New("unknown_directory_instance")
	ErrAmbiguous       = errors.New("ambiguous_directory_instance")
)

// DomainSID drops the last RID. S-1-5-21-1-2-3-1101 is S-1-5-21-1-2-3.
func DomainSID(accountSID string) string {
	accountSID = strings.TrimSpace(accountSID)
	i := strings.LastIndex(accountSID, "-")
	if i <= 0 {
		return ""
	}
	return accountSID[:i]
}

// DomainMatches reports whether directory_domain names this instance.
// The comparison is the stored domain DN, DNS host name, or forest id.
// A DNS name is not rewritten into a DN.
func DomainMatches(inst Instance, domain string) bool {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(inst.DomainDN), domain) ||
		strings.EqualFold(strings.TrimSpace(inst.DNSHost), domain) ||
		strings.EqualFold(strings.TrimSpace(inst.ForestID), domain)
}

// SelectInstance picks the directory the mapping names.
//
// A SID selects by its domain SID. An objectGUID selects only together with
// directory_domain or a SID. Neither display name nor samAccountName is an
// input. Zero matches are an unknown instance. More than one is ambiguous.
func SelectInstance(instances []Instance, hint Hint) (Instance, error) {
	if hint.Unreadable || (hint.SID == "" && hint.GUID == "") {
		return Instance{}, ErrUnknownInstance
	}
	var domainSID string
	if hint.SID != "" {
		domainSID = DomainSID(hint.SID)
		if domainSID == "" {
			return Instance{}, ErrUnknownInstance
		}
	}
	if hint.Domain == "" && domainSID == "" {
		return Instance{}, ErrUnknownInstance
	}
	var matched []Instance
	for _, inst := range instances {
		if hint.Domain != "" && !DomainMatches(inst, hint.Domain) {
			continue
		}
		if domainSID != "" && !strings.EqualFold(strings.TrimSpace(inst.DomainSID), domainSID) {
			continue
		}
		matched = append(matched, inst)
	}
	switch len(matched) {
	case 0:
		return Instance{}, ErrUnknownInstance
	case 1:
		return matched[0], nil
	default:
		return Instance{}, ErrAmbiguous
	}
}
