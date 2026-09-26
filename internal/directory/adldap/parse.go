package adldap

import (
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/directory/adguid"
	"github.com/go-ldap/ldap/v3"
)

// Object is one directory entry after the secret attributes have been dropped.
// Basis is always observed: the value came from an authoritative directory read.
type Object struct {
	AccountKind          string       `json:"account_kind"`
	LDAPClass            string       `json:"ldap_class"`
	Basis                string       `json:"basis"`
	ObjectGUID           string       `json:"object_guid"`
	ObjectSID            string       `json:"object_sid,omitempty"`
	DistinguishedName    string       `json:"distinguished_name"`
	SAMAccountName       string       `json:"sam_account_name,omitempty"`
	UserPrincipalName    string       `json:"user_principal_name,omitempty"`
	ObjectClass          []string     `json:"object_class,omitempty"`
	MemberOf             []string     `json:"member_of,omitempty"`
	MemberOfDisplay      []string     `json:"member_of_display,omitempty"`
	Member               []string     `json:"member,omitempty"`
	MemberDisplay        []string     `json:"member_display,omitempty"`
	ServicePrincipalName []string     `json:"service_principal_name,omitempty"`
	UserAccountControl   uint32       `json:"user_account_control"`
	AccountFlags         adguid.Flags `json:"account_flags"`
	AccountExpires       string       `json:"account_expires,omitempty"`
	PwdLastSet           string       `json:"pwd_last_set,omitempty"`
	WhenChanged          string       `json:"when_changed,omitempty"`
	USNChanged           int64        `json:"usn_changed,omitempty"`
	CN                   string       `json:"cn,omitempty"`
	DisplayName          string       `json:"display_name,omitempty"`
	Mail                 string       `json:"mail,omitempty"`
}

// Account kinds. Canonical projection onto iga_identity_accounts is a later
// package; these strings are the vocabulary that projector will consume.
const (
	KindUser                  = "ad_user"
	KindGroup                 = "ad_group"
	KindComputer              = "ad_computer"
	KindManagedServiceAccount = "ad_managed_service_account"
	BasisObserved             = "observed"
)

// ParseEntry copies only allowlisted attributes. A secret attribute present on
// the entry is ignored, so it cannot reach a payload, a log line or a key.
func ParseEntry(e *ldap.Entry, ldapClass string) (Object, bool) {
	if e == nil {
		return Object{}, false
	}
	rawGUID := e.GetRawAttributeValue("objectGUID")
	guid, err := adguid.Format(rawGUID)
	if err != nil || guid == "" {
		return Object{}, false
	}
	classes := e.GetAttributeValues("objectClass")
	kind := accountKind(classes, ldapClass)
	if kind == "" {
		return Object{}, false
	}
	uac, computed := e.GetAttributeValue("userAccountControl"), e.GetAttributeValue("msDS-User-Account-Control-Computed")
	flags, _ := mergeUAC(uac, computed)
	memberOf := nonEmpty(e.GetAttributeValues("memberOf"))
	member := nonEmpty(e.GetAttributeValues("member"))
	obj := Object{
		AccountKind:          kind,
		LDAPClass:            ldapClass,
		Basis:                BasisObserved,
		ObjectGUID:           guid,
		ObjectSID:            sidOf(e),
		DistinguishedName:    firstNonEmpty(e.GetAttributeValue("distinguishedName"), e.DN),
		SAMAccountName:       e.GetAttributeValue("sAMAccountName"),
		UserPrincipalName:    e.GetAttributeValue("userPrincipalName"),
		ObjectClass:          classes,
		MemberOf:             memberOf,
		MemberOfDisplay:      displayNames(memberOf),
		Member:               member,
		MemberDisplay:        displayNames(member),
		ServicePrincipalName: nonEmpty(e.GetAttributeValues("servicePrincipalName")),
		UserAccountControl:   flags.Raw,
		AccountFlags:         flags,
		AccountExpires:       fileTime(e.GetAttributeValue("accountExpires")),
		PwdLastSet:           fileTime(e.GetAttributeValue("pwdLastSet")),
		WhenChanged:          e.GetAttributeValue("whenChanged"),
		USNChanged:           parseInt(e.GetAttributeValue("uSNChanged")),
		CN:                   e.GetAttributeValue("cn"),
		DisplayName:          firstNonEmpty(e.GetAttributeValue("displayName"), e.GetAttributeValue("cn")),
		Mail:                 e.GetAttributeValue("mail"),
	}
	return obj, true
}

func accountKind(classes []string, ldapClass string) string {
	has := func(name string) bool {
		for _, c := range classes {
			if strings.EqualFold(c, name) {
				return true
			}
		}
		return strings.EqualFold(ldapClass, name)
	}
	switch {
	case has(ClassGMSA), has(ClassSMSA):
		return KindManagedServiceAccount
	case has(ClassComputer):
		return KindComputer
	case has(ClassGroup):
		return KindGroup
	case has(ClassUser):
		return KindUser
	default:
		return ""
	}
}

func mergeUAC(raw, computed string) (adguid.Flags, error) {
	base, err := adguid.ParseUAC(raw)
	if err != nil {
		return adguid.Flags{Active: true}, err
	}
	extra, extraErr := adguid.ParseUAC(computed)
	if extraErr != nil || computed == "" {
		return base, err
	}
	// The computed attribute carries LOCKOUT and PASSWORD_EXPIRED, which the
	// stored userAccountControl usually does not. OR the bits; do not let a
	// zero computed value clear ACCOUNTDISABLE.
	merged := adguid.FromUint(base.Raw | extra.Raw)
	return merged, nil
}

func sidOf(e *ldap.Entry) string {
	raw := e.GetRawAttributeValue("objectSid")
	if len(raw) == 0 {
		return ""
	}
	s, err := adguid.ParseSID(raw)
	if err != nil {
		return ""
	}
	return s
}

func displayNames(dns []string) []string {
	out := make([]string, 0, len(dns))
	for _, dn := range dns {
		if cn := adguid.CommonName(dn); cn != "" {
			out = append(out, cn)
		}
	}
	return out
}

func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseInt(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// fileTime converts a Windows FILETIME decimal string to RFC3339. 0 and the
// "never" sentinel are omitted rather than rendered as a date.
func fileTime(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return ""
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n == 0x7FFFFFFFFFFFFFFF {
		return ""
	}
	const ticksPerSecond int64 = 10_000_000
	const unixEpochDiff int64 = 11_644_473_600
	sec := n / ticksPerSecond
	nsec := (n % ticksPerSecond) * 100
	t := time.Unix(sec-unixEpochDiff, nsec).UTC()
	if t.Year() < 1970 || t.Year() > 9999 {
		return ""
	}
	return t.Format(time.RFC3339)
}
