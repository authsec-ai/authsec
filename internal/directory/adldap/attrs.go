// Package adldap reads an Active Directory scope without ever asking for a
// secret attribute. Paging, completeness and the attribute allowlist live here
// so the inventory service and the legacy importer share one TLS and search path.
package adldap

import "strings"

// DeniedAttributes are never requested and are stripped if a server sends
// them anyway. msDS-ManagedPassword is the gMSA secret; the others are
// password hashes or reversible credentials.
var DeniedAttributes = []string{
	"msDS-ManagedPassword",
	"msDS-ManagedPasswordPreviousId",
	"unicodePwd",
	"userPassword",
	"supplementalCredentials",
	"ntPwdHistory",
	"lmPwdHistory",
	"unixUserPassword",
	"ms-Mcs-AdmPwd",
	"dBCSPwd",
}

// InventoryAttributes is the only attribute set an inventory search may send.
// uSNChanged is included so a cursor can advance; mail is included so an
// account with no address is still recorded as such. Nothing in this list is
// a credential.
func InventoryAttributes() []string {
	return []string{
		"objectGUID",
		"objectSid",
		"distinguishedName",
		"sAMAccountName",
		"userPrincipalName",
		"objectClass",
		"memberOf",
		"member",
		"servicePrincipalName",
		"userAccountControl",
		"msDS-User-Account-Control-Computed",
		"accountExpires",
		"pwdLastSet",
		"whenChanged",
		"whenCreated",
		"uSNChanged",
		"cn",
		"displayName",
		"mail",
		// Posture (D03). The security descriptor is parsed down to SIDs and
		// is not stored. msDS-GroupMSAMembership is not requested: gMSA and
		// sMSA are recorded from object class, not from the password ACL.
		"adminCount",
		"primaryGroupID",
		"msDS-AllowedToDelegateTo",
		"msDS-AllowedToActOnBehalfOfOtherIdentity",
	}
}

// Allowed reports whether name is on the inventory allowlist.
func Allowed(name string) bool {
	for _, a := range InventoryAttributes() {
		if strings.EqualFold(a, name) {
			return true
		}
	}
	return false
}

// Denied reports whether name is a secret attribute.
func Denied(name string) bool {
	for _, a := range DeniedAttributes {
		if strings.EqualFold(a, name) {
			return true
		}
	}
	return false
}
