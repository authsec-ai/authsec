package middlewares

import (
	"strings"

	"github.com/authsec-ai/authsec/internal/sessiontoken"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Automation identities (SecOps W5, SPEC-secops-backend-upgrade.md P3): a
// SOAR playbook, an AI triage agent or any other service principal calling
// the governance APIs. Such a caller may perform tier-0 and tier-1 actions
// only; it never approves, decides or reviews a second-person request
// (services.CheckApprover) and never requests a tier-3 change.
//
// IsAutomationIdentity reports whether the session AuthMiddleware verified
// for this request is NOT a person signed in to this workspace. It fails
// closed: a request without verified claims is automation. A session is
// automation when any of these holds:
//
//   - its class is sdk (typ "sdk"), or it is a legacy token minted for the
//     SDK (token_type "sdk-agent"): what an agent or a service holds;
//   - it names a machine principal: principal_type / actor_kind of
//     service, service_account, automation, agent or sdk; a
//     service_account_id; grant_type or token_type client_credentials or
//     service_account;
//   - it names no person: no user id (user_id or sub) that is a UUID;
//   - it carries no workspace membership (workspace_membership_id): every
//     console session of a person is bound to their membership.
//
// DECISION (W5): IsInteractiveUserSession (F3) also refuses a legacy
// (typ-less) token, because such a token may have been signed with the SDK
// secret. Here a legacy token that names a person and their membership and
// carries no SDK or machine marker counts as that person: legacy tokens
// drain by the legacy deadline (internal/sessiontoken), and refusing them
// would lock every console member of the previous release out of approving
// until they sign in again. Agent action decisions keep F3's stricter rule.
func IsAutomationIdentity(c *gin.Context) bool {
	raw, ok := c.Get("claims")
	if !ok {
		return true
	}
	claims, ok := raw.(jwt.MapClaims)
	if !ok {
		return true
	}
	return ClaimsAreAutomation(claims)
}

// ClaimsAreAutomation is IsAutomationIdentity's rule over verified claims.
func ClaimsAreAutomation(claims jwt.MapClaims) bool {
	if claims == nil {
		return true
	}
	if sessiontoken.ClassOf(claims) == sessiontoken.SDK {
		return true
	}
	str := func(k string) string {
		v, _ := claims[k].(string)
		return strings.ToLower(strings.TrimSpace(v))
	}
	switch str("token_type") {
	case "sdk-agent", "sdk", "client_credentials", "service_account":
		return true
	}
	if str("grant_type") == "client_credentials" {
		return true
	}
	for _, k := range []string{"principal_type", "actor_kind"} {
		switch str(k) {
		case "service", "service_account", "automation", "agent", "sdk":
			return true
		}
	}
	if str("service_account_id") != "" {
		return true
	}
	user := str("user_id")
	if user == "" {
		user = str("sub")
	}
	if _, err := uuid.Parse(user); err != nil {
		return true
	}
	if _, err := uuid.Parse(str("workspace_membership_id")); err != nil {
		return true
	}
	return false
}
