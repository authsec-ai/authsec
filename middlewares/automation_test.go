package middlewares

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestClaimsAreAutomation(t *testing.T) {
	user, member := uuid.NewString(), uuid.NewString()
	person := func(extra jwt.MapClaims) jwt.MapClaims {
		c := jwt.MapClaims{"user_id": user, "workspace_membership_id": member, "client_id": user, "token_type": "default"}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	cases := map[string]struct {
		claims jwt.MapClaims
		want   bool
	}{
		"admin session":                      {person(jwt.MapClaims{"typ": "admin"}), false},
		"legacy person session":              {person(nil), false},
		"console client id is not a machine": {person(jwt.MapClaims{"client_id": uuid.NewString()}), false},
		"nil claims":                         {nil, true},
		"sdk class":                          {person(jwt.MapClaims{"typ": "sdk"}), true},
		"legacy sdk token":                   {person(jwt.MapClaims{"token_type": "sdk-agent"}), true},
		"client credentials":                 {person(jwt.MapClaims{"grant_type": "client_credentials"}), true},
		"service principal":                  {person(jwt.MapClaims{"principal_type": "service_account"}), true},
		"ai triage agent":                    {person(jwt.MapClaims{"actor_kind": "agent"}), true},
		"service account id":                 {person(jwt.MapClaims{"service_account_id": "sa-1"}), true},
		"no person":                          {jwt.MapClaims{"workspace_membership_id": member, "client_id": "svc"}, true},
		"no membership":                      {jwt.MapClaims{"user_id": user, "client_id": "svc"}, true},
		"sub instead of user_id":             {jwt.MapClaims{"sub": user, "workspace_membership_id": member}, false},
	}
	for name, c := range cases {
		if got := ClaimsAreAutomation(c.claims); got != c.want {
			t.Errorf("%s: automation = %v, want %v", name, got, c.want)
		}
	}
}
