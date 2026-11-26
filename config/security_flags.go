package config

import (
	"os"
	"strings"
)

// EnvFlag reports whether the boolean environment variable key is set to a
// true value (true/1/yes/on, case-insensitive). Unset or anything else is
// false. It is read on every call and does not log, so request paths can use
// it for operator escape hatches that default to off.
func EnvFlag(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// CIBAAllowUnauthenticatedClients keeps the workspace CIBA endpoints
// (/authsec/uflow/auth/workspace/ciba/initiate and /token) accepting a bare
// client_id without client authentication, for SDK releases that cannot send
// credentials yet. Off by default (AS-044). The request is still bound to the
// client and resource, scoped to the client's workspace and RBAC-intersected.
func CIBAAllowUnauthenticatedClients() bool {
	return EnvFlag("CIBA_ALLOW_UNAUTHENTICATED_CLIENTS")
}
