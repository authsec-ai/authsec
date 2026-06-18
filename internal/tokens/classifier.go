// Package tokens implements AuthSec's native token family (M2M / XAA / CIBA):
// classification, a Vault-backed RS256 key manager, the narrow minting seam
// (NativeIssuer), and a GrantHandler interface that lets the existing Hydra
// orchestration coexist without being wrapped as a generic sealer.
//
// Prime directive (Phase 0): recognize, introspect, revoke and publish keys for
// two token families while leaving every Hydra authorization_code/refresh_token
// behavior byte-for-byte intact. A token with a native `kid` commits to the
// native path (validate or reject) and NEVER falls back to Hydra.
package tokens

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Family identifies which sealing/validation path a token belongs to.
type Family int

const (
	// FamilyHydra covers interactive OAuth tokens (authorization_code,
	// refresh_token) and anything opaque/unparseable/non-native — the Hydra
	// introspection path.
	FamilyHydra Family = iota
	// FamilyNative covers tokens minted by the NativeSealer (M2M / XAA / CIBA).
	FamilyNative
)

// NativeKIDPrefix is the opaque prefix every native key id carries. It contains
// no workspace identifier, so the public JWKS cannot leak ownership (§17).
const NativeKIDPrefix = "native:"

// Classification is the result of inspecting a token's JWT header.
type Classification struct {
	Family Family
	Kid    string // the header kid, if the token parsed as a JWT
}

// Classify decides the validation path for a bearer token WITHOUT calling Hydra
// and without verifying the signature. It parses only the JWS header:
//
//   - header kid ∈ nativeKIDs            → FamilyNative (commit; bad signature
//     later is rejected, never retried on Hydra)
//   - any other kid / opaque / non-JWT   → FamilyHydra
//
// nativeKIDs is the live published native key-id set (see NativeKeyManager).
func Classify(token string, nativeKIDs map[string]struct{}) Classification {
	kid, ok := parseHeaderKid(token)
	if !ok {
		return Classification{Family: FamilyHydra}
	}
	if _, isNative := nativeKIDs[kid]; isNative {
		return Classification{Family: FamilyNative, Kid: kid}
	}
	return Classification{Family: FamilyHydra, Kid: kid}
}

// parseHeaderKid extracts the `kid` from a compact-JWS header. Returns ok=false
// for opaque tokens, malformed JWTs, or headers without a kid.
func parseHeaderKid(token string) (kid string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var hdr struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return "", false
	}
	if hdr.Kid == "" {
		return "", false
	}
	return hdr.Kid, true
}
