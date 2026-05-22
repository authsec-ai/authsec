package services

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/google/uuid"
)

// OIDCStateClaims is the payload carried out-of-band in the OIDC `state`
// parameter so the callback can verify the workspace + application context
// without trusting a DB lookup or a session cookie. The struct is the v4
// signed-state primitive — Step 7 of the plan.
type OIDCStateClaims struct {
	WorkspaceID   uuid.UUID  `json:"w"`
	ApplicationID *uuid.UUID `json:"a,omitempty"`
	Nonce         string     `json:"n"`
	IssuedAt      int64      `json:"iat"`
}

// signedStateMaxAge bounds how long a signed state remains acceptable. Longer
// than typical OIDC roundtrips but short enough to limit replay windows.
const signedStateMaxAge = 10 * time.Minute

// oidcStateHMACKey returns the HMAC secret used to sign state payloads.
// Resolution order:
//  1. config.AppConfig.OIDCStateHMACKey (set from AUTHSEC_OIDC_STATE_HMAC_KEY)
//  2. AUTHSEC_OIDC_STATE_HMAC_KEY direct env read (for tests that bypass LoadConfig)
//  3. config.AppConfig.JWTSecret (dev fallback so local-k8s works out of the box)
//  4. Hard-coded development key (last resort; warning logged at LoadConfig)
func oidcStateHMACKey() []byte {
	if config.AppConfig != nil && config.AppConfig.OIDCStateHMACKey != "" {
		return []byte(config.AppConfig.OIDCStateHMACKey)
	}
	if v := os.Getenv("AUTHSEC_OIDC_STATE_HMAC_KEY"); v != "" {
		return []byte(v)
	}
	if config.AppConfig != nil && config.AppConfig.JWTSecret != "" {
		return []byte(config.AppConfig.JWTSecret)
	}
	return []byte("authsec-oidc-state-dev-key")
}

// MintSignedState builds an opaque base64-encoded string that carries the
// workspace_id + application_id (signed) plus a fresh random nonce. The
// returned value can be used directly as the OAuth `state` query parameter.
//
// Format:
//
//	base64(payload_json) "." base64(hmac_sha256(payload_json))
//
// Callers should still persist a row in oidc_states keyed by the random
// nonce so server-side replay detection works (the signed state survives a
// DB outage but the nonce check still rejects double-use).
func MintSignedState(workspaceID uuid.UUID, applicationID *uuid.UUID) (state string, nonce string, err error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", fmt.Errorf("oidc state nonce: %w", err)
	}
	nonce = base64.RawURLEncoding.EncodeToString(nonceBytes)

	claims := OIDCStateClaims{
		WorkspaceID:   workspaceID,
		ApplicationID: applicationID,
		Nonce:         nonce,
		IssuedAt:      time.Now().Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", "", fmt.Errorf("oidc state marshal: %w", err)
	}

	mac := hmac.New(sha256.New, oidcStateHMACKey())
	mac.Write(payload)
	sig := mac.Sum(nil)

	state = base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sig)
	return state, nonce, nil
}

// VerifySignedState parses and verifies a state string produced by
// MintSignedState. Returns the embedded claims when the signature checks out
// and the state hasn't aged past signedStateMaxAge.
//
// IMPORTANT: VerifySignedState only proves the state was issued by us. The
// caller still needs to verify the embedded nonce was not already consumed
// (oidc_states.state_token uniqueness) to defeat replay.
func VerifySignedState(state string) (*OIDCStateClaims, error) {
	if state == "" {
		return nil, fmt.Errorf("oidc state is empty")
	}
	parts := strings.SplitN(state, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("oidc state format invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oidc state payload decode: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc state signature decode: %w", err)
	}

	mac := hmac.New(sha256.New, oidcStateHMACKey())
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, fmt.Errorf("oidc state signature mismatch")
	}

	var claims OIDCStateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("oidc state unmarshal: %w", err)
	}

	if claims.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("oidc state missing workspace_id")
	}

	age := time.Since(time.Unix(claims.IssuedAt, 0))
	if age < -1*time.Minute || age > signedStateMaxAge {
		return nil, fmt.Errorf("oidc state expired (age=%s)", age)
	}

	return &claims, nil
}

// LooksLikeSignedState returns true when s has the shape of a MintSignedState
// output (base64.base64). Used by callbacks to decide whether to try the
// signed-state path before falling back to the legacy oidc_states DB lookup.
func LooksLikeSignedState(s string) bool {
	if s == "" {
		return false
	}
	if strings.Count(s, ".") != 1 {
		return false
	}
	parts := strings.SplitN(s, ".", 2)
	if len(parts[0]) < 16 || len(parts[1]) < 16 {
		return false
	}
	return true
}
