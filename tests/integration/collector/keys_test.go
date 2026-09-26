package collector

import (
	"crypto/ed25519"
	"encoding/base64"
)

func generateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func sign(priv ed25519.PrivateKey, msg []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
}
