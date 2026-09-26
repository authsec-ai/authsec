package collectorcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ObjectsDigest is the lowercase hex SHA-256 of the objects array, encoded
// with encoding/json and HTML escaping disabled. Snapshot chunks must declare
// this digest. The server recomputes it and does not trust the collector's
// complete flag in its place.
func ObjectsDigest(objects []Object) (string, error) {
	if objects == nil {
		objects = []Object{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(objects); err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes.TrimRight(buf.Bytes(), "\n"))
	return hex.EncodeToString(sum[:]), nil
}

// PayloadHash is the lowercase hex SHA-256 of the exact decompressed body.
func PayloadHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
