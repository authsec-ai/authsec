package sign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestSignVerifyRotationAndTamper(t *testing.T) {
	oldKey := mustKey(t, "old")
	newKey := mustKey(t, "new")
	wrong := mustKey(t, "wrong")
	files := []File{{Name: "policy.rego", Body: []byte("package authsec.runtime\n")}, {Name: "data.json", Body: []byte(`{"rules":[]}`)}}

	single, err := SignBundle(files, []Key{newKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(single.Bytes, pubs(newKey)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(single.Bytes, pubs(wrong)); err == nil {
		t.Fatal("wrong key verified the bundle")
	}
	tampered := bytes.Clone(single.Bytes)
	tampered[len(tampered)/2] ^= 0x5a
	if err := VerifyBundle(tampered, pubs(newKey)); err == nil {
		t.Fatal("tampered bundle verified")
	}

	// The bundle carries one JWT (OPA rejects more). A bundle signed while the
	// previous key was current still verifies under that key.
	previous, err := SignBundle(files, []Key{oldKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(previous.Bytes, pubs(oldKey)); err != nil {
		t.Fatalf("previous key rejected its own bundle: %v", err)
	}
	if err := VerifyBundle(previous.Bytes, pubs(newKey)); err == nil {
		t.Fatal("current key verified a bundle signed only by the previous key")
	}
	if err := VerifyBundle(single.Bytes, pubs(newKey)); err != nil {
		t.Fatalf("current key rejected its own bundle: %v", err)
	}

	m := Manifest{
		WorkspaceID: "ws", PublicationID: "pub", DeliveryRevision: 2,
		PolicyRevisionHash: "abc", GraphRevision: 184, TargetDigest: "def",
		CompilerBuild: "opa test", OPABundleSHA256: single.SHA256, ControlsSHA256: SHA256Hex([]byte("{}")),
		RevocationEpoch: 1, KeyID: newKey.ID, CreatedAt: time.Unix(0, 0).UTC().Format(time.RFC3339),
		Targets: []TargetEffect{{WorkloadID: "b", Effect: "deny", Source: "quarantine"}, {WorkloadID: "a", Effect: "allow", Source: "runtime_allow"}},
	}
	again, err := CanonicalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	first, err := CanonicalManifest(m)
	if err != nil || !bytes.Equal(first, again) {
		t.Fatal("manifest canonical bytes moved")
	}
	if !bytes.Contains(first, []byte(`"workload_id":"a"`)) || bytes.Index(first, []byte(`"workload_id":"a"`)) > bytes.Index(first, []byte(`"workload_id":"b"`)) {
		t.Fatalf("targets were not sorted: %s", first)
	}
	signed, hash, err := SignManifest(m, []Key{newKey, oldKey})
	if err != nil {
		t.Fatal(err)
	}
	if hash == "" {
		t.Fatal("missing manifest hash")
	}
	if _, err := VerifyManifest(signed, pubs(oldKey)); err != nil {
		t.Fatalf("old key rejected the manifest: %v", err)
	}
	got, err := VerifyManifest(signed, pubs(newKey))
	if err != nil {
		t.Fatal(err)
	}
	if got.RevocationEpoch != 1 || got.DeliveryRevision != 2 || got.Targets[0].WorkloadID != "a" {
		t.Fatalf("manifest = %+v", got)
	}
	if _, err := VerifyManifest(signed, pubs(wrong)); err == nil {
		t.Fatal("wrong key verified the manifest")
	}
}

func TestParsePEMRoundTrip(t *testing.T) {
	key := mustKey(t, "dev")
	der, err := x509.MarshalPKCS8PrivateKey(key.Private)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	parsed, err := ParseECPrivateKey(pemBytes, "dev")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := parsed.ToPublic()
	if err != nil || pub.Alg != "ES256" || pub.PEM == "" || pub.KeyID != "dev" {
		t.Fatalf("public = %+v %v", pub, err)
	}
}

func mustKey(t *testing.T, id string) Key {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Key{ID: id, Private: k, Public: &k.PublicKey}
}

func pubs(keys ...Key) map[string]*ecdsa.PublicKey {
	out := map[string]*ecdsa.PublicKey{}
	for _, k := range keys {
		out[k.ID] = k.Public
	}
	return out
}
