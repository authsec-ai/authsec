// Package sign builds an ES256-signed OPA bundle and a detached manifest.
//
// The bundle is a gzip-compressed tar of policy.rego, data.json and
// .signatures.json. .signatures.json is OPA's format: {"signatures":["<compact
// JWS>"]}. The JWS payload is {"files":[{"name","hash","algorithm":"SHA-256"}],
// "keyid","scope":"write"}. JSON members are hashed the way OPA hashes them
// (canonical object key order, not the raw bytes). Rego is hashed as raw
// bytes. Stock OPA's verifier accepts exactly one JWT, so the bundle is signed
// by the current key only. Rotation overlap is the detached manifest, which
// carries one JWS per key. The signature is raw R||S, not ASN.1.
//
// Targets on the manifest are a workload-level override hint from quarantine,
// emergency, and guardrail facts. They are not the per-action decision.
//
// Only the standard library is used. Private keys are never logged.
package sign

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"path"
	"sort"
	"strings"
	"time"
)

const algo = "ES256"

// Key is one signing key. Private is nil for a verify-only key.
type Key struct {
	ID      string
	Private *ecdsa.PrivateKey
	Public  *ecdsa.PublicKey
}

// File is one bundle member. .signatures.json is added by SignBundle.
type File struct {
	Name string
	Body []byte
}

// Bundle is the signed gzip tar and the hashes agents pin.
type Bundle struct {
	Bytes          []byte
	SHA256         string
	SignaturesJSON []byte
}

// Manifest is the detached claim over both artifact hashes.
type Manifest struct {
	WorkspaceID        string `json:"workspace_id"`
	PublicationID      string `json:"publication_id"`
	TargetScope        string `json:"target_scope,omitempty"`
	DeliveryRevision   int64  `json:"delivery_revision"`
	PolicyRevisionHash string `json:"policy_revision_hash"`
	GraphRevision      int64  `json:"graph_revision"`
	TargetDigest       string `json:"target_digest"`
	CapabilityDigest   string `json:"capability_digest,omitempty"`
	CompilerBuild      string `json:"compiler_build"`
	OPABundleSHA256    string `json:"opa_bundle_sha256"`
	ControlsSHA256     string `json:"controls_sha256"`
	RevocationEpoch    int64  `json:"revocation_epoch"`
	KeyID              string `json:"key_id"`
	CreatedAt          string `json:"created_at"`
	// Mode is observe, enforce, or revoked. Revoked tells the agent to drop
	// the policy. The bundle beside a revoked manifest is a deny-all tombstone,
	// not the previous allow set.
	Mode    string         `json:"mode"`
	Revoked bool           `json:"revoked,omitempty"`
	Targets []TargetEffect `json:"targets,omitempty"`
}

// TargetEffect is a workload-level override hint baked in at publish time.
// It is computed only from quarantine, emergency, and guardrail facts. It is
// not the per-action decision and it is not rewritten on a later sync. A
// quarantine that starts after publish is a separate unsigned marker on desired.
type TargetEffect struct {
	WorkloadID string `json:"workload_id"`
	Effect     string `json:"effect"`
	Source     string `json:"source"`
}

// PublicKey is the enrollment pin. It has no private material.
type PublicKey struct {
	KeyID string `json:"key_id"`
	Alg   string `json:"alg"`
	PEM   string `json:"public_key_pem"`
}

// ParseECPrivateKey parses a PKCS#8 or SEC 1 PEM block.
func ParseECPrivateKey(pemBytes []byte, id string) (Key, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return Key{}, errors.New("policy signing key PEM was not found")
	}
	var key *ecdsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return Key{}, errors.New("policy signing key is not ECDSA")
		}
		key = ec
	} else {
		ec, err2 := x509.ParseECPrivateKey(block.Bytes)
		if err2 != nil {
			return Key{}, errors.New("policy signing key could not be parsed")
		}
		key = ec
	}
	if key.Curve != elliptic.P256() {
		return Key{}, errors.New("policy signing key must be P-256")
	}
	return Key{ID: id, Private: key, Public: &key.PublicKey}, nil
}

// PublicPEM is the PKIX encoding agents pin.
func PublicPEM(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// ToPublic drops the private key.
func (k Key) ToPublic() (PublicKey, error) {
	pub := k.Public
	if pub == nil && k.Private != nil {
		pub = &k.Private.PublicKey
	}
	if pub == nil {
		return PublicKey{}, errors.New("signing key has no public half")
	}
	pemText, err := PublicPEM(pub)
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey{KeyID: k.ID, Alg: algo, PEM: pemText}, nil
}

// SignBundle writes a deterministic gzip tar. keys[0] is the only key in
// .signatures.json. OPA's default verifier rejects more than one JWT, so
// overlap keys are not added here. Callers that still hold a previous key
// verify bundles that were signed when that key was current.
func SignBundle(files []File, keys []Key) (Bundle, error) {
	if len(keys) == 0 || keys[0].Private == nil || keys[0].ID == "" {
		return Bundle{}, errors.New("policy signing key is not configured")
	}
	sorted := append([]File(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	seen := map[string]bool{}
	entries := make([]fileHash, 0, len(sorted))
	for _, f := range sorted {
		name := strings.TrimPrefix(f.Name, "/")
		if name == "" || name == ".signatures.json" || strings.Contains(name, "..") {
			return Bundle{}, errors.New("bundle file name is reserved")
		}
		if seen[name] {
			return Bundle{}, errors.New("bundle file name is duplicated")
		}
		seen[name] = true
		sum, err := fileDigest(name, f.Body)
		if err != nil {
			return Bundle{}, err
		}
		f.Name = name
		entries = append(entries, fileHash{Name: name, Hash: sum, Algorithm: "SHA-256"})
	}
	// The slice above mutated copies. Rebuild members with the trimmed names.
	for i := range sorted {
		sorted[i].Name = strings.TrimPrefix(sorted[i].Name, "/")
	}
	payload, err := json.Marshal(signedFiles{Files: entries, KeyID: keys[0].ID, Scope: "write"})
	if err != nil {
		return Bundle{}, err
	}
	jws, err := signJWS(keys[0].Private, keys[0].ID, payload)
	if err != nil {
		return Bundle{}, err
	}
	sigBody, err := json.Marshal(signaturesDoc{Signatures: []string{jws}})
	if err != nil {
		return Bundle{}, err
	}
	members := append(sorted, File{Name: ".signatures.json", Body: sigBody})
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	if err != nil {
		return Bundle{}, err
	}
	zw.Header.ModTime = time.Unix(0, 0).UTC()
	zw.Header.Name = "bundle.tar"
	tw := tar.NewWriter(zw)
	for _, f := range members {
		hdr := &tar.Header{
			Name: f.Name, Mode: 0o644, Size: int64(len(f.Body)),
			ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return Bundle{}, err
		}
		if _, err := tw.Write(f.Body); err != nil {
			return Bundle{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return Bundle{}, err
	}
	if err := zw.Close(); err != nil {
		return Bundle{}, err
	}
	sum := sha256.Sum256(buf.Bytes())
	return Bundle{Bytes: buf.Bytes(), SHA256: hex.EncodeToString(sum[:]), SignaturesJSON: sigBody}, nil
}

// VerifyBundle accepts the gzip tar when one signature verifies under pubs
// and every tar member is in that signature. An extra or duplicate member is
// rejected. pubs is keyed by key id. JSON files are hashed in OPA's canonical
// form. A bundle signed by a key that is not in pubs fails.
func VerifyBundle(tarGz []byte, pubs map[string]*ecdsa.PublicKey) error {
	files, sigBody, err := readTar(tarGz)
	if err != nil {
		return err
	}
	var doc signaturesDoc
	if err := json.Unmarshal(sigBody, &doc); err != nil || len(doc.Signatures) == 0 {
		return errors.New("bundle has no signature")
	}
	var verified bool
	var first error
	for _, compact := range doc.Signatures {
		kid, payload, err := openJWS(compact)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		pub := pubs[kid]
		if pub == nil {
			if first == nil {
				first = errors.New("unknown signing key")
			}
			continue
		}
		if _, err := verifyJWS(pub, kid, compact); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		var signed signedFiles
		if err := json.Unmarshal(payload, &signed); err != nil {
			return err
		}
		if signed.Scope != "" && signed.Scope != "write" {
			return errors.New("bundle signature scope is not write")
		}
		if err := matchFiles(files, signed.Files); err != nil {
			return err
		}
		verified = true
		break
	}
	if !verified {
		if first == nil {
			first = errors.New("bundle signature did not verify")
		}
		return first
	}
	return nil
}

// CanonicalManifest is the exact JSON that is signed.
func CanonicalManifest(m Manifest) ([]byte, error) {
	if m.Targets != nil {
		sort.Slice(m.Targets, func(i, j int) bool { return m.Targets[i].WorkloadID < m.Targets[j].WorkloadID })
	}
	return json.Marshal(m)
}

// SignManifest returns the compact JWS and the sha256 of the canonical JSON.
// During overlap every key signs; the returned JWS is the current key, and
// All carries one compact JWS per key joined by a comma? No: the wire field
// is one string. Overlap puts every JWS in a JSON array string so verifiers
// can accept old or new. Agents see that string as signed_manifest.
func SignManifest(m Manifest, keys []Key) (string, string, error) {
	payload, err := CanonicalManifest(m)
	if err != nil {
		return "", "", err
	}
	if len(keys) == 0 || keys[0].Private == nil {
		return "", "", errors.New("policy signing key is not configured")
	}
	sum := sha256.Sum256(payload)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		jws, err := signJWS(key.Private, key.ID, payload)
		if err != nil {
			return "", "", err
		}
		parts = append(parts, jws)
	}
	raw, err := json.Marshal(parts)
	if err != nil {
		return "", "", err
	}
	return string(raw), hex.EncodeToString(sum[:]), nil
}

// VerifyManifest checks one of the overlap signatures and returns the claim.
func VerifyManifest(signed string, pubs map[string]*ecdsa.PublicKey) (Manifest, error) {
	var parts []string
	if err := json.Unmarshal([]byte(signed), &parts); err != nil || len(parts) == 0 {
		return Manifest{}, errors.New("manifest is not signed")
	}
	var first error
	for _, part := range parts {
		kid, payload, err := openJWS(part)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		pub := pubs[kid]
		if pub == nil {
			if first == nil {
				first = errors.New("unknown signing key")
			}
			continue
		}
		if _, err := verifyJWS(pub, kid, part); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		var m Manifest
		if err := json.Unmarshal(payload, &m); err != nil {
			return Manifest{}, err
		}
		again, err := CanonicalManifest(m)
		if err != nil {
			return Manifest{}, err
		}
		if !bytes.Equal(again, payload) {
			return Manifest{}, errors.New("manifest is not canonical")
		}
		return m, nil
	}
	if first == nil {
		first = errors.New("manifest signature did not verify")
	}
	return Manifest{}, first
}

// SHA256Hex hashes body.
func SHA256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

type signedFiles struct {
	Files []fileHash `json:"files"`
	KeyID string     `json:"keyid"`
	Scope string     `json:"scope"`
}

type fileHash struct {
	Name      string `json:"name"`
	Hash      string `json:"hash"`
	Algorithm string `json:"algorithm"`
}

type signaturesDoc struct {
	Signatures []string `json:"signatures"`
}

func signJWS(key *ecdsa.PrivateKey, kid string, payload []byte) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": algo, "kid": kid})
	h64 := base64.RawURLEncoding.EncodeToString(header)
	p64 := base64.RawURLEncoding.EncodeToString(payload)
	input := h64 + "." + p64
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func verifyJWS(pub *ecdsa.PublicKey, kid, compact string) ([]byte, error) {
	gotKid, payload, err := openJWS(compact)
	if err != nil {
		return nil, err
	}
	if gotKid != kid {
		return nil, errors.New("signing key id does not match")
	}
	parts := bytes.Split([]byte(compact), []byte{'.'})
	sig, err := base64.RawURLEncoding.DecodeString(string(parts[2]))
	if err != nil || len(sig) != 64 {
		return nil, errors.New("signature encoding is invalid")
	}
	sum := sha256.Sum256([]byte(string(parts[0]) + "." + string(parts[1])))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, sum[:], r, s) {
		return nil, errors.New("signature did not verify")
	}
	return payload, nil
}

func openJWS(compact string) (string, []byte, error) {
	parts := bytes.Split([]byte(compact), []byte{'.'})
	if len(parts) != 3 {
		return "", nil, errors.New("signature is not a compact JWS")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(string(parts[0]))
	if err != nil {
		return "", nil, err
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return "", nil, err
	}
	if header.Alg != algo || header.Kid == "" {
		return "", nil, fmt.Errorf("unsupported signature algorithm")
	}
	payload, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return "", nil, err
	}
	return header.Kid, payload, nil
}

func matchFiles(files map[string][]byte, hashes []fileHash) error {
	if len(hashes) == 0 {
		return errors.New("signed file list is empty")
	}
	signed := map[string]fileHash{}
	for _, h := range hashes {
		if _, dup := signed[h.Name]; dup {
			return errors.New("signed file name is duplicated")
		}
		signed[h.Name] = h
	}
	if len(files) != len(signed) {
		return errors.New("bundle contains a file that is not signed")
	}
	for name, body := range files {
		h, ok := signed[name]
		if !ok {
			return errors.New("bundle contains a file that is not signed")
		}
		sum, err := fileDigest(name, body)
		if err != nil || sum != h.Hash || h.Algorithm != "SHA-256" {
			return errors.New("bundle file hash does not match the signature")
		}
	}
	return nil
}

func fileDigest(name string, body []byte) (string, error) {
	if structuredJSON(name) {
		raw, err := hashCanonicalJSON(body)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(raw), nil
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func structuredJSON(name string) bool {
	base := path.Base(name)
	return base == "data.json" || strings.HasSuffix(base, ".json")
}

// hashCanonicalJSON matches OPA's bundle file hash for structured documents:
// objects are walked with keys in alphabetical order, arrays in order, and
// scalars are JSON-encoded with HTML escaping off.
func hashCanonicalJSON(body []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("bundle json has trailing data")
	}
	h := sha256.New()
	if err := walkJSON(h, value); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func walkJSON(h io.Writer, v any) error {
	switch x := v.(type) {
	case map[string]any:
		if _, err := h.Write([]byte("{")); err != nil {
			return err
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, key := range keys {
			if i > 0 {
				if _, err := h.Write([]byte(",")); err != nil {
					return err
				}
			}
			enc, err := encodePrimitive(key)
			if err != nil {
				return err
			}
			if _, err := h.Write(enc); err != nil {
				return err
			}
			if _, err := h.Write([]byte(":")); err != nil {
				return err
			}
			if err := walkJSON(h, x[key]); err != nil {
				return err
			}
		}
		_, err := h.Write([]byte("}"))
		return err
	case []any:
		if _, err := h.Write([]byte("[")); err != nil {
			return err
		}
		for i, e := range x {
			if i > 0 {
				if _, err := h.Write([]byte(",")); err != nil {
					return err
				}
			}
			if err := walkJSON(h, e); err != nil {
				return err
			}
		}
		_, err := h.Write([]byte("]"))
		return err
	default:
		enc, err := encodePrimitive(x)
		if err != nil {
			return err
		}
		_, err = h.Write(enc)
		return err
	}
}

func encodePrimitive(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func readTar(tarGz []byte) (map[string][]byte, []byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tarGz))
	if err != nil {
		return nil, nil, err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	files := map[string][]byte{}
	var sig []byte
	for {
		hdr, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, nil, err
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(tr); err != nil {
			return nil, nil, err
		}
		name := strings.TrimPrefix(hdr.Name, "/")
		if name == ".signatures.json" {
			sig = buf.Bytes()
			continue
		}
		if _, dup := files[name]; dup {
			return nil, nil, errors.New("bundle file name is duplicated")
		}
		files[name] = buf.Bytes()
	}
	if sig == nil {
		return nil, nil, errors.New("bundle has no .signatures.json")
	}
	return files, sig, nil
}
