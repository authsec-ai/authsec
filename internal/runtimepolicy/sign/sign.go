// Package sign builds an ES256-signed OPA bundle and a detached manifest.
//
// The bundle is a gzip-compressed tar of policy.rego, data.json and
// .signatures.json. .signatures.json follows OPA's bundle signing shape:
// key id, scope "write", the signed file hashes, and a compact JWS whose
// payload is the canonical file list. The signature is raw R||S, not ASN.1.
// Controls are hashed separately and covered by the detached manifest.
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
	"sort"
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
	WorkspaceID        string         `json:"workspace_id"`
	PublicationID      string         `json:"publication_id"`
	TargetScope        string         `json:"target_scope,omitempty"`
	DeliveryRevision   int64          `json:"delivery_revision"`
	PolicyRevisionHash string         `json:"policy_revision_hash"`
	GraphRevision      int64          `json:"graph_revision"`
	TargetDigest       string         `json:"target_digest"`
	CapabilityDigest   string         `json:"capability_digest,omitempty"`
	CompilerBuild      string         `json:"compiler_build"`
	OPABundleSHA256    string         `json:"opa_bundle_sha256"`
	ControlsSHA256     string         `json:"controls_sha256"`
	RevocationEpoch    int64          `json:"revocation_epoch"`
	KeyID              string         `json:"key_id"`
	CreatedAt          string         `json:"created_at"`
	Targets            []TargetEffect `json:"targets,omitempty"`
}

// TargetEffect is the §13.4 result baked into the manifest at publish time.
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

// SignBundle writes a deterministic gzip tar. keys[0] is the current key.
// Additional keys are the rotation overlap and each gets its own signature.
func SignBundle(files []File, keys []Key) (Bundle, error) {
	if len(keys) == 0 || keys[0].Private == nil {
		return Bundle{}, errors.New("policy signing key is not configured")
	}
	sorted := append([]File(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	entries := make([]fileHash, 0, len(sorted))
	for _, f := range sorted {
		if f.Name == ".signatures.json" {
			return Bundle{}, errors.New("bundle file name is reserved")
		}
		sum := sha256.Sum256(f.Body)
		entries = append(entries, fileHash{Name: f.Name, Hash: hex.EncodeToString(sum[:]), Algorithm: "SHA-256"})
	}
	payload, err := json.Marshal(signedFiles{Files: entries})
	if err != nil {
		return Bundle{}, err
	}
	doc := signaturesDoc{Signatures: make([]signatureEntry, 0, len(keys))}
	for _, key := range keys {
		if key.Private == nil || key.ID == "" {
			return Bundle{}, errors.New("policy signing key is not configured")
		}
		jws, err := signJWS(key.Private, key.ID, payload)
		if err != nil {
			return Bundle{}, err
		}
		doc.Signatures = append(doc.Signatures, signatureEntry{
			KeyID: key.ID, Scope: "write", Signed: payload, Signature: jws,
		})
	}
	sigBody, err := json.Marshal(doc)
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
// and every signed file hash matches the tar member. pubs is keyed by key id.
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
	for _, sig := range doc.Signatures {
		pub := pubs[sig.KeyID]
		if pub == nil {
			if first == nil {
				first = errors.New("unknown signing key")
			}
			continue
		}
		payload, err := verifyJWS(pub, sig.KeyID, sig.Signature)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		if !bytes.Equal(payload, sig.Signed) {
			return errors.New("bundle signature payload does not match the file list")
		}
		var signed signedFiles
		if err := json.Unmarshal(payload, &signed); err != nil {
			return err
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
}

type fileHash struct {
	Name      string `json:"name"`
	Hash      string `json:"hash"`
	Algorithm string `json:"algorithm"`
}

type signaturesDoc struct {
	Signatures []signatureEntry `json:"signatures"`
}

type signatureEntry struct {
	KeyID     string          `json:"keyid"`
	Scope     string          `json:"scope"`
	Signed    json.RawMessage `json:"signed"`
	Signature string          `json:"signature"`
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
	for _, h := range hashes {
		body, ok := files[h.Name]
		if !ok {
			return errors.New("signed file is missing from the bundle")
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != h.Hash || h.Algorithm != "SHA-256" {
			return errors.New("bundle file hash does not match the signature")
		}
	}
	return nil
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
		if hdr.Name == ".signatures.json" {
			sig = buf.Bytes()
			continue
		}
		files[hdr.Name] = buf.Bytes()
	}
	if sig == nil {
		return nil, nil, errors.New("bundle has no .signatures.json")
	}
	return files, sig, nil
}
