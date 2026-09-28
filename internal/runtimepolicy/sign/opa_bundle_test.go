package sign

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/bundle"
)

func TestOPALoaderVerifiesBundle(t *testing.T) {
	current := mustKey(t, "current")
	previous := mustKey(t, "previous")
	wrong := mustKey(t, "wrong")
	// Pretty-printed JSON must hash the same as compact JSON.
	files := []File{
		{Name: "policy.rego", Body: []byte("package authsec.runtime\ndefault allow := false\n")},
		{Name: "data.json", Body: []byte("{\n  \"rules\": []\n}\n")},
	}
	cur, err := SignBundle(files, []Key{current})
	if err != nil {
		t.Fatal(err)
	}
	if err := loadOPA(t, cur.Bytes, current); err != nil {
		t.Fatalf("current key: %v", err)
	}
	prev, err := SignBundle(files, []Key{previous})
	if err != nil {
		t.Fatal(err)
	}
	if err := loadOPA(t, prev.Bytes, previous); err != nil {
		t.Fatalf("previous key: %v", err)
	}
	if err := loadOPA(t, cur.Bytes, wrong); err == nil {
		t.Fatal("wrong key loaded the bundle")
	}
	tampered, err := rewriteTar(cur.Bytes, map[string][]byte{
		"policy.rego": []byte("package authsec.runtime\ndefault allow := true\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := loadOPA(t, tampered, current); err == nil {
		t.Fatal("tampered policy.rego loaded")
	}
	extra, err := rewriteTar(cur.Bytes, map[string][]byte{
		"extra.txt": []byte("unsigned"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := loadOPA(t, extra, current); err == nil {
		t.Fatal("unsigned extra file loaded")
	}
	if err := VerifyBundle(extra, pubs(current)); err == nil {
		t.Fatal("VerifyBundle accepted an unsigned extra file")
	}
	dup, err := tarWithDuplicate(files[0].Body, files[1].Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(dup, pubs(current)); err == nil {
		t.Fatal("VerifyBundle accepted a duplicate member")
	}
}

func loadOPA(t *testing.T, raw []byte, key Key) error {
	t.Helper()
	pub, err := key.ToPublic()
	if err != nil {
		t.Fatal(err)
	}
	vc := bundle.NewVerificationConfig(map[string]*bundle.KeyConfig{
		key.ID: {Key: pub.PEM, Algorithm: "ES256"},
	}, key.ID, "write", nil)
	_, err = bundle.NewReader(bytes.NewReader(raw)).WithBundleVerificationConfig(vc).Read()
	return err
}

func rewriteTar(raw []byte, replace map[string][]byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	if err != nil {
		return nil, err
	}
	zw.Header.ModTime = time.Unix(0, 0).UTC()
	tw := tar.NewWriter(zw)
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		if next, ok := replace[hdr.Name]; ok {
			body = next
			delete(replace, hdr.Name)
		}
		seen[hdr.Name] = true
		hdr.Size = int64(len(body))
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(body); err != nil {
			return nil, err
		}
	}
	for name, body := range replace {
		if seen[name] {
			continue
		}
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func tarWithDuplicate(rego, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(zw)
	for _, name := range []string{"policy.rego", "policy.rego"} {
		body := rego
		if name == "data.json" {
			body = data
		}
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(body); err != nil {
			return nil, err
		}
	}
	_ = data
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
