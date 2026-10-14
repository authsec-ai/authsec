package igagov

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

var fuzzSeeds = []string{
	`{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"€$\u000F\u000aA'B"\\\\"\/","literals":[null,true,false]}`,
	`{"€":"Euro Sign","\r":"CR","דּ":"x","1":"One","😀":"e","\u0080":"c","ö":"o"}`,
	`[1e21,1e-7,-0,5e-324,1.7976931348623157e308,123456789012345678]`,
	`{"a":{"b":[{"c":"\u0000"}]}}`,
	`"\ud800"`,
	`{"a":1,"a":2}`,
	`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`,
	`[]`, `{}`, `""`, `0`, `true`, `null`,
}

// FuzzCanonicalize checks RFC 8785 idempotence (canon(canon(x)) ==
// canon(x)), that the canonical text is valid JSON meaning the same value as
// the input, and that nothing panics.
func FuzzCanonicalize(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c1, err := Canonicalize(data)
		if err != nil {
			return
		}
		c2, err := Canonicalize(c1)
		if err != nil {
			t.Fatalf("canonical output does not re-parse: %v\n%q", err, c1)
		}
		if !bytes.Equal(c1, c2) {
			t.Fatalf("not idempotent:\n%q\n%q", c1, c2)
		}
		var a, b any
		if err := json.Unmarshal(data, &a); err != nil {
			t.Fatalf("encoding/json rejects input JCS accepted: %v", err)
		}
		if err := json.Unmarshal(c1, &b); err != nil {
			t.Fatalf("encoding/json rejects canonical output: %v", err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("canonicalisation changed the value:\n%q\n%q", data, c1)
		}
	})
}

// FuzzDecodePolicyDocument checks the decoder never panics, and that an
// accepted document's statement texts are canonical.
func FuzzDecodePolicyDocument(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Add(`%7B%22Statement%22%3A%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22*%22%7D%7D`)
	f.Add(`{"Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":["arn:aws:iam::1:root"]},"NotAction":"s3:Get*","Condition":{"Bool":{"k":[true,1,"x"]}}}]}`)
	f.Fuzz(func(t *testing.T, text string) {
		doc, err := DecodePolicyDocument(text)
		if err != nil {
			return
		}
		for _, st := range doc.Statements {
			c, err := Canonicalize(st.Raw)
			if err != nil || !bytes.Equal(c, st.Raw) {
				t.Fatalf("statement raw is not canonical: %q (%v)", st.Raw, err)
			}
			_ = st.GrantsNamespace("s3")
			_ = st.ExplicitNamespaces()
			_ = EscalationsGranted(st)
		}
	})
}
