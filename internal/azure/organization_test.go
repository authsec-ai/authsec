package azure

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type orgRT struct {
	body string
	got  *http.Request
}

func (f *orgRT) RoundTrip(r *http.Request) (*http.Response, error) {
	f.got = r
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(f.body)), Request: r}, nil
}

// AS-168: the tenant's name, from its organization record.
func TestGetOrganization(t *testing.T) {
	rt := &orgRT{body: `{"value":[{"id":"39f82278-970e-482d-92a5-c5758142b92c","displayName":"Authnull"}]}`}
	org, err := NewClient(&http.Client{Transport: rt}).GetOrganization(context.Background(), "tok")
	if err != nil || org.DisplayName != "Authnull" {
		t.Fatalf("GetOrganization = %+v, %v", org, err)
	}
	if rt.got.URL.Path != "/v1.0/organization" || rt.got.URL.Query().Get("$select") != "id,displayName" ||
		rt.got.Header.Get("Authorization") != "Bearer tok" {
		t.Fatalf("request %s %v", rt.got.URL, rt.got.Header)
	}

	rt.body = `{"value":[]}`
	if _, err := NewClient(&http.Client{Transport: rt}).GetOrganization(context.Background(), "tok"); err == nil {
		t.Fatal("an empty answer is an error, not an empty name")
	}
}
