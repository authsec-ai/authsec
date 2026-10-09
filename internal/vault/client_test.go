package vault

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestKVMetadataPath(t *testing.T) {
	for in, want := range map[string]string{
		"kv/data/secret/workspaces/w1/slack/bot": "kv/metadata/secret/workspaces/w1/slack/bot",
		"/kv/data/secret/x/":                     "kv/metadata/secret/x",
		"secret/data/a":                          "secret/metadata/a",
		"kv/secret/x":                            "", // KV v1
		"kv/data/":                               "",
		"data/x":                                 "",
		"kv/other/data/x":                        "", // data is not the mount's first segment
		"kv/data/secret/data/nested-is-still-key": "kv/metadata/secret/data/nested-is-still-key",
	} {
		if got := KVMetadataPath(in); got != want {
			t.Errorf("KVMetadataPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// DestroySecret on a KV v2 data path deletes the key's METADATA (every
// version, permanently); DeleteSecret deletes the data path (a soft delete of
// the latest version). Run against a fake Vault HTTP server.
func TestDestroySecretDeletesKVMetadata(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	vc, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	destroyed, err := Destroy(vc, "kv/data/secret/workspaces/w1/slack/bot")
	if err != nil || !destroyed {
		t.Fatalf("Destroy: %v %v", destroyed, err)
	}
	if err := vc.DeleteSecret("kv/data/secret/soft"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"DELETE /v1/kv/metadata/secret/workspaces/w1/slack/bot", "DELETE /v1/kv/data/secret/soft"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("requests %v, want %v", got, want)
	}
}

type softOnly struct{ deleted []string }

func (s *softOnly) WriteSecret(string, map[string]interface{}) error  { return nil }
func (s *softOnly) ReadSecret(string) (map[string]interface{}, error) { return nil, nil }
func (s *softOnly) DeleteSecret(p string) error                       { s.deleted = append(s.deleted, p); return nil }

func TestDestroyFallsBackAndSaysSo(t *testing.T) {
	s := &softOnly{}
	destroyed, err := Destroy(s, "kv/data/x")
	if err != nil || destroyed || len(s.deleted) != 1 {
		t.Fatalf("fallback: destroyed=%v err=%v deleted=%v", destroyed, err, s.deleted)
	}
}
