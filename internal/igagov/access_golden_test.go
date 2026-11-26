package igagov

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

var updateAccessGolden = flag.Bool("update-access", false, "rewrite testdata/golden/access.*.json and testdata/access_golden_hashes.json")

// accessGolden is what one access-policy case pins beside its document.
type accessGolden struct {
	DocumentHash string   `json:"document_hash"`
	Actions      []string `json:"actions"`
	Resources    []string `json:"resources"`
	Sentence     string   `json:"sentence"`
}

// accessGoldenCases builds every S3 access document of a fixed shape through
// AccessDocument and AccessSentence, as the service does (a block without an
// end passes AccessNoEnd to the document and nil to the sentence).
func accessGoldenCases(t *testing.T) (docs map[string][]byte, got map[string]accessGolden) {
	t.Helper()
	docs, got = map[string][]byte{}, map[string]accessGolden{}
	start := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	long := strings.Repeat("abcdefghij", 5) + "_reports_/" // 60 characters, past MaxListGuardPrefix
	if len(long) != 60 {
		t.Fatalf("long prefix is %d characters", len(long))
	}
	cases := []struct {
		name     string
		effect   string
		access   []string
		prefix   string
		starts   *time.Time
		ends     *time.Time
		roles    []string
		partial  bool // the list guard cannot name every fragment
		resource string
	}{
		{"block_read_prefix", AccessEffectBlock, []string{AccessRead}, "invoices/", nil, &end, []string{"ApInvoiceReader"}, false, ""},
		{"block_read_long_prefix", AccessEffectBlock, []string{AccessRead}, long, nil, &end, []string{"ApInvoiceReader"}, true, ""},
		{"block_write_prefix", AccessEffectBlock, []string{AccessWrite}, "invoices/", nil, &end, []string{"ApInvoiceReader", "ApBatchJob"}, false, ""},
		{"block_all_bucket_no_end", AccessEffectBlock, []string{AccessAll}, "", nil, nil, []string{"ApInvoiceReader"}, false, ""},
		{"block_all_prefix", AccessEffectBlock, []string{AccessAll}, "invoices/", nil, &end, []string{"ApInvoiceReader"}, false, ""},
		{"allow_read_bucket", AccessEffectAllow, []string{AccessRead}, "", nil, &end, []string{"ApInvoiceReader"}, false, ""},
		{"allow_write_start", AccessEffectAllow, []string{AccessWrite}, "", &start, &end, []string{"ApBatchJob"}, false, ""},
		{"allow_read_write_delete_prefix", AccessEffectAllow, []string{AccessDelete, AccessRead, AccessWrite}, "invoices/", nil, &end, []string{"ApBatchJob"}, false, ""},
		{"block_read_gov_partition", AccessEffectBlock, []string{AccessRead}, "invoices/", nil, &end, []string{"ApInvoiceReader"}, false, "arn:aws-us-gov:s3:::acme-invoices"},
	}
	for _, c := range cases {
		arn := c.resource
		if arn == "" {
			arn = "arn:aws:s3:::acme-invoices"
		}
		target, ok := ParseS3BucketARN(arn)
		if !ok {
			t.Fatalf("%s: %s does not parse", c.name, arn)
		}
		target.Prefix = c.prefix
		if AccessListGuardPartial(c.effect, c.prefix) != c.partial {
			t.Fatalf("%s: list guard partial is not %v", c.name, c.partial)
		}
		docEnd := c.ends
		if docEnd == nil {
			docEnd = &AccessNoEnd
		}
		doc, hash, actions, resources, err := AccessDocument(c.effect, c.access, target, c.starts, docEnd)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		in := AccessIntent{Effect: c.effect, Resource: AccessResource{ResourceID: "11111111-1111-1111-1111-111111111111", Prefix: c.prefix},
			Roles: []AccessRole{{IdentityAccountID: "22222222-2222-2222-2222-222222222222"}}, Access: c.access, StartsAt: c.starts, EndsAt: c.ends}
		name := "access.s3." + c.name
		docs[name] = doc
		got[name] = accessGolden{DocumentHash: hash, Actions: actions, Resources: resources, Sentence: AccessSentence(in, target, c.roles)}
	}
	return docs, got
}

// TestAccessGolden pins today's S3 access documents byte for byte, with their
// hashes, the actions and resources AccessDocument returns and the preview's
// sentence. Documents are committed under testdata/golden/access.s3.*.json
// (sha256sum gives the hash), the rest in testdata/access_golden_hashes.json.
// Rewrite them only for a deliberate change: go test -run TestAccessGolden -update-access.
func TestAccessGolden(t *testing.T) {
	docs, got := accessGoldenCases(t)
	dir := filepath.Join("testdata", "golden")
	hashFile := filepath.Join("testdata", "access_golden_hashes.json")
	if *updateAccessGolden {
		for name, d := range docs {
			if err := os.WriteFile(filepath.Join(dir, name+".json"), d, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		js, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(hashFile, append(js, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(hashFile)
	if err != nil {
		t.Fatalf("%v (run go test -run TestAccessGolden -update-access once)", err)
	}
	var want map[string]accessGolden
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) != len(got) {
		t.Fatalf("golden file has %d entries, test has %d", len(want), len(got))
	}
	names := make([]string, 0, len(got))
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		g, w := got[n], want[n]
		if g.DocumentHash != w.DocumentHash {
			t.Errorf("%s: hash %s, golden %s", n, g.DocumentHash, w.DocumentHash)
		}
		if !reflect.DeepEqual(g.Actions, w.Actions) {
			t.Errorf("%s: actions %v, golden %v", n, g.Actions, w.Actions)
		}
		if !reflect.DeepEqual(g.Resources, w.Resources) {
			t.Errorf("%s: resources %v, golden %v", n, g.Resources, w.Resources)
		}
		if g.Sentence != w.Sentence {
			t.Errorf("%s: sentence %q, golden %q", n, g.Sentence, w.Sentence)
		}
		b, err := os.ReadFile(filepath.Join(dir, n+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != string(docs[n]) {
			t.Errorf("%s: document differs from golden:\n got %s\nwant %s", n, docs[n], b)
		}
		if ContentHash(b) != w.DocumentHash {
			t.Errorf("%s: the golden hash is not sha256 of the golden document", n)
		}
		if PolicyChars(b) > MaxPolicyChars {
			t.Errorf("%s: %d characters, over %d", n, PolicyChars(b), MaxPolicyChars)
		}
	}
}
