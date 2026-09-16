package gcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/auth/credentials/externalaccount"
	"github.com/google/uuid"
)

/* ------------------------------ json_key shape ------------------------------ */

// validKeyJSON builds a structurally valid service-account key JSON, with a
// real (throwaway, test-only) RSA private key so validatePrivateKeyPEM's PEM
// parse genuinely succeeds rather than being skipped.
func validKeyJSON(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal test key: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	shape := jsonKeyShape{
		Type:        "service_account",
		ProjectID:   "test-project",
		ClientEmail: "authsec-reader@test-project.iam.gserviceaccount.com",
		PrivateKey:  pemStr,
	}
	b, err := json.Marshal(shape)
	if err != nil {
		t.Fatalf("marshal key shape: %v", err)
	}
	return b
}

func TestResolveJSONKeyCredential_Valid(t *testing.T) {
	opt, err := ResolveJSONKeyCredential(validKeyJSON(t))
	if err != nil {
		t.Fatalf("ResolveJSONKeyCredential: %v", err)
	}
	if opt == nil {
		t.Fatal("ResolveJSONKeyCredential returned a nil ClientOption for a valid key")
	}
}

func TestResolveJSONKeyCredential_Malformed(t *testing.T) {
	cases := map[string]string{
		"not json at all":                     `not json`,
		"wrong type":                          `{"type":"authorized_user","project_id":"p","client_email":"e@p.iam.gserviceaccount.com","private_key":"x"}`,
		"missing project_id":                  `{"type":"service_account","client_email":"e@p.iam.gserviceaccount.com","private_key":"x"}`,
		"missing client_email":                `{"type":"service_account","project_id":"p","private_key":"x"}`,
		"missing private_key":                 `{"type":"service_account","project_id":"p","client_email":"e@p.iam.gserviceaccount.com"}`,
		"private_key not a PEM block":         `{"type":"service_account","project_id":"p","client_email":"e@p.iam.gserviceaccount.com","private_key":"not-a-pem-block"}`,
		"private_key PEM but not a valid key": `{"type":"service_account","project_id":"p","client_email":"e@p.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nZ2FyYmFnZQ==\n-----END PRIVATE KEY-----\n"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ResolveJSONKeyCredential([]byte(raw))
			if err == nil {
				t.Fatalf("%s: expected an error, got none", name)
			}
			if !errors.Is(err, ErrKeyInvalid) {
				t.Fatalf("%s: err = %v, want it to wrap ErrKeyInvalid", name, err)
			}
		})
	}
}

/* --------------------------------- wif path ---------------------------------- */

// fakeTokenIssuer stands in for internal/tokens.NativeIssuer — it satisfies
// CloudOnboardingTokenIssuer without a real signing keyset or database, and
// records the (sub, audience) it was called with so a test can assert
// ResolveWIFCredential passed through DeriveWIFParams's own output rather
// than something else.
type fakeTokenIssuer struct {
	token     string
	err       error
	gotSub    string
	gotAud    string
	callCount int
	// issuerURL, if set, is what IssuerURL() returns — lets a test construct
	// an issuer with a non-HTTPS URL to exercise ErrWIFIssuerNotHTTPS.
	// Zero value defaults to a valid HTTPS placeholder so every existing
	// test (none of which cares about this) keeps passing unchanged.
	issuerURL string
}

// IssuerURL satisfies gcp.CloudOnboardingTokenIssuer.
func (f *fakeTokenIssuer) IssuerURL() string {
	if f.issuerURL != "" {
		return f.issuerURL
	}
	return "https://app.authsec.test"
}

func (f *fakeTokenIssuer) IssueCloudOnboardingToken(_ context.Context, sub, audience string) (string, error) {
	f.callCount++
	f.gotSub, f.gotAud = sub, audience
	if f.err != nil {
		return "", f.err
	}
	return f.token, nil
}

func TestResolveWIFCredential_MissingParamsRejectedBeforeAnyCall(t *testing.T) {
	issuer := &fakeTokenIssuer{token: "irrelevant"}
	ws := uuid.New()

	_, err := ResolveWIFCredential(context.Background(), issuer, ws, "scope-1", "", "reader@p.iam.gserviceaccount.com")
	if !errors.Is(err, ErrWIFPoolMissing) {
		t.Errorf("empty providerResource: err = %v, want ErrWIFPoolMissing", err)
	}

	_, err = ResolveWIFCredential(context.Background(), issuer, ws, "scope-1", "projects/1/locations/global/workloadIdentityPools/p/providers/pr", "")
	if !errors.Is(err, ErrWIFPoolMissing) {
		t.Errorf("empty readerSAEmail: err = %v, want ErrWIFPoolMissing", err)
	}

	if issuer.callCount != 0 {
		t.Errorf("issuer was called %d times for input the function should have rejected before minting anything", issuer.callCount)
	}
}

func TestResolveWIFCredential_DerivesSubjectAndAudienceFromInputs(t *testing.T) {
	issuer := &fakeTokenIssuer{token: "fake.jwt.token"}
	ws := uuid.New()
	const scopeID = "my-project"
	const providerResource = "projects/123456789012/locations/global/workloadIdentityPools/authsec-abc123/providers/authsec-provider"

	_, err := ResolveWIFCredential(context.Background(), issuer, ws, scopeID, providerResource, "reader@p.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("ResolveWIFCredential: %v", err)
	}

	_, _, wantSubject := DeriveWIFParams(ws, scopeID)
	if issuer.gotSub != wantSubject {
		t.Errorf("issuer was minted for sub=%q, want DeriveWIFParams's own subject %q", issuer.gotSub, wantSubject)
	}
	wantAudience := audiencePrefix + providerResource
	if issuer.gotAud != wantAudience {
		t.Errorf("issuer was minted for audience=%q, want %q", issuer.gotAud, wantAudience)
	}
}

// TestResolveWIFCredential_RejectsNonHTTPSIssuerBeforeAnyCall proves the
// fail-fast requirement directly: an issuer that isn't HTTPS (e.g. this
// deployment's own http://localhost:7001) is rejected with
// ErrWIFIssuerNotHTTPS before the token issuer is ever invoked — no minted
// token, no GCP/STS call, for a failure GCP is guaranteed to produce anyway.
func TestResolveWIFCredential_RejectsNonHTTPSIssuerBeforeAnyCall(t *testing.T) {
	issuer := &fakeTokenIssuer{token: "irrelevant", issuerURL: "http://localhost:7001"}

	_, err := ResolveWIFCredential(context.Background(), issuer, uuid.New(), "scope-1",
		"projects/1/locations/global/workloadIdentityPools/p/providers/pr", "reader@p.iam.gserviceaccount.com")

	if !errors.Is(err, ErrWIFIssuerNotHTTPS) {
		t.Errorf("err = %v, want ErrWIFIssuerNotHTTPS", err)
	}
	if issuer.callCount != 0 {
		t.Errorf("issuer.IssueCloudOnboardingToken was called %d times; a non-HTTPS issuer must be rejected before minting anything", issuer.callCount)
	}
}

// TestResolveWIFCredential_AcceptsHTTPSIssuer proves the check is not
// over-broad: a real HTTPS issuer (production, or a local dev tunnel) is
// not rejected and the function proceeds to mint a token exactly as before
// this check was added.
func TestResolveWIFCredential_AcceptsHTTPSIssuer(t *testing.T) {
	issuer := &fakeTokenIssuer{token: "fake.jwt.token", issuerURL: "https://abc123.trycloudflare.com"}

	_, err := ResolveWIFCredential(context.Background(), issuer, uuid.New(), "scope-1",
		"projects/1/locations/global/workloadIdentityPools/p/providers/pr", "reader@p.iam.gserviceaccount.com")

	if err != nil {
		t.Fatalf("ResolveWIFCredential with a valid HTTPS issuer: %v", err)
	}
	if issuer.callCount != 1 {
		t.Errorf("issuer.IssueCloudOnboardingToken called %d times, want 1", issuer.callCount)
	}
}

func TestResolveWIFCredential_TokenMintFailurePropagates(t *testing.T) {
	issuer := &fakeTokenIssuer{err: errors.New("signing key unavailable")}
	_, err := ResolveWIFCredential(context.Background(), issuer,
		uuid.New(), "scope-1", "projects/1/locations/global/workloadIdentityPools/p/providers/pr", "reader@p.iam.gserviceaccount.com")
	if err == nil {
		t.Fatal("expected an error when the issuer itself fails to mint")
	}
}

/* --------------------- mock STS + impersonation round trip ------------------- */

// TestExternalAccountCredential_MockSTSExchange exercises the SAME
// construction path ResolveWIFCredential uses (externalaccount.Options ->
// newExternalAccountCredentials -> *auth.Credentials.Token(ctx)) against a
// local httptest server standing in for BOTH sts.googleapis.com (the token
// exchange) and iamcredentials.googleapis.com (the impersonation call) — no
// live GCP call anywhere in this test, per this ticket's own instruction.
//
// This is the test that actually proves the SubjectTokenProvider mechanism
// works end to end: a self-signed bearer token going in, a real (mocked)
// RFC 8693 token-exchange response and a real (mocked) generateAccessToken
// response coming back out as a usable access token.
func TestExternalAccountCredential_MockSTSExchange(t *testing.T) {
	const wantSubjectToken = "fake-cloud-onboarding-jwt"

	mux := http.NewServeMux()
	var stsCalled, impersonateCalled bool

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		stsCalled = true
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if got := r.FormValue("subject_token"); got != wantSubjectToken {
			http.Error(w, "unexpected subject_token", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":      "federated-token-from-mock-sts",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	})

	mux.HandleFunc("/generateAccessToken", func(w http.ResponseWriter, r *http.Request) {
		impersonateCalled = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"accessToken": "impersonated-access-token-from-mock-iamcredentials",
			"expireTime":  "2099-01-01T00:00:00Z",
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	creds, err := newExternalAccountCredentials(&externalaccount.Options{
		Audience:                       "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/authsec-abc123/providers/authsec-provider",
		SubjectTokenType:               wifSubjectTokenType,
		SubjectTokenProvider:           mintingSubjectTokenProvider{issuer: &fakeTokenIssuer{token: wantSubjectToken}, subject: "authsec:subject", audience: "//iam.googleapis.com/whatever"},
		TokenURL:                       srv.URL + "/token",
		ServiceAccountImpersonationURL: srv.URL + "/generateAccessToken",
		Scopes:                         []string{ReadOnlyScope},
	})
	if err != nil {
		t.Fatalf("newExternalAccountCredentials: %v", err)
	}

	tok, err := creds.Token(context.Background())
	if err != nil {
		t.Fatalf("creds.Token: %v", err)
	}
	if tok.Value != "impersonated-access-token-from-mock-iamcredentials" {
		t.Errorf("token value = %q, want the mocked IMPERSONATED token (proves the flow went through generateAccessToken, not just STS)", tok.Value)
	}
	if !stsCalled {
		t.Error("mock STS /token endpoint was never called")
	}
	if !impersonateCalled {
		t.Error("mock /generateAccessToken endpoint was never called -- impersonation did not happen")
	}
}

/* ------------------------- subject-token refresh (ONB-1) --------------------- */

// countingIssuer mints a DIFFERENT token on every call, so a test can tell one
// mint apart from the next. fakeTokenIssuer deliberately returns a fixed
// string (several tests assert on its exact value), which cannot distinguish
// "minted twice" from "handed back the same token twice" -- the precise
// confusion this file's ONB-1 tests exist to rule out.
type countingIssuer struct {
	mu     sync.Mutex
	issued []string
}

func (c *countingIssuer) IssuerURL() string { return "https://app.authsec.test" }

func (c *countingIssuer) IssueCloudOnboardingToken(_ context.Context, _, _ string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tok := fmt.Sprintf("minted-subject-token-%d", len(c.issued)+1)
	c.issued = append(c.issued, tok)
	return tok, nil
}

// TestMintingSubjectTokenProvider_MintsFreshEveryCall is the direct unit test
// for the ONB-1 fix: the provider must mint per call, never memoise.
//
// The predecessor (staticSubjectTokenProvider) captured one 5-minute token at
// construction. Since the impersonated access token it feeds lives about an
// hour, the library's first refresh re-invoked the provider and got back an
// assertion that had expired ~55 minutes earlier -- so a credential worked for
// exactly one refresh interval. That is survivable for onboarding's single
// verify call and fatal for a scan that pages for hours.
func TestMintingSubjectTokenProvider_MintsFreshEveryCall(t *testing.T) {
	issuer := &countingIssuer{}
	p := mintingSubjectTokenProvider{issuer: issuer, subject: "authsec:abc", audience: "//iam.googleapis.com/aud"}

	first, err := p.SubjectToken(context.Background(), nil)
	if err != nil {
		t.Fatalf("first SubjectToken: %v", err)
	}
	second, err := p.SubjectToken(context.Background(), nil)
	if err != nil {
		t.Fatalf("second SubjectToken: %v", err)
	}

	if first == second {
		t.Fatalf("both calls returned %q -- the provider memoised instead of minting; a long scan would present an expired assertion at its first refresh", first)
	}
	if len(issuer.issued) != 2 {
		t.Errorf("issuer minted %d times, want 2", len(issuer.issued))
	}
}

// TestMintingSubjectTokenProvider_PassesDerivedSubjectAndAudience proves the
// provider forwards exactly what ResolveWIFCredential derived, rather than
// re-deriving anything of its own on the refresh path.
func TestMintingSubjectTokenProvider_PassesDerivedSubjectAndAudience(t *testing.T) {
	issuer := &fakeTokenIssuer{token: "t"}
	p := mintingSubjectTokenProvider{issuer: issuer, subject: "authsec:deadbeef", audience: "//iam.googleapis.com/projects/1/x"}

	if _, err := p.SubjectToken(context.Background(), nil); err != nil {
		t.Fatalf("SubjectToken: %v", err)
	}
	if issuer.gotSub != "authsec:deadbeef" {
		t.Errorf("sub = %q, want the derived wif_subject", issuer.gotSub)
	}
	if issuer.gotAud != "//iam.googleapis.com/projects/1/x" {
		t.Errorf("aud = %q, want the provider-resource audience", issuer.gotAud)
	}
}

// TestExternalAccountCredential_RefreshMintsANewSubjectToken is the
// integration half: it drives the real externalaccount credential through TWO
// token acquisitions against the mock STS and asserts the second exchange
// carried a DIFFERENT subject token than the first.
//
// The impersonation response deliberately expires immediately, which is what
// makes the library re-run the whole exchange on the second Token() call
// rather than serving a cached access token. Against the old static provider
// this test would see the same subject_token twice -- and in production, an
// expired one.
func TestExternalAccountCredential_RefreshMintsANewSubjectToken(t *testing.T) {
	issuer := &countingIssuer{}

	var mu sync.Mutex
	var seenSubjectTokens []string

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		seenSubjectTokens = append(seenSubjectTokens, r.FormValue("subject_token"))
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":      "federated-token",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			// One second, which the auth library's own refresh margin already
			// treats as stale. The federated STS token is cached SEPARATELY
			// from the impersonated one, so leaving this at 3600 would let the
			// second Token() call re-impersonate off a cached exchange and
			// never re-invoke the subject-token provider at all.
			"expires_in": 1,
		})
	})
	mux.HandleFunc("/generateAccessToken", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Already expired, so the next Token() call cannot serve this from
		// cache and must repeat the exchange -- which is the only way to
		// observe what the provider hands over on a refresh.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"accessToken": "impersonated-access-token",
			"expireTime":  time.Now().UTC().Add(-time.Minute).Format(time.RFC3339),
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	creds, err := newExternalAccountCredentials(&externalaccount.Options{
		Audience:                       "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/authsec-abc123/providers/authsec-provider",
		SubjectTokenType:               wifSubjectTokenType,
		SubjectTokenProvider:           mintingSubjectTokenProvider{issuer: issuer, subject: "authsec:abc", audience: "//iam.googleapis.com/aud"},
		TokenURL:                       srv.URL + "/token",
		ServiceAccountImpersonationURL: srv.URL + "/generateAccessToken",
		Scopes:                         []string{ReadOnlyScope},
	})
	if err != nil {
		t.Fatalf("newExternalAccountCredentials: %v", err)
	}

	ctx := context.Background()
	if _, err := creds.Token(ctx); err != nil {
		t.Fatalf("first Token: %v", err)
	}

	// Wait past the federated token's one-second lifetime before asking again.
	//
	// The impersonated token and the federated STS token are cached at
	// SEPARATE layers. The already-expired impersonation response forces a
	// re-impersonation on every call, but that alone reuses the cached
	// exchange and never re-invokes the subject-token provider -- so simply
	// calling twice in a row observes only one exchange and so fails for the
	// wrong reason -- never reaching the refresh path at all. Sleeping past
	// the STS token's own expiry is what makes the second exchange certain:
	// the library's refresh margin can only make a token expire sooner than
	// its stated lifetime, never later.
	time.Sleep(1200 * time.Millisecond)

	if _, err := creds.Token(ctx); err != nil {
		t.Fatalf("second Token (the refresh this test exists for): %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seenSubjectTokens) < 2 {
		t.Fatalf("STS saw %d exchange(s), want at least 2 -- the credential served a cached token and the refresh path was never exercised", len(seenSubjectTokens))
	}
	if seenSubjectTokens[0] == seenSubjectTokens[1] {
		t.Errorf("both exchanges presented the same subject token %q -- on a real refresh that assertion would be long expired", seenSubjectTokens[0])
	}
}
