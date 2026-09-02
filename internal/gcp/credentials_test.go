package gcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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
		SubjectTokenProvider:           staticSubjectTokenProvider{token: wantSubjectToken},
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
