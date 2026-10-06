package hydramodels

import (
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Regression tests for AS-005: a SAML response is accepted only with a valid
// IdP signature, and only the signed assertion is read.

const (
	testSPEntityID = "https://sp.test/authsec/hmgr/saml/metadata"
	testACSURL     = "https://sp.test/authsec/hmgr/saml/acs"
)

type samlTestIdP struct {
	ks   dsig.X509KeyStore
	cert *x509.Certificate
}

func newSAMLTestIdP(t *testing.T) *samlTestIdP {
	t.Helper()
	ks := dsig.RandomKeyStoreForTest()
	_, der, err := ks.GetKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &samlTestIdP{ks: ks, cert: cert}
}

func samlAssertionXML(id, email string, now time.Time) string {
	return fmt.Sprintf(`<saml:Assertion ID="%s" Version="2.0" IssueInstant="%s">`+
		`<saml:Issuer>https://idp.test</saml:Issuer>`+
		`<saml:Subject><saml:NameID>%s</saml:NameID>`+
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`+
		`<saml:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s" InResponseTo="req-1"/>`+
		`</saml:SubjectConfirmation></saml:Subject>`+
		`<saml:Conditions NotBefore="%s" NotOnOrAfter="%s">`+
		`<saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>`+
		`</saml:Conditions>`+
		`<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`+
		`</saml:Assertion>`,
		id, now.UTC().Format(time.RFC3339), email,
		now.Add(5*time.Minute).UTC().Format(time.RFC3339), testACSURL,
		now.Add(-time.Minute).UTC().Format(time.RFC3339), now.Add(5*time.Minute).UTC().Format(time.RFC3339),
		testSPEntityID, email)
}

func samlResponseXML(assertions ...string) string {
	return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
		`ID="resp-1" Version="2.0" InResponseTo="req-1" Destination="` + testACSURL + `">` +
		`<saml:Issuer>https://idp.test</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		strings.Join(assertions, "") +
		`</samlp:Response>`
}

func (idp *samlTestIdP) signingContext(t *testing.T) *dsig.SigningContext {
	t.Helper()
	ctx := dsig.NewDefaultSigningContext(idp.ks)
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	return ctx
}

// signAssertion signs the assertion with the given index (in document order)
// in place and returns the serialized response.
func (idp *samlTestIdP) signAssertion(t *testing.T, responseXML string, index int) []byte {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(responseXML); err != nil {
		t.Fatal(err)
	}
	target := samlAssertionChildren(doc.Root())[index]
	detached, err := detachSAMLElement(target)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := idp.signingContext(t).SignEnveloped(detached)
	if err != nil {
		t.Fatal(err)
	}
	doc.Root().InsertChildAt(target.Index(), signed)
	doc.Root().RemoveChild(target)
	out, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (idp *samlTestIdP) signResponse(t *testing.T, responseXML string) []byte {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(responseXML); err != nil {
		t.Fatal(err)
	}
	signed, err := idp.signingContext(t).SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	doc.SetRoot(signed)
	out, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifySignedAssertion_AcceptsSignedAssertion(t *testing.T) {
	idp := newSAMLTestIdP(t)
	now := time.Now()
	raw := idp.signAssertion(t, samlResponseXML(samlAssertionXML("a-1", "alice@idp.test", now)), 0)

	a, err := verifySignedAssertion(raw, idp.cert, now)
	if err != nil {
		t.Fatalf("signed assertion rejected: %v", err)
	}
	if a.Subject.NameID.Value != "alice@idp.test" || a.Issuer.Value != "https://idp.test" {
		t.Fatalf("unexpected assertion: %+v", a)
	}
	if err := checkAssertionConditions(a, testSPEntityID, testACSURL, now); err != nil {
		t.Fatalf("conditions rejected a valid assertion: %v", err)
	}
}

func TestVerifySignedAssertion_AcceptsSignedResponse(t *testing.T) {
	idp := newSAMLTestIdP(t)
	now := time.Now()
	raw := idp.signResponse(t, samlResponseXML(samlAssertionXML("a-1", "alice@idp.test", now)))

	a, err := verifySignedAssertion(raw, idp.cert, now)
	if err != nil {
		t.Fatalf("signed response rejected: %v", err)
	}
	if a.Subject.NameID.Value != "alice@idp.test" {
		t.Fatalf("unexpected subject %q", a.Subject.NameID.Value)
	}
}

func TestVerifySignedAssertion_RejectsUnsigned(t *testing.T) {
	idp := newSAMLTestIdP(t)
	now := time.Now()
	raw := []byte(samlResponseXML(samlAssertionXML("a-1", "victim@corp.test", now)))
	if _, err := verifySignedAssertion(raw, idp.cert, now); err == nil {
		t.Fatal("unsigned SAML response was accepted")
	}
}

func TestVerifySignedAssertion_RejectsOtherSigner(t *testing.T) {
	idp := newSAMLTestIdP(t)
	attacker := newSAMLTestIdP(t)
	now := time.Now()
	raw := attacker.signAssertion(t, samlResponseXML(samlAssertionXML("a-1", "victim@corp.test", now)), 0)
	if _, err := verifySignedAssertion(raw, idp.cert, now); err == nil {
		t.Fatal("assertion signed by a different key was accepted")
	}
}

func TestVerifySignedAssertion_RejectsTampered(t *testing.T) {
	idp := newSAMLTestIdP(t)
	now := time.Now()
	raw := idp.signAssertion(t, samlResponseXML(samlAssertionXML("a-1", "alice@idp.test", now)), 0)
	tampered := strings.Replace(string(raw), "<saml:NameID>alice@idp.test", "<saml:NameID>victim@corp.test", 1)
	if tampered == string(raw) {
		t.Fatal("test setup: NameID not found")
	}
	if _, err := verifySignedAssertion([]byte(tampered), idp.cert, now); err == nil {
		t.Fatal("tampered assertion was accepted")
	}
}

// A validly signed assertion next to a forged unsigned one must not let the
// forged one be read.
func TestVerifySignedAssertion_RejectsWrapping(t *testing.T) {
	idp := newSAMLTestIdP(t)
	now := time.Now()
	resp := samlResponseXML(
		samlAssertionXML("forged", "victim@corp.test", now),
		samlAssertionXML("a-1", "alice@idp.test", now),
	)
	raw := idp.signAssertion(t, resp, 1)
	if a, err := verifySignedAssertion(raw, idp.cert, now); err == nil {
		t.Fatalf("response with two assertions accepted (subject %q)", a.Subject.NameID.Value)
	}
}

func TestCheckAssertionConditions(t *testing.T) {
	now := time.Now()
	base := func() *SAMLAssertionEnvelope {
		idp := newSAMLTestIdP(t)
		raw := idp.signAssertion(t, samlResponseXML(samlAssertionXML("a-1", "alice@idp.test", now)), 0)
		a, err := verifySignedAssertion(raw, idp.cert, now)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	ts := func(d time.Duration) string { return now.Add(d).UTC().Format(time.RFC3339) }

	cases := []struct {
		name   string
		mutate func(a *SAMLAssertionEnvelope)
		at     time.Time
		ok     bool
	}{
		{"valid", func(a *SAMLAssertionEnvelope) {}, now, true},
		{"within clock skew after expiry", func(a *SAMLAssertionEnvelope) {}, now.Add(6 * time.Minute), true},
		{"expired", func(a *SAMLAssertionEnvelope) {}, now.Add(10 * time.Minute), false},
		{"not yet valid", func(a *SAMLAssertionEnvelope) { a.Conditions.NotBefore = ts(10 * time.Minute) }, now, false},
		{"wrong audience", func(a *SAMLAssertionEnvelope) {
			a.Conditions.AudienceRestrictions[0].Audiences = []string{"https://other-sp.test"}
		}, now, false},
		{"no audience restriction", func(a *SAMLAssertionEnvelope) { a.Conditions.AudienceRestrictions = nil }, now, false},
		{"no expiry", func(a *SAMLAssertionEnvelope) {
			a.Conditions.NotOnOrAfter = ""
			a.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter = ""
		}, now, false},
		{"bearer expired", func(a *SAMLAssertionEnvelope) {
			a.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter = ts(-10 * time.Minute)
		}, now, false},
		{"wrong recipient", func(a *SAMLAssertionEnvelope) {
			a.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient = "https://evil.test/acs"
		}, now, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := base()
			tc.mutate(a)
			err := checkAssertionConditions(a, testSPEntityID, testACSURL, tc.at)
			if tc.ok && err != nil {
				t.Fatalf("want accepted, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("want rejected, got accepted")
			}
		})
	}
}
