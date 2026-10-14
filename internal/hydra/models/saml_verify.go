package hydramodels

import (
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

const (
	samlAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
	samlProtocolNS  = "urn:oasis:names:tc:SAML:2.0:protocol"

	// samlClockSkew is the tolerance applied to NotBefore/NotOnOrAfter.
	samlClockSkew = 3 * time.Minute
)

// verifySignedAssertion checks the IdP's XML signature on a SAML Response and
// returns the assertion exactly as covered by that signature. Either the
// Response or its assertion must carry a valid enveloped signature made with
// idpCert; otherwise the response is rejected.
//
// The assertion is decoded from the element the signature validated, never
// from the raw document, so an unsigned assertion placed next to (or around)
// a signed one is never read (signature wrapping).
func verifySignedAssertion(responseXML []byte, idpCert *x509.Certificate, now time.Time) (*SAMLAssertionEnvelope, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(responseXML); err != nil {
		return nil, fmt.Errorf("parse SAML response XML: %w", err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "Response" || root.NamespaceURI() != samlProtocolNS {
		return nil, errors.New("SAML response root is not a samlp:Response")
	}
	assertions := samlAssertionChildren(root)
	if len(assertions) != 1 {
		return nil, fmt.Errorf("SAML response must contain exactly one assertion, found %d", len(assertions))
	}

	certStore := dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{idpCert}}
	vctx := dsig.NewDefaultValidationContext(&certStore)
	vctx.Clock = dsig.NewFakeClockAt(now)

	var signed *etree.Element
	if validated, respErr := vctx.Validate(root); respErr == nil {
		inner := samlAssertionChildren(validated)
		if len(inner) != 1 {
			return nil, fmt.Errorf("signed SAML response must contain exactly one assertion, found %d", len(inner))
		}
		el, err := detachSAMLElement(inner[0])
		if err != nil {
			return nil, err
		}
		signed = el
	} else {
		detached, err := detachSAMLElement(assertions[0])
		if err != nil {
			return nil, err
		}
		validated, assertErr := vctx.Validate(detached)
		if assertErr != nil {
			return nil, fmt.Errorf("no valid IdP signature on the response (%v) or the assertion (%v)", respErr, assertErr)
		}
		signed = validated
	}

	out := etree.NewDocument()
	out.SetRoot(signed.Copy())
	raw, err := out.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("serialize signed assertion: %w", err)
	}
	var assertion SAMLAssertionEnvelope
	if err := xml.Unmarshal(raw, &assertion); err != nil {
		return nil, fmt.Errorf("decode signed assertion: %w", err)
	}
	return &assertion, nil
}

// samlAssertionChildren returns the saml:Assertion children of el.
func samlAssertionChildren(el *etree.Element) []*etree.Element {
	var out []*etree.Element
	for _, child := range el.ChildElements() {
		if child.Tag == "Assertion" && child.NamespaceURI() == samlAssertionNS {
			out = append(out, child)
		}
	}
	return out
}

// detachSAMLElement copies el into a standalone element that carries every
// namespace declaration it inherited from its ancestors, so it can be
// canonicalized and signature-checked on its own.
func detachSAMLElement(el *etree.Element) (*etree.Element, error) {
	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, fmt.Errorf("resolve SAML namespaces: %w", err)
	}
	ctx, err = ctx.SubContext(el)
	if err != nil {
		return nil, fmt.Errorf("resolve SAML namespaces: %w", err)
	}
	detached, err := etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return nil, fmt.Errorf("detach SAML assertion: %w", err)
	}
	return detached, nil
}

// checkAssertionConditions enforces the Web SSO profile conditions on a signed
// assertion: the audience must include this SP, the assertion must be inside
// its validity window (with samlClockSkew), it must carry an expiry, and a
// bearer Recipient, when present, must be this ACS URL.
func checkAssertionConditions(a *SAMLAssertionEnvelope, spEntityID, acsURL string, now time.Time) error {
	spEntityID = strings.TrimSpace(spEntityID)
	if len(a.Conditions.AudienceRestrictions) == 0 {
		return errors.New("SAML assertion has no AudienceRestriction")
	}
	for _, ar := range a.Conditions.AudienceRestrictions {
		found := false
		for _, aud := range ar.Audiences {
			if strings.TrimSpace(aud) == spEntityID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("SAML assertion audience does not include %q", spEntityID)
		}
	}

	if v := strings.TrimSpace(a.Conditions.NotBefore); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return fmt.Errorf("invalid NotBefore %q", v)
		}
		if now.Add(samlClockSkew).Before(t) {
			return errors.New("SAML assertion is not yet valid")
		}
	}

	scd := a.Subject.SubjectConfirmation.SubjectConfirmationData
	expiries := 0
	for _, v := range []string{a.Conditions.NotOnOrAfter, scd.NotOnOrAfter} {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		expiries++
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return fmt.Errorf("invalid NotOnOrAfter %q", v)
		}
		if !now.Add(-samlClockSkew).Before(t) {
			return errors.New("SAML assertion has expired")
		}
	}
	if expiries == 0 {
		return errors.New("SAML assertion has no NotOnOrAfter")
	}

	if r := strings.TrimSpace(scd.Recipient); r != "" && r != acsURL {
		return errors.New("SAML assertion recipient is not this ACS URL")
	}
	return nil
}
