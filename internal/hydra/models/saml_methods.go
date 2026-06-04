package hydramodels

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SAML XML structures

type SAMLAuthnRequest struct {
	XMLName                     xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string           `xml:"ID,attr"`
	Version                     string           `xml:"Version,attr"`
	IssueInstant                string           `xml:"IssueInstant,attr"`
	Destination                 string           `xml:"Destination,attr"`
	AssertionConsumerServiceURL string           `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding             string           `xml:"ProtocolBinding,attr"`
	Issuer                      SAMLIssuer       `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameIDPolicy                SAMLNameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
}

type SAMLIssuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Value   string   `xml:",chardata"`
}

type SAMLNameIDPolicy struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	Format      string   `xml:"Format,attr"`
	AllowCreate bool     `xml:"AllowCreate,attr"`
}

type SAMLResponseEnvelope struct {
	XMLName      xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string                `xml:"ID,attr"`
	InResponseTo string                `xml:"InResponseTo,attr"`
	Version      string                `xml:"Version,attr"`
	IssueInstant string                `xml:"IssueInstant,attr"`
	Destination  string                `xml:"Destination,attr"`
	Status       SAMLStatus            `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Assertion    SAMLAssertionEnvelope `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

type SAMLStatus struct {
	StatusCode SAMLStatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

type SAMLStatusCode struct {
	Value string `xml:"Value,attr"`
}

type SAMLAssertionEnvelope struct {
	XMLName            xml.Name               `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                 string                 `xml:"ID,attr"`
	Version            string                 `xml:"Version,attr"`
	IssueInstant       string                 `xml:"IssueInstant,attr"`
	Issuer             SAMLIssuer             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Subject            SAMLSubject            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions         SAMLConditions         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AttributeStatement SAMLAttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

type SAMLSubject struct {
	NameID              SAMLNameID              `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SubjectConfirmation SAMLSubjectConfirmation `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
}

type SAMLNameID struct {
	Format string `xml:"Format,attr"`
	Value  string `xml:",chardata"`
}

type SAMLSubjectConfirmation struct {
	Method                  string                      `xml:"Method,attr"`
	SubjectConfirmationData SAMLSubjectConfirmationData `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
}

type SAMLSubjectConfirmationData struct {
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	Recipient    string `xml:"Recipient,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`
}

type SAMLConditions struct {
	NotBefore    string `xml:"NotBefore,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
}

type SAMLAttributeStatement struct {
	Attributes []SAMLAttribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

type SAMLAttribute struct {
	Name       string               `xml:"Name,attr"`
	NameFormat string               `xml:"NameFormat,attr"`
	Values     []SAMLAttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

type SAMLAttributeValue struct {
	Type  string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Value string `xml:",chardata"`
}

// GetSAMLProvidersForTenant retrieves SAML providers for a workspace via the
// GetSAMLProvidersForTenant returns the workspace's SAML providers by joining
// identity_providers + saml_providers. Only rows whose identity_providers row
// exists and is not disabled are returned. v4: client_id has been dropped from
// saml_providers — per-Application restriction is enforced at initiate via
// application_identity_provider_policies, not at list time.
//
// Variadic clientID is kept for source compatibility with legacy callers but
// is ignored.
func (s *OAuthLoginService) GetSAMLProvidersForTenant(workspaceID string, _ ...string) ([]Provider, error) {
	db := config.DB

	query := db.
		Table("saml_providers sp").
		Select("sp.*").
		Joins(`JOIN identity_providers ip
		         ON ip.workspace_id = sp.workspace_id
		        AND ip.provider_type = 'saml'
		        AND ip.saml_provider_id = sp.id`).
		Where("sp.workspace_id = ?", workspaceID).
		Where("sp.is_active = ?", true).
		Where("ip.status <> 'disabled'")

	var samlProviders []SAMLProvider
	if err := query.Order("sp.sort_order ASC").Find(&samlProviders).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch SAML providers: %w", err)
	}

	providers := make([]Provider, 0, len(samlProviders))
	for _, sp := range samlProviders {
		providers = append(providers, Provider{
			ProviderName: sp.ProviderName,
			DisplayName:  sp.DisplayName,
			Type:         "saml",
			IsActive:     sp.IsActive,
			SortOrder:    sp.SortOrder,
			Config: map[string]interface{}{
				"entity_id":      sp.EntityID,
				"sso_url":        sp.SSOURL,
				"slo_url":        sp.SLOURL,
				"name_id_format": sp.NameIDFormat,
			},
		})
	}
	return providers, nil
}

// GetAllProvidersForTenant returns both OIDC and SAML providers
func (s *OAuthLoginService) GetAllProvidersForTenant(workspaceIDForOIDC string, realWorkspaceID string, clientID ...string) ([]Provider, error) {
	var allProviders []Provider

	oidcProviders, err := s.GetOIDCProvidersForTenant(workspaceIDForOIDC)
	if err != nil {
		log.Printf("Warning: Failed to get OIDC providers: %v", err)
	} else {
		for _, op := range oidcProviders {
			allProviders = append(allProviders, Provider{
				ProviderName: op.ProviderName,
				DisplayName:  op.DisplayName,
				Type:         "oidc",
				IsActive:     op.IsActive,
				SortOrder:    op.SortOrder,
				Config:       op.Config,
			})
		}
	}

	samlProviders, err := s.GetSAMLProvidersForTenant(realWorkspaceID, clientID...)
	if err != nil {
		log.Printf("Warning: Failed to get SAML providers: %v", err)
	} else {
		allProviders = append(allProviders, samlProviders...)
	}

	for i := 0; i < len(allProviders)-1; i++ {
		for j := i + 1; j < len(allProviders); j++ {
			if allProviders[i].SortOrder > allProviders[j].SortOrder {
				allProviders[i], allProviders[j] = allProviders[j], allProviders[i]
			}
		}
	}
	return allProviders, nil
}

// FilterProvidersForApplication applies the same default-allow semantics used
// by the runtime OIDC and SAML initiate gates. When an Application has no
// explicit policies, every active workspace provider remains available. Once
// any policy exists, only explicitly enabled providers are advertised.
func (s *OAuthLoginService) FilterProvidersForApplication(workspaceID, applicationID string, providers []Provider) ([]Provider, error) {
	if applicationID == "" || len(providers) == 0 {
		return providers, nil
	}

	var policyCount int64
	if err := config.DB.Table("application_identity_provider_policies").
		Where("workspace_id = ? AND application_id = ?", workspaceID, applicationID).
		Count(&policyCount).Error; err != nil {
		return nil, fmt.Errorf("count application IDP policies: %w", err)
	}
	if policyCount == 0 {
		return providers, nil
	}

	type enabledProvider struct {
		ProviderType string
		ProviderName string
	}
	var enabledRows []enabledProvider
	if err := config.DB.
		Table("application_identity_provider_policies p").
		Select(`ip.provider_type,
		        COALESCE(op.provider_name, sp.provider_name) AS provider_name`).
		Joins("JOIN identity_providers ip ON ip.id = p.identity_provider_id").
		Joins("LEFT JOIN oidc_providers op ON ip.provider_type = 'oidc' AND op.id = ip.oidc_provider_id").
		Joins("LEFT JOIN saml_providers sp ON ip.provider_type = 'saml' AND sp.id = ip.saml_provider_id").
		Where("p.workspace_id = ? AND p.application_id = ? AND p.enabled = ?", workspaceID, applicationID, true).
		Where("ip.workspace_id = ? AND ip.status <> 'disabled'", workspaceID).
		Scan(&enabledRows).Error; err != nil {
		return nil, fmt.Errorf("list enabled application IDPs: %w", err)
	}

	enabled := make(map[string]struct{}, len(enabledRows))
	for _, row := range enabledRows {
		enabled[strings.ToLower(row.ProviderType)+"\x00"+strings.ToLower(row.ProviderName)] = struct{}{}
	}

	filtered := make([]Provider, 0, len(providers))
	for _, provider := range providers {
		key := strings.ToLower(provider.Type) + "\x00" + strings.ToLower(provider.ProviderName)
		if _, ok := enabled[key]; ok {
			filtered = append(filtered, provider)
		}
	}
	return filtered, nil
}

// GetSAMLProvider retrieves a specific SAML provider by name within the
// workspace. v4: client_id has been dropped from saml_providers — the
// variadic clientID parameter is kept for source compatibility but ignored.
func (s *OAuthLoginService) GetSAMLProvider(workspaceID, providerName string, _ ...string) (*SAMLProvider, error) {
	db := config.DB

	providerName = strings.ToLower(strings.TrimSpace(providerName))
	var provider SAMLProvider
	if err := db.Where("workspace_id = ? AND provider_name = ?", workspaceID, providerName).
		First(&provider).Error; err != nil {
		return nil, fmt.Errorf("SAML provider not found: %w", err)
	}
	return &provider, nil
}

// CreateSAMLRequest creates a SAML authentication request
func (s *OAuthLoginService) CreateSAMLRequest(provider *SAMLProvider, loginChallenge string) (string, string, error) {
	requestID := fmt.Sprintf("_%s", uuid.New().String())
	issueInstant := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	// Workspace-scoped SP entity / ACS URL. Per-Application restriction is
	// expressed via application_identity_provider_policies, not URL paths.
	spEntityID := fmt.Sprintf("%s/saml/metadata/%s", s.cfg.BaseURL, provider.WorkspaceID.String())
	acsURL := fmt.Sprintf("%s/saml/acs/%s", s.cfg.BaseURL, provider.WorkspaceID.String())

	authnRequest := SAMLAuthnRequest{
		ID:                          requestID,
		Version:                     "2.0",
		IssueInstant:                issueInstant,
		Destination:                 provider.SSOURL,
		AssertionConsumerServiceURL: acsURL,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Issuer:                      SAMLIssuer{Value: spEntityID},
		NameIDPolicy: SAMLNameIDPolicy{
			Format:      provider.NameIDFormat,
			AllowCreate: true,
		},
	}

	xmlBytes, err := xml.MarshalIndent(authnRequest, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal SAML request: %w", err)
	}

	xmlString := xml.Header + string(xmlBytes)

	var deflatedBuf bytes.Buffer
	deflater, err := flate.NewWriter(&deflatedBuf, flate.DefaultCompression)
	if err != nil {
		return "", "", fmt.Errorf("failed to create deflater: %w", err)
	}
	if _, err := deflater.Write([]byte(xmlString)); err != nil {
		return "", "", fmt.Errorf("failed to deflate SAML request: %w", err)
	}
	if err := deflater.Close(); err != nil {
		return "", "", fmt.Errorf("failed to close deflater: %w", err)
	}

	samlRequest := base64.StdEncoding.EncodeToString(deflatedBuf.Bytes())
	// Relay state encodes (loginChallenge, providerName, workspaceID).
	// Per-Application restriction is enforced at initiate via
	// application_identity_provider_policies, not via the relay state.
	relayState := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s:%s",
		loginChallenge, provider.ProviderName, provider.WorkspaceID.String())))

	db := config.DB
	samlReq := SAMLRequest{
		ID:             requestID,
		LoginChallenge: loginChallenge,
		WorkspaceID:    provider.WorkspaceID,
		ProviderName:   provider.ProviderName,
		RelayState:     relayState,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(10 * time.Minute),
	}

	if err := db.Create(&samlReq).Error; err != nil {
		return "", "", fmt.Errorf("failed to store SAML request: %w", err)
	}
	return samlRequest, relayState, nil
}

// ValidateSAMLResponse validates and parses a SAML response
// ValidateSAMLResponse parses + validates the SAML assertion. Returns
// (assertion, loginChallenge, providerName, workspaceID, err).
//
// v4: client_id has been removed from the relay state. Per-Application
// restriction is enforced at initiate via application_identity_provider_policies.
func (s *OAuthLoginService) ValidateSAMLResponse(samlResponse string, relayState string) (*SAMLAssertion, string, string, string, error) {
	relayBytes, err := base64.StdEncoding.DecodeString(relayState)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("invalid relay state: %w", err)
	}

	relayParts := []string{}
	current := ""
	for _, b := range []byte(relayBytes) {
		if b == ':' {
			relayParts = append(relayParts, current)
			current = ""
		} else {
			current += string(b)
		}
	}
	relayParts = append(relayParts, current)

	if len(relayParts) < 3 {
		return nil, "", "", "", fmt.Errorf("invalid relay state format, expected 3 parts, got %d", len(relayParts))
	}

	loginChallenge := relayParts[0]
	providerName := relayParts[1]
	workspaceID := relayParts[2]

	responseBytes, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("failed to decode SAML response: %w", err)
	}

	var samlResp SAMLResponseEnvelope
	if err := xml.Unmarshal(responseBytes, &samlResp); err != nil {
		return nil, "", "", "", fmt.Errorf("failed to unmarshal SAML response: %w", err)
	}

	if samlResp.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return nil, "", "", "", fmt.Errorf("SAML authentication failed: %s", samlResp.Status.StatusCode.Value)
	}

	// Re-validate workspace IDP is still active. Pulled through the same
	// workspace-gated path used at initiate — if the operator disabled the
	// provider mid-flow, reject the callback.
	provider, err := s.GetSAMLProvider(workspaceID, providerName)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("SAML provider lookup failed: %w", err)
	}
	if !provider.IsActive {
		return nil, "", "", "", fmt.Errorf("SAML provider %q is not active", providerName)
	}
	responseEntityID := samlResp.Assertion.Issuer.Value
	if responseEntityID != provider.EntityID {
		return nil, "", "", "", fmt.Errorf("SAML entity ID validation failed: response from unexpected identity provider")
	}

	nameID := trimSpace(samlResp.Assertion.Subject.NameID.Value)
	attributes := make(map[string]interface{})
	email, firstName, lastName := "", "", ""

	for _, attr := range samlResp.Assertion.AttributeStatement.Attributes {
		attrName := attr.Name
		var attrValue string
		if len(attr.Values) > 0 {
			attrValue = trimSpace(attr.Values[0].Value)
		}
		attributes[attrName] = attrValue

		switch attrName {
		case "email", "emailAddress", "mail", "urn:oid:0.9.2342.19200300.100.1.3":
			email = attrValue
		case "givenName", "firstName", "urn:oid:2.5.4.42":
			firstName = attrValue
		case "surname", "lastName", "sn", "urn:oid:2.5.4.4":
			lastName = attrValue
		}
	}

	if email == "" {
		email = nameID
	}

	return &SAMLAssertion{
		NameID:     nameID,
		Email:      email,
		FirstName:  firstName,
		LastName:   lastName,
		Attributes: attributes,
	}, loginChallenge, providerName, workspaceID, nil
}

// GetOrCreateSPCertificate gets or creates SP certificate for tenant
func (s *OAuthLoginService) GetOrCreateSPCertificate(workspaceID uuid.UUID) (*SAMLSPCertificate, error) {
	db := config.DB

	var cert SAMLSPCertificate
	err := db.Where("workspace_id = ?", workspaceID).First(&cert).Error
	if err == nil {
		return &cert, nil
	}
	if err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("failed to query certificate: %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	encryptedPrivateKey := string(privateKeyPEM)
	if config.VaultClient != nil {
		encrypted, err := encryptPrivateKeyWithVault(workspaceID.String(), string(privateKeyPEM))
		if err != nil {
			log.Printf("WARNING: Failed to encrypt private key with Vault: %v. Storing plaintext.", err)
		} else {
			encryptedPrivateKey = encrypted
		}
	} else {
		log.Printf("WARNING: Vault not available, storing SAML private key in plaintext")
	}

	newCert := SAMLSPCertificate{
		WorkspaceID: workspaceID,
		Certificate: string(certPEM),
		PrivateKey:  encryptedPrivateKey,
		ExpiresAt:   time.Now().AddDate(1, 0, 0),
	}

	if err := db.Create(&newCert).Error; err != nil {
		return nil, fmt.Errorf("failed to store certificate: %w", err)
	}
	return &newCert, nil
}

// GenerateSAMLMetadata generates SP metadata XML for a tenant and client
// GenerateSAMLMetadata returns workspace-scoped SP metadata XML.
// v4: client_id is no longer in the metadata URL — per-Application
// restriction is policy-table driven, not URL-encoded.
func (s *OAuthLoginService) GenerateSAMLMetadata(workspaceID uuid.UUID) (string, error) {
	cert, err := s.GetOrCreateSPCertificate(workspaceID)
	if err != nil {
		return "", fmt.Errorf("failed to get SP certificate: %w", err)
	}

	entityID := fmt.Sprintf("%s/saml/metadata/%s", s.cfg.BaseURL, workspaceID.String())
	acsURLShared := fmt.Sprintf("%s/saml/acs", s.cfg.BaseURL)
	acsURLWorkspace := fmt.Sprintf("%s/saml/acs/%s", s.cfg.BaseURL, workspaceID.String())
	certData := extractCertificateData(cert.Certificate)

	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="%s">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>%s</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>%s</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                 Location="%s"
                                 index="1"
                                 isDefault="true" />
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                 Location="%s"
                                 index="2" />
  </md:SPSSODescriptor>
</md:EntityDescriptor>`, entityID, certData, certData, acsURLWorkspace, acsURLShared)

	return metadata, nil
}

// Legacy CreateSAMLProvider / UpdateSAMLProvider / DeleteSAMLProvider methods
// have been removed. SAML provider lifecycle is owned by
// services.IdentityProviderService — see CreateSAML / UpdateStatus / Delete.

// XML helper functions

func extractCertificateData(pemCert string) string {
	lines := []string{}
	for _, line := range splitLines(pemCert) {
		trimmed := trimSpace(line)
		if trimmed != "" && !hasPrefix(trimmed, "-----") {
			lines = append(lines, trimmed)
		}
	}
	result := ""
	for _, line := range lines {
		result += line
	}
	return result
}

func splitLines(s string) []string {
	var lines []string
	current := ""
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, current)
			current = ""
		} else if s[i] != '\r' {
			current += string(s[i])
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
