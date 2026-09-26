package adldap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestAllowlistExcludesSecrets(t *testing.T) {
	for _, name := range InventoryAttributes() {
		if Denied(name) {
			t.Fatalf("allowlist contains denied attribute %s", name)
		}
	}
	for _, name := range DeniedAttributes {
		if Allowed(name) {
			t.Fatalf("denied attribute %s is allowed", name)
		}
	}
	if !Denied("msDS-ManagedPassword") || !Denied("UNICODEPWD") {
		t.Fatal("denylist must be case-insensitive")
	}
}

func TestClassFilterIncludesDisabledAndNoMail(t *testing.T) {
	f, err := ClassFilter(ClassUser, 0)
	if err != nil {
		t.Fatal(err)
	}
	if contains(f, "1.2.840.113556.1.4.803:=2") {
		t.Fatal("inventory user filter must not exclude disabled accounts")
	}
	if contains(f, "mail") {
		t.Fatal("inventory user filter must not require mail")
	}
	inc, err := ClassFilter(ClassGroup, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(inc, "uSNChanged>=42") {
		t.Fatalf("incremental filter = %s", inc)
	}
	if _, err := ClassFilter("objectClass=*)(uid=*", 0); err == nil {
		t.Fatal("unknown class must be rejected, not interpolated")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

type scriptedSearch struct {
	calls []ldap.SearchRequest
	fn    func(req *ldap.SearchRequest) (*ldap.SearchResult, error)
}

func (s *scriptedSearch) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	cp := *req
	cp.Attributes = append([]string(nil), req.Attributes...)
	s.calls = append(s.calls, cp)
	return s.fn(req)
}

func TestPagedSearchCompleteAndSizeLimitPartial(t *testing.T) {
	page := 0
	s := &scriptedSearch{fn: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		page++
		if page == 1 {
			return &ldap.SearchResult{
				Entries:  []*ldap.Entry{{DN: "CN=one"}},
				Controls: []ldap.Control{&ldap.ControlPaging{Cookie: []byte("more")}},
			}, nil
		}
		return &ldap.SearchResult{
			Entries:  []*ldap.Entry{{DN: "CN=two"}},
			Controls: []ldap.Control{&ldap.ControlPaging{Cookie: nil}},
		}, nil
	}}
	entries, out := PagedSearch(s, "OU=Svc,DC=authsec,DC=test", "(objectClass=user)", 2)
	if !out.Complete || len(entries) != 2 {
		t.Fatalf("complete read: %+v entries=%d", out, len(entries))
	}
	if len(s.calls) != 2 {
		t.Fatalf("pages = %d", len(s.calls))
	}
	for _, c := range s.calls {
		for _, a := range c.Attributes {
			if Denied(a) {
				t.Fatalf("search requested denied attribute %s", a)
			}
		}
		if !sameSet(c.Attributes, InventoryAttributes()) {
			t.Fatalf("attributes = %v", c.Attributes)
		}
	}

	limited := &scriptedSearch{fn: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		cookie := pagingCookie(req)
		if len(cookie) == 0 {
			return &ldap.SearchResult{
				Entries:  []*ldap.Entry{{DN: "CN=kept"}},
				Controls: []ldap.Control{&ldap.ControlPaging{Cookie: []byte("next")}},
			}, nil
		}
		return nil, &ldap.Error{ResultCode: ldap.LDAPResultSizeLimitExceeded, Err: errString("size limit")}
	}}
	kept, out := PagedSearch(limited, "DC=authsec,DC=test", "(objectClass=group)", 1)
	if out.Complete || out.Reason != "size_limit" || len(kept) != 1 {
		t.Fatalf("size limit: %+v kept=%d", out, len(kept))
	}

	ref := &scriptedSearch{fn: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, &ldap.Error{ResultCode: ldap.LDAPResultReferral, Err: errString("referral")}
	}}
	if _, out := PagedSearch(ref, "DC=x", "(objectClass=user)", 10); out.Reason != "referral" || out.Complete {
		t.Fatalf("referral: %+v", out)
	}
	perm := &scriptedSearch{fn: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, &ldap.Error{ResultCode: ldap.LDAPResultInsufficientAccessRights, Err: errString("insufficient access")}
	}}
	if _, out := PagedSearch(perm, "DC=x", "(objectClass=user)", 10); out.Reason != "permission" || out.Complete {
		t.Fatalf("permission: %+v", out)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func pagingCookie(req *ldap.SearchRequest) []byte {
	c := ldap.FindControl(req.Controls, ldap.ControlTypePaging)
	if c == nil {
		return nil
	}
	p, ok := c.(*ldap.ControlPaging)
	if !ok {
		return nil
	}
	return p.Cookie
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPlanReadRecovery(t *testing.T) {
	stored := Cursor{InvocationID: "dc-a", HighestUSN: 100, Mode: "usn"}
	if mode, floor := PlanRead(true, stored, "dc-a"); mode != "incremental" || floor != 100 {
		t.Fatalf("same DC = %s %d", mode, floor)
	}
	if mode, floor := PlanRead(true, stored, "dc-b"); mode != "full" || floor != 0 {
		t.Fatalf("DC change = %s %d", mode, floor)
	}
	if mode, _ := PlanRead(false, stored, "dc-a"); mode != "full" {
		t.Fatalf("tracking off = %s", mode)
	}
	if mode, floor := PlanRead(true, Cursor{}, "dc-a"); mode != "full" || floor != 0 {
		t.Fatalf("empty cursor = %s %d", mode, floor)
	}
	bad := Cursor{Mode: "dirsync", InvocationID: "dc-a", HighestUSN: 9}
	if mode, floor := PlanRead(true, bad, "dc-a"); mode != "full" || floor != 0 {
		t.Fatalf("stored dirsync cursor = %s %d", mode, floor)
	}
}

func TestParseEntryDropsSecretAndKeepsNoMailDisabled(t *testing.T) {
	guid := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	sid := []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00}
	e := &ldap.Entry{
		DN: "CN=nomail,OU=Svc,DC=authsec,DC=test",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", ByteValues: [][]byte{guid}},
			{Name: "objectSid", ByteValues: [][]byte{sid}},
			{Name: "sAMAccountName", Values: []string{"nomail"}},
			{Name: "objectClass", Values: []string{"top", "person", "organizationalPerson", "user"}},
			{Name: "userAccountControl", Values: []string{"514"}},
			{Name: "memberOf", Values: []string{"CN=Ops,OU=Groups,DC=authsec,DC=test"}},
			{Name: "servicePrincipalName", Values: []string{"HTTP/invoice.authsec.test"}},
			{Name: "uSNChanged", Values: []string{"77"}},
			{Name: "msDS-ManagedPassword", ByteValues: [][]byte{[]byte("CANARY-SECRET-DO-NOT-LEAK-9")}},
			{Name: "unicodePwd", Values: []string{"nope"}},
		},
	}
	obj, ok := ParseEntry(e, ClassUser)
	if !ok {
		t.Fatal("expected an object")
	}
	if obj.ObjectGUID != "03020100-0504-0706-0809-0a0b0c0d0e0f" {
		t.Fatalf("guid %s", obj.ObjectGUID)
	}
	if obj.Mail != "" || obj.UserPrincipalName != "" {
		t.Fatal("no-mail account must be kept without inventing an address")
	}
	if obj.AccountFlags.Active || !obj.AccountFlags.AccountDisabled {
		t.Fatalf("514 must be disabled: %+v", obj.AccountFlags)
	}
	if obj.MemberOf[0] != "CN=Ops,OU=Groups,DC=authsec,DC=test" || obj.MemberOfDisplay[0] != "Ops" {
		t.Fatalf("group identity = %+v display %+v", obj.MemberOf, obj.MemberOfDisplay)
	}
	if obj.ObjectSID != "S-1-5-32-544" {
		t.Fatalf("sid %s", obj.ObjectSID)
	}
	if obj.Basis != BasisObserved {
		t.Fatalf("basis %s", obj.Basis)
	}
	blob := obj.SAMAccountName + obj.ObjectGUID + obj.DistinguishedName + obj.DisplayName
	for _, secret := range []string{"CANARY-SECRET-DO-NOT-LEAK-9", "unicodePwd", "msDS-ManagedPassword"} {
		if contains(blob, secret) {
			t.Fatalf("parsed object leaked %s", secret)
		}
	}
}

func TestTLSUntrustedFailsProvidedCAPasses(t *testing.T) {
	caCert, caKey, caPEM := newCA(t)
	srv := signServer(t, caCert, caKey)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{srv}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	addr := ln.Addr().String()

	empty := x509.NewCertPool()
	untrusted := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "dc.authsec.test", RootCAs: empty}
	if err := Handshake(addr, untrusted); err == nil {
		t.Fatal("untrusted CA must fail")
	}

	plan, err := PlanTLS(TLSOptions{ServerName: "dc.authsec.test", CAPEM: caPEM})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Config.InsecureSkipVerify {
		t.Fatal("default TLS plan must verify")
	}
	if err := Handshake(addr, plan.Config); err != nil {
		t.Fatalf("provided CA should pass: %v", err)
	}

	if _, err := PlanTLS(TLSOptions{SkipVerify: true, Production: true}); err != ErrSkipVerifyRefused {
		t.Fatalf("production skip verify: %v", err)
	}
	skipped, err := PlanTLS(TLSOptions{ServerName: "dc.authsec.test", SkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if skipped.Warning == "" || !skipped.Config.InsecureSkipVerify {
		t.Fatalf("lab skip verify plan = %+v", skipped)
	}
	if err := Handshake(addr, skipped.Config); err != nil {
		t.Fatalf("skip verify should connect: %v", err)
	}
	if _, err := PlanTLS(TLSOptions{CAPEM: []byte("not a cert")}); err == nil {
		t.Fatal("bad PEM must fail")
	}
}

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AuthSec Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func signServer(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "dc.authsec.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"dc.authsec.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}
