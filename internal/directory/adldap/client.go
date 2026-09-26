package adldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"github.com/authsec-ai/authsec/internal/directory/adguid"
	"github.com/go-ldap/ldap/v3"
)

// Conn is the directory connection. Password is the decrypted bind secret and
// is never written to a snapshot, a row or a log line.
type Conn struct {
	Server         string
	Username       string
	Password       string
	UseSSL         bool
	StartTLS       bool
	SkipVerify     bool
	CABundle       string
	PageSize       int
	Production     bool
	ChangeTracking bool
	TrackingMode   string // "usn". "dirsync" is rejected by the API.
}

// LDAPReader talks to one domain controller.
type LDAPReader struct {
	Conn Conn
	// Dial overrides the network dial in tests.
	Dial func(Conn) (Searcher, func(), error)
}

// Identity is the forest/domain anchor taken from rootDSE and the domain object.
type Identity struct {
	ForestID     string
	DomainDN     string
	DomainSID    string
	DNSHostName  string
	InvocationID string
}

// ClassRead is one object class inside one scope.
type ClassRead struct {
	Objects    []Object
	Complete   bool
	Reason     string
	HighestUSN int64
}

// DirectoryIdentity reads rootDSE, the domain SID and the DC invocationID.
func (r *LDAPReader) DirectoryIdentity(ctx context.Context) (Identity, error) {
	s, closeFn, err := r.dial()
	if err != nil {
		return Identity{}, err
	}
	defer closeFn()
	_ = ctx
	root, err := s.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"rootDomainNamingContext", "defaultNamingContext", "dnsHostName", "dsServiceName"},
		nil,
	))
	if err != nil {
		return Identity{}, fmt.Errorf("rootDSE: %w", err)
	}
	if len(root.Entries) == 0 {
		return Identity{}, fmt.Errorf("rootDSE returned no entry")
	}
	e := root.Entries[0]
	id := Identity{
		ForestID:    e.GetAttributeValue("rootDomainNamingContext"),
		DomainDN:    e.GetAttributeValue("defaultNamingContext"),
		DNSHostName: e.GetAttributeValue("dnsHostName"),
	}
	if id.ForestID == "" {
		id.ForestID = id.DomainDN
	}
	if id.DomainDN != "" {
		dom, err := s.Search(ldap.NewSearchRequest(
			id.DomainDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
			"(objectClass=*)",
			[]string{"objectSid"},
			nil,
		))
		if err == nil && len(dom.Entries) > 0 {
			if sid, err := parseSIDAttr(dom.Entries[0]); err == nil {
				id.DomainSID = sid
			}
		}
	}
	if ds := e.GetAttributeValue("dsServiceName"); ds != "" {
		ntds, err := s.Search(ldap.NewSearchRequest(
			ds, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
			"(objectClass=*)",
			[]string{"invocationID"},
			nil,
		))
		if err == nil && len(ntds.Entries) > 0 {
			raw := ntds.Entries[0].GetRawAttributeValue("invocationID")
			if text, err := formatGUID(raw); err == nil {
				id.InvocationID = text
			}
		}
	}
	return id, nil
}

// ReadClass runs one paged search. usnFloor 0 is a full read of the class.
func (r *LDAPReader) ReadClass(ctx context.Context, baseDN, class string, usnFloor int64, pageSize int) (ClassRead, error) {
	_ = ctx
	filter, err := ClassFilter(class, usnFloor)
	if err != nil {
		return ClassRead{}, err
	}
	s, closeFn, err := r.dial()
	if err != nil {
		return ClassRead{}, err
	}
	defer closeFn()
	if pageSize <= 0 {
		pageSize = r.Conn.PageSize
	}
	if pageSize <= 0 {
		pageSize = 500
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	entries, outcome := PagedSearch(s, baseDN, filter, uint32(pageSize))
	out := ClassRead{Complete: outcome.Complete, Reason: outcome.Reason}
	for _, e := range entries {
		obj, ok := ParseEntry(e, class)
		if !ok {
			continue
		}
		out.Objects = append(out.Objects, obj)
		if obj.USNChanged > out.HighestUSN {
			out.HighestUSN = obj.USNChanged
		}
	}
	return out, nil
}

func (r *LDAPReader) dial() (Searcher, func(), error) {
	if r.Dial != nil {
		return r.Dial(r.Conn)
	}
	conn, err := Dial(r.Conn)
	if err != nil {
		return nil, nil, err
	}
	return conn, func() { conn.Close() }, nil
}

// Dial binds to the directory with the TLS policy from PlanTLS.
func Dial(c Conn) (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error
	useTLS := c.UseSSL || c.StartTLS
	if useTLS {
		host, _, splitErr := net.SplitHostPort(c.Server)
		if splitErr != nil {
			host = c.Server
		}
		plan, planErr := PlanTLS(TLSOptions{
			ServerName: host,
			SkipVerify: c.SkipVerify,
			CAPEM:      []byte(c.CABundle),
			Production: c.Production,
		})
		if planErr != nil {
			return nil, planErr
		}
		if plan.Warning != "" {
			log.Printf("WARNING: %s (server %s)", plan.Warning, c.Server)
		}
		if c.UseSSL {
			conn, err = ldap.DialTLS("tcp", c.Server, plan.Config)
		} else {
			conn, err = ldap.Dial("tcp", c.Server)
			if err != nil {
				return nil, fmt.Errorf("dial AD: %w", err)
			}
			if err = conn.StartTLS(plan.Config); err != nil {
				conn.Close()
				return nil, fmt.Errorf("StartTLS: %w", err)
			}
		}
	} else {
		conn, err = ldap.Dial("tcp", c.Server)
	}
	if err != nil {
		return nil, fmt.Errorf("dial AD: %w", err)
	}
	if err := conn.Bind(c.Username, c.Password); err != nil {
		conn.Close()
		return nil, fmt.Errorf("bind AD: %w", err)
	}
	return conn, nil
}

// Handshake checks the TLS certificate without an LDAP bind. Tests use it to
// prove an untrusted CA fails and a provided CA passes.
func Handshake(addr string, cfg *tls.Config) error {
	d := tls.Dialer{Config: cfg}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

func parseSIDAttr(e *ldap.Entry) (string, error) {
	raw := e.GetRawAttributeValue("objectSid")
	if len(raw) == 0 {
		return "", fmt.Errorf("objectSid missing")
	}
	return adguid.ParseSID(raw)
}

func formatGUID(raw []byte) (string, error) {
	if len(raw) != 16 {
		return "", fmt.Errorf("invocationID missing")
	}
	// invocationID uses the same mixed endianness as objectGUID.
	return adguid.Format(raw)
}
