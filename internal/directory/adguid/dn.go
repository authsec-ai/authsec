package adguid

import (
	"strings"
)

// CommonName returns the CN of the first RDN, or "" when the DN does not
// start with CN=. The returned value is display-only. Callers that need the
// group's identity keep the full DN: a rename of the CN is not a new object,
// and two groups can share a CN in different OUs.
func CommonName(dn string) string {
	rdns := splitRDN(dn)
	if len(rdns) == 0 {
		return ""
	}
	typ, val, ok := splitAVA(rdns[0])
	if !ok || !strings.EqualFold(typ, "CN") {
		return ""
	}
	return unescape(val)
}

func splitRDN(dn string) []string {
	var parts []string
	var b strings.Builder
	escaped := false
	for _, r := range dn {
		if escaped {
			b.WriteRune('\\')
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == ',' {
			parts = append(parts, strings.TrimSpace(b.String()))
			b.Reset()
			continue
		}
		b.WriteRune(r)
	}
	if escaped {
		b.WriteRune('\\')
	}
	if strings.TrimSpace(b.String()) != "" {
		parts = append(parts, strings.TrimSpace(b.String()))
	}
	return parts
}

func splitAVA(rdn string) (typ, val string, ok bool) {
	escaped := false
	for i, r := range rdn {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '=' {
			return strings.TrimSpace(rdn[:i]), rdn[i+1:], true
		}
	}
	return "", "", false
}

func unescape(s string) string {
	var b strings.Builder
	escaped := false
	hex := ""
	for _, r := range s {
		if hex != "" {
			hex += string(r)
			if len(hex) == 2 {
				hi := unhex(rune(hex[0]))
				lo := unhex(rune(hex[1]))
				if hi >= 0 && lo >= 0 {
					b.WriteByte(byte(hi<<4 | lo))
				} else {
					b.WriteString(hex)
				}
				hex = ""
			}
			continue
		}
		if escaped {
			if isHex(r) {
				hex = string(r)
			} else {
				b.WriteRune(r)
			}
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		b.WriteRune(r)
	}
	if escaped {
		b.WriteRune('\\')
	}
	if hex != "" {
		b.WriteString(hex)
	}
	return b.String()
}

func isHex(r rune) bool { return unhex(r) >= 0 }

func unhex(r rune) int {
	switch {
	case r >= '0' && r <= '9':
		return int(r - '0')
	case r >= 'a' && r <= 'f':
		return int(r-'a') + 10
	case r >= 'A' && r <= 'F':
		return int(r-'A') + 10
	default:
		return -1
	}
}
