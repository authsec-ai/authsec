// Package adguid converts Active Directory identifiers the way AD stores them.
//
// objectGUID is a 16-byte UUID whose first three fields are little-endian
// (Data1, Data2, Data3). Treating those bytes as an RFC 4122 UUID swaps the
// canonical text. Every importer and the inventory adapter call this package
// so a renamed account still matches the row written by the old importer.
package adguid

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Format renders AD objectGUID bytes as the canonical text form.
//
// The golden vector is bytes 00 01 02 … 0f → 03020100-0504-0706-0809-0a0b0c0d0e0f.
func Format(ad []byte) (string, error) {
	rfc, err := toRFC4122(ad)
	if err != nil {
		return "", err
	}
	u, err := uuid.FromBytes(rfc)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// ToADBytes is the inverse of Format. The byte swap is an involution, so
// converting canonical text back to the on-wire AD order round-trips.
func ToADBytes(canonical string) ([]byte, error) {
	u, err := uuid.Parse(canonical)
	if err != nil {
		return nil, fmt.Errorf("objectGUID %q: %w", canonical, err)
	}
	return toRFC4122(u[:])
}

// LegacyString is the pre-fix rendering: uuid.FromBytes on the raw AD bytes,
// with no endian swap. Stored external_id values written by that code still
// have to match on the next sync.
func LegacyString(ad []byte) (string, error) {
	if len(ad) != 16 {
		return "", fmt.Errorf("objectGUID must be 16 bytes, got %d", len(ad))
	}
	u, err := uuid.FromBytes(ad)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// SwapString flips the endianness of a GUID string. Applying it twice returns
// the original text. It maps a canonical GUID to the legacy stored form and
// back, which is how lookup matches either representation.
func SwapString(s string) (string, error) {
	u, err := uuid.Parse(strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("objectGUID %q: %w", s, err)
	}
	swapped, err := toRFC4122(u[:])
	if err != nil {
		return "", err
	}
	out, err := uuid.FromBytes(swapped)
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

// MatchesEither reports whether stored is the canonical GUID or the legacy
// unswapped rendering of the same 16 bytes. Comparison is case-insensitive.
func MatchesEither(stored, canonical string) bool {
	stored = strings.TrimSpace(stored)
	canonical = strings.TrimSpace(canonical)
	if stored == "" || canonical == "" {
		return false
	}
	if strings.EqualFold(stored, canonical) {
		return true
	}
	legacy, err := SwapString(canonical)
	return err == nil && strings.EqualFold(stored, legacy)
}

// LookupIDs returns the canonical GUID and, when it differs, the legacy form
// that an already-imported user may still be stored under.
func LookupIDs(canonical string) ([]string, error) {
	canonical = strings.ToLower(strings.TrimSpace(canonical))
	if canonical == "" {
		return nil, nil
	}
	if _, err := uuid.Parse(canonical); err != nil {
		return nil, fmt.Errorf("objectGUID %q: %w", canonical, err)
	}
	ids := []string{canonical}
	legacy, err := SwapString(canonical)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(legacy, canonical) {
		ids = append(ids, strings.ToLower(legacy))
	}
	return ids, nil
}

func toRFC4122(ad []byte) ([]byte, error) {
	if len(ad) != 16 {
		return nil, fmt.Errorf("objectGUID must be 16 bytes, got %d", len(ad))
	}
	out := make([]byte, 16)
	// Data1 (uint32) and Data2/Data3 (uint16) are little-endian on the wire.
	binary.BigEndian.PutUint32(out[0:4], binary.LittleEndian.Uint32(ad[0:4]))
	binary.BigEndian.PutUint16(out[4:6], binary.LittleEndian.Uint16(ad[4:6]))
	binary.BigEndian.PutUint16(out[6:8], binary.LittleEndian.Uint16(ad[6:8]))
	copy(out[8:], ad[8:])
	return out, nil
}
