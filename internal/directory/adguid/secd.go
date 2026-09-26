package adguid

import (
	"encoding/binary"
	"fmt"
)

// Security-descriptor control and ACE type values used to read a DACL.
// The LDAP value of msDS-AllowedToActOnBehalfOfOtherIdentity is a
// self-relative security descriptor. Only trustee SIDs are returned; the
// descriptor bytes are not retained.
const (
	sdRevision = 1

	seDACLPresent  = 0x0004
	seSelfRelative = 0x8000

	aceAccessAllowed        = 0x00
	aceAccessDenied         = 0x01
	aceAccessAllowedObject  = 0x05
	aceAccessDeniedObject   = 0x06
	aceObjectTypePresent    = 0x00000001
	aceInheritedTypePresent = 0x00000002
)

// DACLSIDs returns the trustee SIDs of the discretionary ACL. Owner and
// group SIDs are not trustees and are not returned. A descriptor with no
// DACL yields an empty list. A truncated or non-self-relative descriptor
// is an error.
func DACLSIDs(sd []byte) ([]string, error) {
	if len(sd) < 20 {
		return nil, fmt.Errorf("security descriptor too short: %d bytes", len(sd))
	}
	if sd[0] != sdRevision {
		return nil, fmt.Errorf("unsupported security descriptor revision %d", sd[0])
	}
	control := binary.LittleEndian.Uint16(sd[2:4])
	if control&seSelfRelative == 0 {
		return nil, fmt.Errorf("security descriptor is not self-relative")
	}
	if control&seDACLPresent == 0 {
		return nil, nil
	}
	off := binary.LittleEndian.Uint32(sd[16:20])
	if off == 0 {
		return nil, nil
	}
	if int(off) > len(sd) || len(sd)-int(off) < 8 {
		return nil, fmt.Errorf("dacl offset %d outside descriptor of %d bytes", off, len(sd))
	}
	dacl := sd[off:]
	count := int(binary.LittleEndian.Uint16(dacl[4:6]))
	pos := 8
	seen := map[string]bool{}
	var out []string
	for i := 0; i < count; i++ {
		if pos+4 > len(dacl) {
			return nil, fmt.Errorf("ace %d header truncated", i)
		}
		aceType := dacl[pos]
		aceSize := int(binary.LittleEndian.Uint16(dacl[pos+2 : pos+4]))
		if aceSize < 4 || pos+aceSize > len(dacl) {
			return nil, fmt.Errorf("ace %d size %d invalid", i, aceSize)
		}
		ace := dacl[pos : pos+aceSize]
		sid, ok, err := aceTrustee(aceType, ace)
		if err != nil {
			return nil, fmt.Errorf("ace %d: %w", i, err)
		}
		if ok && !seen[sid] {
			seen[sid] = true
			out = append(out, sid)
		}
		pos += aceSize
	}
	return out, nil
}

// aceTrustee parses the SID from an access-allowed or access-denied ACE,
// including the object forms. Other ACE types are skipped.
func aceTrustee(aceType byte, ace []byte) (string, bool, error) {
	var sidOff int
	switch aceType {
	case aceAccessAllowed, aceAccessDenied:
		sidOff = 8 // header 4 + mask 4
	case aceAccessAllowedObject, aceAccessDeniedObject:
		if len(ace) < 12 {
			return "", false, fmt.Errorf("object ace truncated")
		}
		flags := binary.LittleEndian.Uint32(ace[8:12])
		sidOff = 12
		if flags&aceObjectTypePresent != 0 {
			sidOff += 16
		}
		if flags&aceInheritedTypePresent != 0 {
			sidOff += 16
		}
	default:
		return "", false, nil
	}
	if sidOff >= len(ace) {
		return "", false, fmt.Errorf("ace has no sid")
	}
	sid, err := ParseSID(ace[sidOff:])
	if err != nil {
		return "", false, err
	}
	return sid, true, nil
}

// SelfRelativeSD builds a self-relative descriptor whose DACL has one
// access-allowed ACE per SID. Owner and SACL are absent. It exists so tests
// and the Samba fixture can plant a resource-based constrained delegation
// descriptor without storing a real ACL.
func SelfRelativeSD(sids []string) ([]byte, error) {
	var aces []byte
	for _, sid := range sids {
		raw, err := SIDBytes(sid)
		if err != nil {
			return nil, err
		}
		size := 8 + len(raw)
		for size%4 != 0 {
			size++
		}
		ace := make([]byte, size)
		ace[0] = aceAccessAllowed
		binary.LittleEndian.PutUint16(ace[2:4], uint16(size))
		binary.LittleEndian.PutUint32(ace[4:8], 0x00020000) // GENERIC_READ, irrelevant
		copy(ace[8:], raw)
		aces = append(aces, ace...)
	}
	dacl := make([]byte, 8+len(aces))
	dacl[0] = 2 // ACL revision
	binary.LittleEndian.PutUint16(dacl[2:4], uint16(len(dacl)))
	binary.LittleEndian.PutUint16(dacl[4:6], uint16(len(sids)))
	copy(dacl[8:], aces)

	sd := make([]byte, 20+len(dacl))
	sd[0] = sdRevision
	binary.LittleEndian.PutUint16(sd[2:4], seDACLPresent|seSelfRelative)
	binary.LittleEndian.PutUint32(sd[16:20], 20)
	copy(sd[20:], dacl)
	return sd, nil
}
