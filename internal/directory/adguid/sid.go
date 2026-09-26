package adguid

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// ParseSID renders a binary Windows SID as S-1-5-21-… text.
//
// Layout: revision (1 byte), sub-authority count (1), identifier authority
// (6 bytes, big-endian), then count little-endian uint32 sub-authorities.
func ParseSID(b []byte) (string, error) {
	if len(b) < 8 {
		return "", fmt.Errorf("sid too short: %d bytes", len(b))
	}
	rev := b[0]
	if rev != 1 {
		return "", fmt.Errorf("unsupported sid revision %d", rev)
	}
	count := int(b[1])
	if count < 0 || len(b) != 8+4*count {
		return "", fmt.Errorf("sid length %d does not match sub-authority count %d", len(b), count)
	}
	var auth uint64
	for i := 0; i < 6; i++ {
		auth = auth<<8 | uint64(b[2+i])
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", rev, auth)
	for i := 0; i < count; i++ {
		off := 8 + 4*i
		sub := binary.LittleEndian.Uint32(b[off : off+4])
		fmt.Fprintf(&sb, "-%d", sub)
	}
	return sb.String(), nil
}

// SIDBytes parses S-1-… text back into the binary form ParseSID accepts.
func SIDBytes(s string) ([]byte, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 3 || parts[0] != "S" {
		return nil, fmt.Errorf("sid %q: want S-<rev>-<authority>[-<sub>...]", s)
	}
	rev64, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil || rev64 != 1 {
		return nil, fmt.Errorf("sid %q: revision must be 1", s)
	}
	auth, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("sid %q: authority: %w", s, err)
	}
	subs := parts[3:]
	if len(subs) > 15 {
		return nil, fmt.Errorf("sid %q: too many sub-authorities", s)
	}
	out := make([]byte, 8+4*len(subs))
	out[0] = 1
	out[1] = byte(len(subs))
	for i := 5; i >= 0; i-- {
		out[2+i] = byte(auth & 0xff)
		auth >>= 8
	}
	for i, sub := range subs {
		n, err := strconv.ParseUint(sub, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("sid %q: sub-authority %q: %w", s, sub, err)
		}
		binary.LittleEndian.PutUint32(out[8+4*i:], uint32(n))
	}
	return out, nil
}
