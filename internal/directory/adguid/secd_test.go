package adguid

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDACLSIDsAccessAllowedAndObjectACE(t *testing.T) {
	want := []string{"S-1-5-21-1-2-3-1105", "S-1-5-32-544"}
	sd, err := SelfRelativeSD(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DACLSIDs(sd)
	if err != nil {
		t.Fatal(err)
	}
	if stringsJoin(got) != stringsJoin(want) {
		t.Fatalf("SIDs = %v", got)
	}

	// Owner SID must not be reported as a delegation principal.
	owner, err := SIDBytes("S-1-5-21-1-2-3-500")
	if err != nil {
		t.Fatal(err)
	}
	withOwner := make([]byte, 20+len(owner)+len(sd)-20)
	copy(withOwner, sd)
	binary.LittleEndian.PutUint32(withOwner[4:8], 20)                      // owner
	binary.LittleEndian.PutUint32(withOwner[16:20], uint32(20+len(owner))) // dacl
	copy(withOwner[20:], owner)
	copy(withOwner[20+len(owner):], sd[20:])
	got, err = DACLSIDs(withOwner)
	if err != nil {
		t.Fatal(err)
	}
	if stringsJoin(got) != stringsJoin(want) {
		t.Fatalf("owner leaked into trustees: %v", got)
	}

	objectACE := objectACEWithSID(want[0])
	got, err = DACLSIDs(objectACE)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("object ace SIDs = %v", got)
	}
}

func TestDACLSIDsRejectsTruncated(t *testing.T) {
	sd, err := SelfRelativeSD([]string{"S-1-5-32-544"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DACLSIDs(sd[:10]); err == nil {
		t.Fatal("truncated descriptor must fail")
	}
	cut := append([]byte(nil), sd...)
	cut = cut[:len(cut)-4]
	if _, err := DACLSIDs(cut); err == nil {
		t.Fatal("truncated ACE must fail")
	}
	if sids, err := DACLSIDs(nil); err == nil || sids != nil {
		t.Fatalf("empty = %v %v", sids, err)
	}
}

func objectACEWithSID(sid string) []byte {
	raw, err := SIDBytes(sid)
	if err != nil {
		panic(err)
	}
	// header 4 + mask 4 + flags 4 + object-type GUID 16 + SID
	aceSize := 8 + 4 + 16 + len(raw)
	for aceSize%4 != 0 {
		aceSize++
	}
	ace := make([]byte, aceSize)
	ace[0] = aceAccessAllowedObject
	binary.LittleEndian.PutUint16(ace[2:4], uint16(aceSize))
	binary.LittleEndian.PutUint32(ace[8:12], aceObjectTypePresent)
	copy(ace[12:28], bytes.Repeat([]byte{0xab}, 16))
	copy(ace[28:], raw)

	dacl := make([]byte, 8+len(ace))
	dacl[0] = 2
	binary.LittleEndian.PutUint16(dacl[2:4], uint16(len(dacl)))
	binary.LittleEndian.PutUint16(dacl[4:6], 1)
	copy(dacl[8:], ace)

	sd := make([]byte, 20+len(dacl))
	sd[0] = sdRevision
	binary.LittleEndian.PutUint16(sd[2:4], seDACLPresent|seSelfRelative)
	binary.LittleEndian.PutUint32(sd[16:20], 20)
	copy(sd[20:], dacl)
	return sd
}

func stringsJoin(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
