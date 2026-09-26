package igagraph

import (
	"strings"
	"testing"
)

func TestADIdentityKeyEscapesAndRenameKeepsKey(t *testing.T) {
	forest := "DC=authsec,DC=test"
	guid := "03020100-0504-0706-0809-0A0B0C0D0E0F"
	key, err := ADIdentityKey(forest, guid)
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := ADIdentityKey(forest, strings.ToLower(guid))
	if err != nil {
		t.Fatal(err)
	}
	if key != renamed {
		t.Fatalf("case or rename must not change the key:\n%s\n%s", key, renamed)
	}
	// The DN is not an input. A modrdn keeps this key; the SID is not in it.
	parts := strings.Split(key, Sep)
	if len(parts) != 3 || parts[0] != "ad" || parts[1] != forest || parts[2] != strings.ToLower(guid) {
		t.Fatalf("key segments = %#v", parts)
	}
	other, err := ADIdentityKey(forest, "11111111-1111-1111-1111-111111111111")
	if err != nil || other == key {
		t.Fatal("a different objectGUID must be a different key")
	}

	// A forest name containing the unit separator must not invent an extra segment.
	hostile := "DC=a" + Sep + "b,DC=test"
	hostileKey, err := ADIdentityKey(hostile, guid)
	if err != nil {
		t.Fatal(err)
	}
	if segs := strings.Split(hostileKey, Sep); len(segs) != 3 {
		t.Fatalf("escaped forest split into %d segments: %q", len(segs), hostileKey)
	}
	// A literal "%1F" is not the same segment as an encoded separator.
	literal, err := ADIdentityKey("DC=a%1Fb,DC=test", guid)
	if err != nil {
		t.Fatal(err)
	}
	if literal == hostileKey {
		t.Fatal("percent-encoded separator collided with a literal %1F")
	}

	// Path separators are encoded so a DN cannot be read as a path join.
	pathKey, err := ADIdentityKey(`DC=a/b\c,DC=test`, guid)
	if err != nil {
		t.Fatal(err)
	}
	seg := strings.Split(pathKey, Sep)[1]
	if strings.Contains(seg, "/") || strings.Contains(seg, `\`) {
		t.Fatalf("path bytes survived escaping: %q", seg)
	}

	if _, err := ADIdentityKey("", guid); err == nil {
		t.Fatal("empty forest must not produce a key")
	}
	if _, err := ADIdentityKey(forest, ""); err == nil {
		t.Fatal("empty GUID must not produce a key")
	}
}

func TestEscapeSegmentRoundTripDistinct(t *testing.T) {
	a := EscapeSegment("a" + Sep + "b")
	b := EscapeSegment("a")
	c := EscapeSegment("b" + Sep + "c")
	if Key("ad", a, EscapeSegment("c")) == Key("ad", b, c) {
		t.Fatal("separator inside a segment collided with a segment boundary")
	}
}
