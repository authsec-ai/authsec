package adresolve

import (
	"encoding/base64"
	"testing"

	"github.com/authsec-ai/authsec/internal/directory/adguid"
	"github.com/google/uuid"
)

func TestParseCanonicalSIDAndGUIDByteOrder(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1101"
	rawSID, err := adguid.SIDBytes(sid)
	if err != nil {
		t.Fatal(err)
	}
	wire := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	wantGUID, err := adguid.Format(wire)
	if err != nil {
		t.Fatal(err)
	}
	if wantGUID != "03020100-0504-0706-0809-0a0b0c0d0e0f" {
		t.Fatalf("golden guid %s", wantGUID)
	}
	obs := uuid.New()
	hint, ok := Parse(map[string]any{
		"directory_sid":    base64.StdEncoding.EncodeToString(rawSID),
		"directory_guid":   "000102030405060708090a0b0c0d0e0f",
		"directory_domain": "DC=authsec,DC=test",
		"mapping_source":   "SSSD",
		"name":             "alice",
		"sam_account_name": "alice",
	}, []uuid.UUID{obs})
	if !ok || hint.Unreadable {
		t.Fatalf("hint %+v ok %v", hint, ok)
	}
	if hint.SID != sid {
		t.Fatalf("sid %s", hint.SID)
	}
	if hint.GUID != wantGUID {
		t.Fatalf("guid %s", hint.GUID)
	}
	if hint.MappingSource != SourceSSSD || hint.Domain != "DC=authsec,DC=test" || len(hint.ObservationIDs) != 1 {
		t.Fatalf("hint %+v", hint)
	}
	if Rule(hint.MappingSource) != RuleID+"/sssd" {
		t.Fatal(Rule(hint.MappingSource))
	}

	text, ok := Parse(map[string]any{
		"directory_sid":  "s-1-5-21-1-2-3-1101",
		"directory_guid": wantGUID,
		"mapping_source": "winbind",
	}, nil)
	if !ok || text.Unreadable || text.SID != sid || text.GUID != wantGUID || text.MappingSource != SourceWinbind {
		t.Fatalf("text %+v", text)
	}
}

func TestParseRejectsNameOnlyAndBadIdentifiers(t *testing.T) {
	if _, ok := Parse(map[string]any{"name": "alice", "directory_sid": "S-1-5-21-1-2-3-1101"}, nil); ok {
		t.Fatal("a SID without sssd or winbind is not a mapping")
	}
	if _, ok := Parse(map[string]any{"name": "alice", "mapping_source": "files"}, nil); ok {
		t.Fatal("files is not an authoritative mapping source")
	}
	bad, ok := Parse(map[string]any{"mapping_source": "sssd", "directory_sid": "not-a-sid"}, nil)
	if !ok || !bad.Unreadable || bad.Reason != "bad_sid" {
		t.Fatalf("bad sid %+v", bad)
	}
	none, ok := Parse(map[string]any{"mapping_source": "sssd"}, nil)
	if !ok || !none.Unreadable || none.Reason != "no_identifier" {
		t.Fatalf("empty %+v", none)
	}
	if _, ok := Parse(nil, nil); ok {
		t.Fatal("absent mapping")
	}
}

func TestSelectInstanceByDomainOrSID(t *testing.T) {
	forest := Instance{ID: uuid.New(), ForestID: "DC=authsec,DC=test", DomainSID: "S-1-5-21-1-2-3", DomainDN: "DC=authsec,DC=test", DNSHost: "dc.authsec.test"}
	other := Instance{ID: uuid.New(), ForestID: "DC=other,DC=test", DomainSID: "S-1-5-21-9-9-9", DomainDN: "DC=other,DC=test"}
	got, err := SelectInstance([]Instance{other, forest}, Hint{GUID: "03020100-0504-0706-0809-0a0b0c0d0e0f", Domain: "dc.authsec.test"})
	if err != nil || got.ID != forest.ID {
		t.Fatalf("domain %+v %v", got, err)
	}
	got, err = SelectInstance([]Instance{other, forest}, Hint{SID: "S-1-5-21-1-2-3-1101"})
	if err != nil || got.ID != forest.ID {
		t.Fatalf("sid %+v %v", got, err)
	}
	if DomainSID("S-1-5-21-1-2-3-1101") != "S-1-5-21-1-2-3" {
		t.Fatal(DomainSID("S-1-5-21-1-2-3-1101"))
	}
	if _, err := SelectInstance([]Instance{forest}, Hint{GUID: "03020100-0504-0706-0809-0a0b0c0d0e0f"}); err != ErrUnknownInstance {
		t.Fatalf("guid alone: %v", err)
	}
	if _, err := SelectInstance([]Instance{forest}, Hint{GUID: "03020100-0504-0706-0809-0a0b0c0d0e0f", Domain: "DC=missing,DC=test"}); err != ErrUnknownInstance {
		t.Fatalf("missing domain: %v", err)
	}
	if _, err := SelectInstance([]Instance{forest, forest}, Hint{Domain: "DC=authsec,DC=test", GUID: "03020100-0504-0706-0809-0a0b0c0d0e0f"}); err != ErrAmbiguous {
		t.Fatalf("ambiguous: %v", err)
	}
	if _, err := SelectInstance([]Instance{forest}, Hint{SID: "S-1-5-21-1-2-3-1101", Domain: "DC=other,DC=test"}); err != ErrUnknownInstance {
		t.Fatalf("sid and domain disagree: %v", err)
	}
}
