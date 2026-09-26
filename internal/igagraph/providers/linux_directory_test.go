package providers

import (
	"testing"

	"github.com/google/uuid"
)

func TestLinuxDirectoryHintIsNotANameMatch(t *testing.T) {
	obs := uuid.New()
	plan, err := Normalize(Input{
		Provider: "linux", EstateID: "estate-1",
		Objects: []Object{
			{Ref: "mapped", Kind: "linux.local_account", ObservationIDs: []uuid.UUID{obs},
				Native: map[string]any{
					"uid": 1000, "user_namespace": "host",
					"directory_guid":   "11111111-1111-1111-1111-111111111111",
					"directory_domain": "DC=authsec,DC=test", "mapping_source": "sssd",
				},
				Attrs: map[string]any{"name": "alice"}},
			{Ref: "plain", Kind: "linux.local_account",
				Native: map[string]any{"uid": 1001, "user_namespace": "host"},
				Attrs:  map[string]any{"name": "alice"}},
			{Ref: "broken", Kind: "linux.local_group",
				Native: map[string]any{"gid": 10, "mapping_source": "winbind", "directory_sid": "nope"},
				Attrs:  map[string]any{"name": "alice"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Relationships) != 0 {
		t.Fatalf("the normalizer must not invent a directory link: %+v", plan.Relationships)
	}
	var mapped, plain, broken Identity
	for _, id := range plan.Identities {
		switch id.Ref {
		case "mapped":
			mapped = id
		case "plain":
			plain = id
		case "broken":
			broken = id
		}
	}
	if mapped.Directory == nil || mapped.Directory.GUID != "11111111-1111-1111-1111-111111111111" || mapped.Directory.MappingSource != "sssd" {
		t.Fatalf("mapped %+v", mapped.Directory)
	}
	if len(mapped.Directory.ObservationIDs) != 1 || mapped.Directory.ObservationIDs[0] != obs {
		t.Fatalf("observations %+v", mapped.Directory.ObservationIDs)
	}
	if plain.Directory != nil || plain.Name != "alice" {
		t.Fatalf("same name without a mapping: %+v", plain)
	}
	if broken.Directory == nil || !broken.Directory.Unreadable {
		t.Fatalf("unreadable %+v", broken.Directory)
	}
	if len(plan.Unresolved) != 1 {
		t.Fatalf("unresolved %+v", plan.Unresolved)
	}
}
