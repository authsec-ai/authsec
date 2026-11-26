package igaread

// The inventory's subscription and resource group facets (inventory.go).
// The filters themselves are proven end to end in
// tests/integration/p2_azure_inventory_filters_test.go.

import (
	"reflect"
	"testing"
)

func TestInventoryNamedFacet(t *testing.T) {
	got := inventoryNamedFacet(map[string]int64{
		"sub-a/rg-app\x1frg-app": 1,
		"sub-a/rg-app\x1fRG-APP": 2, // one group, two spellings: counted together
		"sub-b\x1fSales":         4,
		"sub-c\x1f":              1, // no name: labelled by its id
		"\x1f":                   9, // no subscription: no chip
		"\x1fProd":               3,
	}, nil)
	want := []FacetValue{
		{Value: "sub-b", Label: "Sales", Count: 4},
		{Value: "sub-a/rg-app", Label: "RG-APP", Count: 3},
		{Value: "sub-c", Label: "sub-c", Count: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("inventoryNamedFacet = %+v, want %+v", got, want)
	}
}
