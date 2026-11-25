package agentgateway

import "testing"

func TestFailModeOrder(t *testing.T) {
	for _, c := range []struct {
		a, b, stricter string
		loosens        bool // a -> b
	}{
		{FailClosed, FailAuto, FailClosed, true},
		{FailClosed, FailOpen, FailClosed, true},
		{FailAuto, FailOpen, FailAuto, true},
		{FailOpen, FailAuto, FailAuto, false},
		{FailAuto, FailClosed, FailClosed, false},
		{FailAuto, FailAuto, FailAuto, false},
		{FailOpen, "typo", FailClosed, true},
	} {
		if got := StricterFailMode(c.a, c.b); got != c.stricter {
			t.Errorf("StricterFailMode(%s,%s)=%s want %s", c.a, c.b, got, c.stricter)
		}
		if got := LoosensFailMode(c.a, c.b); got != c.loosens {
			t.Errorf("LoosensFailMode(%s,%s)=%v want %v", c.a, c.b, got, c.loosens)
		}
	}
}

func TestStoppedSubjectMatching(t *testing.T) {
	r := Request{Kind: KindModel, SubjectID: "rogue-1", IdentityID: "ID-1", WorkloadID: "w-1"}
	if (StoppedSubject{}).Matches(r) {
		t.Fatal("an empty stop matched")
	}
	if !(StoppedSubject{Selector: Selector{IdentityID: "id-1"}}).Matches(r) {
		t.Fatal("identity stop (case-insensitive) did not match")
	}
	if (StoppedSubject{Selector: Selector{IdentityID: "id-1"}, Kind: KindMCPTool}).Matches(r) {
		t.Fatal("mcp-only stop matched a model call")
	}
	if !(StoppedSubject{Selector: Selector{WorkloadID: "w-1", GatewayID: "ignored"}}).Matches(r) {
		t.Fatal("gateway_id on a stop must be ignored")
	}

	pols := []Policy{
		{ID: "a", Effect: EffectDeny, Kind: KindModel, Enabled: true, Subject: Selector{ClientID: "rogue-*"}},
		{ID: "b", Effect: EffectDeny, Kind: KindModel, Enabled: true, Subject: Selector{ClientID: "x"}, Target: Target{Model: "gpt-4o"}},
		{ID: "c", Effect: EffectDeny, Kind: KindModel, Enabled: true},                                    // every agent: not a stop
		{ID: "d", Effect: EffectDeny, Kind: KindModel, Enabled: false, Subject: Selector{ClientID: "y"}}, // disabled
		{ID: "e", Effect: EffectDeny, Kind: KindModel, Enabled: true, Subject: Selector{ClientID: "z"},
			Conditions: Conditions{TimeWindow: &TimeWindow{Timezone: "UTC"}}}, // windowed
		{ID: "f", Effect: EffectDeny, Kind: KindMCPTool, Enabled: true, Subject: Selector{IdentityID: "i", GatewayID: "other"}},
		{ID: "g", Effect: EffectDeny, Kind: KindMCPTool, Enabled: true, Subject: Selector{IdentityID: "j", GatewayID: "GW"}, Target: Target{Tool: "*"}},
		{ID: "h", Effect: EffectAllow, Kind: KindModel, Enabled: true, Subject: Selector{ClientID: "q"}},
	}
	got := PolicyStops(pols, "gw")
	if len(got) != 2 || got[0].Ref != "policy:a" || got[1].Ref != "policy:g" || got[1].GatewayID != "" {
		t.Fatalf("policy stops: %+v", got)
	}
	if StoppedBy(got, r) == nil {
		t.Fatal("rogue-1 not stopped")
	}
}
