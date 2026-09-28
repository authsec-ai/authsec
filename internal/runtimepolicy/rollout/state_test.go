package rollout

import "testing"

func TestMapAndProtect(t *testing.T) {
	if MapControlState("delivered") != Staged || MapControlState("rejected") != Failed || MapControlState("mystery") != Unsupported {
		t.Fatal("state map drifted from §15.2")
	}
	required := []string{"filesystem", "egress"}
	verified := []Control{
		{Kind: "tetragon.file_open_deny", State: "verified"},
		{Kind: "linux.netns_egress", State: "verified"},
	}
	if !Protected(required, verified) {
		t.Fatal("both required controls verified")
	}
	if Protected(required, verified[:1]) {
		t.Fatal("a missing egress control was treated as protected")
	}
	if Protected(nil, verified) {
		t.Fatal("no required controls is not protected")
	}
	if TargetState("canary", "", required, nil) != Pending {
		t.Fatal("no receipt should be pending")
	}
	if TargetState("canary", "verified", required, verified) != Verified {
		t.Fatal("verified controls should verify the target")
	}
	if TargetState("paused", "failed", required, []Control{{Kind: "filesystem", State: "failed"}}) != Failed {
		t.Fatal("failed control should surface")
	}
	if TargetState("rolled_back", "verified", required, verified) != RolledBack {
		t.Fatal("rollback phase should win")
	}
	if len(ControlStates()) != 8 {
		t.Fatal(ControlStates())
	}
}
