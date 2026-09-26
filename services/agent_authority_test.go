package services

import "testing"

func TestRejectWorkloadAuthority(t *testing.T) {
	if err := RejectWorkloadAuthority("human_registration"); err != nil {
		t.Fatal(err)
	}
	for _, basis := range []string{"", "weak", "candidate", "strong", "process", "workload_name", "env"} {
		if err := RejectWorkloadAuthority(basis); err == nil {
			t.Fatalf("basis %q was accepted as workload authority", basis)
		}
	}
}
