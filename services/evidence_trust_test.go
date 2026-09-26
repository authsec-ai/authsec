package services

import (
	"testing"

	"github.com/authsec-ai/authsec/models"
)

func TestAllowsAuthoritativeUse_UnverifiedLegacyNever(t *testing.T) {
	if AllowsAuthoritativeUse(models.EvidenceTrustUnverifiedLegacy) {
		t.Fatal("unverified legacy evidence must not drive policy, edges, ownership or enrollment")
	}
	if AllowsAuthoritativeUse("") || AllowsAuthoritativeUse("forged") {
		t.Fatal("unknown trust must not be authoritative")
	}
	if !AllowsAuthoritativeUse(models.EvidenceTrustAuthenticatedCollector) {
		t.Fatal("authenticated collector evidence is authoritative")
	}
	if !AllowsAuthoritativeUse(models.EvidenceTrustHumanAsserted) {
		t.Fatal("human-asserted evidence is authoritative")
	}
}

func TestSelectPolicyInputs_DropsInvoiceWorkerPoison(t *testing.T) {
	in := []PolicyEvidence{
		{Name: "invoice-worker", Trust: models.EvidenceTrustUnverifiedLegacy},
		{Name: "real", Trust: models.EvidenceTrustAuthenticatedCollector},
	}
	out := SelectPolicyInputs(in)
	if len(out) != 1 || out[0].Name != "real" {
		t.Fatalf("policy input = %+v", out)
	}
}
