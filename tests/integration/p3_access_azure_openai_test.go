package integration

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/services"
)

// Access policies on an Azure OpenAI / AI Services account (step 4): a block
// of read removes the roles that call its models or read its data (OpenAI
// User, Cognitive Services User) and puts them back at the end; a role
// reaching only another data plane of the account (Speech) is refused unless
// the block is "all"; an account without a custom subdomain takes keys only
// and is refused; an allow of read assigns Cognitive Services OpenAI User.
func TestAccessPolicyAzureOpenAI(t *testing.T) {
	z := newAzLab(t)
	const speechUser = "f2dc8367-1007-4938-bd23-fe263f013447"
	z.fake.defs = append(z.fake.defs,
		azureDef(t, z.sub, azure.RoleCognitiveOpenAIUser, []string{"Microsoft.CognitiveServices/*/read"},
			[]string{"Microsoft.CognitiveServices/accounts/OpenAI/*/read", "Microsoft.CognitiveServices/accounts/OpenAI/deployments/chat/completions/action"}),
		azureDef(t, z.sub, azure.RoleCognitiveOpenAIContributor, []string{"Microsoft.CognitiveServices/*/read"}, []string{"Microsoft.CognitiveServices/accounts/OpenAI/*"}),
		azureDef(t, z.sub, speechUser, []string{"Microsoft.CognitiveServices/*/read"}, []string{"Microsoft.CognitiveServices/accounts/SpeechServices/*"}),
	)
	acct := "/subscriptions/" + z.sub + "/resourcegroups/rg/providers/microsoft.cognitiveservices/accounts/aiacct"
	z.fake.props[acct] = map[string]any{"customSubDomainName": "aiacct"}
	res := z.resource("cognitive_account", "aiacct", acct)
	keysOnly := "/subscriptions/" + z.sub + "/resourcegroups/rg/providers/microsoft.cognitiveservices/accounts/aikeys"
	z.fake.props[keysOnly] = map[string]any{}
	keysOnlyRes := z.resource("cognitive_account", "aikeys", keysOnly)

	// Block read: the OpenAI User assignment goes, and comes back at the end.
	caller, callerOID := z.principal("sp-agent")
	z.assign(acct, "oai-user-1", azure.RoleCognitiveOpenAIUser, callerOID)
	pv, err := z.svc.Preview(z.ctx, z.ws, z.intent("block", res, caller, "read"))
	if err != nil || len(pv.Blockers) != 0 || !strings.Contains(fmt.Sprint(pv.Warnings), services.GovCodeAzureAIKeys) {
		t.Fatalf("block read: %+v %v", pv, err)
	}
	v := z.create("az openai block", z.intent("block", res, caller, "read"))
	z.run(v.ID)
	if got := z.fake.roles(callerOID); len(got) != 0 {
		t.Fatalf("after the block the agent holds %v", got)
	}
	z.end(v.ID)
	z.run(v.ID)
	if got := z.fake.roles(callerOID); len(got) != 1 || got[0] != azure.RoleCognitiveOpenAIUser {
		t.Fatalf("after the end the agent holds %v", got)
	}

	// Speech only: a read block cannot classify it; "all" takes it.
	speaker, speakerOID := z.principal("sp-speech")
	z.assign(acct, "speech-1", speechUser, speakerOID)
	if got := previewCode(z.svc.Preview(z.ctx, z.ws, z.intent("block", res, speaker, "read"))); got != services.GovCodeAzureDataUnclassified {
		t.Fatalf("speech-only, block read: %s", got)
	}
	if pv, err := z.svc.Preview(z.ctx, z.ws, z.intent("block", res, speaker, "all")); err != nil || len(pv.Blockers) != 0 {
		t.Fatalf("speech-only, block all: %+v %v", pv, err)
	}

	// Keys only: refused either way.
	for _, effect := range []string{"block", "allow"} {
		if got := previewCode(z.svc.Preview(z.ctx, z.ws, z.intent(effect, keysOnlyRes, caller, "read"))); got != services.GovCodeAzureAIKeysOnly {
			t.Errorf("%s on a keys-only account: %s", effect, got)
		}
	}

	// Allow read: OpenAI User, with what it allows beyond read.
	newcomer, newcomerOID := z.principal("sp-new-agent")
	pv, err = z.svc.Preview(z.ctx, z.ws, z.intent("allow", res, newcomer, "read"))
	if err != nil || len(pv.Blockers) != 0 || !strings.Contains(fmt.Sprint(pv.Warnings), "Cognitive Services OpenAI User also allows") {
		t.Fatalf("allow read: %+v %v", pv, err)
	}
	a := z.create("az openai allow", z.intent("allow", res, newcomer, "read"))
	z.run(a.ID)
	if got := z.fake.roles(newcomerOID); len(got) != 1 || got[0] != azure.RoleCognitiveOpenAIUser {
		t.Fatalf("the allow assigned %v", got)
	}

	// Another workspace's account is 404.
	other := p3NewGov(t, z.db, "oai-other")
	foreign := uuid.New()
	p3exec(t, z.db, `INSERT INTO iga_resources (id, workspace_id, resource_kind, display_name, provider, source_key)
		VALUES (?, ?, 'cognitive_account', 'aiacct', 'azure', ?)`, foreign, other.ws, "azure\x1f"+z.tenantID+"\x1fresource\x1f"+acct+"-foreign")
	if got := previewCode(z.svc.Preview(z.ctx, z.ws, z.intent("block", foreign, caller, "read"))); got != services.GovCodeResourceNotFound {
		t.Errorf("another workspace's account: %s", got)
	}
}
