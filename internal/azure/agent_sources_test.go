package azure

import "testing"

func TestFoundryProjectEndpoint(t *testing.T) {
	cases := map[string]string{
		"https://contoso-ai.cognitiveservices.azure.com/": "https://contoso-ai.services.ai.azure.com/api/projects/proj",
		"https://contoso-ai.services.ai.azure.com":        "https://contoso-ai.services.ai.azure.com/api/projects/proj",
		"":          "",
		"not a url": "",
	}
	for in, want := range cases {
		if got := FoundryProjectEndpoint(in, "proj"); got != want {
			t.Errorf("FoundryProjectEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
}
