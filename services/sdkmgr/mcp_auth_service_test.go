package sdkmgr

import (
	"strings"
	"testing"
)

func TestMarshalMCPToolTextDoesNotHTMLEscapeAuthorizationURL(t *testing.T) {
	text := marshalMCPToolText(map[string]interface{}{
		"authorization_url": "https://oauth.prod.authsec.ai/oauth2/auth?client_id=test-client&redirect_uri=https%3A%2F%2Faks.app.authsec.ai%2Foidc%2Fauth%2Fcallback&response_type=code",
	})

	if strings.Contains(text, `\u0026`) {
		t.Fatalf("authorization_url was HTML escaped: %s", text)
	}
	if !strings.Contains(text, "client_id=test-client&redirect_uri=") {
		t.Fatalf("authorization_url does not contain plain query separators: %s", text)
	}
}
