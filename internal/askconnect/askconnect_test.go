package askconnect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/authsec-ai/authsec/internal/safehttp"
)

type recorded struct {
	Method, Path, Query, Auth string
	Body                      map[string]any
}

type fake struct {
	mu   sync.Mutex
	reqs []recorded
	srv  *httptest.Server
}

func newFake(t *testing.T, h func(w http.ResponseWriter, r *http.Request, body map[string]any)) *fake {
	t.Helper()
	f := &fake{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Auth: r.Header.Get("Authorization"), Body: body})
		f.mu.Unlock()
		h(w, r, body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) last() recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reqs[len(f.reqs)-1]
}

func TestJiraCreateAndStatus(t *testing.T) {
	status := "indeterminate"
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/issue":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"10001","key":"SEC-7","self":"x"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/issue/SEC-7":
			_, _ = w.Write([]byte(`{"key":"SEC-7","fields":{"status":{"name":"Whatever","statusCategory":{"key":"` + status + `"}}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	j := JiraClient{Site: f.srv.URL, Email: "bot@example.com", Token: "tok", ProjectKey: "SEC", HTTP: f.srv.Client()}
	it, err := j.Create(context.Background(), Input{Summary: "Decide about agent X\nnow", Description: "Why", Severity: "high", Link: "https://console/x"})
	if err != nil {
		t.Fatal(err)
	}
	if it.Key != "SEC-7" || !strings.HasSuffix(it.URL, "/browse/SEC-7") {
		t.Fatalf("item %+v", it)
	}
	req := f.last()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("bot@example.com:tok"))
	if req.Auth != want {
		t.Fatalf("auth %q", req.Auth)
	}
	fields := req.Body["fields"].(map[string]any)
	if fields["project"].(map[string]any)["key"] != "SEC" || strings.Contains(fields["summary"].(string), "\n") {
		t.Fatalf("fields %v", fields)
	}
	for _, s := range []struct {
		cat  string
		done bool
	}{{"indeterminate", false}, {"new", false}, {"", false}, {"done", true}} {
		status = s.cat
		got, err := j.Get(context.Background(), "SEC-7")
		if err != nil {
			t.Fatal(err)
		}
		if got.Resolved != s.done {
			t.Fatalf("category %q resolved=%v", s.cat, got.Resolved)
		}
	}
}

func TestServiceNowCreateAndStatus(t *testing.T) {
	state := "2"
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/now/table/incident":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"result":{"sys_id":"abc123","number":"INC0010001","state":"1"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/now/table/incident/abc123":
			_, _ = w.Write([]byte(`{"result":{"sys_id":"abc123","number":"INC0010001","state":"` + state + `"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	s := ServiceNowClient{Instance: f.srv.URL, Username: "svc", Password: "pw", HTTP: f.srv.Client()}
	it, err := s.Create(context.Background(), Input{Summary: "s", Description: "d", Severity: "high", DedupeKey: "ask:1"})
	if err != nil {
		t.Fatal(err)
	}
	if it.Key != "abc123" || it.Number != "INC0010001" || it.Resolved {
		t.Fatalf("item %+v", it)
	}
	if b := f.last().Body; b["urgency"] != "1" || b["correlation_id"] != "ask:1" {
		t.Fatalf("body %v", b)
	}
	for st, done := range map[string]bool{"1": false, "2": false, "3": false, "6": true, "7": true, "8": true, "": false, "99": false} {
		state = st
		got, err := s.Get(context.Background(), "abc123")
		if err != nil {
			t.Fatal(err)
		}
		if got.Resolved != done {
			t.Fatalf("state %q resolved=%v", st, got.Resolved)
		}
	}
}

func TestPagerDutyTriggerResolve(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		if r.URL.Path != "/v2/enqueue" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"success","dedup_key":"` + body["dedup_key"].(string) + `"}`))
	})
	p := PagerDutyClient{Base: f.srv.URL, RoutingKey: "R0UT1NG", HTTP: f.srv.Client()}
	it, err := p.Trigger(context.Background(), Input{Summary: "s", Severity: "high", DedupeKey: "authsec-ask-1"})
	if err != nil || it.Key != "authsec-ask-1" {
		t.Fatalf("%+v %v", it, err)
	}
	b := f.last().Body
	if b["event_action"] != "trigger" || b["routing_key"] != "R0UT1NG" || b["payload"].(map[string]any)["severity"] != "critical" {
		t.Fatalf("trigger body %v", b)
	}
	if err := p.Resolve(context.Background(), "authsec-ask-1"); err != nil {
		t.Fatal(err)
	}
	if b := f.last().Body; b["event_action"] != "resolve" || b["dedup_key"] != "authsec-ask-1" {
		t.Fatalf("resolve body %v", b)
	}
}

func TestOpsgenieTriggerResolve(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"result":"Request will be processed","requestId":"r1"}`))
	})
	o := OpsgenieClient{Base: f.srv.URL, APIKey: "k3y", HTTP: f.srv.Client()}
	if _, err := o.Trigger(context.Background(), Input{Summary: "s", Severity: "medium", DedupeKey: "authsec-ask-2"}); err != nil {
		t.Fatal(err)
	}
	req := f.last()
	if req.Path != "/v2/alerts" || req.Auth != "GenieKey k3y" || req.Body["alias"] != "authsec-ask-2" || req.Body["priority"] != "P3" {
		t.Fatalf("trigger %+v", req)
	}
	if err := o.Resolve(context.Background(), "authsec-ask-2"); err != nil {
		t.Fatal(err)
	}
	req = f.last()
	if req.Path != "/v2/alerts/authsec-ask-2/close" || req.Query != "identifierType=alias" {
		t.Fatalf("close %+v", req)
	}
}

func TestErrorsPermanentOrNot(t *testing.T) {
	code := http.StatusUnauthorized
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) { w.WriteHeader(code) })
	j := JiraClient{Site: f.srv.URL, Email: "e", Token: "t", ProjectKey: "SEC", HTTP: f.srv.Client()}
	_, err := j.Create(context.Background(), Input{Summary: "s"})
	if !IsPermanent(err) {
		t.Fatalf("401 must be permanent: %v", err)
	}
	for _, c := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusRequestTimeout} {
		code = c
		if _, err := j.Create(context.Background(), Input{Summary: "s"}); err == nil || IsPermanent(err) {
			t.Fatalf("%d must be retryable: %v", c, err)
		}
	}
	// A redirect is never followed.
	code = http.StatusFound
	if _, err := j.Create(context.Background(), Input{Summary: "s"}); err == nil {
		t.Fatal("a redirect must fail")
	}
}

// The production client (internal/safehttp) refuses a tenant URL that
// resolves to a loopback or private address: the request never leaves.
func TestSafeHTTPRefusesPrivateAddresses(t *testing.T) {
	t.Setenv("MCP_ALLOW_LOOPBACK", "")
	t.Setenv("OUTBOUND_ALLOWED_CIDRS", "")
	t.Setenv("OUTBOUND_ALLOWED_HOSTS", "")
	hit := false
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) { hit = true })
	client := safehttp.New(5_000_000_000)
	j := JiraClient{Site: f.srv.URL, Email: "e", Token: "t", ProjectKey: "SEC", HTTP: client}
	_, err := j.Create(context.Background(), Input{Summary: "s"})
	if err == nil || !errors.Is(err, safehttp.ErrBlockedAddress) {
		t.Fatalf("want a blocked address, got %v", err)
	}
	sn := ServiceNowClient{Instance: "https://10.0.0.1", Username: "u", Password: "p", HTTP: client}
	if _, err := sn.Get(context.Background(), "x"); err == nil || !errors.Is(err, safehttp.ErrBlockedAddress) {
		t.Fatalf("want a blocked private address, got %v", err)
	}
	pd := PagerDutyClient{Base: "https://169.254.169.254", RoutingKey: "k", HTTP: client}
	if err := pd.Resolve(context.Background(), "x"); err == nil || !errors.Is(err, safehttp.ErrBlockedAddress) {
		t.Fatalf("want a blocked link-local address, got %v", err)
	}
	if hit {
		t.Fatal("the fake server was reached through the safe client")
	}
	if strings.Contains(err.Error(), "tok") {
		t.Fatal("an error leaked a credential")
	}
}

func TestSiteURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://acme.atlassian.net":  "https://acme.atlassian.net",
		"https://acme.atlassian.net/": "https://acme.atlassian.net",
		" https://x.service-now.com ": "https://x.service-now.com",
	} {
		got, err := SiteURL(in)
		if err != nil || got != want {
			t.Fatalf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"http://acme.atlassian.net", "https://user:pw@acme.atlassian.net", "https://acme.atlassian.net/jira",
		"https://acme.atlassian.net?x=1", "ftp://x", "", "acme.atlassian.net", "https://"} {
		if _, err := SiteURL(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
